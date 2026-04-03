import re
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

import requests

from guardian.hash_checker import verify_sha256

KNOWN_COMPROMISED = {
    "litellm": {
        "1.82.7": "Known compromised release window (March 24, 2026).",
        "1.82.8": "Known compromised release window (March 24, 2026).",
    }
}


def _select_text_files(file_names: List[str]) -> List[str]:
    text_ext = (".py", ".pth", ".txt", ".cfg", ".ini", ".json", ".toml", ".yaml", ".yml", ".sh")
    return [name for name in file_names if name.endswith(text_ext)]


def _score_pattern_findings(file_name: str, content: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lower = content.lower()

    if file_name.endswith(".pth"):
        if re.search(r"^\s*import\s+\w+", content, flags=re.MULTILINE):
            findings.append(
                {
                    "severity": "critical",
                    "score": 95,
                    "reason": "Executable import found in .pth file (runs at interpreter startup).",
                    "file": file_name,
                }
            )
        if file_name.endswith("litellm_init.pth"):
            findings.append(
                {
                    "severity": "critical",
                    "score": 100,
                    "reason": "Incident IOC match: litellm_init.pth.",
                    "file": file_name,
                }
            )

    if file_name.endswith(("sitecustomize.py", "usercustomize.py")):
        findings.append(
            {
                "severity": "high",
                "score": 75,
                "reason": "Startup hook file present (sitecustomize/usercustomize).",
                "file": file_name,
            }
        )

    long_b64 = bool(re.search(r"[A-Za-z0-9+/]{200,}={0,2}", content))
    if long_b64 and any(token in lower for token in ("base64.b64decode", "marshal.loads", "exec(", "eval(")):
        findings.append(
            {
                "severity": "high",
                "score": 80,
                "reason": "Potential obfuscated payload (long base64 + dynamic execution).",
                "file": file_name,
            }
        )

    exfil_markers = ("requests.post(", "urllib.request.urlopen(", "http://", "https://")
    secret_markers = ("aws_secret", "api_key", "token", "ssh", "kube", "os.environ")
    if any(marker in lower for marker in exfil_markers) and any(marker in lower for marker in secret_markers):
        findings.append(
            {
                "severity": "high",
                "score": 78,
                "reason": "Possible credential exfiltration behavior.",
                "file": file_name,
            }
        )

    if any(marker in lower for marker in ("systemctl", "/etc/systemd/system")):
        findings.append(
            {
                "severity": "critical",
                "score": 90,
                "reason": "Persistence indicator via systemd artifacts.",
                "file": file_name,
            }
        )

    if "kubectl" in lower and any(marker in lower for marker in ("privileged", "clusterrolebinding", "daemonset")):
        findings.append(
            {
                "severity": "high",
                "score": 82,
                "reason": "Potential Kubernetes lateral movement behavior.",
                "file": file_name,
            }
        )

    return findings


def _read_member_text(member_name: str, raw: bytes) -> str:
    if len(raw) > 1024 * 1024:
        return ""
    try:
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _inspect_archive(archive_path: Path) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    suffix = archive_path.name.lower()

    if suffix.endswith(".whl") or suffix.endswith(".zip"):
        with zipfile.ZipFile(archive_path, "r") as zf:
            candidates = _select_text_files(zf.namelist())
            for name in candidates:
                with zf.open(name) as fp:
                    content = _read_member_text(name, fp.read())
                if not content:
                    continue
                findings.extend(_score_pattern_findings(name, content))
        return findings

    if suffix.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar")):
        with tarfile.open(archive_path, "r:*") as tf:
            names = [m.name for m in tf.getmembers() if m.isfile()]
            for name in _select_text_files(names):
                member = tf.getmember(name)
                extracted = tf.extractfile(member)
                if extracted is None:
                    continue
                content = _read_member_text(name, extracted.read())
                if not content:
                    continue
                findings.extend(_score_pattern_findings(name, content))
        return findings

    return findings


def _download_file(url: str, destination: Path, timeout: int = 20) -> None:
    with requests.get(url, stream=True, timeout=timeout) as response:
        response.raise_for_status()
        with destination.open("wb") as f:
            for chunk in response.iter_content(chunk_size=1024 * 256):
                if chunk:
                    f.write(chunk)


def _fetch_release_files(package: str, version: str = None) -> Tuple[str, List[Dict[str, Any]]]:
    response = requests.get(f"https://pypi.org/pypi/{package}/json", timeout=10)
    response.raise_for_status()
    payload = response.json()
    resolved_version = version or payload.get("info", {}).get("version")
    return resolved_version, payload.get("releases", {}).get(resolved_version, [])


def scan_package(package: str, requested_version: str = None) -> Dict[str, Any]:
    package_lower = package.lower()
    if package_lower in KNOWN_COMPROMISED and requested_version in KNOWN_COMPROMISED[package_lower]:
        return {
            "known_compromise": True,
            "malicious_score": 100,
            "scan_findings": [
                {
                    "severity": "critical",
                    "score": 100,
                    "reason": KNOWN_COMPROMISED[package_lower][requested_version],
                    "file": "",
                }
            ],
        }

    try:
        version, release_files = _fetch_release_files(package, requested_version)
    except requests.RequestException as exc:
        return {
            "scan_error": f"pypi_download_metadata_failed: {exc}",
            "malicious_score": 0,
            "scan_findings": [],
        }
    except ValueError:
        return {"scan_error": "invalid_pypi_json", "malicious_score": 0, "scan_findings": []}

    if not release_files:
        return {
            "scan_error": "no_release_files",
            "version": version,
            "malicious_score": 0,
            "scan_findings": [],
        }

    selected = [f for f in release_files if f.get("packagetype") in ("bdist_wheel", "sdist")]
    selected = selected[:3]
    findings: List[Dict[str, Any]] = []
    hash_mismatch = False

    with tempfile.TemporaryDirectory(prefix="pip_guardian_scan_") as tmp:
        tmp_path = Path(tmp)
        for file_info in selected:
            filename = file_info.get("filename")
            url = file_info.get("url")
            if not filename or not url:
                continue
            dest = tmp_path / filename

            try:
                _download_file(url, dest)
            except requests.RequestException as exc:
                findings.append(
                    {
                        "severity": "medium",
                        "score": 20,
                        "reason": f"Failed to download distribution for scanning: {exc}",
                        "file": filename,
                    }
                )
                continue

            expected_sha = file_info.get("digests", {}).get("sha256")
            if expected_sha and not verify_sha256(dest, expected_sha):
                hash_mismatch = True
                findings.append(
                    {
                        "severity": "critical",
                        "score": 100,
                        "reason": "Artifact sha256 mismatch against PyPI metadata.",
                        "file": filename,
                    }
                )

            findings.extend(_inspect_archive(dest))

    malicious_score = max((f.get("score", 0) for f in findings), default=0)
    has_executable_pth = any("Executable import found in .pth file" in f.get("reason", "") for f in findings)
    return {
        "version": version,
        "hash_mismatch": hash_mismatch,
        "has_executable_pth": has_executable_pth,
        "malicious_score": malicious_score,
        "scan_findings": findings,
        "known_compromise": False,
    }
