import json
from pathlib import Path
from typing import Any, Dict
try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover
    yaml = None

DEFAULT_POLICY = {
    "block_if_version_younger_than_hours": 5,
    "warn_if_version_younger_than_hours": 48,
    "block_if_malicious_score_at_least": 80,
    "warn_if_malicious_score_at_least": 50,
    "block_on_executable_pth": True,
}


def _load_blocklist() -> Dict[str, Any]:
    blocklist_path = Path(__file__).resolve().parent.parent / "policies" / "blocklist.json"
    if not blocklist_path.exists():
        return {"packages": {}, "maintainers": []}

    try:
        with blocklist_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {"packages": {}, "maintainers": []}

    if not isinstance(data, dict):
        return {"packages": {}, "maintainers": []}
    data.setdefault("packages", {})
    data.setdefault("maintainers", [])
    return data


def _load_policy() -> Dict[str, Any]:
    config_path = Path(__file__).resolve().parent.parent / "policies" / "config.yaml"
    if not config_path.exists() or yaml is None:
        return DEFAULT_POLICY

    try:
        with config_path.open("r", encoding="utf-8") as f:
            parsed = yaml.safe_load(f) or {}
    except OSError:
        return DEFAULT_POLICY

    rules = parsed.get("rules", {}) if isinstance(parsed, dict) else {}
    if not isinstance(rules, dict):
        return DEFAULT_POLICY
    return {
        "block_if_version_younger_than_hours": rules.get(
            "block_if_version_younger_than_hours",
            DEFAULT_POLICY["block_if_version_younger_than_hours"],
        ),
        "warn_if_version_younger_than_hours": rules.get(
            "warn_if_version_younger_than_hours",
            DEFAULT_POLICY["warn_if_version_younger_than_hours"],
        ),
        "block_if_malicious_score_at_least": rules.get(
            "block_if_malicious_score_at_least",
            DEFAULT_POLICY["block_if_malicious_score_at_least"],
        ),
        "warn_if_malicious_score_at_least": rules.get(
            "warn_if_malicious_score_at_least",
            DEFAULT_POLICY["warn_if_malicious_score_at_least"],
        ),
        "block_on_executable_pth": rules.get(
            "block_on_executable_pth",
            DEFAULT_POLICY["block_on_executable_pth"],
        ),
    }


def _risk_log(message: str, verbose: bool) -> None:
    if verbose:
        print(message)


def evaluate_risk(report: Dict[str, Any], policy: Dict[str, Any] = None, verbose: bool = True) -> str:
    policy = policy or _load_policy()
    blocklist = _load_blocklist()

    package = report.get("package")
    version = report.get("version")
    maintainer = (report.get("maintainer") or "").strip().lower()

    if report.get("is_yanked", False):
        _risk_log("[Risk] Requested version is yanked on PyPI", verbose)
        return "BLOCK"

    if report.get("known_compromise", False):
        _risk_log("[Risk] Known compromised package version.", verbose)
        return "BLOCK"

    if report.get("hash_mismatch", False):
        _risk_log("[Risk] Downloaded artifact hash mismatch.", verbose)
        return "BLOCK"

    if policy.get("block_on_executable_pth", True) and report.get("has_executable_pth", False):
        _risk_log("[Risk] Executable .pth detected.", verbose)
        return "BLOCK"

    blocked_versions = blocklist.get("packages", {}).get(package, [])
    if version in blocked_versions:
        _risk_log("[Risk] Version is explicitly blocklisted", verbose)
        return "BLOCK"

    blocked_maintainers = [m.strip().lower() for m in blocklist.get("maintainers", [])]
    if maintainer and maintainer in blocked_maintainers:
        _risk_log("[Risk] Maintainer is blocklisted", verbose)
        return "BLOCK"

    # Unknown package metadata should not override stronger IOC-based signals checked above.
    if report.get("risk") == "unknown":
        return "WARN"

    hours_since_upload = report.get("hours_since_upload", 10**9)
    malicious_score = float(report.get("malicious_score", 0))
    block_hours = float(policy.get("block_if_version_younger_than_hours", 5))
    warn_hours = float(policy.get("warn_if_version_younger_than_hours", 48))
    block_score = float(policy.get("block_if_malicious_score_at_least", 80))
    warn_score = float(policy.get("warn_if_malicious_score_at_least", 50))

    if malicious_score >= block_score:
        _risk_log("[Risk] Deep scan flagged high-severity malicious patterns.", verbose)
        return "BLOCK"

    if malicious_score >= warn_score:
        _risk_log("[Risk] Deep scan flagged suspicious package patterns.", verbose)
        return "WARN"

    # Evaluate block threshold before warn threshold.
    if hours_since_upload < block_hours:
        _risk_log("[Risk] Package uploaded in last few hours", verbose)
        return "BLOCK"

    if hours_since_upload < warn_hours:
        _risk_log("[Risk] Package version uploaded very recently", verbose)
        return "WARN"

    if report.get("release_count", 0) <= 1 and hours_since_upload < 24:
        _risk_log("[Risk] New package with little release history", verbose)
        return "WARN"

    return "ALLOW"
