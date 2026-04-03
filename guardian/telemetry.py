import hashlib
import os
import platform
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import requests

from guardian import __version__


def _truthy(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def telemetry_enabled() -> bool:
    return _truthy(os.getenv("GUARDIAN_TELEMETRY", "0"))


def telemetry_endpoint() -> str:
    return os.getenv("GUARDIAN_TELEMETRY_ENDPOINT", "").strip()


def _stable_install_id() -> str:
    preferred = Path.home() / ".pip_guardian"
    fallback = Path.cwd() / ".pip_guardian"
    cache_dir = preferred
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        cache_dir = fallback
        cache_dir.mkdir(parents=True, exist_ok=True)

    install_id_file = cache_dir / "install_id"
    try:
        if install_id_file.exists():
            return install_id_file.read_text(encoding="utf-8").strip()
        install_id = str(uuid.uuid4())
        install_id_file.write_text(install_id, encoding="utf-8")
        return install_id
    except OSError:
        return str(uuid.uuid4())


def _safe_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def build_event(
    *,
    target: str,
    package_name: str,
    command: str,
    decision: str = "",
    installed: bool = False,
    exit_code: int = 0,
    json_mode: bool = False,
) -> Dict[str, Any]:
    user_label = os.getenv("GUARDIAN_TELEMETRY_USER_ID", "").strip()
    host = platform.node() or "unknown-host"
    return {
        "event": "guardian_install",
        "ts_utc": datetime.now(timezone.utc).isoformat(),
        "guardian_version": __version__,
        "install_id": _stable_install_id(),
        "telemetry_user_id": user_label or None,
        "host_hash": _safe_hash(host),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "command": command,
        "target": target,
        "package_name": package_name,
        "decision": decision,
        "installed": installed,
        "exit_code": exit_code,
        "json_mode": json_mode,
    }


def send_event(payload: Dict[str, Any]) -> bool:
    if not telemetry_enabled():
        return False

    endpoint = telemetry_endpoint()
    if not endpoint:
        return False

    headers = {"Content-Type": "application/json"}
    token = os.getenv("GUARDIAN_TELEMETRY_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        requests.post(endpoint, json=payload, headers=headers, timeout=3)
    except requests.RequestException:
        return False
    return True
