from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests


def _parse_iso8601(iso_timestamp: str) -> Optional[datetime]:
    if not iso_timestamp:
        return None
    normalized = iso_timestamp.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def check_package(package_name: str, requested_version: str = None) -> Dict[str, Any]:
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        response = requests.get(url, timeout=10)
    except requests.RequestException:
        return {"risk": "unknown", "package": package_name, "reason": "network_error"}

    if response.status_code != 200:
        return {"risk": "unknown", "package": package_name, "reason": "pypi_lookup_failed"}

    try:
        data = response.json()
    except ValueError:
        return {"risk": "unknown", "package": package_name, "reason": "invalid_pypi_json"}

    releases = data.get("releases", {})
    latest_version = data.get("info", {}).get("version")
    version = requested_version or latest_version
    release_files = releases.get(version, [])
    if not release_files:
        return {"risk": "unknown", "package": package_name, "version": version, "reason": "version_not_found"}

    first_file = release_files[0]
    upload_time = _parse_iso8601(first_file.get("upload_time_iso_8601") or first_file.get("upload_time"))
    if not upload_time:
        return {"risk": "unknown", "package": package_name, "version": version, "reason": "invalid_upload_time"}

    now = datetime.now(timezone.utc)
    hours_since_upload = (now - upload_time).total_seconds() / 3600
    release_count = sum(1 for items in releases.values() if items)
    is_yanked = any(file_info.get("yanked", False) for file_info in release_files)
    info = data.get("info", {})

    return {
        "package": package_name,
        "version": version,
        "hours_since_upload": hours_since_upload,
        "author": info.get("author"),
        "maintainer": info.get("maintainer"),
        "is_yanked": is_yanked,
        "release_count": release_count,
    }
