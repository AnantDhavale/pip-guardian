import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


def log_event(package: str, report: Dict[str, Any], decision: str) -> None:
    preferred_dir = Path.home() / ".pip_guardian"
    fallback_dir = Path.cwd() / ".pip_guardian"
    log_dir = preferred_dir
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        log_dir = fallback_dir
        log_dir.mkdir(parents=True, exist_ok=True)

    log_file = log_dir / "guardian.log"

    entry = {
        "ts_utc": datetime.now(timezone.utc).isoformat(),
        "package": package,
        "decision": decision,
        "report": report,
    }
    with log_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=True) + "\n")
