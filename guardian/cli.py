import json
import subprocess
import sys
from guardian.pypi_checker import check_package
from guardian.policy_engine import evaluate_risk
from guardian.logger import log_event
from guardian.scanner import scan_package
from guardian.telemetry import build_event, send_event, telemetry_enabled


def _extract_name_and_exact_version(requirement: str):
    if "==" in requirement:
        name, version = requirement.split("==", 1)
        return name.strip(), version.strip()
    return requirement.strip(), None


def _extract_flag(args, *flags):
    updated = []
    found = False
    for arg in args:
        if arg in flags:
            found = True
        else:
            updated.append(arg)
    return found, updated


def _emit_json(payload):
    print(json.dumps(payload, ensure_ascii=True))


def _truncate_text(text: str, limit: int = 2000) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "...(truncated)"


def _emit_telemetry(
    *,
    command: str,
    target: str,
    package_name: str,
    decision: str,
    installed: bool,
    exit_code: int,
    json_mode: bool,
):
    if not telemetry_enabled():
        return
    try:
        payload = build_event(
            target=target,
            package_name=package_name,
            command=command,
            decision=decision,
            installed=installed,
            exit_code=exit_code,
            json_mode=json_mode,
        )
        send_event(payload)
    except Exception:
        # Telemetry must never block or crash package installation.
        return


def main():
    cli_args = sys.argv[1:]
    json_mode, cli_args = _extract_flag(cli_args, "--json")
    assume_yes, cli_args = _extract_flag(cli_args, "--yes", "-y")

    if len(cli_args) < 2:
        if json_mode:
            _emit_json(
                {
                    "ok": False,
                    "error": "usage_error",
                    "usage": "guardian install <package_or_spec> [pip args] [--json] [--yes]",
                }
            )
        else:
            print("Usage: guardian install <package_or_spec> [pip args] [--json] [--yes]")
        sys.exit(1)

    command = cli_args[0]
    target = cli_args[1]
    pip_extra_args = cli_args[2:]

    if command != "install":
        if json_mode:
            _emit_json(
                {
                    "ok": False,
                    "error": "json_mode_supported_for_install_only",
                    "command": command,
                }
            )
            _emit_telemetry(
                command=command,
                target=target,
                package_name="",
                decision="ERROR",
                installed=False,
                exit_code=2,
                json_mode=True,
            )
            sys.exit(2)
        result = subprocess.run([sys.executable, "-m", "pip"] + cli_args, check=False)
        _emit_telemetry(
            command=command,
            target=target,
            package_name="",
            decision="PASSTHROUGH",
            installed=result.returncode == 0,
            exit_code=result.returncode,
            json_mode=False,
        )
        sys.exit(result.returncode)
        return

    package_name, pinned_version = _extract_name_and_exact_version(target)
    if not package_name or package_name.startswith("-"):
        if json_mode:
            _emit_json(
                {
                    "ok": False,
                    "error": "invalid_package_specifier",
                    "target": target,
                }
            )
            _emit_telemetry(
                command=command,
                target=target,
                package_name=package_name or "",
                decision="ERROR",
                installed=False,
                exit_code=2,
                json_mode=True,
            )
        else:
            print("[Guardian] Invalid package specifier.")
            _emit_telemetry(
                command=command,
                target=target,
                package_name=package_name or "",
                decision="ERROR",
                installed=False,
                exit_code=2,
                json_mode=False,
            )
        sys.exit(2)

    if not json_mode:
        print(f"[Guardian] Checking {target}...")

    report = check_package(package_name, requested_version=pinned_version)
    deep_scan = scan_package(package_name, requested_version=pinned_version)
    report.update(deep_scan)

    findings = report.get("scan_findings", [])
    if findings and not json_mode:
        print(f"[Guardian] Deep scan findings: {len(findings)}")
        for finding in findings[:5]:
            reason = finding.get("reason", "suspicious pattern")
            file_name = finding.get("file", "")
            where = f" ({file_name})" if file_name else ""
            print(f"  - {reason}{where}")

    decision = evaluate_risk(report, verbose=not json_mode)

    log_event(target, report, decision)

    if decision == "BLOCK":
        if json_mode:
            _emit_json(
                {
                    "ok": False,
                    "decision": decision,
                    "target": target,
                    "installed": False,
                    "exit_code": 1,
                    "report": report,
                }
            )
            _emit_telemetry(
                command=command,
                target=target,
                package_name=package_name,
                decision=decision,
                installed=False,
                exit_code=1,
                json_mode=True,
            )
        else:
            print("[Guardian] BLOCKED due to security policy.")
            _emit_telemetry(
                command=command,
                target=target,
                package_name=package_name,
                decision=decision,
                installed=False,
                exit_code=1,
                json_mode=False,
            )
        sys.exit(1)

    if decision == "WARN" and not assume_yes:
        if json_mode:
            _emit_json(
                {
                    "ok": False,
                    "decision": decision,
                    "target": target,
                    "installed": False,
                    "exit_code": 1,
                    "requires_confirmation": True,
                    "hint": "Use --yes to proceed on WARN in non-interactive CI.",
                    "report": report,
                }
            )
            _emit_telemetry(
                command=command,
                target=target,
                package_name=package_name,
                decision=decision,
                installed=False,
                exit_code=1,
                json_mode=True,
            )
            sys.exit(1)
        print("[Guardian] WARNING: Package may be risky.")
        confirm = input("Proceed? (y/n): ")
        if confirm.lower() != "y":
            _emit_telemetry(
                command=command,
                target=target,
                package_name=package_name,
                decision=decision,
                installed=False,
                exit_code=1,
                json_mode=False,
            )
            sys.exit(1)

    if not json_mode:
        print("[Guardian] Installing package...")
    cmd = [sys.executable, "-m", "pip", "install", target] + pip_extra_args
    if "--no-cache-dir" not in cmd:
        cmd.append("--no-cache-dir")
    if "--disable-pip-version-check" not in cmd:
        cmd.append("--disable-pip-version-check")

    if json_mode:
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        _emit_json(
            {
                "ok": result.returncode == 0,
                "decision": decision,
                "target": target,
                "installed": result.returncode == 0,
                "exit_code": result.returncode,
                "report": report,
                "pip_stdout": _truncate_text(result.stdout or ""),
                "pip_stderr": _truncate_text(result.stderr or ""),
            }
        )
        _emit_telemetry(
            command=command,
            target=target,
            package_name=package_name,
            decision=decision,
            installed=result.returncode == 0,
            exit_code=result.returncode,
            json_mode=True,
        )
        sys.exit(result.returncode)

    result = subprocess.run(cmd, check=False)
    _emit_telemetry(
        command=command,
        target=target,
        package_name=package_name,
        decision=decision,
        installed=result.returncode == 0,
        exit_code=result.returncode,
        json_mode=False,
    )
    sys.exit(result.returncode)

if __name__ == "__main__":
    main()
