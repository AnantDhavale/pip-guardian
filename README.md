# pip-guardian

`pip-guardian` is a security gate in front of `pip install` to reduce PyPI supply-chain risk.

## Why this exists
Package ecosystems are a common attack path. `pip-guardian` checks package metadata and distribution contents before install, then decides `ALLOW`, `WARN`, or `BLOCK`.

## Feature set

### 1) Pre-install risk policy
- Version age rules:
  - block if version is very new (default `< 5h`)
  - warn if version is recent (default `< 48h`)
- Blocks yanked releases.
- Blocks known-compromised versions from local blocklist.
- Blocks maintainer identities from local blocklist.

### 2) Deep artifact scanning
- Downloads wheel/sdist artifacts from PyPI before install.
- Verifies artifact SHA256 against PyPI metadata.
- Static scan heuristics for:
  - executable `.pth` startup hooks
  - `sitecustomize.py` / `usercustomize.py`
  - obfuscated payload patterns (e.g., long base64 + dynamic execution)
  - credential-exfiltration-like behavior
  - persistence indicators (e.g., systemd artifacts)
  - Kubernetes lateral-movement indicators

### 3) Built-in incident guard (LiteLLM March 2026)
- Blocks:
  - `litellm==1.82.7`
  - `litellm==1.82.8`
- Runbook:
  - `docs/INCIDENT_LITELLM_2026.md`

### 4) CI-friendly JSON mode
- `--json` emits one machine-readable JSON object.
- `--yes` allows non-interactive proceed on `WARN`.
- Exit codes:
  - `0` install succeeded
  - `1` blocked, warn-not-confirmed, or pip install failure
  - `2` usage/argument errors

### 5) Logging
- Decision logs written as JSONL.
- Primary path: `~/.pip_guardian/guardian.log`
- Fallback path (if home not writable): `./.pip_guardian/guardian.log`

## Installation
Not published on PyPI yet.

Install from source:
```bash
git clone https://github.com/AnantDhavale/pip-guardian.git
cd pip-guardian
pip install .
```

## Usage
```bash
guardian install requests
guardian install litellm==1.82.8
guardian install fastapi --index-url https://pypi.org/simple
guardian install requests --json --yes
```

## Policy and IOC files
- `policies/config.yaml`:
  - age thresholds
  - deep-scan score thresholds
  - executable `.pth` blocking toggle
- `policies/blocklist.json`:
  - package/version deny list
  - maintainer deny list

## Repository structure
- `guardian/cli.py` - command entrypoint
- `guardian/policy_engine.py` - risk decision logic
- `guardian/scanner.py` - deep artifact scanning
- `guardian/pypi_checker.py` - PyPI metadata collection
- `guardian/logger.py` - local decision logging

## Notes
- This reduces risk but is not a full malware sandbox.
- For production, use pinned dependencies and hash-locked installs.

## Author
Anant Dhavale  
anantdhavale@gmail.com
