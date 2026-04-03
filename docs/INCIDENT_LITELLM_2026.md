# LiteLLM March 2026 Supply Chain Incident Runbook

## What this covers
This runbook tracks the known-compromised LiteLLM versions from March 24, 2026:
- `1.82.7`
- `1.82.8`

If either version was installed in your environment, treat the host as potentially compromised.

## Quick triage
Check installed version:
```bash
python -m pip show litellm
python -c "import litellm; print(litellm.__version__)"
```

Check environment lock files and requirements:
```bash
rg -n "litellm" requirements*.txt pyproject.toml poetry.lock Pipfile.lock
```

## Immediate response actions
1. Isolate affected hosts and CI runners.
2. Rotate all credentials that existed on the host at install/runtime time:
   - cloud credentials (AWS/Azure/GCP)
   - SSH keys
   - API keys (LLM providers, databases, third-party services)
3. Rebuild hosts/runners from clean images where possible.
4. Reinstall dependencies from known-good, pinned, hash-verified lock files.

## Files and persistence checks
Search for startup hooks and suspicious `.pth` artifacts:
```bash
python - <<'PY'
import site, sys
paths = set(site.getsitepackages() + [site.getusersitepackages()])
for p in sorted(paths):
    print(p)
PY

# Then inspect those paths:
find <site-packages-path> -maxdepth 2 -name "*.pth" -o -name "sitecustomize.py" -o -name "usercustomize.py"
```

## Preventive controls
- Pin dependencies and use lock files.
- Use `--require-hashes` for production installs.
- Require CI provenance and signed artifacts where possible.
- Keep `pip-guardian` in front of installs for policy + deep scan checks.
