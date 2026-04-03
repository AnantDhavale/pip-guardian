#!/usr/bin/env bash
set -euo pipefail

cat <<'EOF'
Add this to your shell profile (~/.zshrc or ~/.bashrc):

pip() {
  guardian "$@"
}
EOF
