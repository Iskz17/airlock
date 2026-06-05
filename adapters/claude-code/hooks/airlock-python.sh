#!/usr/bin/env bash
# Locate a usable Python 3 and exec the airlock hook script passed as "$1" (+ args).
# Mirrors the security-guidance plugin's sg-python.sh approach. If no Python is
# found we fail OPEN (emit empty JSON, exit 0) so the host agent is never blocked.
export PYTHONUTF8=1
for cmd in python3 python3.13 python3.12 python3.11 python3.10 python; do
  if command -v "$cmd" >/dev/null 2>&1; then
    exec "$cmd" "$@"
  fi
done
echo '{}'
exit 0
