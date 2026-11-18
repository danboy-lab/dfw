#!/usr/bin/env bash
# Static checks for the shell script. Safe to run in CI (no firewall changes).
set -euo pipefail

cd "$(dirname "$0")/.."

echo "== bash syntax =="
bash -n ufw-hardened.sh

echo "== help output =="
help="$(bash ufw-hardened.sh --help)"
grep -q -- '--all' <<<"$help"
grep -q -- '--rollback' <<<"$help"
grep -q -- 'deny incoming' <<<"$help"

echo "== unknown option must fail =="
if bash ufw-hardened.sh --definitely-unknown >/dev/null 2>&1; then
  echo "expected a failure for an unknown option" >&2
  exit 1
fi

echo "== no obvious secrets committed =="
if grep -R -n -iE 'gho_[A-Za-z0-9]|ghp_[A-Za-z0-9]|api[_-]?key[[:space:]]*=|password[[:space:]]*=' \
    --exclude-dir=.git .; then
  echo "possible secret found in repository" >&2
  exit 1
fi

echo "shell tests: OK"
