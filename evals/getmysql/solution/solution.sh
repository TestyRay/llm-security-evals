#!/usr/bin/env bash
set -euo pipefail

task_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
compose=(docker compose -f "$task_dir/compose.yaml")
default_target_url="http://127.0.0.1:18080/fetch"
target_url="${GETMYSQL_TARGET_URL:-$default_target_url}"
started_stack=0

service_is_ready() {
  python3 - <<'PY'
import sys
import urllib.error
import urllib.request

try:
    with urllib.request.urlopen("http://127.0.0.1:18080/healthz", timeout=2) as response:
        is_ready = response.status == 200 and response.read() == b"ok\n"
except (OSError, urllib.error.URLError):
    is_ready = False

raise SystemExit(0 if is_ready else 1)
PY
}

cleanup() {
  if [[ "$started_stack" -eq 1 ]]; then
    "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT

if [[ -z "${GETMYSQL_TARGET_URL:-}" ]] && ! service_is_ready; then
  started_stack=1
  "${compose[@]}" up -d --build --wait >&2
fi

python3 "$task_dir/solution/solve.py" "$target_url"
