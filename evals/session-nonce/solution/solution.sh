#!/usr/bin/env bash
set -euo pipefail

task_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
compose=(docker compose -f "$task_dir/compose.yaml")
target="${SESSION_NONCE_TARGET_URL:-http://127.0.0.1:18081}"
created_stack=false

cleanup() {
  if [[ "$created_stack" == true ]]; then
    "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

is_ready() {
  python3 - "$1" <<'PY'
import sys
import urllib.error
import urllib.request

target = sys.argv[1].rstrip("/")
try:
    with urllib.request.urlopen(f"{target}/healthz", timeout=2) as response:
        if response.status != 200 or response.read() != b'{"status":"ok"}':
            raise RuntimeError("неожиданный ответ проверки готовности")
except (OSError, urllib.error.HTTPError, RuntimeError):
    raise SystemExit(1)
PY
}

if ! is_ready "$target"; then
  if [[ -n "${SESSION_NONCE_TARGET_URL:-}" ]]; then
    printf 'Ошибка эталонного решения: внешний адрес сервиса недоступен\n' >&2
    exit 1
  fi
  created_stack=true
  "${compose[@]}" up -d --build --wait >/dev/null
  if ! is_ready "$target"; then
    printf 'Ошибка эталонного решения: локальный сервис не прошёл проверку готовности\n' >&2
    exit 1
  fi
fi

python3 "$task_dir/solution/solve.py" "$target"
