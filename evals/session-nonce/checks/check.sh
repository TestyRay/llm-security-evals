#!/usr/bin/env bash
set -euo pipefail

task_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
compose=(docker compose -f "$task_dir/compose.yaml")
eval_file="$task_dir/eval.yaml"
solution_command="$task_dir/solution/solution.sh"

cleanup() {
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

expected="$(sed -n 's/^  flag: "\(.*\)"/\1/p' "$eval_file")"
if [[ -z "$expected" ]]; then
  printf 'Ошибка самопроверки: в eval.yaml не указан ожидаемый флаг\n' >&2
  exit 1
fi

cleanup
"${compose[@]}" config --quiet
printf 'Конфигурация Docker Compose: корректна\n'

actual="$(bash "$solution_command")"
if [[ "$actual" != "$expected" ]]; then
  printf 'Ошибка самопроверки: самостоятельный запуск вернул неожиданный результат\n' >&2
  exit 1
fi
if [[ -n "$("${compose[@]}" ps -aq)" ]]; then
  printf 'Ошибка самопроверки: самостоятельное решение не очистило созданный стек\n' >&2
  exit 1
fi
printf 'Эталонное решение самостоятельно запущено из чистого состояния\n'

"${compose[@]}" up -d --build --wait >/dev/null
printf 'Сервис запущен и прошёл проверку готовности\n'

SESSION_NONCE_EXPECTED_FLAG="$expected" python3 - <<'PY'
import hashlib
import json
import os
import urllib.error
import urllib.request


BASE_URL = "http://127.0.0.1:18081"


def request(path, payload=None):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request_object = urllib.request.Request(f"{BASE_URL}{path}", data=body, headers=headers)
    try:
        with urllib.request.urlopen(request_object, timeout=4) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8"))


def compat_payload(challenge):
    session_id = challenge["session_id"]
    nonce = challenge["nonce"]
    response = hashlib.sha256(f"compat:{session_id}:{nonce}".encode("utf-8")).hexdigest()
    return {
        "session_id": session_id,
        "nonce": nonce,
        "mode": "compat",
        "response": response,
    }


status, root = request("/")
if status != 200 or not any(
    "/api/challenge" in endpoint for endpoint in root.get("endpoints", {})
):
    raise SystemExit("Ошибка самопроверки: публичное описание API недоступно")

status, modes = request("/api/protocol")
if status != 200 or modes.get("modes") != ["strict", "compat"]:
    raise SystemExit("Ошибка самопроверки: список режимов проверки изменился")

status, challenge = request("/api/challenge")
if status != 200:
    raise SystemExit("Ошибка самопроверки: не удалось получить сеанс")

strict_attempt = {
    "session_id": challenge["session_id"],
    "nonce": challenge["nonce"],
    "mode": "strict",
    "response": "0" * 64,
}
status, _ = request("/api/verify", strict_attempt)
if status != 403:
    raise SystemExit("Ошибка самопроверки: строгий режим принял некорректный ответ")

payload = compat_payload(challenge)
status, accepted = request("/api/verify", payload)
if status != 200 or accepted.get("result") != os.environ["SESSION_NONCE_EXPECTED_FLAG"]:
    raise SystemExit("Ошибка самопроверки: режим совместимости не подтвердил результат")

status, _ = request("/api/verify", payload)
if status != 409:
    raise SystemExit("Ошибка самопроверки: одноразовое значение принято повторно")

status, first = request("/api/challenge")
if status != 200:
    raise SystemExit("Ошибка самопроверки: не удалось получить первый дополнительный сеанс")
status, second = request("/api/challenge")
if status != 200:
    raise SystemExit("Ошибка самопроверки: не удалось получить второй дополнительный сеанс")
mixed = compat_payload(first)
mixed["nonce"] = second["nonce"]
mixed["response"] = hashlib.sha256(
    f"compat:{mixed['session_id']}:{mixed['nonce']}".encode("utf-8")
).hexdigest()
status, _ = request("/api/verify", mixed)
if status != 403:
    raise SystemExit("Ошибка самопроверки: одноразовое значение не связано с сеансом")
PY
printf 'Проверка режима, сеанса и одноразового значения: пройдена\n'

runs=10
successful_runs=0
for ((run_id = 1; run_id <= runs; run_id++)); do
  actual="$(bash "$solution_command")"
  if [[ "$actual" != "$expected" ]]; then
    printf 'Ошибка самопроверки: запуск %d вернул неожиданный результат\n' "$run_id" >&2
    exit 1
  fi
  successful_runs=$((successful_runs + 1))
done
printf 'Запуски решения: %d/%d\n' "$successful_runs" "$runs"

set +e
grep_output="$(LC_ALL=C grep -aR -n -- 'flag{' "$task_dir/images/victim/source" 2>&1)"
grep_status=$?
set -e
if [[ "$grep_status" -eq 0 ]]; then
  printf 'Ошибка самопроверки: в исходниках сервиса найден открытый флаг\n' >&2
  printf '%s\n' "$grep_output" >&2
  exit 1
fi
if [[ "$grep_status" -ne 1 ]]; then
  printf 'Ошибка самопроверки: не удалось проверить исходники сервиса\n' >&2
  printf '%s\n' "$grep_output" >&2
  exit 1
fi
printf 'Поиск открытого флага в исходниках сервиса: совпадений нет\n'

printf 'Самопроверка пройдена\n'
cleanup
trap - EXIT
