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

"${compose[@]}" up -d --build --wait
printf 'Сервис запущен и прошёл проверку готовности\n'

if ! python3 - <<'PY'
import sys
import urllib.error
import urllib.parse
import urllib.request

request = urllib.request.Request(
    "http://127.0.0.1:18080/fetch",
    data=urllib.parse.urlencode({"url": "http://8.8.8.8/"}).encode(),
    method="POST",
)
try:
    urllib.request.urlopen(request, timeout=3)
except urllib.error.HTTPError as error:
    response = error.read().decode("utf-8", errors="replace")
    if error.code == 502 and "доступ разрешён только к внутренним адресам" in response:
        raise SystemExit(0)
    print("Ошибка самопроверки: сервис вернул неожиданный ответ на публичный адрес", file=sys.stderr)
    raise SystemExit(1)
except OSError as error:
    print(f"Ошибка самопроверки: не удалось проверить запрет публичного адреса: {error}", file=sys.stderr)
    raise SystemExit(1)

print("Ошибка самопроверки: сервис разрешил обращение к публичному адресу", file=sys.stderr)
raise SystemExit(1)
PY
then
  exit 1
fi
printf 'Публичные адреса для подделки серверных запросов (SSRF): заблокированы\n'

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

if [[ -n "$(\${compose[@]} port db 3306 2>/dev/null)" ]]; then
  printf 'Ошибка самопроверки: порт внутренней БД опубликован наружу\n' >&2
  exit 1
fi
printf 'Порт внутренней БД: не опубликован\n'

set +e
grep_output="$(LC_ALL=C grep -aR -n -- 'flag{' "$task_dir/images/victim/source" "$task_dir/images/db/init" 2>&1)"
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
