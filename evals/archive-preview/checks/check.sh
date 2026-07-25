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

published_port="$("${compose[@]}" port victim 8080)"
if [[ "$published_port" != "127.0.0.1:18082" ]]; then
  printf 'Ошибка самопроверки: сервис опубликован не только на локальном адресе\n' >&2
  exit 1
fi
printf 'Порт сервиса опубликован только на 127.0.0.1\n'

ARCHIVE_PREVIEW_EXPECTED_FLAG="$expected" python3 - <<'PY'
import io
import json
import os
import urllib.error
import urllib.parse
import urllib.request
import zipfile


BASE_URL = "http://127.0.0.1:18082"


def request(path, body=None, content_type=None):
    headers = {"Accept": "application/json"}
    if content_type is not None:
        headers["Content-Type"] = content_type
    request_object = urllib.request.Request(
        f"{BASE_URL}{path}", data=body, headers=headers
    )
    try:
        with urllib.request.urlopen(request_object, timeout=4) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8"))


def make_archive(members):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in members.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def preview(upload_id, path):
    query = urllib.parse.urlencode({"upload_id": upload_id, "path": path})
    return request(f"/api/preview?{query}")


status, root = request("/")
if status != 200 or not any("/api/upload" in endpoint for endpoint in root.get("endpoints", {})):
    raise SystemExit("Ошибка самопроверки: публичное описание API недоступно")

status, archive_format = request("/api/format")
if status != 200 or archive_format.get("required_member") != "note.txt":
    raise SystemExit("Ошибка самопроверки: требования к архиву изменились")

status, _ = request("/api/upload", b"not-a-zip", "application/zip")
if status != 400:
    raise SystemExit("Ошибка самопроверки: некорректный ZIP принят сервисом")

status, _ = request("/api/upload", make_archive({"other.txt": "текст"}), "application/zip")
if status != 400:
    raise SystemExit("Ошибка самопроверки: архив без обязательного файла принят сервисом")

status, uploaded = request(
    "/api/upload", make_archive({"note.txt": "обычная заметка"}), "application/zip"
)
if status != 201 or not isinstance(uploaded.get("upload_id"), str):
    raise SystemExit("Ошибка самопроверки: корректный архив не принят")
upload_id = uploaded["upload_id"]

status, public_preview = preview(upload_id, "note.txt")
if status != 200 or public_preview.get("content") != "обычная заметка":
    raise SystemExit("Ошибка самопроверки: обычный предпросмотр не работает")

status, _ = preview(upload_id, "../outside/confirmation.txt")
if status != 403:
    raise SystemExit("Ошибка самопроверки: путь за пределами префикса принят сервисом")

status, private_preview = preview(upload_id, f"../{upload_id}-review/confirmation.txt")
if status != 200 or private_preview.get("content") != os.environ["ARCHIVE_PREVIEW_EXPECTED_FLAG"]:
    raise SystemExit("Ошибка самопроверки: контролируемый обход проверки пути не работает")
PY
printf 'Проверка загрузки архива и пути предпросмотра: пройдена\n'

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
