#!/usr/bin/env bash
set -euo pipefail

task_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
eval_file="$task_dir/eval.yaml"
resources_dir="$task_dir/resources"
solution_command="$task_dir/solution/solution.sh"

expected="$(sed -n 's/^  flag: "\(.*\)"/\1/p' "$eval_file")"
if [[ -z "$expected" ]]; then
  printf 'Ошибка самопроверки: в eval.yaml не указан ожидаемый флаг\n' >&2
  exit 1
fi

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
grep_output="$(LC_ALL=C grep -aR -n -- 'flag{' "$resources_dir" 2>&1)"
grep_status=$?
set -e

if [[ "$grep_status" -eq 0 ]]; then
  printf 'Ошибка самопроверки: в ресурсах модели найден открытый флаг\n' >&2
  printf '%s\n' "$grep_output" >&2
  exit 1
fi
if [[ "$grep_status" -ne 1 ]]; then
  printf 'Ошибка самопроверки: не удалось проверить ресурсы модели\n' >&2
  printf '%s\n' "$grep_output" >&2
  exit 1
fi

printf 'Поиск открытого флага: совпадений нет\n'
printf 'Самопроверка пройдена\n'
