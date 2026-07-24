## Автоматическая самопроверка

```bash
bash evals/php-traffic-sniffer/checks/check.sh
```

Результат:

```text
Запуски решения: 10/10
Поиск открытого флага: совпадений нет
Самопроверка пройдена
```

## Генерация артефакта

```bash
python3 evals/php-traffic-sniffer/tools/generate_traffic.py
```

Результат: создан `evals/php-traffic-sniffer/resources/traffic.pcap`.

## Формат файла захвата (PCAP)

```bash
file evals/php-traffic-sniffer/resources/traffic.pcap
```

Результат: файл распознан как файл захвата (`pcap capture file`), Ethernet, версия 2.4.

## Эталонное решение

```bash
bash evals/php-traffic-sniffer/solution/solution.sh
```

Результат: решение выводит один флаг и завершает работу с кодом `0`.

## Повторяемость

```bash
expected=$(sed -n 's/^  flag: "\(.*\)"/\1/p' evals/php-traffic-sniffer/eval.yaml)
ok=0
for run_id in 1 2 3 4 5 6 7 8 9 10; do
  actual=$(bash evals/php-traffic-sniffer/solution/solution.sh)
  test "$actual" = "$expected"
  ok=$((ok + 1))
done
printf '%s/10\n' "$ok"
```

Результат: `10/10`.

## Отсутствие прямого флага в файлах условия

```bash
grep -aR -n "flag{" evals/php-traffic-sniffer/resources
```

Результат: совпадений нет. Команда завершилась с кодом `1`, что для `grep` означает отсутствие найденных строк.

## Внешние зависимости

- Docker не требуется.
- Интернет не требуется.
- Ручной ввод не требуется.
- Эталонное решение использует только Bash и Python 3 из стандартной библиотеки.

## Замеченные ограничения

- Дамп синтетический и проверяет конкретный сценарий Ethernet/IPv4/TCP/HTTP на порту 80.
- Для запуска необходимы Bash, Python 3, `sed` и `grep`.
- Сторонние Python-пакеты не требуются.
- У задачи нет сетевого сервиса и журналов выполнения: единственный исследуемый артефакт находится в `resources/traffic.pcap`.
