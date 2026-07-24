#!/usr/bin/env bash
set -euo pipefail

task_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

python3 "$task_dir/solution/solve.py" \
  "$task_dir/resources/traffic.pcap" \
  "$task_dir/resources/recovered_webshell.php"
