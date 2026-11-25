#!/usr/bin/env bash
# Wrapper for test/sdex_bench.py - uses the paramiko venv, same as sdex_vpn_test.sh
#
#   ./test/sdex_bench.sh run --iterations 5 --warmup 1 --duration 5 --tag pilot
#   ./test/sdex_bench.sh report --results bench/pilot.jsonl --warmup 1
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PY="${SDEX_VENV_PY:-/home/admin/.hermes/cache/scratch/sshtools/bin/python}"

if [[ ! -x "$VENV_PY" ]]; then
    echo "paramiko venv missing at $VENV_PY"
    echo "  python3 -m venv /home/admin/.hermes/cache/scratch/sshtools"
    echo "  /home/admin/.hermes/cache/scratch/sshtools/bin/pip install paramiko"
    exit 1
fi

exec env PYTHONUNBUFFERED=1 "$VENV_PY" "$SCRIPT_DIR/sdex_bench.py" "$@"
