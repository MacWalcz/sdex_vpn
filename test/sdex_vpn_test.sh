#!/usr/bin/env bash
# SDEx VPN multi-VM smoke test - wrapper around sdex_vpn_test.py
#
#   VM-sdex-client  192.168.67.2
#   VM-sdex-server  192.168.67.3 (internal) / 192.168.76.2 (external)
#   VM-sdex-http    192.168.76.4
#
# Usage:
#   printf '%s\n' 'PASSWORD_FOR_USER_dupa' > ~/.hermes/vm_pass && chmod 600 ~/.hermes/vm_pass
#   ./test/sdex_vpn_test.sh                 # run the test
#   ./test/sdex_vpn_test.sh --no-cleanup    # keep the processes running afterwards
#
# Everything else (hosts, ports, tun IPs) is overridable - see --help.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PY="${SDEX_VENV_PY:-/home/admin/.hermes/cache/scratch/sshtools/bin/python}"

if [[ ! -x "$VENV_PY" ]]; then
    echo "paramiko venv missing at $VENV_PY"
    echo "Create it with:"
    echo "  python3 -m venv /home/admin/.hermes/cache/scratch/sshtools"
    echo "  /home/admin/.hermes/cache/scratch/sshtools/bin/pip install paramiko"
    echo "or set SDEX_VENV_PY to a python that has paramiko."
    exit 1
fi

exec env PYTHONUNBUFFERED=1 "$VENV_PY" "$SCRIPT_DIR/sdex_vpn_test.py" "$@"
