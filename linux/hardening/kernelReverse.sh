#!/usr/bin/env bash
set -euo pipefail

# Reverse kernel.sh by restoring /etc/sysctl.conf from backup.

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Please run as root"
  exit 1
fi

FILE="/etc/sysctl.conf"
BAK="${FILE}.bak"

if [[ ! -f "${BAK}" ]]; then
  echo "[-] Backup not found: ${BAK}"
  exit 1
fi

cp -a "${BAK}" "${FILE}"
sysctl -p >/dev/null

echo "[+] Restored ${FILE} from ${BAK}"
