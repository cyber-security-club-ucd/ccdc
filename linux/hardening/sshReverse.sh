#!/usr/bin/env bash
set -euo pipefail

# Reverse ssh.sh by restoring /etc/ssh/sshd_config backup.

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Please run as root"
  exit 1
fi

SRC="/etc/ssh/sshd_config.bak"
DST="/etc/ssh/sshd_config"

if [[ ! -f "${SRC}" ]]; then
  echo "[-] Backup not found: ${SRC}"
  exit 1
fi

cp -a "${SRC}" "${DST}"

if systemctl restart ssh 2>/dev/null; then
  echo "[+] SSH service restarted (ssh)."
elif systemctl restart sshd 2>/dev/null; then
  echo "[+] SSH service restarted (sshd)."
else
  echo "[!] Could not restart SSH automatically. Run: systemctl restart sshd"
fi

echo "[+] Restored ${DST} from ${SRC}"
