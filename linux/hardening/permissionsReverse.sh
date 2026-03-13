#!/usr/bin/env bash
set -euo pipefail

# Reverse permissions.sh using latest backup under /root/.permissions_backup_*.

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Please run as root"
  exit 1
fi

LATEST="$(ls -dt /root/.permissions_backup_* 2>/dev/null | head -n 1 || true)"
if [[ -z "${LATEST}" ]]; then
  echo "[-] No permissions backup directory found under /root/.permissions_backup_*"
  exit 1
fi

if [[ -f "${LATEST}/etc_passwd.bak" ]]; then
  cp -a "${LATEST}/etc_passwd.bak" /etc/passwd
  echo "[+] Restored /etc/passwd"
fi

if [[ -f "${LATEST}/etc_shadow.bak" ]]; then
  cp -a "${LATEST}/etc_shadow.bak" /etc/shadow
  echo "[+] Restored /etc/shadow"
fi

for f in prohibfilestat globalwritefilestat setuidfilestat aclfilestat; do
  if [[ -f "./${f}" ]]; then
    rm -f "./${f}"
    echo "[+] Removed generated file ./${f}"
  fi
done

echo "[+] permissions.sh reverse completed using ${LATEST}"
