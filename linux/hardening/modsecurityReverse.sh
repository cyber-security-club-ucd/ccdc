#!/usr/bin/env bash
set -euo pipefail

# Reverse modsecurity.sh by running the generated restore.sh from backup dir.
# Usage:
#   ./modsecurityReverse.sh [backup_dir]

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Please run as root"
  exit 1
fi

BACKUP_DIR="${1:-}"
if [[ -z "${BACKUP_DIR}" ]]; then
  BACKUP_DIR="$(ls -dt /root/.peppermint_patty_backup_* 2>/dev/null | head -n 1 || true)"
fi

if [[ -z "${BACKUP_DIR}" ]]; then
  echo "[-] No backup directory found. Provide one explicitly."
  exit 1
fi

RESTORE_SCRIPT="${BACKUP_DIR}/restore.sh"
if [[ ! -x "${RESTORE_SCRIPT}" ]]; then
  echo "[-] Restore script not found or not executable: ${RESTORE_SCRIPT}"
  exit 1
fi

"${RESTORE_SCRIPT}"
echo "[+] Ran ${RESTORE_SCRIPT}"
