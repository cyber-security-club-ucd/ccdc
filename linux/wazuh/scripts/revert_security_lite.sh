#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

WAZUH_ROOT="${WAZUH_ROOT:-/var/ossec}"
BACKUP_ROOT="${WAZUH_ROOT}/etc/.ccdc-security-lite-backup"
STATE_DIR="${BACKUP_ROOT}/current"
MANIFEST="${STATE_DIR}/manifest.tsv"

if [[ ! -f "${MANIFEST}" ]]; then
  echo "No security-lite backup state found at ${MANIFEST}. Nothing to revert." >&2
  exit 1
fi

while IFS=$'\t' read -r status dest; do
  [[ -n "${status}" ]] || continue

  backup_path="${STATE_DIR}/files${dest}"

  if [[ "${status}" == "EXISTS" ]]; then
    if [[ ! -f "${backup_path}" ]]; then
      echo "Backup missing for ${dest}" >&2
      exit 1
    fi
    mkdir -p "$(dirname "${dest}")"
    cp -p "${backup_path}" "${dest}"
  else
    rm -f "${dest}"
  fi
done < "${MANIFEST}"

rmdir "${WAZUH_ROOT}/etc/shared/debian" 2>/dev/null || true
rmdir "${WAZUH_ROOT}/etc/shared/rhel" 2>/dev/null || true
rmdir "${WAZUH_ROOT}/etc/shared/alpine" 2>/dev/null || true
rmdir "${WAZUH_ROOT}/etc/shared/void" 2>/dev/null || true
rmdir "${WAZUH_ROOT}/etc/shared/windows" 2>/dev/null || true

systemctl restart wazuh-manager
rm -rf "${STATE_DIR}"

echo "Reverted Wazuh security-lite pack and restored pre-apply state."