#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

WAZUH_ROOT="${WAZUH_ROOT:-/var/ossec}"
BACKUP_DIR="${WAZUH_ROOT}/etc/.ccdc-security-lite-hardening"
SNAPSHOT_FILE="${BACKUP_DIR}/permissions.tsv"

if [[ ! -f "${SNAPSHOT_FILE}" ]]; then
  echo "No hardening snapshot found at ${SNAPSHOT_FILE}. Nothing to revert." >&2
  exit 1
fi

while IFS=$'\t' read -r mode owner group path; do
  [[ -n "${path}" ]] || continue
  [[ -e "${path}" ]] || continue

  chown "${owner}:${group}" "${path}" 2>/dev/null || true
  chmod "${mode}" "${path}" 2>/dev/null || true
done < "${SNAPSHOT_FILE}"

rm -f "${SNAPSHOT_FILE}"
rmdir "${BACKUP_DIR}" 2>/dev/null || true

echo "Reverted manager hardening items 4/5/7 from snapshot."
echo "Recommendation: restart wazuh-manager and filebeat if they were impacted by permission changes."