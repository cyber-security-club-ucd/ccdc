#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACK_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WAZUH_ROOT="${WAZUH_ROOT:-/var/ossec}"
BACKUP_ROOT="${WAZUH_ROOT}/etc/.ccdc-security-lite-backup"
STATE_DIR="${BACKUP_ROOT}/current"
MANIFEST="${STATE_DIR}/manifest.tsv"

if [[ -e "${STATE_DIR}" ]]; then
  echo "Existing security-lite backup state found at ${STATE_DIR}. Revert first or remove the backup state if you are certain." >&2
  exit 1
fi

mkdir -p "${STATE_DIR}/files"

declare -a MAPPINGS=(
  "${PACK_ROOT}/manager/ossec.conf|${WAZUH_ROOT}/etc/ossec.conf"
  "${PACK_ROOT}/manager/decoders/local_decoder_security_lite.xml|${WAZUH_ROOT}/etc/decoders/local_decoder_security_lite.xml"
  "${PACK_ROOT}/manager/rules/local_rules_security_lite.xml|${WAZUH_ROOT}/etc/rules/local_rules_security_lite.xml"
  "${PACK_ROOT}/agents/debian/agent.conf|${WAZUH_ROOT}/etc/shared/debian/agent.conf"
  "${PACK_ROOT}/agents/rhel/agent.conf|${WAZUH_ROOT}/etc/shared/rhel/agent.conf"
  "${PACK_ROOT}/agents/alpine/agent.conf|${WAZUH_ROOT}/etc/shared/alpine/agent.conf"
  "${PACK_ROOT}/agents/void/agent.conf|${WAZUH_ROOT}/etc/shared/void/agent.conf"
  "${PACK_ROOT}/agents/windows/agent.conf|${WAZUH_ROOT}/etc/shared/windows/agent.conf"
)

for entry in "${MAPPINGS[@]}"; do
  src="${entry%%|*}"
  dest="${entry##*|}"

  if [[ ! -f "${src}" ]]; then
    echo "Missing source file: ${src}" >&2
    exit 1
  fi
done

if command -v xmllint >/dev/null 2>&1; then
  xmllint --noout \
    "${PACK_ROOT}/manager/ossec.conf" \
    "${PACK_ROOT}/manager/decoders/local_decoder_security_lite.xml" \
    "${PACK_ROOT}/manager/rules/local_rules_security_lite.xml" \
    "${PACK_ROOT}/agents/debian/agent.conf" \
    "${PACK_ROOT}/agents/rhel/agent.conf" \
    "${PACK_ROOT}/agents/alpine/agent.conf" \
    "${PACK_ROOT}/agents/void/agent.conf" \
    "${PACK_ROOT}/agents/windows/agent.conf"
fi

for entry in "${MAPPINGS[@]}"; do
  src="${entry%%|*}"
  dest="${entry##*|}"
  backup_path="${STATE_DIR}/files${dest}"

  if [[ -e "${dest}" ]]; then
    mkdir -p "$(dirname "${backup_path}")"
    cp -p "${dest}" "${backup_path}"
    printf 'EXISTS\t%s\n' "${dest}" >> "${MANIFEST}"
  else
    printf 'MISSING\t%s\n' "${dest}" >> "${MANIFEST}"
  fi

  mkdir -p "$(dirname "${dest}")"
  cp "${src}" "${dest}"
done

systemctl restart wazuh-manager

cat <<EOF
Applied Wazuh security-lite pack.

Deployed manager files:
  ${WAZUH_ROOT}/etc/decoders/local_decoder_security_lite.xml
  ${WAZUH_ROOT}/etc/rules/local_rules_security_lite.xml

Deployed shared agent group files:
  ${WAZUH_ROOT}/etc/shared/debian/agent.conf
  ${WAZUH_ROOT}/etc/shared/rhel/agent.conf
  ${WAZUH_ROOT}/etc/shared/alpine/agent.conf
  ${WAZUH_ROOT}/etc/shared/void/agent.conf
  ${WAZUH_ROOT}/etc/shared/windows/agent.conf

Updated manager local config:
  ${WAZUH_ROOT}/etc/ossec.conf (copied from pack)

Backup state stored in:
  ${STATE_DIR}

Reminder:
  - Assign agents to the appropriate Wazuh groups if you have not already.
  - Restart agents or wait for centralized configuration to refresh on endpoints.
EOF