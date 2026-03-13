#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

WAZUH_ROOT="${WAZUH_ROOT:-/var/ossec}"
WAZUH_ETC="${WAZUH_ROOT}/etc"
WAZUH_BIN="${WAZUH_ROOT}/bin"
FILEBEAT_ETC="/etc/filebeat"
BACKUP_DIR="${WAZUH_ROOT}/etc/.ccdc-security-lite-hardening"
SNAPSHOT_FILE="${BACKUP_DIR}/permissions.tsv"

get_service_user() {
  local svc="$1"
  local val
  val="$(systemctl show "${svc}" -p User --value 2>/dev/null || true)"
  if [[ -z "${val}" ]]; then
    echo "root"
  else
    echo "${val}"
  fi
}

get_service_group() {
  local svc="$1"
  local val
  val="$(systemctl show "${svc}" -p Group --value 2>/dev/null || true)"
  if [[ -z "${val}" ]]; then
    echo "root"
  else
    echo "${val}"
  fi
}

check_supported_runtime() {
  local svc="$1"
  local user="$2"
  local group="$3"
  local allow_users="$4"
  local allow_groups="$5"

  if [[ ! " ${allow_users} " =~ " ${user} " ]]; then
    echo "Unsupported ${svc} runtime user: ${user}" >&2
    return 1
  fi

  if [[ ! " ${allow_groups} " =~ " ${group} " ]]; then
    echo "Unsupported ${svc} runtime group: ${group}" >&2
    return 1
  fi

  return 0
}

snapshot_permissions() {
  local target="$1"
  [[ -e "${target}" ]] || return 0

  while IFS= read -r path; do
    local mode owner group
    mode="$(stat -c '%a' "${path}")"
    owner="$(stat -c '%U' "${path}")"
    group="$(stat -c '%G' "${path}")"
    printf '%s\t%s\t%s\t%s\n' "${mode}" "${owner}" "${group}" "${path}" >> "${SNAPSHOT_FILE}"
  done < <(find "${target}" -xdev -print)
}

fix_tree_perms() {
  local path="$1"
  local owner_group="$2"
  local dmode="$3"
  local fmode="$4"

  [[ -d "${path}" ]] || return 0
  chown -R "${owner_group}" "${path}"
  find "${path}" -type d -exec chmod "${dmode}" {} \;
  find "${path}" -type f -exec chmod "${fmode}" {} \;
}

mkdir -p "${BACKUP_DIR}"

if [[ -e "${SNAPSHOT_FILE}" ]]; then
  echo "Existing hardening snapshot found at ${SNAPSHOT_FILE}. Revert hardening first." >&2
  exit 1
fi

WAZUH_USER="$(get_service_user wazuh-manager)"
WAZUH_GROUP="$(get_service_group wazuh-manager)"
FILEBEAT_USER="$(get_service_user filebeat)"
FILEBEAT_GROUP="$(get_service_group filebeat)"

check_supported_runtime "wazuh-manager" "${WAZUH_USER}" "${WAZUH_GROUP}" "root ossec" "root ossec"

if systemctl list-unit-files 2>/dev/null | grep -q '^filebeat\.service'; then
  check_supported_runtime "filebeat" "${FILEBEAT_USER}" "${FILEBEAT_GROUP}" "root filebeat" "root filebeat"
else
  FILEBEAT_USER="root"
  FILEBEAT_GROUP="root"
fi

snapshot_permissions "${WAZUH_ETC}"
snapshot_permissions "${WAZUH_BIN}"
snapshot_permissions "${FILEBEAT_ETC}"

echo "[4] Locking down Wazuh config and binary paths..."
fix_tree_perms "${WAZUH_ETC}" "root:${WAZUH_GROUP}" 750 640
fix_tree_perms "${WAZUH_BIN}" "root:${WAZUH_GROUP}" 750 750

echo "[5] Tightening secret and key file permissions..."
while IFS= read -r key_file; do
  local_group="${WAZUH_GROUP}"
  if [[ "${key_file}" == "${FILEBEAT_ETC}"/* ]]; then
    local_group="${FILEBEAT_GROUP}"
  fi
  chmod 600 "${key_file}"
  chown root:"${local_group}" "${key_file}"
done < <(find "${WAZUH_ETC}" "${FILEBEAT_ETC}" -type f \( -name "*.key" -o -name "*.pem" -o -name "*.crt" -o -name "client.keys" \) 2>/dev/null || true)

if [[ -f "${WAZUH_ETC}/client.keys" ]]; then
  chmod 600 "${WAZUH_ETC}/client.keys"
  chown root:"${WAZUH_GROUP}" "${WAZUH_ETC}/client.keys"
fi

echo "[7] Locking down Filebeat configuration path..."
if [[ -d "${FILEBEAT_ETC}" ]]; then
  fix_tree_perms "${FILEBEAT_ETC}" "root:${FILEBEAT_GROUP}" 750 640
fi

echo "Done. Applied manager hardening items 4/5/7."
echo "Snapshot written to ${SNAPSHOT_FILE}"
echo "Recommendation: restart wazuh-manager and filebeat after permission changes if needed."