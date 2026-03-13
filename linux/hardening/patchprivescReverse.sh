#!/usr/bin/env bash
set -euo pipefail

# Best-effort reverse for patchprivesc.sh.
# - Restores kernel.unprivileged_userns_clone to 1
# - Removes lines added by patchprivesc.sh from /etc/sysctl.conf
# - Attempts to restore pkexec mode to 4755 (common distro default)

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Please run as root"
  exit 1
fi

if [[ -f /etc/sysctl.conf ]]; then
  cp -a /etc/sysctl.conf /etc/sysctl.conf.patchprivesc_reverse.bak
  sed -i '/^[[:space:]]*kernel\.unprivileged_userns_clone[[:space:]]*=[[:space:]]*0[[:space:]]*$/d' /etc/sysctl.conf
  echo "[+] Removed hardening line(s) for kernel.unprivileged_userns_clone from /etc/sysctl.conf"
fi

sysctl -w kernel.unprivileged_userns_clone=1 >/dev/null 2>&1 || true
sysctl -p >/dev/null 2>&1 || true

if [[ -e /usr/bin/pkexec ]]; then
  chmod 4755 /usr/bin/pkexec 2>/dev/null || true
  echo "[+] Set /usr/bin/pkexec mode to 4755 (best effort)"
else
  echo "[-] /usr/bin/pkexec not found"
fi

echo "[+] patchprivesc reverse completed (best effort)."
