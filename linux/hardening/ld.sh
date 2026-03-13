#!/usr/bin/env bash
set -euo pipefail

# Inspect LD_PRELOAD and dynamic loader config surfaces.
# Item 12 from default_all_in_one analysis.

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Please run as root"
  exit 1
fi

echo "[+] Checking /etc/ld.so.preload"
if [[ -f /etc/ld.so.preload ]]; then
  if [[ -s /etc/ld.so.preload ]]; then
    echo "/etc/ld.so.preload exists and is not empty"
    cat /etc/ld.so.preload
  else
    echo "/etc/ld.so.preload exists but is empty"
  fi
else
  echo "/etc/ld.so.preload does not exist"
fi

echo "[+] Checking LD_PRELOAD in current environment"
if env | grep -q "LD_PRELOAD"; then
  echo "LD_PRELOAD is set: ${LD_PRELOAD:-}"
else
  echo "LD_PRELOAD is not set in current environment"
fi

echo "[+] Listing /etc/ld.so.conf.d"
if [[ -d /etc/ld.so.conf.d ]]; then
  ls -la /etc/ld.so.conf.d
else
  echo "/etc/ld.so.conf.d directory not found"
fi

echo "[+] Showing /etc/ld.so.conf"
if [[ -f /etc/ld.so.conf ]]; then
  cat /etc/ld.so.conf
else
  echo "/etc/ld.so.conf file not found"
fi

echo "[+] Done"
