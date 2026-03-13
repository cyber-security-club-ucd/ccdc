#!/usr/bin/env bash
set -euo pipefail

# Best-effort reverse for packages.sh.
# Reinstalls packages that packages.sh may remove.

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Please run as root"
  exit 1
fi

if command -v dnf >/dev/null 2>&1; then
  dnf install -y nc gcc cmake make telnet || true
  echo "[+] Best-effort reinstall completed via dnf"
elif command -v yum >/dev/null 2>&1; then
  yum install -y nc gcc cmake make telnet || true
  echo "[+] Best-effort reinstall completed via yum"
elif command -v apt-get >/dev/null 2>&1; then
  apt-get update
  apt-get install -y netcat-openbsd gcc cmake make telnet || apt-get install -y netcat gcc cmake make telnet || true
  echo "[+] Best-effort reinstall completed via apt-get"
elif command -v apk >/dev/null 2>&1; then
  apk add gcc make || true
  echo "[+] Best-effort reinstall completed via apk"
else
  echo "[-] Unsupported package manager"
  exit 1
fi
