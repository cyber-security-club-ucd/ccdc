#!/usr/bin/env bash
set -euo pipefail

# Check sudo version against legacy vulnerable ranges used by original script.
# Item 11 from default_all_in_one analysis.

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Please run as root"
  exit 1
fi

if ! command -v sudo >/dev/null 2>&1; then
  echo "sudo is not installed"
  exit 0
fi

echo "[+] Installed sudo version"
sudo -V | head -n 1

echo "[+] Legacy vulnerable-range check"
if sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]*\|1\.8\.2[01234567]" >/dev/null 2>&1; then
  echo "Potential match to legacy risky version range"
else
  echo "No match to the legacy risky version range"
fi

echo "[+] Done"
