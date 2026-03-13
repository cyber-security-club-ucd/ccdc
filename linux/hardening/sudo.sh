#!/usr/bin/env bash
set -euo pipefail

# Check sudo policy files for risky privilege patterns.
# Item 10 from default_all_in_one analysis.

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Please run as root"
  exit 1
fi

echo "[+] Checking for NOPASSWD and !authenticate in sudo policy"

declare -a targets=(/etc/sudoers)
if [[ -d /etc/sudoers.d ]]; then
  while IFS= read -r f; do
    targets+=("$f")
  done < <(find /etc/sudoers.d -maxdepth 1 -type f 2>/dev/null)
fi

echo "--- NOPASSWD matches ---"
grep -nH "NOPASSWD" "${targets[@]}" 2>/dev/null || echo "No NOPASSWD matches found"

echo "--- !authenticate matches ---"
grep -nH "\\!authenticate" "${targets[@]}" 2>/dev/null || echo "No !authenticate matches found"

echo "[+] Done"
