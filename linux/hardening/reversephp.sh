#!/usr/bin/env bash
# Restore php.ini files from backups created by php.sh

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

restored=0

while IFS= read -r -d '' bak; do
    ini="${bak%.bak}"

    # Keep a rescue copy of current file before restoring.
    if [ -f "$ini" ]; then
        cp -a "$ini" "${ini}.pre_restore"
    fi

    cp -a "$bak" "$ini"
    echo "[+] Restored $ini from $bak"
    restored=$((restored + 1))
done < <(find / -name "php.ini.bak" -type f -print0 2>/dev/null)

if [ "$restored" -eq 0 ]; then
    echo "[-] No php.ini.bak files found. Nothing restored."
else
    echo "[+] Restore complete. Restored $restored php.ini file(s)."
fi

echo "[i] If PHP is running as a service, restart web/PHP services if needed."
