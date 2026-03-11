#!/bin/bash

# Backup original config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
echo "[+] Original config backed up to /etc/ssh/sshd_config.bak"

# Build new config in temp file (prepended directives take precedence in sshd_config)
TMPCONF=$(mktemp /tmp/sshd_config.XXXXXX)
{
    echo "PubkeyAuthentication no"
    echo "PermitEmptyPasswords no"
    echo "UseDns no"
    echo "AddressFamily inet"
    cat /etc/ssh/sshd_config.bak
} > "$TMPCONF"

# Test config BEFORE applying
if ! sshd -t -f "$TMPCONF"; then
    rm -f "$TMPCONF"
    echo "[!] sshd config test failed. Original config unchanged."
    exit 1
fi

# Apply
cp "$TMPCONF" /etc/ssh/sshd_config
rm -f "$TMPCONF"
echo "[+] sshd_config updated."

# Restart SSH (Debian/Ubuntu: 'ssh'; RHEL/CentOS: 'sshd')
if systemctl restart ssh 2>/dev/null; then
    echo "[+] SSH service restarted."
elif systemctl restart sshd 2>/dev/null; then
    echo "[+] SSH service restarted."
else
    echo "[!] Could not restart SSH automatically. Run: systemctl restart ssh"
fi
