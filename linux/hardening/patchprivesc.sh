
#!/bin/bash
# Patches pwnkit (CVE-2021-4034) and CVE-2023-32233

if [ "$EUID" -ne 0 ]; then echo "Please run as root"; exit 1; fi

# Patch pwnkit: save original perms first
ORIG_PKEXEC=$(stat -c "%a" /usr/bin/pkexec 2>/dev/null)
if [ -n "$ORIG_PKEXEC" ]; then
	echo "[+] pkexec original perms: $ORIG_PKEXEC -> setting to 0755"
	chmod 0755 /usr/bin/pkexec
else
	echo "[-] /usr/bin/pkexec not found, skipping."
fi

# Patch CVE-2023-32233 (unprivileged user namespaces)
echo "[+] Disabling unprivileged user namespaces (CVE-2023-32233)..."
sysctl -w kernel.unprivileged_userns_clone=0
echo "kernel.unprivileged_userns_clone = 0" >> /etc/sysctl.conf
sysctl -p
echo "[+] Done. To restore pkexec: chmod $ORIG_PKEXEC /usr/bin/pkexec"

