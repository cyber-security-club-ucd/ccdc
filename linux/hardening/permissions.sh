#!/bin/bash
# Combined permissions scanner + hardener
# Combines: permissions.sh + findsusfiles.sh + findsusuids.sh

if [ "$EUID" -ne 0 ]; then echo "Please run as root"; exit 1; fi

BACKUP_DIR="/root/.permissions_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

backup_if_exists() {
	local src="$1"
	local dst_name="$2"
	if [ -e "$src" ]; then
		cp -a "$src" "$BACKUP_DIR/$dst_name"
		echo "[+] Backed up $src -> $BACKUP_DIR/$dst_name"
	fi
}

echo "[+] Creating backups before any changes..."
backup_if_exists /etc/passwd etc_passwd.bak
backup_if_exists /etc/shadow etc_shadow.bak
backup_if_exists ./prohibfilestat prohibfilestat.bak
backup_if_exists ./globalwritefilestat globalwritefilestat.bak
backup_if_exists ./setuidfilestat setuidfilestat.bak
backup_if_exists ./aclfilestat aclfilestat.bak

# ── Harden critical file permissions ─────────────────────────────────────────
echo "[+] Hardening /etc/passwd and /etc/shadow permissions..."
chown root:root /etc/shadow /etc/passwd
chmod 640 /etc/shadow
chmod 644 /etc/passwd
echo "    /etc/shadow -> root:root 640"
echo "    /etc/passwd -> root:root 644"

# ── Tarballs and executables in home dirs (attacker drops) ───────────────────
echo ""
echo "[+] Tarballs and executables in /home (potential attacker tools):"
find /home -type f \( -name "*.tar.*" -o -executable \) 2>/dev/null | tee prohibfilestat

# ── World-writable files and directories ─────────────────────────────────────
echo ""
echo "[+] World-writable files and directories -> ./globalwritefilestat"
find / \( \( -path '/dev*' -o -path '/proc*' -o -path '/sys*' \) -prune \) \
	-o \( -type f -o -type d \) -perm /0002 -exec ls -ld {} + 2>/dev/null \
	| tee globalwritefilestat

# ── SUID/SGID scanner with danger flagging ───────────────────────────────────
echo ""
echo "[+] SUID/SGID files (flagging non-root owned or suspicious paths) -> ./setuidfilestat"
find / \( \( -path '/dev*' -o -path '/proc*' -o -path '/sys*' \) -prune \) \
	-o -type f -perm /7000 -printf '%p\t%u:%g\t%M\n' 2>/dev/null \
	| sort | while IFS=$'\t' read -r file ownerperms perms; do
	danger=""
	owner=$(echo "$ownerperms" | cut -d: -f1)
	if [ "$owner" != "root" ]; then
		danger="[DANGER: Non-root owned]"
	fi
	if [[ "$file" == /tmp/* ]] || [[ "$file" == /var/tmp/* ]] || [[ "$file" == /home/* ]]; then
		danger="[DANGER: User-writable path]"
	fi
	if [ -n "$danger" ]; then
		echo -e "$file\t$ownerperms\t$perms\t$danger"
	else
		echo -e "$file\t$ownerperms\t$perms"
	fi
done | tee setuidfilestat

# ── Files with capabilities ───────────────────────────────────────────────────
echo ""
echo "[+] Files with capabilities:"
getcap -r / 2>/dev/null

# ── Files with ACLs ───────────────────────────────────────────────────────────
echo ""
echo "[+] Files with extended ACLs -> ./aclfilestat"
getfacl -R -s -p / 2>/dev/null \
	| sed -n 's@: //@: /@;s@^# file: @@p' \
	| sort | tee aclfilestat | grep -vE '^/(var|run)/log/journal/'

echo ""
echo "[+] Done. Output files: prohibfilestat, globalwritefilestat, setuidfilestat, aclfilestat"
echo "[+] Backup directory: $BACKUP_DIR"
