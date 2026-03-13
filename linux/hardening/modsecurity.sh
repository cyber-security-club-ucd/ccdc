#!/usr/bin/env bash
set -euo pipefail

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
    exit 1
fi

BACKUP_DIR="/root/.peppermint_patty_backup_$(date +%Y%m%d_%H%M%S)"
CRS_DIR="/etc/apache2/modsecurity-crs"
CRS_TARBALL="v4.23.0.tar.gz"
CRS_SRC_DIR="coreruleset-4.23.0"
SECURITY2_CONF="/etc/apache2/mods-enabled/security2.conf"
SECURITY2_EDIT_TARGET="$(readlink -f "$SECURITY2_CONF" 2>/dev/null || printf '%s' "$SECURITY2_CONF")"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
echo "[+] Backup directory: $BACKUP_DIR"

apt install -y libapache2-mod-security2 apache2

# Backup modsecurity configs before modification
[ -f /etc/modsecurity/modsecurity.conf ] && cp /etc/modsecurity/modsecurity.conf "$BACKUP_DIR/modsecurity.conf.orig"
[ -f /etc/modsecurity/modsecurity.conf-recommended ] && cp /etc/modsecurity/modsecurity.conf-recommended "$BACKUP_DIR/modsecurity.conf-recommended"

cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sed -i "s/SecRuleEngine DetectionOnly/SecRuleEngine On/g" /etc/modsecurity/modsecurity.conf
sed -i "s/SecAuditLogParts [A-Z]*/SecAuditLogParts ABCEFHJKZ/g" /etc/modsecurity/modsecurity.conf
echo "SecAuditLogFormat JSON" >> /etc/modsecurity/modsecurity.conf

a2enmod security2

# Backup security2.conf before modification
[ -f "$SECURITY2_CONF" ] && cp "$SECURITY2_CONF" "$BACKUP_DIR/security2.conf.orig"
[ -L "$SECURITY2_CONF" ] && readlink "$SECURITY2_CONF" > "$BACKUP_DIR/security2.conf.link_target"
[ -d "$CRS_DIR" ] && tar -czf "$BACKUP_DIR/modsecurity-crs.orig.tar.gz" -C /etc/apache2 modsecurity-crs

wget -O "$CRS_TARBALL" https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.23.0.tar.gz
tar -xvf "$CRS_TARBALL"
rm -f "$CRS_TARBALL"
rm -rf "$CRS_DIR"
mv "$CRS_SRC_DIR" "$CRS_DIR"
cp "$CRS_DIR/crs-setup.conf.example" "$CRS_DIR/crs-setup.conf"

sed -i "/IncludeOptional \/usr\/share\/modsecurity-crs\/\*\.load/d" "$SECURITY2_EDIT_TARGET"
sed -i "/<\/IfModule>/d" "$SECURITY2_EDIT_TARGET"
sed -i "/\/etc\/apache2\/modsecurity-crs\/crs-setup\.conf/d" "$SECURITY2_EDIT_TARGET"
sed -i "/IncludeOptional \/etc\/apache2\/modsecurity-crs\/rules\/\*\.conf/d" "$SECURITY2_EDIT_TARGET"

cat <<'EOF' >> "$SECURITY2_EDIT_TARGET"
IncludeOptional /etc/apache2/modsecurity-crs/crs-setup.conf
IncludeOptional /etc/apache2/modsecurity-crs/rules/*.conf
</IfModule>

<IfModule mod_security2.c>
SecRuleRemoveById 920350 942100 931100
</IfModule>
EOF

rm -f /etc/apache2/modsecurity-crs/rules/REQUEST-922-MULTIPART-ATTACK.conf

systemctl restart apache2

# Generate restore script
cat > "$BACKUP_DIR/restore.sh" << 'RESTORE_EOF'
#!/bin/bash
if [ "$EUID" -ne 0 ]; then echo "Please run as root"; exit 1; fi
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "[+] Restoring backed up config files..."
[ -f "$SCRIPT_DIR/modsecurity.conf.orig" ] && \
    cp "$SCRIPT_DIR/modsecurity.conf.orig" /etc/modsecurity/modsecurity.conf && \
    echo "  Restored modsecurity.conf"
[ ! -f "$SCRIPT_DIR/modsecurity.conf.orig" ] && \
    rm -f /etc/modsecurity/modsecurity.conf && \
    echo "  Removed generated modsecurity.conf"
[ -f "$SCRIPT_DIR/security2.conf.link_target" ] && \
    rm -f /etc/apache2/mods-enabled/security2.conf && \
    ln -s "$(cat "$SCRIPT_DIR/security2.conf.link_target")" /etc/apache2/mods-enabled/security2.conf && \
    echo "  Restored security2.conf symlink"
[ -f "$SCRIPT_DIR/security2.conf.orig" ] && \
    cp "$SCRIPT_DIR/security2.conf.orig" /etc/apache2/mods-enabled/security2.conf && \
    echo "  Restored security2.conf"
[ -f "$SCRIPT_DIR/modsecurity-crs.orig.tar.gz" ] && \
    rm -rf /etc/apache2/modsecurity-crs && \
    tar -xzf "$SCRIPT_DIR/modsecurity-crs.orig.tar.gz" -C /etc/apache2 && \
    echo "  Restored modsecurity-crs directory"
[ ! -f "$SCRIPT_DIR/modsecurity-crs.orig.tar.gz" ] && \
    rm -rf /etc/apache2/modsecurity-crs && \
    echo "  Removed generated modsecurity-crs directory"
systemctl restart apache2
echo "[+] Restore complete. Note: apt packages remain installed."
RESTORE_EOF
chmod +x "$BACKUP_DIR/restore.sh"
echo "[+] ModSecurity with OWASP CRS applied."
echo "[+] Backup saved to: $BACKUP_DIR"
echo "[+] To restore config: sudo $BACKUP_DIR/restore.sh"
