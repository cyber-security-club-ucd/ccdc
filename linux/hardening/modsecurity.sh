if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

BACKUP_DIR="/root/.peppermint_patty_backup_$(date +%Y%m%d_%H%M%S)"
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
[ -f /etc/apache2/mods-enabled/security2.conf ] && cp /etc/apache2/mods-enabled/security2.conf "$BACKUP_DIR/security2.conf.orig"

wget https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.23.0.tar.gz
tar -xvf v4.23.0.tar.gz 
rm v4.23.0.tar.gz
mv coreruleset-4.23.0 /etc/apache2/modsecurity-crs
cp /etc/apache2/modsecurity-crs/crs-setup.conf.example /etc/apache2/modsecurity-crs/crs-setup.conf

sed -i "/IncludeOptional \/usr\/share\/modsecurity-crs\/\*\.load/d" /etc/apache2/mods-enabled/security2.conf
sed -i "/<\/IfModule>/d" /etc/apache2/mods-enabled/security2.conf
sed -i "/\/etc\/apache2\/modsecurity-crs\/crs-setup\.conf/d" /etc/apache2/mods-enabled/security2.conf
sed -i "/IncludeOptional \/etc\/apache2\/modsecurity-crs\/rules\/\*\.conf/d" /etc/apache2/mods-enabled/security2.conf

echo '''
IncludeOptional /etc/apache2/modsecurity-crs/crs-setup.conf
IncludeOptional /etc/apache2/modsecurity-crs/rules/*.conf
</IfModule>

<IfModule mod_security2.c>
SecRuleRemoveById 920350 942100 931100
</IfModule>
''' >> /etc/apache2/mods-enabled/security2.conf

# Backup rule file before deletion
[ -f /etc/apache2/modsecurity-crs/rules/REQUEST-922-MULTIPART-ATTACK.conf ] && \
    cp /etc/apache2/modsecurity-crs/rules/REQUEST-922-MULTIPART-ATTACK.conf "$BACKUP_DIR/"
rm /etc/apache2/modsecurity-crs/rules/REQUEST-922-MULTIPART-ATTACK.conf

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
[ -f "$SCRIPT_DIR/security2.conf.orig" ] && \
    cp "$SCRIPT_DIR/security2.conf.orig" /etc/apache2/mods-enabled/security2.conf && \
    echo "  Restored security2.conf"
[ -f "$SCRIPT_DIR/REQUEST-922-MULTIPART-ATTACK.conf" ] && \
    [ -d /etc/apache2/modsecurity-crs/rules ] && \
    cp "$SCRIPT_DIR/REQUEST-922-MULTIPART-ATTACK.conf" /etc/apache2/modsecurity-crs/rules/ && \
    echo "  Restored REQUEST-922-MULTIPART-ATTACK.conf"
systemctl restart apache2
echo "[+] Restore complete. Note: apt packages remain installed."
RESTORE_EOF
chmod +x "$BACKUP_DIR/restore.sh"
echo "[+] ModSecurity with OWASP CRS applied."
echo "[+] Backup saved to: $BACKUP_DIR"
echo "[+] To restore config: sudo $BACKUP_DIR/restore.sh"
