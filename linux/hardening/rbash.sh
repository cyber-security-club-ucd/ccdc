#!/bin/bash
# @d_tranman/Nigel Gerald/Nigerald

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

PASSWD_BAK="/etc/passwd.rbash.bak"
RC_BAK_DIR="/etc/rbash_rc_backups"

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 apply|revert"
    exit 1
fi

MODE="$1"

if [ "$MODE" = "revert" ]; then
    if [ -f "$PASSWD_BAK" ]; then
        cp "$PASSWD_BAK" /etc/passwd
        chmod 644 /etc/passwd
        echo "[+] Restored /etc/passwd from $PASSWD_BAK"
    else
        echo "[-] No passwd backup found at $PASSWD_BAK"
    fi

    if [ -d "$RC_BAK_DIR" ]; then
        while IFS= read -r -d '' bak; do
            dest="${bak#$RC_BAK_DIR}"
            cp "$bak" "$dest"
            echo "[+] Restored $dest"
        done < <(find "$RC_BAK_DIR" -type f -print0)
    fi

    echo "[+] rbash revert complete."
    exit 0
fi

if [ "$MODE" != "apply" ]; then
    echo "Usage: $0 apply|revert"
    exit 1
fi

cp /etc/passwd "$PASSWD_BAK"
chmod 600 "$PASSWD_BAK"
mkdir -p "$RC_BAK_DIR"
chmod 700 "$RC_BAK_DIR"
echo "[+] Backed up /etc/passwd to $PASSWD_BAK"

if ! command -v rbash >/dev/null 2>&1; then
    ln -sf /bin/bash /bin/rbash
fi

# Restrict only human users (UID >= 1000), preserve service users/root shells.
awk -F: 'BEGIN{OFS=FS}
    ($3>=1000 && $1!="nobody" && $7 ~ /\/bin\/.*sh$/){$7="/bin/rbash"}
    {print}
' /etc/passwd > /etc/pw && mv /etc/pw /etc/passwd
chmod 644 /etc/passwd

while IFS= read -r -d '' file; do
    bak="$RC_BAK_DIR$file"
    mkdir -p "$(dirname "$bak")"
    cp "$file" "$bak"

    if ! grep -q "# RBASH_LOCKDOWN" "$file"; then
        {
            echo "# RBASH_LOCKDOWN"
            echo 'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"'
            echo 'export PATH'
        } >> "$file"
    fi
done < <(find /etc /home -type f \( -name ".bashrc" -o -name ".profile" -o -name "*.shrc" \) -print0)

echo "[+] rbash lockdown complete. To revert: bash $0 revert"
