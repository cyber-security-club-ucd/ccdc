#!/usr/bin/env bash
# Combined PII scanner (pii.sh + findpii.sh + pigpen.sh)
# Uses ripgrep (rg) for fast full-system scan if available; falls back to grep on key paths.

THRESHOLD=3

# Directories to skip when scanning
EXCLUDES=(
    /proc /dev /sys /boot /snap
    /usr/share /usr/bin /usr/lib /usr/lib64 /usr/include /usr/src
    /etc/ssh/moduli /var/cache /var/log /var/snap
    /var/lib/apt /var/lib/dpkg /var/lib/ucf
    /usr/local/lib /usr/local/share /usr/local/bin
    /var/db /run/systemd /run/snapd /var/backups /var/lib/yum
    /opt/gitlab /etc/httpd/conf/magic /etc/apache2/magic
)

# Regex patterns
SSN_RE='[0-9]{3}-[0-9]{2}-[0-9]{4}'
EMAIL_RE='[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}'
PHONE_RE='(\([0-9]{3}\) |[0-9]{3}[ -])[0-9]{3}[ -]?[0-9]{4}'
CC_RE='(?:\d{4}[- ]?){3}\d{4}'
VRN_RE='[A-Z]{1,2}[0-9]{1,2} ?[A-Z]{1,3} ?[0-9]{1,4}'
ADDR_RE='[0-9]+\s+[A-Za-z]+\s+[A-Za-z]+'
COMBINED_RE="${SSN_RE}|${EMAIL_RE}|${PHONE_RE}|${CC_RE}|${VRN_RE}"

# Document extensions to flag
DOC_NAMES=(
    "*.doc" "*.docx" "*.xls" "*.xlsx" "*.pdf" "*.ppt" "*.pptx"
    "*.txt" "*.rtf" "*.csv" "*.odt" "*.ods" "*.odp" "*.odf"
    "*.odb" "*.docm" "*.dotx" "*.xltx" "*.xlsb" "*.pptm"
    "*.potx" "*.ppsx" "*.pps" "*.wbk" "*.xlam"
)

find_docs() {
    local path="$1"
    local name_args=()
    for ext in "${DOC_NAMES[@]}"; do
        name_args+=( "-o" "-name" "$ext" )
    done
    find "$path" -type f \( "${name_args[@]:1}" \) 2>/dev/null | sed 's/^/  [DOC] /'
}

rg_search_path() {
    local path="$1"
    local excl=()
    for ex in "${EXCLUDES[@]}"; do
        excl+=( "--glob=!${ex}" "--glob=!${ex}/**" )
    done
    mapfile -t hits < <(rg "${excl[@]}" --no-follow -P "${COMBINED_RE}" -o -c "$path" 2>/dev/null \
        | awk -v t="$THRESHOLD" -F: '$2+0 > t && $1 !~ /\.(h|rb|c|js|js\.map|py|pem|po)$/ {print $1}')
    for f in "${hits[@]}"; do
        echo "  [FILE] $f"
        rg "${excl[@]}" --no-follow -P "$SSN_RE"   -o "$f" 2>/dev/null | head -3 | sed 's/^/    [SSN] /'
        rg "${excl[@]}" --no-follow -P "$EMAIL_RE" -o "$f" 2>/dev/null | head -3 | sed 's/^/    [Email] /'
        rg "${excl[@]}" --no-follow -P "$PHONE_RE" -o "$f" 2>/dev/null | head -3 | sed 's/^/    [Phone] /'
        rg "${excl[@]}" --no-follow -P "$CC_RE"    -o "$f" 2>/dev/null | head -3 | sed 's/^/    [CC] /'
        rg "${excl[@]}" --no-follow -P "$VRN_RE"   -o "$f" 2>/dev/null | head -3 | sed 's/^/    [VRN] /'
    done
}

grep_search_path() {
    local path="$1"
    grep -rElo  "$SSN_RE"   "$path" 2>/dev/null | sed 's/^/  [SSN] /'
    grep -rElo  "$EMAIL_RE" "$path" 2>/dev/null | sed 's/^/  [Email] /'
    grep -rElo  "$PHONE_RE" "$path" 2>/dev/null | sed 's/^/  [Phone] /'
    grep -rPlo  "$CC_RE"    "$path" 2>/dev/null | sed 's/^/  [CC] /'
    grep -rElo  "$VRN_RE"   "$path" 2>/dev/null | sed 's/^/  [VRN] /'
    grep -rElo  "$ADDR_RE"  "$path" 2>/dev/null | sed 's/^/  [Addr] /'
}

search() {
    local path="$1"
    if command -v rg &>/dev/null; then
        rg_search_path "$path"
    else
        grep_search_path "$path"
    fi
    find_docs "$path"
}

# --- Build deduplicated search path list ---
declare -A _seen=()
_paths=()

add_path() {
    local p="$1"
    [ -d "$p" ] && [ -z "${_seen[$p]}" ] && { _seen["$p"]=1; _paths+=("$p"); }
}

[ -n "$1" ] && add_path "$1"
add_path /home
add_path /var/www
add_path /tmp
add_path /var/tmp
add_path /root

# vsftpd
if [ -f /etc/vsftpd.conf ]; then
    echo "[+] vsftpd detected."
    anon=$(grep -E '^anon_root\s*=' /etc/vsftpd.conf | awk -F= '{print $2}' | tr -d ' ')
    loc=$(grep -E '^local_root\s*=' /etc/vsftpd.conf | awk -F= '{print $2}' | tr -d ' ')
    [ -n "$anon" ] && add_path "$anon"
    [ -n "$loc"  ] && add_path "$loc"
fi

# proftpd
if [ -f /etc/proftpd/proftpd.conf ]; then
    echo "[+] ProFTPD detected."
    dr=$(grep -E '^DefaultRoot' /etc/proftpd/proftpd.conf | awk '{print $2}')
    [ -n "$dr" ] && add_path "$dr"
fi

# samba
if [ -f /etc/samba/smb.conf ]; then
    echo "[+] Samba detected."
    while IFS= read -r share; do
        [ -n "$share" ] && add_path "$share"
    done < <(grep -E '^\s*path\s*=' /etc/samba/smb.conf | awk -F= '{gsub(/[" ]/, "", $2); print $2}')
fi

# --- Run ---
for p in "${_paths[@]}"; do
    echo "[+] Searching $p for PII..."
    search "$p"
done
