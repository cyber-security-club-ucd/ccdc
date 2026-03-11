#!/bin/bash
# setuid/setgid scanner with danger flag

echo "Scanning for setUID/setGID files..."
echo "Files flagged as [DANGER] are either not owned by root or in unusual locations." >&2
echo

sudo find / \( \( -path '/dev*' -o -path '/proc*' -o -path '/sys*' \) -prune \) \
  -o -type f -perm /7000 -printf '%p\t%u:%g\t%M\n' | sort | while IFS=$'\t' read -r file ownerperms perms; do
    danger=""
    
    # Split owner:group
    owner=$(echo "$ownerperms" | cut -d: -f1)
    group=$(echo "$ownerperms" | cut -d: -f2)
    
    # Flag if not root-owned
    if [ "$owner" != "root" ]; then
        danger="[DANGER: Non-root owned]"
    fi

    # Flag if file is in /tmp, /home, /var/tmp
    if [[ "$file" == /tmp/* ]] || [[ "$file" == /var/tmp/* ]] || [[ "$file" == /home/* ]]; then
        danger="[DANGER: User-writable path]"
    fi

    # Print file info
    if [ -n "$danger" ]; then
        echo -e "$file\t$owner:$group\t$perms\t$danger"
    else
        echo -e "$file\t$owner:$group\t$perms"
    fi
done