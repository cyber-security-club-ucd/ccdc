#!/bin/bash
# finddefaultpass.sh
# Reads hosts from /etc/hosts and tests a default password against each via SSH.
#
# Usage: ./finddefaultpass.sh DEFAULT_PASS

LOG_FILE="pass_check.log"

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 DEFAULT_PASS" >&2
    exit 1
fi

DEFAULT_PASS="$1"

if ! command -v sshpass &>/dev/null; then
    echo "Error: 'sshpass' is required but not installed." >&2
    exit 1
fi

# Pull all real usernames from /etc/passwd (UID >= 1000, plus root)
USERS=$(awk -F: '($3 == 0 || $3 >= 1000) && $1 != "nobody" {print $1}' /etc/passwd)

# Pull IPs from /etc/hosts, skipping comments, blank lines, and localhost
HOSTS=$(awk '!/^#/ && !/^[[:space:]]*$/ && $1 !~ /^127\./ && $1 != "::1" {print $1}' /etc/hosts)

if [[ -z "$HOSTS" ]]; then
    echo "No hosts found in /etc/hosts."
    exit 0
fi

output=""

while IFS= read -r ip; do
    while IFS= read -r user; do
        name="${user}@${ip}"

        sshpass -p "$DEFAULT_PASS" ssh \
            -o StrictHostKeyChecking=no \
            -o ConnectTimeout=5 \
            -o BatchMode=no \
            "$name" exit &>/dev/null

        if [[ $? -eq 0 ]]; then
            output+="SUCCESS ON ${name}"$'\n'
        else
            output+="FAILED ON ${name}"$'\n'
        fi
    done <<< "$USERS"
done <<< "$HOSTS"

printf '%s' "$output" | tee "$LOG_FILE"
