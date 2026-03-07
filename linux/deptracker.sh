#!/bin/sh
# deptracker.sh - Maps incoming and outgoing network dependencies
# POSIX compliant for maximum cross-distro compatibility

# 1. Ensure script is run as root
if [ "$(id -u)" -ne 0 ]; then
   echo "[-] Error: This script must be run as root (tcpdump requires elevated privileges)." 
   exit 1
fi

# Configuration and Defaults
INTERFACE=${1:-eth0}
DURATION=${2:-60}
THRESHOLD=${3:-5}

# 2. Gather Local IP and Subnet information (BusyBox/POSIX compatible)
LOCAL_IP=$(ip addr show dev "$INTERFACE" 2>/dev/null | grep -w "inet" | awk '{print $2}' | cut -d/ -f1 | head -n 1)
LOCAL_SUBNET=$(ip route show dev "$INTERFACE" scope link 2>/dev/null | grep -w "$LOCAL_IP" | awk '{print $1}' | head -n 1)

if [ -z "$LOCAL_IP" ] || [ -z "$LOCAL_SUBNET" ]; then
    echo "[-] Could not find an IPv4 address or subnet for interface $INTERFACE."
    echo "Usage: sudo ./dep_tracker.sh <interface> <duration_in_seconds> <threshold>"
    exit 1
fi

echo "[*] Interface: $INTERFACE | Local IP: $LOCAL_IP | Subnet: $LOCAL_SUBNET"
echo "[*] Capturing local subnet traffic for $DURATION seconds..."
echo "[*] Threshold set to: $THRESHOLD occurrences"

TMP_FILE=$(mktemp)

# 3. Run tcpdump in the background
# -l ensures line-buffering so we don't lose data when the process is killed
tcpdump -nn -l -i "$INTERFACE" -q \
    "net $LOCAL_SUBNET and ((tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0) or udp)" \
    > "$TMP_FILE" 2>/dev/null &

TCPDUMP_PID=$!

# Wait for the specified duration
sleep "$DURATION"

# Send SIGINT (Ctrl+C equivalent) to gracefully stop tcpdump
kill -INT $TCPDUMP_PID 2>/dev/null

# Wait for the process to fully close out before moving on
wait $TCPDUMP_PID 2>/dev/null

echo "[*] Capture complete. Processing data..."

# 4. Parse and classify connections using awk
awk -v local_ip="$LOCAL_IP" -v threshold="$THRESHOLD" '
$2 == "IP" {
    src = $3
    dst = $5
    sub(/:$/, "", dst) # Clean up trailing colon from tcpdump output

    # Split IP and Port (tcpdump format: IP.IP.IP.IP.PORT)
    n_src = split(src, s_parts, ".")
    n_dst = split(dst, d_parts, ".")

    # Ensure valid parsing
    if (n_src >= 5 && n_dst >= 5) {
        src_port = s_parts[n_src]
        src_ip = s_parts[1] "." s_parts[2] "." s_parts[3] "." s_parts[4]

        dst_port = d_parts[n_dst]
        dst_ip = d_parts[1] "." d_parts[2] "." d_parts[3] "." d_parts[4]

        # Note IPs/Ports and Classify
        if (src_ip == local_ip) {
            # OUTGOING: Local server is reaching out to a destination
            outgoing[dst_ip ":" dst_port]++
        } else if (dst_ip == local_ip) {
            # INCOMING: Remote system is reaching out to local server
            # Heuristic: Ignore likely ephemeral return ports (>=32768) to keep UDP data clean
            if (dst_port < 32768) {
                incoming[src_ip ":" dst_port]++
            }
        }
    }
}
END {
    # 5. Apply Threshold and List
    print "\n=================================================================="
    print " [OUTGOING] DEPENDENCIES (This server relies on...)"
    print "=================================================================="
    printf "%-25s %-15s %-10s\n", "Remote Target IP", "Target Port", "Occurrences"
    print "------------------------------------------------------------------"
    out_found = 0
    for (target in outgoing) {
        if (outgoing[target] >= threshold) {
            split(target, t, ":")
            printf "%-25s %-15s %-10s\n", t[1], t[2], outgoing[target]
            out_found = 1
        }
    }
    if (out_found == 0) print "None found meeting the threshold."

    print "\n=================================================================="
    print " [INCOMING] DEPENDENCIES (Others rely on this server...)"
    print "=================================================================="
    printf "%-25s %-15s %-10s\n", "Remote Source IP", "Local Port", "Occurrences"
    print "------------------------------------------------------------------"
    in_found = 0
    for (source in incoming) {
        if (incoming[source] >= threshold) {
            split(source, s, ":")
            printf "%-25s %-15s %-10s\n", s[1], s[2], incoming[source]
            in_found = 1
        }
    }
    if (in_found == 0) print "None found meeting the threshold."
    print ""
}' "$TMP_FILE"

# Clean up
rm -f "$TMP_FILE"
