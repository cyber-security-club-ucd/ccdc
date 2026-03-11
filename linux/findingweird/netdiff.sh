#!/bin/sh
# @d_tranman/Nigel Gerald/Nigerald

CACHE_DIR="/root/.cache"
BASE_LISTEN="$CACHE_DIR/listen"
BASE_ESTAB="$CACHE_DIR/estab"

mkdir -p "$CACHE_DIR"

TMP_LISTEN=$(mktemp)
TMP_ESTAB=$(mktemp)

cleanup() {
	rm -f "$TMP_LISTEN" "$TMP_ESTAB"
}
trap cleanup EXIT INT TERM

collect_listen() {
	if command -v netstat >/dev/null 2>&1; then
		netstat -tlpn
	elif command -v ss >/dev/null 2>&1; then
		ss -plnt
	else
		echo "Error: neither netstat nor ss found" >&2
		return 1
	fi
}

collect_estab() {
	if command -v netstat >/dev/null 2>&1; then
		netstat -tpwn
	elif command -v ss >/dev/null 2>&1; then
		ss -pnt | grep ESTAB
	else
		echo "Error: neither netstat nor ss found" >&2
		return 1
	fi
}

collect_listen | LC_ALL=C sort > "$TMP_LISTEN"
collect_estab | LC_ALL=C sort > "$TMP_ESTAB"

if [ ! -f "$BASE_LISTEN" ] || [ ! -f "$BASE_ESTAB" ]; then
	cp "$TMP_LISTEN" "$BASE_LISTEN"
	cp "$TMP_ESTAB" "$BASE_ESTAB"
	echo "Initialized baseline in $CACHE_DIR. Run again to view diffs."
	exit 0
fi

diff "$BASE_LISTEN" "$TMP_LISTEN"
diff "$BASE_ESTAB" "$TMP_ESTAB"
