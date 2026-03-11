#!/usr/bin/env bash
# Secure php.ini files

if [ "$EUID" -ne 0 ]; then echo "Please run as root"; exit 1; fi

set_php_ini() {
	local ini="$1"
	local key="$2"
	local value="$3"
	if grep -Eq "^[;[:space:]]*${key}[[:space:]]*=" "$ini"; then
		sed -i "s|^[;[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "$ini"
	else
		echo "${key} = ${value}" >> "$ini"
	fi
}

find / -name "php.ini" -type f -print0 2>/dev/null | while IFS= read -r -d '' ini; do
	echo "[+] Writing php.ini options to $ini..."
	cp -a "$ini" "${ini}.bak"
	set_php_ini "$ini" "disable_functions" "shell_exec, exec, passthru, proc_open, popen, system, phpinfo"
	set_php_ini "$ini" "max_execution_time" "3"
	set_php_ini "$ini" "register_globals" "off"
	set_php_ini "$ini" "magic_quotes_gpc" "on"
	set_php_ini "$ini" "allow_url_fopen" "off"
	set_php_ini "$ini" "allow_url_include" "off"
	set_php_ini "$ini" "display_errors" "off"
	set_php_ini "$ini" "short_open_tag" "off"
	set_php_ini "$ini" "session.cookie_httponly" "1"
	set_php_ini "$ini" "session.use_only_cookies" "1"
	set_php_ini "$ini" "session.cookie_secure" "1"
done
