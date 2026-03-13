#!/usr/bin/env bash
set -euo pipefail

{
	awk -F: '{print "echo \""$1":\"; crontab -l -u "$1" 2>/dev/null; echo"}' /etc/passwd
	echo "echo Cron.daily etc:"
	echo "find /etc -maxdepth 2 -path \"/etc/cron.*\" -type f -print0 | xargs -0 cat"
} | bash | tee cronstat
