#!/bin/bash
(awk -F: '{print "echo \""$1":\"; crontab -l -u "$1"; echo"}' /etc/passwd; echo "echo Cron.daily etc:"; echo "find /etc -maxdepth 2 -path \"/etc/cron.*\" -type f -print0 | xargs -0 cat")| sudo bash | tee cronstat
