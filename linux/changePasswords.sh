#!/bin/bash

echo "What would you like for your new password"
# read -s newPassword # Input is hidden (Don't mess up)
read newPassword

while IFS=: read user _; do
	echo "$user:$newPassword" | chpasswd

	if [ $? -eq 0 ]; then
		echo "$user password changed"
	else
		echo "$user failed"
	fi
done < /etc/passwd
