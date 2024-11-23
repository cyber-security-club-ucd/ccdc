#!/bin/bash

echo "What would you like for your new password"
# read -s newPassword # Input is hidden (Don't mess up)
read newPassword

while IFS=: read user _; do
	echo $user
	echo "$user:$newPassword"
done < /etc/passwd
