echo
echo Finding tarballs and executables in homedirs
echo These files usually warrant investigation
echo
sudo find /home -type f \( -name "*.tar.*" -o -executable \) | tee -a prohibfilestat
echo
echo Finding globally-writeable files and directories - output in ./globalwritefilestat
echo These files definitely warrant investigation
echo
sudo find / \( \( -path '/dev*' -o -path '/proc*' -o -path '/sys*' \) -prune \) -o \( -type f -o -type d \) -perm /0002 -exec ls -ld {} + | tee globalwritefilestat
echo
echo Finding setuid and setgid files - output in ./setuidfilestat
echo This list warrants looking at
echo
sudo find / \( \( -path '/dev*' -o -path '/proc*' -o -path '/sys*' \) -prune \) -o \( -type f -o -type d \) -perm /7000 -exec ls -ld {} + | tee setuidfilestat
echo
echo Finding files with ACLs - output in ./aclfilestat
echo This list warrants looking at
echo
sudo getfacl -R -s -p / | sed -n 's@: //@: /@;s@^# file: @@p' | sort | tee aclfilestat | grep -vE '^/(var|run)/log/journal/'
echo

