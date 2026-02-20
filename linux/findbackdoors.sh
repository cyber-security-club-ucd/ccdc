#!/bin/bash
hashfile=$(readlink -f ./PhpBackdoorHashes.txt)
regexfile=$(readlink -f ./PhpBackdoorRegexes.txt)
extraregexfile=$(readlink -f ./AggressivePhpBackdoorRegexes.txt)
if [[ $# -ge 1 ]]; then
    cd "$1"
fi
echo "SHA1 hits:"
# SHA1 hash list
find -name "*.php" -exec sha1sum {} + | grep -f "$hashfile" | awk 'BEGIN {"pwd" | getline cwd; close("pwd");} {print cwd"/"$2}' | sed 's#/./#/#' # TODO doesn't work with space filenames
echo "Regex hits:"
find -name "*.php" -print0 | xargs -0 grep -a -E -f "$regexfile" | awk -F: 'BEGIN {"pwd" | getline cwd; close("pwd");} {print cwd"/"$1}' | sed 's#/./#/#' | uniq # shouldn't need sort because same file results will be adjacent
echo "Broader-case regex hits:"
find -name "*.php" -print0 | xargs -0 grep -a -E -f "$extraregexfile" | awk -F: 'BEGIN {"pwd" | getline cwd; close("pwd");} {print cwd"/"$1}' | sed 's#/./#/#' | uniq # shouldn't need sort because same file results will be adjacent
