#!/bin/sh
if [ $(whoami) != root ]; then
    echo "Root privileges required"
    exit 1
fi

backup_time=$(TZ=America/Los_Angeles date +"%Y%m%d-%H%M%S")
backup_dir=backup.$backup_time

mkdir $backup_dir
cleanup() {
    rm -rf $backup_dir
}
trap cleanup EXIT

backup_targets="/etc /var /home /srv /opt"
for target in $backup_targets; do
    if [ -d $target ]; then
        cp -a $target $backup_dir
    fi
done

backup_archive=backup.$backup_time.tar.gz
tar -czf $backup_archive $backup_dir
ls -lah $backup_archive