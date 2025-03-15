#!/bin/bash

# Set variables
DB_USER="root"
BACKUP_FILE="$HOME/sop/backups/mysql_backup.sql"

# Restore MySQL database (assumes no password prompt)
sudo mysql -u "$DB_USER" -p < "$BACKUP_FILE"

mkdir -p $HOME/restore_logs

echo "MySQL database restored from backup at $(date)" >> $HOME/restore_logs/mysql_restore.log
