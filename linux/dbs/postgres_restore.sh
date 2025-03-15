#!/bin/bash

# Set variables
DB_USER="postgres"
BACKUP_FILE="$HOME/sop/backups/postgres_backup.sql"

# note if this is getting too much create the file .pgpass in home (~/) directory with the following line:
# "localhost:5432:*:postgres:<password>"
# This will make it so psql doesn't prompt for password each time
sudo psql -U postgres -W -f $BACKUP_FILE

mkdir -p $HOME/restore_logs

echo "MySQL database restored from backup at $(date)" >> $HOME/restore_logs/postgres_restore.log
