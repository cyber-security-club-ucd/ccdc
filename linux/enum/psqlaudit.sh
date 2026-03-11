#!/bin/sh

if [ "$(id -u)" -ne 0 ]; then
    printf 'Must be run as root, exiting!\n'
    exit 1
fi

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <psql_user> <psql_password>"
    exit 1
fi



PSQL_USER="$1"
export PGPASSWORD="$2"
PSQL_HOST="localhost"
DATA_PATH="/root/.psqlaudit"
echo "PSQL Auditing"


mkdir -p "$DATA_PATH"
chown root:root "$DATA_PATH"
chmod 700 "$DATA_PATH"
cd "$DATA_PATH"

# List all databases
psql -h "$PSQL_HOST" -U "$PSQL_USER" -t -c "SELECT datname FROM pg_database WHERE datistemplate = false;" | sed '/^$/d' | awk '{print $1}' > database_list.txt

echo "List of Databases:"
cat database_list.txt

while read selected_db; do
    
    psql -h "$PSQL_HOST" -U "$PSQL_USER" "$selected_db" -c "
    SELECT grantor,grantee,table_name,privilege_type,is_grantable,with_hierarchy
    FROM information_schema.role_table_grants WHERE table_catalog='${selected_db}' AND table_schema = 'public';" > "$selected_db.txt"
done <database_list.txt

echo "PSQL Auditing finished. Results saved to $DATA_PATH"

