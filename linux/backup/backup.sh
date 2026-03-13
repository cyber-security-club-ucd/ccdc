#!/bin/bash
# databack.sh
# Unified backup/restore tool for LDAP, MySQL, and PostgreSQL.
#
# Usage: ./databack.sh

sep()      { echo "==============================================="; }
dash_sep() { echo "-----------------------------------------------"; }

# Default hidden backup directory with hardened permissions
DEFAULT_BACKUP_DIR="/root/.databack"
mkdir -p "$DEFAULT_BACKUP_DIR"
chown root:root "$DEFAULT_BACKUP_DIR"
chmod 700 "$DEFAULT_BACKUP_DIR"

# ─── Ask: Backup or Restore ───────────────────────────────────────────────────
echo "What would you like to do?"
echo "  1) Backup"
echo "  2) Restore"
read -rp "Enter choice [1/2]: " MODE_CHOICE

case "$MODE_CHOICE" in
    1) MODE="backup" ;;
    2) MODE="restore" ;;
    *) echo "Invalid choice." >&2; exit 1 ;;
esac

# ─── Ask: What to backup/restore ─────────────────────────────────────────────
echo ""
echo "What would you like to $MODE?"
echo "  1) LDAP"
echo "  2) MySQL"
echo "  3) PostgreSQL"
read -rp "Enter choice [1/2/3]: " TYPE_CHOICE

case "$TYPE_CHOICE" in
    1) TYPE="ldap" ;;
    2) TYPE="mysql" ;;
    3) TYPE="psql" ;;
    *) echo "Invalid choice." >&2; exit 1 ;;
esac

# ─── LDAP ─────────────────────────────────────────────────────────────────────
ldap_backup() {
    BACKUP_PATH="$DEFAULT_BACKUP_DIR/ldap"
    SLAPCAT=/usr/sbin/slapcat

    echo "Backing up LDAP to $BACKUP_PATH..."
    mkdir -p "$BACKUP_PATH"
    chown root:root "$BACKUP_PATH"
    chmod 700 "$BACKUP_PATH"
    nice "$SLAPCAT" -b cn=config > "$BACKUP_PATH/config.ldif"
    nice "$SLAPCAT" -b dc=example,dc=com > "$BACKUP_PATH/example.com.ldif"
    chown root:root "$BACKUP_PATH"/*.ldif
    chmod 600 "$BACKUP_PATH"/*.ldif
    echo "LDAP backup complete. Files in $BACKUP_PATH"
}

ldap_restore() {
    BACKUP_PATH="$DEFAULT_BACKUP_DIR/ldap"
    SLAPADD=/usr/sbin/slapadd

    if ! command -v "$SLAPADD" &>/dev/null; then
        echo "Error: slapadd not found." >&2; exit 1
    fi

    echo "Restoring LDAP from $BACKUP_PATH..."
    echo "WARNING: Stop slapd before restoring. Is slapd stopped? [y/N]"
    read -rp "> " confirm
    [[ "$confirm" != [yY] ]] && echo "Aborted." && exit 0

    "$SLAPADD" -b cn=config -l "$BACKUP_PATH/config.ldif"
    "$SLAPADD" -b dc=example,dc=com -l "$BACKUP_PATH/example.com.ldif"
    echo "LDAP restore complete."
}

# ─── MySQL ────────────────────────────────────────────────────────────────────
mysql_backup() {
    read -rp "MySQL user: " MYSQL_USER
    read -rsp "MySQL password: " MYSQL_PASSWORD; echo
    DATA_PATH="$DEFAULT_BACKUP_DIR/mysql"

    mkdir -p "$DATA_PATH"
    chown root:root "$DATA_PATH"
    chmod 700 "$DATA_PATH"
    cd "$DATA_PATH" || exit 1

    sep
    echo "MySQL Backup"
    sep
    echo "Using local MySQL server on this machine."

    databases=$(mysql -u "$MYSQL_USER" --password="$MYSQL_PASSWORD" \
        -e "SHOW DATABASES;" | tr -d "| " | grep -v Database)

    for db in $databases; do
        if [[ "$db" != "information_schema" ]] && [[ "$db" != "performance_schema" ]] \
            && [[ "$db" != "mysql" ]] && [[ "$db" != _* ]]; then
            echo "Dumping: $db"
            mysqldump -u "$MYSQL_USER" --password="$MYSQL_PASSWORD" \
                --databases "$db" > "$db.sql"
            chmod 600 "$db.sql"
        fi
    done

    echo "MySQL backup complete. Files in $DATA_PATH"
}

mysql_restore() {
    read -rp "MySQL user: " MYSQL_USER
    read -rsp "MySQL password: " MYSQL_PASSWORD; echo
    DATA_PATH="$DEFAULT_BACKUP_DIR/mysql"

    sep
    echo "MySQL Restore"
    sep
    echo "Using local MySQL server on this machine."

    for sqlfile in "$DATA_PATH"/*.sql; do
        db=$(basename "$sqlfile" .sql)
        echo "Restoring: $db"
        mysql -u "$MYSQL_USER" --password="$MYSQL_PASSWORD" \
            -e "CREATE DATABASE IF NOT EXISTS \`$db\`;"
        mysql -u "$MYSQL_USER" --password="$MYSQL_PASSWORD" "$db" < "$sqlfile"
    done

    echo "MySQL restore complete."
}

# ─── PostgreSQL ───────────────────────────────────────────────────────────────
psql_backup() {
    read -rp "PostgreSQL user: " PSQL_USER
    read -rsp "PostgreSQL password: " PGPASSWORD; echo
    export PGPASSWORD
    DATA_PATH="$DEFAULT_BACKUP_DIR/psql"

    mkdir -p "$DATA_PATH"
    chown root:root "$DATA_PATH"
    chmod 700 "$DATA_PATH"
    cd "$DATA_PATH" || exit 1

    sep
    echo "PostgreSQL Backup"
    sep
    echo "Using local PostgreSQL server on this machine."

    psql -U "$PSQL_USER" -t \
        -c "SELECT datname FROM pg_database WHERE datistemplate = false;" \
        | sed '/^$/d' | awk '{print $1}' > database_list.txt

    echo "Databases found:"; cat database_list.txt
    dash_sep

    while IFS= read -r db; do
        echo "Dumping: $db"
        pg_dump -U "$PSQL_USER" -d "$db" > "$db.sql"
        chmod 600 "$db.sql"
    done < database_list.txt

    echo "PostgreSQL backup complete. Files in $DATA_PATH"
}

psql_restore() {
    read -rp "PostgreSQL user: " PSQL_USER
    read -rsp "PostgreSQL password: " PGPASSWORD; echo
    export PGPASSWORD
    DATA_PATH="$DEFAULT_BACKUP_DIR/psql"

    sep
    echo "PostgreSQL Restore"
    sep
    echo "Using local PostgreSQL server on this machine."

    for sqlfile in "$DATA_PATH"/*.sql; do
        db=$(basename "$sqlfile" .sql)
        echo "Restoring: $db"
        psql -U "$PSQL_USER" \
            -c "CREATE DATABASE \"$db\";" 2>/dev/null || true
        psql -U "$PSQL_USER" -d "$db" < "$sqlfile"
    done

    echo "PostgreSQL restore complete."
}

# ─── Dispatch ─────────────────────────────────────────────────────────────────
echo ""
sep
"${TYPE}_${MODE}"
