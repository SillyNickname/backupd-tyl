#!/bin/bash
#
# examples/client_mysql_stream.sh
#
# Streaming MySQL/MariaDB database dump to a remote backupd-tyl server using
# Speck-128/128-Poly1305 lightweight cipher (-c speck).
#
# (C) 2026 Antigravity / Gemini (Google DeepMind)
# Part of backupd-tyl (Backupd - Thirty Years Later)
# Requested and Commissioned by: Andre Kajita (kajita@univap.br)
#
set -e

SERVER_HOST="${1:-10.0.1.10}"
SERVER_PORT="${2:-12153}"
RESOURCE="database-mysql"
PASSWORD="MariaDbBackupAuth2026!"
DB_NAME="production"

echo "=== backupd-tyl: MySQL/MariaDB Streaming Backup ==="
echo "Database: $DB_NAME"
echo "Target:   $SERVER_HOST:$SERVER_PORT [$RESOURCE]"
echo "Security: Speck-128/128-Poly1305 lightweight mode"

# Dump all tables with transactional consistency, compress with zstd, and stream
mariadb-dump --single-transaction --quick -u backup -pSecretPass "$DB_NAME" | \
    zstd -T0 -4 | \
    backupc -h "$SERVER_HOST" -p "$SERVER_PORT" -c speck -P "$PASSWORD" -w "$RESOURCE"

echo "MySQL/MariaDB backup stream completed successfully."
