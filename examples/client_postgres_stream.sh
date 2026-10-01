#!/bin/bash
#
# examples/client_postgres_stream.sh
#
# Streaming PostgreSQL database dump to a remote backupd-tyl server using
# ChaCha20-Poly1305 high-security mode (-s / --secure).
#
# (C) 2026 Antigravity / Gemini (Google DeepMind)
# Part of backupd-tyl (Backupd - Thirty Years Later)
# Requested and Commissioned by: Andre Kajita (kajita@univap.br)
#
set -e

SERVER_HOST="${1:-10.0.1.10}"
SERVER_PORT="${2:-12153}"
RESOURCE="database-postgres"
PASSWORD="PgSqlBackupAuth2026!"
DB_NAME="production_db"

echo "=== backupd-tyl: PostgreSQL Streaming Backup ==="
echo "Database: $DB_NAME"
echo "Target:   $SERVER_HOST:$SERVER_PORT [$RESOURCE]"
echo "Security: ChaCha20-Poly1305 (RFC 8439 high-security mode)"

# Generate binary custom-format dump, compress with zstd, and stream encrypted
pg_dump -Fc -U postgres "$DB_NAME" | \
    zstd -T0 -4 | \
    backupc -h "$SERVER_HOST" -p "$SERVER_PORT" -s -P "$PASSWORD" -w "$RESOURCE"

echo "PostgreSQL backup stream completed successfully."
