#!/bin/bash
#
# examples/client_zstd_backup.sh
#
# Streaming local directories to a remote backupd-tyl server using tar + zstd
# with high-performance lightweight ASCON-128a encryption.
#
# (C) 2026 Antigravity / Gemini (Google DeepMind)
# Part of backupd-tyl (Backupd - Thirty Years Later)
# Requested and Commissioned by: Andre Kajita (kajita@univap.br)
#
set -e

SERVER_HOST="${1:-192.168.1.100}"
SERVER_PORT="${2:-12153}"
RESOURCE="files-archive"
PASSWORD="SecretClusterVaultPassword42"
SOURCE_DIR="/etc /var/www /home"

echo "=== backupd-tyl: Streaming Archive Backup ==="
echo "Target:   $SERVER_HOST:$SERVER_PORT [$RESOURCE]"
echo "Sources:  $SOURCE_DIR"
echo "Cipher:   ASCON-128a (lightweight, default)"

# Pipe tar archive through zstd compression directly into encrypted backupc client
# Passing -T displays real-time and summary network throughput on stderr
tar --exclude='/home/*/.cache' \
    --exclude='*.tmp' \
    -cpf - $SOURCE_DIR 2>/dev/null | \
    zstd -T0 -3 | \
    backupc -h "$SERVER_HOST" -p "$SERVER_PORT" -P "$PASSWORD" -T -w "$RESOURCE"

RC=$?
if [ $RC -eq 0 ]; then
    echo "Backup stream completed successfully."
else
    echo "Backup failed with exit code $RC"
    exit $RC
fi
