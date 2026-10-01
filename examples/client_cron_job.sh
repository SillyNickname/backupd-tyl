#!/bin/bash
#
# examples/client_cron_job.sh
#
# Production unattended cron job script for backupd-tyl clients.
# Includes error handling, logging, lock-prevention, and status reporting.
#
# (C) 2026 Antigravity / Gemini (Google DeepMind)
# Part of backupd-tyl (Backupd - Thirty Years Later)
# Requested and Commissioned by: Andre Kajita (kajita@univap.br)
#
set -o pipefail

SERVER_HOST="192.168.1.100"
SERVER_PORT="12153"
RESOURCE="files-archive"
PASSWORD="SecretClusterVaultPassword42"
LOG_FILE="/var/log/backupd-client.log"
LOCK_FILE="/var/run/backupd-cron.lock"

# Avoid concurrent runs
exec 200>"$LOCK_FILE"
flock -n 200 || { echo "$(date): Another backup run is in progress. Exiting." >> "$LOG_FILE"; exit 1; }

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log "Starting unattended backup to $SERVER_HOST:$SERVER_PORT ($RESOURCE)..."

START_TIME=$(date +%s)

# Execute streaming backup with negotiation logging and throughput tracking
if tar --exclude='/tmp/*' --exclude='/proc/*' --exclude='/sys/*' -cpf - /etc /var/data 2>/dev/null | \
   zstd -T0 -3 | \
   backupc -h "$SERVER_HOST" -p "$SERVER_PORT" -P "$PASSWORD" \
           -N "/var/log/backupd-negotiation.log" -T \
           -w "$RESOURCE" >> "$LOG_FILE" 2>&1; then
    DURATION=$(( $(date +%s) - START_TIME ))
    log "Backup completed successfully in ${DURATION}s."
    exit 0
else
    RC=$?
    case $RC in
        3) log "FATAL: Network connection failed to $SERVER_HOST:$SERVER_PORT (TYL_EXIT_NETWORK)" ;;
        4) log "FATAL: Authentication rejected (wrong password or ACL denied) (TYL_EXIT_AUTH)" ;;
        5) log "FATAL: Cryptographic handshake or AEAD decryption error (TYL_EXIT_CRYPTO)" ;;
        7) log "FATAL: Remote resource '$RESOURCE' not found or locked (TYL_EXIT_RESOURCE)" ;;
        *) log "FATAL: Backup failed with exit code $RC" ;;
    esac
    exit $RC
fi
