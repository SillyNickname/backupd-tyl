#!/bin/bash
#
# scripts/uninstall.sh - Universal Linux Uninstaller for backupd-tyl
#
# (C) 2026 Antigravity / Gemini (Google DeepMind)
# Part of backupd-tyl (Backupd - Thirty Years Later)
# Requested and Commissioned by: Andre Kajita (kajita@univap.br)
#
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}${RED}=====================================================${NC}"
echo -e "${BOLD}${RED}  backupd-tyl (Backupd - Thirty Years Later) Uninstall ${NC}"
echo -e "${BOLD}${RED}=====================================================${NC}"

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root (or via sudo).${NC}"
    exit 1
fi

# Stop and disable systemd service if running
if pidof systemd >/dev/null 2>&1 || [ -d /run/systemd/system ]; then
    echo -e "${YELLOW}Stopping and disabling systemd service...${NC}"
    systemctl stop backupd-tyl.service 2>/dev/null || true
    systemctl disable backupd-tyl.service 2>/dev/null || true
    rm -f /etc/systemd/system/backupd-tyl.service
    systemctl daemon-reload 2>/dev/null || true
fi

# Stop init.d service if present
if [ -f /etc/init.d/backupd-tyl ]; then
    echo -e "${YELLOW}Stopping init service...${NC}"
    /etc/init.d/backupd-tyl stop 2>/dev/null || true
    if command -v update-rc.d >/dev/null 2>&1; then
        update-rc.d -f backupd-tyl remove 2>/dev/null || true
    elif command -v rc-update >/dev/null 2>&1; then
        rc-update del backupd-tyl default 2>/dev/null || true
    fi
    rm -f /etc/init.d/backupd-tyl
fi

# Remove binaries and symlinks
echo -e "${YELLOW}Removing binaries...${NC}"
rm -f /usr/local/sbin/backupd /usr/local/sbin/backupd-tyl
rm -f /usr/local/bin/backupc /usr/local/bin/backupc-tyl
rm -rf /usr/local/share/doc/backupd-tyl

echo ""
echo -e "${YELLOW}Notice: Configuration in /etc/backupd-tyl/ was PRESERVED.${NC}"
echo -e "To purge configuration files completely, run: ${BOLD}rm -rf /etc/backupd-tyl${NC}"
echo ""
echo -e "${GREEN}backupd-tyl has been uninstalled successfully.${NC}"
