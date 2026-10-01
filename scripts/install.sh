#!/bin/bash
#
# scripts/install.sh - Universal Linux Installation Script for backupd-tyl
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

echo -e "${BOLD}${BLUE}=====================================================${NC}"
echo -e "${BOLD}${BLUE}  backupd-tyl (Backupd - Thirty Years Later) Installer${NC}"
echo -e "${BOLD}${BLUE}=====================================================${NC}"

# Parse command-line options
USE_PRECOMPILED="${USE_PRECOMPILED:-0}"
for arg in "$@"; do
    case "$arg" in
        -p|--precompiled)
            USE_PRECOMPILED=1
            ;;
        -h|--help)
            echo "Usage: $0 [--precompiled|-p]"
            echo "Options:"
            echo "  -p, --precompiled   Install pre-compiled standalone binaries from bin/ (zero dependencies, no build tools needed)"
            exit 0
            ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root (or via sudo).${NC}"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Detect distribution
DISTRO="unknown"
INIT_SYS="unknown"

if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO="$ID"
elif [ -f /etc/centos-release ]; then
    DISTRO="centos"
    PRETTY_NAME=$(cat /etc/centos-release)
elif [ -f /etc/redhat-release ]; then
    DISTRO="rhel"
    PRETTY_NAME=$(cat /etc/redhat-release)
elif [ -f /etc/debian_version ]; then
    DISTRO="debian"
    PRETTY_NAME="Debian $(cat /etc/debian_version)"
fi

if pidof systemd >/dev/null 2>&1 || [ -d /run/systemd/system ]; then
    INIT_SYS="systemd"
elif [ -x /sbin/openrc-run ] || [ -d /etc/runlevels ]; then
    INIT_SYS="openrc"
elif [ -d /etc/init.d ]; then
    INIT_SYS="sysvinit"
fi

echo -e "${BLUE}Detected OS distribution:${NC} $DISTRO ($PRETTY_NAME)"
echo -e "${BLUE}Detected Init System:    ${NC} $INIT_SYS"
echo ""

if [ "$USE_PRECOMPILED" -eq 1 ]; then
    echo -e "${GREEN}Pre-compiled installation selected (--precompiled).${NC}"
    echo -e "  -> Using standalone binaries from bin/ with zero external dependencies (no local compilation needed)."
    echo ""
    echo -e "${YELLOW}[1/5] Verifying pre-compiled binaries in bin/...${NC}"
    if [ ! -f "$REPO_DIR/bin/backupd" ] || [ ! -f "$REPO_DIR/bin/backupc" ]; then
        echo -e "${RED}Error: Pre-compiled binaries not found in $REPO_DIR/bin/.${NC}" >&2
        exit 1
    fi
    SRC_BACKUPD="$REPO_DIR/bin/backupd"
    SRC_BACKUPC="$REPO_DIR/bin/backupc"
    echo -e "  Verified ${GREEN}$SRC_BACKUPD${NC} and ${GREEN}$SRC_BACKUPC${NC}"
else
    # Check for package-managed security dependencies
    HAS_SSL_DEV=0
    SSL_TOO_OLD=0
    SSL_VER_TEXT=""

    if printf '%s\n' '#include <openssl/opensslv.h>' | gcc -E - >/dev/null 2>&1; then
        SSL_VER_TEXT=$(printf '%s\n' '#include <openssl/opensslv.h>' | gcc -E -dM -x c - 2>/dev/null | grep -m1 "OPENSSL_VERSION_TEXT" | cut -d'"' -f2)
        if printf '%s\n' '#include <openssl/opensslv.h>' '#if defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER >= 0x10101000L)' 'int main(void){return 0;}' '#else' '#error "too old"' '#endif' | gcc -x c - -o /dev/null -lcrypto >/dev/null 2>&1; then
            HAS_SSL_DEV=1
        else
            SSL_TOO_OLD=1
        fi
    fi

    if [ "$HAS_SSL_DEV" -eq 1 ]; then
        echo -e "${GREEN}Security dependencies: System OpenSSL ($SSL_VER_TEXT) detected (>= 1.1.1 baseline).${NC}"
        echo -e "  -> Build will link against package-managed libcrypto with hardware acceleration (AES-NI / AVX)."
    elif [ "$SSL_TOO_OLD" -eq 1 ]; then
        echo -e "${YELLOW}Security dependencies: Local system OpenSSL ($SSL_VER_TEXT) is older than package baseline (1.1.1).${NC}"
        echo -e "  -> Automatically using the cryptographic library included with the package (zero external dependencies)."
    else
        echo -e "${YELLOW}Security dependencies: System OpenSSL / libcrypto development headers not found.${NC}"
        echo -e "  -> You can install the security package using your distribution's package manager:"
        case "$DISTRO" in
            ubuntu|debian|linuxmint|pop)
                echo -e "     ${BOLD}apt-get install -y libssl-dev${NC}"
                ;;
            fedora|rhel|centos|rocky|alma)
                echo -e "     ${BOLD}dnf install -y openssl-devel${NC}"
                ;;
            arch|manjaro)
                echo -e "     ${BOLD}pacman -S --noconfirm openssl${NC}"
                ;;
            alpine)
                echo -e "     ${BOLD}apk add openssl-dev${NC}"
                ;;
            opensuse*|sles)
                echo -e "     ${BOLD}zypper install -y libopenssl-devel${NC}"
                ;;
            *)
                echo -e "     Install your distribution's OpenSSL / libcrypto development package."
                ;;
        esac
        echo -e "  -> Proceeding seamlessly using internal local bundled cryptographic engine (zero external dependencies)."
    fi
    echo ""

    # 1. Compile binaries if needed
    echo -e "${YELLOW}[1/5] Building backupd-tyl binaries...${NC}"
    make -C "$REPO_DIR" all
    SRC_BACKUPD="$REPO_DIR/backupd"
    SRC_BACKUPC="$REPO_DIR/backupc"
fi

# 2. Install binaries
echo -e "${YELLOW}[2/5] Installing binaries...${NC}"
install -d -m 0755 /usr/local/sbin
install -d -m 0755 /usr/local/bin
install -m 0755 "$SRC_BACKUPD" /usr/local/sbin/backupd
install -m 0755 "$SRC_BACKUPC" /usr/local/bin/backupc
ln -sf /usr/local/sbin/backupd /usr/local/sbin/backupd-tyl
ln -sf /usr/local/bin/backupc /usr/local/bin/backupc-tyl
echo -e "  Installed ${GREEN}/usr/local/sbin/backupd${NC}"
echo -e "  Installed ${GREEN}/usr/local/bin/backupc${NC}"

# 3. Create configuration directory & sample
echo -e "${YELLOW}[3/5] Setting up configuration...${NC}"
install -d -m 0750 /etc/backupd-tyl
if [ ! -f /etc/backupd-tyl/backupd.conf ]; then
    install -m 0640 "$REPO_DIR/backupd.conf.sample" /etc/backupd-tyl/backupd.conf
    echo -e "  Created initial config: ${GREEN}/etc/backupd-tyl/backupd.conf${NC}"
else
    echo -e "  Existing configuration preserved: ${BLUE}/etc/backupd-tyl/backupd.conf${NC}"
fi

# 4. Create dedicated service user/group if desired
if ! id backup >/dev/null 2>&1; then
    echo -e "  Creating system user 'backup'..."
    if command -v useradd >/dev/null 2>&1; then
        useradd -r -s /sbin/nologin -d /var/backups backup 2>/dev/null || true
    elif command -v adduser >/dev/null 2>&1; then
        adduser -S -D -H -h /var/backups -s /sbin/nologin backup 2>/dev/null || true
    fi
fi
install -d -m 0755 /var/backups

# 5. Service unit installation
echo -e "${YELLOW}[4/5] Installing service daemon unit...${NC}"
if [ "$INIT_SYS" = "systemd" ]; then
    install -m 0644 "$REPO_DIR/systemd/backupd-tyl.service" /etc/systemd/system/backupd-tyl.service
    systemctl daemon-reload
    systemctl enable backupd-tyl.service
    echo -e "  ${GREEN}Enabled systemd service:${NC} backupd-tyl.service"
    echo -e "  Start service with:   ${BOLD}systemctl start backupd-tyl${NC}"
    echo -e "  Check service with:   ${BOLD}systemctl status backupd-tyl${NC}"
elif [ "$INIT_SYS" = "openrc" ]; then
    install -m 0755 "$REPO_DIR/init.d/backupd-tyl" /etc/init.d/backupd-tyl
    rc-update add backupd-tyl default 2>/dev/null || true
    echo -e "  ${GREEN}Installed OpenRC service:${NC} /etc/init.d/backupd-tyl"
    echo -e "  Start service with:   ${BOLD}rc-service backupd-tyl start${NC}"
elif [ "$INIT_SYS" = "sysvinit" ]; then
    install -m 0755 "$REPO_DIR/init.d/backupd-tyl" /etc/init.d/backupd-tyl
    if command -v update-rc.d >/dev/null 2>&1; then
        update-rc.d backupd-tyl defaults
    elif command -v chkconfig >/dev/null 2>&1; then
        chkconfig --add backupd-tyl
    fi
    echo -e "  ${GREEN}Installed SysVinit service:${NC} /etc/init.d/backupd-tyl"
    echo -e "  Start service with:   ${BOLD}/etc/init.d/backupd-tyl start${NC}"
fi

# 6. Documentation
echo -e "${YELLOW}[5/5] Installing documentation...${NC}"
install -d -m 0755 /usr/local/share/doc/backupd-tyl
if [ -f "$REPO_DIR/MANUAL.md" ]; then
    install -m 0644 "$REPO_DIR/MANUAL.md" /usr/local/share/doc/backupd-tyl/MANUAL.md
fi
if [ -f "$REPO_DIR/README.md" ]; then
    install -m 0644 "$REPO_DIR/README.md" /usr/local/share/doc/backupd-tyl/README.md
fi

echo ""
echo -e "${BOLD}${GREEN}=====================================================${NC}"
echo -e "${BOLD}${GREEN}  backupd-tyl installation completed successfully!    ${NC}"
echo -e "${BOLD}${GREEN}=====================================================${NC}"
echo -e "Server Daemon:     /usr/local/sbin/backupd (port 12153)"
echo -e "Client Tool:       /usr/local/bin/backupc"
echo -e "Configuration:     /etc/backupd-tyl/backupd.conf"
echo -e "Documentation:     /usr/local/share/doc/backupd-tyl/MANUAL.md"
echo ""
