# backupd-tyl (Backupd - Thirty Years Later)

[![Build and Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](#testing)
[![C Standard](https://img.shields.io/badge/C-C99-blue.svg)](#requirements)
[![License: GPL v2+](https://img.shields.io/badge/License-GPL%20v2%2B-blue.svg)](LICENSE)
[![Zero External Dependencies](https://img.shields.io/badge/dependencies-none-success.svg)](#features)
[![GitHub Repository](https://img.shields.io/badge/GitHub-SillyNickname%2Fbackupd--tyl-181717.svg?logo=github)](https://github.com/SillyNickname/backupd-tyl)

A modern, lightweight, security-hardened remote streaming backup system for Linux.

Based on the original 1998 `backupd` software by **Ullrich von Bassewitz**, requested and commissioned by **Andre Kajita** (`kajita@univap.br`), and modernized thirty years later in 2026 by **Antigravity / Gemini (Google DeepMind)**.

---

## Highlights & Features

- **TLS-Style Ephemeral Cryptography On-The-Fly**:
  - Ephemeral Curve25519 (X25519) Diffie-Hellman key exchange per session.
  - Session key derivation via HKDF-SHA256 (RFC 5869).
  - Authenticated Encryption with Associated Data (AEAD) frame encapsulation.
- **Lightweight & High-Security Cipher Suites**:
  - **ASCON-128a** (NIST Lightweight Cryptography standard, default, lowest CPU overhead).
  - **Speck-128/128-Poly1305** (High-throughput NSA lightweight block cipher with Poly1305 MAC).
  - **ChaCha20-Poly1305** (RFC 8439 256-bit high security mode via `-s` / `--secure`).
  - **XChaCha20-Poly1305** (192-bit extended nonce mode, eliminating nonce collision risk for massive multi-terabyte continuous stream backups).
  - **AES-256-GCM** (NIST SP 800-38D 256-bit AEAD gold standard, hardware/AES-NI accelerated via system crypto or pure C).
  - **AES-128-GCM** (NIST SP 800-38D 128-bit AEAD high-speed standard).
- **Dual-Engine Cryptography (Package-Managed or Standalone Pure-C)**:
  - Supports system `libcrypto` (OpenSSL 1.1 / 3.x) with hardware acceleration (AES-NI, AVX) kept up-to-date by your OS package manager (`apt`, `dnf`, `pacman`, `apk`, `zypper`).
  - Automatically falls back to 100% self-contained local bundled C implementations when system development libraries are absent.
  - Zero required external dependencies (< 110KB binary footprint in pure-C mode).
- **Pre-Cryptographic Defense-in-Depth Authentication**:
  - Per-resource shared password verified *before* cryptographic handshake to eliminate CPU exhaustion DoS attacks on asymmetric math.
- **Enterprise Server Logging Subsystem**:
  - Configurable logging targets: dedicated log file (`/var/log/backupd-tyl.log`), system logging (`syslog`, `rsyslogd`, `syslog-ng`, `systemd-journald`), or `stderr`.
  - Five verbosity thresholds (`debug`, `info`, `notice`, `warn`, `err`).
  - Seamless `logrotate` support with `SIGHUP` reload.
- **Client Observability & Metrics**:
  - **Negotiation Logging** (`-N, --log-negotiation <stdout|stderr|file>`): Step-by-step audit tracing of the cryptographic handshake.
  - **Throughput Monitoring** (`-T, --throughput`): Real-time rate and completion summary in MB/s on stderr (completely silent by default).
- **Standard Process Exit Codes**:
  - Standardized exit codes (0 to 9) allowing orchestration scripts to differentiate network, authentication, crypto, and resource errors.
- **Modern Configuration Engine**:
  - Multi-line pipelines with backslash `\`, curly brace blocks `{ ... }`, and sequential lines.
  - Unified `Allow` and `Deny` ACL model with per-resource inheritance and overrides.
- **Standalone Service Daemon**:
  - Runs natively as a standalone service listening on TCP port 12153, foreground systemd supervisor, or traditional `inetd`/socket activation.
  - Full distribution packages and installation scripts for Ubuntu/Debian, RHEL/CentOS/Fedora/Rocky/Alma, Arch, Alpine, and openSUSE.
- **Zero External Dependencies**:
  - Pure C99, 64-bit clean, standard POSIX. No OpenSSL, GnuTLS, or external crypto libraries needed. Tiny footprint (< 105KB binary).
- **Backward Compatibility**:
  - Retains client switch (`-L` / `--legacy`) to communicate with unencrypted 1998 v0.20 installations.

---

## Architecture

```
+-------------------------------------------------------------+
| CLIENT (backupc)                                            |
| Reads/writes data from standard input/output                |
| Pipes directly to/from tar, zstd, pg_dump, etc.             |
| Optional live throughput (-T) and negotiation log (-N)     |
+------------------------------+------------------------------+
                               |
                   [AEAD Encrypted TCP Stream]
                    (Port 12153, Curve25519)
                               |
+------------------------------v------------------------------+
| SERVER (backupd)                                            |
| Standalone service daemon with PID management & ACL checks  |
| File/syslog logging engine with logrotate SIGHUP reload     |
| Pipes stream to/from configured local subprocesses          |
+-------------------------------------------------------------+
```

---

## Standard Process Exit Codes

| Code | Name | Description |
|---|---|---|
| **0** | `TYL_EXIT_SUCCESS` | Command completed successfully with verified AEAD integrity. |
| **1** | `TYL_EXIT_USAGE` | Invalid command-line arguments or syntax. |
| **2** | `TYL_EXIT_CONFIG` | Configuration file error or missing directive. |
| **3** | `TYL_EXIT_NETWORK` | Connection refused, host unreachable, or network timeout. |
| **4** | `TYL_EXIT_AUTH` | Missing or incorrect shared password, or client IP rejected by ACL. |
| **5** | `TYL_EXIT_CRYPTO` | Ephemeral key exchange failed or AEAD tag verification failure. |
| **6** | `TYL_EXIT_IO` | Local pipe broken, disk full, or stdin/stdout I/O error. |
| **7** | `TYL_EXIT_RESOURCE` | Resource not found in configuration or lockfile held. |
| **8** | `TYL_EXIT_PERMISSION` | Insufficient OS privileges / setuid error. |
| **9** | `TYL_EXIT_SIGNAL` | Process terminated by signal (SIGTERM/SIGINT). |

---

## Security Dependencies & Package Management

`backupd-tyl` supports dual-mode cryptographic compilation:

1. **System Package-Managed OpenSSL (Recommended for Maximum Throughput)**:  
   Uses hardware acceleration (Intel/AMD AES-NI, AVX, ARM Cryptography Extensions) via OpenSSL EVP. Your OS package manager automatically manages security updates without requiring you to maintain custom crypto patches.
2. **Bundled Pure-C Engine (Fallback / Zero External Dependencies)**:  
   If OpenSSL development packages are not installed, the build seamlessly compiles 100% self-contained pure-C constant-time implementations of all ciphers.
3. **Automatic Version Check & Fallback**:  
   If the local version of OpenSSL installed on the machine is older than the package baseline (OpenSSL 1.1.1 LTS / `0x10101000L`), `backupd-tyl` automatically detects the outdated version and falls back to using the cryptographic library included with the package, ensuring bug-free compilation and full support for all 6 AEAD ciphers.

### Installing Security Dependencies via Package Managers:

| Distribution | Package Manager Command |
|---|---|
| **Ubuntu / Debian / Mint** | `sudo apt-get install -y libssl-dev build-essential` |
| **RHEL / CentOS / Rocky / Alma / Fedora** | `sudo dnf install -y openssl-devel gcc make` |
| **Arch Linux / Manjaro** | `sudo pacman -S --needed openssl base-devel` |
| **Alpine Linux** | `sudo apk add openssl-dev build-base` |
| **openSUSE / SLES** | `sudo zypper install -y libopenssl-devel gcc make` |

---

## Quick Start

### 1. Compile and Run Tests
```bash
git clone https://github.com/SillyNickname/backupd-tyl.git
cd backupd-tyl

# Auto-detects system libcrypto, falling back to pure-C if absent:
make all
make test

# Or force pure-C standalone mode (zero external dependencies):
make clean && make USE_SYSTEM_CRYPTO=0 all test
```

### 2. Install
```bash
# Standard installation (compiles locally with auto-detected crypto):
sudo ./scripts/install.sh

# Or install pre-compiled standalone binaries (zero dependencies, no compiler needed):
sudo ./scripts/install.sh --precompiled
```
Pre-compiled 64-bit ELF standalone binaries with zero external dependencies are provided in [`bin/`](bin/README.md) (`bin/backupd` ~108 KB, `bin/backupc` ~87 KB).

This installs `/usr/local/sbin/backupd`, `/usr/local/bin/backupc`, enables the systemd service (`backupd-tyl.service`), and creates `/etc/backupd-tyl/backupd.conf`.

### 3. Server Configuration (`/etc/backupd-tyl/backupd.conf`)
```ini
Port = 12153
BindAddress = "0.0.0.0"
# Ciphers: ascon, speck, chacha20, xchacha20, aes256, aes128
DefaultCipher = "ascon"
AllowLegacy = no

# Logging configuration
LogTarget = "file"
LogFile   = "/var/log/backupd-tyl.log"
LogLevel  = "info"

[system-archive]
user      = "backup"
password  = "SecretVaultKey42"
write     = "zstd -T0 -3 > /var/backups/hosts/%h/%H-%d.tar.zst"
read      = "zstd -d -c /var/backups/hosts/%h/latest.tar.zst"
Allow     = "192.168.1.0/24"
Deny      = "*"
```

# Validate configuration file syntax and view resources:
backupd -c /etc/backupd-tyl/backupd.conf -C
```

> [!NOTE]
> **User & Group Defaults**: If `user` and `group` are omitted from a resource section, `backupd-tyl` defaults to executing the command as `root:root` (preserving daemon privileges for raw hardware, block devices, or system-level tasks). When `user` is specified, privileges are safely dropped to that account.

### 4. Specialized Example Configurations (`examples/`)
The `examples/` directory contains tailored, production-ready configuration templates:
- [`examples/backupd.full.conf`](examples/backupd.full.conf): Complete configuration reference
- [`examples/backupd.minimal.conf`](examples/backupd.minimal.conf): Minimal footprint (ASCON-128a, edge/embedded devices)
- [`examples/backupd.database.conf`](examples/backupd.database.conf): PostgreSQL, MySQL/MariaDB, Redis, and SQLite
- [`examples/backupd.zfs_btrfs.conf`](examples/backupd.zfs_btrfs.conf): ZFS & Btrfs block-level snapshot replication
- [`examples/backupd.virtualization.conf`](examples/backupd.virtualization.conf): Proxmox VE, QEMU/KVM, Docker, Podman
- [`examples/backupd.tape_vault.conf`](examples/backupd.tape_vault.conf): Physical SCSI LTO tape drive library (`/dev/nst0`)
- [`examples/backupd.multi_tenant.conf`](examples/backupd.multi_tenant.conf): Multi-department isolation with immutable WORM archiving
- [`examples/backupd.hardening.conf`](examples/backupd.hardening.conf): Zero-trust CIS / PCI-DSS compliance (`umask 0077`, AES-256-GCM)

### 5. Client Usage
```bash
# Backup: Stream local directories to server with ASCON-128a and throughput tracking
tar -cpf - /etc /var/www | zstd -3 | \
  backupc -h backup-server.local -P "SecretVaultKey42" -T -w system-archive

# High-Security Backup: Use AES-256-GCM or XChaCha20-Poly1305 with audit trace
tar -cpf - /data | \
  backupc -h backup-server.local -P "SecretVaultKey42" -c aes256 -N stdout -T -w system-archive

# Restore: Stream from server into local extractor
backupc -h backup-server.local -P "SecretVaultKey42" -T -r system-archive | \
  zstd -d | tar -xpf - -C /restore

# Audit handshake negotiation
backupc -h backup-server.local -N stdout -l
```

---

## Documentation

Comprehensive documentation is available in [MANUAL.md](MANUAL.md):
- [Architecture & Design Details](MANUAL.md#3-cryptographic-architecture)
- [Server Reference (`backupd`)](MANUAL.md#5-server-reference-backupd)
- [Client Reference (`backupc`)](MANUAL.md#6-client-reference-backupc)
- [Standard Script Exit Codes](MANUAL.md#7-standard-process-exit-codes-for-scripting)
- [Server Logging & Observability](MANUAL.md#8-server-logging--observability-subsystem)
- [Configuration Directives & Multi-line Syntax](MANUAL.md#9-configuration-file-reference-backupdconf)
- [Enterprise Scenarios (PostgreSQL, MySQL, Zstd, LTO Tape)](MANUAL.md#11-enterprise-scenarios--real-world-examples)
- [Post-2020 Linux Architecture & Modernization Roadmap](POST_2020_ROADMAP.md)

---

## Authors & Attribution

- **Original Author (1998)**: Ullrich von Bassewitz (`backupd` v0.20).  
  *Note: The original author's email address `uz@musoftware.de` appears to no longer be active.*
- **Requested & Commissioned by**: **Andre Kajita** (`kajita@univap.br`).
- **Modernization & Cryptographic Engineering (2026)**: Antigravity / Gemini (Google DeepMind).
- **Public Domain Crypto Primitives**: Donna 64-bit X25519 engine by Adam Langley.

---

## License

GNU General Public License v2.0 or later (GPL-2.0+). See individual file headers for specific component licensing.
