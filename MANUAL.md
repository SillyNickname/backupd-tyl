# backupd-tyl (Backupd - Thirty Years Later)
## Comprehensive User Manual and Technical Reference

```
  _                 _                   _       _             _ 
 | |__   __ _  ____| | ___   _ _ __   __| |     | |_ _   _  __| |
 | '_ \ / _` |/ ___| |/ / | | | '_ \ / _` |_____| __| | | |/ _` |
 | |_) | (_| | |___|   <| |_| | |_) | (_| |_____| |_| |_| | (_| |
 |_.__/ \__,_|\____|_|\_\\__,_| .__/ \__,_|      \__|\__, |\__,_|
                              |_|                    |___/       
```

---

### Authors & Attribution

- **Original Author (1998)**: Ullrich von Bassewitz (`backupd` version 0.20)  
  *Note: The original author's contact address `uz@musoftware.de` appears to no longer be active.*
- **Requested & Commissioned by**: **Andre Kajita** (`kajita@univap.br`)
- **Modernization & Cryptographic Engineering (2026)**: Antigravity / Gemini (Google DeepMind)
- **License**: GNU General Public License v2.0 or later (GPL-2.0+)

---

## Table of Contents

1. [Introduction & Overview](#1-introduction--overview)
2. [Key Modernizations](#2-key-modernizations)
3. [Cryptographic Architecture](#3-cryptographic-architecture)
   - [Supported AEAD Cipher Suites](#supported-aead-cipher-suites)
   - [Dual-Engine Cryptography (Hardware vs Pure-C)](#dual-engine-cryptography-hardware-vs-pure-c)
   - [Pre-Cryptographic Password Verification](#pre-cryptographic-password-verification)
4. [Installation & Requirements](#4-installation--requirements)
   - [Supported Distributions](#supported-distributions)
   - [Security Dependencies & Package Management](#security-dependencies--package-management)
   - [Dual-Engine Compilation Flags](#dual-engine-compilation-flags)
   - [Automated Installation](#automated-installation)
   - [Manual Compilation](#manual-compilation)
5. [Server Reference: `backupd`](#5-server-reference-backupd)
   - [Command-line Options](#server-command-line-options)
   - [Daemon Operation Modes](#daemon-operation-modes)
   - [Signal Handling & SIGHUP Log Rotation](#server-signal-handling)
6. [Client Reference: `backupc`](#6-client-reference-backupc)
   - [Command-line Options](#client-command-line-options)
   - [Negotiation Logging (`-N`)](#client-negotiation-logging)
   - [Network Throughput Monitoring (`-T`)](#client-network-throughput-monitoring)
   - [Usage Patterns & Pipes](#client-usage-patterns)
7. [Standard Process Exit Codes for Scripting](#7-standard-process-exit-codes-for-scripting)
8. [Server Logging & Observability Subsystem](#8-server-logging--observability-subsystem)
   - [Supported Logging Targets (File, Syslog/rsyslog, Stderr)](#logging-targets)
   - [Logging Levels](#logging-levels)
   - [Logrotate Integration](#logrotate-integration)
9. [Configuration File Reference (`backupd.conf`)](#9-configuration-file-reference-backupdconf)
   - [Global Section](#global-configuration-options)
   - [Resource Sections](#resource-definitions)
   - [Multi-line Scripts & Pipelines](#multi-line-scripts)
   - [Access Control Lists (ACLs)](#access-control-lists)
   - [String Macros and Expansions](#string-macros-and-expansions)
10. [Backward Compatibility with Legacy v0.20](#10-backward-compatibility-with-legacy-v020)
11. [Enterprise Scenarios & Real-World Examples](#11-enterprise-scenarios--real-world-examples)
    - [Directory Streaming with Zstandard](#scenario-1-directory-streaming-with-zstandard)
    - [PostgreSQL Database Backup](#scenario-2-postgresql-database-backup)
    - [MySQL / MariaDB Streaming](#scenario-3-mysql--mariadb-streaming)
    - [LTO Physical Tape Streaming](#scenario-4-lto-physical-tape-streaming)
    - [Automated Unattended Cron Jobs](#scenario-5-automated-unattended-cron-jobs)
12. [Security & Threat Model](#12-security--threat-model)
13. [Troubleshooting & Frequently Asked Questions](#13-troubleshooting--frequently-asked-questions)
14. [Future Architecture & Post-2020 Modernization Roadmap](#14-future-architecture--post-2020-modernization-roadmap)

---

## 1. Introduction & Overview

`backupd-tyl` ("Backupd - Thirty Years Later") is a high-performance, lightweight, security-hardened remote streaming backup solution for modern Linux systems. It is an evolutionary modernization of Ullrich von Bassewitz's classic 1998 `backupd` utility, commissioned by **Andre Kajita** and engineered by **Antigravity / Gemini**.

The core philosophy of `backupd` is rooted in the Unix philosophy: **do one thing and do it well, using pipelines**:
- The client connects over a network socket to the server.
- The server locates a configured resource command and attaches the network stream directly to the standard input or standard output of a local shell command.
- The client streams data to or from standard input/output.

```
+---------------+                      +---------------+
| backupc       |                      | backupd       |
| (Client Host) |                      | (Server Host) |
+-------+-------+                      +-------+-------+
        |                                      |
  [stdin / stdout]                       [stdin / stdout]
        |                                      |
        v                                      v
  [AEAD Framing]   == Encrypted TCP ==>  [AEAD Framing]
        |             (Port 12153)             |
        v                                      v
  [Local Pipes]                          [Shell Subprocess]
  (tar, zstd, pg_dump)                   (zstd, dd, files)
```

`backupd-tyl` modernizes this architecture with TLS-style ephemeral cryptography on the fly, defense-in-depth pre-cryptographic authentication, multi-line pipeline configuration, standalone daemon capabilities, comprehensive enterprise logging, network throughput metrics, scriptable process exit codes, and zero external cryptographic dependencies.

---

## 2. Key Modernizations

| Feature | Legacy `backupd` (1998) | Modern `backupd-tyl` (2026) |
|---|---|---|
| **Security / Encryption** | None (plaintext stream, vulnerable to passive eavesdropping and tampering) | Ephemeral Curve25519 (X25519) key exchange, session key derivation via HKDF-SHA256, authenticated encryption (AEAD) |
| **Cipher Suites** | None | 6 AEAD Suites: ASCON-128a (default), Speck-128/128-Poly1305, ChaCha20-Poly1305, XChaCha20-Poly1305 (192-bit nonce), AES-256-GCM, AES-128-GCM |
| **Pre-Crypto Password** | None | Optional shared password verified *before* cryptographic handshake to prevent CPU exhaustion DoS |
| **Server Logging** | Unconfigurable `LOG_DAEMON` syslog | Configurable file (`/var/log/backupd-tyl.log`) or syslog/rsyslog with 5 log levels (debug, info, notice, warn, error) and SIGHUP logrotate support |
| **Client Tracing** | None | Real-time negotiation logging (`-N stdout` or `-N <file>`) detailing crypto steps |
| **Client Throughput** | None | Network throughput monitoring (`-T` / `--throughput`), silent by default, live & summary rate in MB/s |
| **Exit Codes** | Generic 0 or 1 | Standard exit codes (0 to 9) allowing bash scripts to differentiate network, auth, crypto, and resource errors |
| **Configuration Parsing** | Single-line shell command per resource | Multi-line pipelines (`\`), block brace syntax (`{ ... }`), and sequential lines |
| **Access Control Lists** | Global `ListAllow` / `ListDeny` only | Local `ListAllow` / `ListDeny` per resource overriding global rules, enabling hidden administrative targets |
| **Daemon Operation** | `inetd` only | Standalone background service (`-d`), systemd supervisor (`-F`), or socket activation / `inetd` (`-i`) |
| **Portability & Footprint** | 32-bit Linux / libc5 | Dual-engine: Hardware-accelerated OpenSSL EVP (package-managed) or 100% self-contained pure-C fallback (< 110KB binary) |
| **Legacy Compatibility** | Original protocol | Full backward compatibility via client switch (`-L` / `--legacy`) and server flag (`AllowLegacy = yes`) |

---

## 3. Cryptographic Architecture

`backupd-tyl` implements an ephemeral TLS-style handshake with zero certificates or external cryptographic library requirements:

```
CLIENT                                                    SERVER
  |                                                         |
  |  Protocol HELLO & Pre-Crypto Password:                  |
  |  "TYL/1.0 HELLO cmd=WRITE res=tape pass=... ciphers=..."|
  | ------------------------------------------------------> |
  |                                                         | Constant-time verification
  |  Server Ephemeral Public Key & Chosen Cipher:           | (Rejects on mismatch)
  |  "TYL/1.0 KEY pubkey=<srv_x25519_hex> cipher=ascon128a" |
  | <------------------------------------------------------ |
  |                                                         |
  |  Client Ephemeral Public Key:                           |
  |  "TYL/1.0 KEY pubkey=<client_x25519_hex>"               |
  | ------------------------------------------------------> |
  |                                                         |
  +=========================================================+
  | Both sides calculate:                                   |
  |   shared_secret = X25519(priv_key, peer_pub_key)        |
  |   (tx_key, rx_key) = HKDF-SHA256(shared_secret, ...)    |
  +=========================================================+
  |                                                         |
  |  Client Verification Token (Encrypted Frame):           |
  |  [Encrypted "TYL-FINISHED-v1.0"]                        |
  | ------------------------------------------------------> |
  |                                                         |
  |  Server Verification Token (Encrypted Frame):           |
  |  [Encrypted "TYL-SESSION-READY"]                        |
  | <------------------------------------------------------ |
  |                                                         |
  |  Authenticated & Encrypted Data Stream Frames:          |
  |  [4-byte Length] [8-byte Nonce] [Ciphertext] [16-byte Tag]
  | <=====================================================> |
```

### Supported AEAD Cipher Suites

`backupd-tyl` includes a robust portfolio of six modern Authenticated Encryption with Associated Data (AEAD) cipher suites, balancing lightweight efficiency, enterprise compliance, and collision resistance:

| Cipher Name | CLI Option | Key Size | Nonce Size | Tag Size | Performance Profile | Ideal Use Case |
|---|---|---|---|---|---|---|
| **ASCON-128a** | `-c ascon` | 128 bits | 128 bits | 128 bits | Minimal CPU overhead | IoT, edge routers, low-power devices (Default) |
| **Speck-128/128-Poly1305** | `-c speck` | 128 bits | 96 bits | 128 bits | Ultra-fast software ARX | Legacy 64-bit systems lacking AES-NI |
| **ChaCha20-Poly1305** | `-c chacha20` | 256 bits | 96 bits | 128 bits | 256-bit high security | General high-security streaming (RFC 8439) |
| **XChaCha20-Poly1305** | `-c xchacha20` | 256 bits | 192 bits | 128 bits | Extended nonce security | Multi-terabyte continuous streaming backups |
| **AES-256-GCM** | `-s`, `-c aes256` | 256 bits | 96 bits | 128 bits | Maximum security + AES-NI | Enterprise compliance, TLS 1.3 parity, FIPS |
| **AES-128-GCM** | `-c aes128` | 128 bits | 96 bits | 128 bits | Wire-speed throughput | High-speed enterprise LAN backups |

#### Detailed Cipher Descriptions:

1. **ASCON-128a (Default)**:
   - Winner of the official NIST Lightweight Cryptography (LWC) standardization process.
   - Operates on a 320-bit permutation state with 128-bit rate. Designed specifically for low memory footprint, zero cache timing side-channels, and negligible CPU utilization.
   - Recommended for daily backups across heterogeneous servers and virtual machines.
2. **Speck-128/128 with Poly1305 Authenticator (`-c speck`)**:
   - Uses the NSA-developed Speck block cipher (128-bit block, 128-bit key) in Counter (CTR) mode coupled with a Poly1305 universal hash MAC.
   - Pure ARX (Add-Rotate-Xor) operations execute in fixed cycles on modern 64-bit CPUs, providing outstanding throughput even without hardware cryptographic acceleration.
3. **ChaCha20-Poly1305 (`-c chacha20`)**:
   - RFC 8439 standard 256-bit stream cipher paired with Poly1305 authenticator.
   - Proven cryptanalysis history with immune constant-time software execution.
4. **XChaCha20-Poly1305 (`-c xchacha20`)**:
   - Uses HChaCha20 subkey derivation to extend the standard nonce from 96 bits to 192 bits (24 bytes).
   - Standard 96-bit nonces risk collision if an astronomical number of frames are generated under a single key. XChaCha20's 192-bit nonce makes random or sequential nonce reuse virtually impossible ($2^{-96}$ collision threshold), making it the optimal cipher for continuous petabyte streaming pipelines.
5. **AES-256-GCM (`-s`, `--secure`, or `-c aes256`)**:
   - NIST SP 800-38D standard in Galois/Counter Mode.
   - Industry standard for government and financial institutions requiring 256-bit symmetric strength. Hardware accelerated via OpenSSL EVP when package-managed libraries are installed.
6. **AES-128-GCM (`-c aes128`)**:
   - 128-bit variant of NIST SP 800-38D.
   - 10 rounds of AES processing combined with hardware carry-less multiplication (PCLMULQDQ) delivers multi-gigabyte-per-second streaming on modern enterprise processors.

### Dual-Engine Cryptography (Hardware vs Pure-C)

`backupd-tyl` features a dual-engine cryptographic architecture:

- **Hardware Acceleration Mode (System OpenSSL)**:  
  When built with system `libcrypto` headers available (`USE_SYSTEM_CRYPTO=auto` or `USE_SYSTEM_CRYPTO=1`), `backupd-tyl` routes AES-256-GCM, AES-128-GCM, and ChaCha20-Poly1305 through the OpenSSL EVP interface. This unlocks kernel/CPU hardware acceleration (AES-NI, AVX-512, PCLMULQDQ, and ARM NEON).
- **Standalone Pure-C Fallback Engine**:  
  When built without system `libcrypto` (`USE_SYSTEM_CRYPTO=0`), `backupd-tyl` activates its internal, constant-time C implementations for all ciphers. The pure-C AES-GCM engine implements NIST SP 800-38D GF($2^{128}$) carry-less multiplication and constant-time S-box lookups, ensuring 100% self-contained operation without external libraries.

### Pre-Cryptographic Password Verification
Resource targets in `backupd.conf` can define a `password = "secret"` directive. When configured:
- The client sends the password in the opening connection frame.
- The server validates the password using timing-safe comparison (`memcmp_const_time`) *before* generating Curve25519 key pairs or computing scalar multiplications.
- Any client failing authentication is immediately severed, completely mitigating asymmetric key exhaustion attacks.

---

## 4. Installation & Requirements

### Supported Distributions
`backupd-tyl` is written in standard C99 using POSIX and Linux kernel syscalls (`getrandom` / `/dev/urandom`). It compiles and runs on any post-2010 Linux distribution:
- **Debian / Ubuntu / Linux Mint / Raspberry Pi OS**
- **RHEL / Rocky Linux / AlmaLinux / CentOS / Fedora**
- **Arch Linux / Manjaro**
- **Alpine Linux** (musl libc compatible)
- **openSUSE / SLES**

### Security Dependencies & Package Management

To benefit from hardware-accelerated AES-NI throughput and keep underlying security libraries updated with distribution patches, administrators are encouraged to install their distribution's OpenSSL / `libcrypto` development package:

| Operating System | Package Manager Command | Security Dependency Package |
|---|---|---|
| **Ubuntu / Debian / Mint** | `sudo apt-get install -y libssl-dev build-essential` | `libssl-dev` |
| **RHEL / Rocky / Alma / Fedora** | `sudo dnf install -y openssl-devel gcc make` | `openssl-devel` |
| **Arch Linux / Manjaro** | `sudo pacman -S --needed openssl base-devel` | `openssl` |
| **Alpine Linux** | `sudo apk add openssl-dev build-base` | `openssl-dev` |
| **openSUSE / SLES** | `sudo zypper install -y libopenssl-devel gcc make` | `libopenssl-devel` |

> [!NOTE]
> Installing these security packages via your OS package manager ensures that upstream cryptographic security advisories and kernel optimizations are applied automatically via your regular system update routines (`apt upgrade`, `dnf update`, etc.). If these packages are omitted, `backupd-tyl` seamlessly falls back to its bundled pure-C implementation.

> [!IMPORTANT]
> **Older Library Version Fallback**:  
> `backupd-tyl` requires OpenSSL 1.1.1 or newer (`0x10101000L`) for hardware-accelerated AEAD EVP operations (`EVP_chacha20_poly1305`, `EVP_aes_256_gcm`, `EVP_CIPHER_CTX_new`). If the local version of OpenSSL installed on the host is older than the package baseline (e.g., legacy OpenSSL 1.0.1, 1.0.2, or 0.9.8), the build system automatically detects the outdated version and falls back to compiling and using the complete cryptographic library included with the package (`crypto/*.c`).
>
> Furthermore, at runtime, `backupd` and `backupc` verify `OpenSSL_version_num() >= 0x10101000L`. If the dynamically loaded local library is older than the package baseline, the engine automatically routes encryption and decryption frames through the bundled pure-C algorithms.

### Dual-Engine Compilation Flags

The build behavior is controlled by the `USE_SYSTEM_CRYPTO` Makefile variable:

```bash
# 1. Automatic detection (Default):
# Links against system libcrypto if headers are found, otherwise uses bundled pure-C:
make all

# 2. Enforce system OpenSSL with hardware acceleration:
make USE_SYSTEM_CRYPTO=1 all

# 3. Enforce zero-dependency standalone pure-C build (no -lcrypto):
make USE_SYSTEM_CRYPTO=0 all
```

### Automated Installation
The repository includes a distribution-aware installer:

```bash
git clone https://github.com/SillyNickname/backupd-tyl.git
cd backupd-tyl

# Standard installation (compiles locally with auto-detected crypto):
sudo ./scripts/install.sh

# Fast installation using pre-compiled standalone binaries (zero dependencies, no compiler needed):
sudo ./scripts/install.sh --precompiled
```

The script will:
1. Detect distribution and report package-managed security library availability.
2. Compile binaries locally OR copy pre-compiled zero-dependency binaries from `bin/` (when `--precompiled` is passed).
3. Install binaries to `/usr/local/sbin/backupd` and `/usr/local/bin/backupc`.
4. Create default configuration directory `/etc/backupd-tyl/` and sample config.
5. Set up system user/group `backup`.
6. Install and enable the systemd unit (`backupd-tyl.service`) or SysVinit/OpenRC init script.

### Pre-compiled Standalone Binaries (`bin/`)
For target machines without a C compiler (`gcc`), `make`, or modern C libraries (such as minimal appliances, edge routers, containers, or legacy 2010s servers like CentOS 6), 100% statically linked, stripped 64-bit ELF binaries are provided in the `bin/` directory:
* `bin/backupd` (~228 KB): Standalone daemon built with bundled constant-time crypto and statically linked (zero external or glibc dependencies, works on kernel 2.6.32+).
* `bin/backupc` (~179 KB): Streaming backup client with zero external or glibc dependencies.

To uninstall:
```bash
sudo ./scripts/uninstall.sh
```

### Manual Compilation
```bash
# Build both binaries with automatic crypto detection
make all

# Run cryptographic test vectors and integration test suites
make test

# Install to system
sudo make install
```

---

## 5. Server Reference: `backupd`

### Server Command-line Options

```
Usage: backupd [-c <config>] [-d | -F | -i] [-p <port>] [-b <ip>] [-P <pidfile>] 
               [-l <logfile>] [-L <loglevel>] [-t <logtarget>] [-V] [-h]
```

- `-c, --config <path>`: Path to configuration file (default: `/etc/backupd.conf` or `/etc/backupd-tyl/backupd.conf`).
- `-p, --port <port>`: Override listening TCP port (default: `12153`).
- `-b, --bind <address>`: Override bind IP address (default: `0.0.0.0`).
- `-d, --daemon`: Run in background as standalone daemon (forks, detaches, creates PID file).
- `-F, --foreground`: Run in foreground (ideal for systemd or container supervision).
- `-i, --inetd`: Run in inetd / systemd socket-activation mode (stdin/stdout socket).
- `-P, --pidfile <path>`: Path to write daemon PID file.
- `-l, --logfile <file>`: Write logs directly to file (overrides config `LogFile`).
- `-L, --loglevel <level>`: Logging verbosity threshold (`debug`, `info`, `notice`, `warn`, `err`).
- `-t, --logtarget <dest>`: Log destination: `syslog`, `file`, or `stderr`.
- `-C, --check-config`: Validate configuration file syntax, print configured resources, and exit.
- `-V, --version`: Print version, commissioner credit, and supported ciphers.
- `-h, --help`: Display command-line help.

### Daemon Operation Modes

#### 1. Standalone Systemd Service (Recommended)
`systemd` supervises `backupd` running in the foreground:
```ini
# /etc/systemd/system/backupd-tyl.service
[Service]
ExecStart=/usr/local/sbin/backupd -c /etc/backupd-tyl/backupd.conf -F
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
```

#### 2. Standalone Background Daemon
For traditional servers or SysVinit environments:
```bash
/usr/local/sbin/backupd -c /etc/backupd-tyl/backupd.conf -d
```

#### 3. Legacy `inetd` / `xinetd` Mode
When invoking via inetd, `backupd` automatically detects stdin is a socket, or can be forced with `-i`:
```
# /etc/inetd.conf
backupd  stream  tcp  nowait  root  /usr/local/sbin/backupd  backupd -i
```

### Server Signal Handling

- `SIGHUP`: Re-reads the configuration file and re-opens log files. Active transfers continue uninterrupted; new connections use the updated configuration. This allows seamless integration with `logrotate`.
- `SIGTERM`, `SIGINT`: Gracefully terminates the daemon, removes lockfiles, cleans up the PID file, and exits with code `9` (`TYL_EXIT_SIGNAL`).
- `SIGCHLD`: Automatically reaps terminated connection worker child processes without zombie accumulation.

---

## 6. Client Reference: `backupc`

### Client Command-line Options

```
Usage: backupc [options] -w|-r|-l <resource>
```

#### Action Selectors (Exactly one required):
- `-w <resource>`: Write mode. Reads data from stdin and streams it to the remote server's resource.
- `-r <resource>`: Read mode. Streams data from the remote server's resource to client's stdout.
- `-l`: List mode. Queries the server for accessible backup resources.

#### Connection & Security Options:
- `-h, --host <host>`: Server hostname or IP address (default: `localhost`).
- `-p, --port <port>`: Server TCP port (default: `12153`).
- `-P, --password <pass>`: Pre-cryptographic shared password for the target resource.
- `-c, --cipher <name>`: Preferred AEAD cipher: `ascon` (default), `speck`, `chacha20`, `xchacha20`, `aes256`, or `aes128`.
- `-s, --secure`: High-security shortcut (selects 256-bit AES-256-GCM or ChaCha20-Poly1305).
- `-b, --blocksize <n>`: Frame buffer chunk size in KB (default: `16` / 16384 bytes).
- `-N, --log-negotiation <target>`: Trace cryptographic handshake to `stdout`, `stderr`, or a `<file>`.
- `-T, --throughput`: Display network throughput during transfer and summary upon completion (by default, silent).
- `-L, --legacy`: Force legacy unencrypted v0.20 protocol.
- `-V, --version`: Print version, commissioner credit, and cipher details.
- `-H, --help`: Print help message.

### Client Negotiation Logging

Using `-N <target>`, administrators can inspect the exact TLS-style handshake:

```bash
# Log negotiation to standard output:
backupc -h backup.local -N stdout -l

# Log negotiation to a dedicated audit log file:
backupc -h backup.local -N /var/log/backupc-audit.log -w system-archive < data.tar.zst
```

**Sample Negotiation Log Output:**
```
[2026-09-30 13:50:01.204] [NEGOTIATION] Initiating connection to 192.168.1.100:12153 (cmd=WRITE, res='system-archive')
[2026-09-30 13:50:01.205] [NEGOTIATION] Connected to TCP socket 3
[2026-09-30 13:50:01.205] [NEGOTIATION] Sending HELLO: pre-crypto pass=[PROTECTED], proposed ciphers='ascon,speck,chacha20'
[2026-09-30 13:50:01.207] [NEGOTIATION] Received server ephemeral public key (X25519): 83f7a192b0...
[2026-09-30 13:50:01.207] [NEGOTIATION] Negotiated cipher suite: ascon128a
[2026-09-30 13:50:01.208] [NEGOTIATION] Generated client ephemeral public key (X25519): 44d90e21a8...
[2026-09-30 13:50:01.209] [NEGOTIATION] Derived TX/RX session keys using HKDF-SHA256 from X25519 shared secret
[2026-09-30 13:50:01.210] [NEGOTIATION] Sending encrypted handshake verification token: TYL-FINISHED-v1.0
[2026-09-30 13:50:01.212] [NEGOTIATION] Received server encrypted confirmation: TYL-SESSION-READY
[2026-09-30 13:50:01.213] [NEGOTIATION] TLS-style negotiation complete! Encrypted AEAD channel established.
```

### Client Network Throughput Monitoring

By default, `backupc` produces **no auxiliary terminal output**, keeping stdout and stderr clean for Unix pipelines. When `-T` (or `--throughput`) is supplied, network metrics are written to `stderr` so data piped on `stdout` is never corrupted:

```bash
backupc -h backup.local -P "MySecret" -T -r system-archive > restore.tar.zst
```

**Real-time interactive display (on terminal):**
```
[Throughput] Transferred: 48.50 MB | Rate: 32.10 MB/s (Avg: 30.50 MB/s) | Elapsed: 1.6s
```

**Completion summary:**
```
[Throughput] Completed: 104.86 MB (109951162 bytes) in 3.42s (Average: 30.66 MB/s)
```

### Client Usage Patterns

```bash
# Writing: Stream directory through zstd into server with throughput metrics
tar -cpf - /etc /var/www | zstd -3 | \
  backupc -h backup.corp -P "VaultKey" -T -w system-archive

# Reading: Stream from server into zstd extractor
backupc -h backup.corp -P "VaultKey" -T -r system-archive | \
  zstd -d | tar -xpf - -C /restore
```

---

## 7. Standard Process Exit Codes for Scripting

Both `backupc` and `backupd` define standard exit codes so orchestration scripts and monitoring tools can determine the exact cause of any operational issue:

| Exit Code | Constant Name | Cause / Failure Condition | Recommended Action |
|---|---|---|---|
| **0** | `TYL_EXIT_SUCCESS` | Command completed successfully with verified integrity. | Normal continuation. |
| **1** | `TYL_EXIT_USAGE` | Invalid command-line arguments, missing parameters, or help requested. | Check script syntax or arguments passed to CLI. |
| **2** | `TYL_EXIT_CONFIG` | Configuration file syntax error or required directive missing. | Validate `/etc/backupd-tyl/backupd.conf`. |
| **3** | `TYL_EXIT_NETWORK` | Connection refused, host unreachable, DNS resolution error, or socket timeout. | Verify server daemon is running, network routing, and firewall port 12153. |
| **4** | `TYL_EXIT_AUTH` | Missing or incorrect shared password, or client IP rejected by `ListAllow` / `ListDeny`. | Verify `-P <password>` and client IP against server ACLs. |
| **5** | `TYL_EXIT_CRYPTO` | Ephemeral key exchange failed, AEAD tag verification failure (tampered ciphertext), or cipher mismatch. | Inspect network security for MITM tampering or bad cipher negotiation. |
| **6** | `TYL_EXIT_IO` | Local pipe broken, disk full, subcmd failed, or stdin/stdout write failure. | Check local filesystem free space and subprocess errors. |
| **7** | `TYL_EXIT_RESOURCE` | Target resource section does not exist in `backupd.conf` or lockfile held by another backup. | Check resource name or retry once current lock clears. |
| **8** | `TYL_EXIT_PERMISSION` | Insufficient OS permissions (e.g. unable to bind port 12153 or failed `setuid`/`setgid`). | Ensure daemon runs as root with appropriate capabilities. |
| **9** | `TYL_EXIT_SIGNAL` | Process terminated by external signal (`SIGTERM` or `SIGINT`). | Check system shutdown or container manager stop signals. |

### Shell Script Integration Example
```bash
#!/bin/bash
backupc -h backup.corp -P "MySecret" -w database-pg < dump.sql.zst
RC=$?

case $RC in
    0) echo "Backup succeeded." ;;
    3) echo "ERROR: Network failure connecting to backup server." ; alert_ops "net" ;;
    4) echo "ERROR: Authentication rejected (wrong password or unauthorized IP)." ; alert_security ;;
    5) echo "SECURITY ALERT: Cryptographic verification failure!" ; alert_security ;;
    7) echo "WARNING: Resource locked by another backup job. Retrying in 60s..." ; sleep 60 ;;
    *) echo "ERROR: Backup failed with code $RC." ;;
esac
exit $RC
```

---

## 8. Server Logging & Observability Subsystem

`backupd-tyl` includes an enterprise logging engine designed for production observability.

### Logging Targets

Configured via `LogTarget` in `backupd.conf` or CLI option `-t <target>`:

1. **`syslog` (Default)**:
   Routes log messages directly to the local syslog daemon (`rsyslogd`, `syslog-ng`, or `systemd-journald`) using standard POSIX `vsyslog()`. If run on an interactive terminal, logs are also mirrored to standard error.
2. **`file`**:
   Writes directly to a dedicated log file (`LogFile = "/var/log/backupd-tyl.log"`). Lines are formatted with microsecond timestamps, worker PID, level tag, and client context:
   ```
   2026-09-30 13:52:14.412 [184724] [NOTICE] backupd-tyl v1.1.0 standalone service listening on 0.0.0.0:12153 (pid 184724)
   2026-09-30 13:52:20.108 [184730] [INFO] Connection accepted from 192.168.1.50:41232
   2026-09-30 13:52:20.114 [184730] [INFO] Secure session established using ascon128a with client 192.168.1.50
   2026-09-30 13:52:25.890 [184730] [INFO] WRITE completed successfully for 192.168.1.50 (1048576 bytes transferred)
   ```
3. **`stderr`**:
   Writes formatted log messages directly to standard error. Ideal for container environments (Docker, Kubernetes) and systemd unit supervision.

### Logging Levels

Configured via `LogLevel` in `backupd.conf` or CLI option `-L <level>`:

- `debug`: Traces internal operations, ephemeral key generation, and frame exchanges.
- `info`: Logs successful connections, negotiated ciphers, and bytes transferred.
- `notice`: Logs service startup, shutdown, and configuration reloads (`SIGHUP`).
- `warn`: Logs authentication failures, unauthorized client connection attempts, and timeouts.
- `err`: Logs fatal errors and external command execution failures.

### Logrotate Integration

When using file-based logging (`LogTarget = file`), configure log rotation via `/etc/logrotate.d/backupd-tyl`:

```ini
/var/log/backupd-tyl.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0640 backup backup
    postrotate
        if [ -f /var/run/backupd-tyl.pid ]; then
            kill -HUP $(cat /var/run/backupd-tyl.pid) 2>/dev/null || true
        fi
    endscript
}
```

---

## 9. Configuration File Reference (`backupd.conf`)

The configuration file uses INI-style syntax. Directives specified before the first `[resource]` header are global.

### Global Configuration Options

```ini
# TCP port for standalone daemon (default: 12153)
Port = 12153

# Listening IP address (default: 0.0.0.0)
BindAddress = "0.0.0.0"

# PID file path
PidFile = "/var/run/backupd-tyl.pid"

# Default encryption cipher: "ascon", "speck", "chacha20", "xchacha20", "aes256", or "aes128"
DefaultCipher = "ascon"

# Logging configuration
LogTarget   = "syslog"
LogFile     = "/var/log/backupd-tyl.log"
LogLevel    = "info"
LogFacility = "daemon"

# Allow unencrypted v0.20 legacy clients (yes/no)
AllowLegacy = no

# Disable reverse DNS lookups for client IP addresses
NoDNS = 1

# Global access list for the 'LIST' discovery command
ListAllow = "127.0.0.1/32 192.168.1.0/24"
ListDeny  = "*"
```

### Resource Definitions

Each resource corresponds to a client target name specified via `-w` or `-r`:

```ini
[my-resource]
# Linux user and group under which the shell command executes.
# NOTE: If 'user' and 'group' are omitted, backupd-tyl defaults to running
# the resource command as root (UID 0 / GID 0), allowing direct access to
# block devices, filesystems, and administrative tasks.
user     = "backup"
group    = "backup"

# Pre-crypto shared password required to access this resource
password = "StrongSharedSecretPassword"

# Path to lockfile preventing concurrent operations on this resource
lockfile = "/var/lock/backupd-my-resource.lock"

# Command executed when client writes (-w)
write    = "cat > /var/backups/target.dat"

# Command executed when client reads (-r)
read     = "cat /var/backups/target.dat"

# Access control specific to this resource
ListAllow = "192.168.1.0/24"
ListDeny  = "*"
```

### Multi-line Scripts

`backupd-tyl` supports three forms of multi-line commands:

#### 1. Backslash Continuation (`\`):
```ini
[postgres-db]
write = "zstd -d | \
         pg_restore --clean -d prod_db"
read  = "pg_dump -Fc prod_db | \
         zstd -T0 -4"
```

#### 2. Curly Brace Block Syntax (`{ ... }`):
```ini
[ingest-archive]
write = {
    OUTFILE="/var/backups/hosts/%h/%H-%d.tar.zst"
    mkdir -p "$(dirname "$OUTFILE")"
    cat > "$OUTFILE"
    sha256sum "$OUTFILE" >> /var/backups/checksums.log
}
```

#### 3. Sequential Line Entries:
```ini
[sequential-commands]
write = "tar -tf - > /tmp/manifest.txt"
write = "cat > /var/backups/archive.tar"
```

### Access Control Lists

Access lists support:
- Single IPv4 addresses: `192.168.1.50`
- CIDR network blocks: `192.168.1.0/24`, `10.0.0.0/8`
- Hostnames or DNS wildcards: `*.local`, `host.domain.com`
- Universal wildcard: `*`

#### Local Override Rule:
If a resource section contains `ListAllow` or `ListDeny`, it completely overrides the global list. This allows hiding specific sensitive resources from `backupc -l` discovery:

```ini
[admin-secret]
password = "AdminSuperSecret"
ListDeny = "*"
read     = "/usr/local/sbin/get-system-state"
```

### String Macros and Expansions

In `read`, `write`, and `lockfile` directives, the following tokens are expanded at runtime:

- `%h`: Client peer hostname (or IP if DNS resolution is disabled).
- `%H`: Local server hostname.
- `%d`: Current timestamp (`YYYYMMDD_HHMMSS`).
- `%%`: Literal `%` character.

---

## 10. Backward Compatibility with Legacy v0.20

`backupd-tyl` retains backward compatibility with Ullrich von Bassewitz's original 1998 v0.20 implementation.

### Connecting to a Modern Server with Legacy Client
If `AllowLegacy = yes` is set in the server configuration, a 1998 client binary can connect and stream unencrypted.

### Using Modern `backupc` with Legacy Servers
The modern `backupc` client can talk to a 1998 `backupd` daemon using the `-L` (or `--legacy`) flag:

```bash
# Connects using unencrypted 0.20 protocol
backupc -L -h legacy-box.corp -w tape0 < archive.tar
```

> [!WARNING]
> Legacy mode transmits all data, resource names, and commands in plaintext with zero encryption and zero integrity authentication. Only enable `AllowLegacy = yes` on isolated, trusted management networks.

---

## 11. Enterprise Scenarios & Real-World Examples

### Scenario 1: Directory Streaming with Zstandard
Fast parallel compression (`zstd -T0`) streaming directly to storage on the backup server:

**Server Configuration (`/etc/backupd-tyl/backupd.conf`):**
```ini
[system-archive]
user      = "backup"
group     = "backup"
password  = "SecretClusterKey2026"
write     = "zstd -T0 -3 > /var/backups/hosts/%h/%H-%d.tar.zst"
read      = "zstd -d -c /var/backups/hosts/%h/latest.tar.zst"
ListAllow = "192.168.1.0/24"
ListDeny  = "*"
```

**Client Command:**
```bash
tar -cpf - /etc /var/www | zstd -3 | \
  backupc -h backup.corp -P "SecretClusterKey2026" -T -w system-archive
```

### Scenario 2: PostgreSQL Database Backup
Streaming an encrypted custom-format PostgreSQL dump directly across hosts:

**Server Configuration:**
```ini
[postgres-prod]
user      = "postgres"
password  = "PgSqlSecretVault2026"
write     = "zstd -d | pg_restore --clean --if-exists -d production"
read      = "pg_dump -Fc production | zstd -T0 -4"
ListAllow = "10.0.1.50/32"
ListDeny  = "*"
```

**Client Command (ChaCha20-Poly1305 High Security Mode):**
```bash
pg_dump -Fc -U postgres production | zstd -4 | \
  backupc -h backup.corp -s -P "PgSqlSecretVault2026" -T -w postgres-prod
```

### Scenario 3: MySQL / MariaDB Streaming
Transactionally consistent streaming MariaDB dump:

```bash
mariadb-dump --single-transaction --quick -u root -p production | zstd -4 | \
  backupc -h backup.corp -c speck -P "MariaDbVault2026" -T -w database-mysql
```

### Scenario 4: LTO Physical Tape Streaming
Writing 256KB tape blocks directly to a non-rewinding tape drive (`/dev/nst0`):

**Server Configuration:**
```ini
[tape-lto]
user      = "root"
lockfile  = "/var/lock/backupd-lto.lock"
password  = "OffsiteTapeKey2026"
write     = "dd of=/dev/nst0 bs=256k status=progress"
read      = "dd if=/dev/nst0 bs=256k status=progress"
ListAllow = "10.0.0.0/8"
```

### Scenario 5: Automated Unattended Cron Jobs
Use the production-ready script provided in `examples/client_cron_job.sh`:
```bash
# Add to /etc/cron.d/backup-nightly
0 2 * * * root /usr/local/sbin/client_cron_job.sh
```

### Curated Production Configuration Examples in `examples/`

The repository supplies ready-to-deploy, specialized configuration templates in the `examples/` directory:

| Example File | Primary Focus | Default User / Privileges | Highlight Features |
|---|---|---|---|
| [`examples/backupd.full.conf`](file:///home/kajita/git/backupd-tyl/examples/backupd.full.conf) | Full Reference | Mixed (backup / postgres / root) | Demonstrates all configuration directives, logging options, and ACLs |
| [`examples/backupd.minimal.conf`](file:///home/kajita/git/backupd-tyl/examples/backupd.minimal.conf) | Edge / IoT / SBC | `root` (default) | Minimal footprint, ASCON-128a, low-resource VPS and Raspberry Pi |
| [`examples/backupd.database.conf`](file:///home/kajita/git/backupd-tyl/examples/backupd.database.conf) | Enterprise Databases | `postgres`, `mysql`, `redis`, `root` | PostgreSQL (`pg_dump`), MySQL/MariaDB, Redis RDB, SQLite |
| [`examples/backupd.zfs_btrfs.conf`](file:///home/kajita/git/backupd-tyl/examples/backupd.zfs_btrfs.conf) | Snapshot Replication | `root` (default) | Block-level `zfs send/recv` and `btrfs send/receive`, XChaCha20-Poly1305 |
| [`examples/backupd.virtualization.conf`](file:///home/kajita/git/backupd-tyl/examples/backupd.virtualization.conf) | VMs & Containers | `root` (default) | Proxmox VE (`.vma`), QEMU-KVM (`qemu-img`), Docker volumes, Podman images |
| [`examples/backupd.tape_vault.conf`](file:///home/kajita/git/backupd-tyl/examples/backupd.tape_vault.conf) | Physical Tape Vault | `root` (default) | SCSI non-rewinding drives (`/dev/nst0`), 256KB block sizing, drive status query |
| [`examples/backupd.multi_tenant.conf`](file:///home/kajita/git/backupd-tyl/examples/backupd.multi_tenant.conf) | Multi-Department | `finance`, `eng`, `root` | Departmental subnet isolation, immutable WORM archiving (`chattr +i`) |
| [`examples/backupd.hardening.conf`](file:///home/kajita/git/backupd-tyl/examples/backupd.hardening.conf) | Zero-Trust Compliance | `backup`, `root` | CIS benchmarks, PCI-DSS, `umask 0077`, AES-256-GCM, central SIEM syslog |

> [!TIP]
> Administrators can validate any configuration file before deploying using the `-C` flag:
> ```bash
> backupd -c /etc/backupd-tyl/backupd.conf -C
> ```

---

## 12. Security & Threat Model

`backupd-tyl` is designed under modern defense-in-depth principles:

1. **Eavesdropping and Tampering Protection**:
   All communication in modern mode is protected using Authenticated Encryption with Associated Data (AEAD). Any modification of ciphertext or framing in transit causes immediate AEAD tag verification failure and connection termination.
2. **Replay Attack Resistance**:
   Every connection begins with an ephemeral Curve25519 key exchange. Keys are never reused across sessions. Additionally, each frame carries a monotonically increasing 64-bit sequence counter.
3. **Denial-of-Service & Resource Exhaustion Defense**:
   Asymmetric key exchange algorithms (X25519) require scalar multiplications on elliptic curves. `backupd-tyl` enforces optional pre-crypto password checks before triggering crypto calculations.
4. **Buffer Overflow Mitigation**:
   All network I/O functions use bounded lengths (`read_all`, `write_all`, `safe_strncpy`). Format string vulnerabilities are strictly guarded against, and stack-smashing protection (`-fstack-protector-strong`) is enabled by default.
5. **Memory Zeroization**:
   Sensitive ephemeral keys, shared Diffie-Hellman secrets, and derived symmetric keys are zeroed with `tyl_crypto_wipe()` when sessions close.
6. **Privilege Dropping & Escalation Immunity**:
   When resource sections define unprivileged users or groups, `backupd` drops root's supplementary groups with `initgroups()`, switches GID and UID, and actively tests that root privileges cannot be regained (`setuid(0)` / `seteuid(0)` fail).
7. **File Descriptor Leak Prevention**:
   Prior to executing external backup commands (`extcmd.c`), the worker process closes all file descriptors above `stderr` (`fd >= 3`) to ensure daemon listening sockets and log handles are never exposed to child processes.
8. **Reverse DNS Injection Hardening**:
   Client hostnames retrieved via reverse DNS are strictly sanitized (`validfilechar`: alphanumeric, `.`, `-`, `_`) before expanding in command templates (`\h`, `\H`), eliminating remote command injection through spoofed PTR records.
9. **Timing-Safe Password Verification**:
   Password verification evaluates all bytes in constant time across the full length without early exits on length mismatch, eliminating timing side-channel leakage of password lengths.
10. **Descriptor Safety with `poll(2)`**:
    All timed socket I/O loops use standard POSIX `poll(2)` rather than `select(2)`, eliminating `FD_SETSIZE` (1024) buffer overflow limits under heavy connection loads.

---

## 13. Troubleshooting & Frequently Asked Questions

### Q: How does backupd-tyl handle OpenSSL dependencies?
`backupd-tyl` implements a dual-engine cryptographic architecture:
- If your system has OpenSSL development libraries (`libssl-dev` or `openssl-devel`), it links with `-lcrypto` and leverages CPU hardware acceleration (Intel/AMD AES-NI, AVX, and ARMv8 Crypto Extensions) through OpenSSL EVP. This allows your operating system's package manager to handle security updates and patches seamlessly.
- If OpenSSL development libraries are missing, `backupd-tyl` compiles 100% self-contained using internal pure-C constant-time implementations of all 6 AEAD ciphers with zero external dependencies.

### Q: How do I test the installation?
Run the built-in test suite:
```bash
# Test with current configuration (auto/system libcrypto):
make test

# Test with pure-C standalone mode (zero external dependencies):
make clean && make USE_SYSTEM_CRYPTO=0 test
```
This runs both unit cryptographic tests against NIST SP 800-38D / RFC 8439 test vectors and full integration loopback tests verifying all 6 AEAD ciphers (ASCON, Speck, ChaCha20, XChaCha20, AES-256-GCM, AES-128-GCM), shared passwords, multi-line commands, logging, throughput tracking, and exit codes.

### Q: The server returns exit code 4 (`TYL_EXIT_AUTH`)
The server resource has a `password = "..."` directive configured, but the client did not provide `-P <password>` (or provided an incorrect password), or the client IP is blocked by `ListAllow` / `ListDeny`. Provide the matching password on the client CLI or check the server ACLs.

### Q: How can I see debug logs?
On the server, run with `-L debug`:
```bash
backupd -c /etc/backupd-tyl/backupd.conf -F -L debug -t stderr
```
On the client, pass `-N stdout`:
```bash
backupc -h localhost -N stdout -l
```

---

## 14. Future Architecture & Post-2020 Modernization Roadmap

While `backupd-tyl` is designed to run universally across both modern and 2010s-era Linux servers (C99, standard POSIX, select/blocking I/O, bundled pure-C cryptographic fallback), a dedicated technical blueprint is maintained for adapting the codebase exclusively to post-2020 Linux environments (Kernel $\ge$ 5.4 / 5.10 LTS, glibc $\ge$ 2.31+, OpenSSL 3.0+, systemd $\ge$ 245).

Complete specifications, implementation snippets, and phased transition checklists are documented in:
* **[POST_2020_ROADMAP.md](POST_2020_ROADMAP.md)**

Key capabilities covered in the roadmap:
1. **Asynchronous I/O via `io_uring`**: Eliminating user-to-kernel context-switching bottlenecks for 40GbE/100GbE line-rate transfers.
2. **Kernel-Space Zero-Copy Pipelining (`splice`) & Kernel TLS (KTLS)**: Direct kernel socket offload of AEAD frame encryption.
3. **Atomic Process Management**: `close_range(2)` descriptor closing and `pidfd_open(2)` race-free child supervision.
4. **Zero-Trust In-Process Sandboxing**: Filesystem jailing with Linux Landlock LSM (Kernel $\ge$ 5.13) and Seccomp-BPF filters.
5. **Modern Systemd & Toolchain Hardening**: `ProtectSystem=strict`, `MemoryDenyWriteExecute=yes`, `-fstack-clash-protection`, `-fcf-protection=full`, `-std=gnu17`.

