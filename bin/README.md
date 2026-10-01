# Pre-compiled Standalone Binaries (Linux x86_64)

This directory contains standalone, stripped, pre-compiled binaries for **backupd-tyl** with **zero external dependencies**:

* **`backupd`**: Standalone remote backup daemon / service (x86_64 ELF).
* **`backupc`**: Streaming backup client (x86_64 ELF).

---

### Technical Specifications

* **Architecture**: Linux x86_64 (`x86_64-linux`).
* **Binary Type**: 100% Statically linked (`SYSV` ELF, stripped).
* **External Dependencies**: **ABSOLUTELY NONE** (no glibc version requirements, no `/lib64/ld-linux-x86-64.so.2` dynamic interpreter, no shared libraries).
* **Linux Kernel Compatibility**: Universal Linux kernel 2.6.32+ up to modern 6.x kernels (compatible with legacy CentOS 6.x / RHEL 6.x, Debian 6+, Ubuntu 10.04+, Alpine, Rocky, Arch, etc.).
* **Cryptographic Engine**: Local bundled pure-C constant-time implementations of all 6 AEAD ciphers:
  - Ephemeral Curve25519 (X25519) Diffie-Hellman key exchange
  - ASCON-128a (NIST Lightweight Cryptography standard)
  - Speck-128/128-Poly1305 (Lightweight block cipher)
  - ChaCha20-Poly1305 (RFC 8439)
  - XChaCha20-Poly1305 (Extended 192-bit nonce)
  - AES-256-GCM (NIST SP 800-38D)
  - AES-128-GCM (NIST SP 800-38D)
* **Footprint**:
  - `backupc`: ~179 KB (zero dependencies, static)
  - `backupd`: ~228 KB (zero dependencies, static)
* **Security Hardening**:
  - Bounded frame buffers, timing-safe constant-time password verification, memory zeroing, and defense-in-depth privilege drop checks.

---

### Installation via Installer Script

You can install these pre-compiled binaries directly onto any Linux machine without requiring a C compiler (`gcc`), `make`, or OpenSSL development packages:

```bash
# Using command-line flag
sudo ./scripts/install.sh --precompiled

# Or using environment variable
sudo USE_PRECOMPILED=1 ./scripts/install.sh
```

### Manual Installation

To install manually:

```bash
sudo install -d -m 0755 /usr/local/sbin /usr/local/bin
sudo install -m 0755 bin/backupd /usr/local/sbin/backupd
sudo install -m 0755 bin/backupc /usr/local/bin/backupc
sudo ln -sf /usr/local/sbin/backupd /usr/local/sbin/backupd-tyl
sudo ln -sf /usr/local/bin/backupc /usr/local/bin/backupc-tyl
```
