# Pre-compiled Standalone Binaries (Linux x86_64)

This directory contains standalone, stripped, pre-compiled binaries for **backupd-tyl** with **zero external dependencies**:

* **`backupd`**: Standalone remote backup daemon / service (x86_64 ELF).
* **`backupc`**: Streaming backup client (x86_64 ELF).

---

### Technical Specifications

* **Architecture**: Linux x86_64 (`x86_64-linux-gnu`).
* **External Dependencies**: **None** (links only against standard C library `libc.so.6`).
* **Cryptographic Engine**: Local bundled pure-C constant-time implementations of all 6 AEAD ciphers:
  - Ephemeral Curve25519 (X25519) Diffie-Hellman key exchange
  - ASCON-128a (NIST Lightweight Cryptography standard)
  - Speck-128/128-Poly1305 (Lightweight block cipher)
  - ChaCha20-Poly1305 (RFC 8439)
  - XChaCha20-Poly1305 (Extended 192-bit nonce)
  - AES-256-GCM (NIST SP 800-38D)
  - AES-128-GCM (NIST SP 800-38D)
* **Footprint**:
  - `backupc`: ~87 KB
  - `backupd`: ~108 KB
* **Security Hardening**:
  - Compiled with `-fstack-protector-strong`, format string guards, bounded buffer reads, and timing-safe password verification.

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
