# Post-2020 Linux Modernization Blueprint & Architectural Roadmap

```
  _                 _                   _       _             _ 
 | |__   __ _  ____| | ___   _ _ __   __| |     | |_ _   _  __| |
 | '_ \ / _` |/ ___| |/ / | | | '_ \ / _` |_____| __| | | |/ _` |
 | |_) | (_| | |___|   <| |_| | |_) | (_| |_____| |_| |_| | (_| |
 |_.__/ \__,_|\____|_|\_\\__,_| .__/ \__,_|      \__|\__, |\__,_|
                              |_|                    |___/       
                   POST-2020 ARCHITECTURAL ROADMAP
```

---

### Document Overview & Attribution

* **Document Purpose**: Technical specification, code audit, and step-by-step implementation guide for adapting `backupd-tyl` specifically to post-2020 Linux distributions (Linux Kernel $\ge$ 5.4 / 5.10 LTS, glibc $\ge$ 2.31+, OpenSSL 3.0+, systemd $\ge$ 245, GCC $\ge$ 10 / Clang $\ge$ 11).
* **Project Status**: The primary codebase maintains 2010s-era backward compatibility (C99, standard POSIX, select/blocking I/O, pure-C bundled crypto fallback) to support legacy production servers. This document preserves the architectural blueprint and exact refactoring instructions for a future post-2020 targeted release or fork.
* **Commissioned by**: **Andre Kajita** (`kajita@univap.br`)
* **Architected by**: Antigravity / Gemini (Google DeepMind, 2026)
* **Based on Original Work by**: Ullrich von Bassewitz (1998, `uz@musoftware.de` [inactive])

---

## 1. Executive Summary & Design Target

### Target Platform Definition
A "Post-2020 Linux" platform is defined as:
* **Operating Systems**: Ubuntu $\ge$ 20.04 LTS / 22.04 LTS / 24.04 LTS, Debian $\ge$ 11 (Bullseye) / 12 (Bookworm), RHEL/CentOS/Rocky/Alma $\ge$ 8 / 9, Fedora $\ge$ 32, Alpine $\ge$ 3.12, openSUSE Leap 15.3+ / Tumbleweed, Arch Linux.
* **Linux Kernel**: $\ge$ 5.4 (Ubuntu 20.04 baseline) or $\ge$ 5.10 (Debian 11 baseline).
* **C Standard Library**: GNU C Library (glibc) $\ge$ 2.31 or Musl libc $\ge$ 1.2.
* **Cryptographic Foundation**: OpenSSL $\ge$ 1.1.1 / 3.0+ (OpenSSL 1.0.x and 0.9.8 are 100% obsolete and absent).
* **Compiler Toolchain**: GCC $\ge$ 10 or Clang $\ge$ 11 (defaulting to C17/GNU17).

---

## 2. Technical Pillars of Modernization

```
+-----------------------------------------------------------------------------------+
|                        POST-2020 MODERNIZATION PILLARS                           |
+-----------------------------------------------------------------------------------+
| 1. High-Performance I/O    : io_uring async rings, zero syscall context-switches  |
| 2. Kernel-Space Streaming  : splice(2), vmsplice(2), copy_file_range(2)           |
| 3. Race-Free Processes     : close_range(2), pidfd_open(2), waitid(P_PIDFD)       |
| 4. Kernel Cryptography     : Kernel TLS (KTLS) socket offload, OpenSSL 3 Provider |
| 5. Zero-Trust Sandboxing   : Landlock LSM filesystem jail, Seccomp-BPF filters    |
| 6. Systemd Hardening       : Strict dynamic sandboxing, ProtectSystem=strict      |
| 7. Modern C & Toolchain    : C17 / C23 standard, -fstack-clash-protection, PIE    |
+-----------------------------------------------------------------------------------+
```

---

## 3. Detailed Component Refactoring Blueprints

### Pillar 1: High-Performance Asynchronous I/O via `io_uring`

#### Current Status (2010s POSIX)
* Located in [`util.c`](file:///home/kajita/git/backupd-tyl/util.c#L140-L190) (`util_read_all`, `util_write_all`) and the main streaming loops in [`backupc.c`](file:///home/kajita/git/backupd-tyl/backupc.c) and [`client.c`](file:///home/kajita/git/backupd-tyl/client.c).
* Employs synchronous, blocking 64KB chunk loops with standard `read(2)` and `write(2)`.
* Every chunk requires 2 user-to-kernel context switches. On high-speed 40GbE/100GbE networks, CPU context switching becomes the primary throughput bottleneck.

#### Post-2020 Architecture (`io_uring`)
* Linux 5.1+ introduced `io_uring`, stabilized and production-hardened in Kernel 5.4 / 5.10.
* Uses two lockless ring buffers (Submission Queue `SQ` and Completion Queue `CQ`) shared between user space and kernel space.
* Registered buffers (`IORING_REGISTER_BUFFERS`) and fixed file descriptors (`IORING_REGISTER_FILES`) allow streaming multi-gigabyte or terabyte archives with zero syscall overhead after setup.

#### Implementation Pattern for `util.c` / `backupc.c`:
```c
#include <liburing.h>

#define TYL_URING_ENTRIES 64

struct tyl_ring_ctx {
    struct io_uring ring;
    struct iovec iovecs[TYL_URING_ENTRIES];
    uint8_t bufs[TYL_URING_ENTRIES][TYL_MAX_FRAME_SIZE];
};

int tyl_ring_init(struct tyl_ring_ctx* ctx) {
    return io_uring_queue_init(TYL_URING_ENTRIES, &ctx->ring, 0);
}

/* Submit asynchronous framed encryption/decryption requests without syscall per chunk */
int tyl_ring_submit_write(struct tyl_ring_ctx* ctx, int fd, int idx, size_t len) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    io_uring_prep_write(sqe, fd, ctx->bufs[idx], len, 0);
    io_uring_sqe_set_data(sqe, (void*)(uintptr_t)idx);
    return io_uring_submit(&ctx->ring);
}
```

---

### Pillar 2: Process Management & Pipe Forwarding (`extcmd.c`)

#### 1. Atomic Descriptor Closure (`close_range`)
* **Current Status**: In [`extcmd.c`](file:///home/kajita/git/backupd-tyl/extcmd.c#L240-L280), closing inherited file descriptors before `execvp()` loops from 3 up to `sysconf(_SC_OPEN_MAX)` (which can be 1,048,576 iterations) or parses `/proc/self/fd/`.
* **Post-2020 Solution**: `close_range(2)` (Linux 5.9+, glibc 2.34+):
  ```c
  #include <unistd.h>
  #include <linux/close_range.h>

  /* Atomically close all descriptors from 3 upwards with zero loop overhead */
  if (close_range(3, ~0U, CLOSE_RANGE_CLOEXEC) < 0) {
      /* Fallback for Linux 5.4 - 5.8 */
  }
  ```

#### 2. Race-Free Child Process Supervision (`pidfd`)
* **Current Status**: Tracks child command PIDs with integer `pid_t` and `waitpid()`. Under extreme server load or rapid fork/exit cycles, PID recycling can lead to race conditions where signals are sent to the wrong recycled process.
* **Post-2020 Solution**: `pidfd_open(2)` and `waitid(P_PIDFD, ...)` (Linux 5.3+):
  ```c
  #include <sys/syscall.h>
  #include <sys/wait.h>

  int pidfd = syscall(SYS_pidfd_open, child_pid, 0);
  if (pidfd >= 0) {
      siginfo_t info;
      /* Wait on process descriptor - immune to PID reuse */
      waitid(P_PIDFD, pidfd, &info, WEXITED);
      close(pidfd);
  }
  ```

#### 3. Zero-Copy Kernel Splicing (`splice`)
* When streaming raw or unencrypted pipelines (such as legacy mode or internal pipelines), data can be forwarded from the child process stdout pipe directly into the network socket without passing through user memory buffers:
  ```c
  /* Splice up to 64KB directly in kernel page cache */
  ssize_t bytes = splice(pipe_fd, NULL, sock_fd, NULL, 65536, SPLICE_F_MOVE | SPLICE_F_MORE);
  ```

---

### Pillar 3: Cryptography Modernization & OpenSSL 3.x Provider Architecture

#### 1. Elimination of Obsolete Compatibility Guards
* In [`crypto/tyl_crypto.c`](file:///home/kajita/git/backupd-tyl/crypto/tyl_crypto.c#L25-L35) and [`Makefile`](file:///home/kajita/git/backupd-tyl/Makefile#L20-L40), the preprocessor checks `OPENSSL_VERSION_NUMBER < 0x10101000L` can be removed. OpenSSL 1.0.x is extinct on post-2020 systems.

#### 2. OpenSSL 3.0+ Provider Architecture
* OpenSSL 3.0 replaced the old engine API with **Providers** (`OSSL_PROVIDER`).
* Modern cipher instantiation:
  ```c
  #include <openssl/provider.h>
  #include <openssl/evp.h>

  /* Explicitly fetch algorithms from the Default or FIPS provider */
  EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
  ```

#### 3. Kernel TLS (KTLS) Offload
* Linux 4.17+ and OpenSSL 3.0+ support **KTLS** (Kernel TLS socket offload).
* After the ephemeral X25519 handshake derives the symmetric keys (`s->tx_key`, `s->rx_key`), the AES-GCM framing can be loaded directly into the kernel TCP socket:
  ```c
  #include <linux/tls.h>

  struct tls12_crypto_info_aes_gcm_256 crypto_info;
  /* Populate crypto_info with key and IV ... */
  setsockopt(sock_fd, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info));
  ```
* **Benefit**: Once KTLS is enabled on the socket, `sendfile(2)` or `splice(2)` can be called directly from disk or pipes into the encrypted socket. The Linux kernel's network subsystem handles encryption (utilizing hardware AES-NI instructions) during packet generation.

#### 4. Cryptographic Entropy Gathering
* Replace all fallback logic opening `/dev/urandom` with direct `getrandom(2)` (available in glibc 2.25+ and Linux 3.17+):
  ```c
  #include <sys/random.h>

  ssize_t ret = getrandom(buf, len, 0); /* Guaranteed cryptographically secure and non-blocking */
  ```

---

### Pillar 4: Zero-Trust Security & In-Process Sandboxing

#### 1. Linux Landlock LSM (Linux 5.13+)
* Landlock enables unprivileged process sandboxing.
* In [`backupd.c`](file:///home/kajita/git/backupd-tyl/backupd.c#L300-L360), before launching a backup read or write command, the child process can restrict its own filesystem access strictly to the path defined in the configuration:
  ```c
  #include <linux/landlock.h>
  #include <sys/prctl.h>

  struct landlock_ruleset_attr attr = {
      .handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE
  };
  int ruleset_fd = syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0);
  /* Add path rules and enforce sandbox */
  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  syscall(SYS_landlock_restrict_self, ruleset_fd, 0);
  ```

#### 2. Seccomp-BPF Syscall Whitelisting
* A strict Seccomp-BPF filter can be applied to child command runners in `extcmd.c`. For read-only commands (e.g., `tar -cpf -`), network syscalls (`socket`, `connect`, `bind`) can be blocked at the kernel level.

#### 3. Modern Systemd Sandboxing Directives
* Update [`scripts/backupd.service`](file:///home/kajita/git/backupd-tyl/scripts/backupd.service) to utilize systemd v245+ security capabilities:
  ```ini
  [Service]
  Type=simple
  ExecStart=/usr/local/sbin/backupd -F -c /etc/backupd-tyl/backupd.conf
  Restart=on-failure

  # Post-2020 Systemd Hardening
  ProtectSystem=strict
  ProtectHome=read-only
  ProtectKernelTunables=yes
  ProtectKernelModules=yes
  ProtectControlGroups=yes
  MemoryDenyWriteExecute=yes
  RestrictRealtime=yes
  RestrictNamespaces=yes
  RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
  SystemCallFilter=@system-service
  SystemCallErrorNumber=EPERM
  LockPersonality=yes
  ```

---

### Pillar 5: Networking Modernization

* **Dual-Stack IPv6/IPv4 Sockets**:
  * Replace `AF_INET` socket binding in `backupd.c` with dual-stack `AF_INET6`:
    ```c
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    int no = 0;
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));
    ```
  * Automatically binds and listens to both IPv4 and IPv6 on port 12153 simultaneously.
* **`SO_REUSEPORT` Multi-Worker Architecture**:
  * Enables multiple worker threads/processes to bind to the same listening port. The Linux kernel load-balances incoming connections across workers in the networking stack.

---

### Pillar 6: C Standard & Build Toolchain

* **C Standard**: Bump `Makefile` from `-std=gnu99` to `-std=gnu17` (ISO C17 with GNU extensions).
* **Modern Security Compiler Flags**:
  ```makefile
  CFLAGS += -std=gnu17 -D_GNU_SOURCE -O2 -Wall -Wextra \
            -fstack-protector-strong -fstack-clash-protection \
            -fcf-protection=full \
            -D_FORTIFY_SOURCE=3 \
            -Wformat=2 -Werror=format-security \
            -pie -fPIE
  LDFLAGS += -Wl,-z,relro,-z,now
  ```

---

## 4. Phased Migration Checklist (For Future Execution)

When the decision is made to build or fork a post-2020 targeted release of `backupd-tyl`, follow this exact sequence:

- [ ] **Phase 1: Build & Toolchain Update**
  - [ ] Modify `Makefile`: Change `-std=gnu99` to `-std=gnu17`.
  - [ ] Add `-fstack-clash-protection`, `-fcf-protection=full`, and `-D_FORTIFY_SOURCE=3` to `CFLAGS`.
  - [ ] Remove `OPENSSL_MIN_HEX` version check fallback logic; require `libcrypto >= 1.1.1` as default.

- [ ] **Phase 2: Process & FD Hygiene**
  - [ ] In `extcmd.c`: Replace the `sysconf(_SC_OPEN_MAX)` loop with `close_range(3, ~0U, CLOSE_RANGE_CLOEXEC)`.
  - [ ] In `extcmd.c`: Implement `pidfd_open` and `waitid(P_PIDFD, ...)` for child process termination tracking.

- [ ] **Phase 3: Cryptography & Randomness**
  - [ ] In `crypto/tyl_crypto.c`: Remove OpenSSL 1.0.x / 0.9.8 preprocessor `#if` checks.
  - [ ] Standardize entropy gathering strictly to `getrandom(2)`.
  - [ ] (Optional) Add OpenSSL 3.0+ Provider API fetching (`EVP_CIPHER_fetch`).

- [ ] **Phase 4: Networking & Zero-Copy**
  - [ ] In `backupd.c`: Transition server socket to dual-stack `AF_INET6` (`IPV6_V6ONLY=0`).
  - [ ] In `util.c`: Implement `splice(2)` fast-path for unencrypted pipe forwarding.
  - [ ] (Advanced) Implement `liburing` / `io_uring` ring buffer streaming engine for high-throughput client/server I/O.

- [ ] **Phase 5: Systemd & Sandboxing**
  - [ ] In `systemd/backupd.service`: Add strict sandboxing directives (`ProtectSystem=strict`, `MemoryDenyWriteExecute=yes`, etc.).
  - [ ] Add optional Landlock LSM filesystem restriction in `backupd.c` child workers.

- [ ] **Phase 6: Verification & QA**
  - [ ] Run full test suite: `make clean && make test`.
  - [ ] Run test suite under AddressSanitizer and UndefinedBehaviorSanitizer:
    ```bash
    make clean && make CFLAGS="-fsanitize=address,undefined -g" test
    ```
  - [ ] Update `README.md` and `MANUAL.md`.

---

## 5. Summary Matrix: 2010s Universal vs. Post-2020 Modernized

| Architectural Layer | Current Universal (2010s+) | Post-2020 Modernized |
| :--- | :--- | :--- |
| **Linux Kernel Minimum** | Linux 2.6.32+ (CentOS 6, Debian 6/7) | Linux 5.4+ / 5.10+ LTS |
| **C Standard** | C99 / GNU99 | C17 / GNU17 or C23 |
| **I/O Engine** | Synchronous chunked `read(2)` / `write(2)` | Asynchronous `io_uring` & `splice(2)` |
| **File Descriptor Cleanup** | Loop up to `_SC_OPEN_MAX` or `/proc/self/fd` | Single atomic `close_range(2)` syscall |
| **Process Tracking** | Standard `pid_t` + `waitpid` | `pidfd_open(2)` + `waitid(P_PIDFD)` |
| **Entropy Source** | `getrandom(2)` with `/dev/urandom` fallback | Direct non-blocking `getrandom(2)` |
| **System OpenSSL Baseline** | OpenSSL 1.1.1+ with pure-C bundled fallback | OpenSSL 3.0+ Provider API / KTLS |
| **Network Listener** | `AF_INET` IPv4 | Dual-stack `AF_INET6` + `SO_REUSEPORT` |
| **Sandboxing** | Standard POSIX UID/GID drop (`setuid`) | Landlock LSM + Seccomp-BPF + systemd |

---

*Preserved for future development of `backupd-tyl`.*
