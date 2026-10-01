#
# Makefile for backupd-tyl (Backupd - Thirty Years Later)
#
# (C) 2026 Antigravity / Gemini (Google DeepMind)
# Based on original backupd by Ullrich von Bassewitz (1998)
# [Note: original author email uz@musoftware.de is no longer active]
# Requested and Commissioned by: Andre Kajita (kajita@univap.br)
#

PREFIX      ?= /usr/local
BINDIR      ?= $(PREFIX)/bin
SBINDIR     ?= $(PREFIX)/sbin
SYSCONFDIR  ?= /etc/backupd-tyl
SYSTEMDDIR  ?= /etc/systemd/system

CC          ?= gcc
# Probe stack protector flags for backward compatibility (GCC < 4.9 like CentOS 6 GCC 4.4 supports -fstack-protector but not -fstack-protector-strong)
STACK_PROT  := $(shell if $(CC) -fstack-protector-strong -x c /dev/null -E >/dev/null 2>&1; then echo "-fstack-protector-strong"; elif $(CC) -fstack-protector -x c /dev/null -E >/dev/null 2>&1; then echo "-fstack-protector"; fi)
CFLAGS      ?= -std=gnu99 -DLINUX -O2 -Wall -Wextra -D_GNU_SOURCE -I. $(STACK_PROT)
LDFLAGS     ?=

# Baseline requirement for external system OpenSSL library:
# Package baseline is OpenSSL 1.1.1 (0x10101000L).
# If the local system version of OpenSSL is older than the one included with the package,
# the build automatically uses the cryptographic library included with the package.
OPENSSL_MIN_VER := 1.1.1
OPENSSL_MIN_HEX := 0x10101000L

# Probes avoid raw '#' characters or subshells to ensure strict compatibility with GNU Make 3.81 (CentOS 6)
HAVE_OPENSSL_HDR := $(shell echo 'int main(void){return 0;}' | $(CC) $(CFLAGS) -include openssl/opensslv.h -E -x c - >/dev/null 2>&1 && echo 1 || echo 0)
HAVE_OPENSSL_LIB := $(shell echo 'int main(void){return 0;}' | $(CC) -x c - -lcrypto -o /dev/null >/dev/null 2>&1 && echo 1 || echo 0)
OPENSSL_VER_OK   := $(shell echo 'int main(void){int c[OPENSSL_VERSION_NUMBER >= $(OPENSSL_MIN_HEX) ? 1 : -1];(void)c;return 0;}' | $(CC) $(CFLAGS) -include openssl/opensslv.h -x c - -o /dev/null -lcrypto >/dev/null 2>&1 && echo 1 || echo 0)
OPENSSL_VER_TEXT := $(shell echo '' | $(CC) $(CFLAGS) -include openssl/opensslv.h -E -dM -x c - 2>/dev/null | grep -m1 "OPENSSL_VERSION_TEXT" | cut -d'"' -f2)

USE_SYSTEM_CRYPTO ?= auto

ifeq ($(USE_SYSTEM_CRYPTO),0)
  USE_OPENSSL := 0
  CRYPTO_MODE_STR = Local bundled copy (forced by USE_SYSTEM_CRYPTO=0)
else
  # If system OpenSSL headers and lib are present and version >= 1.1.1
  ifeq ($(OPENSSL_VER_OK),1)
    USE_OPENSSL := 1
    CRYPTO_MODE_STR = System OpenSSL libcrypto ($(OPENSSL_VER_TEXT))
  else
    USE_OPENSSL := 0
    ifeq ($(HAVE_OPENSSL_HDR),1)
      CRYPTO_MODE_STR = Local bundled copy (system $(OPENSSL_VER_TEXT) is older than package baseline $(OPENSSL_MIN_VER))
    else
      CRYPTO_MODE_STR = Local bundled copy (zero external dependencies)
    endif
  endif
endif

LDLIBS      ?=

ifeq ($(USE_OPENSSL),1)
  CFLAGS  += -DTYL_USE_OPENSSL
  LDLIBS  += -lcrypto
endif

$(info [backupd-tyl build] Cryptography engine: $(CRYPTO_MODE_STR))

CRYPTO_OBJS = crypto/sha256.o           \
              crypto/x25519.o           \
              crypto/ascon128a.o        \
              crypto/speck.o            \
              crypto/poly1305.o         \
              crypto/chacha20poly1305.o \
              crypto/aes_gcm.o          \
              crypto/tyl_crypto.o

COMMON_OBJS = util.o

SERVER_OBJS = backupd.o check.o client.o config.o error.o extcmd.o global.o sig.o $(COMMON_OBJS) $(CRYPTO_OBJS)
CLIENT_OBJS = backupc.o $(COMMON_OBJS) $(CRYPTO_OBJS)

.PHONY: all clean strip install install-systemd test static

all: backupd backupc

static:
	@if command -v musl-gcc >/dev/null 2>&1; then \
		echo "Building standalone static binaries with musl-gcc..."; \
		$(MAKE) CC="musl-gcc" CFLAGS="-std=gnu99 -DLINUX -O2 -Wall -Wextra -D_GNU_SOURCE -I. -static" LDFLAGS="-static" USE_SYSTEM_CRYPTO=0 all; \
	else \
		echo "Building static binaries with $(CC)..."; \
		$(MAKE) CFLAGS="$(CFLAGS) -static" LDFLAGS="-static" USE_SYSTEM_CRYPTO=0 all; \
	fi

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

backupd: $(SERVER_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SERVER_OBJS) $(LDLIBS)

backupc: $(CLIENT_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(CLIENT_OBJS) $(LDLIBS)

test: all
	@echo "Running cryptographic unit tests..."
	$(CC) $(CFLAGS) $(LDFLAGS) -I. tests/test_crypto.c $(CRYPTO_OBJS) -o test_runner $(LDLIBS)
	./test_runner
	@rm -f test_runner
	@echo "Running integration test suite..."
	./tests/run_integration_tests.sh

strip: backupd backupc
	strip backupd backupc

install: all
	install -d -m 0755 $(DESTDIR)$(SBINDIR)
	install -d -m 0755 $(DESTDIR)$(BINDIR)
	install -d -m 0750 $(DESTDIR)$(SYSCONFDIR)
	install -m 0755 backupd $(DESTDIR)$(SBINDIR)/backupd
	install -m 0755 backupc $(DESTDIR)$(BINDIR)/backupc
	ln -sf backupd $(DESTDIR)$(SBINDIR)/backupd-tyl
	ln -sf backupc $(DESTDIR)$(BINDIR)/backupc-tyl
	@if [ ! -f $(DESTDIR)$(SYSCONFDIR)/backupd.conf ]; then \
	    install -m 0640 backupd.conf.sample $(DESTDIR)$(SYSCONFDIR)/backupd.conf; \
	    echo "Installed default config to $(DESTDIR)$(SYSCONFDIR)/backupd.conf"; \
	fi

clean:
	rm -f *.o crypto/*.o backupd backupc .depend test_runner
