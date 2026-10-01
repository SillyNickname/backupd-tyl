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
CFLAGS      ?= -std=gnu99 -DLINUX -O2 -Wall -Wextra -D_GNU_SOURCE -I. -fstack-protector-strong
LDFLAGS     ?=

# Baseline requirement for external system OpenSSL library:
# Package baseline is OpenSSL 1.1.1 (0x10101000L).
# If the local system version of OpenSSL is older than the one included with the package,
# the build automatically uses the cryptographic library included with the package.
OPENSSL_MIN_VER := 1.1.1
OPENSSL_MIN_HEX := 0x10101000L

HAVE_OPENSSL_HDR := $(shell printf '%s\n' '#include <openssl/opensslv.h>' | $(CC) $(CFLAGS) -E - >/dev/null 2>&1 && echo 1 || echo 0)
HAVE_OPENSSL_LIB := $(shell echo 'int main(void){return 0;}' | $(CC) -x c - -lcrypto -o /dev/null >/dev/null 2>&1 && echo 1 || echo 0)
OPENSSL_VER_OK   := $(shell printf '%s\n' '#include <openssl/opensslv.h>' '#if defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER >= $(OPENSSL_MIN_HEX))' 'int main(void){return 0;}' '#else' '#error "System OpenSSL is older than package baseline"' '#endif' | $(CC) $(CFLAGS) -x c - -o /dev/null -lcrypto >/dev/null 2>&1 && echo 1 || echo 0)
OPENSSL_VER_TEXT := $(shell printf '%s\n' '#include <openssl/opensslv.h>' | $(CC) $(CFLAGS) -E -dM -x c - 2>/dev/null | grep -m1 "OPENSSL_VERSION_TEXT" | cut -d'"' -f2)

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

.PHONY: all clean strip install install-systemd test

all: backupd backupc

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
