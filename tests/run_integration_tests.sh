#!/bin/bash
#
# run_integration_tests.sh - Integration test suite for backupd-tyl
#
# (C) 2026 Antigravity / Gemini (Google DeepMind)
# Part of backupd-tyl (Backupd - Thirty Years Later)
# Requested and Commissioned by: Andre Kajita (kajita@univap.br)
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

BACKUPD="$REPO_DIR/backupd"
BACKUPC="$REPO_DIR/backupc"

if [ ! -x "$BACKUPD" ] || [ ! -x "$BACKUPC" ]; then
    echo "Building backupd-tyl binaries..."
    make -C "$REPO_DIR" all
fi

# Set up temporary working directory
TMP_DIR="$(mktemp -d /tmp/backupd-test.XXXXXX)"
TEST_PORT=$((12000 + RANDOM % 10000))
PID_FILE="$TMP_DIR/backupd.pid"
LOG_FILE="$TMP_DIR/backupd.log"
CONF_FILE="$TMP_DIR/test.conf"

echo "=== STARTING BACKUPD-TYL INTEGRATION TEST SUITE ==="
echo "Working directory: $TMP_DIR"
echo "Test port: $TEST_PORT"

# Generate test configuration with file logging enabled
cat <<EOF > "$CONF_FILE"
Port = $TEST_PORT
BindAddress = "127.0.0.1"
AllowLegacy = yes
ListAllow = "127.0.0.1/32 localhost"
PidFile = "$PID_FILE"
LogTarget = file
LogFile = "$LOG_FILE"
LogLevel = debug

[test-stream]
write = "cat > $TMP_DIR/stream.dat"
read = "cat $TMP_DIR/stream.dat"

[test-auth]
password = "SecretAuthPass42"
write = "cat > $TMP_DIR/auth.dat"
read = "cat $TMP_DIR/auth.dat"

[test-multiline]
write = "sed 's/foo/bar/g' | \\
         tr 'a-z' 'A-Z' > $TMP_DIR/multiline.dat"
read = "cat $TMP_DIR/multiline.dat"

[test-hidden]
ListDeny = "127.0.0.1/32 localhost *"
read = "echo hidden"

[test-legacy]
write = "cat > $TMP_DIR/legacy.dat"
read = "cat $TMP_DIR/legacy.dat"
EOF

cleanup() {
    echo "Cleaning up test environment..."
    if [ -f "$PID_FILE" ]; then
        PID="$(cat "$PID_FILE" 2>/dev/null || true)"
        if [ -n "$PID" ]; then
            kill "$PID" 2>/dev/null || true
            sleep 0.5
            kill -9 "$PID" 2>/dev/null || true
        fi
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

# 1. Start backupd in standalone background daemon mode
echo "1. Starting backupd standalone server with file logging..."
"$BACKUPD" -c "$CONF_FILE" -d
sleep 1

if [ ! -f "$PID_FILE" ]; then
    echo "ERROR: Server failed to create PID file!"
    exit 1
fi
PID="$(cat "$PID_FILE")"
echo "   Server running with PID $PID on port $TEST_PORT"

# 2. Test LIST command
echo "2. Testing LIST command..."
LIST_OUT="$("$BACKUPC" -h 127.0.0.1 -p "$TEST_PORT" -l)"
echo "$LIST_OUT"
echo "$LIST_OUT" | grep -q "test-stream"
echo "$LIST_OUT" | grep -q "test-auth"
echo "$LIST_OUT" | grep -q "test-multiline"
echo "$LIST_OUT" | grep -q "test-legacy"
# test-hidden MUST NOT be listed due to local ListDeny
if echo "$LIST_OUT" | grep -q "test-hidden"; then
    echo "FAILED: test-hidden was listed but should have been blocked by local ListDeny!"
    exit 1
fi
echo "   [PASS] LIST command with local ListDeny override"

# 3. Test Modern Data Transfer with ASCON-128a (default lightweight cipher)
echo "3. Testing data transfer with ASCON-128a..."
dd if=/dev/urandom of="$TMP_DIR/input.dat" bs=64k count=16 status=none
"$BACKUPC" -h 127.0.0.1 -p "$TEST_PORT" -w test-stream < "$TMP_DIR/input.dat"
"$BACKUPC" -h 127.0.0.1 -p "$TEST_PORT" -r test-stream > "$TMP_DIR/output_ascon.dat"
cmp "$TMP_DIR/input.dat" "$TMP_DIR/output_ascon.dat"
echo "   [PASS] 1MB transfer bit-for-bit identical (ASCON-128a)"

# 4. Test Modern Data Transfer with Speck-128/128-Poly1305
echo "4. Testing data transfer with Speck-128/128-Poly1305..."
"$BACKUPC" -h 127.0.0.1 -p "$TEST_PORT" -c speck -w test-stream < "$TMP_DIR/input.dat"
"$BACKUPC" -h 127.0.0.1 -p "$TEST_PORT" -c speck -r test-stream > "$TMP_DIR/output_speck.dat"
cmp "$TMP_DIR/input.dat" "$TMP_DIR/output_speck.dat"
echo "   [PASS] 1MB transfer bit-for-bit identical (Speck-Poly1305)"

# 5. Test Modern Data Transfer with ChaCha20-Poly1305
echo "5. Testing data transfer with ChaCha20-Poly1305..."
"$BACKUPC" -h 127.0.0.1 -p "$TEST_PORT" -c chacha20 -w test-stream < "$TMP_DIR/input.dat"
"$BACKUPC" -h 127.0.0.1 -p "$TEST_PORT" -c chacha20 -r test-stream > "$TMP_DIR/output_chacha.dat"
cmp "$TMP_DIR/input.dat" "$TMP_DIR/output_chacha.dat"
echo "   [PASS] 1MB transfer bit-for-bit identical (ChaCha20-Poly1305)"

# 5b. Test Modern Data Transfer with AES-256-GCM (--secure mode and default)
echo "5b. Testing data transfer with AES-256-GCM (--secure)..."
"$BACKUPC" -h 127.0.0.1 -p "$TEST_PORT" -s -w test-stream < "$TMP_DIR/input.dat"
"$BACKUPC" -h 127.0.0.1 -p "$TEST_PORT" -s -r test-stream > "$TMP_DIR/output_aes256.dat"
cmp "$TMP_DIR/input.dat" "$TMP_DIR/output_aes256.dat"
echo "   [PASS] 1MB transfer bit-for-bit identical (AES-256-GCM)"

# 5c. Test Modern Data Transfer with AES-128-GCM
echo "5c. Testing data transfer with AES-128-GCM..."
"$BACKUPC" -h 127.0.0.1 -p "$TEST_PORT" -c aes128 -w test-stream < "$TMP_DIR/input.dat"
"$BACKUPC" -h 127.0.0.1 -p "$TEST_PORT" -c aes128 -r test-stream > "$TMP_DIR/output_aes128.dat"
cmp "$TMP_DIR/input.dat" "$TMP_DIR/output_aes128.dat"
echo "   [PASS] 1MB transfer bit-for-bit identical (AES-128-GCM)"

# 5d. Test Modern Data Transfer with XChaCha20-Poly1305 (extended nonce)
echo "5d. Testing data transfer with XChaCha20-Poly1305..."
"$BACKUPC" -h 127.0.0.1 -p "$TEST_PORT" -c xchacha20 -w test-stream < "$TMP_DIR/input.dat"
"$BACKUPC" -h 127.0.0.1 -p "$TEST_PORT" -c xchacha20 -r test-stream > "$TMP_DIR/output_xchacha.dat"
cmp "$TMP_DIR/input.dat" "$TMP_DIR/output_xchacha.dat"
echo "   [PASS] 1MB transfer bit-for-bit identical (XChaCha20-Poly1305)"

# 6. Test Pre-Crypto Password Authentication
echo "6. Testing Pre-Crypto Shared Password Authentication..."
# Should fail without password
if "$BACKUPC" -h 127.0.0.1 -p "$TEST_PORT" -w test-auth < "$TMP_DIR/input.dat" 2>/dev/null; then
    echo "FAILED: Connection without password succeeded on password-protected resource!"
    exit 1
fi
echo "   [PASS] Rejected connection without password"

# Should fail with wrong password
if "$BACKUPC" -h 127.0.0.1 -p "$TEST_PORT" -P "WrongPassword" -w test-auth < "$TMP_DIR/input.dat" 2>/dev/null; then
    echo "FAILED: Connection with wrong password succeeded!"
    exit 1
fi
echo "   [PASS] Rejected connection with wrong password"

# Should succeed with correct password
"$BACKUPC" -h 127.0.0.1 -p "$TEST_PORT" -P "SecretAuthPass42" -w test-auth < "$TMP_DIR/input.dat"
"$BACKUPC" -h 127.0.0.1 -p "$TEST_PORT" -P "SecretAuthPass42" -r test-auth > "$TMP_DIR/output_auth.dat"
cmp "$TMP_DIR/input.dat" "$TMP_DIR/output_auth.dat"
echo "   [PASS] Accepted and transferred with correct password"

# 7. Test Multi-line Server Command Execution
echo "7. Testing multi-line server command execution..."
echo "foo hello foo test" | "$BACKUPC" -h 127.0.0.1 -p "$TEST_PORT" -w test-multiline
ML_OUT="$("$BACKUPC" -h 127.0.0.1 -p "$TEST_PORT" -r test-multiline)"
echo "   Output: '$ML_OUT'"
if [ "$ML_OUT" != "BAR HELLO BAR TEST" ]; then
    echo "FAILED: Multi-line command output did not match expected 'BAR HELLO BAR TEST' (got '$ML_OUT')"
    exit 1
fi
echo "   [PASS] Multi-line command pipeline executed correctly"

# 8. Test Legacy Compatibility Mode (-L)
echo "8. Testing legacy 0.20 compatibility mode (-L)..."
"$BACKUPC" -L -h 127.0.0.1 -p "$TEST_PORT" -w test-legacy < "$TMP_DIR/input.dat"
"$BACKUPC" -L -h 127.0.0.1 -p "$TEST_PORT" -r test-legacy > "$TMP_DIR/output_legacy.dat"
cmp "$TMP_DIR/input.dat" "$TMP_DIR/output_legacy.dat"
LEGACY_LIST="$("$BACKUPC" -L -h 127.0.0.1 -p "$TEST_PORT" -l)"
echo "$LEGACY_LIST" | grep -q "test-legacy"
echo "   [PASS] Legacy 0.20 unencrypted mode works seamlessly"

# 9. Test Server Logging & SIGHUP Log Reopen
echo "9. Testing Server Logging and SIGHUP Reopen..."
if [ ! -f "$LOG_FILE" ]; then
    echo "FAILED: Expected server log file $LOG_FILE was not created!"
    exit 1
fi
grep -q "\[NOTICE\]" "$LOG_FILE"
grep -q "\[INFO\]" "$LOG_FILE"
echo "   [PASS] Server log file created with proper levels and timestamps"

# Test SIGHUP reloading
kill -HUP "$PID"
sleep 0.5
grep -q "SIGHUP received" "$LOG_FILE"
echo "   [PASS] SIGHUP caught and logged properly"

# 10. Test Client Negotiation Logging (-N)
echo "10. Testing Client Negotiation Logging (-N)..."
NEG_LOG="$TMP_DIR/client_neg.log"
"$BACKUPC" -h 127.0.0.1 -p "$TEST_PORT" -N "$NEG_LOG" -l >/dev/null
if [ ! -f "$NEG_LOG" ]; then
    echo "FAILED: Negotiation log file was not created!"
    exit 1
fi
grep -q "\[NEGOTIATION\]" "$NEG_LOG"
grep -q "X25519" "$NEG_LOG"
grep -q "HKDF-SHA256" "$NEG_LOG"
grep -q "TLS-style negotiation complete" "$NEG_LOG"
echo "   [PASS] Client negotiation logged X25519, HKDF-SHA256, and AEAD framing"

# Also test negotiation logged to stdout
NEG_STDOUT=$("$BACKUPC" -h 127.0.0.1 -p "$TEST_PORT" -N stdout -l)
echo "$NEG_STDOUT" | grep -q "\[NEGOTIATION\]"
echo "   [PASS] Client negotiation logged to stdout when requested"

# 11. Test Client Network Throughput Option (-T)
echo "11. Testing Client Network Throughput Option (-T)..."
# By default, nothing on stderr
STDERR_DEFAULT=$("$BACKUPC" -h 127.0.0.1 -p "$TEST_PORT" -r test-stream 2>&1 >/dev/null)
if echo "$STDERR_DEFAULT" | grep -q "Throughput"; then
    echo "FAILED: Throughput was shown by default without -T!"
    exit 1
fi
echo "   [PASS] By default, network throughput is completely silent"

# With -T, throughput is shown on stderr
STDERR_THROUGHPUT=$("$BACKUPC" -h 127.0.0.1 -p "$TEST_PORT" -T -r test-stream 2>&1 >/dev/null)
echo "$STDERR_THROUGHPUT" | grep -q "\[Throughput\]"
echo "$STDERR_THROUGHPUT" | grep -q "MB/s"
echo "   [PASS] Network throughput displayed accurately with -T"

# 12. Test Standard Script Exit Codes
echo "12. Testing Script Exit Codes..."
set +e

# Success -> Exit code 0
"$BACKUPC" -h 127.0.0.1 -p "$TEST_PORT" -l >/dev/null 2>&1
EC=$?
if [ $EC -ne 0 ]; then
    echo "FAILED: Expected exit code 0 for success, got $EC"
    exit 1
fi
echo "   [PASS] Exit code 0 on SUCCESS"

# Bad CLI args -> Exit code 1 (TYL_EXIT_USAGE)
"$BACKUPC" --invalid-argument-xyz >/dev/null 2>&1
EC=$?
if [ $EC -ne 1 ]; then
    echo "FAILED: Expected exit code 1 for USAGE, got $EC"
    exit 1
fi
echo "   [PASS] Exit code 1 on TYL_EXIT_USAGE"

# Connection failure -> Exit code 3 (TYL_EXIT_NETWORK)
"$BACKUPC" -h 127.0.0.1 -p 19999 -l >/dev/null 2>&1
EC=$?
if [ $EC -ne 3 ]; then
    echo "FAILED: Expected exit code 3 for NETWORK, got $EC"
    exit 1
fi
echo "   [PASS] Exit code 3 on TYL_EXIT_NETWORK"

# Authentication failure (bad password) -> Exit code 4 (TYL_EXIT_AUTH)
"$BACKUPC" -h 127.0.0.1 -p "$TEST_PORT" -P "WrongSecretPass" -w test-auth < "$TMP_DIR/input.dat" >/dev/null 2>&1
EC=$?
if [ $EC -ne 4 ]; then
    echo "FAILED: Expected exit code 4 for AUTH, got $EC"
    exit 1
fi
echo "   [PASS] Exit code 4 on TYL_EXIT_AUTH"

# Resource not found -> Exit code 7 (TYL_EXIT_RESOURCE)
"$BACKUPC" -h 127.0.0.1 -p "$TEST_PORT" -w nonexistent-resource-xyz < "$TMP_DIR/input.dat" >/dev/null 2>&1
EC=$?
if [ $EC -ne 7 ]; then
    echo "FAILED: Expected exit code 7 for RESOURCE, got $EC"
    exit 1
fi
echo "   [PASS] Exit code 7 on TYL_EXIT_RESOURCE"

set -e

# 13. Test Configuration Validation (-C / --check-config) on all examples
echo "13. Testing Configuration Validation (-C) on all example configurations..."
for ex in "$REPO_DIR"/examples/*.conf; do
    "$BACKUPD" -c "$ex" -C >/dev/null 2>&1
    CHECK_RC=$?
    if [ $CHECK_RC -ne 0 ]; then
        echo "FAILED: Configuration check failed on $ex (exit code $CHECK_RC)"
        exit 1
    fi
done
echo "   [PASS] All example configuration files validated successfully with -C"

echo ""
echo "=== ALL 13 INTEGRATION TESTS PASSED SUCCESSFULLY! ==="
