/*****************************************************************************/
/*                                                                           */
/*                                 backupc.c                                 */
/*                                                                           */
/*                    Backup client for backupd-tyl                          */
/*                    (Backupd - Thirty Years Later)                         */
/*                                                                           */
/* (C) 2026 Antigravity / Gemini (Google DeepMind)                           */
/* Based on original backupd concept by Ullrich von Bassewitz (1998)         */
/* [Note: original author email uz@musoftware.de is no longer active]        */
/* Requested and Commissioned by: Andre Kajita (kajita@univap.br)            */
/*                                                                           */
/* This software is provided 'as-is', without any express or implied         */
/* warranty. In no event will the authors be held liable for any damages     */
/* arising from the use of this software.                                    */
/*****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <inttypes.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "const.h"
#include "proto.h"
#include "util.h"
#include "crypto/tyl_crypto.h"

static const char* progname             = "backupc";
static const char* servername           = "localhost";
static unsigned    serverport           = DEFAULTPORT;
static unsigned    blocksize            = TYL_DEFAULT_BLOCKSIZE;
static const char* password             = "";
static const char* cipher_opt           = "aes256,chacha20,ascon,aes128,speck,xchacha20";
static int         opt_legacy           = 0; /* Default is modern! */
static const char* opt_log_negotiation  = NULL;
static FILE*       fp_negotiation       = NULL;
static int         opt_throughput       = 0;
static int         sock                 = -1;

/* Throughput tracking structure */
typedef struct {
    uint64_t       total_bytes;
    uint64_t       last_bytes;
    struct timeval start_time;
    struct timeval last_update_time;
} throughput_tracker_t;

static void throughput_init (throughput_tracker_t* t) {
    t->total_bytes = 0;
    t->last_bytes = 0;
    gettimeofday (&t->start_time, NULL);
    t->last_update_time = t->start_time;
}

static void throughput_update (throughput_tracker_t* t, size_t bytes) {
    if (!opt_throughput) return;
    t->total_bytes += bytes;

    struct timeval now;
    gettimeofday (&now, NULL);

    double elapsed_since_last = (now.tv_sec - t->last_update_time.tv_sec) +
                                (now.tv_usec - t->last_update_time.tv_usec) / 1000000.0;
    if (elapsed_since_last >= 0.5) { /* update every 500ms */
        double total_elapsed = (now.tv_sec - t->start_time.tv_sec) +
                               (now.tv_usec - t->start_time.tv_usec) / 1000000.0;
        double instant_rate = (t->total_bytes - t->last_bytes) / elapsed_since_last / (1024.0 * 1024.0);
        double avg_rate = total_elapsed > 0 ? (t->total_bytes / total_elapsed / (1024.0 * 1024.0)) : 0;
        double mb_transferred = t->total_bytes / (1024.0 * 1024.0);

        if (isatty (STDERR_FILENO)) {
            fprintf (stderr, "\r[Throughput] Transferred: %.2f MB | Rate: %.2f MB/s (Avg: %.2f MB/s) | Elapsed: %.1fs",
                     mb_transferred, instant_rate, avg_rate, total_elapsed);
            fflush (stderr);
        }
        t->last_update_time = now;
        t->last_bytes = t->total_bytes;
    }
}

static void throughput_finish (throughput_tracker_t* t) {
    if (!opt_throughput) return;
    struct timeval now;
    gettimeofday (&now, NULL);
    double total_elapsed = (now.tv_sec - t->start_time.tv_sec) +
                           (now.tv_usec - t->start_time.tv_usec) / 1000000.0;
    double avg_rate = total_elapsed > 0 ? (t->total_bytes / total_elapsed / (1024.0 * 1024.0)) : 0;
    double mb_transferred = t->total_bytes / (1024.0 * 1024.0);

    if (isatty (STDERR_FILENO)) {
        fprintf (stderr, "\r\033[K"); /* Clear live line on TTY */
    }
    fprintf (stderr, "[Throughput] Completed: %.2f MB (%" PRIu64 " bytes) in %.2fs (Average: %.2f MB/s)\n",
             mb_transferred, t->total_bytes, total_elapsed, avg_rate);
    fflush (stderr);
}

static void log_negotiation (const char* format, ...) {
    if (!fp_negotiation) return;
    struct timeval tv;
    gettimeofday (&tv, NULL);
    struct tm tm;
    localtime_r (&tv.tv_sec, &tm);
    char timebuf[32];
    strftime (timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm);

    fprintf (fp_negotiation, "[%s.%03ld] [NEGOTIATION] ", timebuf, tv.tv_usec / 1000);
    va_list ap;
    va_start (ap, format);
    vfprintf (fp_negotiation, format, ap);
    va_end (ap);
    fprintf (fp_negotiation, "\n");
    fflush (fp_negotiation);
}

static int exit_code_from_server_error (const char* err_msg) {
    if (!err_msg) return TYL_EXIT_IO;
    if (strstr (err_msg, "Password") || strstr (err_msg, "password") ||
        strstr (err_msg, "Access denied") || strstr (err_msg, "denied") ||
        strstr (err_msg, "Authentication") || strstr (err_msg, "auth")) {
        return TYL_EXIT_AUTH;
    }
    if (strstr (err_msg, "Unknown") || strstr (err_msg, "lock") || strstr (err_msg, "Lock") ||
        strstr (err_msg, "not found") || strstr (err_msg, "No such")) {
        return TYL_EXIT_RESOURCE;
    }
    if (strstr (err_msg, "Crypto") || strstr (err_msg, "cipher") || strstr (err_msg, "handshake")) {
        return TYL_EXIT_CRYPTO;
    }
    return TYL_EXIT_IO;
}

static void error_exit (int exit_code, const char* format, ...) {
    va_list ap;
    va_start (ap, format);
    fprintf (stderr, "%s: ", progname);
    vfprintf (stderr, format, ap);
    fprintf (stderr, "\n");
    va_end (ap);
    if (sock >= 0) {
        close (sock);
        sock = -1;
    }
    if (fp_negotiation && fp_negotiation != stdout && fp_negotiation != stderr) {
        fclose (fp_negotiation);
        fp_negotiation = NULL;
    }
    exit (exit_code);
}

static void usage (void) {
    fprintf (stderr,
             "%s (%s) v%s\n"
             "Originally created by Ullrich von Bassewitz (1998) [email uz@musoftware.de inactive]\n"
             "Modernized by Antigravity / Gemini (Google DeepMind, 2026)\n"
             "Requested & Commissioned by: %s\n\n"
             "Usage: %s [options] -w|-r|-l <resource>\n"
             "Options:\n"
             "  -h, --host <name>          Connect to server host (default: localhost)\n"
             "  -p, --port <port>          Connect to port (default: %u)\n"
             "  -P, --password <pass>      Shared authentication password for resource\n"
             "  -c, --cipher <name>        Preferred cipher (aes256, aes128, chacha20, xchacha20, ascon, speck)\n"
             "  -s, --secure               High-security mode (forces aes256gcm / chacha20poly1305)\n"
             "  -b, --blocksize <n>        Block size in KB (default: 16)\n"
             "  -w, --write <res>          Write stdin to server resource\n"
             "  -r, --read <res>           Read server resource to stdout\n"
             "  -l, --list                 List available resources on server\n"
             "  -N, --log-negotiation <t>  Log handshake negotiation to stdout, stderr, or <file>\n"
             "  -T, --throughput           Display real-time and summary network throughput\n"
             "  -L, --legacy               Use legacy unencrypted 0.20 protocol (default: modern)\n"
             "  -V, --version              Print version and cryptographic information\n"
             "  -H, --help                 Print this help message\n",
             SOFTWARE_NAME,
             SOFTWARE_TITLE,
             VERSION,
             COMMISSIONER,
             progname,
             DEFAULTPORT);
    exit (TYL_EXIT_USAGE);
}

static int srvconnect (void) {
    struct addrinfo hints, *res, *p;
    char port_str[16];
    snprintf (port_str, sizeof(port_str), "%u", serverport);

    memset (&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo (servername, port_str, &hints, &res);
    if (rc != 0) {
        error_exit (TYL_EXIT_NETWORK, "Cannot resolve server \"%s\": %s", servername, gai_strerror (rc));
    }

    int s = -1;
    for (p = res; p != NULL; p = p->ai_next) {
        s = socket (p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s < 0) continue;
        if (connect (s, p->ai_addr, p->ai_addrlen) == 0) {
            break; /* Connected */
        }
        close (s);
        s = -1;
    }
    freeaddrinfo (res);

    if (s < 0) {
        error_exit (TYL_EXIT_NETWORK, "Cannot connect to server %s:%u: %s", servername, serverport, strerror (errno));
    }
    return s;
}

/* Modern TYL/1.0 Client Negotiation */
static int modern_handshake (tyl_session_t* session, const char* cmd, const char* res) {
    log_negotiation ("Initiating connection to %s:%u (cmd=%s, res='%s')",
                     servername, serverport, cmd, res ? res : "");

    sock = srvconnect ();
    log_negotiation ("Connected to TCP socket %d", sock);

    /* 1. Send HELLO with password and supported ciphers */
    char hello[512];
    snprintf (hello, sizeof(hello),
              "%s cmd=%s res=%s pass=\"%s\" ciphers=\"%s\"\n",
              TYL_CMD_HELLO, cmd, res ? res : "", password ? password : "", cipher_opt);
    log_negotiation ("Sending HELLO: pre-crypto pass=%s, proposed ciphers='%s'",
                     (password && *password) ? "[PROTECTED]" : "none", cipher_opt);
    if (write_all (sock, hello, strlen (hello)) != 0) {
        error_exit (TYL_EXIT_NETWORK, "Failed to send handshake to server");
    }

    /* 2. Read server response (KEY or ERROR) */
    char resp[512];
    if (read_line_timeout (sock, resp, sizeof(resp), 15) <= 0) {
        error_exit (TYL_EXIT_NETWORK, "Server closed connection or timed out during handshake");
    }

    if (strncmp (resp, "ERROR:", 6) == 0) {
        log_negotiation ("Server returned ERROR: %s", resp + 6);
        error_exit (exit_code_from_server_error (resp + 6), "Server error: %s", resp + 6);
    }
    if (strncmp (resp, TYL_RESP_KEY, strlen (TYL_RESP_KEY)) != 0) {
        error_exit (TYL_EXIT_CRYPTO, "Unexpected server greeting: %s", resp);
    }

    /* Parse server key and cipher */
    char srv_pub_hex[128] = "";
    char chosen_cipher_str[64] = "";
    const char* p = strstr (resp, "pubkey=");
    if (p) {
        sscanf (p + 7, "%127s", srv_pub_hex);
        char* sp = strchr (srv_pub_hex, ' ');
        if (sp) *sp = '\0';
    }
    p = strstr (resp, "cipher=");
    if (p) {
        sscanf (p + 7, "%63s", chosen_cipher_str);
    }

    log_negotiation ("Received server ephemeral public key (X25519): %s", srv_pub_hex);
    log_negotiation ("Negotiated cipher suite: %s", chosen_cipher_str);

    uint8_t srv_pub[32];
    size_t srv_pub_len = 0;
    if (tyl_crypto_hex2bin (srv_pub_hex, srv_pub, 32, &srv_pub_len) != 0 || srv_pub_len != 32) {
        error_exit (TYL_EXIT_CRYPTO, "Invalid server public key");
    }

    int cipher_id = tyl_crypto_cipher_from_name (chosen_cipher_str);
    if (cipher_id == TYL_CIPHER_UNKNOWN) {
        cipher_id = TYL_CIPHER_ASCON128A;
    }

    /* 3. Initialize client session and generate ephemeral keypair */
    if (tyl_crypto_session_init (session, TYL_ROLE_CLIENT) != 0) {
        error_exit (TYL_EXIT_CRYPTO, "Crypto initialization failed");
    }
    char client_pub_hex[65];
    tyl_crypto_bin2hex (session->pub_key, 32, client_pub_hex);
    log_negotiation ("Generated client ephemeral public key (X25519): %s", client_pub_hex);

    if (tyl_crypto_derive_keys (session, srv_pub, cipher_id) != 0) {
        error_exit (TYL_EXIT_CRYPTO, "Key derivation failed");
    }
    log_negotiation ("Derived TX/RX session keys using HKDF-SHA256 from X25519 shared secret");

    /* 4. Send client public key */
    char key_msg[128];
    snprintf (key_msg, sizeof(key_msg), "%s pubkey=%s\n", TYL_RESP_KEY, client_pub_hex);
    if (write_all (sock, key_msg, strlen (key_msg)) != 0) {
        error_exit (TYL_EXIT_NETWORK, "Failed to send public key to server");
    }

    /* 5. Send encrypted verification token */
    log_negotiation ("Sending encrypted handshake verification token: %s", TYL_FIN_TOKEN);
    if (tyl_crypto_send_frame (session, sock, TYL_FIN_TOKEN, strlen (TYL_FIN_TOKEN)) != 0) {
        error_exit (TYL_EXIT_CRYPTO, "Failed to send handshake verification");
    }

    /* 6. Receive encrypted server confirmation */
    uint8_t ok_buf[128];
    size_t ok_len = 0;
    if (tyl_crypto_recv_frame (session, sock, ok_buf, sizeof(ok_buf) - 1, &ok_len) != 0) {
        error_exit (TYL_EXIT_CRYPTO, "Failed to receive server verification");
    }
    ok_buf[ok_len] = '\0';
    log_negotiation ("Received server encrypted confirmation: %s", (char*)ok_buf);
    if (strcmp ((char*)ok_buf, TYL_OK_TOKEN) != 0) {
        error_exit (TYL_EXIT_CRYPTO, "Server verification failed");
    }

    /* 7. Receive initial command status */
    if (tyl_crypto_recv_frame (session, sock, ok_buf, sizeof(ok_buf) - 1, &ok_len) != 0) {
        error_exit (TYL_EXIT_NETWORK, "Failed to receive command acknowledgement");
    }
    ok_buf[ok_len] = '\0';
    if (strncmp ((char*)ok_buf, "ERROR:", 6) == 0) {
        error_exit (exit_code_from_server_error ((char*)ok_buf + 6), "Server error: %s", (char*)ok_buf + 6);
    }
    if (strcmp ((char*)ok_buf, "OK") != 0) {
        error_exit (TYL_EXIT_IO, "Unexpected server response: %s", (char*)ok_buf);
    }

    log_negotiation ("TLS-style negotiation complete! Encrypted AEAD channel established.");
    return 0;
}

static void modern_write (const char* res) {
    tyl_session_t session;
    modern_handshake (&session, CMD_WRITE, res);

    uint8_t* buf = (uint8_t*)malloc (blocksize);
    if (!buf) error_exit (TYL_EXIT_IO, "Out of memory");

    throughput_tracker_t tracker;
    throughput_init (&tracker);

    while (1) {
        size_t n = fread (buf, 1, blocksize, stdin);
        if (n == 0) break;
        if (tyl_crypto_send_frame (&session, sock, buf, n) != 0) {
            free (buf);
            error_exit (TYL_EXIT_IO, "Error sending encrypted data frame");
        }
        throughput_update (&tracker, n);
    }
    free (buf);

    /* Send end of stream */
    tyl_crypto_send_frame (&session, sock, "", 0);
    throughput_finish (&tracker);

    /* Read final status */
    uint8_t status_buf[256];
    size_t status_len = 0;
    if (tyl_crypto_recv_frame (&session, sock, status_buf, sizeof(status_buf) - 1, &status_len) != 0) {
        error_exit (TYL_EXIT_NETWORK, "Failed to receive final status from server");
    }
    status_buf[status_len] = '\0';
    if (strncmp ((char*)status_buf, "ERROR:", 6) == 0) {
        error_exit (exit_code_from_server_error ((char*)status_buf + 6), "Server error: %s", (char*)status_buf + 6);
    }
    if (strcmp ((char*)status_buf, "OK") != 0) {
        error_exit (TYL_EXIT_IO, "Server reported: %s", (char*)status_buf);
    }

    close (sock);
    sock = -1;
}

static void modern_read (const char* res) {
    tyl_session_t session;
    modern_handshake (&session, CMD_READ, res);

    uint8_t* buf = (uint8_t*)malloc (blocksize + 512);
    if (!buf) error_exit (TYL_EXIT_IO, "Out of memory");

    throughput_tracker_t tracker;
    throughput_init (&tracker);

    while (1) {
        size_t n = 0;
        if (tyl_crypto_recv_frame (&session, sock, buf, blocksize + 512, &n) != 0) {
            free (buf);
            error_exit (TYL_EXIT_CRYPTO, "Failed to decrypt incoming data frame");
        }
        if (n == 0) break; /* EOF */
        if (fwrite (buf, 1, n, stdout) != n) {
            free (buf);
            error_exit (TYL_EXIT_IO, "Error writing data to stdout");
        }
        throughput_update (&tracker, n);
    }
    free (buf);
    fflush (stdout);
    throughput_finish (&tracker);

    /* Read final status */
    uint8_t status_buf[256];
    size_t status_len = 0;
    if (tyl_crypto_recv_frame (&session, sock, status_buf, sizeof(status_buf) - 1, &status_len) != 0) {
        error_exit (TYL_EXIT_NETWORK, "Failed to receive final status from server");
    }
    status_buf[status_len] = '\0';
    if (strncmp ((char*)status_buf, "ERROR:", 6) == 0) {
        error_exit (exit_code_from_server_error ((char*)status_buf + 6), "Server error: %s", (char*)status_buf + 6);
    }
    if (strcmp ((char*)status_buf, "OK") != 0) {
        error_exit (TYL_EXIT_IO, "Server reported: %s", (char*)status_buf);
    }

    close (sock);
    sock = -1;
}

static void modern_list (void) {
    tyl_session_t session;
    modern_handshake (&session, CMD_LIST, "");

    uint8_t buf[4096];
    size_t n = 0;
    if (tyl_crypto_recv_frame (&session, sock, buf, sizeof(buf) - 1, &n) != 0) {
        error_exit (TYL_EXIT_CRYPTO, "Failed to receive resource list from server");
    }
    buf[n] = '\0';

    /* Parse and print resource list lines */
    char* line = strtok ((char*)buf, "\r\n");
    while (line) {
        if (line[0] == '-') {
            printf ("%s\n", line + 1);
        } else if (line[0] != '\0') {
            printf ("%s\n", line);
        }
        line = strtok (NULL, "\r\n");
    }

    /* Read final status */
    uint8_t status_buf[256];
    size_t status_len = 0;
    if (tyl_crypto_recv_frame (&session, sock, status_buf, sizeof(status_buf) - 1, &status_len) != 0) {
        error_exit (TYL_EXIT_NETWORK, "Failed to receive final status from server");
    }
    status_buf[status_len] = '\0';
    if (strcmp ((char*)status_buf, "OK") != 0 && strncmp ((char*)status_buf, "ERROR:", 6) == 0) {
        error_exit (exit_code_from_server_error ((char*)status_buf + 6), "Server error: %s", (char*)status_buf + 6);
    }

    close (sock);
    sock = -1;
}

/* Legacy 0.20 Protocol Client Implementation */
static void legacy_write (const char* res) {
    log_negotiation ("Connecting to server %s:%u in LEGACY 0.20 unencrypted mode", servername, serverport);
    sock = srvconnect ();
    char cmd[256];
    snprintf (cmd, sizeof(cmd), "%s %s\n", CMD_WRITE, res);
    log_negotiation ("Sending legacy plaintext command: %s %s", CMD_WRITE, res);
    if (write_all (sock, cmd, strlen (cmd)) != 0) {
        error_exit (TYL_EXIT_NETWORK, "Failed to send command to server");
    }

    char resp[256];
    if (read_line_timeout (sock, resp, sizeof(resp), 15) <= 0) {
        error_exit (TYL_EXIT_NETWORK, "Server closed connection");
    }
    if (strncmp (resp, "ERROR:", 6) == 0) {
        error_exit (exit_code_from_server_error (resp + 6), "Server error: %s", resp + 6);
    }
    if (strncmp (resp, "OK", 2) != 0) {
        error_exit (TYL_EXIT_IO, "Unexpected server answer: %s", resp);
    }
    log_negotiation ("Legacy server acknowledged OK. Streaming data...");

    throughput_tracker_t tracker;
    throughput_init (&tracker);

    uint8_t buf[256];
    while (1) {
        size_t n = fread (buf, 1, 255, stdin);
        if (n == 0) break;
        uint8_t cnt = (uint8_t)n;
        if (write (sock, &cnt, 1) != 1 || write_all (sock, buf, n) != 0) {
            error_exit (TYL_EXIT_IO, "Error sending data");
        }
        throughput_update (&tracker, n);
    }
    uint8_t zero = 0;
    if (write (sock, &zero, 1) != 1) error_exit (TYL_EXIT_IO, "Error sending EOF");
    throughput_finish (&tracker);

    if (read_line_timeout (sock, resp, sizeof(resp), 30) <= 0) {
        error_exit (TYL_EXIT_NETWORK, "Server closed connection");
    }
    if (strncmp (resp, "ERROR:", 6) == 0) {
        error_exit (exit_code_from_server_error (resp + 6), "Server error: %s", resp + 6);
    }

    write_all (sock, "BYE\n", 4);
    close (sock);
    sock = -1;
}

static void legacy_read (const char* res) {
    log_negotiation ("Connecting to server %s:%u in LEGACY 0.20 unencrypted mode", servername, serverport);
    sock = srvconnect ();
    char cmd[256];
    snprintf (cmd, sizeof(cmd), "%s %s\n", CMD_READ, res);
    log_negotiation ("Sending legacy plaintext command: %s %s", CMD_READ, res);
    if (write_all (sock, cmd, strlen (cmd)) != 0) {
        error_exit (TYL_EXIT_NETWORK, "Failed to send command to server");
    }

    char resp[256];
    if (read_line_timeout (sock, resp, sizeof(resp), 15) <= 0) {
        error_exit (TYL_EXIT_NETWORK, "Server closed connection");
    }
    if (strncmp (resp, "ERROR:", 6) == 0) {
        error_exit (exit_code_from_server_error (resp + 6), "Server error: %s", resp + 6);
    }
    if (strncmp (resp, "OK", 2) != 0) {
        error_exit (TYL_EXIT_IO, "Unexpected server answer: %s", resp);
    }
    log_negotiation ("Legacy server acknowledged OK. Receiving data...");

    throughput_tracker_t tracker;
    throughput_init (&tracker);

    uint8_t buf[256];
    while (1) {
        uint8_t cnt;
        if (read (sock, &cnt, 1) != 1) error_exit (TYL_EXIT_NETWORK, "Connection lost");
        if (cnt == 0) break;
        if (read_all (sock, buf, cnt) != 0) error_exit (TYL_EXIT_IO, "Error reading data");
        if (fwrite (buf, 1, cnt, stdout) != cnt) error_exit (TYL_EXIT_IO, "Error writing stdout");
        throughput_update (&tracker, cnt);
    }
    fflush (stdout);
    throughput_finish (&tracker);

    if (read_line_timeout (sock, resp, sizeof(resp), 30) <= 0) {
        error_exit (TYL_EXIT_NETWORK, "Server closed connection");
    }
    if (strncmp (resp, "ERROR:", 6) == 0) {
        error_exit (exit_code_from_server_error (resp + 6), "Server error: %s", resp + 6);
    }

    write_all (sock, "BYE\n", 4);
    close (sock);
    sock = -1;
}

static void legacy_list (void) {
    log_negotiation ("Connecting to server %s:%u in LEGACY 0.20 unencrypted mode for LIST", servername, serverport);
    sock = srvconnect ();
    if (write_all (sock, "LIST\n", 5) != 0) {
        error_exit (TYL_EXIT_NETWORK, "Failed to send command to server");
    }

    char line[512];
    while (read_line_timeout (sock, line, sizeof(line), 15) > 0) {
        if (strcmp (line, "OK") == 0) break;
        if (strncmp (line, "ERROR:", 6) == 0) {
            error_exit (exit_code_from_server_error (line + 6), "Server error: %s", line + 6);
        }
        if (line[0] == '-') {
            printf ("%s\n", line + 1);
        } else {
            printf ("%s\n", line);
        }
    }

    write_all (sock, "BYE\n", 4);
    close (sock);
    sock = -1;
}

int main (int argc, char* argv[]) {
    signal (SIGPIPE, SIG_IGN);
    progname = argv[0];

    static struct option long_options[] = {
        {"host",            required_argument, 0, 'h'},
        {"port",            required_argument, 0, 'p'},
        {"password",        required_argument, 0, 'P'},
        {"cipher",          required_argument, 0, 'c'},
        {"secure",          no_argument,       0, 's'},
        {"blocksize",       required_argument, 0, 'b'},
        {"write",           required_argument, 0, 'w'},
        {"read",            required_argument, 0, 'r'},
        {"list",            no_argument,       0, 'l'},
        {"legacy",          no_argument,       0, 'L'},
        {"log-negotiation", required_argument, 0, 'N'},
        {"throughput",      no_argument,       0, 'T'},
        {"version",         no_argument,       0, 'V'},
        {"help",            no_argument,       0, 'H'},
        {0, 0, 0, 0}
    };

    int opt;
    char* target_write = NULL;
    char* target_read  = NULL;
    int   action_list  = 0;

    while ((opt = getopt_long (argc, argv, "h:p:P:c:sb:w:r:lLN:TVH", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h': servername = optarg; break;
            case 'p': serverport = (unsigned)atoi (optarg); break;
            case 'P': password = optarg; break;
            case 'c': cipher_opt = optarg; break;
            case 's': cipher_opt = "aes256"; break;
            case 'b': blocksize = (unsigned)atoi (optarg) * 1024; break;
            case 'w': target_write = optarg; break;
            case 'r': target_read = optarg; break;
            case 'l': action_list = 1; break;
            case 'L': opt_legacy = 1; break;
            case 'N': opt_log_negotiation = optarg; break;
            case 'T': opt_throughput = 1; break;
            case 'V':
                printf ("%s (%s) v%s\n"
                        "Original author: Ullrich von Bassewitz (1998) [email uz@musoftware.de no longer active]\n"
                        "Modernized by: Antigravity / Gemini (Google DeepMind, 2026)\n"
                        "Requested & Commissioned by: %s\n"
                        "Engine: %s\n"
                        "Key exchange: X25519 (Curve25519 ECDH)\n"
                        "Ciphers: AES-256-GCM (NIST/TLS 1.3), AES-128-GCM, ChaCha20-Poly1305 (RFC 8439),\n"
                        "         XChaCha20-Poly1305 (extended nonce), ASCON-128a (NIST LWC), Speck-128/128-Poly1305\n",
                        SOFTWARE_NAME, SOFTWARE_TITLE, VERSION, COMMISSIONER,
                        tyl_crypto_engine_desc ());
                return TYL_EXIT_SUCCESS;
            case 'H':
            default:
                usage ();
                break;
        }
    }

    if (!target_write && !target_read && !action_list) {
        usage ();
    }

    /* Set up negotiation logging if requested */
    if (opt_log_negotiation) {
        if (strcasecmp (opt_log_negotiation, "stdout") == 0 || strcmp (opt_log_negotiation, "-") == 0) {
            fp_negotiation = stdout;
        } else if (strcasecmp (opt_log_negotiation, "stderr") == 0) {
            fp_negotiation = stderr;
        } else {
            fp_negotiation = fopen (opt_log_negotiation, "a");
            if (!fp_negotiation) {
                error_exit (TYL_EXIT_IO, "Cannot open negotiation log file \"%s\": %s",
                            opt_log_negotiation, strerror (errno));
            }
        }
    }

    if (opt_legacy) {
        if (target_write) legacy_write (target_write);
        if (target_read)  legacy_read (target_read);
        if (action_list)  legacy_list ();
    } else {
        if (target_write) modern_write (target_write);
        if (target_read)  modern_read (target_read);
        if (action_list)  modern_list ();
    }

    if (fp_negotiation && fp_negotiation != stdout && fp_negotiation != stderr) {
        fclose (fp_negotiation);
        fp_negotiation = NULL;
    }

    return TYL_EXIT_SUCCESS;
}
