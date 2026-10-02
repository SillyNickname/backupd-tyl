/*****************************************************************************/
/*                                                                           */
/*                                 backupd.c                                 */
/*                                                                           */
/*                    Backup daemon for backupd-tyl                          */
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
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <setjmp.h>
#include <paths.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#include "const.h"
#include "proto.h"
#include "global.h"
#include "config.h"
#include "error.h"
#include "util.h"
#include "client.h"
#include "extcmd.h"
#include "crypto/tyl_crypto.h"

#ifdef _PATH_STDPATH
#  define PATH _PATH_STDPATH
#else
#  define PATH "/usr/bin:/bin:/usr/sbin:/sbin"
#endif

static char lockfile [PATH_MAX] = "";
static unsigned long wbytes = 0;
static unsigned long rbytes = 0;
static int master_socket = -1;
static char active_pidfile [PATH_MAX] = "";
static volatile sig_atomic_t got_sighup = 0;

/*
 * rmlock: Removes any active lockfile previously acquired by makelock().
 * Called during clean exit, signal termination, and command completion.
 */
static void rmlock (void) {
    if (lockfile[0] != '\0') {
        if (remove (lockfile) < 0 && errno != ENOENT) {
            tyl_log_warn ("Cannot remove lock file \"%s\": %m", lockfile);
        }
        lockfile[0] = '\0';
    }
}

static void remove_pidfile (void) {
    if (active_pidfile[0] != '\0') {
        unlink (active_pidfile);
        active_pidfile[0] = '\0';
    }
}

static void doexit (void) {
    rmlock ();
    remove_pidfile ();
    if (master_socket >= 0) {
        close (master_socket);
        master_socket = -1;
    }
    tyl_log_close ();
}

/*
 * setup_security:
 * Initializes baseline process environment hardening:
 * 1. Sets a strict umask (0077) to ensure any files created by the daemon
 *    are inaccessible to other local users by default.
 * 2. Overwrites PATH with a sanitized, immutable system search path
 *    to prevent PATH hijacking vulnerabilities during external command execution.
 */
static void setup_security (void) {
    char envbuf [256];
    umask (0077);
    if (snprintf (envbuf, sizeof (envbuf), "PATH=%s", PATH) < 0) {
        errexit_code (TYL_EXIT_PERMISSION, "Cannot set PATH");
    }
    if (putenv (strdup (envbuf)) != 0) {
        errexit_code (TYL_EXIT_PERMISSION, "Cannot set PATH");
    }
}

/*
 * changeuser:
 * Implements strict, irreversible privilege separation for resource execution:
 *
 * 1. Looks up the requested target user and group from the resource configuration.
 * 2. If the daemon is running as root (euid == 0):
 *    - Resolves target UID and GID.
 *    - Calls initgroups() to properly configure supplementary groups for the user.
 *    - Permanently switches group identity (setgid).
 *    - Permanently drops root user privileges (setuid).
 *    - Defense-in-depth: attempts to regain root via setuid(0) / seteuid(0);
 *      if successful, terminates immediately to prevent running with dropped credentials failed.
 * 3. If running unprivileged (e.g. non-root container or test suite), verifies that the
 *    current effective UID matches the requested target user.
 */
static void changeuser (const char* section) {
    const CfgSection* s = CfgGetSection (section);
    if (!s) return;

    /*
     * If no user / group is specified in the configuration, the resource
     * command defaults to running as root (when the daemon is started as root).
     */
    const char* req_group = (s->group && s->group[0] != '\0') ? s->group : NULL;
    const char* req_user  = (s->user  && s->user[0]  != '\0') ? s->user  : NULL;

    /* When running with root privileges, drop to requested user/group or remain root */
    if (geteuid () == 0) {
        gid_t target_gid = 0;
        int has_target_gid = 0;

        if (req_group) {
            struct group* g = getgrnam (req_group);
            if (!g) {
                errexit_code (TYL_EXIT_PERMISSION, "Group \"%s\" is unknown", req_group);
            }
            target_gid = g->gr_gid;
            has_target_gid = 1;
        } else if (req_user) {
            /* If group not specified, switch to user's primary group */
            struct passwd* p = getpwnam (req_user);
            if (p) {
                target_gid = p->pw_gid;
                has_target_gid = 1;
            }
        }

        if (req_user) {
            struct passwd* p = getpwnam (req_user);
            if (!p) {
                errexit_code (TYL_EXIT_PERMISSION, "User \"%s\" is unknown", req_user);
            }
            if (!has_target_gid) {
                target_gid = p->pw_gid;
                has_target_gid = 1;
            }

            /* Initialize supplementary groups for requested user with target GID */
            if (initgroups (p->pw_name, target_gid) != 0) {
                errexit_code (TYL_EXIT_PERMISSION, "Cannot initialize supplementary groups for \"%s\": %m", req_user);
            }

            /* Set GID first */
            if (setgid (target_gid) < 0) {
                errexit_code (TYL_EXIT_PERMISSION, "Cannot change group to gid %u: %m", (unsigned)target_gid);
            }

            /* Permanently drop UID to requested user */
            if (setuid (p->pw_uid) < 0) {
                errexit_code (TYL_EXIT_PERMISSION, "Cannot change user to \"%s\": %m", req_user);
            }

            /* Defense-in-depth: Verify that root privileges cannot be regained */
            if (setuid (0) == 0 || seteuid (0) == 0) {
                errexit_code (TYL_EXIT_PERMISSION, "Security failure: could not permanently drop root privileges");
            }
        } else if (has_target_gid) {
            /* Group specified without specific user: drop supplementary groups and set GID */
            if (setgroups (1, &target_gid) < 0) {
                tyl_log_warn ("Cannot reset supplementary groups: %m");
            }
            if (setgid (target_gid) < 0) {
                errexit_code (TYL_EXIT_PERMISSION, "Cannot change group to gid %u: %m", (unsigned)target_gid);
            }
        } else {
            /* If no user specified, ensure process runs as root (uid 0) */
            if (setuid (0) < 0) {
                /* Already root */
            }
        }
    } else {
        /* Running unprivileged (e.g. unit/integration test suite or unprivileged container) */
        if (req_user) {
            struct passwd* p = getpwnam (req_user);
            if (p && p->pw_uid != geteuid ()) {
                errexit_code (TYL_EXIT_PERMISSION, "Cannot switch to user \"%s\" without root privileges", req_user);
            }
        }
    }
}

/*
 * makelock: Creates a mutual-exclusion lockfile for the specified resource.
 * Uses atomic open(O_CREAT | O_EXCL) to prevent race conditions when multiple
 * clients attempt to access the same resource simultaneously.
 */
static int makelock (const char* res) {
    const CfgSection* s = CfgGetSection (res);
    if (!s || !s->lockfile || s->lockfile[0] == '\0') {
        return SUCCESS;
    }

    if (expand_meta (lockfile, s->lockfile, sizeof (lockfile), clientname) == FAILURE) {
        tyl_log_err ("Could not expand lock file name");
        return FAILURE;
    }

    int fd = open (lockfile, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd == -1) {
        lockfile[0] = '\0';
        return FAILURE;
    }
    close (fd);
    return SUCCESS;
}

static int get_expanded_cmd (const char* res, const char* op, char* buf, unsigned size) {
    const CfgSection* s = CfgGetSection (res);
    if (!s) return FAILURE;

    const char* raw_cmd = NULL;
    if (strcasecmp (op, CMD_WRITE) == 0) raw_cmd = s->write_cmd;
    else if (strcasecmp (op, CMD_READ) == 0) raw_cmd = s->read_cmd;

    if (!raw_cmd || raw_cmd[0] == '\0') {
        tyl_log_err ("No %s entry for resource \"%s\"", op, res);
        return FAILURE;
    }

    if (expand_meta (buf, raw_cmd, size, clientname) != SUCCESS) {
        tyl_log_err ("Expanding external command failed");
        return FAILURE;
    }
    tyl_log_info ("Resource \"%s\" command: %s", res, buf);
    return SUCCESS;
}

/* Parse parameter key=value from protocol string */
static const char* parse_param (const char* line, const char* key, char* val_buf, size_t val_buf_size) {
    val_buf[0] = '\0';
    char search_key[64];
    snprintf (search_key, sizeof(search_key), "%s=", key);

    const char* p = line;
    const char* found = NULL;
    while ((found = strstr (p, search_key)) != NULL) {
        if (found == line || isspace ((unsigned char)*(found - 1))) {
            break; /* exact parameter boundary match */
        }
        p = found + strlen (search_key);
    }
    if (!found) return NULL;
    p = found + strlen (search_key);

    size_t i = 0;
    if (*p == '"') {
        p++;
        while (*p && *p != '"' && i < val_buf_size - 1) {
            val_buf[i++] = *p++;
        }
        if (*p == '"') p++;
    } else {
        while (*p && !isspace ((unsigned char)*p) && i < val_buf_size - 1) {
            val_buf[i++] = *p++;
        }
    }
    val_buf[i] = '\0';
    return val_buf;
}

/*
 * handle_modern_connection:
 * Manages modern TYL/1.0 encrypted sessions through a 4-phase security pipeline:
 *
 * Phase 1: Pre-Crypto Authentication & Access Control
 *   - Parses initial client request line containing requested command, resource,
 *     proposed ciphers, and pre-auth password token.
 *   - Evaluates client credentials against resource-specific or global passwords
 *     using constant-time verification.
 *   - Enforces IP/hostname Allow/Deny ACLs before allocating crypto state.
 *
 * Phase 2: Ephemeral Diffie-Hellman Key Exchange (X25519)
 *   - Generates ephemeral Curve25519 keypair for the worker process.
 *   - Sends server public key and selected AEAD cipher suite to client.
 *   - Receives client ephemeral public key.
 *   - Computes 32-byte shared secret via X25519 scalar multiplication.
 *   - Feeds shared secret into HKDF-SHA256 to derive forward-secure unidirectional
 *     session keys (client->server and server->client) and IV/nonces.
 *
 * Phase 3: Cryptographic Handshake Verification
 *   - Awaits encrypted AEAD frame containing TYL_FIN_TOKEN ("FINISHED").
 *   - Decrypts and authenticates frame using derived session key.
 *   - Acknowledges readiness with encrypted TYL_OK_TOKEN ("OK").
 *
 * Phase 4: Authenticated Streaming & External Command Supervision
 *   - Transitions process to dropped privileges (changeuser) and sets custom umask.
 *   - Acquires resource lock (makelock).
 *   - Forks external shell command with isolated descriptors (startcmd).
 *   - Bidirectionally relays data through AEAD frames (each packet length-prefixed,
 *     encrypted, and authenticated with a 16-byte Poly1305 or GCM tag).
 *   - Awaits command completion (endcmd), releases lock (rmlock), and sends status.
 */
static void handle_modern_connection (int sock_fd, const char* hello_line) {
    char cmd[64] = "";
    char res[256] = "";
    char pass[256] = "";
    char ciphers[256] = "";

    parse_param (hello_line, "cmd", cmd, sizeof(cmd));
    parse_param (hello_line, "res", res, sizeof(res));
    parse_param (hello_line, "pass", pass, sizeof(pass));
    parse_param (hello_line, "ciphers", ciphers, sizeof(ciphers));

    tyl_log_notice ("TYL/1.0 Handshake from %s: cmd=%s res=%s", clientname, cmd, res);

    /* 1. Pre-Crypto Authentication & Authorization */
    if (client_check_auth (res[0] ? res : NULL, pass) != 0) {
        tyl_log_warn ("Authentication failed for client %s on resource \"%s\"", clientname, res);
        dprintf (sock_fd, "ERROR: Authentication failed\n");
        exit (TYL_EXIT_AUTH);
    }

    if (cmd[0] != '\0' && (strcasecmp (cmd, CMD_WRITE) == 0 || strcasecmp (cmd, CMD_READ) == 0)) {
        if (!CfgHaveSection (res)) {
            tyl_log_warn ("Client %s requested unknown resource \"%s\"", clientname, res);
            dprintf (sock_fd, "ERROR: Unknown resource: %s\n", res);
            exit (TYL_EXIT_RESOURCE);
        }
        if (clientaccess (res) == NO) {
            tyl_log_warn ("Access denied for client %s to resource \"%s\"", clientname, res);
            dprintf (sock_fd, "ERROR: Access denied\n");
            exit (TYL_EXIT_AUTH);
        }
    } else if (strcasecmp (cmd, CMD_LIST) == 0) {
        if (clientaccess (NULL) == NO) {
            tyl_log_warn ("LIST access denied for client %s", clientname);
            dprintf (sock_fd, "ERROR: Access denied\n");
            exit (TYL_EXIT_AUTH);
        }
    }

    /* 2. Cryptographic Handshake */
    tyl_session_t session;
    if (tyl_crypto_session_init (&session, TYL_ROLE_SERVER) != 0) {
        dprintf (sock_fd, "ERROR: Crypto initialization failed\n");
        exit (TYL_EXIT_CRYPTO);
    }

    /* Select cipher suite based on server configuration and client proposal */
    int chosen_cipher = TYL_CIPHER_AES256GCM;
    const CfgGlobal* g = CfgGetGlobal ();
    if (g && g->default_cipher) {
        int dc = tyl_crypto_cipher_from_name (g->default_cipher);
        if (dc != TYL_CIPHER_UNKNOWN) chosen_cipher = dc;
    } else {
        if (strstr (ciphers, "aes256") || strstr (ciphers, "aes-gcm") || strstr (ciphers, "secure")) {
            chosen_cipher = TYL_CIPHER_AES256GCM;
        } else if (strstr (ciphers, "chacha20") || strstr (ciphers, "chacha")) {
            chosen_cipher = TYL_CIPHER_CHACHA20;
        } else if (strstr (ciphers, "xchacha")) {
            chosen_cipher = TYL_CIPHER_XCHACHA20;
        } else if (strstr (ciphers, "aes128")) {
            chosen_cipher = TYL_CIPHER_AES128GCM;
        } else if (strstr (ciphers, "ascon")) {
            chosen_cipher = TYL_CIPHER_ASCON128A;
        } else if (strstr (ciphers, "speck")) {
            chosen_cipher = TYL_CIPHER_SPECK128;
        }
    }

    char server_pub_hex[65];
    tyl_crypto_bin2hex (session.pub_key, 32, server_pub_hex);
    tyl_log_debug ("Worker generated ephemeral Curve25519 public key: %s", server_pub_hex);

    /* Send server key */
    dprintf (sock_fd, "%s pubkey=%s cipher=%s\n", TYL_RESP_KEY, server_pub_hex, tyl_crypto_cipher_name (chosen_cipher));

    /* Read client key */
    char client_resp[512];
    if (read_line_timeout (sock_fd, client_resp, sizeof(client_resp), 15) <= 0) {
        tyl_log_warn ("Timeout waiting for client key from %s", clientname);
        exit (TYL_EXIT_NETWORK);
    }

    char client_pub_hex[128] = "";
    parse_param (client_resp, "pubkey", client_pub_hex, sizeof(client_pub_hex));
    uint8_t client_pub[32];
    size_t pub_len = 0;
    if (tyl_crypto_hex2bin (client_pub_hex, client_pub, 32, &pub_len) != 0 || pub_len != 32) {
        tyl_log_warn ("Invalid client public key from %s", clientname);
        exit (TYL_EXIT_CRYPTO);
    }

    if (tyl_crypto_derive_keys (&session, client_pub, chosen_cipher) != 0) {
        tyl_log_warn ("Key derivation failed for client %s", clientname);
        exit (TYL_EXIT_CRYPTO);
    }
    tyl_log_debug ("Computed X25519 shared secret and derived session keys for %s", clientname);

    /* 3. Handshake Verification */
    uint8_t fin_buf[128];
    size_t fin_len = 0;
    if (tyl_crypto_recv_frame (&session, sock_fd, fin_buf, sizeof(fin_buf) - 1, &fin_len) != 0) {
        tyl_log_warn ("Handshake frame decryption failed for client %s", clientname);
        exit (TYL_EXIT_CRYPTO);
    }
    fin_buf[fin_len] = '\0';
    if (strcmp ((char*)fin_buf, TYL_FIN_TOKEN) != 0) {
        tyl_log_warn ("Handshake verification token mismatch for client %s", clientname);
        exit (TYL_EXIT_CRYPTO);
    }

    /* Confirm ready */
    if (tyl_crypto_send_frame (&session, sock_fd, TYL_OK_TOKEN, strlen (TYL_OK_TOKEN)) != 0) {
        exit (TYL_EXIT_NETWORK);
    }

    tyl_log_info ("Secure session established using %s with %s", tyl_crypto_cipher_name (chosen_cipher), clientname);

    /* 4. Command Handling */
    if (strcasecmp (cmd, CMD_WRITE) == 0) {
        char cmdline[4096];
        if (get_expanded_cmd (res, CMD_WRITE, cmdline, sizeof (cmdline)) != SUCCESS) {
            tyl_crypto_send_frame (&session, sock_fd, "ERROR: Internal config error", 28);
            exit (TYL_EXIT_CONFIG);
        }

        changeuser (res);
        const CfgSection* s = CfgGetSection (res);
        if (s && s->has_umask) umask ((mode_t)s->umask_val);

        if (makelock (res) == FAILURE) {
            tyl_crypto_send_frame (&session, sock_fd, "ERROR: Resource is locked", 25);
            exit (TYL_EXIT_RESOURCE);
        }

        startcmd (cmdline, "w");
        tyl_crypto_send_frame (&session, sock_fd, "OK", 2);

        /* Streaming encrypted frames to command stdin */
        uint8_t frame_payload[TYL_DEFAULT_BLOCKSIZE + 512];
        while (1) {
            size_t chunk_len = 0;
            if (tyl_crypto_recv_frame (&session, sock_fd, frame_payload, sizeof(frame_payload), &chunk_len) != 0) {
                tyl_log_warn ("Data frame decryption failed or connection lost from %s", clientname);
                break;
            }
            if (chunk_len == 0) {
                /* End of stream */
                break;
            }
            if (fwrite (frame_payload, 1, chunk_len, clientio) != chunk_len) {
                tyl_log_warn ("Error writing to external command pipe for %s", clientname);
                break;
            }
            wbytes += chunk_len;
        }

        int rc = endcmd ();
        rmlock ();

        if (rc == 0) {
            tyl_crypto_send_frame (&session, sock_fd, "OK", 2);
            tyl_log_info ("WRITE completed successfully for %s (%lu bytes transferred)", clientname, wbytes);
            exit (TYL_EXIT_SUCCESS);
        } else {
            char errbuf[128];
            snprintf (errbuf, sizeof(errbuf), "ERROR: External command exited with code %d", rc);
            tyl_crypto_send_frame (&session, sock_fd, errbuf, strlen(errbuf));
            tyl_log_err ("External command for resource \"%s\" failed with code %d", res, rc);
            exit (TYL_EXIT_IO);
        }

    } else if (strcasecmp (cmd, CMD_READ) == 0) {
        char cmdline[4096];
        if (get_expanded_cmd (res, CMD_READ, cmdline, sizeof (cmdline)) != SUCCESS) {
            tyl_crypto_send_frame (&session, sock_fd, "ERROR: Internal config error", 28);
            exit (TYL_EXIT_CONFIG);
        }

        changeuser (res);
        const CfgSection* s = CfgGetSection (res);
        if (s && s->has_umask) umask ((mode_t)s->umask_val);

        if (makelock (res) == FAILURE) {
            tyl_crypto_send_frame (&session, sock_fd, "ERROR: Resource is locked", 25);
            exit (TYL_EXIT_RESOURCE);
        }

        startcmd (cmdline, "r");
        tyl_crypto_send_frame (&session, sock_fd, "OK", 2);

        /* Streaming command stdout in encrypted frames */
        uint8_t read_buf[TYL_DEFAULT_BLOCKSIZE];
        while (1) {
            size_t n = fread (read_buf, 1, sizeof(read_buf), clientio);
            if (n == 0) break;
            if (tyl_crypto_send_frame (&session, sock_fd, read_buf, n) != 0) {
                tyl_log_warn ("Error sending encrypted data frame to %s", clientname);
                break;
            }
            rbytes += n;
        }

        /* Send EOF marker */
        tyl_crypto_send_frame (&session, sock_fd, "", 0);

        int rc = endcmd ();
        rmlock ();

        if (rc == 0) {
            tyl_crypto_send_frame (&session, sock_fd, "OK", 2);
            tyl_log_info ("READ completed successfully for %s (%lu bytes transferred)", clientname, rbytes);
            exit (TYL_EXIT_SUCCESS);
        } else {
            char errbuf[128];
            snprintf (errbuf, sizeof(errbuf), "ERROR: External command exited with code %d", rc);
            tyl_crypto_send_frame (&session, sock_fd, errbuf, strlen(errbuf));
            tyl_log_err ("External command for resource \"%s\" failed with code %d", res, rc);
            exit (TYL_EXIT_IO);
        }

    } else if (strcasecmp (cmd, CMD_LIST) == 0) {
        tyl_crypto_send_frame (&session, sock_fd, "OK", 2);
        char* list_data = NULL;
        size_t list_size = 0;
        FILE* mfp = open_memstream (&list_data, &list_size);
        if (mfp) {
            CfgListSectionsForClient (mfp, clientname, clientaddr);
            fclose (mfp);
        }

        if (list_data) {
            tyl_crypto_send_frame (&session, sock_fd, list_data, list_size);
            free (list_data);
        } else {
            tyl_crypto_send_frame (&session, sock_fd, "", 0);
        }
        tyl_crypto_send_frame (&session, sock_fd, "OK", 2);
        tyl_log_info ("LIST completed successfully for %s", clientname);
        exit (TYL_EXIT_SUCCESS);
    }

    exit (TYL_EXIT_SUCCESS);
}

/* Legacy 0.20 unencrypted connection handler */
static void handle_legacy_connection (int sock_fd, const char* initial_line) {
    const CfgGlobal* g = CfgGetGlobal ();
    if (g && !g->allow_legacy) {
        dprintf (sock_fd, "ERROR: Legacy unencrypted connections are disabled.\n");
        tyl_log_warn ("Rejected legacy connection from %s (legacy disabled)", clientname);
        exit (TYL_EXIT_AUTH);
    }

    tyl_log_notice ("Handling legacy 0.20 connection from %s", clientname);
    dup2 (sock_fd, STDIN_FILENO);
    dup2 (sock_fd, STDOUT_FILENO);

    char cmd[1024];
    StrNCopy (cmd, initial_line, sizeof(cmd));

    do {
        trim_whitespace (cmd);
        if (cmd[0] == '\0') continue;

        tyl_log_info ("Legacy command from %s: \"%s\"", clientname, cmd);

        if (strncmp (cmd, CMD_WRITE, strlen (CMD_WRITE)) == 0) {
            const char* res = cmd + strlen(CMD_WRITE);
            while (isspace ((unsigned char)*res)) res++;

            char cmdline[4096];
            if (get_expanded_cmd (res, CMD_WRITE, cmdline, sizeof(cmdline)) != SUCCESS) {
                erranswer ("Configuration error");
                continue;
            }
            if (clientaccess (res) == NO) {
                erranswer ("Access denied");
                continue;
            }
            changeuser (res);
            if (makelock (res) == FAILURE) {
                erranswer ("Resource is locked");
                continue;
            }

            startcmd (cmdline, "w");
            okanswer ();

            char buf[256];
            while (1) {
                int count = getchar ();
                if (count == EOF) {
                    connbroken ();
                }
                if (count == 0) break;
                while (count > 0) {
                    int c = fread (buf, 1, (count > 255) ? 255 : count, stdin);
                    if (c <= 0) connbroken ();
                    fwrite (buf, 1, c, clientio);
                    count -= c;
                    wbytes += c;
                }
            }
            int rc = endcmd ();
            rmlock ();
            if (rc == 0) okanswer ();
            else erranswer ("External command exited with code %d", rc);

        } else if (strncmp (cmd, CMD_READ, strlen (CMD_READ)) == 0) {
            const char* res = cmd + strlen(CMD_READ);
            while (isspace ((unsigned char)*res)) res++;

            char cmdline[4096];
            if (get_expanded_cmd (res, CMD_READ, cmdline, sizeof(cmdline)) != SUCCESS) {
                erranswer ("Configuration error");
                continue;
            }
            if (clientaccess (res) == NO) {
                erranswer ("Access denied");
                continue;
            }
            changeuser (res);
            if (makelock (res) == FAILURE) {
                erranswer ("Resource is locked");
                continue;
            }

            startcmd (cmdline, "r");
            okanswer ();

            char buf[256];
            while (1) {
                int count = fread (buf, 1, 255, clientio);
                if (count <= 0) break;
                putchar (count);
                if (fwrite (buf, 1, count, stdout) != (size_t)count) {
                    connbroken ();
                }
                rbytes += count;
            }
            putchar (0);
            fflush (stdout);

            int rc = endcmd ();
            rmlock ();
            if (rc == 0) okanswer ();
            else erranswer ("External command exited with code %d", rc);

        } else if (strncmp (cmd, CMD_LIST, strlen (CMD_LIST)) == 0) {
            if (clientaccess (NULL) == NO) {
                erranswer ("Access denied");
            } else {
                CfgListSectionsForClient (stdout, clientname, clientaddr);
                okanswer ();
            }
        } else if (strncmp (cmd, CMD_BYE, strlen (CMD_BYE)) == 0) {
            break;
        } else {
            erranswer ("Unknown command");
        }
    } while (fgets (cmd, sizeof(cmd), stdin) != NULL);

    exit (TYL_EXIT_SUCCESS);
}

static void handle_connection (int sock_fd) {
    getclient_from_sock (sock_fd);
    tyl_log_notice ("Client connected: %s", clientname);

    char first_line[1024];
    if (read_line_timeout (sock_fd, first_line, sizeof(first_line), 30) <= 0) {
        close (sock_fd);
        exit (TYL_EXIT_NETWORK);
    }

    if (strncmp (first_line, TYL_MAGIC, strlen (TYL_MAGIC)) == 0) {
        handle_modern_connection (sock_fd, first_line);
    } else {
        handle_legacy_connection (sock_fd, first_line);
    }

    close (sock_fd);
    exit (TYL_EXIT_SUCCESS);
}

static void sigchld_handler (int sig) {
    (void)sig;
    while (waitpid (-1, NULL, WNOHANG) > 0);
}

static void sigterm_handler (int sig) {
    (void)sig;
    tyl_log_notice ("Received termination signal, shutting down.");
    doexit ();
    _exit (TYL_EXIT_SIGNAL);
}

static void sighup_handler (int sig) {
    (void)sig;
    got_sighup = 1;
}

static void daemonize (const char* pidfile) {
    pid_t pid = fork ();
    if (pid < 0) errexit_code (TYL_EXIT_IO, "fork failed: %m");
    if (pid > 0) _exit (0); /* Exit parent */

    if (setsid () < 0) errexit_code (TYL_EXIT_IO, "setsid failed: %m");

    pid = fork ();
    if (pid < 0) errexit_code (TYL_EXIT_IO, "second fork failed: %m");
    if (pid > 0) _exit (0);

    /* Write PID file with failover between /var/run and /run */
    if (pidfile && pidfile[0] != '\0') {
        FILE* fp = fopen (pidfile, "w");
        char alt_path[PATH_MAX];
        alt_path[0] = '\0';
        if (!fp) {
            if (strncmp (pidfile, "/run/", 5) == 0) {
                snprintf (alt_path, sizeof(alt_path), "/var%s", pidfile);
                fp = fopen (alt_path, "w");
            } else if (strncmp (pidfile, "/var/run/", 9) == 0) {
                snprintf (alt_path, sizeof(alt_path), "%s", pidfile + 4);
                fp = fopen (alt_path, "w");
            }
            if (fp) pidfile = alt_path;
        }
        if (fp) {
            fprintf (fp, "%d\n", getpid ());
            fclose (fp);
            StrNCopy (active_pidfile, pidfile, sizeof(active_pidfile));
        } else {
            tyl_log_warn ("Could not write PID file \"%s\": %m", pidfile);
        }
    }

    /* Redirect standard file descriptors to /dev/null */
    int null_fd = open ("/dev/null", O_RDWR);
    if (null_fd >= 0) {
        dup2 (null_fd, STDIN_FILENO);
        dup2 (null_fd, STDOUT_FILENO);
        dup2 (null_fd, STDERR_FILENO);
        if (null_fd > 2) close (null_fd);
    }
}

int main (int argc, char* argv[]) {
    int opt;
    int override_port = 0;
    char* override_bind = NULL;
    char* override_pidfile = NULL;
    char* override_logfile = NULL;
    char* override_loglevel = NULL;
    char* override_logtarget = NULL;
    int opt_daemon = 0;
    int opt_foreground = 0;
    int opt_inetd = 0;
    int opt_check_config = 0;

    progname = argv[0];
    atexit (doexit);

    struct option long_options[] = {
        {"config",       required_argument, 0, 'c'},
        {"port",         required_argument, 0, 'p'},
        {"bind",         required_argument, 0, 'b'},
        {"daemon",       no_argument,       0, 'd'},
        {"foreground",   no_argument,       0, 'F'},
        {"inetd",        no_argument,       0, 'i'},
        {"pidfile",      required_argument, 0, 'P'},
        {"logfile",      required_argument, 0, 'l'},
        {"loglevel",     required_argument, 0, 'L'},
        {"logtarget",    required_argument, 0, 't'},
        {"check-config", no_argument,       0, 'C'},
        {"version",      no_argument,       0, 'V'},
        {"help",         no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long (argc, argv, "c:p:b:dFiP:l:L:t:VCh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c': configname = optarg; break;
            case 'p': override_port = atoi (optarg); break;
            case 'b': override_bind = optarg; break;
            case 'd': opt_daemon = 1; break;
            case 'F': opt_foreground = 1; break;
            case 'i': opt_inetd = 1; break;
            case 'P': override_pidfile = optarg; break;
            case 'l': override_logfile = optarg; break;
            case 'L': override_loglevel = optarg; break;
            case 't': override_logtarget = optarg; break;
            case 'C': opt_check_config = 1; break;
            case 'V':
                printf ("%s (%s) v%s\n"
                        "Original author: Ullrich von Bassewitz (1998) [email uz@musoftware.de no longer active]\n"
                        "Modernized by: Antigravity / Gemini (Google DeepMind, 2026)\n"
                        "Requested & Commissioned by: %s\n"
                        "Engine: %s\n"
                        "Key exchange: X25519 (Curve25519 ECDH)\n"
                        "Supported ciphers: AES-256-GCM (NIST/TLS 1.3 default), AES-128-GCM, ChaCha20-Poly1305 (RFC 8439),\n"
                        "                   XChaCha20-Poly1305 (extended nonce), ASCON-128a (NIST LWC), Speck-128/128-Poly1305\n",
                        SOFTWARE_NAME, SOFTWARE_TITLE, VERSION, COMMISSIONER,
                        tyl_crypto_engine_desc ());
                return TYL_EXIT_SUCCESS;
            case 'h':
            case '?':
                usage ();
                break;
        }
    }

    if (CfgInit () != SUCCESS) {
        errexit_code (TYL_EXIT_CONFIG, "Error accessing config file \"%s\"", configname);
    }
    setup_security ();

    if (opt_check_config) {
        printf ("Configuration file \"%s\" syntax OK\n", configname);
        printf ("Configured resources:\n");
        const CfgSection* sec = CfgGetFirstSection ();
        if (!sec) {
            printf ("  (no resources defined)\n");
        }
        while (sec) {
            printf ("  [%s]\n", sec->name);
            printf ("    user:     %s\n", (sec->user && sec->user[0]) ? sec->user : "root (default)");
            printf ("    group:    %s\n", (sec->group && sec->group[0]) ? sec->group : "root (default)");
            printf ("    password: %s\n", sec->password ? "[configured]" : "[none]");
            printf ("    write:    %s\n", sec->write_cmd ? "[configured]" : "[none]");
            printf ("    read:     %s\n", sec->read_cmd ? "[configured]" : "[none]");
            if (sec->lockfile) printf ("    lockfile: %s\n", sec->lockfile);
            sec = sec->next;
        }
        return TYL_EXIT_SUCCESS;
    }

    /* Configure server logging subsystem */
    const CfgGlobal* g = CfgGetGlobal ();
    const char* log_tgt = override_logtarget ? override_logtarget : (g && g->log_target ? g->log_target : "file");
    const char* log_fil = override_logfile ? override_logfile : (g && g->log_file ? g->log_file : "/var/log/backupd-tyl.log");
    int log_lvl = g ? g->log_level : TYL_LOG_WARN;
    if (override_loglevel) {
        if (strcasecmp (override_loglevel, "debug") == 0) log_lvl = TYL_LOG_DEBUG;
        else if (strcasecmp (override_loglevel, "info") == 0) log_lvl = TYL_LOG_INFO;
        else if (strcasecmp (override_loglevel, "notice") == 0) log_lvl = TYL_LOG_NOTICE;
        else if (strcasecmp (override_loglevel, "warn") == 0 || strcasecmp (override_loglevel, "warning") == 0) log_lvl = TYL_LOG_WARN;
        else if (strcasecmp (override_loglevel, "err") == 0 || strcasecmp (override_loglevel, "error") == 0) log_lvl = TYL_LOG_ERR;
    }
    int log_fac = g ? g->log_facility : LOG_DAEMON;
    tyl_log_init (log_tgt, log_fil, log_lvl, log_fac);

    int port = override_port ? override_port : (g ? g->port : DEFAULTPORT);
    const char* bind_addr = override_bind ? override_bind : (g && g->bind_address ? g->bind_address : "0.0.0.0");
    const char* pid_file = override_pidfile ? override_pidfile : (g && g->pid_file ? g->pid_file : "/var/run/backupd-tyl.pid");

    /* Detect inetd mode if stdin is a socket and neither daemon nor foreground was specified */
    if (!opt_daemon && !opt_foreground) {
        struct sockaddr_storage ss;
        socklen_t sslen = sizeof(ss);
        if (getsockname (STDIN_FILENO, (struct sockaddr*)&ss, &sslen) == 0) {
            opt_inetd = 1;
        }
    }

    if (opt_inetd) {
        tyl_log_notice ("%s v%s started in inetd mode", SOFTWARE_NAME, VERSION);
        handle_connection (STDIN_FILENO);
        return TYL_EXIT_SUCCESS;
    }

    /* Standalone Service Mode */
    if (opt_daemon) {
        daemonize (pid_file);
    } else if (opt_foreground && pid_file && pid_file[0] != '\0') {
        FILE* fp = fopen (pid_file, "w");
        char alt_path[PATH_MAX];
        alt_path[0] = '\0';
        if (!fp) {
            if (strncmp (pid_file, "/run/", 5) == 0) {
                snprintf (alt_path, sizeof(alt_path), "/var%s", pid_file);
                fp = fopen (alt_path, "w");
            } else if (strncmp (pid_file, "/var/run/", 9) == 0) {
                snprintf (alt_path, sizeof(alt_path), "%s", pid_file + 4);
                fp = fopen (alt_path, "w");
            }
            if (fp) pid_file = alt_path;
        }
        if (fp) {
            fprintf (fp, "%d\n", getpid ());
            fclose (fp);
            StrNCopy (active_pidfile, pid_file, sizeof(active_pidfile));
        }
    }

    /* Setup signal handlers for standalone daemon */
    struct sigaction sa;
    memset (&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_handler;
    sigemptyset (&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction (SIGCHLD, &sa, NULL);

    sa.sa_handler = sigterm_handler;
    sigaction (SIGTERM, &sa, NULL);
    sigaction (SIGINT, &sa, NULL);

    struct sigaction sa_hup;
    memset (&sa_hup, 0, sizeof(sa_hup));
    sa_hup.sa_handler = sighup_handler;
    sigemptyset (&sa_hup.sa_mask);
    sa_hup.sa_flags = 0; /* Do not restart system calls so accept() interrupts immediately */
    sigaction (SIGHUP, &sa_hup, NULL);

    /* Create TCP master socket */
    master_socket = socket (AF_INET, SOCK_STREAM, 0);
    if (master_socket < 0) {
        errexit_code (TYL_EXIT_NETWORK, "Cannot create master socket: %m");
    }

    int optval = 1;
    setsockopt (master_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in sin;
    memset (&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons ((uint16_t)port);
    if (inet_pton (AF_INET, bind_addr, &sin.sin_addr) <= 0) {
        errexit_code (TYL_EXIT_NETWORK, "Invalid bind address \"%s\"", bind_addr);
    }

    if (bind (master_socket, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
        errexit_code (TYL_EXIT_NETWORK, "Cannot bind to %s:%d: %m", bind_addr, port);
    }

    if (listen (master_socket, 128) < 0) {
        errexit_code (TYL_EXIT_NETWORK, "listen failed: %m");
    }

    tyl_log_notice ("%s v%s standalone service listening on %s:%d (pid %d)",
                    SOFTWARE_NAME, VERSION, bind_addr, port, getpid ());

    while (1) {
        if (got_sighup) {
            got_sighup = 0;
            tyl_log_notice ("SIGHUP received, reloading configuration from \"%s\"", configname);
            CfgInit ();
            const CfgGlobal* cur_g = CfgGetGlobal ();
            const char* cur_tgt = override_logtarget ? override_logtarget : (cur_g && cur_g->log_target ? cur_g->log_target : "file");
            const char* cur_fil = override_logfile ? override_logfile : (cur_g && cur_g->log_file ? cur_g->log_file : "/var/log/backupd-tyl.log");
            int cur_lvl = cur_g ? cur_g->log_level : TYL_LOG_WARN;
            if (override_loglevel) {
                if (strcasecmp (override_loglevel, "debug") == 0) cur_lvl = TYL_LOG_DEBUG;
                else if (strcasecmp (override_loglevel, "info") == 0) cur_lvl = TYL_LOG_INFO;
                else if (strcasecmp (override_loglevel, "notice") == 0) cur_lvl = TYL_LOG_NOTICE;
                else if (strcasecmp (override_loglevel, "warn") == 0 || strcasecmp (override_loglevel, "warning") == 0) cur_lvl = TYL_LOG_WARN;
                else if (strcasecmp (override_loglevel, "err") == 0 || strcasecmp (override_loglevel, "error") == 0) cur_lvl = TYL_LOG_ERR;
            }
            int cur_fac = cur_g ? cur_g->log_facility : LOG_DAEMON;
            tyl_log_init (cur_tgt, cur_fil, cur_lvl, cur_fac);
            tyl_log_reopen ();
        }

        struct sockaddr_in client_sa;
        socklen_t client_len = sizeof(client_sa);
        int client_sock = accept (master_socket, (struct sockaddr*)&client_sa, &client_len);
        if (client_sock < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            tyl_log_warn ("accept failed: %m");
            continue;
        }

        pid_t child = fork ();
        if (child == 0) {
            /* Child worker */
            signal (SIGCHLD, SIG_DFL);
            close (master_socket);
            master_socket = -1;
            handle_connection (client_sock);
            exit (TYL_EXIT_SUCCESS);
        } else if (child > 0) {
            /* Parent listener */
            close (client_sock);
        } else {
            tyl_log_warn ("fork failed for client: %m");
            close (client_sock);
        }
    }

    return TYL_EXIT_SUCCESS;
}
