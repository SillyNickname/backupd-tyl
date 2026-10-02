/*****************************************************************************/
/*                                                                           */
/*                                 client.c                                  */
/*                                                                           */
/*                    Code handling client specific things                   */
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
#include <errno.h>
#include <syslog.h>
#include <fnmatch.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "const.h"
#include "error.h"
#include "config.h"
#include "client.h"
#include "util.h"
#include "crypto/tyl_crypto.h"

unsigned long clientaddr = 0x7F000001; /* 127.0.0.1 */
char          clientname [1024] = "localhost";

static void iptoname (void) {
    snprintf (clientname, sizeof(clientname), "%u.%u.%u.%u",
              (unsigned)(clientaddr >> 24) & 0xFF,
              (unsigned)(clientaddr >> 16) & 0xFF,
              (unsigned)(clientaddr >> 8) & 0xFF,
              (unsigned)(clientaddr >> 0) & 0xFF);
}

void getclient_from_sock (int fd) {
    struct sockaddr_in client;
    socklen_t len = sizeof(client);

    memset (&client, 0, sizeof(client));
    if (getpeername (fd, (struct sockaddr*)&client, &len) == -1) {
        if (errno == ENOTSOCK) {
            StrNCopy (clientname, "console", sizeof(clientname));
            clientaddr = 0x7F000001;
            return;
        }
        warning ("Cannot determine client IP address: %m(%d)", errno);
        StrNCopy (clientname, "unknown", sizeof(clientname));
        return;
    }

    clientaddr = ntohl (client.sin_addr.s_addr);

    const CfgGlobal* g = CfgGetGlobal ();
    if (g && g->nodns) {
        iptoname ();
    } else {
        char host_buf[NI_MAXHOST];
        if (getnameinfo ((struct sockaddr*)&client, len, host_buf, sizeof(host_buf), NULL, 0, NI_NAMEREQD) == 0) {
            StrNCopy (clientname, host_buf, sizeof(clientname));
        } else {
            iptoname ();
        }
    }

    /*
     * Security: Strictly sanitize clientname against reverse DNS shell injection.
     * When backup commands expand meta-tokens (\h or \H), any characters outside
     * [a-zA-Z0-9._-] could otherwise cause shell metacharacter injection.
     */
    char* c = clientname;
    while (*c) {
        if (!validfilechar ((unsigned char)*c)) {
            *c = '_';
        }
        c++;
    }
}

/*
 * clientaccess: Evaluates access permission for the current client against
 * the configured Access Control Lists.
 *
 * Rules:
 * 1. If a specific resource is requested, its local Allow/Deny settings override
 *    the global settings.
 * 2. If a setting (Allow or Deny) is not specified at the resource level, the
 *    global setting is inherited as fallback.
 * 3. If no resource is requested (e.g. LIST command), the global ACL is evaluated.
 * 4. Within check_client_acl(), Allow takes precedence over Deny.
 */
int clientaccess (const char* res) {
    const CfgGlobal* g = CfgGetGlobal ();
    const CfgSection* s = (res && res[0] != '\0') ? CfgGetSection (res) : NULL;

    if (res && res[0] != '\0' && !s) {
        return NO;
    }

    const char* eff_allow = (s && s->allow) ? s->allow : (g ? g->allow : NULL);
    const char* eff_deny  = (s && s->deny)  ? s->deny  : (g ? g->deny  : NULL);

    return check_client_acl (eff_allow, eff_deny, clientname, clientaddr);
}

/*
 * client_check_auth: Validates the client password.
 * Checks resource-specific password first; if not set, falls back to global password.
 * If neither is set, access is unauthenticated (allowed).
 * If password is required, uses constant-time comparison to prevent timing leaks.
 */
int client_check_auth (const char* res, const char* provided_password) {
    const CfgSection* s = res ? CfgGetSection (res) : NULL;
    const char* expected = NULL;

    if (s && s->password && s->password[0] != '\0') {
        expected = s->password;
    } else {
        const CfgGlobal* g = CfgGetGlobal ();
        if (g && g->password && g->password[0] != '\0') {
            expected = g->password;
        }
    }

    if (!expected || expected[0] == '\0') {
        /* No password required */
        return 0;
    }

    if (!provided_password || provided_password[0] == '\0') {
        return -1;
    }

    return tyl_crypto_verify_password (expected, provided_password);
}

void answer (const char* format, ...) {
    char buf [2048];
    va_list ap;
    va_start (ap, format);
    vsnprintf (buf, sizeof (buf), format, ap);
    va_end (ap);

    if (puts (buf) == EOF) {
        connbroken ();
    }
    fflush (stdout);
}

void okanswer (void) {
    answer ("OK");
}

void erranswer (const char* msg, ...) {
    char buf [2048];
    va_list ap;
    va_start (ap, msg);
    vsnprintf (buf, sizeof (buf), msg, ap);
    va_end (ap);

    if (printf ("ERROR: %s\n", buf) <= 0) {
        connbroken ();
    }
    fflush (stdout);
}
