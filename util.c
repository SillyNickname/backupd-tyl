/*****************************************************************************/
/*                                                                           */
/*                                  util.c                                   */
/*                                                                           */
/*                        Utility functions for backupd                      */
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
#include <assert.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <poll.h>
#include <errno.h>

#include "const.h"
#include "util.h"

/*
 * Safe bounded string copy: ensures NUL-termination under all conditions,
 * avoiding truncation vulnerabilities and buffer overruns.
 */
char* StrNCopy (char* Dest, const char* Src, size_t Size) {
    if (!Dest || Size == 0) return Dest;
    if (!Src) {
        Dest[0] = '\0';
        return Dest;
    }
    size_t i = 0;
    while (i < Size - 1 && Src[i] != '\0') {
        Dest[i] = Src[i];
        i++;
    }
    Dest[i] = '\0';
    return Dest;
}

int validfilechar (int c) {
    return (isascii (c) && (isalnum (c) || c == '-' || c == '_' || c == '.'));
}

int is_ascii_whitespace (int c) {
    return (isascii(c) && isspace(c));
}

void trim_whitespace (char* s) {
    if (!s) return;
    int len = (int)strlen(s);
    while (len > 0 && is_ascii_whitespace((unsigned char)s[len - 1])) {
        s[--len] = '\0';
    }
    char* start = s;
    while (*start && is_ascii_whitespace((unsigned char)*start)) {
        start++;
    }
    if (start != s) {
        memmove(s, start, strlen(start) + 1);
    }
}

int sanitize_identifier (char* dest, const char* src, size_t max_size) {
    if (!dest || !src || max_size == 0) return -1;
    size_t j = 0;
    for (size_t i = 0; src[i] != '\0' && j < max_size - 1; ++i) {
        if (validfilechar((unsigned char)src[i])) {
            dest[j++] = src[i];
        } else {
            dest[j++] = '-';
        }
    }
    dest[j] = '\0';
    return 0;
}

int expand_meta (char* target, const char* src, unsigned size, const char* clientname) {
    unsigned i = 0;
    if (!target || !src || size == 0) return FAILURE;

    while (*src && i < size - 1) {
        if (*src != '\\') {
            target[i++] = *src++;
            continue;
        }

        /* Found backslash */
        src++;
        switch (*src) {
            case 'h': {
                const char* host = clientname ? clientname : "unknown";
                while (*host && i < size - 1) {
                    if (validfilechar((unsigned char)*host)) {
                        target[i++] = *host;
                    } else {
                        target[i++] = '_';
                    }
                    host++;
                }
                src++;
                break;
            }
            case 'H': {
                const char* host = clientname ? clientname : "unknown";
                while (*host && i < size - 1) {
                    if (validfilechar((unsigned char)*host)) {
                        target[i++] = *host;
                    } else {
                        target[i++] = '-';
                    }
                    host++;
                }
                src++;
                break;
            }
            case '\\':
                target[i++] = '\\';
                src++;
                break;
            case '\0':
                break;
            default:
                target[i++] = *src++;
                break;
        }
    }
    target[i] = '\0';
    return (*src == '\0') ? SUCCESS : FAILURE;
}

int write_all (int fd, const void* buf, size_t len) {
    const uint8_t* p = (const uint8_t*)buf;
    size_t rem = len;
    while (rem > 0) {
        ssize_t n = write(fd, p, rem);
        if (n <= 0) {
            if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
                continue;
            }
            return -1;
        }
        p += n;
        rem -= (size_t)n;
    }
    return 0;
}

int read_all (int fd, void* buf, size_t len) {
    uint8_t* p = (uint8_t*)buf;
    size_t rem = len;
    while (rem > 0) {
        ssize_t n = read(fd, p, rem);
        if (n <= 0) {
            if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
                continue;
            }
            return -1;
        }
        p += n;
        rem -= (size_t)n;
    }
    return 0;
}

int read_line_timeout (int fd, char* buf, size_t max_len, int timeout_sec) {
    if (!buf || max_len == 0) return -1;
    size_t idx = 0;

    while (idx < max_len - 1) {
        if (timeout_sec > 0) {
            struct pollfd pfd;
            pfd.fd = fd;
            pfd.events = POLLIN;
            pfd.revents = 0;
            int sel = poll(&pfd, 1, timeout_sec * 1000);
            if (sel <= 0) {
                if (sel < 0 && errno == EINTR) continue;
                return -1; /* Timeout or error */
            }
            if (!(pfd.revents & (POLLIN | POLLHUP | POLLERR))) {
                return -1;
            }
        }

        char c;
        ssize_t n = read(fd, &c, 1);
        if (n <= 0) {
            if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
            break; /* EOF or error */
        }

        if (c == '\n') {
            break;
        }
        if (c != '\r') {
            buf[idx++] = c;
        }
    }

    buf[idx] = '\0';
    return (idx > 0 || max_len > 0) ? (int)idx : -1;
}
