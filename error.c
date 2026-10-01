/*****************************************************************************/
/*                                                                           */
/*                                  error.c                                  */
/*                                                                           */
/*                    Error and logging functions for backupd-tyl            */
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
#include <syslog.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>

#include "const.h"
#include "proto.h"
#include "global.h"
#include "config.h"
#include "error.h"
#include "util.h"

static char  s_log_target[32]    = "syslog";
static char  s_log_file[512]     = "";
static int   s_log_level         = TYL_LOG_INFO;
static int   s_log_facility      = LOG_DAEMON;
static FILE* s_log_fp            = NULL;
static int   s_syslog_open       = 0;

static const char* level_name (int level) {
    switch (level) {
        case TYL_LOG_DEBUG:  return "DEBUG";
        case TYL_LOG_INFO:   return "INFO";
        case TYL_LOG_NOTICE: return "NOTICE";
        case TYL_LOG_WARN:   return "WARN";
        case TYL_LOG_ERR:    return "ERROR";
        default:             return "LOG";
    }
}

void tyl_log_init (const char* target, const char* file, int level, int facility) {
    tyl_log_close ();

    if (target && target[0] != '\0') {
        StrNCopy (s_log_target, target, sizeof(s_log_target));
    }
    if (file && file[0] != '\0') {
        StrNCopy (s_log_file, file, sizeof(s_log_file));
        /* If a log file is explicitly given and target wasn't set to stderr/syslog, use file */
        if (strcasecmp (s_log_target, "file") != 0 &&
            strcasecmp (s_log_target, "stderr") != 0 &&
            strcasecmp (s_log_target, "syslog") != 0) {
            StrNCopy (s_log_target, "file", sizeof(s_log_target));
        }
    }
    if (level > 0) {
        s_log_level = level;
    }
    if (facility > 0) {
        s_log_facility = facility;
    }

    if (strcasecmp (s_log_target, "file") == 0) {
        if (s_log_file[0] != '\0') {
            s_log_fp = fopen (s_log_file, "a");
            if (!s_log_fp) {
                fprintf (stderr, "backupd: Cannot open log file \"%s\": %s. Falling back to syslog.\n",
                         s_log_file, strerror (errno));
                StrNCopy (s_log_target, "syslog", sizeof(s_log_target));
            }
        } else {
            StrNCopy (s_log_target, "syslog", sizeof(s_log_target));
        }
    }

    if (strcasecmp (s_log_target, "syslog") == 0) {
        openlog (progname, LOG_PID, s_log_facility);
        s_syslog_open = 1;
    }
}

void tyl_log_reopen (void) {
    if (strcasecmp (s_log_target, "file") == 0 && s_log_file[0] != '\0') {
        if (s_log_fp) {
            fclose (s_log_fp);
            s_log_fp = NULL;
        }
        s_log_fp = fopen (s_log_file, "a");
        if (!s_log_fp) {
            fprintf (stderr, "backupd: Reopen failed for log file \"%s\": %s\n",
                     s_log_file, strerror (errno));
        }
    } else if (strcasecmp (s_log_target, "syslog") == 0) {
        if (s_syslog_open) closelog ();
        openlog (progname, LOG_PID, s_log_facility);
        s_syslog_open = 1;
    }
}

void tyl_log_close (void) {
    if (s_log_fp) {
        fclose (s_log_fp);
        s_log_fp = NULL;
    }
    if (s_syslog_open) {
        closelog ();
        s_syslog_open = 0;
    }
}

void tyl_log (int level, const char* format, ...) {
    if (level > s_log_level) {
        return; /* Filtered out by configured log level */
    }

    int saved_errno = errno;
    struct timeval tv;
    gettimeofday (&tv, NULL);
    struct tm tm;
    localtime_r (&tv.tv_sec, &tm);
    char timebuf[32];
    strftime (timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm);

    va_list ap;

    if (strcasecmp (s_log_target, "file") == 0 && s_log_fp) {
        fprintf (s_log_fp, "%s.%03ld [%d] [%s] ",
                 timebuf, tv.tv_usec / 1000, getpid (), level_name (level));
        va_start (ap, format);
        vfprintf (s_log_fp, format, ap);
        va_end (ap);
        fprintf (s_log_fp, "\n");
        fflush (s_log_fp);
    } else if (strcasecmp (s_log_target, "stderr") == 0) {
        fprintf (stderr, "%s.%03ld [%d] [%s] ",
                 timebuf, tv.tv_usec / 1000, getpid (), level_name (level));
        va_start (ap, format);
        vfprintf (stderr, format, ap);
        va_end (ap);
        fprintf (stderr, "\n");
        fflush (stderr);
    } else {
        /* Default: syslog / rsyslogd */
        if (!s_syslog_open) {
            openlog (progname, LOG_PID, s_log_facility);
            s_syslog_open = 1;
        }
        va_start (ap, format);
        vsyslog (level, format, ap);
        va_end (ap);

        /* If attached to an interactive terminal, mirror to stderr */
        if (isatty (STDERR_FILENO)) {
            fprintf (stderr, "%s [%s] ", timebuf, level_name (level));
            va_start (ap, format);
            vfprintf (stderr, format, ap);
            va_end (ap);
            fprintf (stderr, "\n");
        }
    }

    errno = saved_errno;
}

void tyl_log_debug (const char* format, ...) {
    va_list ap;
    va_start (ap, format);
    char buf[1024];
    vsnprintf (buf, sizeof(buf), format, ap);
    va_end (ap);
    tyl_log (TYL_LOG_DEBUG, "%s", buf);
}

void tyl_log_info (const char* format, ...) {
    va_list ap;
    va_start (ap, format);
    char buf[1024];
    vsnprintf (buf, sizeof(buf), format, ap);
    va_end (ap);
    tyl_log (TYL_LOG_INFO, "%s", buf);
}

void tyl_log_notice (const char* format, ...) {
    va_list ap;
    va_start (ap, format);
    char buf[1024];
    vsnprintf (buf, sizeof(buf), format, ap);
    va_end (ap);
    tyl_log (TYL_LOG_NOTICE, "%s", buf);
}

void tyl_log_warn (const char* format, ...) {
    va_list ap;
    va_start (ap, format);
    char buf[1024];
    vsnprintf (buf, sizeof(buf), format, ap);
    va_end (ap);
    tyl_log (TYL_LOG_WARN, "%s", buf);
}

void tyl_log_err (const char* format, ...) {
    va_list ap;
    va_start (ap, format);
    char buf[1024];
    vsnprintf (buf, sizeof(buf), format, ap);
    va_end (ap);
    tyl_log (TYL_LOG_ERR, "%s", buf);
}

void warning (const char* format, ...) {
    va_list ap;
    char buf[1024];
    va_start (ap, format);
    vsnprintf (buf, sizeof(buf), format, ap);
    va_end (ap);
    tyl_log (TYL_LOG_WARN, "%s", buf);
}

void error (const char* format, ...) {
    va_list ap;
    char buf[1024];
    va_start (ap, format);
    vsnprintf (buf, sizeof(buf), format, ap);
    va_end (ap);
    tyl_log (TYL_LOG_ERR, "%s", buf);
}

void errexit (const char* format, ...) {
    va_list ap;
    char buf[1024];
    va_start (ap, format);
    vsnprintf (buf, sizeof(buf), format, ap);
    va_end (ap);
    tyl_log (TYL_LOG_ERR, "%s", buf);
    tyl_log_close ();
    exit (TYL_EXIT_IO);
}

void errexit_code (int exit_code, const char* format, ...) {
    va_list ap;
    char buf[1024];
    va_start (ap, format);
    vsnprintf (buf, sizeof(buf), format, ap);
    va_end (ap);
    tyl_log (TYL_LOG_ERR, "%s", buf);
    tyl_log_close ();
    exit (exit_code);
}

void usage (void) {
    fprintf (stderr,
             "%s (%s) v%s\n"
             "Originally created by Ullrich von Bassewitz (1998) [email uz@musoftware.de inactive]\n"
             "Modernized by Antigravity / Gemini (Google DeepMind, 2026)\n"
             "Requested & Commissioned by: %s\n\n"
             "Usage: %s [options]\n"
             "Options:\n"
             "  -c, --config <file>     Use configuration file (default: %s)\n"
             "  -p, --port <port>       Listen on specified TCP port (default: %d)\n"
             "  -b, --bind <ip>         Bind to local IP address (default: 0.0.0.0)\n"
             "  -d, --daemon            Run in background as standalone daemon\n"
             "  -F, --foreground        Run in foreground (systemd / container mode)\n"
             "  -i, --inetd             Run in inetd / socket activation mode (stdin/stdout)\n"
             "  -P, --pidfile <file>    Write PID to specified file\n"
             "  -l, --logfile <file>    Write logs to specified file\n"
             "  -L, --loglevel <level>  Logging level (debug, info, notice, warn, error)\n"
             "  -t, --logtarget <dest>  Log target: syslog, file, or stderr (default: syslog)\n"
             "  -C, --check-config      Validate configuration file syntax and exit\n"
             "  -V, --version           Print version, commissioner, and cryptographic info\n"
             "  -h, --help              Print this help screen\n",
             SOFTWARE_NAME,
             SOFTWARE_TITLE,
             VERSION,
             COMMISSIONER,
             progname,
             configname,
             DEFAULTPORT);
    exit (TYL_EXIT_USAGE);
}

void connbroken (void) {
    warning ("Connection broken");
    tyl_log_close ();
    exit (TYL_EXIT_IO);
}

void opensyslog (void) {
    const CfgGlobal* g = CfgGetGlobal ();
    int fac = (g && g->log_facility) ? g->log_facility : LOG_DAEMON;
    int lvl = (g && g->log_level) ? g->log_level : TYL_LOG_INFO;
    const char* tgt = (g && g->log_target) ? g->log_target : "syslog";
    const char* fpath = (g && g->log_file) ? g->log_file : "";
    tyl_log_init (tgt, fpath, lvl, fac);
}
