/*****************************************************************************/
/*                                                                           */
/*                                   sig.c                                   */
/*                                                                           */
/*                    Signals handling stuff for backupd                     */
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

#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "sig.h"

sigjmp_buf sigexit;
sig_atomic_t sigcaught;

void tyl_sigignore (int sig) {
    struct sigaction action, oldaction;
    action.sa_handler = SIG_IGN;
    sigemptyset (&action.sa_mask);
    action.sa_flags   = SA_RESTART;
    if (sigaction (sig, &action, &oldaction) != 0) {
        syslog (LOG_ERR, "Error ignoring signal %d: %s", sig, strerror (errno));
        exit (EXIT_FAILURE);
    }
}

void tyl_sigset (int sig, void (*handler) (int)) {
    struct sigaction action, oldaction;
    action.sa_handler = handler;
    sigemptyset (&action.sa_mask);
    action.sa_flags   = SA_RESTART;
    if (sigaction (sig, &action, &oldaction) != 0) {
        syslog (LOG_ERR, "Error setting signal handler for signal %d: %s", sig, strerror (errno));
        exit (EXIT_FAILURE);
    }
}

void sighandler (int sig) {
    sigcaught = sig;
    siglongjmp (sigexit, 1);
}
