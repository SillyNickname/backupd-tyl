/*****************************************************************************/
/*                                                                           */
/*                                   sig.h                                   */
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

#ifndef SIG_H
#define SIG_H

#include <signal.h>
#include <setjmp.h>

extern sigjmp_buf sigexit;
extern sig_atomic_t sigcaught;

void tyl_sigignore (int sig);
void tyl_sigset (int sig, void (*handler) (int));
void sighandler (int sig);

#endif /* SIG_H */
