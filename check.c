/*****************************************************************************/
/*                                                                           */
/*                                  check.c                                  */
/*                                                                           */
/*                     Assertion macros for backupd-tyl                      */
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



#include <stdlib.h>

#include "error.h"
#include "check.h"



/*****************************************************************************/
/*                                   Data                                    */
/*****************************************************************************/



/* Predefined messages */
const char* _MsgInternalError   = "Internal error: ";
const char* _MsgAbstractCall    = "Call to abstract method";
const char* _MsgPrecondition    = "Precondition violated: ";
const char* _MsgCheckFailed     = "Check failed: ";
const char* _MsgProgramAborted  = "Program aborted: ";



static void _checkfailed (const char* msg, const char* cond,
                           int code, const char* file, int line) __attribute__((noreturn));

void (*checkfailed) (const char* msg, const char* cond, int code,
                     const char* file, int line) = _checkfailed;
/* Function pointer that is called from check if the condition code is true. */



/*****************************************************************************/
/*                                   Code                                    */
/*****************************************************************************/



static void _checkfailed (const char* msg, const char* cond,
                          int code, const char* file, int line)
{
    /* Log the error */
    if (code) {
       	error ("%s%s (= %d), file %s, line %d", msg, cond, code, file, line);
    } else {
	error ("%s%s, file %s, line %d", msg, cond, file, line);
    }

    /* Use abort() to create a core for debugging */
    abort ();
}



void check (const char* msg, const char* cond, int code,
            const char* file, int line)
/* This function is called from all check macros (see below). It checks,
 * wether the given Code is true (!= 0). If so, it calls the CheckFailed
 * vector with the given strings. If not, it simply returns.
 */
{
    if (code != 0) {
        checkfailed (msg, cond, code, file, line);
    }
}



