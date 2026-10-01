/*****************************************************************************/
/*                                                                           */
/*                                  check.h                                  */
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



#ifndef CHECK_H
#define CHECK_H



/*****************************************************************************/
/*                                   Data                                    */
/*****************************************************************************/



extern const char* _MsgInternalError;           // "Internal error: "
extern const char* _MsgPrecondition;            // "Precondition violated: "
extern const char* _MsgCheckFailed;             // "Check failed: "
extern const char* _MsgProgramAborted;		// "Program aborted: "



extern void (*checkfailed) (const char* msg, const char* cond, 
				     int code, const char* file, int line);
/* Function pointer that is called from check if the condition code is true. */



/*****************************************************************************/
/*                                   Code                                    */
/*****************************************************************************/



extern void check (const char* msg, const char* cond, int code,
                   const char* file, int line);
/* This function is called from all check macros (see below). It checks,
 * wether the given Code is true (!= 0). If so, it calls the CheckFailed
 * vector with the given strings. If not, it simply returns.
 */



#define FAIL(s) checkfailed (_MsgInternalError, s, 0, __FILE__, __LINE__)
/* Fail macro. Is used if something evil happens, calls checkfailed directly. */

#define ABORT(s) checkfailed (_MsgProgramAborted, s, 0, __FILE__, __LINE__)
/* Use this one instead of FAIL if there is no internal program error but an
 * error condition that is caused by the user or operating system (FAIL and
 * ABORT are essentially the same but the message differs).
 */

#define PRECONDITION(c) check (_MsgPrecondition,                \
                        #c, !(c), __FILE__, __LINE__)

#define CHECK(c)        check (_MsgCheckFailed,                 \
                        #c, !(c), __FILE__, __LINE__)

#define ZCHECK(c)       check (_MsgCheckFailed,                 \
                        #c, c, __FILE__, __LINE__)



/* End of check.h */

#endif
