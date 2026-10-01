/*****************************************************************************/
/*                                                                           */
/*                                  error.h                                  */
/*                                                                           */
/*                    Error and logging headers for backupd-tyl              */
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



#ifndef ERROR_H
#define ERROR_H



/*****************************************************************************/
/*     	       	   	  	     Data				     */
/*****************************************************************************/

/* Logging levels (mirroring syslog priorities) */
#define TYL_LOG_DEBUG   7
#define TYL_LOG_INFO    6
#define TYL_LOG_NOTICE  5
#define TYL_LOG_WARN    4
#define TYL_LOG_ERR     3

/*****************************************************************************/
/*     	       	   	  	     Code				     */
/*****************************************************************************/

/* Subsystem logging functions */
void tyl_log_init (const char* target, const char* file, int level, int facility);
void tyl_log_reopen (void);
void tyl_log_close (void);
void tyl_log (int level, const char* format, ...);
void tyl_log_debug (const char* format, ...);
void tyl_log_info (const char* format, ...);
void tyl_log_notice (const char* format, ...);
void tyl_log_warn (const char* format, ...);
void tyl_log_err (const char* format, ...);

/* Legacy error and warning functions */
void warning (const char* format, ...);
void error (const char* format, ...);
void errexit (const char* format, ...);
void errexit_code (int exit_code, const char* format, ...);

void usage (void);
void connbroken (void);
void opensyslog (void);

#endif /* ERROR_H */



