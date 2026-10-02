/*****************************************************************************/
/*                                                                           */
/*                                  util.h                                   */
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

#ifndef UTIL_H
#define UTIL_H

#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

/* Safe string operations */
char* StrNCopy (char* Dest, const char* Src, size_t Size);
int   validfilechar (int c);
void  trim_whitespace (char* s);
int   is_ascii_whitespace (int c);
int   sanitize_identifier (char* dest, const char* src, size_t max_size);
int   expand_meta (char* target, const char* src, unsigned size, const char* clientname);

/* Robust blocking/timeout socket and file descriptor I/O */
int   write_all (int fd, const void* buf, size_t len);
int   read_all (int fd, void* buf, size_t len);
int   read_line_timeout (int fd, char* buf, size_t max_len, int timeout_sec);

#endif /* UTIL_H */
