/*****************************************************************************/
/*                                                                           */
/*                                 client.h                                  */
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

#ifndef CLIENT_H
#define CLIENT_H

#include <stdio.h>

extern unsigned long clientaddr;
extern char          clientname [1024];

/* Resolves remote peer IP and reverse DNS hostname (if nodns=0) */
void getclient_from_sock (int fd);

/* Evaluates resource-level and global-level ACLs (Allow/Deny) */
int  clientaccess (const char* res);

/* Validates client authentication password (resource-specific or global fallback) */
int  client_check_auth (const char* res, const char* provided_password);

/* Protocol response formatting helpers */
void answer (const char* format, ...) __attribute__((format(printf, 1, 2)));
void okanswer (void);
void erranswer (const char* msg, ...) __attribute__((format(printf, 1, 2)));

#endif /* CLIENT_H */
