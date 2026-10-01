/*****************************************************************************/
/*                                                                           */
/*                                  proto.h                                  */
/*                                                                           */
/*                  Protocol definitions for backupd-tyl                     */
/*                    (Backupd - Thirty Years Later)                         */
/*                                                                           */
/* (C) 2026 Antigravity / Gemini (Google DeepMind)                           */
/* Based on original backupd concept by Ullrich von Bassewitz (1998)         */
/* [Note: original author email uz@musoftware.de is no longer active]        */
/*                                                                           */
/* This software is provided 'as-is', without any express or implied         */
/* warranty. In no event will the authors be held liable for any damages     */
/* arising from the use of this software.                                    */
/*                                                                           */
/* Permission is granted to anyone to use this software for any purpose,     */
/* including commercial applications, and to alter it and redistribute it    */
/* freely, subject to the following restrictions:                            */
/*                                                                           */
/* 1. The origin of this software must not be misrepresented; you must not   */
/*    claim that you wrote the original software. If you use this software   */
/*    in a product, an acknowledgment in the product documentation would be  */
/*    appreciated but is not required.                                       */
/* 2. Altered source versions must be plainly marked as such, and must not   */
/*    be misrepresented as being the original software.                      */
/* 3. This notice may not be removed or altered from any source              */
/*    distribution.                                                          */
/*                                                                           */
/*****************************************************************************/

#ifndef PROTO_H
#define PROTO_H

/*****************************************************************************/
/*                                   data                                    */
/*****************************************************************************/

/* Software name, version, and attribution */
#define SOFTWARE_NAME   "backupd-tyl"
#define SOFTWARE_TITLE  "Backupd - Thirty Years Later"
#define VERSION         "1.2.0"
#define LEGACY_VERSION  "0.20"
#define COMMISSIONER    "Andre Kajita (kajita@univap.br)"

/* Standard exit codes for scripts and process monitoring */
#define TYL_EXIT_SUCCESS        0   /* Successful execution */
#define TYL_EXIT_USAGE          1   /* Invalid command-line arguments or syntax */
#define TYL_EXIT_CONFIG         2   /* Configuration file error or missing parameter */
#define TYL_EXIT_NETWORK        3   /* Network socket, DNS resolution, or connect failure */
#define TYL_EXIT_AUTH           4   /* Authentication failure (bad/missing password or ACL denied) */
#define TYL_EXIT_CRYPTO         5   /* Cryptographic failure (handshake, negotiation, bad tag) */
#define TYL_EXIT_IO             6   /* File or stream I/O error, pipe broken */
#define TYL_EXIT_RESOURCE       7   /* Resource not found in config or lock held */
#define TYL_EXIT_PERMISSION     8   /* Insufficient OS privileges / setuid/setgid error */
#define TYL_EXIT_SIGNAL         9   /* Terminated by signal (SIGTERM, SIGINT) */

/* Default IP port */
#define DEFAULTPORT     12153

/* Legacy command strings */
#define CMD_WRITE       "WRITE"
#define CMD_READ        "READ"
#define CMD_LIST        "LIST"
#define CMD_BYE         "BYE"

/* Modern TYL/1.0 protocol tokens */
#define TYL_MAGIC       "TYL/1.0"
#define TYL_CMD_HELLO   "TYL/1.0 HELLO"
#define TYL_RESP_KEY    "TYL/1.0 KEY"
#define TYL_RESP_OK     "TYL/1.0 OK"
#define TYL_RESP_ERROR  "ERROR:"

/* Default block sizes */
#define TYL_DEFAULT_BLOCKSIZE 16384
#define LEGACY_MAX_BLOCKSIZE  255

/* Verification tokens */
#define TYL_FIN_TOKEN   "TYL-FINISHED-v1.0"
#define TYL_OK_TOKEN    "TYL-SESSION-READY"

#endif /* PROTO_H */
