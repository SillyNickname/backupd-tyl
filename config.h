/*****************************************************************************/
/*                                                                           */
/*                                 config.h                                  */
/*                                                                           */
/*                 Configuration parser for backupd-tyl                      */
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

#ifndef CONFIG_H
#define CONFIG_H

#include <stdio.h>
#include <syslog.h>

extern const char* configname;

typedef struct CfgSection {
    char* name;                 /* Section name, lowercase */
    char* user;
    char* group;
    char* password;             /* Command block shared password */
    char* write_cmd;            /* Full (possibly multiline) command */
    char* read_cmd;             /* Full (possibly multiline) command */
    char* lockfile;
    long  umask_val;
    int   has_umask;
    char* allow;                /* Local Allow overriding global */
    char* deny;                 /* Local Deny overriding global */
    struct CfgSection* next;
} CfgSection;

typedef struct {
    int   port;
    char* bind_address;
    int   log_facility;
    char* log_target;           /* "file", "syslog", "stderr" (default: file) */
    char* log_file;             /* Path to log file (default: /var/log/backupd-tyl.log) */
    int   log_level;            /* Log level threshold (default: TYL_LOG_WARN) */
    int   nodns;
    int   allow_legacy;
    char* default_cipher;
    char* password;             /* Global fallback password */
    char* allow;                /* Global fallback Allow */
    char* deny;                 /* Global fallback Deny */
    char* pid_file;
} CfgGlobal;

/* Global config access */
const CfgGlobal*  CfgGetGlobal (void);
const CfgSection* CfgGetSection (const char* section);
const CfgSection* CfgGetFirstSection (void);
int               CfgHaveSection (const char* section);

/* Section listing considering resource Allow/Deny with global inheritance */
unsigned long CfgListSectionsForClient (FILE* F, const char* client_name, unsigned long client_addr);

/* ACL evaluation: Allow takes precedence over Deny */
int get_host_match_specificity (const char* list_str, const char* client_name, unsigned long client_addr);
int check_client_acl (const char* allow_str, const char* deny_str, const char* client_name, unsigned long client_addr);
int host_in_list (const char* list_str, const char* client_name, unsigned long client_addr);

/* Legacy helper functions for backward compatibility */
int CfgGetInt (const char* Section, const char* Entry, long DefVal, long* Val);
int CfgGetStr (const char* Section, const char* Entry, const char* DefVal, char* Str, unsigned StrSize);
unsigned long CfgListSections (FILE* F);

int  CfgInit (void);
void CfgDone (void);

#endif /* CONFIG_H */
