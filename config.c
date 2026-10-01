/*****************************************************************************/
/*                                                                           */
/*                                 config.c                                  */
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fnmatch.h>
#include <syslog.h>
#include <errno.h>

#include "const.h"
#include "proto.h"
#include "config.h"
#include "error.h"
#include "util.h"

const char* configname = "/etc/backupd.conf";

static CfgGlobal   global_cfg;
static CfgSection* section_list = NULL;

static void free_section (CfgSection* s) {
    if (!s) return;
    free (s->name);
    free (s->user);
    free (s->group);
    free (s->password);
    free (s->write_cmd);
    free (s->read_cmd);
    free (s->lockfile);
    free (s->allow);
    free (s->deny);
    free (s->list_allow);
    free (s->list_deny);
    free (s);
}

void CfgDone (void) {
    CfgSection* cur = section_list;
    while (cur) {
        CfgSection* next = cur->next;
        free_section (cur);
        cur = next;
    }
    section_list = NULL;

    free (global_cfg.bind_address);
    free (global_cfg.default_cipher);
    free (global_cfg.password);
    free (global_cfg.allow);
    free (global_cfg.deny);
    free (global_cfg.list_allow);
    free (global_cfg.list_deny);
    free (global_cfg.pid_file);
    free (global_cfg.log_target);
    free (global_cfg.log_file);
    memset (&global_cfg, 0, sizeof(global_cfg));
}

const CfgGlobal* CfgGetGlobal (void) {
    return &global_cfg;
}

const CfgSection* CfgGetSection (const char* section) {
    if (!section) return NULL;
    CfgSection* cur = section_list;
    while (cur) {
        if (strcasecmp (cur->name, section) == 0) {
            return cur;
        }
        cur = cur->next;
    }
    return NULL;
}

const CfgSection* CfgGetFirstSection (void) {
    return section_list;
}

int CfgHaveSection (const char* section) {
    return (CfgGetSection (section) != NULL) ? YES : NO;
}

static CfgSection* get_or_create_section (const char* name) {
    CfgSection* cur = section_list;
    while (cur) {
        if (strcasecmp (cur->name, name) == 0) {
            return cur;
        }
        cur = cur->next;
    }

    CfgSection* s = (CfgSection*) calloc (1, sizeof(CfgSection));
    if (!s) return NULL;
    s->name = strdup (name);
    s->umask_val = 0077;
    s->has_umask = 0;

    /* Append to list */
    if (!section_list) {
        section_list = s;
    } else {
        CfgSection* p = section_list;
        while (p->next) p = p->next;
        p->next = s;
    }
    return s;
}

static void append_str (char** dest, const char* str) {
    if (!dest || !str) return;
    if (!*dest) {
        *dest = strdup (str);
    } else {
        size_t len1 = strlen (*dest);
        size_t len2 = strlen (str);
        char* n = (char*) realloc (*dest, len1 + len2 + 2);
        if (n) {
            n[len1] = '\n';
            memcpy (n + len1 + 1, str, len2 + 1);
            *dest = n;
        }
    }
}

static char* extract_val (char* val_str) {
    trim_whitespace (val_str);
    size_t len = strlen (val_str);
    if (len >= 2 && val_str[0] == '"' && val_str[len - 1] == '"') {
        val_str[len - 1] = '\0';
        return val_str + 1;
    }
    return val_str;
}

static int parse_facility (const char* str) {
    if (!str || !*str) return LOG_DAEMON;
    if (isdigit ((unsigned char)*str)) return atoi (str);
    if (strcasecmp (str, "daemon") == 0) return LOG_DAEMON;
    if (strcasecmp (str, "local0") == 0) return LOG_LOCAL0;
    if (strcasecmp (str, "local1") == 0) return LOG_LOCAL1;
    if (strcasecmp (str, "local2") == 0) return LOG_LOCAL2;
    if (strcasecmp (str, "local3") == 0) return LOG_LOCAL3;
    if (strcasecmp (str, "local4") == 0) return LOG_LOCAL4;
    if (strcasecmp (str, "local5") == 0) return LOG_LOCAL5;
    if (strcasecmp (str, "local6") == 0) return LOG_LOCAL6;
    if (strcasecmp (str, "local7") == 0) return LOG_LOCAL7;
    if (strcasecmp (str, "auth") == 0) return LOG_AUTH;
    if (strcasecmp (str, "authpriv") == 0) return LOG_AUTHPRIV;
    if (strcasecmp (str, "user") == 0) return LOG_USER;
    return LOG_DAEMON;
}

static int parse_log_level (const char* str) {
    if (!str || !*str) return TYL_LOG_INFO;
    if (isdigit ((unsigned char)*str)) return atoi (str);
    if (strcasecmp (str, "debug") == 0) return TYL_LOG_DEBUG;
    if (strcasecmp (str, "info") == 0) return TYL_LOG_INFO;
    if (strcasecmp (str, "notice") == 0) return TYL_LOG_NOTICE;
    if (strcasecmp (str, "warn") == 0 || strcasecmp (str, "warning") == 0) return TYL_LOG_WARN;
    if (strcasecmp (str, "err") == 0 || strcasecmp (str, "error") == 0) return TYL_LOG_ERR;
    return TYL_LOG_INFO;
}

int host_in_list (const char* list_str, const char* client_name, unsigned long client_addr) {
    if (!list_str || list_str[0] == '\0') return NO;
    char* buf = strdup (list_str);
    if (!buf) return NO;

    int match = NO;
    char* saveptr = NULL;
    char* tok = strtok_r (buf, " \t,", &saveptr);
    while (tok) {
        if (isdigit ((unsigned char)tok[0])) {
            unsigned q1 = 0, q2 = 0, q3 = 0, q4 = 0, bits = 32;
            int n = sscanf (tok, "%u.%u.%u.%u/%u", &q1, &q2, &q3, &q4, &bits);
            if (n >= 4 && q1 <= 255 && q2 <= 255 && q3 <= 255 && q4 <= 255 && bits <= 32) {
                unsigned long ip = ((unsigned long)q1 << 24) |
                                   ((unsigned long)q2 << 16) |
                                   ((unsigned long)q3 << 8)  |
                                   ((unsigned long)q4);
                unsigned long mask = (bits == 0) ? 0 : (~0UL << (32 - bits));
                if ((ip & mask) == (client_addr & mask)) {
                    match = YES;
                    break;
                }
            }
        } else {
            if (client_name && fnmatch (tok, client_name, 0) == 0) {
                match = YES;
                break;
            }
        }
        tok = strtok_r (NULL, " \t,", &saveptr);
    }
    free (buf);
    return match;
}

unsigned long CfgListSectionsForClient (FILE* F, const char* client_name, unsigned long client_addr) {
    unsigned long bytes = 0;
    CfgSection* s = section_list;

    while (s) {
        /*
         * Effective Allow for listing: local list_allow -> global list_allow -> local allow -> global allow
         * Effective Deny for listing:  local list_deny  -> global list_deny  -> (if list_allow specified, NULL; else local deny -> global deny)
         */
        const char* eff_allow = NULL;
        if (s->list_allow)              eff_allow = s->list_allow;
        else if (global_cfg.list_allow) eff_allow = global_cfg.list_allow;
        else if (s->allow)              eff_allow = s->allow;
        else if (global_cfg.allow)      eff_allow = global_cfg.allow;

        const char* eff_deny = NULL;
        if (s->list_deny)               eff_deny = s->list_deny;
        else if (global_cfg.list_deny)  eff_deny = global_cfg.list_deny;
        else if (s->list_allow || global_cfg.list_allow) eff_deny = NULL;
        else if (s->deny)               eff_deny = s->deny;
        else if (global_cfg.deny)       eff_deny = global_cfg.deny;

        int allowed = YES;
        if (eff_allow && !host_in_list (eff_allow, client_name, client_addr)) {
            allowed = NO;
        }
        if (eff_deny && host_in_list (eff_deny, client_name, client_addr)) {
            allowed = NO;
        }

        if (allowed) {
            int n = fprintf (F, "-%s\n", s->name);
            if (n > 0) bytes += (unsigned long)n;
        }
        s = s->next;
    }
    return bytes;
}

unsigned long CfgListSections (FILE* F) {
    return CfgListSectionsForClient (F, NULL, 0);
}

int CfgInit (void) {
    CfgDone ();

    /* Default global settings */
    global_cfg.port = DEFAULTPORT;
    global_cfg.bind_address = strdup ("0.0.0.0");
    global_cfg.log_facility = LOG_DAEMON;
    global_cfg.log_target = strdup ("file");
    global_cfg.log_file = strdup ("/var/log/backupd-tyl.log");
    global_cfg.log_level = TYL_LOG_WARN;
    global_cfg.nodns = 0;
    global_cfg.allow_legacy = 1; /* Default allow legacy clients with warning */
    global_cfg.default_cipher = strdup ("ascon128a");
    global_cfg.pid_file = strdup ("/var/run/backupd-tyl.pid");
    global_cfg.allow = NULL;
    global_cfg.deny = NULL;

    FILE* fp = fopen (configname, "r");
    if (!fp) {
        syslog (LOG_ERR, "Could not open config file \"%s\": %m", configname);
        return FAILURE;
    }

    char line[4096];
    CfgSection* current_sec = NULL;
    char** multiline_dest = NULL; /* points to &current_sec->write_cmd or &read_cmd */

    while (fgets (line, sizeof(line), fp) != NULL) {
        trim_whitespace (line);

        /* Check for multiline block end */
        if (multiline_dest != NULL) {
            if (strcmp (line, "}") == 0) {
                multiline_dest = NULL;
                continue;
            }
            append_str (multiline_dest, line);
            continue;
        }

        /* Skip comments and empty lines */
        if (line[0] == '\0' || line[0] == '#' || line[0] == ';') {
            continue;
        }

        /* Check for section header */
        if (line[0] == '[') {
            char* end = strchr (line, ']');
            if (end) {
                *end = '\0';
                char* sec_name = line + 1;
                trim_whitespace (sec_name);
                current_sec = get_or_create_section (sec_name);
                continue;
            }
        }

        /* Key = Value */
        char* eq = strchr (line, '=');
        if (!eq) continue;

        *eq = '\0';
        char* key = line;
        char* val = eq + 1;
        trim_whitespace (key);
        trim_whitespace (val);

        /* Check for line continuation with backslash */
        size_t vlen = strlen (val);
        while (vlen > 0 && val[vlen - 1] == '\\') {
            val[vlen - 1] = '\0';
            char next_line[1024];
            if (fgets (next_line, sizeof(next_line), fp) == NULL) break;
            trim_whitespace (next_line);

            size_t used = (size_t)(val - line) + strlen (val);
            if (used + 2 < sizeof (line)) {
                strcat (val, " ");
                used++;
                size_t avail = sizeof (line) - used - 1;
                strncat (val, next_line, avail);
            }
            vlen = strlen (val);
        }

        /* Check for block start: key = { */
        if (strcmp (val, "{") == 0) {
            if (current_sec) {
                if (strcasecmp (key, "write") == 0) {
                    multiline_dest = &current_sec->write_cmd;
                } else if (strcasecmp (key, "read") == 0) {
                    multiline_dest = &current_sec->read_cmd;
                }
            }
            continue;
        }

        char* clean_val = extract_val (val);

        if (current_sec == NULL) {
            /* Global options */
            if (strcasecmp (key, "port") == 0) {
                global_cfg.port = atoi (clean_val);
            } else if (strcasecmp (key, "bindaddress") == 0 || strcasecmp (key, "bind_address") == 0) {
                free (global_cfg.bind_address);
                global_cfg.bind_address = strdup (clean_val);
            } else if (strcasecmp (key, "logfacility") == 0 || strcasecmp (key, "log_facility") == 0) {
                global_cfg.log_facility = parse_facility (clean_val);
            } else if (strcasecmp (key, "logtarget") == 0 || strcasecmp (key, "log_target") == 0) {
                free (global_cfg.log_target);
                global_cfg.log_target = strdup (clean_val);
            } else if (strcasecmp (key, "logfile") == 0 || strcasecmp (key, "log_file") == 0) {
                free (global_cfg.log_file);
                global_cfg.log_file = strdup (clean_val);
                if (!global_cfg.log_target || strcasecmp (global_cfg.log_target, "syslog") == 0) {
                    free (global_cfg.log_target);
                    global_cfg.log_target = strdup ("file");
                }
            } else if (strcasecmp (key, "loglevel") == 0 || strcasecmp (key, "log_level") == 0) {
                global_cfg.log_level = parse_log_level (clean_val);
            } else if (strcasecmp (key, "nodns") == 0) {
                global_cfg.nodns = atoi (clean_val);
            } else if (strcasecmp (key, "allowlegacy") == 0 || strcasecmp (key, "allow_legacy") == 0) {
                global_cfg.allow_legacy = (strcasecmp (clean_val, "yes") == 0 || atoi(clean_val) != 0);
            } else if (strcasecmp (key, "defaultcipher") == 0 || strcasecmp (key, "default_cipher") == 0) {
                free (global_cfg.default_cipher);
                global_cfg.default_cipher = strdup (clean_val);
            } else if (strcasecmp (key, "password") == 0 || strcasecmp (key, "secret") == 0) {
                free (global_cfg.password);
                global_cfg.password = strdup (clean_val);
            } else if (strcasecmp (key, "allow") == 0) {
                free (global_cfg.allow);
                global_cfg.allow = strdup (clean_val);
            } else if (strcasecmp (key, "deny") == 0) {
                free (global_cfg.deny);
                global_cfg.deny = strdup (clean_val);
            } else if (strcasecmp (key, "listallow") == 0 || strcasecmp (key, "list_allow") == 0) {
                free (global_cfg.list_allow);
                global_cfg.list_allow = strdup (clean_val);
            } else if (strcasecmp (key, "listdeny") == 0 || strcasecmp (key, "list_deny") == 0) {
                free (global_cfg.list_deny);
                global_cfg.list_deny = strdup (clean_val);
            } else if (strcasecmp (key, "pidfile") == 0 || strcasecmp (key, "pid_file") == 0) {
                free (global_cfg.pid_file);
                global_cfg.pid_file = strdup (clean_val);
            }
        } else {
            /* Resource section options */
            if (strcasecmp (key, "user") == 0) {
                free (current_sec->user);
                current_sec->user = strdup (clean_val);
            } else if (strcasecmp (key, "group") == 0) {
                free (current_sec->group);
                current_sec->group = strdup (clean_val);
            } else if (strcasecmp (key, "password") == 0 || strcasecmp (key, "secret") == 0 || strcasecmp (key, "auth") == 0) {
                free (current_sec->password);
                current_sec->password = strdup (clean_val);
            } else if (strcasecmp (key, "write") == 0) {
                append_str (&current_sec->write_cmd, clean_val);
            } else if (strcasecmp (key, "read") == 0) {
                append_str (&current_sec->read_cmd, clean_val);
            } else if (strcasecmp (key, "lockfile") == 0) {
                free (current_sec->lockfile);
                current_sec->lockfile = strdup (clean_val);
            } else if (strcasecmp (key, "umask") == 0) {
                current_sec->umask_val = strtol (clean_val, NULL, 0);
                current_sec->has_umask = 1;
            } else if (strcasecmp (key, "allow") == 0) {
                free (current_sec->allow);
                current_sec->allow = strdup (clean_val);
            } else if (strcasecmp (key, "deny") == 0) {
                free (current_sec->deny);
                current_sec->deny = strdup (clean_val);
            } else if (strcasecmp (key, "listallow") == 0) {
                free (current_sec->list_allow);
                current_sec->list_allow = strdup (clean_val);
            } else if (strcasecmp (key, "listdeny") == 0) {
                free (current_sec->list_deny);
                current_sec->list_deny = strdup (clean_val);
            }
        }
    }

    fclose (fp);
    return SUCCESS;
}

int CfgGetInt (const char* Section, const char* Entry, long DefVal, long* Val) {
    if (!Val) return FAILURE;
    *Val = DefVal;
    if (!Section || Section[0] == '\0') {
        if (strcasecmp (Entry, "nodns") == 0) {
            *Val = global_cfg.nodns;
            return SUCCESS;
        } else if (strcasecmp (Entry, "logfacility") == 0) {
            *Val = global_cfg.log_facility;
            return SUCCESS;
        } else if (strcasecmp (Entry, "port") == 0) {
            *Val = global_cfg.port;
            return SUCCESS;
        }
    } else {
        const CfgSection* s = CfgGetSection (Section);
        if (s && strcasecmp (Entry, "umask") == 0 && s->has_umask) {
            *Val = s->umask_val;
            return SUCCESS;
        }
    }
    return FAILURE;
}

int CfgGetStr (const char* Section, const char* Entry, const char* DefVal, char* Str, unsigned StrSize) {
    if (!Str || StrSize == 0) return FAILURE;
    if (DefVal) {
        StrNCopy (Str, DefVal, StrSize);
    } else {
        Str[0] = '\0';
    }

    if (!Section || Section[0] == '\0') {
        if (strcasecmp (Entry, "allow") == 0 && global_cfg.allow) {
            StrNCopy (Str, global_cfg.allow, StrSize);
            return SUCCESS;
        } else if (strcasecmp (Entry, "deny") == 0 && global_cfg.deny) {
            StrNCopy (Str, global_cfg.deny, StrSize);
            return SUCCESS;
        } else if (strcasecmp (Entry, "listallow") == 0 && global_cfg.list_allow) {
            StrNCopy (Str, global_cfg.list_allow, StrSize);
            return SUCCESS;
        } else if (strcasecmp (Entry, "listdeny") == 0 && global_cfg.list_deny) {
            StrNCopy (Str, global_cfg.list_deny, StrSize);
            return SUCCESS;
        } else if (strcasecmp (Entry, "password") == 0 && global_cfg.password) {
            StrNCopy (Str, global_cfg.password, StrSize);
            return SUCCESS;
        }
    } else {
        const CfgSection* s = CfgGetSection (Section);
        if (s) {
            const char* val = NULL;
            if (strcasecmp (Entry, "user") == 0) val = s->user;
            else if (strcasecmp (Entry, "group") == 0) val = s->group;
            else if (strcasecmp (Entry, "password") == 0) val = s->password;
            else if (strcasecmp (Entry, "write") == 0) val = s->write_cmd;
            else if (strcasecmp (Entry, "read") == 0) val = s->read_cmd;
            else if (strcasecmp (Entry, "lockfile") == 0) val = s->lockfile;
            else if (strcasecmp (Entry, "allow") == 0) val = s->allow;
            else if (strcasecmp (Entry, "deny") == 0) val = s->deny;
            else if (strcasecmp (Entry, "listallow") == 0) val = s->list_allow ? s->list_allow : global_cfg.list_allow;
            else if (strcasecmp (Entry, "listdeny") == 0) val = s->list_deny ? s->list_deny : global_cfg.list_deny;

            if (val) {
                StrNCopy (Str, val, StrSize);
                return SUCCESS;
            }
        }
    }
    return FAILURE;
}
