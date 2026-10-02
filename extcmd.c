/*****************************************************************************/
/*                                                                           */
/*                                  extcmd.c                                 */
/*                                                                           */
/*                     Execution of external commands                        */
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
#include <stdarg.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <errno.h>
#include <paths.h>
#include <sys/wait.h>

#include "const.h"
#include "global.h"
#include "config.h"
#include "error.h"
#include "extcmd.h"



/*****************************************************************************/
/*     	       	   	  	     Data				     */
/*****************************************************************************/



/* File descriptor connected to the clients input/output */
FILE*  	clientio  = 0;

#ifdef _PATH_BSHELL
#  define SHELL	 	_PATH_BSHELL
#else
#  define SHELL	 	"/bin/sh"
#endif

#define	NULLDEV		"/dev/null"

/* PID of the child process */
static pid_t clientpid = -1;



/*****************************************************************************/
/*     	       	   	  	     Code	      			     */
/*****************************************************************************/



/*
 * dodup2: Safe wrapper around dup2() that avoids self-duplication if fd1 == fd2,
 * closes the original fd1 upon successful duplication, and aborts with an error
 * message on any failure.
 */
static void dodup2 (int fd1, int fd2)
{
    if (fd1 != fd2) {
	if (dup2 (fd1, fd2) != fd2) {
	    errexit ("dup2: %m(%d)", errno);
	}
	if (close (fd1) == -1) {
	    errexit ("close: %m(%d)", errno);
	}
    }
}



/*
 * connect0: Opens /dev/null and duplicates it onto the specified descriptor fd,
 * ensuring unused standard streams (stdin, stdout, or stderr) cannot leak or block.
 */
static void connect0 (int fd)
{
    int fd2 = open (NULLDEV, 0);
    if (fd2 == -1) {
	errexit ("Cannot open %s: %m(%d)", NULLDEV, errno);
    }
    dodup2 (fd2, fd);
}



/*
 * startcmd: Spawns an external command string under /bin/sh.
 *
 * Execution flow:
 * 1. Validates arguments: cmdline must be non-null; mode must be "r" (streaming child stdout
 *    to daemon/network) or "w" (streaming network data into child stdin).
 * 2. Allocates a unidirectional pipe(fd).
 * 3. Forks a child worker:
 *    - In parent: closes child end of pipe and wraps the parent end in a buffered FILE* stream.
 *    - In child: connects child pipe end to STDIN or STDOUT, redirects the opposite stream
 *      and STDERR to /dev/null, closes all file descriptors >= 3 to prevent file/socket descriptor
 *      leakage into child commands, and replaces the process image via execl(SHELL).
 */
void startcmd (const char* cmdline, const char* mode)
{
    int fd [2];

    /* Check the given arguments */
    if (!cmdline || !mode || (mode[0] != 'r' && mode[0] != 'w') || mode[1] != '\0') {
        errexit ("Invalid argument to startcmd");
    }

    /* Create a pipe */
    if (pipe (fd) != 0) {
 	errexit ("Error creating pipe: %m(%d)", errno);
    }

    /* Fork a child process */
    clientpid = fork ();
    if (clientpid == -1) {
 	/* Some sort of error occurred */
        errexit ("Cannot fork: %m(%d)", errno);
    }

    if (clientpid > 0) {

 	/* This is the father. Close the childs end of the pipe, and setup
         * a file stream for reading or writing.
         */
	if (mode [0] == 'r') {
    	    close (fd [1]);
            clientio = fdopen (fd [0], mode);
     	} else {
	    close (fd [0]);
	    clientio = fdopen (fd [1], mode);
	}

	/* Check for errors */
       	if (clientio == 0) {
	    /* Some sort of error */
	    errexit ("Error setting up client pipe: %m(%d)", errno);
	}

    } else {

     	/* This is the son. Close the fathers end of the pipe and create
         * file descriptors for stdin or stdout. Connect the unused channel
     	 * and stderr to /dev/null.
         */
       	if (mode [0] == 'r') {

     	    /* Close the remote side of the pipe */
     	    close (fd [0]);

     	    /* Open /dev/null and make it stdin of the process */
	    connect0 (STDIN_FILENO);

     	    /* Connect the pipe to stdout */
	    dodup2 (fd [1], STDOUT_FILENO);

       	} else {

	    /* Close the remote side of the pipe */
     	    close (fd [1]);

	    /* Connect the pipe to stdin */
	    dodup2 (fd [0], STDIN_FILENO);

	    /* Open /dev/null and make it stdout of the process */
	    connect0 (STDOUT_FILENO);

     	}

	/* Connect stderr to /dev/null */
	connect0 (STDERR_FILENO);

	/* Close all open file descriptors >= 3 so child does not inherit daemon sockets/logs */
	int maxfd = (int)sysconf (_SC_OPEN_MAX);
	if (maxfd < 0 || maxfd > 65536) maxfd = 1024;
	for (int i = 3; i < maxfd; ++i) {
	    close (i);
	}

     	/* Execute the shell with the given command */
     	execl (SHELL, "sh", "-c", cmdline, (char*) 0);

       	/* If we reach this point, something went wrong. Mimic the
     	 * behaviour of popen and exit with return code 127 ("could not
     	 * execute shell"). Use _exit since we don't want to flush the
	 * output buffers.
     	 */
     	_exit (127);

    }
}



/*
 * endcmd: Flushes and closes the stream pipe to the child process and awaits
 * process termination via waitpid(). Returns the process exit status (0 on success,
 * or 128 + signal number if terminated by an unhandled signal).
 */
int endcmd (void) {
    int stat = 0;
    if (clientio) {
        if (fclose (clientio) == EOF) {
            error ("Error closing client pipe: %m(%d)", errno);
            clientio = NULL;
            return -1;
        }
        clientio = NULL;
    }
    while (waitpid (clientpid, &stat, 0) < 0) {
        if (errno == ECHILD) {
            return 0;
        }
        if (errno != EINTR) {
            return -1;
        }
    }
    if (WIFEXITED(stat)) {
        return WEXITSTATUS(stat);
    } else if (WIFSIGNALED(stat)) {
        return 128 + WTERMSIG(stat);
    }
    return stat;
}



