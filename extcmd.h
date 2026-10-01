/*****************************************************************************/
/*                                                                           */
/*                                  extcmd.h                                 */
/*                                                                           */
/*                     External command execution headers                    */
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



#ifndef EXTCMD_H
#define EXTCMD_H



#include <stdio.h>



/*****************************************************************************/
/*     	       	   	  	     Data				     */
/*****************************************************************************/



/* File descriptor connected to the clients input/output */
extern FILE* clientio;



/*****************************************************************************/
/*     	       	   	  	     Code	      			     */
/*****************************************************************************/



void startcmd (const char* cmdline, const char* mode);
/* Start an external command with the given command line. The child will have
 * it's standard input or ouput connected to clientio.
 */

int endcmd (void);				      
/* Close the pipes to the child process and wait for it's termination. */



/* End of extcmd.h */

#endif



