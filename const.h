/*****************************************************************************/
/*                                                                           */
/*                                  const.h                                  */
/*                                                                           */
/*                     Universal constants for backupd-tyl                   */
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



#ifndef CONST_H
#define CONST_H



/*****************************************************************************/
/*				   Constants				     */
/*****************************************************************************/



/* Somes values for returning success and failure from functions. Use this
 * values instead of 0/1, -1/0 or similar. The values are designed to be
 * interchangeable, so you may use whatever fits best in the given context.
 * It is explicitly allowed to test a function result stated as SUCCESS/FAILURE
 * against OK, if this is more readable in the given situation.
 */
#define SUCCESS		1
#define FAILURE		0

#define TRUE		1
#define FALSE		0

#define OK		1
#define ERROR		0

#define YES		1
#define NO		0



/* End of CONST.H */

#endif
