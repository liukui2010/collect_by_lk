/****************************************************************************
 * 
 * rttmem.h
 * 
 * Header file for memory allocation module.
 * 
 ***************************************************************************
 * 
 * This code is Copyright 1994, 1995, 1996 by the Department of Computer
 * Science, University of British Columbia, British Columbia, Canada.
 * 
 * No part of of this code may be sold or used for any commercial purposes
 * without the expressed written permission of the University of
 * British Columbia.
 * 
 * RT Threads may be freely used, copied, modified, or distributed for
 * noncommercial purposes, provided that this copyright notice is
 * included in all sources.
 * 
 * RT Threads is provided as is.  The UBC Department of Computer Science
 * makes no warranty as to the correctness or fitness for use of the
 * RT Threads code or environment.
 * 
 ***************************************************************************
 */

#ifndef RTTMEM_H
#define RTTMEM_H

void *SysMalloc_(int);
void SysFree_(void *);

#ifdef RTT_MEM_DEBUG
void *SysDebugMalloc_(int, char *, int);
void SysDebugFree_(void *, char *, int);
#define SysMalloc_(X) SysDebugMalloc_(X,__FILE__,__LINE__)
#define SysFree_(X) SysDebugFree_(X,__FILE__,__LINE__)
#endif

#endif /* RTTMEM_H */

