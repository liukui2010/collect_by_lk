/****************************************************************************
 * 
 * rttthreadmgmt.h
 * 
 * Header file for thread management module.
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

#ifndef RTTTHREADMGMT_H
#define RTTTHREADMGMT_H

#define TCBINRANGE(X) ( ((X) >= &(TCBTBL[0])) && \
		       ((X) <= &(TCBTBL[NUMBTCBS-1])) )

#define ThreadExists(X) ( TCBINRANGE(X) && GetInUse(X) )

#ifdef m88k
#define STACK_ALIGNMENT 8
#elif ibm
#define STACK_ALIGNMENT 16
#else  
#define STACK_ALIGNMENT 4
#endif

#ifdef hp700
#define STACKBOT(X) (GetStmembeg(X) + 8) /* adds 32 bytes to sp */
#else
#define STACKBOT(X) ((int *) (((int)GetStkend(X)) & ~(STACK_ALIGNMENT - 1))) 
#endif

#define SETUPTHREADMGMT( TD, ATTR, STKSIZE, ADDR, ARG )  \
    {                                                                   \
    SetStart(TD, ATTR.startingtime);                                    \
    SetPrio(TD, ATTR.priority);                                         \
    SetDeadline(TD, ATTR.deadline);                                     \
    SetState(TD, THREAD_READY);                                         \
    SetStkend(TD, GetStmembeg(TD) + (STKSIZE >> 2) );                   \
    SetSp(TD, STACKBOT(TD));                                            \
    SetThreadAddr(TD, ADDR);                                            \
    SetThreadArg(TD, ARG);                                              \
    }

extern TCB *currthread;         /* thread currently running            */
extern TCB *prevthread;         /* thread previously running           */
extern TCB *NullThread_Proc;	/* NullThread TCB structure	       */

#ifdef RTTEXITDEBUG
#define SysExit_(X) {                                                   \
          printf("exiting RT Threads at %s:%d\n", __FILE__, __LINE__);  \
          exit(X);                                                      \
	}
#else
#define SysExit_(X) exit(X)
#endif /* RTTEXITDEBUG */

void CallNclean_();
void InitThreadMgmt_();
void CallExitRoutines_();

#endif /* RTTTHREADMGMT_H */
