/****************************************************************************
 * 
 * rttsched.h
 * 
 * Header file for scheduling module.
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

#ifndef RTTSCHED_H
#define RTTSCHED_H

extern short inOsFlag;  /* falg used to protect shares data structures */

#define INOSCTXT    inOsFlag
#if 0
#define ENTERINGOS  {RttTrace2("ENTERINGOS: %s:%d\n", (int)__FILE__, __LINE__);enteringOs();}
#define LEAVINGOS   {RttTrace2("LEAVINGOS:  %s:%d\n", (int)__FILE__, __LINE__);leavingOs();}
#else
#define ENTERINGOS  enteringOs()
#define LEAVINGOS   leavingOs()
#endif

#ifdef NATIVE_THREADS
extern short inIoFlag;
#define INIOCTXT    inIoFlag
#define ENTERINGIO  {inIoFlag = 1;}
#define LEAVINGIO   {inIoFlag = 0;}
#endif /* NATIVE_THREADS */

#define USE_SCHEDMACRO

#ifdef WIN32
#define SchedM Sched_(__FILE__, __LINE__)
#else
#ifndef USE_SCHEDMACRO
#define SchedM Sched_()
#else
#define SchedM {                                             \
    if ((GetState(currthread) == THREAD_READY) || (GetState(currthread) == THREAD_RUNNING)) {                                               \
      TCB *newthread;                                        \
      if ((newthread = DeqIfReady_()) != currthread) {       \
	if( saveThreadContext(GetSavearea( currthread )) ) { \
          prevthread = currthread;			     \
          currthread = newthread;                            \
          SchedThread_();                                    \
        }                                                    \
        else {                                               \
          LEAVINGOS; /* back in user thread */               \
        }                                                    \
      }                                                      \
      else {                                                 \
        LEAVINGOS;                                           \
      }                                                      \
    }                                                        \
    else  {                                                  \
      if ( GetState(currthread) == SLEP) {} else             \
     {                                                       \
       ENQUEUE_HEAD(QTBL[GetState(currthread)],currthread,TCB,queueMgmtInfo,GetState(currthread) ); \
     }                                                       \
     if( saveThreadContext(GetSavearea( currthread )) ) {    \
       prevthread = currthread;				     \
       currthread = DeqReadyThread_();                       \
       SchedThread_();                                       \
     }                                                       \
     else                                                    \
       LEAVINGOS; /* back in user thread */                  \
     }                                                       \
  }
#endif /* USE_SCHEDMACRO */
#endif /* WIN32 */

#define SETUPSCHED(X, Q) {            \
  SetNew( X, 1 );                     \
}

void SigMask_(int, int);

void StartOs_();
void SchedThread_();
void StartClock_(int);
void enteringOs();
void leavingOs();

#endif /* RTTSCHED_H */
