/****************************************************************************
 * 
 * rttattr.c
 * 
 * Scheduling attributes module.
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

#include <stdarg.h>
#ifdef WIN32
#include <sys/timeb.h>
#endif /* WIN32 */
#include "rttkernel.h"

static void resetTimeout(TCB *);

/*------------------------------------------------------------------------
 * resetTimeout  --  take a thread off the sleep queue and change its 
 *                   state accordingly
 *
 * Notes:            assumes that thread is in the sleep queue
 *------------------------------------------------------------------------
 */
static void resetTimeout(TCB *thread)
{
  DEQUEUE_ITEM(QTBL[SLEP], thread, TCB, queueMgmtInfo);

  SetState(thread,THREAD_READY);
  SetStart(thread,RTTZEROTIME);
}

/*------------------------------------------------------------------------
 * SetTimeout_  --  place thread on a time-ordered sleep queue
 *------------------------------------------------------------------------
 */
int SetTimeout_(TCB *thread, RttTimeValue wakeTime)
{
  TCB *next_thread;
  RttTimeValue now;
  int rcode;

  SetState(thread,SLEP);
  SetStart(thread,wakeTime);

  if ((next_thread = QUEUE_FIRST(QTBL[SLEP])) == TNULL ||
      CompTime_(GetStart(next_thread), wakeTime, >) ) {
    ENQUEUE_HEAD(QTBL[SLEP], thread, TCB, queueMgmtInfo,SLEP);
  }
  else {
    for (next_thread = QUEUE_NEXT(next_thread, queueMgmtInfo);
	 next_thread != TNULL;
	 next_thread = QUEUE_NEXT(next_thread, queueMgmtInfo)) {
      if (CompTime_(GetStart(next_thread), wakeTime, >)) {
	ENQUEUE_ITEM(thread, next_thread, TCB, queueMgmtInfo,SLEP);
	break;
      }
    }

    if (next_thread == TNULL) {
      ENQUEUE_TAIL(QTBL[SLEP], thread, TCB, queueMgmtInfo,SLEP);
    }
  }
  
  return (RTTOK);
}

/*------------------------------------------------------------------------
 * RttSetThreadSchedAttr  --  change attributes of a thread, rescheduling
 *                            immediately if required
 *------------------------------------------------------------------------
 */
int RttSetThreadSchedAttr(RttThreadId thread, RttSchAttr attr)
{
  RttTimeValue 	now;
  int i;
  TCB *tcbPtr;

  tcbPtr = getTcbFromThreadId(thread);

  if (!TCBINRANGE(tcbPtr)) {
    return (RTTNOSUCHTHREAD);
  }

  if ((attr.priority < 0) || (attr.priority >=  NULP))
  {
    return(RTTFAILED);
  }

  ENTERINGOS;
/*
  RttTrace1("RttSetThreadSchedAttr(%s, ", (int)GetTname(tcbPtr));
  RttTrace10("st %u.%u --> %u.%u, pr %d --> %d, dl %u.%u --> %u.%u\n", 
	     GetStart(tcbPtr).seconds, GetStart(tcbPtr).microseconds, 
	     attr.startingtime.seconds, attr.startingtime.microseconds, 
	     GetPrio(tcbPtr), attr.priority, 
	     GetDeadline(tcbPtr).seconds, GetDeadline(tcbPtr).microseconds, 
	     attr.deadline.seconds, attr.deadline.microseconds);
*/
  if (GetState(tcbPtr) == SLEP) {
    resetTimeout(tcbPtr);
  }
  else if (GetState(tcbPtr) == THREAD_READY) {
    DeleteReadyThread_(tcbPtr);
  }

  RttGetTimeOfDay(&now);
  
  /*
   * If the starting time is past, the thread should be made ready
   * to run now if it is not blocked.
   */
  if (!CompTime_(attr.startingtime, now, >)) {
    /*
     * Avoid a call to SchedThread_() if no CSW is expected.
     */
    if (tcbPtr == currthread) {
/*#ifdef NATIVE_THREADS*/
#if 1
      SetStart(tcbPtr,attr.startingtime);	      
      SetPrio(tcbPtr,attr.priority);
      SetDeadline(tcbPtr,attr.deadline);

      SchedM;
#else
      if (((GetPrio(tcbPtr) > attr.priority) ||
	   ((GetPrio(tcbPtr) == attr.priority) 
	    && !CompTime_(GetDeadline(tcbPtr), attr.deadline, <)))) 
	{
	  SetStart(tcbPtr,attr.startingtime);	      
	  SetPrio(tcbPtr,attr.priority);
	  SetDeadline(tcbPtr,attr.deadline);
	  LEAVINGOS;
	  return (RTTOK);
	}

      /* put the running thread back on the ready queue */
      else if(saveThreadContext(GetSavearea(tcbPtr))) {
	SetStart(tcbPtr,attr.startingtime);	      
	SetPrio(tcbPtr,attr.priority);
	SetDeadline(tcbPtr,attr.deadline);
	  
	EnqueueEdfTail_(tcbPtr);
	SetState(tcbPtr,THREAD_READY);
	prevthread = currthread;
	currthread = DeqReadyThread_();
	SchedThread_();
      }
      else LEAVINGOS;
#endif /* NATIVE_THREADS */
      return (RTTOK);
    }
    
    SetStart(tcbPtr,attr.startingtime);
    SetPrio(tcbPtr,attr.priority);
    SetDeadline(tcbPtr,attr.deadline);
    
    if (GetState(tcbPtr) == THREAD_READY) {
      EnqueueEdfTail_(tcbPtr);
    }
    else {
      LEAVINGOS;
      return (RTTOK);
    }
    
    SchedM;                        /* implicitly makes call to LEAVINGOS */

    return (RTTOK);
  }


  /* 
   * Starting time is in the future.
   */
#ifndef WIN32
  SetStart(tcbPtr,attr.startingtime);
#endif /* WIN32 */
  SetPrio(tcbPtr,attr.priority);
  SetDeadline(tcbPtr,attr.deadline);
  
  if (tcbPtr == currthread) {
    SetTimeout_(tcbPtr, attr.startingtime);
    SchedM; 
    return (RTTOK);
  }
  else if (GetState(tcbPtr) == THREAD_READY) {
    SetTimeout_( tcbPtr, attr.startingtime );
  }
  else {	
    SetStart(tcbPtr, attr.startingtime); 
  }
  
  LEAVINGOS;
  
  return (RTTOK);
}

/*------------------------------------------------------------------------
 * RttGetThreadSchedAttr  --  return attributes    
 *------------------------------------------------------------------------
 */
int RttGetThreadSchedAttr(RttThreadId thread, RttSchAttr *attr)
{
  TCB *tcbPtr;
  
  tcbPtr = getTcbFromThreadId(thread);
  
  if (!TCBINRANGE(tcbPtr)) {
    return (RTTNOSUCHTHREAD);
  }

  attr->priority = GetPrio(tcbPtr);
  attr->deadline = GetDeadline(tcbPtr);
  attr->startingtime = GetStart(tcbPtr);   
  return (RTTOK);
}

/*------------------------------------------------------------------------
 * RttGetTimeOfDay  --  return current time value
 *
 * Notes:               wrapper for gettimeofday UNIX system call
 *------------------------------------------------------------------------
 */
#ifdef WIN32
static RttTimeValue startTime;

static double frequency;
static DWORD highPartStart;
static DWORD lowPartStart;
static DWORD secondsPerHighPart;
static double microsecondsPerHighPart;

static DWORD startMilliseconds;

void InitTimeOfDay_()
{
  LARGE_INTEGER freq, count;
  DWORD remainder;
  struct _timeb timebuf;
  
  startMilliseconds = timeGetTime();
  QueryPerformanceCounter(&count);
  _ftime(&timebuf);
  startTime.seconds = timebuf.time;
  startTime.microseconds = timebuf.millitm*1000;

  QueryPerformanceFrequency(&freq);
  frequency = freq.LowPart;
  
  lowPartStart = count.LowPart;
  highPartStart = count.HighPart;
  remainder = 0xffffffff%freq.LowPart;
  secondsPerHighPart = 
    (0xffffffff/freq.LowPart) + (remainder == (freq.LowPart - 1));
  microsecondsPerHighPart = 
    (double)((remainder+1)%freq.LowPart)/frequency*1000000.0;
}

int RttFtime(RttTimeValue *tp)
{
  struct _timeb timebuf;

  _ftime(&timebuf);
  tp->seconds = timebuf.time;
  tp->microseconds = timebuf.millitm*1000;

  return (RTTOK);
}

int RttPerfTimeOfDay(RttTimeValue *tp)
{
  LARGE_INTEGER count;
  DWORD highPart, micros;

  QueryPerformanceCounter(&count);
  micros = ((double)(count.LowPart-lowPartStart))*1000000.0/frequency;
  highPart = count.HighPart-highPartStart;
  tp->microseconds = 
    startTime.microseconds + micros + (microsecondsPerHighPart*highPart);
  tp->seconds = 
    startTime.seconds 
      + (secondsPerHighPart*highPart) + (tp->microseconds/1000000);
  tp->microseconds %= 1000000;

  return (RTTOK);
}

int RttGetTimeOfDay(RttTimeValue *tp)
{
  DWORD millis, secs;

  millis = timeGetTime() - startMilliseconds;
  secs = millis / 1000;
  millis %= 1000;
  tp->seconds = startTime.seconds + secs;
  tp->microseconds = startTime.microseconds + (millis*1000);
  if (tp->microseconds >= 1000000) {
    tp->seconds++;
    tp->microseconds -= 1000000;
  }

  return (RTTOK);
}

#else
int RttGetTimeOfDay(RttTimeValue *tp)
{
  struct timezone dummy;

  return (gettimeofday((struct timeval *)tp, &dummy) ? RTTFAILED : RTTOK);
}
#endif /* WIN32 */
