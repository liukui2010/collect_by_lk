/****************************************************************************
 * 
 * rttsem.c
 * 
 * Semaphore module.
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

#include "rttkernel.h"

static void addBlockedThread(SemaphoreStruct *);
static TCB *dequeueFirstBlockedThread(SemaphoreStruct *);
static TCB *dequeueHighPrioBlockedThread(SemaphoreStruct *);

/*------------------------------------------------------------------------
 * addBlockedThread  --  add to list of threads blocked on semaphore
 *------------------------------------------------------------------------
 */
static void addBlockedThread(SemaphoreStruct *semaph)
{
  if(semaph->firstBlockedThread != NULL) {
    SetSemaphPrev(currthread, semaph->lastBlockedThread);
    SetSemaphNext(semaph->lastBlockedThread, currthread);
  }
  else {   /* no one is currently blocked on this semaphore */
    semaph->firstBlockedThread = currthread;
    SetSemaphPrev(currthread, NULL);
  }
  
  SetSemaphore(currthread, semaph);
  SetSemaphNext(currthread, NULL);
  semaph->lastBlockedThread = currthread;
}

/*------------------------------------------------------------------------
 * removeThread  --  remove thread from list of semaphore blocked threads
 *------------------------------------------------------------------------
 */
static void removeThread(SemaphoreStruct *semaph, TCB *tcbPtr)
{
  TCB *prev, *next;

  prev = GetSemaphPrev(tcbPtr);
  next = GetSemaphNext(tcbPtr);
  
  if(prev == NULL) {
    semaph->firstBlockedThread = next;
  }
  else {
    SetSemaphNext(prev, next);
  }
  
  if(next == NULL) {
    semaph->lastBlockedThread = prev;
  }
  else {
    SetSemaphPrev(next, prev);
  }
  
  SetSemaphNext(tcbPtr, NULL);
  SetSemaphPrev(tcbPtr, NULL);
  SetSemaphore(tcbPtr, NULL);
}

/*------------------------------------------------------------------------
 * dequeueFirstBlockedThread  --  remove first thread from list of 
 *                                semaphore blocked threads
 *------------------------------------------------------------------------
 */
static TCB *dequeueFirstBlockedThread(SemaphoreStruct *semaph)
{
  TCB *tcbPtr;

  tcbPtr = semaph->firstBlockedThread;

  if (tcbPtr == NULL) return NULL;

  removeThread(semaph, tcbPtr);

  return (tcbPtr);
}

/*------------------------------------------------------------------------
 * dequeueHighPrioBlockedThread  --  remove highest priority, lowest
 *                                   deadline thread from list of semaphore 
 *                                   blocked threads
 *------------------------------------------------------------------------
 */
static TCB *dequeueHighPrioBlockedThread(SemaphoreStruct *semaph)
{
  TCB *tcbPtr, *searcher;
  int highPrio = NULP;
  RttTimeValue lowDeadline = RTTINFINITE;

  if (semaph->firstBlockedThread == NULL) return NULL;

  for (tcbPtr = searcher = semaph->firstBlockedThread;
       searcher != TNULL;
       searcher = GetSemaphNext(searcher))
    {
      if ((GetPrio(searcher) < highPrio) 
	  || ((GetPrio(searcher) == highPrio) 
	      && CompTime_(GetDeadline(searcher), lowDeadline, <)))
	{
	  highPrio = GetPrio(searcher);
	  lowDeadline = GetDeadline(searcher);
	  tcbPtr = searcher;
	}
    }

  removeThread(semaph, tcbPtr);

  return (tcbPtr);
}

/*------------------------------------------------------------------------
 * SemCleanup_  --  to be called for every thread leaving the system 
 *------------------------------------------------------------------------
 */
void SemCleanup_(TCB *tcbPtr)
{
  SemaphoreStruct *semaph;

  if (GetState(tcbPtr) == SEMB) {
    semaph = GetSemaphore(tcbPtr);
    removeThread(semaph, tcbPtr);
    semaph->semaphValue++;
  }
}

/*------------------------------------------------------------------------
 * RttAllocSem  --  allocate a new semaphore
 *------------------------------------------------------------------------
 */
int RttAllocSem(RttSem *newSem, int value, int mode)
{
  SemaphoreStruct *semaph;

  if ((value < 0) || ((mode != RTTFCFS) && (mode != RTTPRIORITY))) {
    return (RTTFAILED);
  }

  ENTERINGOS;
  semaph = (SemaphoreStruct *) SysMalloc_(sizeof(SemaphoreStruct));
  LEAVINGOS;

  if(semaph == NULL) {
    return (RTTFAILED);
  }
  else {
    semaph->magicNumb = SEM_MAGIC_NUMBER;
    semaph->firstBlockedThread = NULL;
    semaph->lastBlockedThread = NULL;
    semaph->semaphValue = value;
    semaph->mode = mode;

    *newSem = (RttSem) semaph;

    return (RTTOK);
  }
}

/*------------------------------------------------------------------------
 * RttFreeSem  --  free a semaphore
 *------------------------------------------------------------------------
 */
int RttFreeSem(RttSem semaphore)
{
  SemaphoreStruct *semaph;
  
  semaph = (SemaphoreStruct *) semaphore;

  if ((semaph->magicNumb != SEM_MAGIC_NUMBER) || (semaph->semaphValue < 0)) {
    return (RTTFAILED);
  }
  
  semaph->magicNumb = 0;

  ENTERINGOS;
  SysFree_(semaphore);
  LEAVINGOS;

  return(RTTOK);
}

/*------------------------------------------------------------------------
 * RttP  --  wait on semaphore
 *------------------------------------------------------------------------
 */
int RttP(RttSem semaphore)
{
  int retVal;
  short doCtxtSw = 0;
  SemaphoreStruct *semaph;

  semaph = (SemaphoreStruct *) semaphore;

  if (semaph->magicNumb != SEM_MAGIC_NUMBER) {
    return (RTTFAILED);
  }

  ENTERINGOS;
  
  if((--(semaph->semaphValue)) < 0) {
    doCtxtSw = 1;
    addBlockedThread(semaph);
    SetState(currthread, SEMB);
  } 
  
  if(doCtxtSw) {
    SchedM;   /* implicitly does a LEAVINGOS  */
  }
  else {
    LEAVINGOS;
  }

  return(RTTOK);
}

/*------------------------------------------------------------------------
 * RttV  --  signal semaphore
 *------------------------------------------------------------------------
 */
int RttV(RttSem semaphore)
{
  int retVal;
  short doCtxtSw = 0;
  SemaphoreStruct *semaph;
  
  semaph = (SemaphoreStruct *) semaphore;
  
  if (semaph->magicNumb != SEM_MAGIC_NUMBER) {
    return (RTTFAILED);
  }
  
  ENTERINGOS;
  
  if((++(semaph->semaphValue)) <= 0) {
    TCB *tcbPtr;

    doCtxtSw = 1;
    switch (semaph->mode) {
    case RTTFCFS:
      tcbPtr = dequeueFirstBlockedThread(semaph);
      break;

    case RTTPRIORITY:
      tcbPtr = dequeueHighPrioBlockedThread(semaph);
      break;

    default:
      LEAVINGOS;
      /* this assertion will fail */
      assert((semaph->mode == RTTFCFS) || (semaph->mode == RTTPRIORITY));
      SysExit_(-1);
      break;
    }

    assert(tcbPtr);
    SetState(tcbPtr, THREAD_READY);
    DEQUEUE_ITEM(QTBL[SEMB], tcbPtr, TCB, queueMgmtInfo);
    EnqueueEdfTail_(tcbPtr);
  } 
  
  if(doCtxtSw) {
    SchedM;     /* implicitly does a LEAVINGOS */
  }
  else {
    LEAVINGOS;
  }
  
  return(RTTOK);
}

/*------------------------------------------------------------------------
 * RttSemValue  --  return semaphore value by reference
 *------------------------------------------------------------------------
 */
int RttSemValue(RttSem semaphore, int *value)
{
  int retVal;
  SemaphoreStruct *semaph;

  semaph = (SemaphoreStruct *) semaphore;
  
  if (semaph->magicNumb != SEM_MAGIC_NUMBER) {
    return (RTTFAILED);
  }
  
  *value = semaph->semaphValue;

  return (RTTOK);
}
