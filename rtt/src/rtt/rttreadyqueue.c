/****************************************************************************
 * 
 * rttreadyqueue.c
 * 
 * Ready queue module.
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

#define NO_HINT -1
#define USE_HINT

static int hint;

/*------------------------------------------------------------------------
 * DeleteReadyThread_  --  take a thread off the ready queue
 *------------------------------------------------------------------------
 */
void DeleteReadyThread_(TCB *thread)
{
  DEQUEUE_ITEM(RDYQTBL[GetPrio(thread)], thread,   TCB, queueMgmtInfo);
  SetNumbReadyThreads(GetNumbReadyThreads()-1);
}

/*------------------------------------------------------------------------
 * InitReadyQueue_  --  initialize the ready queue
 *------------------------------------------------------------------------
 */
void InitReadyQueue_()
{
  int i;

  for (i = 0; i < NUM_READYQ_PRIORITIES; i++) {
    QUEUE_INIT(RDYQTBL[i]);
  }
  
  hint = 0;
  SetNumbReadyThreads(0);
}

/*------------------------------------------------------------------------
 * GetNextReadyThread_  --  return the highest priority ready thread, but 
 *                          leave it on the ready queue 
 *
 * XXX NOTE: this routine is no longer used, it should be removed
 *------------------------------------------------------------------------
 */
TCB *GetNextReadyThread_()
{
  TCB *thread;
  
#ifndef USE_HINT
  hint = 0;
#endif

  for (; hint < NUM_READYQ_PRIORITIES; hint++) {   
    if ( !QUEUE_EMPTY(RDYQTBL[hint]) ) {
      return(QUEUE_HEAD(RDYQTBL[hint]));
    }
  }

  return(TNULL);
}

/*------------------------------------------------------------------------
 * printReadyQueue  --  print names of threads on ready queue for given
 *                      priority
 *------------------------------------------------------------------------
 */
static void printReadyQueue(int priority)
{
  void	*next;
  
  next = RDYQTBL[priority].next;
  while (next != TNULL) {
    printf("%s ", GetTname(((TCB *)next)));
    next =   GetNext((TCB *) next);
  }
  printf("\n");
}

/*------------------------------------------------------------------------
 * printQueue  --  print names of threads on given queue
 *------------------------------------------------------------------------
 */
static void printQueue(int q)
{
  void	*next;
  
  next = QTBL[q].next;
  while (next != TNULL) {
    printf("%s ", GetTname(((TCB *)next)));
    next = GetNext((TCB *) next);
  }
  printf("\n");
}

/*------------------------------------------------------------------------
 * RttQueuePrint  --  debugging to see all queues 
 *------------------------------------------------------------------------
 */
void RttQueuePrint()
{
  int i = NUM_READYQ_PRIORITIES-1;
  printf("****************************************************************\n");
  printf("RttQueuePrint():\n");
  printf("----------------\n");
  if (currthread) {
    printf("running thread:            %s\n", GetTname(currthread));
  }
  for (; i >= 0; i--) {
    if (!QUEUE_EMPTY(RDYQTBL[i])) {
      printf("readyq pri %d:             ", i);
      printReadyQueue(i);
    }
  }
  if (!QUEUE_EMPTY(QTBL[RBLK])) {
    printf("receive blocked q:         "); 
    printQueue(RBLK);
  }
  if (!QUEUE_EMPTY(QTBL[SBLK])) {
    printf("send blocked q:            "); 
    printQueue(SBLK);
  }
  if (!QUEUE_EMPTY(QTBL[WTFR])) {
    printf("wait for reply blocked q:  "); 
    printQueue(WTFR);
  }
  if (!QUEUE_EMPTY(QTBL[SLEP])) {
    printf("SLEEP q:                   "); 
    printQueue(SLEP);
  }
  if (!QUEUE_EMPTY(QTBL[SEMB])) {
    printf("semaphore blocked q:       "); 
    printQueue(SEMB);
  }
  if (!QUEUE_EMPTY(QTBL[IOBK])) {
    printf("blocking I/O q:            "); 
    printQueue(IOBK);
  }
  printf("****************************************************************\n");
}


/*------------------------------------------------------------------------
 * EnqueueEdfHead_  --  add thread to ready queue according to edf rule
 *                      and at the head of all others with the same 
 *                      scheduling attributes
 *------------------------------------------------------------------------
 */
void EnqueueEdfHead_(TCB *thread)
{
  TCB *next = TNULL;
  RttTimeValue now;
  
  RttGetTimeOfDay(&now);
  
  if (CompTime_(GetStart(thread), now, >)) {
    SetTimeout_(thread, GetStart(thread));
    return;
  }
  
  SetState(thread,THREAD_READY);
  
  next = (TCB *) QUEUE_FIRST(RDYQTBL[GetPrio(thread)]);
  while (next != TNULL) {
    if (GetDeadlineSecs(next) > GetDeadlineSecs(thread)) {
      break;
    }
    if ((GetDeadlineSecs(next) == GetDeadlineSecs(thread)) &&
	(GetDeadlineMicSecs(next) >= GetDeadlineMicSecs( thread))) {
      break;
    }
    next = QUEUE_NEXT(next, queueMgmtInfo);
  }
  if (next == TNULL) {
    ENQUEUE_TAIL(RDYQTBL[GetPrio(thread)],thread,TCB,
		 queueMgmtInfo,GetPrio(thread));
  }
  else if (next ==  QUEUE_FIRST(RDYQTBL[GetPrio(thread)])) {
    ENQUEUE_HEAD(RDYQTBL[GetPrio(thread)],thread,TCB,
		 queueMgmtInfo,GetPrio(thread));
  }
  else {
    ENQUEUE_ITEM(thread, next, TCB, queueMgmtInfo,GetPrio(thread));
  }
  
  if (hint > GetPrio(thread)) {
    hint = GetPrio(thread);
  }
  
  SetNumbReadyThreads(GetNumbReadyThreads()+1);
}

/*------------------------------------------------------------------------
 * EnqueueEdfTail_  --  add thread to ready queue according to edf rule
 *                      and at the tail of all others with the same 
 *                      scheduling attributes
 *------------------------------------------------------------------------
 */
void EnqueueEdfTail_(TCB *thread)
{
  int cpu;
  TCB *prev;
  RttTimeValue now;
  
  RttGetTimeOfDay(&now);

  if (CompTime_(GetStart(thread), now, >)) {
    SetTimeout_(thread, GetStart(thread));
    return;
  }
  
  SetState(thread,THREAD_READY);

  prev = (TCB *) QUEUE_LAST(RDYQTBL[GetPrio(thread)]);
  if (GetDeadlineSecs(thread) != DEFAULT_D_SECONDS) {
    while (prev != TNULL) {
      if (GetDeadlineSecs(prev) < GetDeadlineSecs(thread)) {
	break;
      }
      else if (GetDeadlineSecs(prev) == GetDeadlineSecs(thread)) {
	if (GetDeadlineMicSecs(prev) <= GetDeadlineMicSecs(thread)) {
	  break;
	}
      }
      prev = QUEUE_PREV(prev,queueMgmtInfo);
    }	
  }
  if (prev == TNULL) {
    ENQUEUE_HEAD(RDYQTBL[GetPrio(thread)],thread,TCB,
		 queueMgmtInfo,GetPrio(thread));
  } 
  else if (prev == (TCB *) QUEUE_LAST(RDYQTBL[GetPrio(thread)])) {
    ENQUEUE_TAIL(RDYQTBL[GetPrio(thread)],thread,TCB,
		 queueMgmtInfo,GetPrio(thread));
  }
  else {
    SetNext(thread,GetNext(prev));
    SetPrev(thread,prev);
    SetPrev(GetNext(prev),thread);
    SetNext(prev,thread);
  }
  
  if (hint > GetPrio(thread)) {
    hint = GetPrio(thread);
  }
    
  SetNumbReadyThreads(GetNumbReadyThreads()+1);
}

/*------------------------------------------------------------------------
 * DeqReadyThread_  --  remove highest priority thread from ready queue
 *------------------------------------------------------------------------
 */
TCB *DeqReadyThread_()
{
  TCB *thread;
  
#ifndef USE_HINT
  hint = 0;
#endif

  for ( ; hint < NUM_READYQ_PRIORITIES; hint++) {   

    if (!QUEUE_EMPTY(RDYQTBL[hint])) {
      DEQUEUE_HEAD(RDYQTBL[hint], thread, TCB, queueMgmtInfo);
      SetNumbReadyThreads(GetNumbReadyThreads()-1);
      return(thread);
    }
  }

  hint = 0;
  return(TNULL);
}

/*------------------------------------------------------------------------
 * DeqIfReady_  --  if there is a more schedulable thread on the ready 
 *                  queues, dequeue it and enqueue currthread
 *------------------------------------------------------------------------
 */
TCB *DeqIfReady_()
{
  TCB *thread;
  int oldhint;
  
#ifndef USE_HINT
  hint = 0;
#endif

  oldhint = hint;

  for ( ; hint < NUM_READYQ_PRIORITIES; hint++) {   
    if (!QUEUE_EMPTY(RDYQTBL[hint])) {
      thread = QUEUE_HEAD(RDYQTBL[hint]);

      if (((GetPrio(currthread) > GetPrio(thread)) ||
	   ((GetPrio(currthread) == GetPrio(thread)) 
	    && CompTime_(GetDeadline(currthread), GetDeadline(thread), >)))) 
	{
	  DEQUEUE_HEAD(RDYQTBL[hint], thread, TCB, queueMgmtInfo);
	  SetState(thread,THREAD_READY); 
	  SetNumbReadyThreads(GetNumbReadyThreads()-1);
	  SetState(currthread,THREAD_READY); 
	  EnqueueEdfHead_(currthread);
	  
	  return (thread);
	}
      else
	{
	  return (currthread);
	}
    }
  }

  hint = oldhint;
  
  return(currthread);
}
