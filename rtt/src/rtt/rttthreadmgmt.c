/****************************************************************************
 * 
 * rttthreadmgmt.c
 * 
 * Thread management module.
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

#ifdef NATIVE_THREADS
int _KillNativeThread_ = 0;
#endif /* NATIVE_THREADS */

TCB *currthread;       /* thread currently running                  */
TCB *prevthread;       /* thread previously running                 */

static void *stackToBeFreed = NULL;

#ifndef WIN32
sigset_t RttSigExitSet;
#endif /* WIN32 */

static void threadIsLeaving(TCB *);
static void initTCB(int, TCB *);
static TCB *findUnusedTCB();
static void killCurrthread();

typedef struct ExitNodeStruct {
  void (*func)();
  struct ExitNodeStruct *next;
} ExitNode;
static ExitNode *exitList = NULL;
static ExitNode *exitTail = NULL;


/*------------------------------------------------------------------------
 * CallExitRoutines_  --  call registered exit routines
 *------------------------------------------------------------------------
 */
void CallExitRoutines_() {
  ExitNode *node;

  PTRACE_END();

  while (exitList != NULL) {
    (*exitList->func)();
    node = exitList;
    exitList = exitList->next;
  }
}

/*------------------------------------------------------------------------
 * RttRegisterExitRoutine  --  register a routine to be called upon 
 *                             exiting RTThreads
 *------------------------------------------------------------------------
 */
int RttRegisterExitRoutine(void (*func)()) {
  ExitNode *node;

  if ((node = (ExitNode *)RttMalloc(sizeof(ExitNode))) == NULL) {
    return (RTTFAILED);
  }
  if (exitList == NULL) {
    exitList = exitTail = node;
  }
  else {
    exitTail->next = node;
    exitTail = node;
  }
  node->func = func;
  node->next = NULL;

  return (RTTOK);
}

/*------------------------------------------------------------------------
 * RttMyThreadId  --  return current thread's thread id
 *------------------------------------------------------------------------
 */
RttThreadId RttMyThreadId()          
{
  RttThreadId retVal;
  
  ENTERINGOS;
  
  retVal = getThreadIdFromTcb(currthread);

  LEAVINGOS;
  
  return(retVal);
}

/*------------------------------------------------------------------------
 * RttNameToThreadId  --  get thread id, unless there is no such name
 *------------------------------------------------------------------------
 */
int RttNameToThreadId(RttThreadId *thread, char *name)
{
  int retVal;
  TCB *tcbPtr;
  int tcbNo;
  
  retVal = RTTFAILED;
  
  ENTERINGOS;
  
  tcbNo = 0;
  while((tcbNo < NUMBTCBS) && (retVal == RTTFAILED)) {
    tcbPtr = &(TCBTBL[tcbNo++]);
    if(GetInUse(tcbPtr) && (! strcmp(GetTname(tcbPtr), name))) {
      *thread = getThreadIdFromTcb(tcbPtr);
      retVal = RTTOK;
      break;
    }
  }

  LEAVINGOS;
  
  return (retVal);
}

/*------------------------------------------------------------------------
 * RttThreadExists  --  public interface to ThreadExists
 *------------------------------------------------------------------------
 */
int RttThreadExists(RttThreadId thread)
{
  int retVal;

  ENTERINGOS;
  
  if ((GetIpAddrFromThreadId(thread) != GetIpAddr(currthread)) ||
      (GetPortNoFromThreadId(thread) != GetPortNo(currthread))) {
    retVal = 0;
  }
  else {
    retVal = ThreadExists(getTcbFromThreadId(thread));
  }

  LEAVINGOS;
  
  return (retVal);
}

/*------------------------------------------------------------------------
 * threadIsLeaving  --  call all clean up routines when a thread leaves
 *------------------------------------------------------------------------
 */
static void threadIsLeaving(TCB *tcbPtr)
{
  PTRACE_EXIT(tcbPtr);

  ItcThreadCleanup_(tcbPtr);
  SemCleanup_(tcbPtr);
}

/*------------------------------------------------------------------------
 * RttKill  --  kill thread
 *------------------------------------------------------------------------
 */
int RttKill(RttThreadId thread)

{
  int retVal;
  TCB *tcbPtr;

  ENTERINGOS;

  if ((GetIpAddrFromThreadId(thread) != GetIpAddr(currthread)) ||
      (GetPortNoFromThreadId(thread) != GetPortNo(currthread))) {
    LEAVINGOS;
    return (RTTFAILED);
  }

  tcbPtr = getTcbFromThreadId(thread);

  if (tcbPtr == currthread) {
    killCurrthread();
  }

  if(ThreadExists(tcbPtr)) {
    SetNumbThreads(GetNumbThreads()-1);
    if (GetLevel(tcbPtr) == RTTSYS) {
      SetNumbSysThreads(GetNumbSysThreads()-1);
    }

    retVal = RTTOK;

    threadIsLeaving(tcbPtr);       /* call cleanup routines */
    
    SysFree_(GetStmembeg(tcbPtr));        /* free the stack */

    if ((GetState(tcbPtr) == THREAD_RUNNING) 
	|| (GetState(tcbPtr) == THREAD_READY)) {
      DEQUEUE_ITEM(RDYQTBL[GetPrio(tcbPtr)], tcbPtr, TCB, queueMgmtInfo);
    }
    else {
      DEQUEUE_ITEM(QTBL[GetState( tcbPtr )], tcbPtr, TCB, queueMgmtInfo);
    }

    SetState(tcbPtr,THREAD_FREE);
    IncInstance(tcbPtr);
    SetInUse(tcbPtr, 0);
  }
  else {
    retVal = RTTNOSUCHTHREAD;
  }

  SchedM;  /* implicitly does a LEAVINGOS */

  return(retVal);
}

/*------------------------------------------------------------------------
 * RttExit  --  kill the currently running thread
 *------------------------------------------------------------------------
 */
void RttExit()
{
  ENTERINGOS;
  
  killCurrthread();
}

/*------------------------------------------------------------------------
 * CallNclean_  --  starts new thread, and cleans up after it is done
 *------------------------------------------------------------------------
 */
void CallNclean_()
{
  PTRACE_START(currthread);

#ifndef NATIVE_THREADS  /* XXX why? */
  LEAVINGOS;
#endif /* NATIVE_THREADS */

  (*currthread->threadMgmtInfo.threadAddr)(currthread->threadMgmtInfo.threadArg);

  ENTERINGOS;
  
  killCurrthread();
}

/*------------------------------------------------------------------------
 * killCurrthread  --  do cleanup when current thread dies (must be called
 *                     in OS context)
 *------------------------------------------------------------------------
 */
static void killCurrthread()
{
  SetNumbThreads(GetNumbThreads()-1);

  if (GetLevel(currthread) == RTTSYS) {
    SetNumbSysThreads(GetNumbSysThreads()-1);
  }

  threadIsLeaving(currthread);   /* call cleanup routines */

  /* we can't free our own stack right away */
  if (stackToBeFreed != NULL) {
    SysFree_(stackToBeFreed);
  }
  stackToBeFreed = GetStmembeg(currthread);
  
  SetState(currthread,THREAD_FREE);
  IncInstance(currthread);
  SetInUse(currthread, 0);

  currthread = TNULL;
  
  if(GetNumbThreads() > GetNumbSysThreads()) {
    prevthread = currthread;
    currthread = DeqReadyThread_();
#ifdef NATIVE_THREADS
    _KillNativeThread_ = 1;
#endif /* NATIVE_THREADS */
    SchedThread_();
  }
  else {
    CallExitRoutines_();
    SysExit_(0);
  }
}

/*------------------------------------------------------------------------
 * initTCB  --  initialize the TCB struct
 *------------------------------------------------------------------------
 */
static void initTCB(int tcbNo, TCB *tcbPtr)
{
  memset(tcbPtr, 0, sizeof(struct tcb));

  SetInUse(tcbPtr, 0);
  SetState(tcbPtr,THREAD_FREE);
  SetTname(tcbPtr,GetNameArea(tcbPtr));
  SetIpAddr(tcbPtr, GetHid());
  SetPortNo(tcbPtr, GetLid());   
  SetInstance(tcbPtr, 1);  /* (not 0) XXX USE A TIMESTAMP TO INITIALIZE ! */
  SetIndex(tcbPtr, tcbNo);
  SetSysData(tcbPtr, NULL);

  ITCTCBINIT(tcbPtr);
  QMGMTTCBINIT(tcbPtr);
  SEMTCBINIT(tcbPtr);
}

/*------------------------------------------------------------------------
 * InitThreadMgmt_  --  initialize the TCBs
 *------------------------------------------------------------------------
 */
void InitThreadMgmt_()
{
  int tcbNo;
  
  SetNumbThreads(0);
  SetNumbSysThreads(0);

  for(tcbNo = 0; tcbNo < NUMBTCBS; tcbNo++) {
    initTCB(tcbNo, &TCBTBL[tcbNo]);
  }
}

/*------------------------------------------------------------------------
 * findUnusedTCB  --  find a free TCB
 *------------------------------------------------------------------------
 */
static TCB *findUnusedTCB()
{
  TCB *tcbPtr;
  static int tcbNo = 0;
  int lastTry;
  
  lastTry = tcbNo;
  do {
    tcbPtr = &TCBTBL[tcbNo++];
    tcbNo &= (NUMBTCBS - 1);    /* wrap if necessary */
  }
  while((tcbNo != lastTry) && GetInUse(tcbPtr));
  
  return(GetInUse(tcbPtr)? TNULL: tcbPtr);
}

/*------------------------------------------------------------------------
 * RttCreate  --  create a thread  
 *------------------------------------------------------------------------
 */
int RttCreate(RttThreadId *thread, void(*addr)(), int stksize, char *name, 
		     void *arg, RttSchAttr sched_attr, int level)
{
  int *sp;
  TCB *tcbPtr;
  RttTimeValue now;
#ifdef NATIVE_THREADS
  ThreadHandle threadHandle;

  threadHandle = NativeThreadCreate_(CallNclean_, stksize, arg);
#endif /* NATIVE_THREADS */

  ENTERINGOS;

  if((tcbPtr = findUnusedTCB()) != TNULL) {

    /* at this stage we have found an unused TCB - mark it as being used */
    SetInUse(tcbPtr, 1);

    SetStackSize(tcbPtr, stksize);

#ifdef NATIVE_THREADS
    {
      char *namecopy;
      namecopy = (char *)SysMalloc_(strlen(name)+1);
      strcpy(namecopy, name);
      RttTrace2("* Created thread %s  (0x%x)\n", (int)namecopy, (int)tcbPtr);
    }
#else
    SetStmembeg(tcbPtr, (int *) SysMalloc_(stksize));

    if (GetStmembeg(tcbPtr) == NULL) {
      SetInUse(tcbPtr, 0);
      LEAVINGOS;
      return (RTTFAILED);
    }

    PTRACE_FILLMEM(tcbPtr);

#endif /* NATIVE_THREADS */

    PTRACE_NAMEPREFIX(tcbPtr);

    if (name) {
      strncpy(GetTname(tcbPtr), name, MAXTNAMELEN);
    }
    else {
      strcpy(GetTname(tcbPtr), "nameless");
    }

    PTRACE_CREATE(tcbPtr);

    SETUPTHREADMGMT(tcbPtr, sched_attr, stksize, addr, arg);
    SETUPITC(tcbPtr);
    SetIpAddr(tcbPtr, GetHid());
    SetPortNo(tcbPtr, GetLid()); 

    SetNew(tcbPtr, 1);
    SetNumbThreads(GetNumbThreads()+1);
    SetState(tcbPtr,THREAD_READY);

#ifdef NATIVE_THREADS
    SetThreadHandle(tcbPtr, threadHandle);
#ifdef USE_SEM_SWITCH
    tcbPtr->switchSemBlocked = 0;
    tcbPtr->switchSem = NativeThreadSemCreate(0);
#endif /* USE_SEM_SWITCH */
#endif /* NATIVE_THREADS */
    
    RttGetTimeOfDay(&now);
    if (CompTime_(now, GetStart(tcbPtr), >)) {
      EnqueueEdfTail_(tcbPtr);
      }
    else {
      SetTimeout_(tcbPtr,GetStart(tcbPtr));
    }

    SetLevel(tcbPtr, level);
    if (level == RTTSYS) {
      SetNumbSysThreads(GetNumbSysThreads()+1);
    }
  }

  if(currthread) {
    SchedM;  /* implicitly does a LEAVINGOS */ 
  }
  else {     /* still in main(), StartOs_ has not been called yet */
    LEAVINGOS;
  }

  if (tcbPtr != TNULL) {
    *thread = getThreadIdFromTcb(tcbPtr);
    return (RTTOK);
  }
  else {
    return (RTTFAILED);
  }
}

/*------------------------------------------------------------------------
 * RttSetData  --  set user data
 *------------------------------------------------------------------------
 */
int RttSetData(RttThreadId thread, unsigned long data)
{
  TCB *tcbPtr;

  tcbPtr = getTcbFromThreadId(thread);

  if (ThreadExists(tcbPtr)) {
    ENTERINGOS;
    SetUVal(tcbPtr, data);
    LEAVINGOS;
    return (RTTOK);
  }
  else {
    return (RTTNOSUCHTHREAD);
  }
}

/*------------------------------------------------------------------------
 * RttGetData  --  get user data
 *------------------------------------------------------------------------
 */
int RttGetData(RttThreadId thread, unsigned long *data )

{
  unsigned long retValue;
  TCB *tcbPtr;

  tcbPtr = getTcbFromThreadId(thread);

  if (ThreadExists(tcbPtr)) {
    ENTERINGOS;
    retValue = GetUVal(currthread);
    LEAVINGOS;
    *data = retValue;
    return (RTTOK);
  }
  else {
    return (RTTNOSUCHTHREAD);
  }
}
