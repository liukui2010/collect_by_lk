/****************************************************************************
 * 
 * rttsched.c
 * 
 * Scheduling module.
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
#include "rttmeasure.h"

#ifdef WIN32
#include <fcntl.h>
#include <io.h>
#include "Win32Timer.h"
#endif /* WIN32 */

#define DPRINTF (void)

#define THREADNAME(X) (X ? GetTname(X) : "???")

extern int WatchCounter, WatchValue[], *WatchPointer[];
extern TCB* NullThread_Proc;

/*--------------- Global Variables -------------------------*/
short inOsFlag; /* used to avoid context switches in OS code */

#ifdef NATIVE_THREADS
short inIoFlag = 0;
int _InTickHandler_ = 0;
#endif /* NATIVE_THREADS */

static int wakeSleepers();

#ifdef WIN32

static DWORD _MainThread_;

#define ENTERINGHANDLER {\
	RttBeginCritical();\
	inOsFlag = 0;\
	}

#define LEAVINGHANDLER {\
	inOsFlag = 1;\
	RttEndCritical();\
	}

#else /* not WIN32 */

#define ENTERINGHANDLER {\
	  SigMask_(SIG_BLOCK, SIGALRM);\
	  SigMask_(SIG_BLOCK, SIGIO);\
          inOsFlag = 0;\
	}

#define LEAVINGHANDLER {\
          inOsFlag = 1;\
	  SigMask_(SIG_UNBLOCK, SIGALRM);\
	  SigMask_(SIG_UNBLOCK, SIGIO);\
	}

#endif /* WIN32 */

#define ENTERINGOSCHECK if (inOsFlag) RttTrace("**** ALREADY IN OS ****\n");
#define LEAVINGOSCHECK if (!inOsFlag) RttTrace("**** NOT IN OS ****\n");

#ifdef NATIVE_THREADS
void TickHandler_();
#else
static void tickHandler();
#endif /* NATIVE_THREADS */

#ifndef WIN32
void print_blocked() {
  sigset_t mask;
  sigprocmask(SIG_BLOCK, NULL, &mask);
  printf("blocked signals: %s %s\n", sigismember(&mask, SIGIO) ? "SIGIO" : " ",
	 sigismember(&mask, SIGALRM) ? "SIGALRM" : " ");
}

/*------------------------------------------------------------------------
 *  SigMask_  --  SIG_BLOCK or SIG_UNBLOCK given signal number
 *------------------------------------------------------------------------
 */
void SigMask_(int how, int sig) {
  sigset_t mask;

  sigemptyset(&mask);
  sigaddset(&mask, sig);
  if (sigprocmask(how, &mask, NULL) == -1) {
    perror("sigprocmask");
  }
}
#endif /* WIN32 */

/* A note regarding ENTERINGOS and LEAVINGOS:                               */
/*  -  these routines protect against context switches during OS execution. */
/*  -  these routines are only called (with small exceptions) from interface*/
/*     routines. Calling LEAVINGOS from an OS routine called by             */
/*     some other OS routine could leave things in an unprotected state.    */
/*  -  routines that call ShedM must be in OS context at the time of call,  */
/*     but must not leave OS context after call as this will be done        */
/*     by SchedM as soon as a thread is resumed.                           */

#ifdef NATIVE_THREADS
#define USE_OSMUTEX
static MutexHandle osMutex;
void InitOsMutex_()
{
  osMutex = NativeThreadMutexCreate_();
}
#endif /* NATIVE_THREADS */
/*------------------------------------------------------------------------
 * enteringOs  --  entering OS code
 *------------------------------------------------------------------------
 */
void enteringOs()
{
  ENTERINGOSCHECK;

#ifdef USE_OSMUTEX
  NativeThreadMutexLock_(osMutex);
#endif /* USE_OSMUTEX */

  inOsFlag = 1;            /* disallow context switches */
}

/*------------------------------------------------------------------------
 * leavingOs  --  leaving OS code
 *------------------------------------------------------------------------
 */
void leavingOs()
{
  LEAVINGOSCHECK;

#ifdef NATIVE_THREADS	/* XXX */
#ifdef USE_OSMUTEX
  NativeThreadMutexUnlock_(osMutex);
#else
  if (GetIoPending()) {
    IoHandler_();
    SetIoPending(0);
  }
#endif /* USE_OSMUTEX */  
#else

  if (GetIoPending()) {
#ifdef WIN32
    SetIoPending(0);
    SchedM;
#else  
    ENTERINGHANDLER;
    IoHandler_();
    LEAVINGHANDLER;
    SetIoPending(0);
#endif /* WIN32 */
  }

  if (GetTickPending()) {
    ENTERINGHANDLER;
    tickHandler();
    LEAVINGHANDLER;
    SetTickPending(0);
  }
#endif /* NATIVE_THREADS */

  inOsFlag = 0;    /* allows context switches         */
}

static char *noThread = "???";
#define TNAMESTRING(X) ((X) ? GetTname(X) : noThread)

/*------------------------------------------------------------------------
 * SchedThread_  --  schedule next thread without saving current context
 *------------------------------------------------------------------------
 */
void SchedThread_()
{
  int someInt = 1;

  PTRACE_CTXTSW(prevthread, currthread);
  PTRACE_CHECK(prevthread, "INSIDE Context Switch Code");
  PTRACE_WATCH();

  if (currthread == TNULL) {
    CallExitRoutines_();
    SysExit_(0); /* XXX is this a natural exit? */
  }
  else {
    assert(GetState(currthread) == THREAD_READY);
  }

  SetState(currthread, THREAD_RUNNING);

#ifndef WIN32   /* XXX think about this one! */
  /*
     If we're about to run the NullThread, just start it again from its 
     beginning. This is to make sure the NullThread doesn't get into a tight 
     recursive loop handling SIGIOs.
   */
  if (currthread == NullThread_Proc)
  {
    RttTrace2("SWITCH:         %s ---> %s\n", 
	      (int)TNAMESTRING(prevthread), (int)TNAMESTRING(currthread));
    startNewThread(NullThread_, GetSp(currthread));
  }
  else
#endif /* WIN32 */

  {
    if (GetNew(currthread)) {
      SetNew(currthread, 0);
      RttTrace2("SWITCH: (new)   %s ---> %s\n", 
		(int)TNAMESTRING(prevthread), (int)TNAMESTRING(currthread));
#ifdef NATIVE_THREADS
      NativeThreadSwitch_();
#else
      startNewThread(CallNclean_, GetSp(currthread));
#endif /* NATIVE_THREADS */
    }
    else {
      RttTrace2("SWITCH:         %s ---> %s\n", 
		(int)TNAMESTRING(prevthread), (int)TNAMESTRING(currthread));
#ifdef NATIVE_THREADS
      NativeThreadSwitch_();
#else
      returnToThread(GetSavearea(currthread));
#endif /* NATIVE_THREADS */
    }
  }
}

/*------------------------------------------------------------------------
 * StartClock_  --  start the system clock
 *------------------------------------------------------------------------
 */
void StartClock_(int useconds)   /* tick interval in microseconds */
     
{
#ifdef WIN32
  Win32_TimerInit (useconds / 1000);	/* use milliseconds */
#else /* not WIN32 */
  struct itimerval interval;
  
  interval.it_interval.tv_sec   = (useconds / 1000000);
  interval.it_interval.tv_usec  = (useconds % 1000000);
  interval.it_value.tv_sec   = (useconds / 1000000);
  interval.it_value.tv_usec  = (useconds % 1000000);

  setitimer(ITIMER_REAL, &interval, NULL); 
#endif /* WIN32 */
}


#ifdef NATIVE_THREADS
#if 1
Sched_(char *file, int line) {
/*printf("\n{%s:%d}\n", file, line);*/
#else
Sched_() {    /* XXX  ?????????????????????????????????????? */
#endif
	
  if ((GetState(currthread) == THREAD_READY) || (GetState(currthread) == THREAD_RUNNING)) {
    TCB *newthread;

    if ((newthread = DeqIfReady_()) != currthread) {
      prevthread = currthread;				 
      currthread = newthread;
      SchedThread_();
    }
    else {
      LEAVINGOS;
    }
  }
  else {
    if (GetState(currthread) == SLEP) {} 
    else {
      ENQUEUE_HEAD(QTBL[GetState(currthread)],currthread,TCB,queueMgmtInfo,GetState(currthread) );
    }
    prevthread = currthread;
    currthread = DeqReadyThread_();
    SchedThread_();
  }
}
#else
#ifdef WIN32
Sched_(char *file, int line) {
  if ((GetState(currthread) == THREAD_READY) || (GetState(currthread) == THREAD_RUNNING))
    {
      TCB *newthread;
      if ((newthread = DeqIfReady_()) != currthread) {
	if( saveThreadContext(GetSavearea( currthread )) ) 
	  {
	    prevthread = currthread;				 
	    currthread = newthread;
	    SchedThread_();
	  }
        else 
	  {
	    LEAVINGOS; /* back in user thread */
	  }
      }
      else 
	{
	  LEAVINGOS;
	}
    }
  else  
    {
      if ( GetState(currthread) == SLEP) {} 
      else
	{
	  ENQUEUE_HEAD(QTBL[GetState(currthread)],currthread,TCB,queueMgmtInfo,GetState(currthread) );
	}
      if( saveThreadContext(GetSavearea( currthread )) ) 
	{
	  prevthread = currthread;
	  currthread = DeqReadyThread_();
	  SchedThread_();
	}
      else
        LEAVINGOS; /* back in user thread */
    }
}
#else
void Sched_()
  {
    if ((GetState(currthread) == THREAD_READY) || (GetState(currthread) == THREAD_RUNNING)) {
      TCB *newthread;
      if ((newthread = DeqIfReady_()) != currthread) {
	if( saveThreadContext(GetSavearea( currthread )) ) {
          prevthread = currthread;			    
          currthread = newthread;                           
          SchedThread_();                                   
        }                                                   
        else {                                              
          LEAVINGOS; /* back in user thread */              
        }                                                   
      }                                                     
      else {                                                
        LEAVINGOS;                                          
      }                                                     
    }                                                       
    else  {                                                 
      if ( GetState(currthread) == SLEP) {} else            
     {                                                      
       ENQUEUE_HEAD(QTBL[GetState(currthread)],currthread,TCB,queueMgmtInfo,GetState(currthread) );
     }                                                      
     if( saveThreadContext(GetSavearea( currthread )) ) {   
       prevthread = currthread;				    
       currthread = DeqReadyThread_();                      
       SchedThread_();                                      
     }                                                      
     else                                                   
       LEAVINGOS; /* back in user thread */                 
     }                                                      
  }
#endif /* WIN32 */
#endif /* NATIVE_THREADS */


/*------------------------------------------------------------------------
 * RttStartClock  --  start the system clock
 *------------------------------------------------------------------------
 */
void RttStartClock()
{
  StartClock_(TICKINTERVAL);
}

/*------------------------------------------------------------------------
 * RttStopClock  --  stop the system clock
 *------------------------------------------------------------------------
 */
void RttStopClock()
{
#ifdef WIN32
  Win32_TimerKill();
#else /* not WIN32 */
  StartClock_(0);
#endif /* WIN32 */
}

/*------------------------------------------------------------------------
 * wakeSleepers  --  check the sleep queue for threads whose wake time has
 *                   passed, make them ready, and return number awakened
 *------------------------------------------------------------------------
 */
static int wakeSleepers()
{
  TCB *next_thread, *thread;
  RttTimeValue now;
  short numSleepers = 0;
  
  RttGetTimeOfDay(&now); 

  for (thread = QUEUE_FIRST(QTBL[SLEP]);
       (thread != TNULL) && (!CompTime_(GetStart(thread), now, >));
       thread = next_thread ) {
    next_thread = QUEUE_NEXT(thread, queueMgmtInfo);
    
    DEQUEUE_HEAD(QTBL[SLEP], thread,  TCB, queueMgmtInfo);
#if 1
    RTTSCHEDMEASURE(thread, now, GetStart(thread));
#else
    {
      RttMeasure *measure;
      int *diffs;
      measure = (RttMeasure *)GetSysData(thread);
      if (measure && (measure->type == RTTSCHEDMEASUREMENT)) {
	diffs = (int *)measure->data;
	diffs[measure->count++] = RTTTIMEDIFF(now, GetStart(thread));
	measure->lastWakeTime = now;
      } 
    }
#endif
    EnqueueEdfTail_(thread);
    numSleepers++;
  }

  return (numSleepers);
}

#ifdef NATIVE_THREADS
/*------------------------------------------------------------------------
 * TickHandler_  --  call wakeSleepers periodically
 *------------------------------------------------------------------------
 */
void TickHandler_()
#else
/*------------------------------------------------------------------------
 * tickHandler  --  call wakeSleepers periodically
 *------------------------------------------------------------------------
 */
static void tickHandler()
#endif /* NATIVE_THREADS */
{
  register short switchNeeded;
  unsigned long	fooey;
  unsigned long stackTop;
  unsigned long stackBottom;
#ifdef NATIVE_THREADS
  extern ThreadHandle thandle;

  while (1)
    {
      /* wait for the tickHandler to signal us */
      NativeThreadWaitForTick_();
#else
#ifndef WIN32
    SetIoPending(1);	/* HACK HACK HACK HACK */
#endif /* WIN32 */
#endif /* NATIVE_THREADS */

#ifdef NATIVE_THREADS
#ifdef USE_OSMUTEX
  if (1) {
#else
  if (!INOSCTXT && !INIOCTXT) {
#endif /* USE_OSMUTEX */
#else
  if (!INOSCTXT) {
#endif /* NATIVE_THREADS */
    /*
       We must not be in the OS context when this is checked.
       If called from a signal handler, we won't switch after the
       check; if called by hand, our state is clean enough.
     */
#ifndef NATIVE_THREADS
    stackBottom = (unsigned long)GetStmembeg(currthread);
    stackTop = (unsigned long)GetStkend(currthread);
  
    if ((int)(&fooey) < stackBottom)
    {
      SetTickPending(1);
      return;
      write(fileno(stdout), "IOH: BELOW STACK\n", 17);
      kill(getpid(), SIGILL);
    }
    if ((int)(&fooey) > stackTop)
    {
      SetTickPending(1);
      return;
      write(fileno(stdout), "IOH: ABOVE STACK\n", 17);
      kill(getpid(), SIGILL);
    }
#else
    NativeThreadMutexHack_();
#endif /* NATIVE_THREADS */
    SetTickPending(0);
    ENTERINGOS;

    switchNeeded = wakeSleepers();

    if(switchNeeded) {
      /* 
       * due to the unnatural return from this routine (i.e. SchedM),
       * we must turn the interrupts back on using sigprocmask().
       */

#ifdef WIN32
      /*RttEndCritical ();*/
#else /* not WIN32 */
      SigMask_ (SIG_UNBLOCK, SIGALRM);
      SigMask_ (SIG_UNBLOCK, SIGIO);
#endif /* WIN32 */
#ifdef NATIVE_THREADS
      _InTickHandler_	= 1;
#endif /* NATIVE_THREADS */
      SchedM;    /* implicitly does a LEAVINGOS                        */
#ifdef NATIVE_THREADS
      _InTickHandler_	= 0;
#endif /* NATIVE_THREADS */
    }
    else {
      LEAVINGOS;
    }
  }
  else {
    SetTickPending(1);
  }
#ifdef NATIVE_THREADS
  }  /* matches "while (1) {" above */
#endif /* NATIVE_THREADS */

}

/*------------------------------------------------------------------------
 * StartOs_()  --  set up system clock and load the first thread
 *------------------------------------------------------------------------
 */
void StartOs_()
{
#ifdef NATIVE_THREADS
  NativeThreadStartTicker_();
  NativeThreadGetCurrentThread_();
#else
#ifdef WIN32
  Win32_SetTimerCallback (tickHandler);
  _MainThread_ = GetCurrentThreadId;
#else
  sigset_t mask;
  struct sigaction action;

  sigemptyset(&mask);
  sigaddset(&mask, SIGIO);
  sigaddset(&mask, SIGALRM);

  action.sa_handler = tickHandler;
  action.sa_mask = mask;
  action.sa_flags = 0;

  sigaction(SIGALRM, &action, NULL);

  action.sa_handler = IoHandler_;
  action.sa_mask = mask;
  action.sa_flags = 0;

  sigaction(SIGIO, &action, NULL);
#endif /* WIN32 */
#endif /* NATIVE_THREADS */
  /*
   * NOTE: if, for some reason, you want to use sigset() to register
   *       handlers, you have to use signal() for sun4 architecture
   */

  ENTERINGOS;

  StartClock_(TICKINTERVAL);

  if(GetNumbThreads() > GetNumbSysThreads()) {
    prevthread = TNULL;
    currthread = DeqReadyThread_();
    SchedThread_();	/* never returns */
  }
  else {
    CallExitRoutines_();
    SysExit_(0);
  }
}

/*------------------------------------------------------------------------
 * RttBeginCritical  --  block signals
 *------------------------------------------------------------------------
 */
void RttBeginCritical() {
#ifdef WIN32
  ENTERINGOS;
  /*Win32_TimerBlock();*/
#else /* not WIN32 */
  SigMask_(SIG_BLOCK, SIGALRM);
  SigMask_(SIG_BLOCK, SIGIO);
#endif /* WIN32 */
}

/*------------------------------------------------------------------------
 * RttEndCritical  --  unblock signals
 *------------------------------------------------------------------------
 */
void RttEndCritical() {
#ifdef WIN32
  LEAVINGOS;
  /*Win32_TimerUnblock();*/
#else /* not WIN32 */
  SigMask_(SIG_UNBLOCK, SIGALRM);
  SigMask_(SIG_UNBLOCK, SIGIO);
#endif /* WIN32 */
}
