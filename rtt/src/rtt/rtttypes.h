/****************************************************************************
 * 
 * rtttypes.h
 * 
 * Types used within RT Threads implementation.
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

#ifndef RTTTYPES_H
#define RTTTYPES_H

#ifdef NATIVE_THREADS
#include "NativeThr.h"
#endif /* NATIVE_THREADS */

extern int errno;

typedef enum {
  RBLK = 0,             /* q of receive blocked threads       */
  SBLK = 1,             /* q of send blocked threads          */
  WTFR = 2,             /* q of threads waiting for replys    */
  SLEP = 3,             /* q of sleeping threads              */
  SEMB = 4,             /* q of semaphore blocked threads     */
  IOBK = 5,             /* q of blocking I/O blocked threads  */
#define NUMQS 6
  THREAD_FREE    = 20,
  THREAD_READY   = 21,
  THREAD_RUNNING = 22,
  THREAD_DYING   = 23 ,
  NOQ            = 0xff  /* threads not on any queue */
} TSTATE;

typedef struct tcb TCB;

#define TNULL ((struct tcb *) NULL)

#define NULP  31 /*  null thread prio */


#define DEFAULT_D_SECONDS               0xffffffff
#define DEFAULT_D_MICROSECONDS          0
#define DEFAULT_INFINITE                0xffffffff


/*-----------------------------------------------------------------------*/

typedef struct
{
  int remoteItc;             /* flag indicating cross address space ITC    */
  RttThreadId remoteThreadId;/* thread id  of remote sender                */

  void  *sendmsg;            /* pointer to buffer of sent message          */
  u_int sendlen;             /* length of sent message                     */
  struct tcb *peer;          /* sender / receiver of message		   */
  void *receivedmsg;         /* pointer to buffer of received message      */
  u_int receivedlen;         /* length of sent message                     */

  struct tcb *waitingFirst;  /* list of threads sending to me		   */
  struct tcb *waitingLast;   /* last thread in above list	           */
  struct tcb *waitingNext;   /* next thread waiting for one I'm waiting on */
  struct tcb *waitingPrev;   /* prev thread waiting for one I'm waiting on */
} ITCInfo;

#define GetRemoteItc(X)         ((X)->itcInfo.remoteItc)
#define GetRemoteThreadId(X)    ((X)->itcInfo.remoteThreadId)
#define GetReceivedMsg(X)       ((X)->itcInfo.receivedmsg)
#define GetReceivedLen(X)       ((X)->itcInfo.receivedlen)
#define GetSendMsg(X)           ((X)->itcInfo.sendmsg)
#define GetSendLen(X)           ((X)->itcInfo.sendlen)
#define GetPeer(X)              ((X)->itcInfo.peer)
#define GetWaitingFirst(X)      ((X)->itcInfo.waitingFirst)
#define GetWaitingLast(X)       ((X)->itcInfo.waitingLast)
#define GetWaitingNext(X)       ((X)->itcInfo.waitingNext)
#define GetWaitingPrev(X)       ((X)->itcInfo.waitingPrev)

#define SetRemoteItc(X, V)      ((X)->itcInfo.remoteItc = (V))
#define SetRemoteThreadId(X, V) ((X)->itcInfo.remoteThreadId = (V))
#define SetReceivedMsg(X, V)    ((X)->itcInfo.receivedmsg = (V))
#define SetReceivedLen(X, V)    ((X)->itcInfo.receivedlen = (V))
#define SetSendMsg(X, V)        ((X)->itcInfo.sendmsg = (V))
#define SetSendLen(X, V)        ((X)->itcInfo.sendlen = (V))
#define SetPeer(X, V)           ((X)->itcInfo.peer = (V))
#define SetWaitingFirst(X,V)    ((X)->itcInfo.waitingFirst = (V))
#define SetWaitingLast(X,V)     ((X)->itcInfo.waitingLast = (V))
#define SetWaitingNext(X,V)     ((X)->itcInfo.waitingNext = (V))
#define SetWaitingPrev(X,V)     ((X)->itcInfo.waitingPrev = (V))

typedef struct
    {
    int inUse;                /* is there a thread occupying this TCB?  */
    RttSchAttr attrs;
    TSTATE state;             /* thread state                           */
    char name[MAXTNAMELEN + 1 + PTRACE_NAMEOFFSET];
    char *namePtr;
    int *stmembeg;            /* stack limit (lowest stack byte)        */
 
    int *stkend;              /* end of stack                           */
    int *sp;                  /* current stack pointer                  */
    int stackSize;            /* size of thread's stack.                */

    void (*threadAddr)();     /* thread entry point                     */
    void *threadArg;          /* arg to thread                          */
    unsigned long uVal;	      /* Thread specific data structure (DM)    */
    int level;		      /* RTTUSR or RTTSYS                       */
  } ThreadMgmtInfo;

#define GetStmembeg(X)        ((X)->threadMgmtInfo.stmembeg)
#define GetSp(X)              ((X)->threadMgmtInfo.sp)
#define GetStkend(X)          ((X)->threadMgmtInfo.stkend)
#define GetStart(X)           ((X)->threadMgmtInfo.attrs.startingtime)
#define GetStartSecs(X)       ((X)->threadMgmtInfo.attrs.startingtime.seconds)
#define GetStartMicSecs(X)    ((X)->threadMgmtInfo.attrs.startingtime.microseconds)
#define GetPrio(X)            ((X)->threadMgmtInfo.attrs.priority)
#define GetDeadline(X)        ((X)->threadMgmtInfo.attrs.deadline)
#define GetDeadlineSecs(X)    ((X)->threadMgmtInfo.attrs.deadline.seconds)
#define GetDeadlineMicSecs(X) ((X)->threadMgmtInfo.attrs.deadline.microseconds)
#define GetState(X)           ((X)->threadMgmtInfo.state)
#define GetNameArea(X)        ((X)->threadMgmtInfo.name)
#define GetTname(X)           ((X)->threadMgmtInfo.namePtr)
#define GetThreadAddr(X)      ((X)->threadMgmtInfo.threadAddr)
#define GetThreadArg(X)       ((X)->threadMgmtInfo.threadArg)
#define GetInUse(X)           ((X)->threadMgmtInfo.inUse)
#define GetStackSize(X)       ((X)->threadMgmtInfo.stackSize)
#define GetUVal(X)            ((X)->threadMgmtInfo.uVal)
#define GetLevel(X)           ((X)->threadMgmtInfo.level)
#define SetStmembeg(X,V)      ((X)->threadMgmtInfo.stmembeg = (V))
#define SetSp(X,V)            ((X)->threadMgmtInfo.sp = (V))
#define SetStkend(X,V)        ((X)->threadMgmtInfo.stkend = (V))
#define SetStart(X,V)         ((X)->threadMgmtInfo.attrs.startingtime = (V))
#define SetPrio(X,V)          ((X)->threadMgmtInfo.attrs.priority = (V))
#define SetDeadline(X,V)      ((X)->threadMgmtInfo.attrs.deadline = (V))
#define SetState(X,V)         ((X)->threadMgmtInfo.state = (V))
#define SetTname(X,V)         ((X)->threadMgmtInfo.namePtr = (V))
#define SetThreadAddr(X,V)    ((X)->threadMgmtInfo.threadAddr = (V))
#define SetThreadArg(X,V)     ((X)->threadMgmtInfo.threadArg = (V))
#define SetInUse(X,V)         ((X)->threadMgmtInfo.inUse = (V))
#define SetStackSize(X,V)     ((X)->threadMgmtInfo.stackSize = (V))
#define SetUVal(X,V)          ((X)->threadMgmtInfo.uVal = (V))
#define SetLevel(X,V)         ((X)->threadMgmtInfo.level = (V))

typedef struct
    {
    struct tcb *prev;         /* pointer to previous thread descripter */
    struct tcb *next;         /* pointer to next thread descriptor     */
    u_char queue;             /* the queue this is thread currently on?*/
    } QueueMgmtInfo;

#define GetPrev(X)           ((X)->queueMgmtInfo.prev)
#define GetNext(X)           ((X)->queueMgmtInfo.next)
#define GetQueue(X)          ((X)->queueMgmtInfo.queue)
#define SetPrev(X,V)         ((X)->queueMgmtInfo.prev = (V))
#define SetNext(X,V)         ((X)->queueMgmtInfo.next = (V))
#define SetQueue(X,V)        ((X)->queueMgmtInfo.queue = (V))

typedef struct
    {
      /* 
       * Need savearea of 11 for sparc, 13 for 68000, 17 for 88100, 21 for
       * RS6000. For the 88000, this area must be 8byte aligned, which implies
       * that the size of the thread descriptor must be a multiple of 8 bytes.
       * With no other changes, that is guaranteed if this area is an odd
       * number of words
       */
      int savearea[36];      /* XXX context save area (was 24 before aio) */
#ifndef WIN32
      sigset_t mask; 	   /* XXX DON'T NEED THIS, NOT USED! Current state of the signal mask		*/
#endif /* WIN32 */    
      int new;               /* if non-zero, thread has not run yet	*/
    } SchedInfo;

#define GetSavearea(X)       	((X)->schedInfo.savearea)
#define GetSignalMask(X)	((X)->schedInfo.mask)
#define GetNew(X)            	((X)->schedInfo.new)
#define SetSavearea(X,V)        ((X)->schedInfo.savearea = (V))
#define SetSignalMask(X,V)	((X)->schedInfo.mask = (V))
#define SetNew(X,V)             ((X)->schedInfo.new = (V))

typedef struct
    {
      struct tcb *semaphNext; /* next of threads blocked on this semaphore*/
      struct tcb *semaphPrev; /* prev of threads blocked on this semaphore*/
      RttSem  semaphore;  /* semaphore this thread is blocked on     */
    } SemInfo;

#define GetSemaphNext(X)   ((X)->semInfo.semaphNext)
#define GetSemaphPrev(X)   ((X)->semInfo.semaphPrev)
#define GetSemaphore(X)    ((X)->semInfo.semaphore)
#define SetSemaphNext(X,V)   ((X)->semInfo.semaphNext = (V))
#define SetSemaphPrev(X,V)   ((X)->semInfo.semaphPrev = (V))
#define SetSemaphore(X,V)    ((X)->semInfo.semaphore = (V))

#if defined(ASYNCIO) && (defined(solaris) || defined(sun4))
typedef struct
{
  struct aio_result_t	aioInfo;
  int			canFree;
} SolarisAIOInfo;
#endif

typedef struct 
    {
    char ioOp;                /* READN, WRITEN, READ, WRITE, etc.       */
    int  ioRes;               /* result: number of bytes transferred    */
    char *ioBuf;              /* pointer to dest/source buffer          */
    int  ioNumBytes;          /* number of bytes requested transferred  */
    int  ioFlags;             /* flags for recvfrom                     */
    char *ioSrcBuf;           /* buffer for from field in recvfrom      */
    int  *ioSblPtr;           /* pointer to srcbuf len in recvfrom      */
#ifdef ASYNCIO
#ifdef ibm
    struct aiocb aioInfo;     /* asynchronous I/O info structure	*/
#else
    aio_result_t *aioInfo;    /* asynchronous I/O info structure	*/
#endif /* ibm */
#endif /* ASYNCIO */
    int  ioSeekPos;           /* location to seek to - if desired       */
    int  ioSeekMode;          /* how to seek (whence in lseek())        */
    fd_set *ioMask;           /* ptr to read or write mask for select   */
    int  ioA1;                /* arg 1 for request.                     */
    int  ioA2;
    int  ioA3;
    int  ioA4;
    int  ioA5;
    } IOInfo;

#define GetIoOp(X) ((X)->ioInfo.ioOp)
#define GetIoNumBytes(X) ((X)->ioInfo.ioNumBytes)
#define GetIoBuf(X) ((X)->ioInfo.ioBuf)
#define GetIoRes(X) ((X)->ioInfo.ioRes)
#define GetIoFlags(X) ((X)->ioInfo.ioFlags)
#define GetIoSrcBuf(X) ((X)->ioInfo.ioSrcBuf)
#define GetIoSblPtr(X) ((X)->ioInfo.ioSblPtr)
#ifdef ASYNCIO
#define GetAIOInfo(X) ((X)->ioInfo.aioInfo)
#endif /* ASYNCIO */
#define GetIoSeekPos(X) ((X)->ioInfo.ioSeekPos)
#define GetIoSeekMode(X) ((X)->ioInfo.ioSeekMode)
#define GetIoMask(X) ((X)->ioInfo.ioMask)
#define GetIoA1(X) ((X)->ioInfo.ioA1)
#define GetIoA2(X) ((X)->ioInfo.ioA2)
#define GetIoA3(X) ((X)->ioInfo.ioA3)
#define GetIoA4(X) ((X)->ioInfo.ioA4)
#define GetIoA5(X) ((X)->ioInfo.ioA5)

#define SetIoOp(X,V) ((X)->ioInfo.ioOp = (V))
#define SetIoNumBytes(X,V) ((X)->ioInfo.ioNumBytes = (V))
#define SetIoBuf(X,V) ((X)->ioInfo.ioBuf = (V))
#define SetIoRes(X,V) ((X)->ioInfo.ioRes = (V))
#define SetIoFlags(X,V) ((X)->ioInfo.ioFlags = (V))
#define SetIoSrcBuf(X,V) ((X)->ioInfo.ioSrcBuf = (V))
#define SetIoSblPtr(X,V) ((X)->ioInfo.ioSblPtr = (V))
#ifdef ASYNCIO
#define SetAIOInfo(X,V)  ((X)->ioInfo.aioInfo = (V))
#endif /* ASYNCIO */
#define SetIoSeekPos(X,V) ((X)->ioInfo.ioSeekPos = (V))
#define SetIoSeekMode(X,V) ((X)->ioInfo.ioSeekMode = (V))
#define SetIoMask(X,V) ((X)->ioInfo.ioMask = (V))
#define SetIoA1(X,V) ((X)->ioInfo.ioA1 = (V))
#define SetIoA2(X,V) ((X)->ioInfo.ioA2 = (V))
#define SetIoA3(X,V) ((X)->ioInfo.ioA3 = (V))
#define SetIoA4(X,V) ((X)->ioInfo.ioA4 = (V))
#define SetIoA5(X,V) ((X)->ioInfo.ioA5 = (V))

struct tcb
{
  RttThreadId threadId;
  int errNo;

#ifdef NATIVE_THREADS
  HANDLE threadHandle;
#ifdef USE_SEM_SWITCH
  int switchSemBlocked;
  HANDLE switchSem;
#endif /* USE_SEM_SWITCH */
#endif /* NATIVE_THREADS */
  
  ThreadMgmtInfo threadMgmtInfo;
  QueueMgmtInfo queueMgmtInfo;
  SchedInfo schedInfo;
  ITCInfo itcInfo;
  SemInfo semInfo;
  IOInfo ioInfo;

  void *sysData;
};

#ifdef NATIVE_THREADS
#define SetThreadHandle(X,V) ((X)->threadHandle = (V))
#define GetThreadHandle(X)   ((X)->threadHandle)
#endif /* NATIVE_THREADS */

#define SetIpAddr(X,V)    SetThreadIdIpAddr((X)->threadId, (V))
#define SetPortNo(X,V)    SetThreadIdPortNo((X)->threadId, (V))
#define SetInstance(X,V)  SetThreadIdInstance((X)->threadId, (V))
#define SetIndex(X,V)     SetThreadIdIndex((X)->threadId, (V))

#define GetIpAddr(X)      GetIpAddrFromThreadId((X)->threadId)
#define GetPortNo(X)      GetPortNoFromThreadId((X)->threadId)
#define GetInstance(X)    GetInstanceFromThreadId((X)->threadId)
#define GetIndex(X)       GetIndexFromThreadId((X)->threadId)

#define SetErrno(X,V)	  ((X)->errNo = (V))
#define GetErrno(X)	      ((X)->errNo)

#define SetSysData(X,V)	  ((X)->sysData = (V))
#define GetSysData(X)	  ((X)->sysData)

/* so we can use instance == 0 to id nameserver */
#define IncInstance(X) {\
	  SetInstance((X),((GetInstance(X)+1)%INSTANCE_BITS));     \
	  SetInstance((X),(GetInstance(X)+(GetInstance(X) == 0))); \
	  }

#define getTcbFromThreadId(X)   (&TCBTBL[GetIndexFromThreadId(X)])
#define getThreadIdFromTcb(X)   ((X)->threadId)

typedef struct
{
    void *next;
    void *prev; 
} QUEUE_LINK, QUEUE;

struct globals {
  int		numbThreads;
  int		numbReadyThreads;
  int		numbSysThreads;
  int           ioPending;
  int           tickPending;
  int           nameServerCreated;
  RttThreadId	nameServerId;
  u_long        hid;           /* Host id (IP address)   */
  u_long        lid;           /* Local id (port number, instance, index) */
  struct tcb    tcbTbl[NUMBTCBS];
  QUEUE		qTbl[NUMQS];   /* thread queues (ready, blocked, ...) */
  QUEUE         rdyqTbl[NUM_READYQ_PRIORITIES];
};

extern struct globals _Globals_;

#define TCBTBL                 (_Globals_.tcbTbl)
#define QTBL                   (_Globals_.qTbl)
#define RDYQTBL                (_Globals_.rdyqTbl)

#define GetNumbThreads()       (_Globals_.numbThreads)
#define GetNumbReadyThreads()  (_Globals_.numbReadyThreads)
#define GetNumbSysThreads()    (_Globals_.numbSysThreads)
#define GetIoPending()         (_Globals_.ioPending)
#define GetTickPending()       (_Globals_.tickPending)
#define GetNameServerCreated() (_Globals_.nameServerCreated)
#define GetNameServerId()      (_Globals_.nameServerId)
#define GetHid()               (_Globals_.hid)
#define GetLid()               (_Globals_.lid)

#define SetNumbThreads(V)      (_Globals_.numbThreads = (V))
#define SetNumbReadyThreads(V) (_Globals_.numbReadyThreads = (V))
#define SetNumbSysThreads(V)   (_Globals_.numbSysThreads = (V))
#define SetIoPending(V)        (_Globals_.ioPending = (V))
#define SetTickPending(V)      (_Globals_.tickPending = (V))
#define SetNameServerCreated(V)(_Globals_.nameServerCreated = (V))
#define SetNameServerId(V)     (_Globals_.nameServerId = (V))
#define SetHid(V)              (_Globals_.hid = (V))
#define SetLid(V)              (_Globals_.lid = (V))

#endif /* RTTTYPES_H */
