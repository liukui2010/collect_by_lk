/*************************************************
 * rtthreads.h
 *
 * Copyright 1994 The University of British Columbia
 * No part of this code may be sold or used for commercial
 * purposes without permission.	
 *
 */

/* Wed Jun 29 14:46:45 PDT 1994 <acton> 
 * protect against multiple inclusion

 * Fri June 21 17:57  CST 2002 <makaroff>
 * Added definitions to allow 64 bit offsets into files
 *************************************
 */


#ifndef _RTTHREADS_H
#define _RTTHREADS_H

#ifdef __cplusplus
extern "C" {
#endif

/* June 21, 2002 */
#define _FILE_OFFSET_BITS 64
#define __USE_FILE_OFFSET64


/*  rtthreads.h includes all necessary function prototypes */
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#ifdef ibm
#include <aio.h>
#endif
#ifdef solaris
#include <sys/asynch.h>
#endif


#include <signal.h>

#include "RttThreadId.h"  /* contains typedef for RttThreadId */


#define RTTTHREAD void

#ifdef sun4
#define memmove(x,y,z) memcpy((x),(y),(z))
#endif

#ifdef ASYNCIO
#ifdef ibm
#include <aio.h>
#else
#ifdef sun4
#include <sys/unistd.h>
#include <sys/asynch.h>
#else
#ifdef solaris
#include <sys/asynch.h>
#ifdef AIOWAIT
#undef AIOWAIT
#endif
#ifdef AIOREAD
#undef AIOREAD
#endif
#ifdef AIOWRITE
#undef AIOWRITE
#endif
#else
#undef ASYNCIO
#endif /* solaris */
#endif /* sun4 */
#endif /* ibm */
#endif /* ASYNCIO */




#ifdef WIN32
struct iovec {
	char   *iov_base;	/* base memory address			*/
	int	iov_len;	/* length of transfer for this area	*/
};
struct msghdr {
  char *msg_name;
  int msg_namelen;
  struct iovec *msg_iov;
  int msg_iovlen;
  char *msg_accrights;
  int msg_accrightslen;
};
#endif /* WIN32 */

/*------------------------------------------------------------------------*/


/* time representation */
typedef struct {
        unsigned long    seconds;
        unsigned long    microseconds;
} RttTimeValue;


typedef void *RttSem;

/* Structure for scheduling attributes for REAL-TIME SCHEDULING */

typedef struct {
  RttTimeValue       startingtime;
  int                priority;
  RttTimeValue       deadline;
} RttSchAttr;


/*
  AIO data types and definitons
*/
struct RttAIOPrivate
{
  struct RttAIOPrivate	*next;
  struct RttAIOList	*handle;
  void			*thread;
  void               *aioInfo;   /* opaque */
  int			result;     /* used only for Sun ASYNCIO */
  int			errNo;      /* used only for Sun ASYNCIO */
};
typedef struct RttAIOPrivate RttAIOPrivate;

typedef enum
{
  RTTAIOREAD, RTTAIOWRITE
} RttAIOType;

typedef enum
{
  RTTAIOERROR = -1,
  RTTAIOINPROGRESS = 0,
  RTTAIOCOMPLETED = 1
} RttAIOStatus;

typedef struct
{
  RttAIOType	iotype;
  off_t		offset;
  int		whence;
  int		numbytes;
  void		*buffer;
  int		fd;
  int		ioreturn;
  int		errNo;
  RttAIOStatus	status;
  RttAIOPrivate	aioPrivate;         /* used only for Sun ASYNCIO */
} RttAIOCommand;

struct RttAIOList
{
  RttAIOCommand		*commandList;
  int			numCommands;
  RttAIOStatus		status;
  RttAIOPrivate		aioPrivate;         /* used only for ibm ASYNCIO */
  int			commandsCompleted;  /* used only for Sun ASYNCIO */
};
typedef struct RttAIOList RttAIOList;


extern RttTimeValue     RTTNODEADLINE;   /* default deadline */
extern RttTimeValue     RTTINFINITE;     /* infinite starting time */
extern RttTimeValue     RTTZEROTIME;     /* default starting time of 0 */

/* semaphore types */
#define RTTFCFS     0
#define RTTPRIORITY 1

#define RTTOK              0
#define RTTFAILED          (-1)
/* send, receive, reply error codes  */
#define RTTNOSUCHTHREAD    (-2)  /* no such destination process  */
#define RTTNOTBLOCKED      (-3)

/* process priorities */
#define RTTHIGH  10  /*  high priority     */
#define RTTNORM  20 /*  normal priority   */
#define RTTLOW   30 /*  low priority      */


#define RTTSYS  1
#define RTTUSR  0

#ifndef WIN32
#ifndef AIX_PTHREADS
#ifdef PTRACE
#define exit(X) {PTraceEnd_(); RttBeginCritical(); fflush(stdout); exit(X);}
#else
#define exit(X) {RttBeginCritical(); fflush(stdout); exit(X);}
#endif
#endif
#endif /* WIN32 */

int RttGetThreadSchedAttr(RttThreadId, RttSchAttr *);
int RttSetThreadSchedAttr(RttThreadId, RttSchAttr) ;


int RttSend(RttThreadId, void *, unsigned int, void *, unsigned int *);
int RttMsgWaits();
int RttReceive(RttThreadId *, void *, unsigned int *);
int RttReply(RttThreadId, void *, unsigned int);

RttThreadId RttMyThreadId();
int RttNameToThreadId(RttThreadId *, char *);
int RttThreadExists(RttThreadId);
int RttKill(RttThreadId);
void RttExit();
int RttCreate(RttThreadId *, void(*)(), int, char *, void *, RttSchAttr, int);
int RttP(RttSem);
int RttV(RttSem);
int RttAllocSem(RttSem *, int, int);
#define RttNewSem(S,V) RttAllocSem(S,V,RTTFCFS)  /* backward compat */
int RttSemValue(RttSem, int *);
int RttFreeSem(RttSem);
int RttCreateNS(RttThreadId *,void(*)(), int, char *, void *, RttSchAttr, int);
int RttGetNS(unsigned long, unsigned short, RttThreadId *);
int RttGetData(RttThreadId, unsigned long *);
int RttSetData(RttThreadId, unsigned long);
int RttGetTimeOfDay(RttTimeValue *);
int RttNetInit(unsigned long, unsigned short);
int RttMyPort(unsigned short *);
int RttMyIP(unsigned long *);

int RttRegisterExitRoutine(void (*)());

void *RttMalloc(int);
void RttFree(void *);
void *RttRealloc(void *, int);
void *RttCalloc(int, int);

void RttBeginCritical(void);
void RttEndCritical(void);

int RttOpen(char *, int, ...);
int RttPipe(int *);
int RttSocket(int, int, int);
int RttClose(int);
int RttGetsockopt(int, int, int, char *, int *);
int RttSetsockopt(int, int, int, char *, int);
int RttGetsockname(int, struct sockaddr *, int *);
int RttListen(int, int);
int RttBind(int, struct sockaddr *, int);
int RttAccept(int, struct sockaddr *, int *);
int RttConnect(int, struct sockaddr *, int);
int RttSeekNRead(int, char *, int, int, int);
int RttRead(int, char *, int);
int RttRecvfrom(int, char *, int, int, struct sockaddr *, int *);
int RttSendto(int, char *, int, int, struct sockaddr *, int);
int RttRecvmsg(int, struct msghdr *, int);
int RttSendmsg(int, struct msghdr *, int);
int RttSeekNWrite(int, char *, int, int,int);
int RttWrite(int, char *, int);
#ifdef ASYNCIO
int RttAIORequest(RttAIOList *);
int RttAIOWait(RttAIOList *[], int);
#endif

/*------------------------------------------------------------------------
 * Debugging.
 *------------------------------------------------------------------------
 */

void RttMemPrint();
void RttQueuePrint();
void RttStartClock();
void RttStopClock();

#ifdef RTT_MEM_DEBUG
void *RttDebugMalloc(int, char *, int);
void *RttDebugRealloc(void *, int, char *, int);
void *RttDebugCalloc(int, int, char *, int);
void RttDebugFree(void *, char *, int);
#define RttMalloc(X) RttDebugMalloc(X,__FILE__,__LINE__)
#define RttCalloc(X,Y) RttDebugCalloc(X,Y,__FILE__,__LINE__)
#define RttRealloc(X,Y) RttDebugRealloc(X,Y,__FILE__,__LINE__)
#define RttFree(X) RttDebugFree(X,__FILE__,__LINE__)
#endif /* RTT_MEM_DEBUG */


#define TRACE_INC(X) {(X) = ((X)+1) % _MaxRttTraces_;}

#ifdef USE_RTTTRACING
#define RttTrace(f) { \
	  static char *__RttTraceStr__ = f;\
	  _RttTrace_[_RttTracer_].format = __RttTraceStr__;\
	  TRACE_INC(_RttTracer_);}

#define RttTrace1(f,v1) { \
	  static char *__RttTraceStr__ = f;\
	  _RttTrace_[_RttTracer_].format = __RttTraceStr__;\
	  _RttTrace_[_RttTracer_].val1 = v1;\
	  TRACE_INC(_RttTracer_);}

#define RttTrace2(f,v1,v2) { \
	  static char *__RttTraceStr__ = f;\
	  _RttTrace_[_RttTracer_].format = __RttTraceStr__;\
	  _RttTrace_[_RttTracer_].val1 = v1;\
	  _RttTrace_[_RttTracer_].val2 = v2;\
	  TRACE_INC(_RttTracer_);}

#define RttTrace3(f,v1,v2,v3) { \
	  static char *__RttTraceStr__ = f;\
	  _RttTrace_[_RttTracer_].format = __RttTraceStr__;\
	  _RttTrace_[_RttTracer_].val1 = v1;\
	  _RttTrace_[_RttTracer_].val2 = v2;\
	  _RttTrace_[_RttTracer_].val3 = v3;\
	  TRACE_INC(_RttTracer_);}

#define RttTrace4(f,v1,v2,v3,v4) { \
	  static char *__RttTraceStr__ = f;\
	  _RttTrace_[_RttTracer_].format = __RttTraceStr__;\
	  _RttTrace_[_RttTracer_].val1 = v1;\
	  _RttTrace_[_RttTracer_].val2 = v2;\
	  _RttTrace_[_RttTracer_].val3 = v3;\
	  _RttTrace_[_RttTracer_].val4 = v4;\
	  TRACE_INC(_RttTracer_);}

#define RttTrace5(f,v1,v2,v3,v4,v5) { \
	  static char *__RttTraceStr__ = f;\
	  _RttTrace_[_RttTracer_].format = __RttTraceStr__;\
	  _RttTrace_[_RttTracer_].val1 = v1;\
	  _RttTrace_[_RttTracer_].val2 = v2;\
	  _RttTrace_[_RttTracer_].val3 = v3;\
	  _RttTrace_[_RttTracer_].val4 = v4;\
	  _RttTrace_[_RttTracer_].val5 = v5;\
	  TRACE_INC(_RttTracer_);}

#define RttTrace6(f,v1,v2,v3,v4,v5,v6) { \
	  static char *__RttTraceStr__ = f;\
	  _RttTrace_[_RttTracer_].format = __RttTraceStr__;\
	  _RttTrace_[_RttTracer_].val1 = v1;\
	  _RttTrace_[_RttTracer_].val2 = v2;\
	  _RttTrace_[_RttTracer_].val3 = v3;\
	  _RttTrace_[_RttTracer_].val4 = v4;\
	  _RttTrace_[_RttTracer_].val5 = v5;\
	  TRACE_INC(_RttTracer_);\
	  _RttTrace_[_RttTracer_].format = NULL;\
	  _RttTrace_[_RttTracer_].val1 = v6;\
	  TRACE_INC(_RttTracer_);}

#define RttTrace7(f,v1,v2,v3,v4,v5,v6,v7) { \
	  static char *__RttTraceStr__ = f;\
	  _RttTrace_[_RttTracer_].format = __RttTraceStr__;\
	  _RttTrace_[_RttTracer_].val1 = v1;\
	  _RttTrace_[_RttTracer_].val2 = v2;\
	  _RttTrace_[_RttTracer_].val3 = v3;\
	  _RttTrace_[_RttTracer_].val4 = v4;\
	  _RttTrace_[_RttTracer_].val5 = v5;\
	  TRACE_INC(_RttTracer_);\
	  _RttTrace_[_RttTracer_].format = NULL;\
	  _RttTrace_[_RttTracer_].val1 = v6;\
	  _RttTrace_[_RttTracer_].val2 = v7;\
	  TRACE_INC(_RttTracer_);}

#define RttTrace8(f,v1,v2,v3,v4,v5,v6,v7,v8) { \
	  static char *__RttTraceStr__ = f;\
	  _RttTrace_[_RttTracer_].format = __RttTraceStr__;\
	  _RttTrace_[_RttTracer_].val1 = v1;\
	  _RttTrace_[_RttTracer_].val2 = v2;\
	  _RttTrace_[_RttTracer_].val3 = v3;\
	  _RttTrace_[_RttTracer_].val4 = v4;\
	  _RttTrace_[_RttTracer_].val5 = v5;\
	  TRACE_INC(_RttTracer_);\
	  _RttTrace_[_RttTracer_].format = NULL;\
	  _RttTrace_[_RttTracer_].val1 = v6;\
	  _RttTrace_[_RttTracer_].val2 = v7;\
	  _RttTrace_[_RttTracer_].val3 = v8;\
	  TRACE_INC(_RttTracer_);}

#define RttTrace9(f,v1,v2,v3,v4,v5,v6,v7,v8,v9) { \
	  static char *__RttTraceStr__ = f;\
	  _RttTrace_[_RttTracer_].format = __RttTraceStr__;\
	  _RttTrace_[_RttTracer_].val1 = v1;\
	  _RttTrace_[_RttTracer_].val2 = v2;\
	  _RttTrace_[_RttTracer_].val3 = v3;\
	  _RttTrace_[_RttTracer_].val4 = v4;\
	  _RttTrace_[_RttTracer_].val5 = v5;\
	  TRACE_INC(_RttTracer_);\
	  _RttTrace_[_RttTracer_].format = NULL;\
	  _RttTrace_[_RttTracer_].val1 = v6;\
	  _RttTrace_[_RttTracer_].val2 = v7;\
	  _RttTrace_[_RttTracer_].val3 = v8;\
	  _RttTrace_[_RttTracer_].val4 = v9;\
	  TRACE_INC(_RttTracer_);}

#define RttTrace10(f,v1,v2,v3,v4,v5,v6,v7,v8,v9,v10) { \
	  static char *__RttTraceStr__ = f;\
	  _RttTrace_[_RttTracer_].format = __RttTraceStr__;\
	  _RttTrace_[_RttTracer_].val1 = v1;\
	  _RttTrace_[_RttTracer_].val2 = v2;\
	  _RttTrace_[_RttTracer_].val3 = v3;\
	  _RttTrace_[_RttTracer_].val4 = v4;\
	  _RttTrace_[_RttTracer_].val5 = v5;\
	  TRACE_INC(_RttTracer_);\
	  _RttTrace_[_RttTracer_].format = NULL;\
	  _RttTrace_[_RttTracer_].val1 = v6;\
	  _RttTrace_[_RttTracer_].val2 = v7;\
	  _RttTrace_[_RttTracer_].val3 = v8;\
	  _RttTrace_[_RttTracer_].val4 = v9;\
	  _RttTrace_[_RttTracer_].val5 = v10;\
	  TRACE_INC(_RttTracer_);}
#else
#define RttTrace(f) 
#define RttTrace1(f,v1) 
#define RttTrace2(f,v1,v2) 
#define RttTrace3(f,v1,v2,v3) 
#define RttTrace4(f,v1,v2,v3,v4) 
#define RttTrace5(f,v1,v2,v3,v4,v5) 
#define RttTrace6(f,v1,v2,v3,v4,v5,v6) 
#define RttTrace7(f,v1,v2,v3,v4,v5,v6,v7) 
#define RttTrace8(f,v1,v2,v3,v4,v5,v6,v7,v8) 
#define RttTrace9(f,v1,v2,v3,v4,v5,v6,v7,v8,v9) 
#define RttTrace10(f,v1,v2,v3,v4,v5,v6,v7,v8,v9,v10) 
#endif /* USE_RTTTRACING */

#define RTTSTDOUT "RTTSTDOUT"
#define RTTSTDERR "RTTSTDERR"

typedef struct {
  char *format;
  int val1;
  int val2;
  int val3;
  int val4;
  int val5;
} RttTraceStruct;

extern RttTraceStruct *_RttTrace_;
extern int _MaxRttTraces_;
extern int _RttTracer_;

#define RttTraceInit RttTraceOpen  /* XXX for backward compatibility */
int RttTraceOpen(char *filename, int size);
int RttTraceDump();
int RttTraceClose();

#ifdef __cplusplus
}
#define mainp extern "C" void mainp
#endif

#endif /* _RTTHREADS_H */
