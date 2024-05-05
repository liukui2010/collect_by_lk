/****************************************************************/
/*							        */
/* RttBarrier.c							*/
/* Simple barrier, implemented as a high-priority thread	*/
/* which accepts RttSend() messages from threads and then	*/
/* does an RttReply() to each one when all threads have		*/
/* checked in.  The thread must be high priority since we want	*/
/* to ensure that all the threads which checked in will be	*/
/* ready to run once this thread blocks itself again.  Due	*/
/* to the nature of the barrier, if we were of a lower priority */
/* than the other threads, the highest priority thread which 	*/
/* checked in may not run until after many of the other threads */
/* which checked in get a chance to run.			*/
/*							    	*/
/* Copyright 1994 The University of British Columbia		*/
/* No part of this code may be sold or used for commercial	*/
/* purposes without permission.					*/
/*							    	*/
/*							    DXF */
/****************************************************************/

#include <stdio.h>
#include "rtthreads.h"
#include "RttBarrier.h"
#include "RttCommon.h"

#define BARRIERMAGICNUM		0xDAFACADEUL

struct barrierStruct
{
  unsigned long	magic;
  int		barrierSize;
  int		arraySize;
  int		status;
  int		numThreadsWaiting;
  RttThreadId	*waitingThreads;
};

typedef struct barrierStruct barrierStruct;

static RttSchAttr	superAttr = {{0,0}, 0, {0,0}};


int RttNewBarrier(RttBarrier *barrier, int size)
{
  barrierStruct	*newBarrier;
  RttThreadId	*waitingThreads;

  if (size < 0) return RTTFAILED;
  
  newBarrier = (barrierStruct *)RttMalloc(sizeof(barrierStruct));
  if (newBarrier == NULL)
    return RTTFAILED;
  newBarrier->barrierSize = size;
  newBarrier->arraySize = size;
  if (size)
  {
    waitingThreads = (RttThreadId *)RttMalloc(sizeof(RttThreadId) * size);
    if (waitingThreads == NULL)
    {
      RttFree(newBarrier);
      return RTTFAILED;
    }
  }
  else
  {
    waitingThreads = NULL;
  }
  newBarrier->waitingThreads = waitingThreads;
  newBarrier->status = RTTOK;
  newBarrier->numThreadsWaiting = 0;
  newBarrier->magic = BARRIERMAGICNUM;
  *barrier = (RttBarrier)newBarrier;
  return RTTOK;
}


  
int RttWaitOnBarrier(RttBarrier barrier, int status)
{
  RttSchAttr	origAttr;
  RttThreadId	me = RttMyThreadId();
  barrierStruct *barrierData = (barrierStruct *)barrier;
  int		lc;
  int		retVal;
  
  RttGetThreadSchedAttr(me, &origAttr);
  RttSetThreadSchedAttr(me, superAttr);
  if (barrierData->magic != BARRIERMAGICNUM)
  {
    RttSetThreadSchedAttr(me, origAttr);
    return RTTFAILED;
  }
  if (barrierData->barrierSize < 2)
  {
    RttSetThreadSchedAttr(me, origAttr);
    return status;
  }
  
  if (status != RTTOK)
  {
    barrierData->status = RTTFAILED;
  }
  
  if (barrierData->barrierSize == (barrierData->numThreadsWaiting + 1))
  {
    for (lc = 0; lc < barrierData->numThreadsWaiting; lc++)
    {
      RttResume(barrierData->waitingThreads[lc]);
    }
    barrierData->numThreadsWaiting = 0;
  }
  else
  {
    barrierData->waitingThreads[barrierData->numThreadsWaiting] = me;
    if (barrierData->numThreadsWaiting == 0)
    {
      barrierData->status = status;
    }
    barrierData->numThreadsWaiting++;
    RttSuspend();
  }
  retVal = barrierData->status;
  RttSetThreadSchedAttr(me, origAttr);
  return retVal;
}

  
int RttReapBarrier(RttBarrier barrier)
{
  barrierStruct	*barrierData = (barrierStruct *)barrier;
  RttSchAttr	origAttr;
  RttThreadId	me = RttMyThreadId();

  RttGetThreadSchedAttr(me, &origAttr);
  RttSetThreadSchedAttr(me, superAttr);
  if ((barrierData->magic != BARRIERMAGICNUM) || (barrierData->numThreadsWaiting != 0))
  {
    RttSetThreadSchedAttr(me, origAttr);
    return RTTFAILED;
  }
 
  barrierData->magic = 0;
  if (barrierData->waitingThreads != NULL)
  {
    RttFree((char *)barrierData->waitingThreads);
  }
  RttFree((char *)barrierData);
  RttSetThreadSchedAttr(me, origAttr);
  return RTTOK;
}



int RttGrowBarrier(RttBarrier barrier)
{
  barrierStruct	*barrierData = (barrierStruct *)barrier;
  RttSchAttr	origAttr;
  RttThreadId	me = RttMyThreadId();
  
  RttGetThreadSchedAttr(me, &origAttr);
  RttSetThreadSchedAttr(me, superAttr);
  if (barrierData->magic != BARRIERMAGICNUM)
  {
    RttSetThreadSchedAttr(me, origAttr);
    return RTTFAILED;
  }
  
  barrierData->barrierSize++;
  if (barrierData->barrierSize > barrierData->arraySize)
  {
    RttThreadId	*newArray;
    
    newArray = (RttThreadId *)RttMalloc(sizeof(RttThreadId) * barrierData->barrierSize);
    if (barrierData->arraySize)
    {
      memcpy(newArray, barrierData->waitingThreads, (barrierData->arraySize * sizeof(RttThreadId)));
      RttFree(barrierData->waitingThreads);
    }
    barrierData->arraySize = barrierData->barrierSize;
    barrierData->waitingThreads = newArray;
  }
  RttSetThreadSchedAttr(me, origAttr);
}



int RttShrinkBarrier(RttBarrier barrier)
{
  barrierStruct	*barrierData = (barrierStruct *)barrier;
  RttSchAttr	origAttr;
  RttThreadId	me = RttMyThreadId();
  int		lc;

  RttGetThreadSchedAttr(me, &origAttr);
  RttSetThreadSchedAttr(me, superAttr);
  if (barrierData->magic != BARRIERMAGICNUM)
  {
    RttSetThreadSchedAttr(me, origAttr);
    return RTTFAILED;
  }
  if (barrierData->barrierSize == 0)
  {
    RttSetThreadSchedAttr(me, origAttr);
    return RTTFAILED;
  }    
  barrierData->barrierSize--;
  if (barrierData->barrierSize == barrierData->numThreadsWaiting)
  {
    for (lc = 0; lc < barrierData->numThreadsWaiting; lc++)
    {
      RttResume(barrierData->waitingThreads[lc]);
    }
  }
  RttSetThreadSchedAttr(me, origAttr);
  return RTTOK;
}

