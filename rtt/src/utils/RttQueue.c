/****************************************************************/
/*							        */
/* RttQueue.c							*/
/*							        */
/* General purpose queuing routines.  Multiple producers and	*/
/* consumers supported.  Different queue types are available	*/
/* and described in RttQueue.h.					*/
/*							        */
/* Copyright 1994 The University of British Columbia		*/
/* No part of this code may be sold or used for commercial	*/
/* purposes without permission.					*/
/*							    	*/
/*							    DXF */
/****************************************************************/


#include "rtthreads.h"
#include "RttQueue.h"

static RttSchAttr	superAttr = {{0,0}, 0, {0,0}};


struct queueStruct		/* Queue data structure		   */
{
  int		size;		/* Size of the queue			    */
  RttSem	enqueueSem;	/* Counting semaphore for enqueue requests  */
  RttSem	dequeueSem;	/* Counting semaphore for dequeue requests  */
  RttSem	accessSem;	/* Needed to protect this structure	    */
  int		numItems;	/* Number of items currently in the queue   */
  int		status;		/* Status of the queue (EMPTY, etc.)	    */
  int		underflowCount;	/* # of times dequeu made with no items	    */
  int		mode;		/* Queue mode, see RttQueue.h		    */
  int		head;		/* Head element of the queue		    */
  int		tail;		/* Tail element of the queue		    */
  void		**elements;	/* Array of queue elements		    */
};

typedef struct queueStruct queueStruct;


int RttNewQueue(RttQueue *queue, int size, int mode)
{
  void		**elements;
  queueStruct	*newQueue;
  RttSem	enqueueSem;
  RttSem	dequeueSem;  
  RttSem	accessSem;
  int		status;
  
  if (size < 1)
  {
    printf("What are you, some kind of joker?  A %d sized queue?\n", size);
    return RTTQFAILED;
  }
  
  elements = (void **)RttMalloc(size * (sizeof(void *)));
  if (!elements)
  {
    printf("RttNewQueue: Cannot create queue of size %d\n", size);
    return RTTQFAILED;
  }
  
  newQueue = (queueStruct *)RttMalloc(sizeof(struct queueStruct));
  if (!newQueue) 
  {
    printf("RttNewQueue: Cannot create queue of size %d\n", size);
    return RTTQFAILED;
  }

  status = RttAllocSem(&enqueueSem, size, RTTFCFS);		    /* Probably ought to check the status	 */
  status = RttAllocSem(&dequeueSem, 0, RTTFCFS);
  status = RttAllocSem(&accessSem, 1, RTTFCFS);
  
  newQueue->size = size;
  newQueue->enqueueSem = enqueueSem;
  newQueue->accessSem = accessSem;
  newQueue->dequeueSem = dequeueSem;
  newQueue->numItems = 0;
  newQueue->status = RTTQOK;
  newQueue->underflowCount = 0;
  newQueue->mode = mode;
  newQueue->head = 0;
  newQueue->tail = 0;
  newQueue->elements = elements;

  *queue = newQueue;
  return RTTQOK;
}

    
int RttReapQueue(RttQueue queue, void (*cleaner)()) 
{
  queueStruct	*queuePtr = (queueStruct *)queue;
  
  if (cleaner != NULL)
  {
    for (;;)
    {
      if (queuePtr->tail == queuePtr->head)
      {
	break;
      }
      (cleaner)(queuePtr->elements[queuePtr->tail]);
      queuePtr->tail += 1;
      if (queuePtr->tail == queuePtr->size)
      {
	queuePtr->tail = 0;
      }
    }
  }    
  
  RttFreeSem(queuePtr->enqueueSem);
  RttFreeSem(queuePtr->dequeueSem);
  RttFreeSem(queuePtr->accessSem);
  RttFree(queuePtr->elements);
  RttFree(queuePtr);
  return RTTQOK;
}

int RttDequeue(RttQueue queue, void **item) 
{
  queueStruct	*queuePtr = (queueStruct *)queue;
  int		newTail;
  int		dequeueSemValue;
  RttSchAttr	origAttr;
  RttThreadId	me = RttMyThreadId();

  RttGetThreadSchedAttr(me, &origAttr);

  if ((queuePtr->mode & RTTQREPORT) || (queuePtr->mode & RTTQNBDEQ))	/* Check for nonblock, set underflowCount	 */
  {
    RttP(queuePtr->accessSem);
    RttSetThreadSchedAttr(me, superAttr);
    RttSemValue(queuePtr->dequeueSem, &dequeueSemValue);
    if (dequeueSemValue < 1)					    /* Any items actually in the queue?		 */
    {
      if (queuePtr->mode & RTTQREPORT)
      {
	queuePtr->status = RTTQEMPTY;				    /* Set status to RTTQEMPTY			 */
	queuePtr->underflowCount = queuePtr->underflowCount + 1;    /* Set underflowCount			 */
      }
      if (queuePtr->mode & RTTQNBDEQ) 
      {
	RttSetThreadSchedAttr(me, origAttr);
	RttV(queuePtr->accessSem);				    /* Just return if RTTQNBDEQ			 */
	return (RTTQEMPTY);
      }

      /*
	 There's nothing to dequeue now, but we block (we don't
	 return immediately), so we need to wait.  We need to
	 wait like any other thread, so we better release the
	 access semaphore and drop back to our regular priority.
       */
      RttV(queuePtr->accessSem);
      RttSetThreadSchedAttr(me, origAttr);
      RttP(queuePtr->dequeueSem);
      RttP(queuePtr->accessSem);
    }
    else
    {
      /* Grab the available item now, since there is something on the queue */
      RttP(queuePtr->dequeueSem);
      RttSetThreadSchedAttr(me, origAttr);
    }
  }
  else
  {
    RttP(queuePtr->dequeueSem);					    /* Try to dequeue an item			 */
    RttP(queuePtr->accessSem);
  }
  
  newTail = queuePtr->tail;
  *item = queuePtr->elements[newTail];
  queuePtr->numItems -= 1;
  newTail += 1;
  if (newTail == queuePtr->size) 
  {
    newTail = 0;
  }
  queuePtr->tail = newTail;
  RttV(queuePtr->enqueueSem);					    /* Let another thread enqueue an item	 */
  RttV(queuePtr->accessSem);
  return RTTQOK;
}


int RttEnqueue(RttQueue queue, void *item, int *underflowCount)
{
  queueStruct	*queuePtr = (queueStruct *)queue;  
  int		newHead;
  int		returnVal = RTTQOK;
  int		enqueueSemValue;
  RttSchAttr	origAttr;
  RttThreadId	me = RttMyThreadId();
  
  RttGetThreadSchedAttr(me, &origAttr);

  if ((queuePtr->mode & RTTQREPORT) || (queuePtr->mode & RTTQNBENQ) || (queuePtr->mode & RTTQOVERWRITEENQ)) 
  {
    RttP(queuePtr->accessSem);
    /*
      Reset the queue status to RTTQOK.  We do this here because we ourselves report
      if the status if RTTQFULL, and the dequeue routine will set the status to
      RTTQEMPTY if the queue is empty, and we'll catch that condition because we've
      already gotten the status in returnVal.
      underflowCount is also reset to zero, since we return it's old value.
     */
    returnVal = queuePtr->status;
    queuePtr->status = RTTQOK;
    *underflowCount = queuePtr->underflowCount;
    queuePtr->underflowCount = 0;
    RttSetThreadSchedAttr(me, superAttr);
    RttSemValue(queuePtr->enqueueSem, &enqueueSemValue);
    if (enqueueSemValue < 1)
    {
      if (queuePtr->mode & RTTQOVERWRITEENQ)
      {
	if ((newHead = queuePtr->head) == 0)
	  newHead = queuePtr->size - 1;
	queuePtr->elements[newHead] = item;
	RttSetThreadSchedAttr(me, origAttr);
	RttV(queuePtr->accessSem);
	return (RTTQFULL);
      }
      if (queuePtr->mode & RTTQNBENQ) 
      {
	RttSetThreadSchedAttr(me, origAttr);
	RttV(queuePtr->accessSem);
	return (RTTQFULL);
      }
      /*
	 No spots for our item, but we're just RTTQREPORT, so we
	 need to wait like any other thread.
       */
      RttV(queuePtr->accessSem);
      RttSetThreadSchedAttr(me, origAttr);
      RttP(queuePtr->enqueueSem);
      RttP(queuePtr->accessSem);
    }
    else
    {
      /* Grab the empty slot now, since there's a spot available */
      RttP(queuePtr->enqueueSem);
      RttSetThreadSchedAttr(me, origAttr);
    }
  }
  else
  {
    RttP(queuePtr->enqueueSem);
    RttP(queuePtr->accessSem);
  }
  
  newHead = queuePtr->head;
  queuePtr->elements[newHead] = item;
  queuePtr->numItems += 1;
  newHead += 1;
  if (newHead == queuePtr->size) 
  {
    newHead = 0;
  }
  queuePtr->head = newHead;
  RttV(queuePtr->dequeueSem);
  RttV(queuePtr->accessSem);
  return returnVal;
}


int RttUnqueue(RttQueue queue, void **item) 
{
  queueStruct	*queuePtr = (queueStruct *)queue;
  int		newHead;
  int		dequeueSemValue;
  RttSchAttr	origAttr;
  RttThreadId	me = RttMyThreadId();
  
  RttGetThreadSchedAttr(me, &origAttr);

  RttP(queuePtr->accessSem);
  RttSetThreadSchedAttr(me, superAttr);
  RttSemValue(queuePtr->dequeueSem, &dequeueSemValue);
  if (dequeueSemValue < 1)
  {
    RttSetThreadSchedAttr(me, origAttr);
    *item = NULL;
    RttV(queuePtr->accessSem);
    return RTTQEMPTY;
  }
  
  RttP(queuePtr->dequeueSem);
  RttSetThreadSchedAttr(me, origAttr);
  newHead = queuePtr->head - 1;
  if (newHead < 0)
  {
    newHead = (queuePtr->size - 1);
  }
  queuePtr->head = newHead;
  *item = queuePtr->elements[newHead];
  queuePtr->numItems -= 1;
  RttV(queuePtr->enqueueSem);
  RttV(queuePtr->accessSem);
  return RTTQOK;
}

