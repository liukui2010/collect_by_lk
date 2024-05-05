/****************************************************************/
/*							        */
/* RttQueue.h							*/
/*							        */
/* Definitions used by produce/consumer queueing routines.	*/
/* The queue routines provide reporting features, so the	*/
/* producer can determine if the consumer is being starved	*/
/* or if the producer is flooding the consumer.  Non-blocking	*/
/* queues can also be created.					*/
/*							        */
/* Copyright 1994 The University of British Columbia		*/
/* No part of this code may be sold or used for commercial	*/
/* purposes without permission.					*/
/*							    	*/
/*							    DXF */
/****************************************************************/

/* 
  Protect against multiple inclusion
 */
#ifndef _RTTQ_H_
#define _RTTQ_H_

/*
  Queue status codes, returned to the consumer if the queue mode is Q_REPORT
  or as the status of an RttNewQueue
 */

#define RTTQOK		0
#define RTTQFAILED	-1
#define RTTQFULL	-2
#define RTTQEMPTY	-3

/*********************************************************************************************************

Queue modes
  
  RTTQDEFAULT		Default style queue, simple add/remove.  All you'll probably need.

  RTTQREPORT		Returns a status code (see above) to RttEnqueue so the producer can detect
  			the status of the queue.  Generally, the status will either be RTTQOK or
			RTTQEMPTY; if the queue is full, RttEnqueue will block and return RTTQOK
			when space becomes available (see below for nonblocking enqueue options).
			If the returned value is RTTQEMPTY, then *underflowCount will be set to 
			the number of times the consumer attempted to get an item from the queue 
			and found it empty before RttEnqueue was called	(this will be always be 1
			unless RTTQNBDEQ is set also).  If you don't care if your producer
			is faster than your consumer (or vice versa) you don't need RTTQREPORT.

  RTTQNBDEQ		Dequeue will not block if the queue is empty.  Instead, it returns RTTQEMPTY
  			immediately to RttDequeue.

  RTTQNBENQ		Enqueue will not block if the queue is full.  Instead, it returns RTTQFULL
  			immediately to RttEnqueue.

  RTTQOVERWRITEENQ 	Enqueue will not block if the queue is full.  Instead, it overwrites the last
  			item placed into the queue (multiple RttEnqueue() calls to a full
			RTTOVERWRITEENQ queue will write over the same element in the queue) and
			returns RTTQFULL.

The mode is set by doing a bitwise-or of the modes desired, as in

  status = RttNewQueue(somesize, &myQueue, RTTQNBDEQ | RTTQNBENQ | RTTQREPORT)

*********************************************************************************************************/

#define	RTTQDEFAULT		0x0l
#define RTTQREPORT		0x1l
#define	RTTQNBDEQ		0x2l
#define RTTQNBENQ		0x4l
#define RTTQOVERWRITEENQ	0x8l

typedef void *RttQueue;


/*
  Return a new queue of the given size and mode
 */

int RttNewQueue(RttQueue *queue, int size, int mode);


/*
  Reap (free up) the given queue, calling the cleaner routine on each item still
  in the queue.  If you don't want the items in the queue cleaned, pass NULL.

  Sample usage:

  RttReapQueue(myHappyQueue, NULL);
  RttReapQueue(myZippyQueue, RttFree);

  NOTE:  Don't call RttReapQueue() if threads are still trying to enqueue/dequeue
  items.
 */

int RttReapQueue(RttQueue queue, void(*cleaner)());


/*
  Dequeue an item from the given queue.  Normally blocks if the queue is empty, returning RTTQOK
  when an item is available.  If the queue is empty and the mode is RTTQNBDEQ, the
  thread will not block and RTTQEMPTY is returned.
 */

int RttDequeue(RttQueue queue, void **item);


/*
  Enqueue an item onto the given queue.  Normally blocks if the queue is full, returning RTTQOK
  when space is available.  If the mode is RTTQREPORT, the status returned may be RTTQEMPTY if a
  thread attempted to dequeue an item when none was available. *underflowCount is set to
  the number of times this happened since the last RttEnqueue().
 */

int RttEnqueue(RttQueue queue, void *item, int *underflowCount);

/*
   Pull off the last item placed onto the queue; sort of a
   "Whoops, give me that back" operation.
   Never blocks.  Returns RTTQOK if successful or RTTQEMPTY if the queue is empty.
  */
int RttUnqueue(RttQueue, void **item);

#endif
