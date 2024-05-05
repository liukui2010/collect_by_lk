/****************************************************************************
 * 
 * rttqueuemgmt.h
 * 
 * Queue management header file.
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

#ifndef RTTQUEUEMGMT_H
#define RTTQUEUEMGMT_H

#define NEXT(P)   (GetNext(P))
#define PREV(P)   (GetPrev(P))

#define QUEUE_EMPTY(q)  ((q).next == TNULL)

#define QUEUE_INIT(q)  ((q).next = (q).prev = TNULL)

#define QUEUE_HEAD(q)  ((q).next)

#define QUEUE_FIRST(qhead) \
    (((qhead).next == TNULL) ? TNULL : (qhead).next)

#define QUEUE_LAST(qhead) \
    (((qhead).prev == TNULL) ? TNULL : (qhead).prev)

#define QUEUE_NEXT(item, qlink) \
    (((item)->qlink.next == TNULL) ? TNULL : (item)->qlink.next)

#define QUEUE_PREV(item, qlink) \
    (((item)->qlink.prev == TNULL) ? TNULL : (item)->qlink.prev)

#define ENQUEUE_HEAD(qhead, item, item_type, qlink,qstate)	\
{								\
    void *next = (qhead).next;					\
    if ( next == TNULL )	(qhead).prev = item;		\
    else ((item_type *) next)->qlink.prev = (void *) item;      \
								\
    item->qlink.next = next;                                    \
    item->qlink.prev = TNULL;		                        \
    (qhead).next = item;					\
    item->qlink.queue = qstate;                                 \
}

#define ENQUEUE_TAIL(qhead, item, item_type, qlink,qstate)	\
{								\
    void *prev = (qhead).prev;					\
    if ( prev == TNULL )	(qhead).next = item;            \
    else ((item_type*) prev)->qlink.next = (void *) (item);     \
								\
    (item)->qlink.prev = prev;	                                \
    (item)->qlink.next = TNULL;		                        \
    (qhead).prev = item;					\
    item->qlink.queue = qstate;                                 \
}

/* insert "item" directly before "next_item" in list.	*/
/* "next_item" must not be the head or tail item!!!	*/
#define ENQUEUE_ITEM(item, next_item, item_type, qlink,qstate)	\
{								\
    register void *prev = (next_item)->qlink.prev;		\
								\
    (item)->qlink.next = (void *) next_item;			\
    (item)->qlink.prev = (void *) prev;				\
								\
    ((item_type *) prev)->qlink.next = (void *) (item);		\
    (next_item)->qlink.prev = (void *) (item);			\
    item->qlink.queue = qstate;                                 \
}

/* dequeues an item from the head of the queue */
#define DEQUEUE_HEAD(qhead, item, item_type, qlink)             \
{								\
    register void *next;					\
								\
    next = (item = (item_type*) (qhead).next)->qlink.next;	\
								\
    if ( next == TNULL )	(qhead).prev = TNULL;           \
    else ((item_type*) next)->qlink.prev = TNULL;               \
								\
    (qhead).next = next;					\
    item->qlink.queue = NOQ;                                    \
}
	
/* dequeues an item from anywhere in the queue */
#define DEQUEUE_ITEM(qhead, item, item_type, qlink)	        \
{								\
    register void *next, *prev;					\
    								\
    next = (item)->qlink.next;					\
    prev = (item)->qlink.prev;					\
								\
    if ( TNULL == next )	(qhead).prev = prev;		\
    else ((item_type *) next)->qlink.prev = prev;		\
								\
    if ( TNULL == prev )	(qhead).next = next;		\
    else ((item_type *) prev)->qlink.next = next;	        \
    item->qlink.queue = NOQ;                                    \
}

#define QMGMTTCBINIT( tcb )                                     \
    {                                                           \
    SetPrev( tcb, TNULL );                                      \
    SetNext( tcb, TNULL );                                      \
    }

#define FindThreadOnQ_(q,t) \
  ((TCBINRANGE(t) && GetInUse(t) && (GetQueue(t) == q)) ? t : TNULL)

#endif /* RTTQUEUEMGMT_H */
