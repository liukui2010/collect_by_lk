/*
 * Gated Release 4.x, 5.x, 6.x, 7.x
 *
 *	$Id: gqueue.h,v 1.11 1999/11/26 19:09:49 chopps Exp $
 */
/*
 * GateD Releases Unicast, Multicast, IPv6, RSd
 * 
 * Copyright (c) 1996,1997,1998,1999 
 * The Regents of the University of Michigan.
 * All Rights Reserved.
 * 
 * License to use, copy, modify, and distribute this software and its
 * documentation can be obtained from Merit Network, Inc. at the 
 * University of Michigan.
 * 
 * Merit GateD Consortium
 * Merit Network, Inc.
 * 4251 Plymouth Road, Suite C
 * Ann Arbor, MI 48105
 * 
 * THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE REGENTS OF THE
 * UNIVERSITY OF MICHIGAN AND MERIT DO NOT WARRANT THAT THE FUNCTIONS 
 * CONTAINED IN THE SOFTWARE WILL MEET LICENSEE'S REQUIREMENTS OR THAT 
 * OPERATION WILL BE UNINTERRUPTED OR ERROR FREE. The Regents of the
 * University of Michigan and Merit shall not be liable for any special, 
 * indirect, incidental or consequential damages with respect to any claim 
 * by Licensee or any third party arising from use of the software. 
 * GateD was originated and developed through release 3.0 by Cornell 
 * University and its collaborators.
 * 
 * Please send questions or comments to gated-people@gated.org.
 *
 * Please submit bugs, bug fixes, and enhancements using the send-pr(1) 
 * utility or via the web at 
 * www.gated.org/gated-web/support/html/report_prob.html.
 *
 * __END_OF_COPYRIGHT__
 */

/*
 * Written by Christian E. Hopps
 *
 * The idea for these queues was derived from the functionality provided
 * by BSD4.4. queue(3); however, the BSD source was not consulted in their
 * writing.
 */

/*
 * Simple Queues
 * ---------------
 */

/*
 * define a head structure
 */
#define	GQ_HEAD(headtype, linktype)	\
	struct headtype { struct linktype *gh_head; }

/*
 * init (i.e., zero, not needed if this has been done already)
 */
#define	GQ_INIT(hp)	do { (hp)->gh_head = 0; } while (0)

/*
 * define a link structure
 */

#define	GQ_LINK(linktype)			\
	struct {				\
		struct linktype *gl_next;	\
		struct linktype **gl_pnext;	\
	}
/*
 * get the first element form the head
 */
#define	GQ_FIRST(hp)	(hp)->gh_head

/*
 * get the next element from the element
 */
#define	GQ_NEXT(elmp, lf)	(elmp)->lf.gl_next

/*
 * true if head is empty
 */
#define	GQ_ISEMPTY(hp)	((hp)->gh_head == 0)

/*
 * remove the element from the list
 */
#define	GQ_REMOVE(elmp, lf)	do { 			\
		if ((elmp)->lf.gl_next)			\
			(elmp)->lf.gl_next->lf.gl_pnext	\
			    = (elmp)->lf.gl_pnext;	\
		*(elmp)->lf.gl_pnext = (elmp)->lf.gl_next;	\
	} while (0)

/*
 * add the element to the head of the list
 */
#define	GQ_ADDHEAD(hp, elmp, lf)	do {		\
		if (((elmp)->lf.gl_next = (hp)->gh_head))	\
			(hp)->gh_head->lf.gl_pnext = &(elmp)->lf.gl_next; \
		(elmp)->lf.gl_pnext = &(hp)->gh_head;	\
		(hp)->gh_head = (elmp);			\
	} while (0)

/*
 * add the element 'elmp' after the element 'lelmp' which is already
 * on the list
 */
#define	GQ_APPEND(lelmp, elmp, lf)	do {			\
		if (((elmp)->lf.gl_next = (lelmp)->lf.gl_next))	\
			(elmp)->lf.gl_next->lf.gl_pnext		\
			    = &(elmp)->lf.gl_next;		\
		(elmp)->lf.gl_pnext = &(lelmp)->lf.gl_next;	\
		(lelmp)->lf.gl_next = (elmp);			\
	} while (0)

/*
 * add the element 'elmp' before the element 'lelmp' which is already
 * on the list
 */
#define	GQ_PREPEND(lelmp, elmp, lf)	do {			\
		(elmp)->lf.gl_next = (lelmp);			\
		(elmp)->lf.gl_pnext = (lelmp)->lf.gl_pnext;	\
		(lelmp)->lf.gl_pnext = &(elmp)->lf.gl_next;	\
		*(elmp)->lf.gl_pnext = (elmp);			\
	} while (0)

/*
 * move the list of elements on `fromq' to `toq'
 */
#define GQ_MOVE(fromq, toq, lf)	do {				\
		if (((toq)->gh_head = (fromq)->gh_head))	\
			(toq)->gh_head->lf.gl_pnext = &(toq)->gh_head;	\
		(fromq)->gh_head = 0;				\
	} while (0)

/*
 * Tail Queues
 * ---------------
 */

/*
 * define a head structure
 */
#define GTQ_HEAD(headtype, linktype)		\
	struct headtype { 			\
		struct linktype *gtq_head; 	\
		struct linktype **gtq_tnext;	\
	}

#define GTQ_LINK(linktype)	\
	struct { struct linktype *gtl_next; struct linktype **gtl_pnext; }

/*
 * init the head structure
 */
#define GTQ_INIT(headp)	do {		\
		(headp)->gtq_head = 0;	\
		(headp)->gtq_tnext = &(headp)->gtq_head;	\
	} while (0)

/*
 * get the first or last elements
 */
#define GTQ_FIRST(headp)	((headp)->gtq_head)


/*
 * get the next element from the element
 */
#define	GTQ_NEXT(elmp, lf)	(elmp)->lf.gtl_next

/*
 * true if the queue is empty
 */
#define GTQ_ISEMPTY(headp)	\
	((void *)(headp)->gtq_head == 0)

/*
 * add an element to the head of the queue
 */
#define GTQ_ADDHEAD(hp, elmp, lf)	do {			\
		if (((elmp)->lf.gtl_next = (hp)->gtq_head) == 0)	\
			(hp)->gtq_tnext = &(elmp)->lf.gtl_next;	\
		else						\
			(elmp)->lf.gtl_next->lf.gtl_pnext = 	\
			    &(elmp)->lf.gtl_next;		\
		(elmp)->lf.gtl_pnext = &(hp)->gtq_head;		\
		(hp)->gh_head = (elmp);				\
	} while (0)

/*
 * add an element to the tail of the queue
 */
#define GTQ_ADDTAIL(hp, elmp, lf)	do {		\
		(elmp)->lf.gtl_next = 0;		\
		(elmp)->lf.gtl_pnext = (hp)->gtq_tnext;	\
		*(hp)->gtq_tnext = (elmp);		\
		(hp)->gtq_tnext = &(elmp)->lf.gtl_next;	\
	} while (0)

/*
 * add the element 'elmp' after the element 'lelmp' which is already
 * on the list
 */
#define	GTQ_APPEND(hp, lelmp, elmp, lf)	do {			\
		if (((elmp)->lf.gtl_next = (lelmp)->lf.gtl_next) == 0)	\
			(hp)->gtq_tnext = &(elmp)->lf.gtl_next;	\
		else						\
			(elmp)->lf.gtl_next->lf.gtl_pnext	\
			    = &(elmp)->lf.gtl_next;		\
		(elmp)->lf.gtl_pnext = &(lelmp)->lf.gtl_next;	\
		(lelmp)->lf.gtl_next = (elmp);			\
	} while (0)

/*
 * add the element 'elmp' before the element 'lelmp' which is already
 * on the list
 */
#define	GTQ_PREPEND(lelmp, elmp, lf)	do {			\
		(elmp)->lf.gtl_next = (lelmp);			\
		(elmp)->lf.gtl_pnext = (lelmp)->lf.gtl_pnext;	\
		(lelmp)->lf.gtl_pnext = &(elmp)->lf.gtl_next;	\
		*(elmp)->lf.gtl_pnext = (elmp);			\
	} while (0)

/*
 * remove the element from the queue
 */
#define GTQ_REMOVE(hp, elmp, lf)	do { \
		if ((elmp)->lf.gtl_next)			\
			(elmp)->lf.gtl_next->lf.gtl_pnext	\
			    = (elmp)->lf.gtl_pnext;		\
		else						\
			(hp)->gtq_tnext = (elmp)->lf.gtl_pnext;	\
		*(elmp)->lf.gtl_pnext = (elmp)->lf.gtl_next;	\
	} while (0)

/*
 * move the list of elements on `fromq' to `toq'
 */
#define GTQ_MOVE(fromq, toq, lf)	do {				\
		if (((toq)->gtq_head = (fromq)->gtq_head))	\
			(toq)->gtq_head->lf.gtl_pnext = &(toq)->gtq_head;	\
		(toq)->gtq_tnext = (fromq)->gtq_tnext;		\
		GTQ_INIT(fromq);				\
	} while (0)

/*
 * move the list in `fromq' to the tail of `toq'
 */
#define GTQ_SPLICETAIL(fromq, toq, lf) do {			\
		if ((*(toq)->gtq_tnext = (fromq)->gtq_head)) {	\
			(fromq)->gtq_head->lf.gtl_pnext = (toq)->gtq_tnext; \
			(toq)->gtq_tnext = (fromq)->gtq_tnext;	\
			GTQ_INIT(fromq);			\
		}						\
	} while (0)

/*
 * Circle Queues
 * ---------------
 */
/*
 * define a head structure
 */
#define GCQ_HEAD(headtype, linktype)		\
	struct headtype { 			\
		struct linktype *gcq_head; 	\
		struct linktype *gcq_tail;	\
	}

#define GCQ_LINK(linktype)	\
	struct { struct linktype *gcq_next; struct linktype *gcq_prev; }

/*
 * init the head structure
 */
#define GCQ_INIT(headp)	do {				\
		(headp)->gcq_head = (headp)->gcq_tail =	\
		    (void *)&(headp)->gcq_head;	\
	} while (0)

#define GCQ_END(headp, elmp) ((void *)(headp) == (void *)(elmp))

/*
 * get the first or last elements
 */
#define GCQ_FIRST(headp)	((headp)->gcq_head)
#define GCQ_LAST(headp)		((headp)->gcq_tail)

/*
 * get the next element from the element
 */
#define	GCQ_NEXT(elmp, lf)	((elmp)->lf.gcq_next)
#define	GCQ_PREV(elmp, lf)	((elmp)->lf.gcq_prev)

#define GCQ_ISEMPTY(headp)	((headp)->gcq_head == (void *)(headp))

#define GCQ_ADDHEAD(headp, elmp, lf)	do {			\
	(elmp)->lf.gcq_prev = (void *)(headp);			\
	if (((elmp)->lf.gcq_next = (headp)->gcq_head) != (void *)(headp)) \
		(headp)->gcq_head->lf.gcq_prev = (elmp);	\
	else							\
		(headp)->gcq_tail = (elmp);			\
	(headp)->gcq_head = (elmp);				\
    } while (0)

#define GCQ_ADDTAIL(headp, elmp, lf)	do {			\
	(elmp)->lf.gcq_next = (void *)(headp);			\
	if (((elmp)->lf.gcq_prev = (headp)->gcq_tail) != (void *)(headp)) \
		(headp)->gcq_tail->lf.gcq_next = (elmp);	\
	else							\
		(headp)->gcq_head = (elmp);			\
	(headp)->gcq_tail = (elmp);				\
    } while (0)

#define GCQ_APPEND(headp, lelmp, elmp, lf) do {			\
	if (((elmp)->lf.gcq_next = (lelmp)->lf.gcq_next) == (void *)(headp)) \
		(headp)->gcq_tail = (elmp);			\
	else							\
		(elmp)->lf.gcq_next->lf.gcq_prev = (elmp);	\
	(lelmp)->lf.gcq_next = (elmp);				\
	(elmp)->lf.gcq_prev = (lelmp);				\
    } while (0)

#define GCQ_INSERT(headp, lelmp, elmp, lf) do {			\
	if (((elmp)->lf.gcq_prev = (lelmp)->lf.gcq_prev) == (void *)(headp)) \
		(headp)->gcq_head = (elmp);			\
	else							\
		(elmp)->lf.gcq_prev->lf.gcq_next = (elmp);	\
	(lelmp)->lf.gcq_prev = (elmp);				\
	(elmp)->lf.gcq_next = (lelmp);				\
    } while (0)

#define GCQ_REMOVE(headp, elmp, lf)	do {				\
	if ((elmp)->lf.gcq_next == (void *)(headp))			\
		(headp)->gcq_tail = (elmp)->lf.gcq_prev;		\
	else								\
		(elmp)->lf.gcq_next->lf.gcq_prev = (elmp)->lf.gcq_prev; \
	if ((elmp)->lf.gcq_prev == (void *)(headp))			\
		(headp)->gcq_head = (elmp)->lf.gcq_next;		\
	else								\
		(elmp)->lf.gcq_prev->lf.gcq_next = (elmp)->lf.gcq_next; \
    } while (0)

