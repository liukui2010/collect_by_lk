/*
 * GateD Releases Unicast, Multicast, IPv6, RSd
 *
 *	$Id: lrtimer.h,v 1.3 1999/11/26 19:11:29 chopps Exp $
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
 *
 * Low-resolution timers are optimized for ubiquitous usage.  That is
 * they try to minimize overhead when *many* items are to have timers.
 * This is done at the expense of some resolution.
 *
 * The user creates a lr_daemon_t object to manage lr_timer_ts.  The
 * daemon's creation requires an interval and the number of buckets
 * as well as a callback function for timer expiry
 *
 * The value `interval' * `number of buckets' specifies the maximum
 * timer value.  The resultion of the timer is `interval'
 * 
 * The implementation:
 *
 *	At `interval' seconds the daemon rotates to the next
 *	bucket, expiring all found timers.
 *
 *	When a user request a timer scheduling the time
 *	requested is divided by the `interval' the result
 *	is rounded to the nearest multiple of an `interval'
 *	and it is placed in the appropriate bucket.
 *
 *	Adjustments are made for an active timer that will fire
 *	in sometime less than `interval' seconds.
 *
 * Notes:
 *	The rotation is implemented very efficiently.  Each
 *	bucket requires 4 bytes so requesting 720 5 second intervals
 *	(thus with a maxtime of 1 hour) would require < 3k.
 *
 *
 * Written by Christian E. Hopps
 */

typedef struct _lr_timer_t {
	GQ_LINK(_lr_timer_t)	lt_link;
} lr_timer_t;

typedef struct _lr_step_desc_t {
	size_t	sd_ndivs;	/* number of ival's in a step */
	time_t	sd_ival;	/* the interval between divs */
} lr_step_desc_t;

typedef void *lr_daemon_t;

typedef	void (*lr_expire_func_t)(lr_timer_t *tp);

lr_daemon_t lr_daemon_create(task *, time_t , int, lr_expire_func_t);
void lr_daemon_delete(lr_daemon_t);
void lr_timer_cancel(lr_daemon_t, lr_timer_t *);
void lr_timer_schedule(lr_daemon_t, lr_timer_t *, time_t);

/*
 * these two macros are optional if you want to be able to check
 * for scheduling and/or cancel without schedule you need to make
 * their semantics work (either calling init or having zerod the
 * timer struct at init time)
 */

/* inidicate time is not scheduled */
#define lr_timer_init(tp)		((tp)->lt_link.gl_pnext = 0)
/* check to see if currently scheduled */
#define lr_timer_is_scheduled(tp)	((tp)->lt_link.gl_pnext != 0)
