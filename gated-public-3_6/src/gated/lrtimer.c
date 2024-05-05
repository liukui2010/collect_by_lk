/*
 * GateD Releases Unicast, Multicast, IPv6, RSd
 * 
 *	$Id: lrtimer.c,v 1.4 2000/01/12 23:13:50 chopps Exp $
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
 * See lrtimer.h for a description of the overall algorithm.
 *
 * Written by Christian E. Hopps
 */

#define	INCLUDE_STDDEF
#include "include.h"
#include "gqueue.h"
#include "lrtimer.h"

/*
 * -----------------------------------------------------
 *      Local Types
 * -----------------------------------------------------
 */
typedef GQ_HEAD(,_lr_timer_t)	bucket_t;

/*
 * the internal representation of the lr_daemon_t
 *
 * note we try to force locality of reference, everything modified
 * by the timer job is next to each other
 *
 * special meanings:
 *	d_expirenext -- is used while walking the expire bucket in
 *	the timer, if we get a cancel this keeps things working
 *	we also know we are processing if this is true.
 *
 *	d_nbucket -- if this is set to zero while we are expiring
 *	in the timer, the timer will delete the daemon.
 */
typedef struct _daemon_t {
	task_timer		*d_timer;	/* the interval timer */
	lr_expire_func_t 	d_funcp;	/* the expire function */
	task		*d_task;	/* owning task */
	time_t		d_maxtime;	/* maximum timer value */
	time_t		d_ival;		/* the interval time */
	u_int		d_nactive;	/* number of active timers */
	lr_timer_t	*d_expirenext;	/* next to be expired -- in timer */
	size_t		d_nbucket;	/* number of step_ts in d_step array */
	size_t		d_zbucket;	/* bucket that represents 0 */
	bucket_t	d_bucket[1];	/* array of step_ts */
} daemon_t;

static void daemon_timer_job(task_timer *, time_t);

/*
 * -----------------------------------------------------
 *      Local Functions
 * -----------------------------------------------------
 */

/*
 * the rotate timer job -- as much as possible has been done to
 * 	keep the overhead as low as possible for this.
 *	especially if we won't be doing any expiring
 */
static void
daemon_timer_job(task_timer *tasktimerp, time_t offset)
{
	lr_timer_t *tp;
	daemon_t *dp;
	u_int ebi;

	dp = (daemon_t *)tasktimerp->task_timer_data;

	/* inflate this to keep from flapping */
	++dp->d_nactive;

	/* rotate */
	ebi = dp->d_zbucket;
	dp->d_zbucket = (ebi + 1) % dp->d_nbucket;

	/*
	 * expire if we have any -- be careful to allow insertion on this bucket
	 */
	dp->d_expirenext = GQ_FIRST(&dp->d_bucket[ebi]);
	while ((tp = dp->d_expirenext)) {
		dp->d_expirenext = GQ_NEXT(tp, lt_link);
		GQ_REMOVE(tp, lt_link);
		lr_timer_init(tp);
		--dp->d_nactive;
		(*dp->d_funcp)(tp);

		/* see if we were deleted during callback */
		if (dp->d_nbucket == 0) {
			dp->d_expirenext = 0;
			lr_daemon_delete(dp);
			return;
		}
	}

	/* deflate the active and reset timer if needed */
	if (--dp->d_nactive == 0)
		task_timer_reset(dp->d_timer);
}

/*
 * -----------------------------------------------------
 *      Globals Fucntions
 * -----------------------------------------------------
 */

/*
 * create a daemon object
 */
lr_daemon_t
lr_daemon_create(task *tp, time_t ival, int nvals, lr_expire_func_t fp)
{
	daemon_t *dp;

	dp = task_mem_malloc(tp,
	    sizeof(daemon_t) + sizeof(bucket_t) * (nvals - 1));
	
	/* initialize the daemon object */
	dp->d_funcp = fp;
	dp->d_task = tp;
	dp->d_maxtime = ival * nvals;
	dp->d_nactive = 0;
	dp->d_expirenext = 0;
	dp->d_nbucket = nvals;
	dp->d_zbucket = 0;
	dp->d_ival = ival;

	/* this assumes we are using GQ lists */
	memset(dp->d_bucket, 0, sizeof(bucket_t) * nvals);

	/* create the interval timer -- inactive */
	dp->d_timer = task_timer_create(tp, "lr_daemon_t", 0, 0, 0,
	    daemon_timer_job, dp);

	return ((lr_daemon_t)dp);
}

/*
 * delete a daemon object
 */
void
lr_daemon_delete(lr_daemon_t udp)
{
	daemon_t *dp;
	task *tp;

	if ((dp = (daemon_t *)udp) == 0)
		return;

	/* if we were deleted while expiring, have the expiry function do it */
	if (dp->d_expirenext) {
		/* indicate delete needed and return */
		dp->d_nbucket = 0;
		return;
	}

	tp = dp->d_task;
	task_timer_delete(dp->d_timer);

	/* delete our chunk of memory */
	task_mem_free(tp, dp);
}

/*
 * cancel a previously scheduled timer
 */
void
lr_timer_cancel(lr_daemon_t udp, lr_timer_t *tp)
{
	daemon_t *dp;

	if ((dp = (daemon_t *)udp) == 0)
		return;

	/* check to see if not active */
	if (!lr_timer_is_scheduled(tp))
		return;

	GASSERT(dp->d_nactive);

	/* if we are deleting the next to expire forward that walk */
	if (dp->d_expirenext == tp)
		dp->d_expirenext = GQ_NEXT(tp, lt_link);

	GQ_REMOVE(tp, lt_link);
	lr_timer_init(tp);

	if (--dp->d_nactive == 0)
		task_timer_reset(dp->d_timer);
}

/*
 * schedule an lr_timer_t object
 *
 * if we are currently inactive reset the zbuckets as we find
 * the appropiate insertion location.
 */
void
lr_timer_schedule(lr_daemon_t udp, lr_timer_t *tp, time_t tval)
{
	task_timer *tip;
	daemon_t *dp;
	u_int which;

	dp = (daemon_t *)udp;
	tip = dp->d_timer;

	/*
	 * if we aren't active initialize our zbucket otherwise
	 * possibly adjust the requested time val by the current
	 * remaining time till the interval timer fires
	 *
	 * note: since we aren't multithreaded (XXX) the only way we
	 * can be entered while processing a timer is if we were
	 * called while we were expiring.
	 */
	if (!dp->d_nactive)
		dp->d_zbucket = 0;
	else if (dp->d_expirenext) {
		time_t nexttime, addtime;
		/*
		 * our interval timer is active and hasn't fired
		 * adjust the time up by the amount left in our
		 * interval.  I.e,. the interface we present is
		 * that if you request ival secs you will get
		 * at least that much, this makes sure of this
		 */
		nexttime = tip->task_timer_next_time;
		if (nexttime <= time_sec)
			addtime	= dp->d_ival;
		else {
			addtime = nexttime - time_sec;
			/* sanity check */
			if (addtime > dp->d_ival)
				addtime = 0;
			else
				addtime = dp->d_ival - addtime;
		}
		tval += addtime;
	}

	/* if the given timer value exceeds max time truncate */
	if (tval > dp->d_maxtime)
		tval = dp->d_maxtime;

	/* if the given timer value is less than min resolution round up */
	if (tval < dp->d_ival)
		tval = dp->d_ival;

	/* link into appropriate bucket */
	which = (tval / dp->d_ival) - 1;
	GASSERT(which < dp->d_nbucket);
	which = (dp->d_zbucket + which) % dp->d_nbucket;
	GQ_ADDHEAD(&dp->d_bucket[which], tp, lt_link);

	/* increment active counters possibly starting the timer */
	if (++dp->d_nactive == 1)
		task_timer_set(dp->d_timer, dp->d_ival, 0);
}
