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
 * ------------------------------------------------------------------------
 *
 *      Copyright (c) 1990,1991,1992,1993,1994,1995 by Cornell University.
 *          All rights reserved.
 *
 *      THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY
 *      EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT
 *      LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 *      AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 *      GateD is based on Kirton's EGP, UC Berkeley's routing
 *      daemon   (routed), and DCN's HELLO routing Protocol.
 *      Development of GateD has been supported in part by the
 *      National Science Foundation.
 *
 * ------------------------------------------------------------------------
 *
 *      Portions of this software may fall under the following
 *      copyrights:
 *
 *      Copyright (c) 1988 Regents of the University of California.
 *      All rights reserved.
 *
 *      Redistribution and use in source and binary forms are
 *      permitted provided that the above copyright notice and
 *      this paragraph are duplicated in all such forms and that
 *      any documentation, advertising materials, and other
 *      materials related to such distribution and use
 *      acknowledge that the software was developed by the
 *      University of California, Berkeley.  The name of the
 *      University may not be used to endorse or promote
 *      products derived from this software without specific
 *      prior written permission.  THIS SOFTWARE IS PROVIDED
 *      ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES,
 *      INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 *      MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * __END_OF_COPYRIGHT__
 */


#define	INCLUDE_KINFO
#define	INCLUDE_ROUTE
#define	INCLUDE_IF
#include "include.h"

#ifdef KRT_RTREAD_KINFO
#ifdef	PROTO_INET
#include "inet/inet.h"
#endif	/* PROTO_INET */
#ifdef	PROTO_ISO
#include "iso/iso.h"
#endif	/* PROTO_ISO */
#include "krt/krt.h"
#include "krt/krt_var.h"


/* Use the getkinfo() system call to read the routing table(s) */
/*ARGSUSED*/
int
krt_rtread (task *tp)
{
    size_t size, alloc_size;
    caddr_t kbuf, cp, limit;
    rt_parms rtparms;
    struct rt_msghdr *rtp;
#ifdef	HAVE_SYSCTL
    static int mib[] = { CTL_NET, PF_ROUTE, 0, 0, NET_RT_DUMP, 0 };
#endif	/* HAVE_SYSCTL */

    trace_only_tp(tp,
		  TRC_NL_BEFORE,
		  ("krt_rtread: Initial routes read from kernel (via getkerninfo/sysctl):"));

    if (
#ifdef	HAVE_SYSCTL
	sysctl(mib, sizeof mib / sizeof *mib, (caddr_t) 0, &alloc_size, NULL, 0)
#else	/* HAVE_SYSCTL */
	(int) (alloc_size = getkerninfo(KINFO_RT_DUMP, (caddr_t) 0, (int *) 0, 0))
#endif	/* HAVE_SYSCTL */
	< 0) {
	trace_log_tp(tp,
		     0,
		     LOG_ERR,
		     ("krt_rtread: getkerninfo/sysctl routing table estimate: %m"));
	return errno;
    }
    trace_tp(tp,
	     TR_STATE,
	     0,
	     ("krt_rtread: getkerninfo/sysctl estimates %d bytes needed",
	      alloc_size));
    size = alloc_size = ROUNDUP(alloc_size, task_pagesize);
    kbuf = (caddr_t) task_block_malloc(alloc_size);
    if (
#ifdef	HAVE_SYSCTL
	sysctl(mib, sizeof mib / sizeof *mib, kbuf, &size, NULL, 0)
#else	/* HAVE_SYSCTL */
	getkerninfo(KINFO_RT_DUMP, kbuf, (int *) &size, 0)
#endif	/* HAVE_SYSCTL */
	< 0) {
	trace_log_tp(tp,
		     0,
		     LOG_ERR,
		     ("krt_rtread: getkerninfo/sysctl routing table retrieve: %m"));
	return errno;
    }
    limit = kbuf + size;

    for (cp = kbuf; cp < limit; cp += rtp->rtm_msglen) {
	sockaddr_un *author;
	krt_addrinfo *adip;
	const char *errmsg = (char *) 0;
	int pri = 0;

    	bzero((caddr_t) &rtparms, sizeof (rtparms));
	rtp = (struct rt_msghdr *) ((void_t) cp);

#ifdef IPSEC
	/* Set the IPSEC related rtparms fields.
	 */
	rtparms.rtp_fwant = rtp->rtm_fwant ;
	rtparms.rtp_rcvkeylen = rtp->rtm_rcvkeylen;
	rtparms.rtp_rcvalgo = rtp->rtm_rcvalgo;
	rtparms.rtp_rcvttl = rtp->rtm_rcvttl;
#endif

	adip = krt_xaddrs(rtp,
			  (size_t) rtp->rtm_msglen);
	if (!adip) {
	    continue;
	}

	if (TRACE_TP(tp, TR_KRT_REMNANTS)) {
	    /* Always trace in detail */
	    krt_trace_msg(tp,
			  "RTINFO",
			  rtp,
			  (size_t) rtp->rtm_msglen,
			  adip,
			  0,
			  TRUE);
	}

	switch (krt_rtaddrs(adip, &rtparms, &author, (flag_t) rtp->rtm_flags)) {
	case KRT_ADDR_OK:
	    break;

	case KRT_ADDR_IGNORE:
	    errmsg = "ignoring";
	    pri = LOG_INFO;
	    goto Trace;

	case KRT_ADDR_BOGUS:
	    errmsg = "deleting bogus";
	    pri = LOG_WARNING;
	    krt_delq_add(&rtparms);
	    goto Trace;

#ifdef	IP_MULTICAST
	case KRT_ADDR_MC:
#ifndef KRT_IPMULTI_RTSOCK
	    if (krt_multicast_install(rtparms.rtp_dest, rtparms.rtp_router)) {
		errmsg = "deleting multicast";
		pri = LOG_WARNING;
		krt_delq_add(&rtparms);
		goto Trace;
	    }
#endif  /* KRT_IPMULTI_RTSOCK */
	    errmsg = "ignoring multicast";
	    pri = LOG_INFO;
	    goto Trace;
#endif	/* IP_MULTICAST */
	}

#ifdef IPSEC
	/* If a tunnel or key exist we want to keep the route even if it
	 * an interface route to ourself.
	 */
	if (rtparms.rtp_tunnel || rtparms.rtp_key)
		BIT_SET(rtparms.rtp_state, RTS_FORCE);
#endif

	/* Kernel routes are part of the Unicast RIB */
        RTP_RESET_ELIGIBLE(rtparms);
        RTP_SET_ELIGIBLE(rtparms, RIB_UNICAST);

	errmsg = krt_rtadd(&rtparms, (flag_t) rtp->rtm_flags);
	if (errmsg) {
	    /* It has been deleted */

	    pri = LOG_WARNING;
	}

    Trace:
	if (errmsg) {
	    krt_trace(tp,
		      "READ",
		      "REMNANT",
		      adip->rti_info[RTAX_DST],
		      adip->rti_info[RTAX_NETMASK],
		      adip->rti_info[RTAX_GATEWAY],
		      (flag_t) rtp->rtm_flags,
		      errmsg,
		      pri);
	}
    }

    task_block_reclaim(alloc_size, kbuf);

    return 0;
}
#endif /* KRT_RTREAD_KINFO */

