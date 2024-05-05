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


/* krt.c
 *
 * Kernel routing table interface routines
 */

#define	INCLUDE_IOCTL
#define	INCLUDE_NETOPT_IBMR2
#include "include.h"
#ifdef KRT_NETOPTS

#ifdef	PROTO_INET
#include "inet/inet.h"
#endif	/* PROTO_INET */
#include "krt/krt.h"
#include "krt/krt_var.h"

#ifndef	MAXOPTLEN
#define	MAXOPTLEN	128

struct optreq {
    char name[MAXOPTLEN];
    char data[MAXOPTLEN];
    char getnext;
} ;

#endif	/* MAXOPTLEN */


static struct optreq net_opts[] = {
#define	NOPTS_IPFORWARDING	0
    { "ipforwarding" },
#define	NOPTS_COMPAT43		1
    { "compat_43" },
    { "" }
} ;


int
krt_netopts (task *tp)
{
    int rc, s;
    struct optreq *op;

    NON_INTR(s, socket(AF_UNIX, SOCK_STREAM, 0));
    if (s < 0) {
	int error = errno;

	trace_log_tp(tp,
		     0,
		     LOG_WARNING,
		     ("krt_netopts: socket(AF_UNIX, SOCK_STREAM, 0): %m"));

	return error;
    }
    
    for (op = net_opts; *op->name; op++) {
	op->getnext = 0;
	
	if (task_ioctl(s, 
		       (u_long) SIOCGNETOPT, 
		       (caddr_t) op, 
		       sizeof (*op)) < 0) {
	    trace_log_tp(tp,
			 0,
			 LOG_WARNING,
			 ("krt_netopts: ioctl(SIOCGNETOPT, %s): %m",
			  op->name,
			  errno));
	    continue;
	}
	trace_tp(tp,
		 TR_KRT_SYMBOLS,
		 0,
		 ("krt_netops: request %s response %s",
		  op->name,
		  op->data));

	switch (op - net_opts) {
	case NOPTS_IPFORWARDING:
#ifdef	PROTO_INET
	    inet_ipforwarding = atoi(op->data) > 0;
	    trace_tp(tp,
		     TR_KRT_SYMBOLS,
		     0,
		     ("krt_netops: IP forwarding: %u using %u",
		      atoi(op->data),
		      inet_udpcksum));
#endif	/* PROTO_INET */
	    break;

	case NOPTS_COMPAT43:
	    trace_tp(tp,
		     TR_KRT_SYMBOLS,
		     0,
		     ("krt_netops: 4.3 compatibility: %u",
		      atoi(op->data)));
	    if (atoi(op->data)) {
		trace_log_tp(tp,
			     0,
			     LOG_INFO,
			     ("krt_netops: running with %s=%d(%s) results in slightly reduced functionality!",
			      op->name,
			      atoi(op->data),
			      op->data));
	    }
	    break;
	    
	default:
	    assert(FALSE);
	}
    }

    NON_INTR(rc, close(s));
    if (rc < 0) {
	trace_log_tp(tp,
		     0,
		     LOG_WARNING,
		     ("krt_netopts: close(socket): %m"));
    }
    
    return 0;
}

#endif KRT_NETOPTS
