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

#if defined(HAVE_SYSCTL) || defined(HAVE_GETKERNINFO)
#ifdef	PROTO_INET
#include "inet/inet.h"
#endif	/* PROTO_INET */
#ifdef	PROTO_ISO
#include "iso/iso.h"
#endif	/* PROTO_ISO */
#include "krt/krt.h"
#include "krt/krt_var.h"

#if	IFNAMSIZ > IFL_NAMELEN
error - IFL_NAMELEN not compatible with IFNAMESIZ
#endif


int
krt_ifread(flag_t save_task_state)
{
	size_t size;
	caddr_t cp, kbuf, limit;
	struct if_msghdr *ifap;
	if_link *ifl;
	register task *tp = krt_task;
	sockaddr_un *ap, *lladdr;
	int primary;

#ifdef	HAVE_SYSCTL
	static int mib[] = { CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST, 0 };
#endif	/* HAVE_SYSCTL */

	ifl = NULL;
	tp = krt_task;
	primary = FALSE;

	for (;;) {
		if (
#ifdef	HAVE_SYSCTL
		sysctl(mib, sizeof mib / sizeof *mib, (caddr_t) 0, &size, NULL, 0)
#else	/* HAVE_SYSCTL */
		(int)(size = getkerninfo(KINFO_RT_IFLIST, (caddr_t) 0, (size_t *) 0, 0))
#endif	/* HAVE_SYSCTL */
		< 0) {
			trace_log_tp(tp, 0, LOG_ERR,
			    ("krt_ifread: getkerninfo/sysctl: %m"));
			return (errno);
		}
		if (size > task_send_buffer_len) {
			/* Need more memory */

			trace_tp(tp, TR_NORMAL, 0,
			    ("krt_ifread: %s estimates %d bytes needed",
		      	    "getkerninfo/sysctl", size));
			task_alloc_send(tp, size);
		}
		kbuf = task_send_buffer;
		if (
#ifdef	HAVE_SYSCTL
		sysctl(mib, sizeof mib / sizeof *mib, task_send_buffer, &size, NULL, 0)
#else	/* HAVE_SYSCTL */
		getkerninfo(KINFO_RT_IFLIST, task_send_buffer, &size, 0)
#endif	/* HAVE_SYSCTL */
		< 0) {
			trace_log_tp(tp, 0, LOG_ERR, 
			    ("krt_ifread: interface table retrieval %m"));
		} else {
	    		/* Should have the data */
	   		 break;
		}
    	}

	limit = kbuf + size;

	/* Tell the IF code that we are passing complete knowledge */
	if_conf_open(tp, TRUE);
    
	for (cp = kbuf; cp < limit; cp += ifap->ifm_msglen) {
		krt_addrinfo *adip;
	
	ifap = (struct if_msghdr *) cp;

	/* Pick out the addresses */
	adip = krt_xaddrs((struct rt_msghdr *) ifap, ifap->ifm_msglen);
	if (!adip) {
		/* Try the next message */
		continue;
	}

	/* Trace the message */
	if (TRACE_TP(tp, TR_KRT_IFLIST)) {
		/* Always trace in detail */
		krt_trace_msg(tp, "IFINFO", (struct rt_msghdr *) ifap,
		    ifap->ifm_msglen, adip, 0, TRUE);
	}

	switch (ifap->ifm_type) {
	case RTM_IFINFO:
		/* New interface */
		primary = TRUE;
		if ((ap = adip->rti_info[RTAX_IFP])) {
			/* Link level info */
#ifndef HAVE_IFM_DATA
        if_link *ifl_ptr;
#endif
			if (ap->dl.gdl_alen) {
				lladdr = sockbuild_ll(krt_type_to_ll(ap->dl.gdl_type),
				    (byte *) ap->dl.gdl_data + ap->dl.gdl_nlen,
				    (size_t) ap->dl.gdl_alen);
			} else {
				lladdr = NULL;
			}

#ifndef  HAVE_IFM_DATA
      ifl_ptr = ifl_locate_index(ap->dl.gdl_index);
      ifl = ifl_addup(tp,
            ifl_ptr,
            ap->dl.gdl_index,
            krt_if_flags(ifap->ifm_flags),
            ifl_ptr->ifl_metric,
            ifl_ptr->ifl_mtu,
            ap->dl.gdl_data,
            ap->dl.gdl_nlen,
            lladdr,
						ap);
#else
			ifl = ifl_addup(tp, ifl_locate_index(ap->dl.gdl_index),
			    ap->dl.gdl_index, krt_if_flags(ifap->ifm_flags),
			    ifap->ifm_data.ifi_metric, (mtu_t) ifap->ifm_data.ifi_mtu,
			    ap->dl.gdl_data, ap->dl.gdl_nlen, lladdr, ap);
#endif
		} else {
			/* No link level info? */
			ifl = NULL;
		}
		break;
	case RTM_NEWADDR:
		if (primary == TRUE) {
			/* this is not an alias */
			primary = FALSE;
			krt_ifaddr(tp, (struct ifa_msghdr *) ifap, adip, ifl,
			    IFS_ALIAS_PRIMARY);
		} else {
			krt_ifaddr(tp, (struct ifa_msghdr *) ifap, adip, ifl, 0);
		}
		break;
	default:
		trace_log_tp(tp, 0, LOG_ERR, 
		    ("krt_ifread: ignoring unknown message type: %s (%d)",
		    trace_state(rtm_type_bits, ifap->ifm_type),
		    ifap->ifm_type));
		continue;
	}
	trace_tp(tp, TR_NORMAL, 0, (NULL));
    }

    if_conf_close(tp, FALSE);

    return 0;
}
#endif /* defined(HAVE_SYSCTL) || defined(HAVE_GETKERNINFO) */
