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


#define	INCLUDE_ROUTE
#define	INCLUDE_KVM
#include "include.h"

#ifdef KRT_RTREAD_HP10X
#ifdef	PROTO_INET
#include "inet/inet.h"
#endif	/* PROTO_INET */
#ifdef	PROTO_ISO
#include "iso/iso.h"
#endif	/* PROTO_ISO */
#include "krt/krt.h"
#include "krt/krt_var.h"



 /*  Read the kernel's routing table.			*/
int
krt_rtread (task *tp)
{
    int i;
    size_t rtbufsize;
    rt_parms rtparms;
    int num_routes = 0;
    if_addr *ifap;
    int error = 0;

    struct rtlist  rtlist;
    struct rtreq   *rtptr, *base;

    bzero((caddr_t) &rtparms, sizeof (rtparms));
    rtparms.rtp_n_gw = 1;

    trace_only_tp(tp,
		  TRC_NL_BEFORE,
		  ("krt_rtread: Initial routes read from kernel (via ioctl):"));

    if ( ioctl (krt_task->task_socket, SIOCGRTSIZE, &num_routes) < 0) {
        error = errno;
	trace_only_tp(tp,
		      0,
		      ("krt_rtread: ioctl fails on SIOCGRTSIZE: %m"));
         return (error);
    }

    /* set up to read the kernel routing table */

    rtbufsize = (num_routes + 8) * sizeof(struct rtreq);
    rtptr = (struct rtreq *) task_block_malloc(rtbufsize);
    base = rtptr;

    rtlist.rtl_rtreq = rtptr;
    rtlist.rtl_len = rtbufsize;
    rtlist.rtl_cnt = 0;

    if ( ioctl (krt_task->task_socket, SIOCGRTTABLE, (void*) &rtlist) < 0) {
        error = errno;
	trace_only_tp(tp,
		      0,
		      ("krt_rtread: ioctl fails on SIOCGRTTABLE: %m"));
         return (error);
    }

    /* map the kernel routing data to gated structure */
    for (i=0; i < rtlist.rtl_cnt; i++, rtptr++)  {
        rtparms.rtp_dest =  sockbuild_in (0, rtptr->rtr_destaddr);
        rtparms.rtp_router = sockbuild_in (0, rtptr->rtr_gwayaddr) ;

        rtparms.rtp_state = krt_flags_to_state((flag_t) rtptr->rtr_flags);
        RTP_RESET_ELIGIBLE(rtparms);
        RTP_SET_ELIGIBLE(rtparms, RIB_UNICAST);
	
	switch (krt_addrcheck(&rtparms)) {
		case KRT_ADDR_OK:
		    /* Address is OK */
		    break;

		case KRT_ADDR_IGNORE:
		    /* Ignore it */
		    continue;

		case KRT_ADDR_BOGUS:
		    /* Delete it */
		    continue;

#ifdef	IP_MULTICAST
		case KRT_ADDR_MC:
		    /* Multicast specification */
		    if (krt_multicast_install(rtparms.rtp_dest,
rtparms.rtp_router)) {
			goto Delete;
		    }
		    continue;
#endif	/* IP_MULTICAST */
		}

		/* Is it interior or exterior? */
		if ((ifap = if_withdstaddr(rtparms.rtp_dest))
		    || (ifap = if_withnet(rtparms.rtp_dest))) {
		    BIT_SET(rtparms.rtp_state, RTS_INTERIOR);
		} else {
		    BIT_SET(rtparms.rtp_state, RTS_EXTERIOR);
		}

		/* Determine host mask */
  	        rtparms.rtp_dest_mask = sockbuild_in (0,
rtptr->rtr_subnetmask);

		/* Add route to our routing table */
		if (!krt_rtadd(&rtparms, rtptr->rtr_flags)) {
		    /* We don't want it around, delete it */

		Delete:
		    krt_delete_dst(krt_task,
				   (rt_entry *) 0,
				   &rtparms,
				   (sockaddr_un *) 0,
				   RTPROTO_KERNEL,
				   &krt_gw_list);
		}
    }
    task_block_reclaim(rtbufsize, (caddr_t) base);

    return 0;
}
#endif /* KRT_RTREAD_HP10X */

