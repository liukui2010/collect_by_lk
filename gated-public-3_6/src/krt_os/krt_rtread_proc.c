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


#define	INCLUDE_NLIST
#define	INCLUDE_ROUTE
#define	INCLUDE_KVM
#include "include.h"

#ifdef KRT_RTREAD_PROC
#ifdef	PROTO_INET
#include "inet/inet.h"
#endif	/* PROTO_INET */
#ifdef	PROTO_ISO
#include "iso/iso.h"
#endif	/* PROTO_ISO */
#include "krt/krt.h"
#include "krt/krt_var.h"
#include <stdio.h>

/*  Read the kernel's routing table.			*/

/*
    Iface Destination Gateway Flags RefCnt  Use Metric  Mask   MTU   Window
    lo     0100007F  00000000  05     0    6261    0  FFFFFFFF 1936    0
    eth0   00C702CB  00000000  01     0    2123    0  00FFFFFF 1476    0
 */

int
krt_rtread (task *tp)
{
    int i;
    flag_t flags;
    char if_name[IFL_NAMELEN+1];
    u_int32 addr_dest, addr_mask, addr_gw;
    rt_parms rtparms;
    FILE *DFile;
    if_addr *ifap;
    char buf[256];		/* Buffer space */

    bzero((caddr_t) &rtparms, sizeof (rtparms));
    rtparms.rtp_n_gw = 1;

    DFile = fopen("/proc/net/route", "r");
    if(DFile == NULL)
	return EBADF;

    trace_only_tp(tp,
		  TRC_NL_BEFORE,
		  ("krt_rtread: Initial routes read from kernel (via /proc/net/route):"));

    /* read route data from /proc   */

/* skip over header line */
    fgets(buf,256,DFile);

/*
 *     It is important we use fgets here. The linux /proc files will keep the s
 *     ame order through releases but new entries can appear at the end of
 *     each line. This changed  reader will always stay in sync.
 *             -- Alan Cox.
 */
    while(fgets(buf,256,DFile))
    {
	/*i=sscanf(buf,"%s\t%lx\t%lx\t%02x\t%*d\t%*d\t%*d\t%lx\t%*d\t%*d\n",*/
       i=sscanf(buf,"%s\t%lx\t%lx\t%04x\t%*d\t%*d\t%*d\t%lx\t%*d\t%*d\t%*d\n",
		 if_name,
		 &addr_dest,
		 &addr_gw,
		 &flags,
		 &addr_mask);

	/* ignore routes not marked up */
	if (!BIT_TEST(flags, RTF_UP))
		continue;
	
	rtparms.rtp_dest = sockbuild_in(0, addr_dest);
	rtparms.rtp_dest_mask = inet_mask_locate(addr_mask);
	rtparms.rtp_state = krt_flags_to_state(flags);
        RTP_RESET_ELIGIBLE(rtparms);
        RTP_SET_ELIGIBLE(rtparms, RIB_UNICAST);

	if (addr_gw) {
	    /* Gateway was specified, use it */
	    
	    rtparms.rtp_router = sockbuild_in(0, addr_gw);
	} else {
	    /* Gateway was not specified - try to figure it out */
	    
	    if (BIT_TEST(flags, RTF_GATEWAY)) {
		/* Not an interface route - ignore it */

		continue;
	    }

	    ifap = if_withsubnet(rtparms.rtp_dest);

	    if (!ifap
		|| strcmp(ifap->ifa_link->ifl_name, if_name)) {
		/* We could not find the interface */

		continue;
	    }

	    rtparms.rtp_router = IFA_UNIQUE_ADDR(ifap);
	}


	krt_rtread_add(tp,
		       &rtparms,
		       flags,
		       FALSE,
		       "REMNANT");
    }

    return 0;
}
#endif /* KRT_RTREAD_PROC */

