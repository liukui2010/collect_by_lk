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

#ifdef KRT_RTREAD_HPSTREAMS

#ifdef	PROTO_INET
#include "inet/inet.h"
#endif	/* PROTO_INET */
#ifdef	PROTO_ISO
#include "iso/iso.h"
#endif	/* PROTO_ISO */
#include "krt/krt.h"
#include "krt/krt_var.h"
#include <sys/mib.h>


 /*  Read the kernel's routing table.			*/
int
krt_rtread (task *tp)
{
    s_int32 i;
    size_t rtbufsize;
    rt_parms rtparms;
    s_int32 num_routes = 0;
    if_addr *ifap;

    s_int32 fd, count, len;
    struct nmparms parms;
    mib_ipRouteEnt *route_buf, *rtptr;
    flag_t  rt_flag;

    bzero((caddr_t) &rtparms, sizeof (rtparms));
    rtparms.rtp_n_gw = 1;

    trace_only_tp(tp,
                  TRC_NL_BEFORE,
                  ("krt_rtread: Initial routes read from kernel (via
dev/ip MIB):"));

    if ((fd = open_mib("/dev/ip", O_RDWR, 0, 0)) < 0) {
	trace_only_tp(tp,
                      0,
                      ("krt_rtread: open_mib failed: %m"));
         return (EINVAL);
    }

    parms.objid = ID_ipRouteNumEnt;
    parms.buffer = &count;
    len = sizeof(count);
    parms.len = &len;

    if (get_mib_info (fd, &parms) < 0) {
        trace_only_tp(tp,
                      0,
                      ("krt_rtread: Can't get ID_ipRouteNumEnt"));
         close_mib(fd);
         return (EINVAL);
    }

    /* count = Number of route entries  */
    /* set up to read the kernel routing table */
    rtbufsize = count * sizeof(mib_ipRouteEnt);
    if ((route_buf = (mib_ipRouteEnt *) task_block_malloc (rtbufsize)) == 0) {
        trace_only_tp(tp,
                      0,
                      ("krt_rtread: Error in allocating space for the
kernel routing table"));
         close_mib(fd);
         return (EINVAL);
    }
 
    parms.objid = ID_ipRouteTable;
    parms.buffer = route_buf;
    len = count * sizeof(mib_ipRouteEnt);
    parms.len = &len;

    if (get_mib_info (fd, &parms) < 0) {
        trace_only_tp(tp,
                      0,
                      ("krt_rtread: Can't get ID_ipRouteTable"));
         close_mib(fd);
         return (EINVAL);
    }

    close_mib(fd);

    /* map the kernel routing data to gated structure */
    rtptr = route_buf;
    for (i=0; i < count; i++, rtptr++)  {
        if ((rtptr->Type == NMDIRECT) || (rtptr->Type == NMREMOTE) ) {
          rtparms.rtp_dest =  sockbuild_in (0, rtptr->Dest);
          rtparms.rtp_router = sockbuild_in (0, rtptr->NextHop) ;

          rtparms.rtp_state = (flag_t) 0;
          if (rtptr->Type == NMREMOTE) 
              BIT_SET(rtparms.rtp_state, RTS_GATEWAY);

	  /* Determine netmask */
          /*
          if (BIT_TEST(rtptr->Type, NMREMOTE)) {
              rtparms.rtp_dest_mask = inet_mask_default;
          } else {
              rtparms.rtp_dest_mask = inet_mask_locate(rtptr->Mask);
	  }
          */
          rtparms.rtp_dest_mask = inet_mask_locate(rtptr->Mask);

	  krt_rtread_add(tp,
		       &rtparms,
		       krt_state_to_flags(rtparms.rtp_state),
		       FALSE,
		       "REMNANT");
	}
    }
    task_block_reclaim(rtbufsize, (caddr_t) route_buf);

    return 0;
}
#endif /* KRT_RTREAD_HPSTREAMS */
