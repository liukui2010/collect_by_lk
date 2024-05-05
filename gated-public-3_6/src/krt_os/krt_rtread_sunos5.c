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


#define	INCLUDE_FCNTL /* to get O_RDWR */
#define	INCLUDE_ROUTE
#define	INCLUDE_KVM
#define	INCLUDE_FILE

#include "include.h"

#ifdef KRT_RTREAD_SUNOS5
#ifdef HAVE_STROPTS_H
#include <stropts.h>
#endif
#ifdef	PROTO_INET
#include "inet/inet.h"
#endif	/* PROTO_INET */
#ifdef	PROTO_ISO
#include "iso/iso.h"
#endif	/* PROTO_ISO */
#include "krt/krt.h"
#include "krt/krt_var.h"

#ifdef	ROUNDUP
#undef	ROUNDUP
#endif
#ifdef	IPOPT_EOL
#undef	IPOPT_EOL
#endif
#ifdef	IPOPT_NOP
#undef	IPOPT_NOP
#endif
#ifdef	IPOPT_LSRR
#undef	IPOPT_LSRR
#endif
#ifdef	IPOPT_RR
#undef	IPOPT_RR
#endif
#ifdef	IPOPT_SSRR
#undef	IPOPT_SSRR
#endif
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/tihdr.h>
#include <sys/tiuser.h>
#include <inet/common.h>
#include <inet/mib2.h>
#include <inet/ip.h>

/*
 * XXX 
 */
#ifndef T_CURRENT
#define T_CURRENT       MI_T_CURRENT
#endif


#ifdef	USE_IRE_DEFAULT

static const bits krt_ire_bits[] = {
    { IRE_BROADCAST,	"BROADCAST" },
    { IRE_DEFAULT,	"DEFAULT" },             
    { IRE_LOCAL,	"LOCAL" },               
    { IRE_LOOPBACK,	"LOOPBACK" },            
    { IRE_PREFIX,       "PREFIX" },
    { IRE_CACHE,        "CACHE" },
    { IRE_IF_NORESOLVER,"IF_NORESOLVER" },
    { IRE_IF_RESOLVER,  "IF_RESOLVER" },
    { IRE_HOST,         "HOST" },
    { IRE_HOST_REDIRECT, "HOST_REDIRECT" },
    { 0, NULL },
} ;
#else	/*  USE_IRE_DEFAULT */

static const bits krt_ire_bits[] = {
    { IRE_BROADCAST,	"BROADCAST" },
    { IRE_GATEWAY,	"GATEWAY" },            
    { IRE_LOCAL,	"LOCAL" },               
    { IRE_LOOPBACK,	"LOOPBACK" },            
    { IRE_NET,		"NET" },                 
    { IRE_ROUTE,	"ROUTE" },               
    { IRE_SUBNET,	"SUBNET" },              
    { IRE_RESOLVER,     "RESOLVER" },
    { IRE_ROUTE_ASSOC,  "ROUTE_ASSOC" },
    { IRE_ROUTE_REDIRECT, "ROUTE_REDIRECT" },
    { 0, NULL },
} ;

#endif	/* USE_IRE_DEFAULT */


/*  Read the kernel's routing table */
/*ARGSUSED*/
int
krt_rtread (task *tp)
{
    int sd;
    rt_parms rtparms;
    void_t buf = task_block_malloc(task_pagesize);
    int flags;
    int j = 0;
    int	i, rc;
    struct strbuf strbuf;
    struct T_optmgmt_req *tor = (struct T_optmgmt_req *) buf;
    struct T_optmgmt_ack *toa = (struct T_optmgmt_ack *) buf;
    struct T_error_ack	*tea = (struct T_error_ack *) buf;
    struct opthdr *req;

    bzero((caddr_t) &rtparms, sizeof (rtparms));
    rtparms.rtp_n_gw = 1;

    trace_only_tp(tp,
		  TRC_NL_BEFORE,
		  ("krt_rtread: Initial routes read from kernel (via mibget):"));

    NON_INTR(sd, open("/dev/ip", O_RDWR));
    if (sd == -1) {
	trace_log_tp(tp,
		     0,
		     LOG_ERR,
		     ("krt_rtread: open mib stream %m"));
	task_quit(errno);
    }

    strbuf.buf = buf;

    tor->PRIM_type = T_OPTMGMT_REQ;
    tor->OPT_offset = sizeof(struct T_optmgmt_req);
    tor->OPT_length = sizeof(struct opthdr);
    tor->MGMT_flags = T_CURRENT;
    req = (struct opthdr *) (tor + 1);
    req->level = MIB2_IP;		/* any MIB2_xxx value ok here */
    req->name = 0;
    req->len = 0;

    strbuf.len = tor->OPT_length + tor->OPT_offset;
    flags = 0;
    NON_INTR(rc, putmsg(sd, &strbuf, (struct strbuf *) 0, flags));
    if (rc == -1) {
	trace_log_tp(tp,
		     0,
		     LOG_ERR,
		     ("mibget: putmsg(ctl) failed: %m"));
	goto Return;
    }
    /*
     * each reply consists of a ctl part for one fixed structure
     * or table, as defined in mib2.h.  The format is a T_OPTMGMT_ACK,
     * containing an opthdr structure.  level/name identify the entry,
     * len is the size of the data part of the message.
     */
    req = (struct opthdr *) (toa + 1);
    strbuf.maxlen = task_pagesize;
    while (++j) {
	flags = 0;
	NON_INTR(rc, getmsg(sd, &strbuf, (struct strbuf *) 0, &flags));
	if (rc == -1) {
	    trace_log_tp(tp,
			 LOG_ERR,
			 0,
			 ("mibget getmsg(ctl) failed: %m"));
	    goto Return;
	}
	if (rc == 0
	    && strbuf.len >= sizeof(struct T_optmgmt_ack)
	    && toa->PRIM_type == T_OPTMGMT_ACK
	    && toa->MGMT_flags == T_SUCCESS
	    && req->len == 0) {
	    goto Return;		/* this is EOD msg */
	}

	if (strbuf.len >= sizeof(struct T_error_ack)
	    && tea->PRIM_type == T_ERROR_ACK) {
	    trace_log_tp(tp,
			 LOG_ERR,
			 0,
			 ("mibget %d gives T_ERROR_ACK: TLI_error = 0x%x, UNIX_error = 0x%x",
			  j,
			  tea->TLI_error,
			  tea->UNIX_error));
	    errno = (tea->TLI_error == TSYSERR) ? tea->UNIX_error : EPROTO;
	    goto Return;
	}
			
	if (rc != MOREDATA
	    || strbuf.len < sizeof(struct T_optmgmt_ack)
	    || toa->PRIM_type != T_OPTMGMT_ACK
	    || toa->MGMT_flags != T_SUCCESS) {
	    trace_log_tp(tp,
			 LOG_ERR,
			 0,
			 ("mibget getmsg(ctl) %d returned %d, strbuf.len = %d, PRIM_type = %d",
			  j,
			  rc,
			  strbuf.len,
			  toa->PRIM_type));
	    if (toa->PRIM_type == T_OPTMGMT_ACK)
		    trace_log_tp(tp,
				 LOG_ERR,
				 0,
				 ("T_OPTMGMT_ACK: MGMT_flags = 0x%x, req->len = %d", 
				  toa->MGMT_flags,
				  req->len));
	    errno = ENOMSG;
	    goto Return;
	}

	if (req->level != MIB2_IP
	    || req->name != MIB2_IP_21) {
	    /* If this is not the routing table, skip it */

	    strbuf.maxlen = task_pagesize;
	    do {
		NON_INTR(rc, getmsg(sd, (struct strbuf *) 0, &strbuf, &flags));
	    } while (rc == MOREDATA) ;
	    continue;
	}

	strbuf.maxlen = (task_pagesize / sizeof (mib2_ipRouteEntry_t)) * sizeof (mib2_ipRouteEntry_t);
	strbuf.len = 0;
	flags = 0;
	do {
	    NON_INTR(rc, getmsg(sd, (struct strbuf * ) 0, &strbuf, &flags));
	    
	    switch (rc) {
	    case -1:
		trace_log_tp(tp,
			     LOG_ERR,
			     0,
			     ("mibget getmsg(data) failed %m"));
		goto Return;

	    default:
		trace_log_tp(tp,
			     LOG_ERR,
			     0,
			     ("mibget getmsg(data) returned %d, strbuf.maxlen = %d, strbuf.len = %d",
			      rc,
			      strbuf.maxlen,
			      strbuf.len));
		goto Return;

	    case MOREDATA:
	    case 0:
	        {
		    mib2_ipRouteEntry_t *rp = (mib2_ipRouteEntry_t *) strbuf.buf;
		    mib2_ipRouteEntry_t *lp = (mib2_ipRouteEntry_t *) (strbuf.buf + strbuf.len);

		    do {
			flag_t rt_flags = (flag_t) 0;

			rtparms.rtp_state = (flag_t) 0;
		
			rtparms.rtp_dest = sockbuild_in(0, rp->ipRouteDest);
			rtparms.rtp_router = sockbuild_in(0, rp->ipRouteNextHop);

			/* Determine netmask */
#ifdef USE_IRE_DEFAULT	
			if (BIT_TEST(rp->ipRouteInfo.re_ire_type, IRE_DEFAULT)) {
#else	/* USE_IRE_DEFAULT */
			if (BIT_TEST(rp->ipRouteInfo.re_ire_type, IRE_GATEWAY)) {
#endif	/* USE_IRE_DEFAULT */
	
			    rtparms.rtp_dest_mask = inet_mask_default;
			} else {
			    rtparms.rtp_dest_mask = inet_mask_locate(rp->ipRouteMask);
			}
		
			if (!BIT_TEST(rp->ipRouteInfo.re_ire_type, IRE_INTERFACE|IRE_LOOPBACK)) {
			    BIT_SET(rtparms.rtp_state, RTS_GATEWAY);
			}

#ifdef	USE_IRE_DEFAULT
			if (BIT_TEST(rp->ipRouteInfo.re_ire_type, IRE_HOST_REDIRECT)) {
#else	/* USE_IRE_DEFAULT */ 
			if (BIT_TEST(rp->ipRouteInfo.re_ire_type, IRE_ROUTE_REDIRECT)) {
#endif  /* USE_IRE_DEFAULT */
 
			    BIT_SET(rt_flags, RTF_DYNAMIC);
			}

			/* Kernel routes are part of the Unicast RIB */
                        RTP_RESET_ELIGIBLE(rtparms);
                        RTP_SET_ELIGIBLE(rtparms, RIB_UNICAST);

			krt_rtread_add(tp,
				       &rtparms,
				       rt_flags | krt_state_to_flags(rtparms.rtp_state),
#ifdef	USE_IRE_DEFAULT
				       !BIT_TEST(rp->ipRouteInfo.re_ire_type,
						 IRE_DEFAULT|IRE_PREFIX|IRE_HOST
						 |IRE_HOST_REDIRECT|IRE_INTERFACE|IRE_LOOPBACK),
#else  /* USE_IRE_DEFAULT */
				       !BIT_TEST(rp->ipRouteInfo.re_ire_type,
						 IRE_GATEWAY|IRE_NET|IRE_ROUTE_ASSOC
						 |IRE_ROUTE_REDIRECT|IRE_INTERFACE|IRE_LOOPBACK),
#endif	/* USE_IRE_DEFAULT */
				       trace_bits(krt_ire_bits, rp->ipRouteInfo.re_ire_type));
		    } while (++rp < lp) ;
		}
		break;
	    }
	} while (rc == MOREDATA) ;
    }

 Return:
    (void) close(sd);
    
    task_block_reclaim(task_pagesize, buf);

    return 0;
}
#endif /* KRT_RTREAD_SUNOS5 */

