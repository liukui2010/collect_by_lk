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
#ifdef KRT_RTREAD_KMEM
#ifdef	PROTO_INET
#include "inet/inet.h"
#endif	/* PROTO_INET */
#ifdef	PROTO_ISO
#include "iso/iso.h"
#endif	/* PROTO_ISO */
#include "krt/krt.h"
#include "krt/krt_var.h"

u_long krt_rthashsize;
u_long krt_rthash[2];

#ifdef	ROUTES_WO_MBUFS
typedef struct rtentry krt_type;

#define	krt_next	rt_next
#define	krt_size	sizeof(krt_type)
#define	krt_conv(ptr)	(&(ptr))
#endif	/* ROUTES_WO_MBUFS */

#ifdef	SYSVR4
#ifdef _nec_ews
struct msgb {
      struct msgb     *b_next;
      struct msgb     *b_prev;
      struct msgb     *b_cont;
      unsigned char   *b_rptr;
      unsigned char   *b_wptr;
      struct datab    *b_datap;
      unsigned char   b_band;
      unsigned char   b_pad1;
      unsigned short  b_flag;
      caddr_t         b_caller;       /* save caller address :NEC_ADDON */
};
typedef struct msgb mblk_t;
#endif /* _nec_ews */
typedef	mblk_t krt_type;
#define	krt_next	b_cont
#define	krt_size	sizeof (krt_type)
#endif	/* SYSVR4 */

#ifdef	SYSV
typedef struct msgb krt_type;
#define	krt_next	b_next
#define	krt_size	sizeof (krt_type)
#endif	/* SYSV */

#if	!defined(krt_next)
typedef struct mbuf krt_type;

#define	krt_next	m_next
#ifndef MMINOFF /* e.g., FreeBSD */
#define MMINOFF sizeof(struct m_hdr)
#endif
#define	krt_size	(MMINOFF + sizeof(struct rtentry))
#define krt_conv(ptr)	mtod(&ptr, struct rtentry *)
#endif

 /*  Read the kernel's routing table.			*/
int
krt_rtread (task *tp)
{
    int i, hashsize = 0, krt_table;
    size_t rtbufsize;
    struct rtentry *krt;
    krt_type *next, m_buf, **base;
    rt_parms rtparms;

    bzero((caddr_t) &rtparms, sizeof (rtparms));
    rtparms.rtp_n_gw = 1;

    if (!kd) {
	return EBADF;
    }

    trace_only_tp(tp,
		  TRC_NL_BEFORE,
		  ("krt_rtread: Initial routes read from kernel (via kmem):"));

    if (!krt_rthash[KRT_RTHOST]
	|| !krt_rthash[KRT_RTNET]) {
	trace_only_tp(tp,
		      0,
		      ("krt_rtread: rthost and/or rtnet not in namelist"));

	return ESRCH;
    }
    if (krt_rthashsize) {
	if (KVM_READ(kd,
		     krt_rthashsize,
		     &hashsize,
		     sizeof(hashsize)) < 0) {
	    trace_log_tp(tp,
			 0,
			 LOG_ERR,
			 ("krt_rtread: reading hashsize: %s",
			  KVM_GETERR(kd, "kvm_read error")));
	    return EINVAL;
	}
    }
    if (!hashsize) {
	trace_log_tp(tp,
		     0,
		     LOG_ERR,
		     ("krt_rtread: rthashsize not in namelist"));
	return ESRCH;
    }
    /* set up to read table of net hash chains */

    rtbufsize = hashsize * sizeof(krt_type *);
    base = (krt_type **) task_block_malloc(rtbufsize);
    for (krt_table = KRT_RTHOST; krt_table <= KRT_RTNET; krt_table++) {
	if (KVM_READ(kd,
		     krt_rthash[krt_table],
		     base,
		     rtbufsize) < 0) {
	    trace_log_tp(tp,
			 0,
			 LOG_ERR,
			 ("krt_rtread: readhing hash bucket: %s",
			  KVM_GETERR(kd, "kvm_read error")));
	    return EINVAL;
	}
	for (i = 0; i < hashsize; i++) {
	    if_addr *ifap;
	    
	    for (next = base[i]; next != NULL; next = m_buf.krt_next) {
#if	defined(SYSV) || defined(SYSVR4)
		struct rtentry krt_rtentry;
#endif

		if (KVM_READ(kd,
			     next,
			     &m_buf,
			     krt_size) < 0) {
		    trace_log_tp(tp,
				 0,
				 LOG_ERR,
				 ("krt_rtread: reading mbuf: %s",
				  KVM_GETERR(kd, "kvm_read error")));
		    return EINVAL;
		}
#if	defined(SYSV) || defined(SYSVR4)
		if (KVM_READ(kd,
			     m_buf.b_rptr,
			     &krt_rtentry,
			     sizeof (krt_rtentry)) < 0) {
		    trace_log_tp(tp,
				 0,
				 LOG_ERR,
				 ("krt_rtread: reading rtentry: %s",
				  KVM_GETERR(kd, "kvm_read error")));
		    return EINVAL;
		}
		krt = &krt_rtentry;
#else
		krt = krt_conv(m_buf);
#endif

#ifdef	SYSVR4
		/*
 		 * SVR4 has a serious bug in the routing tables.  The address
 		 * family for routes that are direct connections are invalid,
 		 * and the sin_zero field is not always zero.  For now, assume
 		 * that they are all IP addresses (when in Rome...).
 		 */
		{
		    struct sockaddr_in *addr;
		    
		    addr = (struct sockaddr_in *) &krt->rt_dst;
		    addr->sin_family = AF_INET;
		    addr->sin_port = 0;
		    bzero((caddr_t) addr->sin_zero, sizeof (addr->sin_zero));

		    addr = (struct sockaddr_in *) &krt->rt_gateway;
		    addr->sin_family = AF_INET;
		    addr->sin_port = 0;
		    bzero((caddr_t) addr->sin_zero, sizeof (addr->sin_zero));
		    
		}
#endif	/* SYSVR4 */

		/* Ignore unknown address families */
		switch (krt->rt_dst.sa_family) {
#ifdef	PROTO_INET
		case AF_INET:
		    break;
#endif	/* PROTO_INET */

		default:
		    continue;
		}

		rtparms.rtp_dest = sock2gated(&krt->rt_dst, unix_socksize(&krt->rt_dst, krt->rt_dst.sa_family));
		rtparms.rtp_router = sock2gated(&krt->rt_gateway, unix_socksize(&krt->rt_gateway, krt->rt_dst.sa_family));
		rtparms.rtp_state = krt_flags_to_state((flag_t) krt->rt_flags);
                RTP_RESET_ELIGIBLE(rtparms);
                RTP_SET_ELIGIBLE(rtparms, RIB_UNICAST);

		/* Determine netmask */
		if (BIT_TEST(krt->rt_flags, RTF_HOST)) {
		    rtparms.rtp_dest_mask = sockhostmask(rtparms.rtp_dest);
		} else if ((ifap = if_withdstaddr(rtparms.rtp_dest))
			   || (ifap = inet_ifwithnet(rtparms.rtp_dest))) {
		    rtparms.rtp_dest_mask = ifap->ifa_netmask;
		} else {
		    rtparms.rtp_dest_mask = inet_mask_natural(rtparms.rtp_dest);
		}

		krt_rtread_add(tp,
			       &rtparms,
			       (flag_t) krt->rt_flags,
			       FALSE,
			       "REMNANT");
	    }
	}
    }
    task_block_reclaim(rtbufsize, (caddr_t) base);

    return 0;
}
#endif /* KRT_RTREAD_KMEM */

