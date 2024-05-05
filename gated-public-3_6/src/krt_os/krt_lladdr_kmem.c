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


#define	INCLUDE_KVM
#define	INCLUDE_CTYPE
#define	INCLUDE_ETHER
#define	INCLUDE_IF
#include "include.h"

#ifdef KRT_LLADDR_KMEM
#include "krt/krt.h"
#include "krt/krt_var.h"


u_long krt_ifnet;

/*
 *	Default krt_lladdr, poke around in the kernel
 */

/*
 * Obtain physical address of the interface by peeking in the kernel.
 * This *hack* assumes that the interface uses an arpcom structure where
 * the physical address resides immediately after the ifnet structure.
 */
sockaddr_un *
krt_lladdr (struct ifreq *ifr)
{
    struct ifnet *ifp, *ifnet;
#if !defined(USE_XNAME)
    int unit = 0;
    size_t namelen;
#endif /* !defined(USE_XNAME) */

    if (!kd) {
	return (sockaddr_un *) 0;
    }
    
#if !defined(USE_XNAME)
    /* Get length of name and fetch unit */
    {
	register char *sp = ifr->ifr_name;
	char *lp = ifr->ifr_name + IFNAMSIZ;

	while (isalpha(*sp)) {
	    sp++;
	}

	namelen = sp - ifr->ifr_name;

	do {
	    unit = (unit * 10) + (*sp - '0');
	} while (*++sp && sp < lp) ;
    }
#endif /* !defined(USE_XNAME) */

    if (KVM_READ(kd,
		 krt_ifnet,
		 &ifnet,
		 sizeof (ifnet)) < 0) {
	trace_log_tp(krt_task,
		     0,
		     LOG_ERR,
		     ("krt_lladdr: reading ifnet for %.*s: %s",
		      IFNAMSIZ, ifr->ifr_name,
		      KVM_GETERR(kd, "kvm_read error")));
	return (sockaddr_un *) 0;
    }

    for (ifp = ifnet; ifp;
#if defined(USE_IF_LIST_TAILQ)
	ifp = TAILQ_NEXT(ifp,if_list))
#else
	ifp = ifp->if_next)
#endif /* defined(USE_IF_LIST_TAILQ) */
		{
	struct arpcom arpcom;
#if !defined(USE_XNAME)
	char name[IFNAMSIZ];
#endif /* defined(USE_XNAME) */

	/* Read ifnet */
	if (KVM_READ(kd,
		     ifp,
		     &arpcom,
		     sizeof (arpcom)) < 0) {
	    trace_log_tp(krt_task,
			 0,
			 LOG_ERR,
			 ("krt_lladdr: reading arpcom for %.*s: %s",
			  IFNAMSIZ, ifr->ifr_name,
			  KVM_GETERR(kd, "kvm_read error")));
	    break;
	}
	ifp = &arpcom.ac_if;

	if (
#if defined(USE_XNAME)
	    strncmp(ifp->if_xname, ifr->ifr_name, IFNAMSIZ)
#else
	    !ifp->if_addrlist
	    || !ifp->if_name
	    || ifp->if_unit != unit
#endif /* defined(USE_XNAME) */
	) {
	    /* Not the one we want */

	    continue;
	}
	
#if !defined(USE_XNAME)
	/* And interface name */
	if (KVM_READ(kd,
		     ifp->if_name,
		     name,
		     sizeof name) < 0) {
	    trace_log_tp(krt_task,
			 0,
			 LOG_ERR,
			 ("krt_lladdr: reading interface name for %.*s: %s",
			  IFNAMSIZ, ifr->ifr_name,
			  KVM_GETERR(kd, "kvm_read error")));
	    break;
	}
	ifp->if_name = name;	

	if (!isalpha(name[0])) {
	    /* Something is terribly wrong! */
	    break;
	}
#endif /* !defined(USE_XNAME) */

	if (BIT_TEST(ifp->if_flags, IFF_BROADCAST)
#ifdef	IFT_OTHER
	    && krt_type_to_ll(ifp->if_type) == LL_8022
#endif	/* IFT_OTHER */
	    ) {
	    /* Assume broadcast nets have 802.2 addresses */

#if !defined(KRT_LLADDR_KMEM)
	    if (unit == ifp->if_unit
		&& !strncmp(ifp->if_name, ifr->ifr_name, namelen))
		/* This is the one we want */
#endif /* !defined(KRT_LLADDR_KMEM) */

		return sockbuild_ll(LL_8022,
				    (byte *) &arpcom.ac_enaddr,
#ifdef	KRT_RT_SOCK
				    (size_t) ifp->if_addrlen
#else	/* KRT_RT_SOCK */
#ifndef	ETHER_ADDRLEN
#define	ETHER_ADDRLEN	6
#endif	/* ETHER_ADDRLEN */
				    ETHER_ADDRLEN
#endif	/* KRT_RT_SOCK */
				    );
	}
    }

    return (sockaddr_un *) 0;
}
#endif /* KRT_LLADDR_KMEM */
