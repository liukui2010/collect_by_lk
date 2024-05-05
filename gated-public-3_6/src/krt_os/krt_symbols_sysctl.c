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


#define	INCLUDE_UDP
#define	INCLUDE_UDP_VAR
#include "include.h"

#ifdef KRT_SYMBOLS_SYSCTL

#ifdef	PROTO_INET
#include "inet/inet.h"
#endif	/* PROTO_INET */
#ifdef PROTO_INET6 /* HITACHI_INET6 */
#include "inet6/inet6.h"
#endif /* PROTO_INET6 */
#include "krt/krt.h"
#include "krt/krt_var.h"
#include <sys/sysctl.h>

int
krt_symbols (task *tp)
{
    char buf[BUFSIZ];
    int name[CTL_MAXNAME];
    size_t len;
    int value;

    name[0] = CTL_KERN;
    name[1] = KERN_VERSION;
    len = sizeof buf;
    if (sysctl(name, 2, buf, &len, (void *) 0, 0) < 0) {
	trace_log_tp(tp,
		     0,
		     LOG_INFO,
		     ("krt_symbols: sysctl(CTL_KERN, KERN_VERSION): %m"));
    } else {
	/* Set version */

	krt_version_kernel = task_mem_strdup(tp, buf);
	trace_tp(tp,
		 TR_KRT_SYMBOLS,
		 0,
		 ("krt_symbols: kernel version: %s\n",
		  krt_version_kernel));
    }

#ifdef	PROTO_INET
    name[0] = CTL_NET;
    name[1] = AF_INET;

    name[2] = IPPROTO_IP;
    name[3] = IPCTL_FORWARDING;
    len = sizeof value;
    if (sysctl(name, 4, (void *) &value, &len, (void *) 0, 0) < 0) {
	trace_log_tp(tp,
		     0,
		     LOG_INFO,
		     ("krt_symbols: sysctl(CTL_NET, AF_INET, IPPROTO_IP, IPCTL_FORWARDING): %m"));
    } else {
	inet_ipforwarding = value >= 1;
	trace_tp(tp,
		 TR_KRT_SYMBOLS,
		 0,
		 ("krt_symbols: IP forwarding: %u using %u\n",
		  value,
		  inet_ipforwarding));
    }

    name[2] = IPPROTO_UDP;
    name[3] = UDPCTL_CHECKSUM;
    len = sizeof value;
    if (sysctl(name, 4, (void *) &value, &len, (void *) 0, 0) < 0) {
	trace_log_tp(tp,
		     0,
		     LOG_INFO,
		     ("krt_symbols: sysctl(CTL_NET, AF_INET, IPPROTO_UDP, UDP_CHECKSUM): %m"));
    } else {
	inet_udpcksum = value != 0;
	trace_tp(tp,
		 TR_KRT_SYMBOLS,
		 0,
		 ("krt_symbols: UDP checksum: %u using %u\n",
		  value,
		  inet_udpcksum));
    }
#endif	/* PROTO_INET */
    
#ifdef PROTO_INET6 /* HITACHI_INET6 */
    name[0] = CTL_NET;
    name[1] = PF_INET6;
    name[2] = 0; /* IPPROTO_IPV6 */
#ifdef IPV6_NETINET
#define IP6CTL_FORWARDING 1
    name[3] = IP6CTL_FORWARDING;
#else
    name[3] = IPV6CTL_FORWARDING; 
#endif
    len = sizeof value;
    if (sysctl(name, 4, (void *) &value, &len, (void *) 0, 0) < 0) {
        trace_log_tp(tp,
		     0,
		     LOG_INFO,
		     ("krt_symbols: sysctl(CTL_NET, AF_INET6, IPPROTO_IPV6, IPV6CTL_FORWARDING): %m"));
    } else {
        inet6_ipforwarding = value >= 1;
	trace_tp(tp,
		 TR_KRT_SYMBOLS,
		 0,
		 ("krt_symbols: IPv6 forwarding: %u using %u\n",
		  value,
		  inet6_ipforwarding));
    }
#endif /* PROTO_INET6 */
    
    trace_tp(tp,
	     TR_KRT_SYMBOLS,
	     0,
	     (NULL));

    return 0;
}
#endif /* KRT_SYMBOLS_SYSCTL */
