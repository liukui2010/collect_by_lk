/*
 *  Consortium Release 4
 *  
 *  $Id: krt_lladdr_sunos4.c,v 1.12 2000/02/18 21:52:32 bobsills Exp $
 */

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

#define	INCLUDE_TIME
#define	INCLUDE_IOCTL
#define	INCLUDE_ETHER
#define	INCLUDE_FILE
#define	INCLUDE_IF
#define	INCLUDE_SOCKIO /* for SIOCGIFADDR */

#include "include.h"
#include "krt/krt.h"
#include "krt/krt_var.h"
#ifdef KRT_LLADDR_SUNOS4

#include <net/nit_if.h>

sockaddr_un *
krt_lladdr (struct ifreq *ifr)
{
    static int s_nit = -2;
    sockaddr_un *addr = (sockaddr_un *) 0;

    struct ifreq working_copy;

    strcpy(working_copy.ifr_name, ifr->ifr_name);

    switch (s_nit) {
    case -1:
	/* Previous open failed */
	break;

    case -2:
	/* Try to open it */
	NON_INTR(s_nit, open("/dev/nit", O_RDONLY));
	if (s_nit < 0) {
	    if (!BIT_MATCH(task_state, TASKS_TEST|TASKS_NODUMP)) {
		trace_only_tp(krt_task,
			      0,
			      ("krt_lladdr: open(\"/dev/nit\"): %m"));
	    }
	    break;
	}
	(void) task_floating_socket(krt_task, s_nit, "/dev/nit");
	/* Fall through */

    default:
	/* Bind the NIT socket to this interface */
	bzero ((caddr_t) &working_copy.ifr_ifru, sizeof (working_copy.ifr_ifru));
	if (task_ioctl(s_nit,
		       (u_long) NIOCBIND,
		       (caddr_t) &working_copy, 
		       sizeof (working_copy)) < 0) {
	    int rc;
	    
	    trace_only_tp(krt_task,
			  0,
			  ("krt_lladdr: NIOCBIND could not bind to interface %.*s: %m",
			   IFNAMSIZ, working_copy.ifr_name));

	    /* Close the socket */
	    NON_INTR(rc, close(s_nit));
	    if (rc < 0) {
		trace_only_tp(krt_task,
			      0,
			      ("krt_lladdr: close(\"/dev/nit\"): %m"));
	    }
	    s_nit = -1;
	    break;
	}

	bzero ((caddr_t) &working_copy.ifr_ifru, sizeof (working_copy.ifr_ifru));
	if (task_ioctl(s_nit,
		       (u_long) SIOCGIFADDR,
		       (caddr_t) &working_copy,
		       sizeof (working_copy)) < 0) {
	    switch (errno) {
	    case EINVAL:
	    case EOPNOTSUPP:
		break;

	    default:
		trace_only_tp(krt_task,
			      0,
			      ("krt_lladdr: could not get link layer address for interface %.*s: %m",
			       IFNAMSIZ, working_copy.ifr_name));
	    }
	    break;
	}

	addr = sockbuild_ll(LL_8022,
			    (byte *) working_copy.ifr_addr.sa_data,
			    sizeof (struct ether_addr));
    }

    return addr;
}

#endif /* KRT_LLADDR_SUNOS4 */

