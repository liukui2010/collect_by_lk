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


#define	INCLUDE_FILE
#define INCLUDE_FCNTL /* to get O_RDWR */
#define	INCLUDE_IOCTL
#include "include.h"

#ifdef KRT_SYMBOLS_SUNOS5

#ifdef	PROTO_INET
#include "inet/inet.h"
#ifdef HAVE_INET_ND_H
#include <inet/nd.h>
#endif /* HAVE_INET_ND_H */
#endif	/* PROTO_INET */
#include "krt/krt.h"
#include "krt/krt_var.h"
#ifdef HAVE_SYS_SYSTEMINFO_H
#include <sys/systeminfo.h>
#else
#ifdef HAVE_SYS_SYSINFO_H
#include <sys/sysinfo.h>
#endif /* HAVE_SYS_SYSINFO_H */
#endif /* HAVE_SYS_SYSTEMINFO_H */
#ifdef HAVE_STREAMS_ND_H
#include <streams/nd.h>
#endif /* HAVE_STREAMS_ND_H */

static char *
krt_symbols_ndd (task *tp, const char *module, const char *name) 
{
    int sd;
    int rc;
    static char buf[64];

    NON_INTR(sd, open(module, O_RDWR));
    if (sd == -1) {
	trace_log_tp(tp,
		     0,
		     LOG_ERR,
		     ("krt_symbols_ndd: open %s: %m",
		      module));
	return (char *) 0;
    }

    strcpy(buf, name);

    rc = task_ioctl(sd,
		    (u_long) ND_GET,
		    buf,
		    sizeof buf);
    if (rc == -1) {
	trace_log_tp(tp,
		     0,
		     LOG_ERR,
		     ("krt_symbols_ndd: ioctl(ND_GET, %s): %m",
		      name));
	(void) close(sd);
	return (char *) 0;
    }

    (void) close(sd);
    return buf;
}


int
krt_symbols (task *tp)
{
    char *resp;
    char buf[BUFSIZ], *bp = buf;
    int len = sizeof buf;
    static long infos[] = {
	SI_SYSNAME,
	SI_RELEASE,
	SI_VERSION,
	SI_HOSTNAME,
	SI_MACHINE,
	SI_ARCHITECTURE,
	0
    };
    long *info = infos;

#ifdef	PROTO_INET
    resp = krt_symbols_ndd(tp, "/dev/ip", "ip_forwarding");
    if (resp) {
	inet_ipforwarding = atoi(resp) > 0;
	trace_tp(tp,
		 TR_KRT_SYMBOLS,
		 0,
		 ("krt_symbols: IP forwarding: %u using %u\n",
		  atoi(resp),
		  inet_ipforwarding));
    }
    resp = krt_symbols_ndd(tp, "/dev/udp", "udp_do_checksum");
    if (resp) {
	inet_udpcksum = atoi(resp) != 0;
	trace_tp(tp,
		 TR_KRT_SYMBOLS,
		 0,
		 ("krt_symbols: UDP checksums: %u using %u\n",
		  atoi(resp),
		  inet_udpcksum));
    }
#endif	/* PROTO_INET */

    do {
	int rc;
	
	*bp = (char) 0;
	rc = sysinfo(*info, bp, len);
	if (rc == -1) {
	    trace_log_tp(tp,
			 0,
			 LOG_ERR,
			 ("krt_symbols: sysinfo(): %m"));
	    continue;
	}
	bp += rc;
	len -= rc;
	bp[-1] = ' ';
    } while (*++info) ;
    *bp = (char) 0;

    krt_version_kernel = task_mem_strdup(tp, buf);

    trace_tp(tp,
	     TR_KRT_SYMBOLS,
	     0,
	     ("krt_symbols: krt_version_kernel = %s",
	      krt_version_kernel));

    return 0;
}
#endif /* KRT_SYMBOLS_SUNOS5 */
