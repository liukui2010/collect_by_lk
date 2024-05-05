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


#define	INCLUDE_STAT
#define	INCLUDE_CTYPE
#define	INCLUDE_FILE
#define	INCLUDE_FCNTL /* for O_RDWR */
#define	INCLUDE_IOCTL
#define	INCLUDE_IF
#include "include.h"
#ifdef KRT_LLADDR_SUNOS5

#include "krt/krt.h"
#include "krt/krt_var.h"
#include <sys/dlpi.h>


static int
krt_lladdr_open (struct ifreq * ifr, char * path)
{
    int	fd;
    int	unit;
    int	rc;
    register char *pp = path;
    register char *sp = ifr->ifr_name;
    char *lp = ifr->ifr_name + IFNAMSIZ;
    struct stat st;

    pp += sprintf(pp, "%s/", _PATH_DEV);

    do {
	*pp++ = *sp++;
    } while (sp < lp
	     && *sp
	     && isalpha(*sp)) ;

    *pp = (char) 0;

    if (stat(path, &st) == 0) {
	/* Type 2 */

	unit = 0;
	
	do {
	    unit = (unit * 10) + (*sp - '0');
	} while (*++sp && sp < lp) ;

	
	trace_tp(krt_task,
		 TR_STATE,
		 0,
		 ("krt_lladdr_open: %s, unit %u",
		  path,
		  unit));

    } else {
	/* Type 1 */

	unit = -1;
	
	do {
	    *pp++ = *sp++;
	} while (*sp && sp < lp) ;

	*pp = (char) 0;

	rc = stat(path, &st);
	if (rc < 0) {
	    switch (errno) {
	    default:
		trace_tp(krt_task,
			 TR_ALL,
			 0,
			 ("krt_lladdr_open: stat(%s): %m",
			  path));
		/* Fall through */

	    case ENOENT:
		return -1;
	    }
	}
	
	trace_tp(krt_task,
		 TR_STATE,
		 0,
		 ("krt_lladdr_open: %s, unit %u",
		  path));
    }

    fd = open(path, O_RDWR);
    if (fd < 0) {
	trace_tp(krt_task,
		 TR_ALL,
		 0,
		 ("krt_lladdr_open: open(%s): %m",
		  path));
	return fd;
    }

    if (unit != -1) {
	int flags;
	char buf[BUFSIZ];
	union DL_primitives *dlp = (union DL_primitives *) buf;
	struct strbuf ctl;

	ctl.buf = buf;

	/*
	 * Issue DL_ATTACH_REQ
	 */
	dlp->attach_req.dl_primitive = DL_ATTACH_REQ;
	dlp->attach_req.dl_ppa = unit;
	ctl.len = DL_ATTACH_REQ_SIZE;
	if (putmsg(fd, &ctl, NULL, 0) < 0) {
	    trace_tp(krt_task,
		     TR_ALL,
		     0,
		     ("krt_lladdr_open: putmsg(DL_ATTACH_REQ, %u): %m",
		      unit));

	Close:
	    (void) close(fd);
	    return -1;
	}

	ctl.maxlen = sizeof buf;
	ctl.len = 0;
	flags = 0;
	rc = getmsg(fd, &ctl, NULL, &flags);
	if (rc < 0) {
	    trace_tp(krt_task,
		     TR_ALL,
		     0,
		     ("krt_lladdr_open: getmsg(): %m",
		      unit));
	    goto Close;
	}

	/*
	 * Validate DL_OK_ACK reply.
	 */
	if (ctl.len < sizeof(u_long)) {
	    trace_tp(krt_task,
		     TR_ALL,
		     0,
		     ("krt_lladdr_open: DL_ATTACH_REQ: short reply %s %u",
		      path,
		      unit));
	    goto Close;
	}

	switch (dlp->dl_primitive) {
	case DL_ERROR_ACK:
	    trace_tp(krt_task,
		     TR_ALL,
		     0,
		     ("krt_lladdr_open: DL_ATTACH_REQ: %d: %s",
		      dlp->error_ack.dl_errno,
		      strerror(dlp->error_ack.dl_unix_errno)));
	    goto Close;

	default:
	    trace_tp(krt_task,
		     TR_ALL,
		     0,
		     ("krt_lladdr_open: DL_ATTACH_REQ: Unknown response %d",
		      dlp->dl_primitive));
	    goto Close;

	case DL_OK_ACK:
	    if (ctl.len < DL_OK_ACK_SIZE) {
		trace_tp(krt_task,
			 TR_ALL,
			 0,
			 ("krt_lladdr_open: DL_ATTACH_REQ: short reply %s %u",
			  path,
			  unit));
		goto Close;
	    }
	    if (dlp->ok_ack.dl_correct_primitive != DL_ATTACH_REQ) {
		trace_tp(krt_task,
			 TR_ALL,
			 0,
			 ("krt_lladdr_open: DL_ATTACH_REQ: unknown request: %d",
			  dlp->ok_ack.dl_correct_primitive));
		goto Close;
	    }
	    break;
	}
    }

    return fd;
}


static sockaddr_un *
krt_lladdr_get (int fd, char * path)
{
    char buf[BUFSIZ];
    union DL_primitives	*dlp = (union DL_primitives *) buf;
    struct strbuf ctl;
    int	flags;
    int rc;

    ctl.buf = buf;

    /*
     * Issue DL_PHYS_ADDR_REQ
     */
    dlp->physaddr_req.dl_primitive = DL_PHYS_ADDR_REQ;
    dlp->physaddr_req.dl_addr_type = DL_CURR_PHYS_ADDR;
    ctl.len = DL_PHYS_ADDR_REQ_SIZE;
    if (putmsg(fd, &ctl, NULL, 0) < 0) {
	trace_tp(krt_task,
		 TR_ALL,
		 0,
		 ("krt_lladdr_get: putmsg(DL_PHYS_ADDR_REQ, DL_CURR_PHYS_ADDR): %m"));
	
	return (sockaddr_un *) 0;
    }

    ctl.len = 0;
    ctl.maxlen = sizeof buf;
    flags = 0;
    rc = getmsg(fd, &ctl, NULL, &flags);
    if (rc < 0) {
	trace_tp(krt_task,
		 TR_ALL,
		 0,
		 ("krt_lladdr_get: getmsg(): %m"));
	return (sockaddr_un *) 0;
    }

    if (ctl.len < sizeof(u_long)) {
	trace_tp(krt_task,
		 TR_ALL,
		 0,
		 ("krt_lladdr_get: DL_PHYS_ADDR_REQ: short reply %s",
		  path));
	return (sockaddr_un *) 0;
    }

    switch (dlp->dl_primitive) {
    case DL_ERROR_ACK:
	/*
	 * Do not print errors for DL_UNSUPPORTED and DL_NOTSUPPORTED
	 */
	switch (dlp->error_ack.dl_errno) {
	case DL_UNSUPPORTED:
	case DL_NOTSUPPORTED:
	    break;

	default:
	    trace_tp(krt_task,
		     TR_ALL,
		     0,
		     ("krt_lladdr_get: DL_PHYS_ADDR_REQ: %d: %s",
		      dlp->error_ack.dl_errno,
		      strerror(dlp->error_ack.dl_unix_errno)));
	    break;
	}
	return (sockaddr_un *) 0;

    default:
	trace_tp(krt_task,
		 TR_ALL,
		 0,
		 ("krt_lladdr_get: DL_PHYS_ADDR_REQ: Unknown response %d",
		  dlp->dl_primitive));
	return (sockaddr_un *) 0;

    case DL_PHYS_ADDR_ACK:
	if (ctl.len < DL_PHYS_ADDR_ACK_SIZE) {
	    trace_tp(krt_task,
		     TR_ALL,
		     0,
		     ("krt_lladdr_get: DL_PHYS_ADDR_REQ: short ack %s",
		      path));
	    return (sockaddr_un *) 0;
	}
	break;
    }

    return sockbuild_ll(LL_8022,
			(byte *) (buf + dlp->physaddr_ack.dl_addr_offset),
			dlp->physaddr_ack.dl_addr_length);
}


sockaddr_un *
krt_lladdr (struct ifreq * ifr)
{
    int fd;
    char path[MAXPATHLEN];
    sockaddr_un *lladdr = (sockaddr_un *) 0;

    fd = krt_lladdr_open(ifr, path);
    if (fd < 0) {
	/* Do not report an error */
	return lladdr;
    }

    lladdr = krt_lladdr_get(fd, path);

    (void) close(fd);

    return lladdr;
}

#endif /* KRT_LLADDR_SUNOS5 */

