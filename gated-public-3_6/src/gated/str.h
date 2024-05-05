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
#ifdef HAVE_AIX
typedef char *              va_list;
#endif

#ifdef HAVE_SUNOS4
typedef char *		    va_list;
#endif

/* Definitions for putting data into and getting data out of packets */
/* in a machine dependent manner. */
#define	PickUp(s, d)	bcopy((caddr_t) s, (caddr_t)&d, sizeof(d));	s += sizeof(d);
#define	PutDown(s, d)	bcopy((caddr_t)&d, (caddr_t) s, sizeof(d));	s += sizeof(d);
#define	PickUpStr(s, d, l)	bcopy((caddr_t) s, (caddr_t) d, l);	s += l;
#define	PutDownStr(s, d, l)	bcopy((caddr_t) d, (caddr_t) s, l);	s += l;

#ifdef	notdef
#define	PickUp(s, d)	{ \
    register int PickUp_i = sizeof(d); \
    d = 0; \
    while (PickUp_i--) { \
	d <<= 8; \
        d |= *s++;
    } \
}
#define	PutDown(s, d)	{
    register int i = sizeof(d);
    register long ii = d;
    register caddr_t cp;

    cp = (s += i);
    while (i--) {
	*--cp = (ii & 0xff);
	ii >>= 8;
    }
}
#define	PickUpStr(s, d, l) {
    register int i = l;
    register char *cp = d;

    while (i--) {
	*cp++ = *s++;
    }
}
#define	PutDownStr(s, d, l) {
    register int i = l;
    register char *cp = s;

    while (i--) {
	*s++ = *cp++;
    }
}
#endif	/* notdef */

char * gd_uplow(const char *, int);
#define	gd_upper(str)	gd_uplow(str, TRUE)
#define	gd_lower(str)	gd_uplow(str, FALSE)
int fprintf(FILE *, const char *, ...);
int vsprintf(char *, const char *, va_list );
int sprintf(char *, const char *, ...);
#ifndef	HAVE_STRCASECMP
int strcasecmp(const char *, const char *);
int strncasecmp(const char *, const char *, size_t);
#endif	/* HAVE_STRCASECMP */
#ifndef	HAVE_STRERROR
const char * strerror(int);
#endif	/* HAVE_STRERROR */
