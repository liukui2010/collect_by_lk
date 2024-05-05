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


/* egp_param.h
 *
 * Defines various egp parameters
 */

#define EGP_PKTSIZE	8192		/* Maximum EGP packet size we can send and receive */
#define	EGP_PKTSLOP	1024		/* Slop in packet size to make it easier to detect overflow */

/* RFC904 defined parameters */
#define EGP_P1		30		/* Minimum interval for sending and receiving hellos */
#define EGP_P2		120		/* Minimum interval for sending and receiving polls */

#define	EGP_P3		30		/* interval between Request or Cease command retransmissions */
#define	EGP_P4		3600		/* interval during which state variables are maintained in */
					/* the absence of commands or responses in the Down or Up states */
#define	EGP_P5		120		/* interval during which state variables are maintained in */
					/* the absence of responses in the Acquisition and Cease states */

/* Automatic restart timers */
#define	EGP_START_RETRY	EGP_P5		/* Retry if max neighbors already acquired */
#define	EGP_START_SHORT	EGP_P5		/* Retry neighbor in 2 minutes */
#define	EGP_START_LONG	EGP_P5		/* Retry neighbor in an hour */

/* Hello interval constants */

#define MAXHELLOINT	900		/* Maximum hello interval, sec. */
#define HELLOMARGIN	2		/* Margin in hello interval to allow for delay variation in */
					/* the network */
/* Poll interval constants */

#define MAXPOLLINT  	3600		/* Maximum poll interval, sec. */

/* repoll interval is set to the hello interval for the particular neighbor */

/* Reachability test constants */

#define REACH_RATIO	4		/* No. commands sent on which reachability is based */
#define MAXNOUPDATE	3		/* Maximum # successive polls (new id) for which no update */
					/* was received before cease  and try to acquire an alternative */

#define	RATE_WINDOW	4		/* Size of polling rate window */
#define	RATE_MAX	3		/* Number of violations before generating an error message */


/* Limits of gateways per update */
#define	EGP_GATEWAY_MAX		255

/* Limits of EGP distance */
#define	EGP_DISTANCE_MIN	0
#define	EGP_DISTANCE_MAX	255

/* Limits of EGP networks per distance */
#define	EGP_ROUTES_MAX		255

