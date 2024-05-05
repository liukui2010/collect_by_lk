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


#define	RDISC_DOING_OFF		0
#define	RDISC_DOING_SERVER	1
#define	RDISC_DOING_CLIENT	2

/* Server stuff */
#define RDISC_MAX_INITIAL_ADVERT_INTERVAL 	16	/* seconds */
#define RDISC_MAX_INITIAL_ADVERTISEMENTS	3	/* transmissions */
#define RDISC_MAX_RESPONSE_DELAY		2	/* seconds */
#define RDISC_MAX_ADINTERVAL_DEFAULT 		600

#define RDISC_CONFIG_MAXADVINT  1
#define RDISC_CONFIG_MINADVINT  2
#define RDISC_CONFIG_LIFETIME   3
#define RDISC_CONFIG_MAX        4

#define RDISC_CONFIG_IFA_IGNORE     1
#define RDISC_CONFIG_IFA_BROADCAST  2
#define RDISC_CONFIG_IFA_PREFERENCE 3
#define RDISC_IFA_CONFIG_MAX        4

/* Client stuff */
#define	RDISC_MAX_SOLICITATION_DELAY	1	/* seconds */
#define	RDISC_SOLICITATION_INTERVAL	3	/* interval */
#define	RDISC_MAX_SOLICITATIONS		3

#define	RDISC_CONFIG_CLIENT_DISABLE	1
#define	RDISC_CONFIG_CLIENT_BROADCAST	2
#define	RDISC_CONFIG_CLIENT_QUIET	3
#define	RDISC_CONFIG_CLIENT_MAX		4


#define	RDISC_LIFETIME_MIN	3
#define	RDISC_LIFETIME_MAX	9000

#define RDISC_LIMIT_MAXADVINT   4, 1800
#define RDISC_LIMIT_MINADVINT   3, 1800
#define RDISC_LIMIT_LIFETIME    RDISC_LIFETIME_MIN, RDISC_LIFETIME_MAX
#define RDISC_LIMIT_PREFERENCE  (u_int) 0x80000000, 0x7fffffff

#define RDISC_PREFERENCE_INELIGIBLE     0x80000000
#define	RDISC_PREFERENCE_DEFAULT	0

extern u_long doing_rdisc;
extern const bits rdisc_trace_types[];
extern trace *rdisc_trace_options;
extern adv_entry *rdisc_server_address_policy;
extern adv_entry *rdisc_interface_policy;
extern pref_t rdisc_client_preference;

extern void rdisc_init(void);
extern void rdisc_var_init(void);
