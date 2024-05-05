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


#if defined(PROTO_SMUX)

#define OK	0
#define NOTOK	-1

#define RONLY	1
#define RWRITE	2

#define SMUX_MAX_STR_LEN	256
#define	SMUX_PORT		167
#define SMUX_MAX_NAME		15

/* Tracing */
#define	TR_SMUX_RECV		TR_USER_1
#define	TR_SMUX_SEND		TR_USER_3
#define	TR_SMUX_PACKETS		TR_USER_4

extern int doing_snmp;

trace *smux_trace_options;
extern const bits smux_trace_types[];
u_short smux_port;
int smux_debug, smux_errno, doing_smux;
char smux_passwd[SMUX_MAX_STR_LEN];
extern block_t asn1_oid_block_index;

#define	SMUX_MAX_SIZE		1500

/*
 * SMUX/SNMP errors
 */

#define SMUX_NOSUCHOBJECT	0x80
#define SMUX_NOSUCHINSTANCE	0x81
 

/* 
 * SMUX message types.
 */

#define SMUX_OPEN	0x60
#define SMUX_CLOSE      0x41
#define SMUX_RREQ       0x62
#define SMUX_RRSP       0x43
#define SMUX_SOUT       0x44
 
#define SMUX_GET        0xA0
#define SMUX_GETNEXT    0xA1
#define SMUX_GETRSP     0xA2
#define SMUX_SET	0xA3

/* 
 * SMUX ClosePDU types.
 */

#define SMUX_CLOSE_GOINGDOWN			0
#define SMUX_CLOSE_UNSUPPORTEDVERSION		1
#define SMUX_CLOSE_PACKETFORMAT			2
#define SMUX_CLOSE_PROTOCOLERROR		3
#define SMUX_CLOSE_INTERNALERROR		4
#define SMUX_CLOSE_AUTHENTICATIONFAILURE 	5

void smux_init(void);
void smux_var_init(void);

#endif		/* defined(PROTO_SMUX) */
