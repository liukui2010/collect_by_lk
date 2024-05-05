/*
 * Gated Release 4.x, 5.x, 6.x, 7.x
 *
 *	$Id: smux_asn1.h,v 1.10 2000/02/18 02:32:03 naamato Exp $
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
 * __END_OF_COPYRIGHT__
 */

#ifndef _SMUX_ASN1_H
#define _SMUX_ASN1_H

#define	ASN1_BIT_STRING		0x03
#define	ASN1_BOOLEAN		0x01
#define ASN1_COUNTER		0x41
#define ASN1_COUNTER_64		0x46
#define ASN1_GAUGE		0x42
#define ASN1_INTEGER		0x02
#define ASN1_IP_ADDRESS		0x40
#define ASN1_NULL		0x05
#define ASN1_NSAP		0x45
#define ASN1_OBJECT_ID		0x06
#define ASN1_OCTET_STRING	0x04
#define ASN1_OPAQUE		0x44
#define ASN1_SEQUENCE		0x30
#define ASN1_SET		0x11
#define ASN1_TIMETICKS		0x43
#define ASN1_UINTEGER		0x47
#define ASN1_UNSIGNED    	0x42

#define ASN1_MSIG_BIT		(0x80)
#define ASN1_LONG_LENGTH	ASN1_MSIG_BIT
#define ASN1_LAST_SUBID		ASN1_MSIG_BIT
#define ASN1_SUBID_MASK		(0xFF & ~ASN1_LAST_SUBID)
#define ASN1_LONG_MASK		(0xFF & ~ASN1_LONG_LENGTH)
#define ASN1_NEGATIVE(x)	((x) & 0x80)

#define INTEGER     ASN1_INTEGER
#define STRING      ASN1_OCTET_STRING
#define OBJID       ASN1_OBJECT_ID
#define NULLOBJ     ASN1_NULL
#define IPADDRESS   ASN1_IP_ADDRESS
#define COUNTER     ASN1_COUNTER
#define GAUGE       ASN1_GAUGE
#define UNSIGNED    ASN1_UNSIGNED
#define TIMETICKS   ASN1_TIMETICKS
#define ASNT_OPAQUE ASN1_OPAQUE
#define NSAP        ASN1_NSAP
#define COUNTER64   ASN1_COUNTER_64
#define UINTEGER    ASN1_UINTEGER

#define RONLY	1
#define RWRITE	2
#define MIB 1, 3, 6, 1, 2, 1
#define	ENTRY_ACTIVE 1

#define	ASN1_MAX_OID_SIZE	256
#define	MAX_NAME_LEN		32

extern int32 smux_reqid;

#define ASN1_DECODE_LENGTH(bufp, buflen, length) 				\
	do { 									\
		if (*(bufp)++ & ASN1_LONG_LENGTH) {				\
			(length) = (long)*(bufp)++;				\
			(length) = (long)(((length) << 8) | *(bufp)++);		\
			(buflen) -= 3;						\
		} else {							\
			(length) = *(bufp);					\
			(buflen) -= 2;						\
		}								\
	} while(0);								\

#define ASN1_ENCODE_LENGTH(bufp, buflen, length) 				\
	do { 									\
		*(bufp)++ = (u_char)(((length) >> 8) | ASN1_LONG_LENGTH);	\
		*(bufp)++ = (u_char)(length);					\
		(buflen) -= 2;							\
	} while(0);

typedef u_long oid;

int smux_parse_rrsp(u_char *, int *, int32 *);
int smux_parse_close(u_char *, int *, int32 *);
int smux_parse_get(u_char *, int *, oid **, int *, int *);

int smux_build_open(u_char *, int *, oid *, int, char *, char *);
int smux_build_getrsp(u_char *, int *, oid **, int *, u_char **, int *,
    u_char *, int, int, int);
int smux_build_rreq(u_char *, int *, oid *, int, int32, int32);
int smux_build_close(u_char *, int *, u_char);
#endif /* _SMUX_ASN1_H */
