/*
 * Gated Release 4.x, 5.x, 6.x, 7.x
 *
 *	$Id: smux_asn1.c,v 1.10 2000/02/18 02:32:02 naamato Exp $
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

/*
 * Routines to parse SMUX PDUs expressed in ASN.1.
 * Author:  Nick Amato <naamato@merit.net>
 */

#include "include.h"
#include "smux_asn1.h"
#include "smux.h"

block_t asn1_oid_block_index;

static int asn_decode(u_char **, int *, u_char, void *, int *);
static int asn_encode(u_char **, int *, u_char, void *, int32);
static int asn_encode_length(u_char **, int *, int32);
static int asn_decode_length(u_char **, int *, int32 *);

/*
 * #######################################################################
 * SMUX PDU Parse Routines
 * #######################################################################
 */

int
smux_parse_rrsp(u_char *buf, int *buflen, int32 *failure)
{
	int32 len;

	if (*buf != (u_char)SMUX_RRSP)
		return 1;

	buf++;
	*buflen -= 1;

	if (asn_decode_length(&buf, buflen, &len))
		return 1;

	if (len > *buflen)
		return 1;

	*buflen = len;
	if (len > sizeof(failure))
		return 1;

	*failure = 0;

	bcopy(buf, failure, sizeof(failure));
	*failure >>= (8 * (sizeof(*failure) - len));

	return 0;
}

int
smux_parse_close(u_char *buf, int *buflen, int32 *reason)
{
	int32 length;
	
	*reason = 0;

	if (*buf != (u_char)SMUX_CLOSE)
		return 1;

	buf++;
	*buflen -= 1;

	/* implicit int */
	if (asn_decode_length(&buf, buflen, &length))
		return 1;

	if ((length > *buflen) || (length > sizeof(int32)))
		return 1;

	while(length--)
		*reason = (*reason << 8) | *buf++;

	*buflen -= length;

	return 0;
}

int
smux_parse_get(u_char *buf, int *buflen, oid **names, int *namelens, int *nnam)
{

	oid *op;
	int idx, null, nlen, olen, reqid, errst, erridx;
	int32 length;

	idx = nlen = 0;

	if ((*buf != (u_char)SMUX_GET) &&
	    (*buf != (u_char)SMUX_GETNEXT))
		return 1;

	buf++;
	*buflen -= 1;

	if (asn_decode_length(&buf, buflen, &length))
		return 1;

	*buflen = length;
	nlen = sizeof(reqid);

	/* request ID, error status, error index */
	if (asn_decode(&buf, buflen, (u_char)ASN1_INTEGER, &reqid, &nlen))
		return 1;
	
	smux_reqid = (int32)reqid;
	nlen = sizeof(reqid);

	/* ignore */
	if (asn_decode(&buf, buflen, (u_char)ASN1_INTEGER, &reqid, &nlen))
		return 1;

	nlen = sizeof(reqid);

	if (asn_decode(&buf, buflen, (u_char)ASN1_INTEGER, &reqid, &nlen))
		return 1;

	/* pass sequence */
	buf++;
	*buflen -= 1;

	/* get the sequence length */
	if (asn_decode_length(&buf, buflen, &length))
		return 1;

	*buflen = length;

	while(*buflen > 0) {	

		op = (oid *)task_block_alloc(asn1_oid_block_index);
		olen = ASN1_MAX_OID_SIZE;

		/* pass sequence */
		buf++;
		*buflen -= 1;

		/* get the sequence length */
		if (asn_decode_length(&buf, buflen, &length))
			return 1;

		*buflen = length;

		if (asn_decode(&buf, buflen, (u_char)ASN1_OBJECT_ID, op, &olen) ||
		    asn_decode(&buf, buflen, (u_char)ASN1_NULL, &null, &nlen))
			return 1;

		names[idx] = op;
		namelens[idx++] = olen;
	}
	*nnam = idx;
	return 0;
}


/*
 * #######################################################################
 * SMUX PDU Formation Routines
 * #######################################################################
 */

int
smux_build_open(u_char *buf, int *buflen, oid *ident, int idlen, char *desc,
    char *passwd)
{
	u_char *savep;
	int32 version;
	
	*buf++ = (u_char)SMUX_OPEN;
	savep = buf;
	version = 0;
	buf += 5;
	*buflen -= 6;

	if (asn_encode(&buf, buflen, (u_char)ASN1_INTEGER,
	    &version, sizeof(version)))
		return 1;

	if (asn_encode(&buf, buflen, (u_char)ASN1_OBJECT_ID, ident, idlen))
		return 1;

	if (asn_encode(&buf, buflen, (u_char)ASN1_OCTET_STRING, desc,
	    strlen(desc)))
		return 1;

	if (asn_encode(&buf, buflen, (u_char)ASN1_OCTET_STRING,
	    passwd, strlen(passwd)))
		return 1;

	*buflen += 5;	/* XXX */
	if (asn_encode_length(&savep, buflen, (int32)(buf - savep - 5)))
		return 1;

	return 0;
}

int
smux_build_getrsp(u_char *buf, int *buflen, oid **names, int *namelens,
    u_char **vals, int *vlens, u_char *types, int n, int error, int idx)
{
	u_char *save1, *save2, *save3;
	int32 ie, in;
	int i;

	*buf++ = (u_char)SMUX_GETRSP;
	save1 = buf;
	buf += 5;
	*buflen -= 6;

	ie = (int32) error;
	in = (int32) idx;

	if (asn_encode(&buf, buflen, (u_char)ASN1_INTEGER, &smux_reqid,
	    sizeof(smux_reqid)) ||
	    asn_encode(&buf, buflen, (u_char)ASN1_INTEGER, &ie, sizeof(ie)) ||
	    asn_encode(&buf, buflen, (u_char)ASN1_INTEGER, &in, sizeof(in)))
		return 1;

	if (error) {
		*buf++ = (u_char)ASN1_SEQUENCE;
		save2 = buf;
		buf += 5;
		*buflen -= 6;

		for (i = 0; i < n; i++) {
			if (asn_encode(&buf, buflen,
			    (u_char)ASN1_OBJECT_ID, names[i],
			    namelens[i]))
				return 1;
		}

		/* oid length */
		*buflen += 5;
		if (asn_encode_length(&save2, buflen, (int32)(buf - save2 - 5)))
			return 1;

	} else {

		*buf++ = (u_char)ASN1_SEQUENCE;
		save2 = buf;
		buf += 5;
		*buflen -= 6;

		for (i = 0; i < n; i++) {
			*buf++ = ASN1_SEQUENCE;
			save3 = buf;
			buf += 5;
			*buflen -= 6;
		
			/* name */	
			if (asn_encode(&buf, buflen,
			    (u_char)ASN1_OBJECT_ID, names[i],
			    namelens[i]))
				return 1;

			/* value */
			if (asn_encode(&buf, buflen,
			    types[i], vals[i], vlens[i]))
				return 1;

			/* sequence length */
			*buflen += 5;
			if (asn_encode_length(&save3, buflen,
			    (int32)(buf - save3 - 5)))
				return 1;
		}
		/* sequence length */
		*buflen += 5;
		if (asn_encode_length(&save2, buflen,
		    (int32)(buf - save2 - 5)))
			return 1;
	}
	/* pkt length */
	*buflen += 5;
	if (asn_encode_length(&save1, buflen, (int32)(buf - save1 - 5)))
		return 1;

	return 0;
}

int
smux_build_close(u_char *buf, int *buflen, u_char reason)
{
	if (*buflen < 3)
		return 1;

	*buf++ = (u_char)SMUX_CLOSE;
	*buf++ = 1;
	*buf++ = reason;

	*buflen -= 3;

	return 0;
}

int
smux_build_rreq(u_char *buf, int *buflen, oid *subtree,
    int slen, int32 pri, int32 op)
{
	u_char *savep;

	*buf++ = (u_char)SMUX_RREQ;
	savep = buf;
	buf += 5;
	*buflen -= 6;

	if (asn_encode(&buf, buflen, (u_char)ASN1_OBJECT_ID, subtree, slen) ||
	    asn_encode(&buf, buflen, (u_char)ASN1_INTEGER, &pri, sizeof(pri)) ||
	    asn_encode(&buf, buflen, (u_char)ASN1_INTEGER, &op, sizeof(op))) {
		return 1;
	}

	*buflen += 5;	/* XXX */
	if (asn_encode_length(&savep, buflen, (int32)(buf - savep - 5)))
		return 1;

	return 0;
}

int
smux_build_trap() {
	/* traps not implemented */
}




/*
 * #######################################################################
 * ASN.1 Encode/Decode Routines
 * #######################################################################
 */

void
asn_init()
{
	asn1_oid_block_index = 
	    task_block_init((ASN1_MAX_OID_SIZE * sizeof(oid)), "smux_oid");
}

static int
asn_decode(u_char **buf, int *buflen, u_char type, void *storage, int *slen)
{
	int i, j;
	int32 *ip, length;
	u_char *cp, *ptr;
	oid *op;

	ptr = *buf;

	if (type != *ptr) {
		/* trace */
		return 1;
	}

	ptr++;
	*buflen -= 1;

	switch(type) {
	case ASN1_INTEGER:
		if (asn_decode_length(&ptr, buflen, &length) ||
		    (length > *buflen) || (length > *slen))
			return 1;
		ip = (int32 *)storage;
		*ip = 0;
		if (ASN1_NEGATIVE(*ptr))
			*ip = -1;
		while(length--)
			*ip = (long)(*ip << 8) | *ptr++;
		*buflen -= length;
		*slen = length;
		break;
	case ASN1_OCTET_STRING:
	case ASN1_IP_ADDRESS:
	case ASN1_OPAQUE:
	case ASN1_NSAP:
		if (asn_decode_length(&ptr, buflen, &length) ||
		    (length > *buflen) || (length > *slen))
			return 1;
		cp = (u_char *)storage;
		bcopy(ptr, cp, length);
		ptr += length;
		*buflen -= length;
		*slen = length;
		break;
	case ASN1_OBJECT_ID:
		if (asn_decode_length(&ptr, buflen, &length) ||
		    (length > *buflen) || ((length * (sizeof(oid) + 1)) > *slen))
			return 1;
		op = (oid *)storage;
		for (i = 0, j = 1; i < length; j++) {
			do {
				op[j] = (op[j] << 7) |
				    (*ptr & ASN1_SUBID_MASK);
				*buflen -= 1;
				if (i++ >= length)
					break;
			} while (*ptr++ & ASN1_LAST_SUBID);
		}
		/* + 1 for expansion */
		*slen = j;

		/* op[0] and op[1] are encoded as:
		 * (a * 40) + b, where a, b are the first two subid's
		 */
		if (op[1] == 0x2B) {
			op[0] = 1;
			op[1] = 3;
		} else {
			op[0] = op[1];
			op[1] = op[1] % 40;
			op[0] = (op[0] - op[1]) / 40;
		}
		break;
	case ASN1_NULL:
		ip = (int32 *)storage;
		*slen = 0;
		*ip = 0;
		ptr++;
		*buflen -= 1;
		break;
	case ASN1_BIT_STRING:
		if (asn_decode_length(&ptr, buflen, &length) ||
		    (length > *buflen) || (length > *slen))
			return 1;
		*buflen -= length;
		*slen = length;
		cp = (u_char *)storage;
		bcopy(ptr, storage, length);
		ptr += length;
		break;
	default:
		return 1;
	}
	*buf = ptr;
	return 0;
}

static int
asn_encode(u_char **buf, int *buflen, u_char dtype, void *data, int32 dlen)
{
	u_char *ptr, oid_val[5];
	int i, j;
	int32 *number, siz;
	oid *op;

	ptr = *buf;

	switch(dtype) {
	case ASN1_INTEGER:
	case ASN1_COUNTER:
	case ASN1_GAUGE:
	case ASN1_TIMETICKS:
		if ((*buflen < (dlen + 1)) || (dlen > 4))
			goto encode_error;
		*ptr++ = dtype;
		*buflen -= 1;
		if (asn_encode_length(&ptr, buflen, dlen))
			return 1;
		number = (int32 *)data;
		for (i = 0; i < dlen; i++)
			*ptr++ = (u_char)((*number) >> (8 * (dlen - i - 1)));
		*buflen -= dlen;
		break;
	case ASN1_OCTET_STRING:
	case ASN1_IP_ADDRESS:
	case ASN1_OPAQUE:
	case ASN1_NSAP:
		if (*buflen < (dlen + 3))
			goto encode_error;
		*ptr++ = dtype;
		if (asn_encode_length(&ptr, buflen, dlen))
			return 1;
		bcopy(data, ptr, dlen);
		ptr += dlen;
		*buflen -= dlen + 1;
		break;
	case ASN1_OBJECT_ID:
		siz = (dlen - 2) * (sizeof(oid) + 1) + 1;
		if ( ((dlen < 2) && (dlen > *buflen)) ||
			((dlen >= 2) && ((siz + 3) > *buflen)))
			goto encode_error;
		op = (oid *)data;
		*ptr++ = dtype;
		*buflen -= 1;
		if (asn_encode_length(&ptr, buflen, siz))
			return 1;
		if (dlen < 2) {
			*ptr++ = 0;
			*ptr++ = 0;
			break;
		} else {
			*ptr++ = (op[0] * 40) + op[1];
			op += 2;
		}

		for (i = 0; i < (dlen - 2); i++) {
			*ptr++ = ((op[i] & 0xF0000000) >> 28) | 0x80;
			*ptr++ = ((op[i] & 0x0FE00000) >> 21) | 0x80;
			*ptr++ = ((op[i] & 0x001FC000) >> 14) | 0x80;
			*ptr++ = ((op[i] & 0x00003F80) >> 7)  | 0x80;
			*ptr++ =  (op[i] & 0x0000007F);
		}
		*buflen -= siz;
		break;
	case ASN1_NULL:
		if (*buflen < 2)
			goto encode_error;
		*ptr++ = dtype; 	
		*ptr++ = 0;
		*buflen -= 2;
		break;
	case ASN1_BIT_STRING:
		if ((dlen + 3) > *buflen)
			goto encode_error;
		if (asn_encode_length(&ptr, buflen, dlen))
			return 1;
		bcopy(data, ptr, dlen);
		ptr += dlen;
		*buflen -= dlen + 1;
		break;
	default:
		GASSERT(0);
	}
	*buf = ptr;
	return 0;
encode_error:
	/* XXX maybe do more here, the packet is too big */
	return 1;
}


static int
asn_encode_length(u_char **buf, int *buflen, int32 length)
{
	int i;
	u_char *ptr;

	length = htonl(length);
	ptr = *buf;

	*ptr++ = 0x84;
	bcopy(&length, ptr, sizeof(length));

	*buf += 5;
	*buflen -= 5;

	return 0;
}

static int
asn_decode_length(u_char **buf, int *buflen, int32 *length)
{
	u_char *ptr;
	int i, len;

	ptr = *buf;

	if (*ptr & ASN1_LONG_LENGTH) {
		len = (int)((*ptr++) & ~ASN1_LONG_LENGTH);
		if (len > 4)
			return 1;
		*length = 0;
		for (i = 0; i < len; i++)
			*length = (*length << (8 * i)) | *ptr++;
		len++;
		*buf = ptr;
		*buflen -= len + 1;
	} else {
		*length = (int32)(*ptr);
		*buf += 1;
		*buflen -= 1;
	}
	return 0;
}
