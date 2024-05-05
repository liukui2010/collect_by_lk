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


#define	INCLUDE_IF
#include "include.h"
#ifdef	PROTO_INET
#include "inet/inet.h"
#endif	/* PROTO_INET */
#ifdef	PROTO_INET6
#include "inet6/inet6.h"
#endif	/* PROTO_INET6 */
#ifdef	PROTO_ISO
#include "iso/iso.h"
#endif	/* PROTO_ISO */
#ifdef PROTO_IPX
#include "ipx_rip.h"
#endif /* PROTO_IPX */

struct sock_info sock_info[256] = { { 0 } };

const bits ll_type_bits[] = {
    { LL_OTHER,		"Unknown" },
    { LL_SYSTEMID,	"SystemID" },
    { LL_8022,		"802.2" },
    { LL_X25,		"X.25" },
    { LL_PRONET,	"ProNET" },
    { LL_HYPER,		"HyperChannel" }
};

/*
 * Compare two addresss
 * This routine compares the 'ga_data' fields of the two address, s1 and s2,
 * by comparing s1.ga_data[x] to s2.ga_data[x].  If s1 > s2,
 * then a 1 is returned. If s1 < s2, then -1 is returned and if s1 == s2,
 * then 0 is returned.
 *
 * By definition s1 > s2 if there exists an index x such that 
 * s1.ga_data[x] > s2.ga_data[x] and there exists no y such that y < x
 * and s1.ga_data[y] < s2.ga_data[y].
 *
 * This is like comparing binary coded decimals.
 */
int
sockaddrcmp2(sockaddr_un *s1, sockaddr_un *s2)
{
	register byte *a1 = (byte *) &s1->a.ga_family;
	register byte *a2 = (byte *) &s2->a.ga_family;
	register byte *lp = (byte *) s1 + MIN(socksize(s1), socksize(s2));
	register int i;

	/* The socket data immediately follows the ga_family field, so the first
	 * post-increment in the do loop below starts off the byte-by-byte 
	 * comparison using the data (not the family) just as it should.
	 *
	 * 'lp' is used to mark the number of bytes that can be compared between
	 * the two addresses.  If one address is shorter, we don't want to read
	 * past the end of the data.
	 *
	 * Loop below until we find two bytes that differ or reach the end of
	 * one of the addresses (i.e. data fields ). 
	 *
	 * If we find a byte that differs between the two (before we run out of
	 * data ) then the address with the larger byte is the larger address.
	 * And since we're subtracting bytes of s2 from bytes of s1, a subtraction 
	 * yielding a positive result indicates that s1 is "greater" and we
	 * return 1.  Otherwise we return a -1.
	 */
	do {
		i = *(a1++) - *(a2++);
		if (i) {
			return i > 0 ? 1 : -1;
		}
	} while (a1 < lp);

	/* If we arrived here, then one could not determine a winner by looking
	 * at bytes up to 'lp'.  Look at their complete sizes now instead.
	 * if s1 is longer than s2, then return 1
	 * if s1 is shorter than s2 then return -1
	 * if s1 is the same length as s2 then return 0
	 */
	i = socksize(s1) - socksize(s2);

	return i ? (i > 0 ? 1 : -1) : 0;
}


/*
 *	Compare two addresses
 */
int
sockaddrcmp(sockaddr_un *s1, sockaddr_un *s2)
{
    if (s1 == s2) {
	return TRUE;
    }
    
	assert (s1);
	assert (s2);
	
    if (socktype(s1) != socktype(s2)) {
	return FALSE;
    }

    switch (socktype(s1)) {
#ifdef	PROTO_INET
    case AF_INET:
	/* Only compare addresses */
	return sockaddrcmp_in(s1, s2);
#endif	/* PROTO_INET */

#if defined(PROTO_ISO) || defined(PROTO_ISIS2)
    case AF_ISO:
  return s1->iso.giso_len == s2->iso.giso_len
      && !bcmp((caddr_t) s1->iso.giso_addr,
         (caddr_t) s2->iso.giso_addr,
         s1->iso.giso_len - (sizeof (s1->iso) - 1));
#endif  /* PROTO_ISO || PROTO_ISIS2 */

#ifdef PROTO_INET6
    case AF_INET6:
        /* Only compare addresses */
        return sockaddrcmp_in6(s1, s2);
#endif /* PROTO_INET6 */

#ifdef PROTO_IPX
    case AF_IPX:
	return(IPXADDR_EQU(s1->ipx.sipx_addr, s2->ipx.sipx_addr));
#endif

    case AF_LL:
	return s1->ll.gll_type == s2->ll.gll_type
	    && s1->ll.gll_len == s2->ll.gll_len
	    && !bcmp((caddr_t) s1->ll.gll_addr,
		     (caddr_t) s2->ll.gll_addr,
		     s1->ll.gll_len - (sizeof (s1->ll) - 1));

    case AF_STRING:
	return s1->s.gs_len == s2->s.gs_len
	    && !strncmp(s1->s.gs_string, s2->s.gs_string,
			s1->s.gs_len - (sizeof(s1->s) - 1));
    }

    return FALSE;
}


/*
 *	Compare two addresses under a mask
 */
int
sockaddrcmp_mask(sockaddr_un *s1, sockaddr_un *s2, sockaddr_un *m)
{
    if (socktype(s1) == socktype(s2) &&
	socksize(s1) >= socksize(m) &&
	socksize(s2) >= socksize(m)) {
	register byte *cp = (byte *) s1->a.ga_data;
	register byte *mp = (byte *) m->a.ga_data;
	register byte *ap = (byte *) s2->a.ga_data;
	byte *lim = (byte *) s2 + socksize(m);

	if (socksize(m) <= socksize(s1)) {
	    while (ap < lim) {
		if ((*ap++ ^ *cp++) & *mp++) {
		    return FALSE;
		}
	    }

	    /* Success */
	    return TRUE;
	}
    }

    return FALSE;
}


sockaddr_un *
sockdup(const sockaddr_un *src)
{
	register size_t len = socksize(src);
	const byte *sp = (const byte *) src;
	sockaddr_un *dst;
	register byte *dp;
	block_t block_index = SI_INDEX(socktype(src));

	if (block_index) {
		dst = (sockaddr_un *) task_block_alloc(block_index);
	} else {
		dst = (sockaddr_un *) task_mem_malloc((task *) 0, len);
	}

	dp = (byte *) dst;
	while (len--) {
		*dp++ = *sp++;
	}

	return dst;
}


void
sockclean(sockaddr_un *dest)
{
    /* Clean up the address */
    switch (socktype(dest)) {
#ifdef	PROTO_INET
    case AF_INET:
	sock2port(dest) = 0;
	break;
#endif	/* PROTO_INET */

#ifdef PROTO_INET6
    case AF_INET6:
        sock2port6(dest) = 0;
	sock2flow6(dest) = 0; /* ? */
	break;
#endif /* PROTO_INET6 */

#ifdef	PROTO_ISO
    case AF_ISO:
	/* XXX - What do we need here? */
	break;
#endif	/* PROTO_ISO */
    }
}


void
sockmask(sockaddr_un *addr, sockaddr_un *mask)
{
    switch (socktype(addr)) {
#ifdef	PROTO_INET
    case AF_INET:
	/* Optimize IP case */
	sockmask_in(addr, mask);
	break;
#endif	/* PROTO_INET */

#ifdef PROTO_INET6
	/* may I use sockmask_in6 ? */
    case AF_INET6: {
        byte *ap = addr->a.ga_data;
	byte *mp = mask->a.ga_data;
	byte *lp = (byte *)mask + MIN(socksize(addr), socksize(mask));

	while (mp < lp) {
	    *ap++ &= *mp++;
	}

	if ( socksize(addr) > socksize(mask) ) {
	    lp = (byte *)addr + socksize(addr);
	    while (ap<lp) *ap++ = 0;
	}
    }
    break;
#endif	/* PROTO_INET6 */

    default: {
	    register byte *ap = addr->a.ga_data;
	    register byte *mp = mask->a.ga_data;
	    register byte *lp = (byte *) mask + MIN(socksize(addr), socksize(mask));
	    while (mp < lp) {
		*ap++ &= *mp++;
	    }

	    socksize(addr) = MIN(socksize(addr), socksize(mask));
	}
    }

    return;
}


int
sockishost(sockaddr_un *addr, sockaddr_un *mask)
{
    int host = 0;
    
    switch (socktype(addr)) {
#ifdef	PROTO_INET
    case AF_INET:
	if (mask
	    && mask == inet_mask_host) {
	    host++;
	}
	break;
#endif	/* PROTO_INET */

#ifdef PROTO_INET6
    case AF_INET6:
        if (mask
	    && mask == inet6_mask_host) {
	    host++;
	}
	break;
#endif /* PROTO_INET6 */

#ifdef	PROTO_ISO
    case AF_ISO:
	break;
#endif	/* PROTO_ISO */

#ifdef PROTO_IPX
    case AF_IPX:
	if (mask && IPXADDR_EQU(mask->ipx.sipx_addr, ipx_hostmask->sipx_addr))
		host++;
	break;
#endif

    default:
	assert(FALSE);
	break;
    }

    return host;
}


sockaddr_un *
sockhostmask(sockaddr_un *addr)
{
    sockaddr_un *mask = (sockaddr_un *) 0;

    switch (socktype(addr)) {
#ifdef	PROTO_INET
    case AF_INET:
	mask = inet_mask_host;
	break;
#endif	/* PROTO_INET */

#ifdef	PROTO_INET6
    case AF_INET6:
	mask = inet6_mask_host;
	break;
#endif	/* PROTO_INET6 */

#ifdef	PROTO_ISO
    case AF_ISO:
	mask = iso_mask_natural(addr);
	break;
#endif	/* PROTO_ISO */

#ifdef PROTO_IPX
    case AF_IPX:
	mask = (sockaddr_un *)ipx_hostmask;
	break;
    case AF_IPXSERV:
	break;
#endif

    default:
	assert(FALSE);
	break;
    }

    return mask;
}


/**/

/*
 *	Buffer for pseudo dynamic sockaddrs.
 */
static char *sock_buf;
static void_t sock_bufp;
static int sock_buf_size;

#define	BUF_ALLOC(ap, type, len) do { \
    int XXlen = ROUNDUP((len), sizeof (u_long)); \
    if ((caddr_t) sock_bufp + XXlen > sock_buf + sock_buf_size) \
	sock_bufp = (void_t) sock_buf; \
    ap = (type *) sock_bufp; \
    sock_bufp = (caddr_t) sock_bufp + XXlen; \
} while (0)

#define	SOCKBUILD(ap, type, len, af) do { \
    int Xlen = (len); \
    BUF_ALLOC(ap, type, Xlen); \
    socksize(ap) = Xlen; \
    socktype(ap) = (af); \
} while (0)

/*
 * build a copy of the given sockaddr_un
 */
sockaddr_un *
sockbuild_copy(const sockaddr_un *src)
{
	sockaddr_un *dst;
	const byte *sp;
	size_t len;
	byte *dp;
	int type;

	len = socksize(src);
	type = socktype(src);
	SOCKBUILD(dst, sockaddr_un, len, type);

	sp = (const byte *)src;
	dp = (byte *) dst;
	while (len--)
		*dp++ = *sp++;
	return (dst);
}

#ifdef	PROTO_INET
/*
 *	Build an inet address
 */
sockaddr_un *
sockbuild_in(u_short port, u_int32 addr)
{
    register sockaddr_un *sock;
    
    SOCKBUILD(sock, sockaddr_un, SOCKADDR_IN_LEN, AF_INET);
    sock2port(sock) = port;
    sock2ip(sock) = addr;

    return sock;
}
#endif	/* PROTO_INET */

#ifdef PROTO_INET6
/*
 *      Build an IPv6 address
 */
sockaddr_un *
sockbuild_in6(u_int16 port, const u_int8 *addr)
{
	register sockaddr_un *sock;

#ifdef	PROTO_BGP4MP
    SOCKBUILD(sock, sockaddr_un, SOCKADDR_BGP6_LEN, AF_INET6);
    socksize(sock) = SOCKADDR_IN6_LEN;
    bzero((char *)sock + SOCKADDR_IN6_LEN, sizeof(struct in6_addr));
#else	/* PROTO_BGP4MP */
    SOCKBUILD(sock, sockaddr_un, SOCKADDR_IN6_LEN, AF_INET6);
#endif	/* PROTO_BGP4MP */
    sock2port6(sock) = port;
    sock2flow6(sock) = 0;
    bcopy(addr, &sock2in6(sock), sizeof(struct in6_addr));

    return sock;
}
#endif  /* PROTO_INET6 */

#ifdef PROTO_IPX
/*
 *      Build an IPX address
 */
sockaddr_un *
sockbuild_ipx(u_int16 *net, char *laddr, u_int16 port)
{
  register sockaddr_un *sock;

  SOCKBUILD(sock, sockaddr_un, SOCKADDR_IPX_LEN, AF_IPX);
  if (net) {
    sock2ipxnets(sock)[0] = net[0];
    sock2ipxnets(sock)[1] = net[1];
  }
  else {
    sock2ipxnets(sock)[0] = 0;
                sock2ipxnets(sock)[1] = 0;
        }

  if (laddr)
    (void)bcopy(laddr, sockipx(sock)->sipx_addr.x_host.c_host, 6);
  else
    (void)bzero(sockipx(sock)->sipx_addr.x_host.c_host, 6);
  sockipx(sock)->sipx_addr.x_port = port;

  return(sock);
}

sockaddr_un *
sockbuild_ipxserv(u_int16 type)
{
	register sockaddr_un *sock;

	SOCKBUILD(sock, sockaddr_un, SOCKADDR_IPXSERV_LEN, AF_IPXSERV);
	sockipxserv(sock)->sipxserv_addr.ipxs_type = type;

	return(sock);
}
#endif  /* PROTO_IPX */

/*
 *	Build a string sockaddr
 */
sockaddr_un *
sockbuild_str(const char *str)
{
    register sockaddr_un *sock;
    int len = (strlen(str) + 1) + (sizeof (sock->s) - 1);

    SOCKBUILD(sock, sockaddr_un, len, AF_STRING);
    strcpy(sock->s.gs_string, str);

    return sock;
}


/*
 *	Build a string sockaddr
 */
sockaddr_un *
sockbuild_byte(u_char *str, size_t len)
{
    register sockaddr_un *sock;

    SOCKBUILD(sock, sockaddr_un, len + sizeof (sock->s) - 1, AF_STRING);
    bcopy((caddr_t) str, sock->s.gs_string, len);

    return sock;
}


#ifdef	PROTO_UNIX
/*
 *	Build a Unix domain sockaddr
 */
sockaddr_un *
sockbuild_un(const char *str)
{
    register sockaddr_un *sock;
    int len = (strlen(str) + 1) + (sizeof (sock->un) - 1);

    SOCKBUILD(sock, sockaddr_un, len, AF_UNIX);
    strcpy(sock->un.gun_path, str);

    return sock;
}
#endif	/* PROTO_UNIX */


#ifdef	SOCKADDR_DL
/*
 *	Build a data link sockaddr
 */
sockaddr_un *
sockbuild_dl(int indx, int type, const char *name, size_t nlen, u_char *addr,
    size_t alen, u_char *sel, size_t slen)
{
    register sockaddr_un *sock;
    int len = nlen + alen + slen + sizeof (sock->dl) - 1;

    SOCKBUILD(sock, sockaddr_un, len, AF_LINK);
    sock->dl.gdl_index = indx;
    sock->dl.gdl_type = type;
    sock->dl.gdl_nlen = nlen;
    sock->dl.gdl_alen = alen;
    sock->dl.gdl_slen = slen;
    bcopy(name, sock->dl.gdl_data, nlen);
    bcopy((caddr_t) addr, sock->dl.gdl_data + nlen, alen);
    bcopy((caddr_t) sel, sock->dl.gdl_data + nlen + alen, slen);

    return sock;
}
#endif	/* SOCKADDR_DL */


/*
 *	Build a link address sockaddr
 */
sockaddr_un *
sockbuild_ll(int type, const u_char *addr, size_t alen)
{
    register sockaddr_un *sock;
    int len = alen + sizeof (sock->ll) - 1;

    if (!alen) {
	return (sockaddr_un *) 0;
    }

    SOCKBUILD(sock, sockaddr_un, len, AF_LL);
    sock->ll.gll_type = type;
    bcopy(addr, (caddr_t) sock->ll.gll_addr, alen);

    return sock;
}


#if defined(PROTO_ISO) || defined(PROTO_ISIS2)
/*
 *	Build an ISO address sockaddr
 */
sockaddr_un *
sockbuild_iso(const u_char *addr, size_t alen)
{
    register sockaddr_un *sock;
    int len = alen + sizeof (sock->iso) - 1;

    SOCKBUILD(sock, sockaddr_un, len, AF_ISO);
    if (addr) {
	memcpy(sock->iso.giso_addr, addr, alen);
    } else {
	memset(sock->iso.giso_addr, 0, alen);
    }

    return sock;
}
#endif	/* PROTO_ISO || PROTO_ISIS2 */


void
sock_init_family (u_int family, u_int offset, size_t size, u_char *mask_list,
    size_t mask_size, const char *name)
{
    struct sock_info *sip;
    
    assert(family < 256);

    sip = &sock_info[family];
    sip->si_family = family;
    sip->si_offset = offset;
    sip->si_size = size;
    sip->si_mask_count = mask_size / size;
    sip->si_mask_min = (sockaddr_un *) ((void_t) mask_list);
    sip->si_mask_max = (sockaddr_un *) ((void_t) (mask_list + mask_size - size));
#ifdef	PROTO_BGP4MP
    if (family == AF_INET6)
	size = SOCKADDR_BGP6_LEN;
#endif	/* PROTO_BGP4MP */
    sip->si_index = task_block_init(size, name);
}


/**/
/*
 * number of bits in byte
 */
int n_bits[256] = {
        0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
        1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
        1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
        1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
        3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
        4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8
};

/*
 * Count the number of bits set in a mask, not including the family and
 * length fields.
 */
int
mask_bits(sockaddr_un *mask)
{
    register int i_bits = 0;
    register byte *cp = mask->a.ga_data;
    byte *lp = (byte * ) mask + socksize(mask);

    while (cp < lp) {
	i_bits += n_bits[*cp++];
    }

    return i_bits;
}


/*
 * Check to be sure all bits in a mask are contiguous.  Does not include
 * the family and length fields
 */
int
mask_contig(sockaddr_un *mask)
{
    register byte *cp = (byte *) mask + SI_OFFSET(socktype(mask));
    register byte *cplim = (byte *) mask + socksize(mask);
    
    static int contig[256] = {
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1 };

    /* Skip leading bytes of all ones */
    while (*cp == 0xff) {
	if (++cp == cplim) {
	    return TRUE;
	}
    }

    /* Make sure the first byte that is not all ones is contiguos */
    if (!contig[*cp++]) {
	return FALSE;
    }

    /* Make sure the rest of the bytes are zero */
    for (; cp < cplim; cp++) {
	if (*cp) {
	    return FALSE;
	}
    }

    /* Contiguous */
    return TRUE;
}


int
mask_contig_bits(sockaddr_un *mask)
{
    int mlen = 0;
    byte *mp = (byte *) mask + SI_OFFSET(socktype(mask));
    byte *mp_lim = (byte *) mask + socksize(mask);

    static byte contig_count[256] = {
	/* 0 - 127 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 128 - 191 */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	/* 192 - 223 */
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	/* 224 - 239 */
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	/* 240 - 255 */
	4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 7, 8
    };

    while (mp < mp_lim) {
	if (*mp == (1 << NBBY) - 1) {
	    mlen += NBBY;
	} else {
	    mlen += contig_count[*mp];
	    break;
	}
	mp++;
    }

    return mlen;
}

/**/

/* XXX - masks should be stored in a radix tree... */
struct mask_entry {
    struct mask_entry *rtm_forw;
    struct mask_entry *rtm_back;
    sockaddr_un *rtm_mask;
} ;

static int mask_dup = TRUE;
static struct mask_entry mask_list = { &mask_list, &mask_list} ;

#define	MASK_LIST(rtm)	for (rtm = mask_list.rtm_forw; rtm != &mask_list; rtm = rtm->rtm_forw)
#define	MASK_LIST_END(rtm)

sockaddr_un *
mask_locate(register sockaddr_un *mask)
{
    register u_int len;
    register struct mask_entry *rtm;
    register byte *cp = (byte *) mask + socksize(mask);
    static block_t mask_block_index;

    /* some optmized cases...
     */
    switch(socktype(mask)) {
#ifdef PROTO_IPX
    case AF_IPX:
  /* Only 3 possible masks!
   */
        if (mask->ipx.sipx_shost[0] || mask->ipx.sipx_shost[1] ||
      mask->ipx.sipx_shost[2])
    return((sockaddr_un *)ipx_hostmask);
  else if (mask->ipx.sipx_net)
    return((sockaddr_un *)ipx_netmask);
  else
    return((sockaddr_un *)ipxrip_nullmask);
#endif
    default:
  break;
    }

#ifdef PROTO_INET6
    if (socktype(mask) == AF_INET6) {
        mask->in6.gin6_flowinfo = 0;
	mask->in6.gin6_port = 0;
    }
#endif /* PROTO_INET6 */

    if (cp[-1]) {
	len = socksize(mask);
    } else {
	/* Trim the mask */
	while (cp-- > (byte *) mask && !*cp) ;
	len = cp - (byte *) mask + 1;

	assert(socksize(mask) >= 2);
    }
    
    MASK_LIST(rtm) {
	if (socksize(rtm->rtm_mask) > len) {
	    /* Not in list */
	    goto New;
	}
	if (socksize(rtm->rtm_mask) == len) {
	    register byte *cp1 = (byte *) rtm->rtm_mask;
	    register byte *cp2 = (byte *) mask;
	    byte *lp = cp1 + len;

	    while (++cp2, ++cp1 < lp) {
		if (*cp1 > *cp2) {
		    /* Not in list */
		    goto New;
		}
		if (*cp1 < *cp2) {
		    /* This is not the one */
		    goto Continue;
		}
	    }

	    /* Found it */
	    goto Return;
	}

    Continue:
	;
    } MASK_LIST_END(rtm) ;

 New:
    /* Insert at the end of the list */
    rtm = rtm->rtm_back;

    /* Insert before this one */
    if (!mask_block_index) {
	mask_block_index = task_block_init(sizeof (struct mask_entry), "mask_entry");
    }
    
    INSQUE(task_block_alloc(mask_block_index), rtm);
    rtm = rtm->rtm_forw;
    rtm->rtm_mask = mask_dup ? sockdup(mask) : mask;
    socksize(rtm->rtm_mask) = len;

 Return:
    return rtm->rtm_mask;
}


int
mask_refines(sockaddr_un *m1, sockaddr_un *m2)
{
    register byte *lim = (byte *) m2 + socksize(m2);
    register byte *lim2 = lim;
    register byte *b1 = (byte *) m1 + 1;
    register byte *b2 = (byte *) m2 + 1;
    int longer = socksize(m2) - socksize(m1);
    int masks_are_equal = 1;

    if (longer > 0) {
	lim -= longer;
    }

    while (b2 < lim) {
	if (*b2 & ~(*b1)) {
	    return 0;
	}
	if (*b2++ != *b1++) {
	    masks_are_equal = 0;
	}
    }

    while (b2 < lim2) {
	if (*b2++) {
	    return 0;
	}
    }

    if (masks_are_equal
	&& longer < 0) {
	for (lim2 = b1 - longer; b1 < lim2;) {
	    if (*b1++) {
		return 1;
	    }
	}
    }

    return !masks_are_equal;
}


void
mask_insert(register sockaddr_un *mask)
{
    sockaddr_un *new_mask;
    
    mask_dup = FALSE;
    new_mask = mask_locate(mask);
    mask_dup = TRUE;
    /* assert(new_mask == mask); */
}


void
mask_dump(FILE *fd)
{
    register struct mask_entry *rtm;

    fprintf(fd, "\tMasks and addresses:\n\n\t\tFamily\tAddress\tLength\tMask\n");
	
    MASK_LIST(rtm) {
	register sockaddr_un *mask = rtm->rtm_mask;

	switch (socktype(mask)) {
#ifdef	PROTO_INET
	case AF_INET:
	    fprintf(fd, "\t\tinet\t%X\t%d\t",
		    mask,
		    inet_prefix_mask(mask));
	    break;
#endif	/* PROTO_INET */

#ifdef PROTO_INET6
	case AF_INET6:
	  fprintf(fd, "\t\tinet6\t%X\t%d\t",
		  mask,
		  inet6_prefix_mask(mask));
	  break;
#endif /* PROTO_INET6 */

#ifdef	PROTO_ISO
	case AF_ISO:
	    fprintf(fd, "\t\tiso\t%X\t%d\t",
		    mask,
		    iso_prefix_mask(mask));
	    break;
#endif	/* PROTO_ISO */
	}
	fprintf(fd, "%A\n",
		mask);
    } MASK_LIST_END(rtm) ;

    fprintf(fd, "\n");
}


/*
 *	Convert a gated sockaddr into an Unix sockaddr.
 *	Returns the address of a static structure.
 */
struct sockaddr *
sock2unix(sockaddr_un *ga, int *len)
{

    switch (socktype(ga)) {
#ifdef	PROTO_UNIX
    case AF_UNIX:
        {
	    struct sockaddr_un *un;

	    BUF_ALLOC(un, struct sockaddr_un, ga->un.gun_len);

	    bcopy((caddr_t) &ga->un, (caddr_t) un, ga->un.gun_len);
#ifndef	USE_SOCKLEN
	    un->sun_family = ga->un.gun_family;
#endif	/* USE_SOCKLEN */

	    if (len) {
		*len = ga->un.gun_len;
	    }
	    return (struct sockaddr *) un;
	}
#endif	/* PROTO_UNIX */

#ifdef	PROTO_INET
    case AF_INET:
        {
	    struct sockaddr_in *in;

	    BUF_ALLOC(in, struct sockaddr_in, sizeof (struct sockaddr_in));
	
	    bzero((caddr_t) in, sizeof (*in));

	    assert(!((u_long) in % 4));
	
	    in->sin_family = AF_INET;
#ifdef	USE_SOCKLEN
	    in->sin_len = sizeof (*in);
#endif	/* USE_SOCKLEN */
	    in->sin_port = sock2port(ga);
	    in->sin_addr = sock2in(ga);	/* struct copy */

	    if (len) {
		*len = sizeof (struct sockaddr_in);
	    }
	    return (struct sockaddr *) in;
	}
#endif	/* PROTO_INET */

#ifdef PROTO_INET6
    case AF_INET6:
	{
	    struct sockaddr_in6 *in6;

	    BUF_ALLOC(in6, struct sockaddr_in6, sizeof (struct sockaddr_in6));

	    bzero((caddr_t) in6, sizeof (*in6));

	    assert(!((u_long) in6 % 4));

	    in6->sin6_family = AF_INET6;
#ifdef	USE_SOCKLEN 
	    in6->sin6_len = sizeof (*in6);
#endif  /* USE_SOCKLEN */
	    in6->sin6_port = sock2port6(ga);
	    in6->sin6_flowinfo = sock2flow6(ga);
	    in6->sin6_addr = sock2in6(ga); /* struct copy */

			if (len) {
	        *len = sizeof (struct sockaddr_in6);
	    }
	    return (struct sockaddr *) in6;
    }
#endif /* PROTO_INET6 */

#ifdef PROTO_IPX
    case AF_IPX:
  {
            struct sockaddr_ipx *ipx;

            BUF_ALLOC(ipx, struct sockaddr_ipx, sizeof (struct sockaddr_ipx));

      *ipx = ga->ipx;

            if (len) {
                *len = sizeof (struct sockaddr_ipx);
            }
            return (struct sockaddr *) ipx;
        }
#endif  /* PROTO_IPX */

#ifdef  SOCKADDR_DL
    case AF_LINK:
        {
      struct sockaddr_dl *dl;

      BUF_ALLOC(dl, struct sockaddr_dl, sizeof (struct sockaddr_dl));

      bzero((caddr_t) dl, sizeof (*dl));

#ifdef  USE_SOCKLEN
      dl->sdl_len = sizeof (struct sockaddr_dl);
#endif
      dl->sdl_family = AF_LINK;
      dl->sdl_index = ga->dl.gdl_index;
      dl->sdl_type = ga->dl.gdl_type;
      dl->sdl_nlen = ga->dl.gdl_nlen;
      dl->sdl_alen = ga->dl.gdl_alen;
      dl->sdl_slen = ga->dl.gdl_slen;

      bcopy(ga->dl.gdl_data, dl->sdl_data, ga->dl.gdl_nlen);
      bcopy(ga->dl.gdl_data + ga->dl.gdl_nlen,
      dl->sdl_data + ga->dl.gdl_nlen, ga->dl.gdl_alen);
      bcopy(ga->dl.gdl_data + ga->dl.gdl_nlen + ga->dl.gdl_alen,
      dl->sdl_data + ga->dl.gdl_nlen + ga->dl.gdl_alen,
      ga->dl.gdl_slen);
      return (struct sockaddr *) dl;
  }
#endif /* USE_SOCKLEN */

#ifdef	PROTO_ISO
    case AF_ISO:
        {
	    struct sockaddr_iso *iso;
	    
	    BUF_ALLOC(iso, struct sockaddr_iso, sizeof (struct sockaddr_iso));

	    bzero((caddr_t) iso, sizeof (*iso));

	    /* Copy the address and leave the selectors null */

	    iso->siso_len = sizeof (struct sockaddr_iso);
	    iso->siso_family = AF_ISO;
	    iso->siso_addr.isoa_len = ga->iso.giso_len - ((caddr_t) ga->iso.giso_addr - (caddr_t) ga);
	    bcopy((caddr_t) ga->iso.giso_addr,
		  iso->siso_addr.isoa_genaddr,
		  iso->siso_addr.isoa_len = ga->iso.giso_len - ((caddr_t) ga->iso.giso_addr - (caddr_t) ga));

	    if (len) {
		*len = ga->iso.giso_len;
	    }
	    return (struct sockaddr *) iso;
	}
#endif	/* PROTO_ISO */
    default:
	break;
    }

    return (struct sockaddr *) 0;
}


/*
 *	Convert a Unix sockaddr into a gated sockaddr.
 */
sockaddr_un *
sock2gated(struct sockaddr *ua, size_t len)
{
    sockaddr_un *ga;

    assert(len);

    switch (ua->sa_family) {
#ifdef AF_KEY
    case AF_KEY:
	{
	    struct sockaddr_key *key = (struct sockaddr_key *) ((void_t) ua);

	    SOCKBUILD(ga, sockaddr_un, len, AF_KEY);
	    bcopy((caddr_t)key, (caddr_t)ga, len);
	}
	break;
#endif /* AF_KEY */

#ifdef	PROTO_UNIX
    case AF_UNIX:
        {
	    struct sockaddr_un *un = (struct sockaddr_un *) ((void_t) ua);

	    SOCKBUILD(ga, sockaddr_un, len, AF_UNIX);
	    bcopy(un->sun_path, ga->un.gun_path, len);
	}
	break;
#endif	/* PROTO_UNIX */

#ifdef	PROTO_INET
    case AF_INET:
        {
	    struct sockaddr_in *in = (struct sockaddr_in *) ((void_t) ua);
#ifdef	USE_SOCKLEN
	    register u_short port = 0;
	    u_int32 addr = 0;

#define	PORT_OFFSET(in)	((caddr_t) &(in)->sin_port - (caddr_t) in)
#define	ADDR_OFFSET(in)	((caddr_t) &(in)->sin_addr - (caddr_t) in)
	    if (len > sizeof (struct sockaddr_in)) {
		len = sizeof (struct sockaddr_in);
	    }

	    if (len >= PORT_OFFSET(in) + sizeof (in->sin_port)) {
		/* We have at least port */
		port = in->sin_port;
		if (len > ADDR_OFFSET(in)) {
		    /* Copy as much as there is */
		    bcopy((caddr_t) &in->sin_addr,
			  (caddr_t) &addr,
			  (size_t) MIN(len - ADDR_OFFSET(in), sizeof (in->sin_addr)));
		}
	    }
	    ga = sockbuild_in(port, addr);
#else	/* USE_SOCKLEN */
	    ga = sockbuild_in(in->sin_port, in->sin_addr.s_addr);
#endif	/* USE_SOCKLEN */
	}
	break;
#endif	/* PROTO_INET */

#ifdef PROTO_INET6
    case AF_INET6:
	{
	    struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) ((void_t) ua);
#ifdef	USE_SOCKLEN
	    register u_short port = 0;
	    byte addr[16];

#define PORT6_OFFSET(in6)	((caddr_t) &(in6)->sin6_port - (caddr_t) in6)
#define FLOW6_OFFSET(in6)	((caddr_t) &(in6)->sin6_flowinfo - (caddr_t) in6)
#define ADDR6_OFFSET(in6)	((caddr_t) &(in6)->sin6_addr - (caddr_t) in6)
	    if (len > sizeof (struct sockaddr_in6)) {
	        len = sizeof (struct sockaddr_in6);
	    }

	    bzero(addr, 16);
	    if (len >= PORT6_OFFSET(in6) + sizeof (in6->sin6_port)) {
	        /* We have at least port */
	        port = in6->sin6_port;
		if (len > ADDR6_OFFSET(in6)) {
		    /* Copy as much as there is */
		    bcopy((caddr_t) &in6->sin6_addr,
			  (caddr_t) &addr,
			  (size_t) MIN(len - ADDR6_OFFSET(in6), sizeof (in6->sin6_addr)));
		}
	    }
	    ga = sockbuild_in6(port, addr);
#else	/* USE_SOCKLEN */
	    ga = sockbuild_in6(in6->sin6_port, (byte *)&in6->sin6_addr);
#endif	/* USE_SOCKLEN */
	}
	break;
#endif /* PROTO_INET6 */

#ifdef PROTO_IPX
    case AF_IPX:
  {
    struct sockaddr_ipx *ipx = (struct sockaddr_ipx *)ua;

    ga = sockbuild_ipx(sock2ipxnets(ua),
      ipx->sipx_host, ipx->sipx_port);
  }
  break;
#endif  /* PROTO_IPX */

#ifdef	PROTO_ISO
    case AF_ISO:
        {
	    struct sockaddr_iso *iso = (struct sockaddr_iso *) ua;
	    int isoa_len = 0;

	    if (len >= (byte *) iso->siso_addr.isoa_genaddr - (byte *) iso) {
		isoa_len = iso->siso_addr.isoa_len;
	    }

	    /* If this is a mask, the length field is probably zero, */
	    /* but it could be all ones. */
	    if (!isoa_len
		|| isoa_len > ISO_MAXADDRLEN) {
		/* Try to derive the length from the length of the sockaddr. */
		/* This could easily be too long because there is padding at */
		/* the end */

		isoa_len = ((byte *) iso + len) - (byte *) iso->siso_addr.isoa_genaddr;
		if (isoa_len < 0) {
		    isoa_len = 0;
		} else if (isoa_len > ISO_MAXADDRLEN) {
		    isoa_len = ISO_MAXADDRLEN;
		}
	    }
	    len = sizeof (ga->iso) - 1 + isoa_len;

	    SOCKBUILD(ga, sockaddr_un, len, AF_ISO);
	    /* Ditch the selectors and just grab the address */
	    bcopy((caddr_t) iso->siso_addr.isoa_genaddr,
		  (caddr_t) ga->iso.giso_addr,
		  (size_t) isoa_len);
	}
	break;
#endif	/* PROTO_ISO */

#ifdef	SOCKADDR_DL
    case AF_LINK:
#ifdef	USE_SOCKLEN
        {
	    struct sockaddr_dl *dl = (struct sockaddr_dl *) ((void_t) ua);
	    BUF_ALLOC(ga, sockaddr_un, dl->sdl_len);
	    bcopy((caddr_t) dl, (caddr_t) &ga->dl, dl->sdl_len);
	}
#else	/* USE_SOCKLEN */
	{
	    struct sockaddr_dl *dl = (struct sockaddr_dl *) ((void_t) ua);
#ifdef	IRIX_SDL_LEN_BUG

	   /* IN IRIX 6.4 dl->sdl_len is always zero, recalculate it!!! */
            dl->sdl_len=dl->sdl_len - sizeof(dl->sdl_data) + dl->sdl_alen + dl->s
dl_slen + dl->sdl_nlen;
            BUF_ALLOC(ga, sockaddr_un, dl->sdl_len);
            bcopy((caddr_t) dl, (caddr_t) &ga->dl, dl->sdl_len);
#else /* IRIX_SDL_LEN_BUG */
            BUF_ALLOC(ga, sockaddr_un, sizeof(*dl));

            bcopy((caddr_t) dl, (caddr_t) &ga->dl, sizeof(*dl));
            ga->dl.gdl_len = sizeof(*dl);
            ga->dl.gdl_family =  AF_LINK;
#endif /* IRIX_SDL_LEN_BUG */
	}
#endif /* USE_SOCKLEN */	
	break;


#endif	/* SOCKADDR_DL */

#ifdef	KRT_RT_SOCK
    case AF_ROUTE:
	SOCKBUILD(ga, sockaddr_un, 2, AF_ROUTE);
	break;
#endif	/* KRT_RT_SOCK */

    default:
	return (sockaddr_un *) 0;
    }

    return ga;
}


void
sock_init(void)
{
    sock_buf_size = task_pagesize * SOCK_BUF_PAGES;
    sock_buf = task_block_malloc(sock_buf_size);
    sock_bufp = sock_buf;
}

int unix_socksize(struct sockaddr *x, int family)
{
#ifdef  USE_SOCKLEN
  return ((x)->sa_len);
#else /* USE_SOCKLEN */
#ifdef __sgi
  return (_FAKE_SA_LEN_DST(x) > 0 ? _FAKE_SA_LEN_DST(x) : sizeof (*x));
#else
  switch(family) {
#ifdef PROTO_INET6
    case(AF_INET6):
        return (sizeof(struct sockaddr_in6));
				break;
#endif
    case(AF_INET):
        return (sizeof(struct sockaddr_in));
				break;
#ifdef USE_SOCKADDR_UN
    case(AF_UNIX):
        return (sizeof(struct sockaddr_un));
				break;
#endif
#ifdef SOCKADDR_DL
    case(AF_LINK):
        return (sizeof(struct sockaddr_dl));
				break;
#endif /* SOCKADDR_DL */
#ifdef PROTO_ISO
    case(AF_ISO):
        return (sizeof(struct sockaddr_iso));
				break;
#endif
    default:
        return (sizeof(*x));
    }
#endif  /* __sgi */
#endif  /* USE_SOCKLEN */
}


#define IPMAXLEN        20
#define MASK(m)         ((m)?   (int)0x80000000 >> ((m) - 1): 0)

/* Convert a string ip/mask into a sockaddr_un * for ip and mask
 * Returns 1 for an syntax error
 */
int
sockstr(const char *str, sockaddr_un **addr, sockaddr_un **mask)
{
        char *c, lbuff[IPMAXLEN];
        int masklen = -1, nbtok = 0;
        struct in_addr ip;
	int error = 0;

        (void)strncpy(lbuff, str, IPMAXLEN);

        /* first the mask */
        if ((c = (char *)index(lbuff, '/'))) {
                masklen = atoi(c + 1);
                *c = '\0';
        }

        /* Them parse the X.X.X.X address */
	if(!inet_aton(lbuff, &ip)) error = 1;

        if (masklen < 0)
                masklen = DEFAULTMASKLEN(ip.s_addr);

        /* Make the gated socket addresses */
        *addr = sockbuild_in(0, ip.s_addr);
        *mask = inet_mask_locate(htonl(MASK(masklen)));

	return(error);
}

#ifdef PROTO_IPX

/* parse an IPX address into a sockaddr_un. Return 1 on error.
 */
int
sockstr_ipx(char *str, sockaddr_un **addr, sockaddr_un **mask)
{
	struct ipx_addr ipxaddr;

	/* well, i do a ipx_addr() call from the ipx library.  */
	*addr = sockbuild_ipx(NULL, NULL, 0);
	sockipx(*addr)->sipx_addr = *ipx_addr(str);

	/* If no host address, the mask is the default.  */
	if (ipx_nullhost(sockipx(*addr)->sipx_addr))
		*mask = (sockaddr_un *)ipx_netmask;
	else
		*mask = (sockaddr_un *)ipx_hostmask;

	return(0);
}

/* Parse an IPX service into a sockaddr_un. Return 1 on error.
 */
int
sockstr_ipxserv(char *str, sockaddr_un **addr, sockaddr_un **mask)
{
	u_int16 serv;

	/* first we try the service by name....  */
	/* [...] later... */

	/* Then if the string starts with '0x' that's a Hex number.  */
	if (!strncasecmp(str, "0x", 2))
		(void)sscanf(str, "%hx", &serv);
	else
		(void)sscanf(str, "%hd", &serv);

	*addr = sockbuild_ipxserv(serv);
        return(0);
}
#endif /* PROTO_IPX */

