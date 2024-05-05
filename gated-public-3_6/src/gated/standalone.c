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


#define	MALLOC_OK
#include "include.h"
#if defined(PROTO_INET)
#include "inet/inet.h"
#endif /* PROTO_INET */
#if defined(PROTO_INET6)
#include "inet6/inet6.h"
#endif /* PROTO_INET6 */

/* Support for stand-alone programs (ripquery, gdc) */
#if defined(PROTO_INET)
sockaddr_un *inet_masks[34] = { 0 };
byte inet_mask_list[SOCKADDR_IN_LEN * (sizeof (struct in_addr) * NBBY + 1)];
struct sock_info sock_info[256] = { { 0 } };
#endif /* PROTO_INET */

#if defined(PROTO_INET6)
sockaddr_un *inet6_masks[130] = { 0 };
byte inet6_mask_list[SOCKADDR_IN6_LEN * (sizeof (struct in6_addr) * NBBY + 1)];
#endif /* PROTO_INET6 */

struct gtime task_time;

const bits ll_type_bits[] = {
    { LL_OTHER,		"Unknown" },
    { LL_8022,		"802.2" },
    { LL_X25,		"X.25" },
    { LL_PRONET,	"ProNET" },
    { LL_HYPER,		"HyperChannel" }
};


void
task_assert (const char * file, const int line, const char * test)
{
    fprintf(stderr,
	    "Assertion failed: file \"%s\", line %d: %s",
	    file,
	    line,
	    test);

    /* Exit with a core dump */
    abort();
}


void_t
task_mem_malloc (task * tp UNUSED, size_t size)
{
    void_t p;

    p = (void_t) malloc(size);
    if (!p) {
	(void) fprintf(stderr,
		       "malloc: Can not malloc(%d)",
		       size);
	abort();
    }

    return p;
}


void_t
task_mem_calloc (task * tp UNUSED, u_int number, size_t size)
{
    void_t p;

    p = (void_t) calloc(number, size);
    if (!p) {
	(void) fprintf(stderr,
		       "calloc: Can not calloc(%d, %d)",
		       number,
		       size);
	abort();
    }

    return p;
}


/*ARGSUSED*/
void
task_mem_free (task * tp UNUSED, void_t p)
{
    if (p) {
	free((caddr_t) p);
    }
}


/**/

u_short
task_get_port (trace * tf UNUSED, const char * name, const char * proto, u_short default_port)
{
    struct servent *se = getservbyname((const char *)name, proto);
    u_short port;

    if (se) {
	port = se->s_port;
    } else {
	port = default_port;
	(void) fprintf(stderr,
		       "task_get_port: getservbyname(\"%s\", \"%s\") failed, using port %d\n",
		       name,
		       proto,
		       htons(port));
    }

    return port;
}

int
task_get_proto (trace * tf UNUSED, const char * name, int default_proto)
{
    struct protoent *pe = getprotobyname(name);
    int proto;

    if (pe) {
			proto = pe->p_proto;
    } else {
			proto = default_proto;
			(void) fprintf(stderr,
		       "task_get_proto: getprotobyname(\"%s\") failed, using proto %d\n",
		       name,
		       proto);
    }

    return proto;
}

const char * keydump(void);

const char *
keydump ()
{
	return("***");
}

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
mask_locate (register sockaddr_un * mask)
{
    register u_int len;
    register struct mask_entry *rtm;
    register byte *cp = (byte *) mask + socksize(mask);

#ifdef PROTO_INET6
	if (socktype(mask) == AF_INET6) {
		mask->in6.gin6_flowinfo = 0;
		mask->in6.gin6_port = 0;
	}
#endif

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

    INSQUE(task_mem_calloc(0, 1, sizeof(struct mask_entry)), rtm);
    rtm = rtm->rtm_forw;
    rtm->rtm_mask = mask_dup ? sockdup(mask) : mask;
    socksize(rtm->rtm_mask) = len;

 Return:
    return rtm->rtm_mask;
}

void
mask_insert (register sockaddr_un * mask)
{
    sockaddr_un *new_mask;
    
    mask_dup = FALSE;
    new_mask = mask_locate(mask);
    mask_dup = TRUE;
    assert(new_mask == mask);
}

sockaddr_un *sockdup(const sockaddr_un *src)
{
    size_t len = socksize(src);
    const byte *sp = (const byte *) src;
    sockaddr_un *dst;
    register byte *dp;

    dst = (sockaddr_un *) task_mem_malloc((task *) 0, len);

    dp = (byte *) dst;
    while (len--) {
	*dp++ = *sp++;
    }

    return dst;
}

void
sock_init_family (u_int family, u_int offset, size_t size, byte * masklist, size_t masksize, const char * name)
{
    struct sock_info *sip;
    
    assert(family < 256);

    sip = &sock_info[family];
    sip->si_family = family;
    sip->si_offset = offset;
    sip->si_size = size;
    sip->si_mask_count = masksize / size;
    sip->si_mask_min = (sockaddr_un *) ((void_t) masklist);
    sip->si_mask_max = (sockaddr_un *) ((void_t) (masklist + masksize));
/*    sip->si_index = task_block_init(size, name); */
}


#if defined(PROTO_INET6)
#define	INET6_IFPS_ALLROUTERS	IFPS_KEEP1	/* We joined the all-routers group on this interface */
sockaddr_un *inet6_addr_allnodes;	/* All nodes multicast address */
sockaddr_un *inet6_addr_allrouters;	/* All routers multicast address */

static const bits inet6_if_bits[] = {
    { INET6_IFPS_ALLROUTERS, "AllRouters" },
    { 0 }
};

/*
 *	Init all kinds of IPv6 structures
 */
void
inet6_family_init ()
{
    struct in6_addr ia;
    sockaddr_un *addr;
    sockaddr_un **mp = inet6_masks;
    sockaddr_un *mpp = (sockaddr_un *) ((void_t) inet6_mask_list);
    byte *cp, *lp;

    /* Get an address to work with */
    bzero((void_t) &ia, sizeof(ia));
    addr = sockbuild_in6(0, (byte *) &ia);

    /* Build all possible contiguous masks */
    /* Add null mask */
    sockcopy(addr, mpp);
    mask_insert(*mp++ = mpp);
    mpp = (sockaddr_un *) ((void_t) ((byte *) mpp + SOCKADDR_IN6_LEN));

    for (cp = (byte *) &addr->in6.gin6_addr, lp = cp + sizeof(ia);
	 cp < lp; cp++) {
	int bit = NBBY;

	*cp = (byte) 0;

	while (bit--) {
	    *cp |= 1 << bit;
	    sockcopy(addr, mpp);
	    mask_insert(*mp++ = mpp);
	    mpp = (sockaddr_un *) ((void_t) ((byte *) mpp + SOCKADDR_IN6_LEN));
	}
    }
    
    sock_init_family(AF_INET6,
		     (SOCKADDR_IN6_LEN - sizeof sock2in6(inet6_addr_default)),
		     SOCKADDR_IN6_LEN,
		     inet6_mask_list,
		     sizeof inet6_mask_list,
		     "sockaddr_un.in6");

    bzero((void_t) &ia, sizeof(ia));
    ia.s6_addr[0] = 0xff;
    ia.s6_addr[1] = 2;
    ia.s6_addr[15] = 1;
    inet6_addr_allnodes = sockdup(sockbuild_in6(0, (byte *) &ia));
    ia.s6_addr[15] = 2;
    inet6_addr_allrouters = sockdup(sockbuild_in6(0, (byte *) &ia));

}

static char *sock_buf;
static void_t sock_bufp;
static int sock_buf_size;

#define BUF_ALLOC(ap, type, len) do { \
    int XXlen = ROUNDUP((len), sizeof (u_long)); \
    if ((caddr_t) sock_bufp + XXlen > sock_buf + sock_buf_size) \
			sock_bufp = (void_t) sock_buf; \
		ap = (type *) sock_bufp; \
		sock_bufp = (caddr_t) sock_bufp + XXlen; \
} while (0)

#define SOCKBUILD(ap, type, len, af) do { \
    int Xlen = (len); \
    BUF_ALLOC(ap, type, Xlen); \
    socksize(ap) = Xlen; \
    socktype(ap) = (af); \
} while (0)

sockaddr_un *
sockbuild_in6(u_int16 port, const u_int8 *addr)
{
    register sockaddr_un *sock; 

		SOCKBUILD(sock, sockaddr_un, SOCKADDR_IN6_LEN, AF_INET6);
    sock2port6(sock) = port;

    bcopy(addr, &sock2in6(sock), sizeof(struct in6_addr));

    return sock;
}

#endif /* PROTO_INET6 */
