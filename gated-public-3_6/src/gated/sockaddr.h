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


typedef union {
    /* Generic address used only for referencing length and family */
    struct {
	byte	ga_len;
	byte	ga_family;
	byte	ga_data[1];
    } a;
    /* Unix domain address */
    struct {
	byte	gun_len;
	byte	gun_family;
	char	gun_path[1];
    } un;
#ifdef	PROTO_INET
    /* IP address.  Note that sin_zero has been removed */
    struct {
	byte	gin_len;
	byte	gin_family;
	u_int16	gin_port;
	struct in_addr gin_addr;
    } in;
#endif	/* PROTO_INET */
#ifdef  PROTO_IPX
    struct sockaddr_ipx ipx;
    struct sockaddr_ipxserv ipxserv;
#endif  /* PROTO_IPX */
#ifdef  PROTO_INET6 
    /* IPv6 address. */
    struct {
        byte    gin6_len;
        byte    gin6_family;
        u_int16 gin6_port;
        u_int32 gin6_flowinfo;
        struct in6_addr gin6_addr;
    } in6;
#ifdef  PROTO_BGP4MP
    /* Dual (global/link-local) IPv6 addresses */
    struct {
        byte    bgp6_len;
        byte    bgp6_family;
        u_int16 bgp6_port;
        u_int32 bgp6_flowinfo;
        struct in6_addr bgp6_addr;
        struct in6_addr bgp6_lladdr;
    } bgp6;
#endif	/* PROTO_BGP4MP*/
/* For easy programming, added by Yixin */
#define	g6_addr	in6.gin6_addr
#endif  /* PROTO_INET6 */
#ifdef	SOCKADDR_DL
    struct {
	u_char	gdl_len;	/* Total length of sockaddr */
	u_char	gdl_family;	/* AF_DLI */
	u_short	gdl_index;	/* if != 0, system given index for interface */
	u_char	gdl_type;	/* interface type */
	u_char	gdl_nlen;	/* interface name length, no trailing 0 reqd. */
	u_char	gdl_alen;	/* link level address length */
	u_char	gdl_slen;	/* link layer selector length */
	char	gdl_data[1];	/* work area */
    } dl;
#endif	/* SOCKADDR_DL */
#if defined(PROTO_ISO) || defined(PROTO_ISIS2)
    struct {
	u_char	giso_len;
	u_char	giso_family;
	u_char	giso_addr[1];
    } iso;
#endif	/* PROTO_ISO || PROTO_ISIS2 */
    struct {
	u_char	gll_len;
	u_char	gll_family;
	u_char	gll_type;
	u_char	gll_addr[1];
    } ll;
    struct {
	byte	gs_len;
	byte	gs_family;
	char	gs_string[1];
    } s;
} sockaddr_un;

/* The maximum possible _address_ (not socket) length */
#define	SOCK_MAX_ADDRESS_LEN	20

#ifndef       SOCK_BUF_PAGES
#define       SOCK_BUF_PAGES  1
#endif        /* SOCK_BUF_PAGES */

#define	AF_LL		253	/* Link level address */
#ifdef	notdef
#ifndef	AF_LINK
#define	AF_LINK		254	/* Link level interface info */
#endif	/* AF_LINK */
#endif	/* notdef */
#define	AF_STRING	255	/* String hack */

/* For compatibility with BSD 4.4 and later */
#define	socksize(x)	((x)->a.ga_len)
#define	socktype(x)	((x)->a.ga_family)
#define	sockcopy(x, y)	bcopy((caddr_t) (x), (caddr_t) (y), socksize(x))

#ifndef	SOCK_BUF_PAGES
#define	SOCK_BUF_PAGES  1
#endif	/* SOCK_BUF_PAGES */


/* Types for AF_LL */
#define	LL_OTHER	0	/* Unknown or Other */
#define	LL_SYSTEMID	1	/* ISO System ID */
#define	LL_8022		2	/* IEEE 802.2 Address */
#define	LL_X25		3	/* X.25 Address */
#define	LL_PRONET	4	/* Proteon Pronet */
#define	LL_HYPER	5	/* NSC Hyperchannel */

extern const bits ll_type_bits[];

/* number of bits in a byte */
extern int n_bits[256];


struct sock_info {
    u_int	si_family;	/* Address family */
    u_int	si_offset;	/* Offset to beginning of address */
    u_int	si_size;	/* Maximum size */
    block_t	si_index;	/* Pointer to allocation block */
    u_int	si_mask_count;	/* Number of masks */
    sockaddr_un	*si_mask_min;	/* Minimum length mask */
    sockaddr_un	*si_mask_max;	/* Maximum length mask */
    adv_entry	*si_martians;	/* Martians for this family */
};
#define	SI_FROM_AF(af)		(&sock_info[(af)])
#define	SI_OFFSET(af)		SI_FROM_AF(af)->si_offset
#define	SI_SIZE(af)		SI_FROM_AF(af)->si_size
#define	SI_INDEX(af)		SI_FROM_AF(af)->si_index
#define	SI_MASK_MIN(af)		SI_FROM_AF(af)->si_mask_min
#define	SI_MASK_MAX(af)		SI_FROM_AF(af)->si_mask_max
#define	SI_MASK_COUNT(af)	SI_FROM_AF(af)->si_mask_count
#define	SI_MARTIANS(af)		SI_FROM_AF(af)->si_martians

extern struct sock_info sock_info[256];

#define	sockfree(addr) \
{ \
    register block_t block_index = SI_INDEX(socktype(addr)); \
    if (block_index) { \
	task_block_free(block_index, (void_t) addr); \
    } else { \
	task_mem_free((task *) 0, (caddr_t) addr); \
    } \
}

/**/

/* Locating masks given prefixes and vice versa */

#define	mask_from_prefix_si(si, pfx) \
	(((u_int) (pfx) < 0 || (pfx) > (si)->si_mask_count) \
	 ? (sockaddr_un *) 0 \
	 : (sockaddr_un *) ((void_t) ((byte *) (si)->si_mask_min + ((si)->si_size * (pfx)))))

#define	mask_from_prefix(af, pfx) mask_from_prefix_si(SI_FROM_AF(af), pfx)

#define	mask_to_prefix_si(si, mask) \
	(((mask) >= (si)->si_mask_min && (mask) <= (si)->si_mask_max) \
	 ? (u_int) ((byte *) (mask) - (byte *) (si)->si_mask_min) / (si)->si_size \
	 : (u_int) -1)

#define	mask_to_prefix(mask)	mask_to_prefix_si(SI_FROM_AF(socktype(mask)), mask)

#define IPMAXLEN        20
#define DEFAULTMASKLEN(ip)      \
  (!(ip)? 0: \
          ((ip) & 0xff)? 32: \
      (((ip) & 0xc0000000) == 0xc0000000)? 24: \
              ((ip) & 0x80000000)? 16: 8)

#define MASK(m)         ((m)?   (int)0x80000000 >> ((m) - 1): 0)

#ifdef PROTO_IPX
/* sockaddr_un * to sockaddr_ipx * */
#define sockipx(sock)   (&((sockaddr_un *)(sock))->ipx)
/* sockaddr_un * to sockaddr_ipxserv * */
#define sockipxserv(sock) (&(sock)->ipxserv)
/* return the net number of a IPX sockaddr_un as an int. The sockaddr_un is
 * supposed to be alligned.
 */
#define sock2ipxnet(sock) \
  (*((u_int32 *)&(sockipx(sock)->sipx_addr.x_net)))
/* Same as a u_int16[] */
#define sock2ipxnets(sock)  (sockipx(sock)->sipx_addr.x_net.s_net)
 
/* sockaddr_un * to host as char[] */
#define sock2ipxhost(sock)  (sockipx(sock)->sipx_addr.x_host.c_host)
/* sockaddr_un * to port (u_int16) */
#define sock2ipxsock(sock)  (sockipx(sock)->sipx_addr.x_port)

#define sock2serv(sock)   (sockipxserv(sock)->sipxserv_addr.ipxs_type)
#define sockaddrcmp_ipx(s1, s2) \
  sockaddrcmp((sockaddr_un *)(s1), (sockaddr_un *)(s2))
#define sockcmp_ipxnet(s1, s2)  (!(sock2ipxnet(s1) == sock2ipxnet(s2)))
#define SOCKADDR_IPX_LEN  sizeof(struct sockaddr_ipx)
#define SOCKADDR_IPX_OFFSET \
  (sizeof(struct sockaddr_ipx) - sizeof(struct ipx_addr))
#define SOCKADDR_IPXSERV_LEN  sizeof(struct sockaddr_ipxserv)
#define SOCKADDR_IPXSERV_OFFSET \
  (sizeof(struct sockaddr_ipxserv) - sizeof(ipxserv_addr))
#endif  /* PROTO_IPX */

void sockclean(sockaddr_un *);
int sockaddrcmp2(sockaddr_un *, sockaddr_un *);
int sockaddrcmp(sockaddr_un *, sockaddr_un *);
int sockaddrcmp_mask(sockaddr_un *, sockaddr_un *, sockaddr_un *);
void sockmask(sockaddr_un *, sockaddr_un *);
int sockishost(sockaddr_un *, sockaddr_un *);
sockaddr_un *sockhostmask(sockaddr_un *);
sockaddr_un *sockdup(const sockaddr_un *);
sockaddr_un *sockbuild_copy(const sockaddr_un *src);
sockaddr_un *mask_locate(sockaddr_un *);
void mask_insert(sockaddr_un *);
int mask_contig(sockaddr_un *);
int mask_bits(sockaddr_un *);
int mask_contig_bits(sockaddr_un *);
int mask_refines(sockaddr_un *, sockaddr_un *);
void mask_dump(FILE *);
struct sockaddr *sock2unix(sockaddr_un *, int *);
sockaddr_un *sock2gated(struct sockaddr *, size_t);
sockaddr_un *sockbuild_un(const char *);
sockaddr_un *sockbuild_in(u_short, u_int32);
#ifdef PROTO_INET6
sockaddr_un *sockbuild_in6(u_int16, const u_int8 *);
#endif /* PROTO_INET6 */
#ifdef PROTO_IPX
sockaddr_un *sockbuild_ipx(u_int16 *, char *, u_int16);
extern sockaddr_un * sockbuild_ipxserv(u_int16);
#endif  /* PROTO_IPX */
#if defined(PROTO_ISO) || defined(PROTO_ISIS2)
#if ! defined (PROTO_ISO)
#define ISO_MAXADDRLEN  20
#endif
sockaddr_un *sockbuild_iso(const byte *, size_t);
#endif  /* PROTO_ISO || PROTO_ISIS2 */
sockaddr_un *sockbuild_str(const char *);
sockaddr_un *sockbuild_byte(u_char *, size_t);
#ifdef	SOCKADDR_DL
sockaddr_un *sockbuild_dl(int, int, const char *, size_t, byte *, size_t,
    byte *, size_t);
#endif	/* SOCKADDR_DL */
sockaddr_un *sockbuild_ll(int, const byte *, size_t);
void sock_init(void);
void sock_init_family(u_int, u_int, size_t, byte *, size_t, const char *);
int sockstr(const char *, sockaddr_un **, sockaddr_un **);
int unix_socksize(struct sockaddr *, int);
