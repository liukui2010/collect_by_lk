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


/* Kernel interface definitions */

extern const bits krt_flag_bits[];	/* Route flag bits */
extern rt_entry krt_rt;			/* For faking route changes */
extern gw_entry *krt_gwp;
extern gw_entry *krt_gwp_remnant;

#define        KRT_PACKET_MAX  1024            /* Maximum routing socket packet we expect */

/**/

#ifdef HAVE_AIX
#undef KVM_TYPE_NONE
#define INCLUDE_KVM
#endif


#if	defined(INCLUDE_KVM) && !defined(KVM_TYPE_NONE) 
/* KVM stuff */
#ifdef	KVM_TYPE_RENO
#define	KVM_OPENFILES(nl, core, swap, flags, buf)	((kvm_openfiles(nl, core, swap) < 0) ? NULL : TRUE)
#define	KVM_OPEN_DEFINE(buf)	
#define	KVM_OPEN_ERROR(buf)	kvm_geterr()
#define	KVM_GETERR(kd, string)		kvm_geterr()
#endif	/* KVM_TYPE_RENO */

#ifdef	KVM_TYPE_BSD44
#define	KVM_OPENFILES(nl, core, swap, flags, buf)	kvm_openfiles(nl, core, swap, flags, buf)
#define	KVM_OPEN_DEFINE(buf)	char buf[LINE_MAX]
#define	KVM_OPEN_ERROR(buf)	buf
#define	KVM_WITH_KD
#define	KVM_GETERR(kd, string)		kvm_geterr(kd)
#endif	/* KVM_TYPE_BSD44 */

#ifdef	KVM_TYPE_SUNOS4
#define	KVM_OPENFILES(nl, core, swap, flags, buf)	kvm_open(nl, core, swap, flags, "kvm")
#define	KVM_OPEN_DEFINE(buf)
#define	KVM_OPEN_ERROR(buf)	"kvm_open error"
#define	KVM_WITH_KD
#define	KVM_GETERR(kd, string)		string
#endif	/* KVM_OPEN_SUNOS */

#ifdef	KVM_TYPE_OTHER
#define	KVM_OPENFILES(nl, core, swap, flags, buf)	kvm_openfiles(nl, core, swap, flags, buf)
#define	KVM_OPEN_DEFINE(buf)	char buf[LINE_MAX]
#define	KVM_OPEN_ERROR(buf)	buf
#define	KVM_WITH_KD
#define	KVM_GETERR(kd, string)		kvm_geterr(kd)
typedef struct __kvm kvm_t;

extern kvm_t * kvm_openfiles(char *,
	   char *,
	   char *,
	   int,
	   char *);
extern int kvm_read(kvm_t *,
	   u_long,
	   void_t,
	   size_t);
extern int kvm_write(kvm_t *,
	   u_long,
	   void_t,
	   size_t);
extern int kvm_close(kvm_t *);
extern char * kvm_geterr(kvm_t *);
#ifdef	INCLUDE_NLIST
extern int kvm_nlist(kvm_t *,
	   NLIST_T *,
	   size_t);
#endif	/* INCLUDE_NLIST */
#endif	/* KVM_TYPE_OTHER */

#ifdef	HAVE_KVM_H
#include <kvm.h>
#endif

#ifdef	KVM_WITH_KD
extern kvm_t	*kd;

#ifdef	KVM_TYPE_OTHER

#define	KVM_NLIST(kd, nl, sz)		kvm_nlist(kd, nl, sz)
#else	/* KVM_TYPE_OTHER */
#define	KVM_NLIST(kd, nl, sz)		kvm_nlist(kd, nl)
#endif	/* KVM_TYPE_OTHER */
#define	KVM_READ(kd, addr, buf, nbytes)	kvm_read(kd, (u_long) (addr), (void_t) (buf), nbytes)
#define	KVM_CLOSE(kd)			kvm_close(kd)

#else	/* KVM_WITH_KD */
extern int kd;

#define	KVM_NLIST(kd, nl, sz)		kvm_nlist(nl)
#define	KVM_READ(kd, addr, buf, nbytes)	kvm_read((u_long) (addr), (void_t) (buf), nbytes)
#define	KVM_CLOSE(kd)			kvm_close()
#endif	/* KVM_WITH_KD */

#endif	/* INCLUDE_KVM && !KVM_TYPE_NONE */

/**/
/* Return codes from krt_addrcheck */

#define	KRT_ADDR_OK	1	/* Address is OK */
#define	KRT_ADDR_IGNORE	0	/* Ignore this address */
#define	KRT_ADDR_BOGUS	-1	/* Bogus, delete it */
#define	KRT_ADDR_MC	-2	/* Multicast default specification */

/**/
/* Routing table scanning routines */

#ifdef	KRT_RTREAD_KMEM

extern u_long krt_rthashsize;
extern u_long krt_rthash[2];
#define	KRT_RTHOST	0
#define	KRT_RTNET	1
#endif	/* KRT_RTREAD_KMEM */

#ifdef	KRT_RTREAD_RADIX
extern u_long krt_radix_head;
#endif	/* KRT_RTREAD_RADIX */

/**/
/* Routing table manipulation routines */

#ifdef HP_VARIABLE_MASKS
#define RTM_ADD         ((u_long) SIOCADDRTEX)
#define RTM_DELETE      ((u_long) SIOCDELRTEX)
#else
#if	defined (KRT_RT_IOCTL) || defined (KRT_RT_NETLINK)
#define	RTM_ADD		((u_long) SIOCADDRT)
#define	RTM_DELETE	((u_long) SIOCDELRT)
#endif	/* KRT_RT_IOCTL || KRT_RT_NETLINK */
#endif  /* HP_VARIABLE_MASKS */

/**/
/* Symbols */

extern int krt_symbols(task *);
#ifdef	SIOCGNETOPT
extern int krt_netopts(task *);
#endif	/* SIOCGNETOPT */

/**/

/* Routing socket */

extern void krt_recv(task *);

/**/

/* LL addr */

#ifdef	KRT_LLADDR_NONE
#define	krt_lladdr(ifr)	((sockaddr_un *) 0)
#else	/* KRT_LLADDR_NONE */
#ifdef	KRT_LLADDR_KMEM
extern u_long krt_ifnet;
#endif

#ifdef	INCLUDE_IF
extern sockaddr_un * krt_lladdr(struct ifreq *);
#endif	/* INCLUDE_IF */
#endif	/* KRT_LLADDR_NONE */

/**/

/* Routing socket and kerninfo support */

#if	defined(KRT_RT_SOCK) && defined(INCLUDE_ROUTE)
/*
 *	Support code for use with the getkerninfo() call and the routing socket.
 */

#ifdef	RTM_IFINFO
#define	RTM_MAX		(RTM_IFINFO + 1)
#else	/* RTM_IFINFO */
#define	RTM_MAX		(RTM_RESOLVE + 1)
#endif	/* RTM_IFINFO */

#ifndef	RTAX_DST
/*
 * Index offsets for sockaddr array for alternate internal encoding.
 */
#define RTAX_DST	0	/* destination sockaddr present */
#define RTAX_GATEWAY	1	/* gateway sockaddr present */
#define RTAX_NETMASK	2	/* netmask sockaddr present */
#define RTAX_GENMASK	3	/* cloning mask sockaddr present */
#define RTAX_IFP	4	/* interface name sockaddr present */
#define RTAX_IFA	5	/* interface addr sockaddr present */
#define RTAX_AUTHOR	6	/* sockaddr for author of redirect */
#define	RTAX_BRD	7	/* broadcast address */
#define	RTAX_DOWNSTREAM	8	/* multicast downstream intf */
#define RTAX_MAX	9	/* size of array to allocate */
#endif	/* RTAX_DST */

typedef struct {
	flag_t rti_addrs;
	sockaddr_un *rti_info[RTAX_MAX];
} krt_addrinfo;

#define	RTAX_LIST(i)	for (i = 0; i < RTAX_MAX; i++)
#define	RTAX_LIST_END(i)

#define	RTM_ADDR(ap)	ap = (struct sockaddr *) \
    ((caddr_t) ap + (unix_socksize(ap, ap->sa_family) ? ROUNDUP(unix_socksize(ap, ap->sa_family), \
		sizeof (u_long)) : sizeof(u_long)))


extern const bits rtm_type_bits[];

/* Prototypes */
extern krt_addrinfo * krt_xaddrs(register struct rt_msghdr *, size_t);
void krt_trace_msg(task *, const char *, struct rt_msghdr *, size_t,
	   krt_addrinfo *, int, int);
#if	defined(KRT_IFREAD_KINFO) && defined(INCLUDE_IF)
extern void krt_ifaddr(task *, struct ifa_msghdr *, krt_addrinfo *,
	   if_link *, int);
#endif	/* defined(KRT_IFREAD_KINFO) && defined(INCLUDE_IF) */
#ifdef	KRT_RTREAD_KINFO
int krt_rtaddrs(krt_addrinfo *, rt_parms *, sockaddr_un **, flag_t);
#endif	/* KRT_RTREAD_KINFO */
#endif	/* KRT_RT_SOCK && INCLUDE_ROUTE */

/**/

/* Routing table interface */

#define	KRT_OP_SUCCESS	0	/* operation successful (or unrecoverable error) */
#define	KRT_OP_NOCANDO	KRT_OP_SUCCESS
#define	KRT_OP_DEFER	1	/* operation failed (ENETUNREACH), defer this install for later */
#define	KRT_OP_FULL	2	/* operation failed (table full), defer all installs for later */
#define	KRT_OP_BLOCKED	3	/* can't install this route or any more now, defer all until krt_unblock() */
#define	KRT_OP_PARTIAL	4	/* bit set when route delete succeeded, route add failed */
#define	KRT_OP_PARTIAL_DEFER	(KRT_OP_DEFER|KRT_OP_PARTIAL)
#define	KRT_OP_PARTIAL_FULL	(KRT_OP_FULL|KRT_OP_PARTIAL)
#define	KRT_OP_PARTIAL_BLOCKED	(KRT_OP_BLOCKED|KRT_OP_PARTIAL)

/* Prototypes */
extern int krt_change(task *, sockaddr_un *, sockaddr_un *,
	   krt_parms *, krt_parms *);
extern void krt_rth_reset(rt_head *, flag_t, int, sockaddr_un **, if_addr **);
extern void krt_dst_reset(sockaddr_un *, sockaddr_un *, flag_t, int,
	   sockaddr_un **, if_addr **);
extern int krt_change_start(task *);
extern int krt_change_end(task *);
extern void krt_unblock(void);
extern sockaddr_un * krt_make_router(int, flag_t);


/* Options supported by this kernel */

extern flag_t krt_rt_support;

#define	KRTS_REJECT	BIT(0x01)	/* Supports reject routes */
#define	KRTS_BLACKHOLE	BIT(0x02)	/* Supports blackhole routes */
#define	KRTS_VAR_MASK	BIT(0x04)	/* Supports variable mask routes */
#define	KRTS_HOST	BIT(0x08)	/* Supports host routes */
#define	KRTS_MULTIPATH	BIT(0x10)	/* Supports multipath routes */

/**/

/* General prototypes */

void krt_trace(task *, const char *, const char *, sockaddr_un *,
	   sockaddr_un *, sockaddr_un *, flag_t, const char *, int);
#ifndef	KRT_RTREAD_KINFO
extern void krt_rtread_add(task *, rt_parms *, flag_t, int, const char *);
#endif	/* KRT_RTREAD_KINFO */
#if	defined(IP_MULTICAST) && !defined(KRT_IPMULTI_RTSOCK)
extern int krt_multicast_install(sockaddr_un *, sockaddr_un *);
#ifdef	RTM_CHANGE
extern void krt_multicast_change(int, rt_parms *);
#endif	/* RTM_CHANGE */
extern void krt_multicast_dump(task *, FILE *);
#endif	/* defined(IP_MULTICAST) && !defined(KRT_IPMULTI_RTSOCK) */
#if defined(PROTO_INET6)
extern int krt_multicast6_install(sockaddr_un *, sockaddr_un *);
#ifdef	RTM_CHANGE
extern void krt_multicast6_change(int, rt_parms *);
#endif	/* RTM_CHANGE */
extern void krt_multicast6_dump(task *, FILE *);
#endif /* PROTO_INET6 */
#if defined(INCLUDE_ROUTE) && defined(KRT_RT_SOCK) && defined(KRT_IPMULTI_RTSOCK)
extern int krt_action(task *, struct rt_msghdr *);
#endif	/* KRT_RT_SOCK && KRT_IPMULTI_RTSOCK */
#ifdef	IFT_OTHER
extern int krt_type_to_ll(int);
#endif	/* IFT_OTHER */
extern int krt_rtread(task *);
extern const char * krt_rtadd(rt_parms *, flag_t);
extern void krt_delq_add(rt_parms *);
extern int krt_addrcheck(rt_parms *);
extern flag_t krt_if_flags(int);
extern flag_t krt_flags_to_state(flag_t);
extern void krt_age_create(void);
extern int krt_ifread(flag_t);
