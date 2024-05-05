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


/*
 * if.c
 *
 */

#define	INCLUDE_IOCTL
#define	INCLUDE_CTYPE
#include "include.h"
#ifdef	PROTO_INET
#include "inet/inet.h"
#endif	/* PROTO_INET */
#ifdef PROTO_INET6
#include "inet6/inet6.h"
#endif
#ifdef	PROTO_ISO
#include "iso/iso.h"
#endif	/* PROTO_ISO */
#include "krt/krt.h"
#ifdef PROTO_IPX
#include "ipx_rip.h"
#endif
#ifdef IP_MULTICAST_ROUTING
#include "mcore/mrt.h"
#include "mcore/mroute.h"
#endif

/* local prototypes */
static if_link *ifl_alloc(if_link *);
static if_link *ifl_free(if_link *);
static void if_policy_sub(if_addr *, adv_entry **, adv_entry *);
static int ifi_match(if_info *, if_info *);
static int ifi_merge(if_info *, if_info *);
static void if_age(task_timer *, time_t);
static void if_cleanup(task *);
static void if_control_reset(task *, if_addr *);
static void if_control_set(task *, if_addr *, const char *);
static void if_dump(task *, FILE *);
static void if_dupcheck(task *);
static void if_ifachange(task *, if_addr *);
static void if_iflchange(task *, if_link *);
static void if_int_dump(FILE *, config_entry *);
static void if_parse_clear(void);
static void if_policy_alloc(if_addr *);
static void if_policy_cleanup(void);
static void if_policy_free(if_addr *);
static void if_rtdelete(if_addr *);
static void if_rtdown(if_addr *);
static void if_rtfree(rt_entry *, void_t);
static void if_rtifachange(if_addr *);
static void if_rtup(if_addr *);
static void if_terminate(task *);
static void ifa_display (task *, if_addr *, const char *, const char *,
	flag_t, int);
static void ifae_delete(task_job *);
static void ifae_ifa_alloc(if_addr *);
static void ifae_ifl_alloc(if_link *);
static void ifl_insert(if_link *, u_int);


static task *if_task = (task *) 0;

if_link if_plist = { &if_plist, &if_plist };	/* List of link-layer interfaces */
if_count if_n_link = { 0 };			/* Number of link-layer interfaces */

if_addr if_list = { {(if_info *) &if_list, (if_info *) &if_list} };	/* List of network-layer interfaces */
if_count if_n_addr[AF_MAX] = { { 0 } };		/* Number of protocol addresses */

if_addr_entry if_local_list = { &if_local_list, &if_local_list };	/* List of unique local addresses of up interfaces */
if_addr_entry if_remote_list = { &if_remote_list, &if_remote_list };	/* List of remote addresses */
if_addr_entry if_unique_list = { &if_unique_list, &if_unique_list };	/* List of unique addresses */
if_addr_entry if_name_list = { &if_name_list, &if_name_list };		/* List of interface names */
if_addr_entry if_link_list = { &if_link_list, &if_link_list };		/* List of link-layer addresses */

if_info if_config = { &if_config, &if_config };	/* List of network-layer interfaces "define"'d in config file */

static block_t int_link_block_index;		/* Allocation index for	if_link */
adv_entry *int_import[RTPROTO_MAX] = { 0 };	/* Import clauses for various protocols */
adv_entry *int_export[RTPROTO_MAX] = { 0 };	/* Export clauses for various protocols */
bits const *int_ps_bits[RTPROTO_MAX] = { 0 };	/* Bit definitions for protocols */
adv_entry *int_policy = 0;		/* Interface control info */
static block_t int_block_index;		/* Allocation index for if_addr */
static block_t int_info_block_index;	/* Allocation index for if_info */
static block_t int_entry_block_index;	/* Allocation index for if_addr_entry */
static block_t iflist_block_index;	/* Allocation of intf lists (config) */
block_t intf_primary_list_index;	/* Allocation of primary address list */

flag_t intf_alias_processing;		/* how to select interface route */


/* dgt 9/18/97  Need to store a metric of 1 for direct routes for use
 * with DVMRP's rules to determine the designated forwarder per route.
 * I don't know of anything else that uses the metric on direct routes.
 */
rt_parms int_rtparms = RTPARMS_INIT(1,
				    (metric_t) 1,
				    (flag_t) 0,
				    (pref_t) 0);
const bits if_state_bits[] =
{                                       /* see if.h for descriptions */
    {IFS_UP,		"Up"},
    {IFS_BROADCAST,	"Broadcast"},
    {IFS_POINTOPOINT,	"PointToPoint"},
    {IFS_MASKED_POINTOPOINT, "SubnetPointToPoint"},
    {IFS_LOOPBACK,	"Loopback"},
    {IFS_MULTICAST,	"Multicast"},
    {IFS_SIMPLEX,	"Simplex"},
    {IFS_ALLMULTI,	"Allmulti"},
    {IFS_NOROUTE,       "NoRoute"},
    {IFS_TUNNEL,        "Tunnel"},
    {IFS_REGISTER,	"PimRegister"},
    {IFS_NOAGE,		"NoAge"},
    {IFS_DELETE,	"Delete"},
    {IFS_ALIAS_PRIMARY, "PrimaryAddr"},
    {IFS_KEEPALL,	"KeepAllRoutes"},
    {IFS_USE_PRIMARY,	"UsePrimaryAddr"},
    {IFS_PRIVATE,	"Private"},
    {IFS_OSPFVLINK,	"OSPF_Virtual_Link"},
    {IFS_OSPFSECURE,	"OSPF_Encrypted"},
    {0}
};

const bits if_change_bits[] =               /* see if.h for descriptions */
{
/*  {IFC_NOCHANGE,	"NoChange"}, */
    {IFC_REFRESH,	"Refresh"},
    {IFC_ADD,		"Add"},
    {IFC_DELETE,	"Delete"},
    {IFC_UPDOWN,	"UpDown"},
    {IFC_NETMASK,	"Netmask"},
    {IFC_METRIC,	"Metric"},
    {IFC_BROADCAST,	"Broadcast"},
    {IFC_MTU,		"MTU"},
    {IFC_ADDR,		"Address"},
    {IFC_PRIVATE,	"Private"},
    {0}
};

const bits if_proto_bits[] = {               /* see if.h for descriptions */
    {IFPS_METRICIN,	"MetricIn"},
    {IFPS_METRICOUT,	"MetricOut"},
    {IFPS_NOIN,		"NoIn"},
    {IFPS_NOOUT,	"NoOut"},
    {IFPS_JOINMC,	"JoinMC"},

    {0}
};

/*
 * returns true if the given if_link 'lp' has a logical network
 * address which contains the host address 'hostaddrp'
 *
 * XXX this needs to be optimized badly! we should hang if_addrs
 * off the link in multiple ways so it can be fast
 */
int
ifl_withdst(if_link *lp, sockaddr_un *destp)
{
	if_addr *ifap;

	if ((ifap = if_withdst(destp)))
		return (ifap->ifa_link == lp);
	return (0);
}

/*
 * Find the network-layer interface with specified unique address.  Matches 
 * the destination address of P2P interfaces, and the local address of all
 * other interfaces.  This should only be called by routines using information 
 * configured in the config file.  Protocol routines should search for
 * the local or remote address explicitly.
 */
if_info *
ifi_withaddr(sockaddr_un *addr, int broad_ok, if_info *list)
{
    register if_info *ifi;

    IF_INFO(ifi, list) {
	if (socktype(IFI_UNIQUE_ADDR(ifi)) == socktype(addr) &&
	    BIT_TEST(ifi->ifi_state, IFS_UP)) {
	    if (sockaddrcmp(IFI_UNIQUE_ADDR(ifi), addr)) {
		break;
	    }
	    if (broad_ok
		&& BIT_TEST(ifi->ifi_state, IFS_BROADCAST)
		&& ifi->ifi_addr_broadcast
		&& sockaddrcmp(ifi->ifi_addr_broadcast, addr)) {
		break;
	    }
	}
    } IF_INFO_END(ifi, list) ;

    return ifi;
}

/*
 * Find the first network-layer interface with the specified local address.  
 */
if_info *
ifi_withlcladdr(sockaddr_un *addr, int broad_ok, if_info *list)
{
    register if_info *ifi;

    IF_INFO(ifi, list) {
	if (socktype(IFI_UNIQUE_ADDR(ifi)) == socktype(addr) &&
	    BIT_TEST(ifi->ifi_state, IFS_UP)) {
	    if (sockaddrcmp(ifi->ifi_addr_local, addr)) {
		break;
	    }
	    if (broad_ok
		&& BIT_TEST(ifi->ifi_state, IFS_BROADCAST)
		&& ifi->ifi_addr_broadcast
		&& sockaddrcmp(ifi->ifi_addr_broadcast, addr)) {
		break;
	    }
	}
    } IF_INFO_END(ifi, list) ;

    return ifi;
}


/*
 * Find the POINTOPOINT or LOOPBACK network-layer interface with the specified 
 * remote address.
 */
if_info *
ifi_withdstaddr(sockaddr_un *addr, if_info *list)
{
    register if_info *ifi;

    IF_INFO(ifi, list) {
	if (socktype(IFI_UNIQUE_ADDR(ifi)) == socktype(addr)  &&
	    BIT_TEST(ifi->ifi_state, IFS_UP) &&
	    BIT_TEST(ifi->ifi_state, IFS_IPV6|IFS_POINTOPOINT|IFS_LOOPBACK) &&
	    sockaddrcmp(IFI_UNIQUE_ADDR(ifi), addr)) {
	    /* Found it */
	    break;
	}
    } IF_INFO_END(ifi, list) ;

    return ifi;
}


/*
 * Find interface on a specific subnet of a possibly subnetted network
 */
if_info *
ifi_withsubnet(sockaddr_un *dstaddr, if_info *list)
{
    int af = socktype(dstaddr); /* address family */
    register if_info *ifi, *ifi_maybe = (if_info *) 0;
#ifdef PROTO_INET6
    int islink;
    u_int16 dstindex, ifindex;
#endif /* PROTO_INET6 */

#ifdef PROTO_INET6
    islink = IN6_IS_ADDR_LINKLOCAL(&sock2in6(dstaddr));
    dstindex = GET_IFINDEX_ADDR6(sock2in6(dstaddr));
#endif /* PROTO_INET6 */

    IF_INFO(ifi, list) {
	if (socktype(IFI_UNIQUE_ADDR(ifi)) == af &&
	    BIT_TEST(ifi->ifi_state, IFS_UP) &&
	    !BIT_TEST(ifi->ifi_state, IFS_POINTOPOINT|IFS_LOOPBACK)) {
	    register byte *dp = (byte *) dstaddr->a.ga_data;
	    register byte *ap = (byte *) ifi->ifi_addr_local->a.ga_data;
	    register byte *mp = (byte *) ifi->ifi_netmask->a.ga_data;
	    register byte *lp = (byte *) ifi->ifi_netmask + socksize(ifi->ifi_netmask);

#ifdef PROTO_INET6
	    if(af == AF_INET6) {
	        dp = (byte *) &sock2in6(dstaddr);
		ap = (byte *) &sock2in6(ifi->ifi_addr_local);
		mp = (byte *) &sock2in6(ifi->ifi_netmask);
		if (IN6_IS_ADDR_LINKLOCAL(&sock2in6(ifi->ifi_addr_local))
		    && islink && dstindex) {
			/*
			 * if index bytes are in the dest use them
			 */
			if (*(u_int32 *)mp != 0xffffffff)
				goto Continue;
			if (*(u_int16 *)ap != *(u_int16 *)dp)
				goto Continue;
			ifindex =
			    GET_IFINDEX_ADDR6(sock2in6(ifi->ifi_addr_local));
			if (ifi->ifi_link) {
				if (dstindex != ifi->ifi_link->ifl_index)
					goto Continue;
				if (ifindex && dstindex != ifindex)
					goto Continue;
			} else if (!ifindex || dstindex != ifindex) {
				/* since we don't have a if_link must match */
				goto Continue;
			}
			/* skip the first part */
			dp += 4;
			ap += 4;
			mp += 4;
		}
	    }
#endif /* PROTO_INET6 */

	    for (; mp < lp; mp++) {
		if ((*dp++ ^ *ap++) & *mp) {
		    /* Match failure */
		    goto Continue;
		}
	    }

	    if ((BIT_TEST(ifi->ifi_state, IFS_USE_PRIMARY)
		|| BIT_TEST(ifi->ifi_state, IFS_KEEPALL)) &&
		!BIT_TEST(ifi->ifi_state, IFS_ALIAS_PRIMARY)) {
		/* always return the primary address */
		goto Continue;
	    }

	    if (!ifi_maybe ||
		mask_refines(ifi->ifi_netmask, ifi_maybe->ifi_netmask)) {
		/* This is the only mask or is more specific than the last one */
		ifi_maybe = ifi;
	    }
	}
    Continue:
	;
    } IF_INFO_END(ifi, list);

    return ifi_maybe;
}


/*
 * Find the interface for the specified gateway.  First try to find a P2P interface
 * with the specified address, then find out if we are on the attached network of
 * any multi-access interfaces.
 */
if_info *
ifi_withdst(sockaddr_un *dstaddr, if_info *list)
{
    register if_info *ifi = 0;

    ifi = ifi_withdstaddr(dstaddr, list);
    if (!ifi) {
	ifi = ifi_withsubnet(dstaddr, list);
    }

    return ifi;
}


/*
 * Find the interface from the routing table for the specified gateway.
 */
if_info *
ifi_withdstroute (task *tp, sockaddr_un *dstaddr)
{
    register rt_list *rtl = (rt_list *) 0;
    register rt_head *rth = (rt_head *) 0;
    register rt_entry *rt = (rt_entry *) 0;
    register if_info *ifi = 0;
    register sockaddr_un *maskaddr = (sockaddr_un *) 0;

    if (!tp)
			return ifi;
    if (!dstaddr || dstaddr->a.ga_family == AF_UNSPEC)
			return ifi;
    rtl = rthlist_active(dstaddr->a.ga_family, RIB_UNICAST);
    if (!rtl)
			return ifi;

    rt_open(tp);
    RT_LIST(rth, rtl, rt_head) {
		if (socktype(rth->rth_dest) != dstaddr->a.ga_family) {
	    continue;
		}

		rt = rth->rth_rib_active[RIB_UNICAST];
		if (!rt) {
	    continue;
	}
	maskaddr = sockdup(dstaddr);
	switch (socktype(dstaddr)) {
#ifdef	PROTO_INET
	case AF_INET:
	    sockaddrmask_in(maskaddr, rt->rt_dest_mask);
	    break;
#endif
#ifdef PROTO_INET6
	case AF_INET6:
	    sockaddrmask_in6(maskaddr, rt->rt_dest_mask);
	    break;
#endif
	default:
	    break;
	}
	if (!sockaddrcmp(rt->rt_dest, maskaddr)) {
	    sockfree(maskaddr);
	    continue;
	} else {
	    ifi = (if_info *) RT_IFAP(rt);
	    sockfree(maskaddr);
	    rt_close(tp, (gw_entry *) 0, 0, NULL);
	    return ifi;
	}
    } RT_LIST_END(rth, rtl, rt_head);
    rt_close(tp, (gw_entry *) 0, 0, NULL);

    return ifi;
}

/*
 * Find the interface with the specified if_index and address scope
 * (for IPv6/4 interface)
 * Note: This is diff then ifi_withindex, but may be made to be the
 *       same.
 */
if_info *
ifi_withindex2 (u_int ifindex, byte addrscope, if_info *list)
{
    register if_info *ifi = 0;
    if_link *ifl = 0;
  
    ifl = ifl_locate_index(ifindex);
    if (!ifl) {
        return ifi;
    }
    IF_INFO(ifi, list) {
        if (socktype(ifi->ifi_addr_local) == addrscope &&
	    BIT_TEST(ifi->ifi_state, IFS_UP)) {
	    	if(ifi->ifi_link == ifl) {
			return ifi;
		}
	}
    } IF_INFO_END(ifi, list);
    ifi = 0;			/* Not Found */
    return ifi;
}

#ifdef PROTO_INET6
/*
 * Find the interface with the specified if_index and address socpe
 * (for IPv6 interface)
 */
if_info *
ifi_withindex (u_int ifindex, byte addrscope, if_info *list)
{
    register if_info *ifi = 0;
    if_link *ifl = 0;
  
    switch (addrscope) {
    case INET6_SCOPE_NONE:
        return (if_info *) 0;
    default:
        break;
    }

    ifl = ifl_locate_index(ifindex);
    if (!ifl) {
        return ifi;
    }
    IF_INFO(ifi, list) {
        if (socktype(ifi->ifi_addr_local) == AF_INET6 &&
	    BIT_TEST(ifi->ifi_state, IFS_UP) &&
	    !BIT_TEST(ifi->ifi_state, IFS_LOOPBACK)) {
	    if(ifi->ifi_link == ifl &&
	       inet6_scope_of(ifi->ifi_addr_local) == addrscope) {
	        return ifi;
	    }
	}
    } IF_INFO_END(ifi, list);
    ifi = 0;			/* Not Found */
    return ifi;
}

/*
 * Find the interface with the specified interface name and address
 * socpe (for IPv6 interface)
 */
if_info *
ifi_withname(const char *name, size_t nlen, byte addrscope, if_info *list)
{
    register if_info *ifi = (if_info *)0;
    if_link *ifl = (if_link *)0;
  
    switch (addrscope) {
    case INET6_SCOPE_NONE:
        return (if_info *) 0;
    default:
        break;
    }

    if ((ifl = ifl_locate_name(name, nlen)) == NULL) {
        return ifi;
    }
    IF_INFO(ifi, list) {
        if (socktype(ifi->ifi_addr_local) == AF_INET6 &&
	    BIT_TEST(ifi->ifi_state, IFS_UP) &&
	    !BIT_TEST(ifi->ifi_state, IFS_LOOPBACK)) {
	    if(ifi->ifi_link == ifl &&
	       inet6_scope_of(ifi->ifi_addr_local) == addrscope) {
	        return ifi;
	    }
	}
    } IF_INFO_END(ifi, list);
    ifi = 0;			/* Not Found */
    return ifi;
}
#endif /* PROTO_INET6 */

/*
 * Find the interface with the specified local address or net/subnet address
 */
int
if_myaddr(if_addr *ifap, sockaddr_un *addr, sockaddr_un *mask)
{
    int af = socktype(addr);
    int host_route = mask == sockhostmask(addr);
    
    if (socktype(IFA_UNIQUE_ADDR(ifap)) == af &&
	BIT_TEST(ifap->ifa_state, IFS_UP)) {
	if (host_route
	    && sockaddrcmp(IFA_UNIQUE_ADDR(ifap), addr)) {
	    /* My address */

	    return TRUE;
	}
	if (BIT_TEST(ifap->ifa_state, IFS_POINTOPOINT)) {
	    if (host_route
		&& sockaddrcmp(ifap->ifa_addr_local, addr)) {
		/* My local address */

		return TRUE;
	    }
	} else {
	    if (BIT_TEST(ifap->ifa_state, IFS_BROADCAST)
		&& ifap->ifa_addr_broadcast
		&& host_route
		&& sockaddrcmp(ifap->ifa_addr_broadcast, addr)) {
		/* My broadcast address */

		return TRUE;
	    }
	    if (ifap->ifa_addr_remote
		&& ifap->ifa_netmask == mask
		&& sockaddrcmp(ifap->ifa_addr_remote, addr)) {
		/* My network address */

		return TRUE;
	    }
	}
    }

    return FALSE;
}

#ifdef PROTO_INET6
int
if_subnet (sockaddr_un *super, sockaddr_un *sub, sockaddr_un *mask)
{
    register byte *a = (byte *)super->a.ga_data;
    register byte *b = (byte *)sub->a.ga_data;
    register byte *m = (byte *)mask->a.ga_data;
    register byte *l = (byte *)mask + socksize(mask);

    for (; m < l; m++) {
        if ((*a++ ^ *b++) & *m) {
            /* Match failure */
            return FALSE;
        }
    }
    return TRUE;
}
#endif /* PROTO_INET6 */

/* Lookup the interface the way the kernel does */
if_addr *
if_withroute(sockaddr_un *iwr_dest, sockaddr_un *iwr_router, flag_t iwr_state)
{
    register if_addr *iwr_ifap;
    
    if (BIT_TEST(iwr_state, RTS_GATEWAY)) {
	/* Remote net or host.  On the other end of a p2p link? */
	iwr_ifap = if_withdstaddr(iwr_router);
	if (!iwr_ifap) {
	    iwr_ifap = if_withsubnet(iwr_router);
	}
    } else {
	/* Route to an interface. */
	iwr_ifap = if_withdstaddr(iwr_dest);
	if (!iwr_ifap) {
	    iwr_ifap = if_withaddr(iwr_router, FALSE);
	}
    }

    return iwr_ifap;
}


/*
 *		Log the configuration of the interface
 */
static void
ifa_display(task *tp, if_addr *ifap, const char *name, const char *name1,
    flag_t tf, int pri)
{
    int proto;

    if (pri) {
	/* Log some info in the syslog */

	tracef("EVENT %s %s ",
	       trace_bits(if_change_bits, ifap->ifa_change),
	       ifap->ifa_link->ifl_name);
	       
	switch (BIT_TEST(ifap->ifa_state, IFS_BROADCAST|IFS_LOOPBACK|IFS_POINTOPOINT)) {
	case IFS_POINTOPOINT:
	    tracef("%A -> %A",
		   ifap->ifa_addr_local,
		   ifap->ifa_addr_remote);
	    break;

	case IFS_BROADCAST:
	    tracef("%A/%A -> %A",
		    ifap->ifa_addr_local,
		    ifap->ifa_netmask,
		    ifap->ifa_addr_broadcast);
	    break;

	case IFS_LOOPBACK:
	    tracef("%A",
		   ifap->ifa_addr_local);
	    break;

	default:
	    /* NBMA */
	    tracef("%A/%A",
		   ifap->ifa_addr_local,
		   ifap->ifa_netmask);
	    break;
	}
	trace_log_tp(tp,
		     TRC_LOGONLY,
		     pri,
		     (" <%s>",
		      trace_bits(if_state_bits, ifap->ifa_state)));
    }

    if (TRACE_TP(tp, tf)) {
	trace_only_tp(tp,
		      0,
		      ("%s%s\t%A",
		       name,
		       name1,
		       IFA_UNIQUE_ADDR(ifap)));

	trace_only_tp(tp,
		      0,
		      ("%s%s\t\tindex: %u  name: %s  state: <%s>",
		       name,
		       name1,
		       ifap->ifa_link->ifl_index,
		       ifap->ifa_link->ifl_name,
		       trace_bits(if_state_bits, ifap->ifa_state)));

	trace_only_tp(tp,
		      0,
		      ("%s%s\t\tchange: <%s>  metric: %u  route: %sinstalled",
		       name,
		       name1,
		       trace_bits(if_change_bits, ifap->ifa_change),
		       ifap->ifa_metric,
		       ifap->ifa_rt ? "" : "not "));

	trace_only_tp(tp,
		      0,
		      ("%s%s\t\tpreference: %d  down: %d  refcount: %d  mtu: %d",
		       name,
		       name1,
		       ifap->ifa_preference,
		       ifap->ifa_preference_down,
		       ifap->ifa_refcount,
		       ifap->ifa_mtu));

	if (ifap->ifa_addr_broadcast
	    || BIT_TEST(ifap->ifa_state, IFS_POINTOPOINT)) {
	    if (ifap->ifa_addr_broadcast) {
		tracef("%s%s\t\tbroadaddr: %A",
		       name,
		       name1,
		       ifap->ifa_addr_broadcast);
	    } else if (BIT_TEST(ifap->ifa_state, IFS_POINTOPOINT)) {
		tracef("%s%s\t\tlcladdr: %A",
		       name,
		       name1,
		       ifap->ifa_addr_local);
	    }
	    trace_only_tp(tp,
			  0,
			  (NULL));
	}
		    
	if (ifap->ifa_addr_remote) {
	    trace_only_tp(tp,
			  0,
			  ("%s%s\t\tsubnet: %A  subnetmask: %A",
			   name,
			   name1,
			   ifap->ifa_addr_remote,
			   ifap->ifa_netmask));
	} else if (ifap->ifa_netmask) {
	    trace_only_tp(tp,
			  0,
			  ("%s%s\t\tsubnetmask: %A",
			   name,
			   name1,
			   ifap->ifa_netmask));
	} 
		    
	for (proto = 0; proto < RTPROTO_MAX; proto++) {
	    if (ifap->ifa_ps[proto].ips_state) {
		tracef("%s%s\t\t\tproto %s state: <%s>",
		       name,
		       name1,
		       trace_state(rt_proto_bits, proto),
		       trace_bits(if_proto_bits, ifap->ifa_ps[proto].ips_state));
		if (BIT_TEST(ifap->ifa_ps[proto].ips_state, IFPS_METRICIN)) {
		    tracef("  metricin: %u",
			   ifap->ifa_ps[proto].ips_metric_in);
		}
		if (BIT_TEST(ifap->ifa_ps[proto].ips_state, IFPS_METRICOUT)) {
		    tracef("  metricout: %u",
			   ifap->ifa_ps[proto].ips_metric_out);
		}
		trace_only_tp(tp,
			      0,
			      (NULL));
	    }
	}
	trace_only_tp(tp,
		      0,
		      (NULL));
    }
}


/* Verify that no two non-POINTOPOINT interfaces have the same local address 
 * and that no two interfaces have the same destination route.
 */
static void
if_dupcheck(task *tp)
{
    register if_addr *ifap;

    IF_ADDR(ifap) {
	switch (socktype(IFA_UNIQUE_ADDR(ifap))) {
	case AF_UNSPEC:	/* Place holder */
#ifdef	SOCKADDR_DL
	case AF_LINK:
#endif	/* SOCKADDR_DL */
#ifdef	PROTO_ISO
	case AF_ISO:
#endif	/* PROTO_ISO */
	    continue;

#ifdef PROTO_INET6
	case AF_INET6:
	    if (IN6_IS_ADDR_LINKLOCAL(&sock2in6(ifap->ifa_addr_local))) continue;
		/* fall through */
#endif
	default:
	    if (BIT_TEST(ifap->ifa_state, IFS_UP)) {
		register if_addr *ifap2;
		
		IF_ADDR(ifap2) {
		    if (ifap != ifap2
			&& socktype(IFA_UNIQUE_ADDR(ifap)) == socktype(IFA_UNIQUE_ADDR(ifap2))
			&& BIT_TEST(ifap2->ifa_state, IFS_UP)
			&& sockaddrcmp(IFA_UNIQUE_ADDR(ifap), IFA_UNIQUE_ADDR(ifap2))) {
			/* Duplicate! */

			tracef("if_dupcheck: address/destination conflicts between %s %A",
			       ifap->ifa_link->ifl_name,
			       IFA_UNIQUE_ADDR(ifap));
			if (BIT_TEST(ifap->ifa_state, IFS_POINTOPOINT)) {
			    tracef(" lcladdr %A",
				   ifap->ifa_addr_local);
			}
			tracef(" and %s %A",
			       ifap2->ifa_link->ifl_name,
			       IFA_UNIQUE_ADDR(ifap2));
			if (BIT_TEST(ifap2->ifa_state, IFS_POINTOPOINT)) {
			    tracef(" lcladdr %A",
				   ifap->ifa_addr_local);
			}
			trace_log_tp(tp,
				     0,
				     LOG_CRIT,
				     (NULL));
			ifa_display(tp, ifap, "if_dupcheck:", "", TR_ALL, LOG_CRIT);
			ifa_display(tp, ifap2, "if_dupcheck:", "", TR_ALL, LOG_CRIT);
			break;
		    }
		} IF_ADDR_END(ifap2) ;
	    }
	    break;
	}
    } IF_ADDR_END(ifap) ;
}


/*
 *	Scan the supplied list for any matches with this interface
 */
adv_entry *
if_policy_match(if_addr *ifap, adv_entry *list)
{
    register adv_entry *adv;

    ADV_LIST(list, adv) {
	switch (adv->adv_flag & ADVF_TYPE) {
		
	case ADVFT_ANY:
	    return adv;

	case ADVFT_IFN:
	    if (ifap->ifa_link->ifl_nameent == adv->adv_ifn
		|| ifap->ifa_link->ifl_nameent_wild == adv->adv_ifn) {
		return adv;
	    }
	    break;

	case ADVFT_IFAE_UNIQUE:
            /* Since this is an old-style ifae, we don't know whether it
             * refers to a local or a remote address.  So we have to
             * test the actual address, since adv->adv_ifae is in the
             * _remote_ list, and the "unique" addrent may be in either
             * list.
             */
	    if (ifap->ifa_addrent_unique == adv->adv_ifae) {
		return adv;
	    }
	    break;

	case ADVFT_IFAE_LOCAL:
	    if (ifap->ifa_addrent_local == adv->adv_ifae) {
		return adv;
	    }
	    break;

	case ADVFT_IFAE_REMOTE:
	    if (ifap->ifa_addrent_remote == adv->adv_ifae) {
		return adv;
	    }
	    break;

	default:
	    assert(FALSE);
	}
    } ADV_LIST_END(list, adv) ;

    return (adv_entry *) 0;
}

/*
 * Process any control info about this interface
 */
static void
if_control_reset(task *tp, if_addr *ifap)
{
    ifap->ifa_preference = RTPREF_DIRECT;
    ifap->ifa_preference_down = RTPREF_DIRECT_DOWN;
    BIT_RESET(ifap->ifa_state, ifap->ifa_state_policy);
    ifap->ifa_state_policy = (flag_t) 0;
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
    ifap->ifa_as = (as_t) 0;
#endif	/* PROTO_ASPATHS */
}


static void
if_control_set(task *tp, if_addr *ifap, const char *whom)
{
    int change = 0;
    config_entry **list = config_resolv_ifa(int_policy,
					    ifap,
					    IF_CONFIG_MAX);
    sockaddr_un *router;
    sockaddr_un *routers[RT_N_MULTIPATH];
    int a_changed, i, j, need_del, ngw;
    if_primary_list_t *ifpl;

    router = IFA_UNIQUE_ADDR(ifap);
    a_changed = need_del = 0;

    /* Reset old policy */
    if_control_reset(tp, ifap);

    if (list) {
	int type = IF_CONFIG_MAX;
	config_entry *cp;

	/* Fill in the parameters */
	while (--type) {
	    if ((cp = list[type])) {
		switch (type) {
		case IF_CONFIG_PREFERENCE_UP:
		    if (ifap->ifa_preference != (pref_t)GA2S(cp->config_data)) {
			ifap->ifa_preference = GA2S(cp->config_data);
			change++;
		    }
		    break;
			
		case IF_CONFIG_PREFERENCE_DOWN:
		    if (ifap->ifa_preference_down != (pref_t)GA2S(cp->config_data)) {
			ifap->ifa_preference_down = GA2S(cp->config_data);
			change++;
		    }
		    break;
			
		case IF_CONFIG_ENABLE:
                    if (GA2S(cp->config_data)) {
		       BIT_RESET(ifap->ifa_ps[RTPROTO_DIRECT].ips_state,IFPS_NOIN);
		       BIT_RESET(ifap->ifa_ps[RTPROTO_DIRECT].ips_state,IFPS_NOOUT);
                    } else {
		       BIT_SET(ifap->ifa_ps[RTPROTO_DIRECT].ips_state,IFPS_NOIN);
		       BIT_SET(ifap->ifa_ps[RTPROTO_DIRECT].ips_state,IFPS_NOOUT);
                    }
		    break;
			
		case IF_CONFIG_PASSIVE:
		    if (!BIT_TEST(ifap->ifa_state, IFS_NOAGE)) {
			BIT_SET(ifap->ifa_state_policy, (ifap->ifa_state ^ IFS_NOAGE) & IFS_NOAGE);
			BIT_SET(ifap->ifa_state, IFS_NOAGE);
			change++;
		    }
		    break;
			
		case IF_CONFIG_SIMPLEX:
		    if (!BIT_TEST(ifap->ifa_state, IFS_SIMPLEX)) {
			BIT_SET(ifap->ifa_state_policy, (ifap->ifa_state ^ IFS_SIMPLEX) & IFS_SIMPLEX);
			BIT_SET(ifap->ifa_state, IFS_SIMPLEX);
			change++;
		    }
		    break;

		case IF_CONFIG_REJECT:
#ifdef	PROTO_INET
		    if (socktype(ifap->ifa_addr_local) == AF_INET
			&& BIT_TEST(ifap->ifa_state, IFS_LOOPBACK)
			&& (!inet_addr_reject
			    || !sockaddrcmp(ifap->ifa_addr_local, inet_addr_reject))
			&& !sockaddrcmp(ifap->ifa_addr_local, inet_addr_loopback)) {
			if (inet_addr_reject) {
			    sockfree(inet_addr_reject);
			}
			inet_addr_reject = sockdup(ifap->ifa_addr_local);
			trace_tp(tp,
				 TR_ALL, 0,
				 ("%s: Reject address set to %A",
				  whom,
				  inet_addr_reject));
		    }
#endif	/* PROTO_INET */
		    break;
		case IF_CONFIG_ALIAS_KEEPALL:
			a_changed++;
			change++;
			if (!BIT_TEST(ifap->ifa_state, IFS_KEEPALL)) {
			    if (ifap->ifa_rt) {
				    rt_delete(ifap->ifa_rt);
				    ifap->ifa_rt = NULL;
			    }
			}
			BIT_RESET(ifap->ifa_state, IFS_USE_PRIMARY);
			BIT_SET(ifap->ifa_state, IFS_KEEPALL);
			trace_tp(tp, TR_ALL, 0, ("%s: interface %A: all interface routes will be kept in kernel ", whom, IFA_UNIQUE_ADDR(ifap)));
		break;
 		case IF_CONFIG_ALIAS_PRIMARY:
			a_changed++;
			change++;
			if (BIT_TEST(ifap->ifa_state, IFS_KEEPALL))
			    need_del = 1;
			BIT_RESET(ifap->ifa_state, IFS_KEEPALL);
			BIT_SET(ifap->ifa_state, IFS_USE_PRIMARY);
 			trace_tp(tp, TR_ALL, 0, ("%s: interface %A: interface uses primary address to select interface route ", whom, IFA_UNIQUE_ADDR(ifap)));
 			break;
 		case IF_CONFIG_ALIAS_LOWESTIP:
			a_changed++;
			change++;
			if (BIT_TEST(ifap->ifa_state, IFS_KEEPALL))
				need_del = 1;
			BIT_RESET(ifap->ifa_state, IFS_KEEPALL);
			BIT_RESET(ifap->ifa_state, IFS_USE_PRIMARY);
			trace_tp(tp, TR_ALL, 0, ("%s: interface %s: interface route uses lowest IP to select interface route   ", whom, IFA_UNIQUE_ADDR(ifap)));
 			break;
 		case IF_CONFIG_ALIAS_PRIMARY_NET:
			change++;
 			/* This is a primary address for a subnet */
 			ifpl = (if_primary_list_t *) cp->config_data;
 			if_alias_add_primary(tp, ifap, ifpl);
 			break;
		case IF_CONFIG_BLACKHOLE:
#ifdef	PROTO_INET
		    if (socktype(ifap->ifa_addr_local) == AF_INET
			&& BIT_TEST(ifap->ifa_state, IFS_LOOPBACK)
			&& (!inet_addr_blackhole
			    || !sockaddrcmp(ifap->ifa_addr_local, inet_addr_blackhole))
			&& !sockaddrcmp(ifap->ifa_addr_local, inet_addr_loopback)) {
			if (inet_addr_blackhole) {
			    sockfree(inet_addr_blackhole);
			}
			inet_addr_blackhole = sockdup(ifap->ifa_addr_local);
			trace_tp(tp,
				 TR_ALL, 0,
				 ("%s: Reject address set to %A",
				  whom,
				  inet_addr_blackhole));
		    }
#endif	/* PROTO_INET */
		    break;

#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
		case IF_CONFIG_AS:
		    ifap->ifa_as = (u_int) GA2S(cp->config_data);
		    break;
#endif	/* PROTO_ASPATHS */

		default:
		    assert(FALSE);
		    break;
		}
	    }
	}

	config_resolv_free(list, IF_CONFIG_MAX);
    }

    if (!a_changed) {
	if (BIT_TEST(intf_alias_processing, IFALIAS_ALL_PRIMARY)) {
	    if (BIT_TEST(ifap->ifa_state, IFS_KEEPALL))
		need_del = 1;
	    BIT_RESET(ifap->ifa_state, IFS_KEEPALL);
	    BIT_SET(ifap->ifa_state, IFS_USE_PRIMARY);
	} else if (BIT_TEST(intf_alias_processing, IFALIAS_ALL_KEEPALL)) {
	    if (!BIT_TEST(ifap->ifa_state, IFS_KEEPALL) && ifap->ifa_rt) {
		rt_delete(ifap->ifa_rt);
		ifap->ifa_rt = NULL;
	    }
	    BIT_RESET(ifap->ifa_state, IFS_USE_PRIMARY);
	    BIT_SET(ifap->ifa_state, IFS_KEEPALL);
	} else { 
	    /* lowest ip */
	    if (BIT_TEST(ifap->ifa_state, IFS_KEEPALL))
		need_del = 1;
	    BIT_RESET(ifap->ifa_state, IFS_KEEPALL);
	    BIT_RESET(ifap->ifa_state, IFS_USE_PRIMARY);
	}
    }

    /* Set the interface route selection method if not
     * changed above.
     */ 
    if (need_del) {

	/* if old was keepall, delete our gw from the rt_entry */
	if (BIT_TEST(ifap->ifa_state, IFALIAS_ALL_KEEPALL)) {
	    if (ifap->ifa_rt) {
		if (ifap->ifa_rt->rt_n_gw == 1) {
		/* if there is one router left, it better be us? */
		    GASSERT(sockaddrcmp(ifap->ifa_rt->rt_routers[0],
			IFA_UNIQUE_ADDR(ifap)));
	        } else {
		    bcopy(ifap->ifa_rt->rt_routers, routers,
		        (RT_N_MULTIPATH * sizeof(sockaddr_un)));
		    for (i = 0; i < ifap->ifa_rt->rt_n_gw; i++) {

			if (sockaddrcmp(ifap->ifa_rt->rt_routers[i],
			    IFA_UNIQUE_ADDR(ifap))) {
			    for (j = i; j < (ifap->ifa_rt->rt_n_gw - 1); j++) {
			        routers[j] = routers[j-1];
			    }
			routers[j] = NULL;
			ngw--;
		        }
		    }
		    (void) rt_change(ifap->ifa_rt, ifap->ifa_rt->rt_metric, (metric_t) 0,
		        (metric_t) 0, ifap->ifa_rt->rt_preference, 
			ifap->ifa_rt->rt_preference2,
		        ngw, routers);
		}
	    }
	}
    }

    /* If it's administratively disabled, make sure it isn't up */
    if (BIT_TEST(ifap->ifa_ps[RTPROTO_DIRECT].ips_state, IFPS_NOOUT)) {
       BIT_RESET(ifap->ifa_state, IFS_UP);
       BIT_SET(ifap->ifa_state, IFS_NOAGE);
    }
    
    if (change) {
	ifa_display(tp, ifap, whom, "", TR_ALL, 0);
    }
}


/**/

/*
 *	Maintain list of local addresses
 */
if_addr_entry *
ifae_alloc(register if_addr_entry *ifae)
{
    ifae->ifae_refcount++;

    return ifae;
}


if_addr_entry *
ifae_locate(sockaddr_un *addr, if_addr_entry *list)
{
    register if_addr_entry *ifae;

    IF_ADDR_LIST(ifae, list) {
	if (sockaddrcmp(addr, ifae->ifae_addr)) {
	    /* Found it! */

	    goto Found;
	}
    } IF_ADDR_LIST_END(ifae, list) ;

    /* XXX - Sorted order */

    ifae = (if_addr_entry *) task_block_alloc(int_entry_block_index);
    ifae->ifae_addr = sockdup(addr);

    INSQUE(ifae, list->ifae_back);

 Found:
    return ifae_alloc(ifae);
}


if_addr_entry *
ifae_lookup(sockaddr_un *addr, if_addr_entry *list)
{
    register if_addr_entry *ifae;

    IF_ADDR_LIST(ifae, list) {
	if (sockaddrcmp(addr, ifae->ifae_addr)) {
	    /* Found it! */

	    return ifae_alloc(ifae);
	}
    } IF_ADDR_LIST_END(ifae, list) ;

    return ifae;
}

#define	IFAE_ITYPE(state) \
    (BIT_TEST((state), IFS_POINTOPOINT|IFS_MASKED_POINTOPOINT) ? (1) : \
     (BIT_TEST((state), IFS_LOOPBACK) ? (2) : (0)))

#define	ifae_incr(ifae, itype) \
    do { \
	(ifae)->ifae_n_if++; \
	if ((itype)) { \
	    if ((itype) == 1) { \
		(ifae)->ifae_n_p2p++; \
	    } else { \
		(ifae)->ifae_n_loop++; \
	    } \
	} \
    } while (0)

#define	ifae_decr(ifae, itype) \
    do { \
	(ifae)->ifae_n_if--; \
	if ((itype)) { \
	    if ((itype) == 1) { \
		(ifae)->ifae_n_p2p--; \
	    } else { \
		(ifae)->ifae_n_loop--; \
	    } \
	} \
    } while (0)


static void
ifae_ifa_alloc(if_addr *ifap)
{
    /* Local address */
    ifap->ifa_addrent_local = ifae_locate(ifap->ifa_addr_local,
					  &if_local_list);
    /* Remote address */
    ifap->ifa_addrent_remote = ifae_locate(ifap->ifa_addr_remote,
				    &if_remote_list);

    /* Unique address */
    ifap->ifa_addrent_unique = ifae_locate(IFA_UNIQUE_ADDR(ifap),
				    &if_unique_list);
}


static void
ifae_ifl_alloc(if_link *ifl)
{
    char name[IFL_NAMELEN];
    register char *sp = ifl->ifl_name;
    register char *dp = name;

    while (isalpha(*sp)) {
	*dp++ = *sp++;
    }
    *dp = (char) 0;

    /* Wildcard name  (e.g., "ep") */
    ifl->ifl_nameent_wild = ifae_locate(sockbuild_str(name),
					 &if_name_list);

    /* Link-layer interface name (e.g., "ep0") */
    ifl->ifl_nameent = ifae_locate(sockbuild_str(ifl->ifl_name),
				  &if_name_list);

    /* Link-layer address */
    if (ifl->ifl_addr) {
	ifl->ifl_addrent = ifae_locate(ifl->ifl_addr,
				       &if_link_list);
    }
}


/* Defered route deletion */
static void
ifae_delete(task_job *jp)
{
    rt_entry *rt = (rt_entry *) jp->task_job_data;
    
    rt_open(jp->task_job_task);
    rt_delete(rt);
    rt_close(jp->task_job_task, (gw_entry *) 0, 1, NULL);
}


void
ifae_free(if_addr_entry *ifae)
{
    if (!--ifae->ifae_refcount) {
	/* Address no longer referenced, delete entry */

	REMQUE(ifae);

	/* Free the address */
	sockfree(ifae->ifae_addr);

	/* If there is a direct route for this address, schedule its deletion */
	if (ifae->ifae_rt) {
	    ifae->ifae_rt->rt_data = (void_t) 0;
	    task_job_create(if_task,
			    TASK_JOB_FG,
			    "ifae_delete",
			    ifae_delete,
			    (void_t) ifae->ifae_rt);
	}

	task_block_free(int_entry_block_index, (void_t) ifae);
    }
}


/**/

/* Find all import or export policy that refers to this interface */
static void
if_policy_sub(if_addr *ifap, adv_entry **new, adv_entry *list)
{
    adv_entry *adv, *last = (adv_entry *) 0;

    for (adv = list;
	 (adv = if_policy_match(ifap, adv));
	 adv = adv->adv_next) {
	/* Allocate a new entry and add it to the list */

	adv_entry *new_adv = adv_alloc(ADVFT_ANY, adv->adv_proto);

	new_adv->adv_next = (adv_entry *) 0;
	new_adv->adv_flag = adv->adv_flag;
	new_adv->adv_ru = adv->adv_ru;
	if ((new_adv->adv_list = adv->adv_list)) {
	    register adv_entry *advp;

	    ADV_LIST(new_adv->adv_list, advp) {
		advp->adv_refcount++;
	    } ADV_LIST_END(new_adv->adv_list, advp) ;
	}
	switch (adv->adv_flag & ADVF_TYPE) {
	case ADVFT_ANY:
	    break;
	    
	case ADVFT_IFN:
	    new_adv->adv_ifn = ifae_alloc(adv->adv_ifn);
	    break;

	case ADVFT_IFAE_UNIQUE:
	case ADVFT_IFAE_LOCAL:
	case ADVFT_IFAE_REMOTE:
	    new_adv->adv_ifae = ifae_alloc(adv->adv_ifae);
	    break;

	default:
	    assert(FALSE);
	    break;
	}
#ifdef	notdef
	BIT_RESET(new_adv->adv_flag, ADVF_TYPE);
	BIT_SET(new_adv->adv_flag, ADVFT_ANY);
#endif	/* notdef */

	/* Append to the list */
	if (last) {
	    last->adv_next = new_adv;
	    last = new_adv;
	} else {
	    *new = last = new_adv;
	}
    }
}


static void
if_policy_alloc(if_addr *ifap)
{
    int proto = RTPROTO_MAX;

    while (proto--) {
	register struct ifa_ps *ips = &ifap->ifa_ps[proto];

	if (int_import[proto]) {
	    if_policy_sub(ifap, &ips->ips_import, int_import[proto]);
	}
	if (int_export[proto]) {
	    if_policy_sub(ifap, &ips->ips_export, int_export[proto]);
	}
    }
}


/* Free protocol policy lists for this interface */
static void
if_policy_free(if_addr *ifap)
{
    int proto = RTPROTO_MAX;

    while (proto--) {
	register struct ifa_ps *ips = &ifap->ifa_ps[proto];

	if (ips->ips_import) {
	    adv_free_list(ips->ips_import);
	    ips->ips_import = (adv_entry *) 0;
	}
	if (ips->ips_export) {
	    adv_free_list(ips->ips_export);
	    ips->ips_export = (adv_entry *) 0;
	}
    }
}


/* Free protocol policy lists */
static void
if_policy_cleanup(void)
{
    register int proto = RTPROTO_MAX;
    register if_addr *ifap;

    IF_ADDR(ifap) {
	if_policy_free(ifap);
    } IF_ADDR_END(ifap) ;

    while (proto--) {
	if (int_import[proto]) {
	    adv_free_list(int_import[proto]);
	    int_import[proto] = (adv_entry *) 0;
	}
	if (int_export[proto]) {
	    adv_free_list(int_export[proto]);
	    int_export[proto] = (adv_entry *) 0;
	}
    }
}

/**/

static if_link *
ifl_alloc(if_link *ifl)
{
    if (ifl) {
	ifl->ifl_refcount++;
#ifdef	DEBUG
	trace_tp(if_task,
		 TR_ALL,
		 0,
		 ("ifl_alloc: interface %s index %u refcount %d",
		  ifl->ifl_name,
		  ifl->ifl_index,
		  ifl->ifl_refcount));
#endif	/* DEBUG */
    }

    return ifl;
}


static if_link *
ifl_free(if_link *ifl)
{
    if (ifl) {
	ifl->ifl_refcount--;

#ifdef	DEBUG
	trace_tp(if_task,
		 TR_ALL,
		 0,
		 ("ifl_free: interface %s index %u refcount %d",
		  ifl->ifl_name,
		  ifl->ifl_index,
		  ifl->ifl_refcount));
#endif	/* DEBUG */

	if (!ifl->ifl_refcount) {
	    if_link *prev_ifl = ifl->ifl_back;

	    /* Remove this from the count */
	    if (!BIT_TEST(ifl->ifl_state, IFS_LOOPBACK)) {
		if_n_link.all--;
	    }

	    if (ifl->ifl_addrent) {
		ifae_free(ifl->ifl_addrent);
	    }
	    ifae_free(ifl->ifl_nameent);
	    ifae_free(ifl->ifl_nameent_wild);

	    if (ifl->ifl_ps[RTPROTO_DIRECT]) {
		/* free the primary address list */
		ifl_free_primary_list(ifl);
	    }

	    if (ifl->ifl_addr) {
		sockfree(ifl->ifl_addr);
	    }

            if (ifl->ifl_handle) {
                sockfree(ifl->ifl_handle);
            }
	    
	    REMQUE(ifl);
	
	    task_block_free(int_link_block_index, (void_t) ifl);

	    ifl = prev_ifl;
	}
    }

    return ifl;
}


if_addr *
ifa_free(if_addr *ifap)
{
    if_addr *prev_ifap = (if_addr *) ifap->ifa_back;

    /* Release the addresses */
    ifi_addr_free(&ifap->ifa_info);

    /* Free the address entry pointers */
    ifae_free(ifap->ifa_addrent_remote);
    ifae_free(ifap->ifa_addrent_local);

    /* Free the link-layer interface if necessary */
    (void) ifl_free(ifap->ifa_link);

    if_policy_free(ifap);
    
    REMQUE(ifap);

    task_block_free(int_block_index, (void_t) ifap);
    
    return prev_ifap;
}


/**/

/*
 * Notify the protocols of all the interfaces.
 * Called during initialization and reconfiguration.
 */
void
if_notify(void)
{
    if_addr *ifap;
    if_link *ifl;

    /* Link level interfaces */
    IF_LINK(ifl) {
	/* Notify the protocols */

	task_iflchange(ifl);
    } IF_LINK_END(ifl) ;

    /* Network-layer addresses */
    IF_ADDR(ifap) {
	/* Notify the protocols */

	task_ifachange(ifap);
    } IF_ADDR_END(ifap) ;
}


/**/
static task *if_conf_task;	/* Task that is configuring the interfaces */
static int if_conf_all;		/* True if interfaces not referenced are going away */


void
if_conf_open(task *tp, int all)
{

    assert(!if_conf_task);
    if_conf_task = tp;
    if_conf_all = all;

    if (if_conf_all) {
	register if_addr *ifap;
	register if_link *ifl;
	
	IF_ADDR(ifap) {
	    ifap->ifa_change = IFC_NOCHANGE;
	} IF_ADDR_END(ifap) ;

	IF_LINK(ifl) {
	    ifl->ifl_change = IFC_NOCHANGE;
	} IF_LINK_END(ifl);
    }
}


void
if_conf_close(task *tp, int propagate_state)
{
    register if_addr *ifap;
    register if_link *ifl;

    assert(tp == if_conf_task);
    
    if (if_conf_all) {
	/* Scan for down interfaces */

	/* Check for any link-layer interfaces that have gone away */
	IF_LINK(ifl) {
	    if (ifl->ifl_change == IFC_NOCHANGE
		&& !BIT_TEST(ifl->ifl_state, IFS_DELETE)) {
		/* No longer present, mark it down */

		ifl->ifl_change = IFC_DELETE;
	    }
	} IF_LINK_END(ifl) ;

	/* Check for addresses that are no longer present */
	IF_ADDR(ifap) {
	    if (ifap->ifa_change == IFC_NOCHANGE
		&& !BIT_TEST(ifap->ifa_state, IFS_DELETE)
		&& !BIT_TEST(ifap->ifa_state, IFS_TUNNEL)
		&& !BIT_TEST(ifap->ifa_state, IFS_REGISTER)) {
		/* No longer present - delete it */

		if (BIT_TEST(ifap->ifa_state, IFS_UP)) {
		    BIT_RESET(ifap->ifa_state, IFS_UP);
		    ifap->ifa_change = IFC_DELETE|IFC_UPDOWN;
		} else {
		    ifap->ifa_change = IFC_DELETE;
		}
	    }
	} IF_ADDR_END(ifap) ;
    }

    if_dupcheck(if_task);

    /* Now scan any remaining link-layer interfaces to see if we have to change */
    /* state on any addresses */
    IF_LINK(ifl) {
	int itype = IFAE_ITYPE(ifl->ifl_state);

	switch (ifl->ifl_change) {
	case IFC_NOCHANGE:
	case IFC_REFRESH:
	    break;

	case IFC_ADD:
	    ifae_ifl_alloc(ifl);
	    break;

	case IFC_DELETE:
	    /* Going away */

	    if (BIT_TEST(ifl->ifl_state, IFS_UP)) {
		/* Was up */

		ifl->ifl_transitions++;

		BIT_RESET(ifl->ifl_state, IFS_UP);
		BIT_SET(ifl->ifl_change, IFC_UPDOWN);
	    }
	    
	    if (propagate_state) {
		IF_ADDR(ifap) {
		    if (ifap->ifa_link == ifl
			&& !BIT_TEST(ifap->ifa_state, IFS_DELETE)) {
		    
			if (BIT_TEST(ifap->ifa_state, IFS_UP)) {
			    BIT_RESET(ifap->ifa_state, IFS_UP);

			    BIT_SET(ifap->ifa_change, IFC_UPDOWN);
			}
		    }
		} IF_ADDR_END(ifap) ;
	    }
	    break;

	default:
	    if (BIT_TEST(ifl->ifl_change, IFC_UPDOWN)) {
		/* Up or Down transition */

		if (BIT_TEST(ifl->ifl_state, IFS_UP)) {
		    /* Down to up */

		    if (propagate_state) {
			IF_ADDR(ifap) {
			    if (ifap->ifa_link == ifl
				&& !BIT_TEST(ifap->ifa_state, IFS_DELETE|IFS_UP)
                                && !BIT_TEST(ifap->ifa_ps[RTPROTO_DIRECT].ips_state, IFPS_NOOUT)) {
				BIT_SET(ifap->ifa_state, IFS_UP);
				BIT_SET(ifap->ifa_change, IFC_UPDOWN);
			    }
			} IF_ADDR_END(ifap) ;
		    }
		} else {
		    /* Up to down */

		    ifl->ifl_transitions++;

		    if (propagate_state) {
			IF_ADDR(ifap) {
			    if (ifap->ifa_link == ifl
				&& BIT_TEST(ifap->ifa_state, IFS_UP)) {
				BIT_RESET(ifap->ifa_state, IFS_UP);
				if (ifap->ifa_change != IFC_ADD) {
				    BIT_SET(ifap->ifa_change, IFC_UPDOWN);
				}
			    }
			} IF_ADDR_END(ifap) ;
		    }
		}
	    }
	    if (BIT_TEST(ifl->ifl_change, IFC_ADDR)) {

		/* Change link-layer address entry */
		if (ifl->ifl_addrent) {
		    if (BIT_TEST(ifl->ifl_state, IFS_UP)) {
			ifae_decr(ifl->ifl_addrent, itype);
		    }
		    ifae_free(ifl->ifl_addrent);
		}
		if (ifl->ifl_addr) {
		    ifl->ifl_addrent = ifae_locate(ifl->ifl_addr, &if_link_list);
		    if (BIT_TEST(ifl->ifl_state, IFS_UP)) {
			ifae_incr(ifl->ifl_addrent, itype);
		    }
		} else {
		    ifl->ifl_addrent = (if_addr_entry *) 0;
		}
	    }
	}
    } IF_LINK_END(ifl) ;

    /* Do housekeeping based on network-layer interfaces */
    IF_ADDR(ifap) {
	int itype = IFAE_ITYPE(ifap->ifa_state);

	switch (ifap->ifa_change) {
	case IFC_NOCHANGE:
	case IFC_REFRESH:
	    break;

	case IFC_ADD:
	    /* Inherit IFS_UP from interface */
	    ifae_ifa_alloc(ifap);
	    if (!BIT_TEST(ifap->ifa_state, IFS_LOOPBACK)) {
		if_n_addr[socktype(ifap->ifa_addr_local)].all++;
	    }
	    if (BIT_TEST(ifap->ifa_state, IFS_UP)) {
		if (!BIT_TEST(ifap->ifa_state, IFS_LOOPBACK)) {
		    if_n_addr[socktype(IFA_UNIQUE_ADDR(ifap))].up++;
		}
		ifae_incr(ifap->ifa_addrent_local,  itype);
		ifae_incr(ifap->ifa_addrent_remote, itype);
	    }
	    break;

	case IFC_DELETE|IFC_UPDOWN:
	    if (!BIT_TEST(ifap->ifa_state, IFS_LOOPBACK)) {
		if_n_addr[socktype(IFA_UNIQUE_ADDR(ifap))].up--;
	    }
	    ifae_decr(ifap->ifa_addrent_local,  itype);
	    ifae_decr(ifap->ifa_addrent_remote, itype);
	    /* Fall through */

	case IFC_DELETE:
	    /* Already down */
	    if (!BIT_TEST(ifap->ifa_state, IFS_LOOPBACK)) {
		if_n_addr[socktype(IFA_UNIQUE_ADDR(ifap))].all--;
	    }
	    break;

	default:
	    if (BIT_TEST(ifap->ifa_change, IFC_UPDOWN)) {
		/* Up or Down transition */

		if (BIT_TEST(ifap->ifa_state, IFS_UP)) {
		    /* Down to up */

		    if (!BIT_TEST(ifap->ifa_state, IFS_LOOPBACK)) {
			if_n_addr[socktype(IFA_UNIQUE_ADDR(ifap))].up++;
		    }
		    ifae_incr(ifap->ifa_addrent_local,  itype);
		    ifae_incr(ifap->ifa_addrent_remote, itype);
		} else {
		    /* Up to down */

		    if (!BIT_TEST(ifap->ifa_state, IFS_LOOPBACK)) {
			if_n_addr[socktype(IFA_UNIQUE_ADDR(ifap))].up--;
		    }
		    ifae_decr(ifap->ifa_addrent_local,  itype);
		    ifae_decr(ifap->ifa_addrent_remote, itype);
		}
	    }
	    if (BIT_TEST(ifap->ifa_change, IFC_ADDR)) {
		/* Local address change */

		if (BIT_TEST(ifap->ifa_state, IFS_UP)) {
		    ifae_decr(ifap->ifa_addrent_local, itype);
		}
		ifae_free(ifap->ifa_addrent_local);
		ifap->ifa_addrent_local = ifae_locate(ifap->ifa_addr_local, &if_local_list);
		if (BIT_TEST(ifap->ifa_state, IFS_UP)) {
		    ifae_incr(ifap->ifa_addrent_local, itype);
		}
	    }
	}
    } IF_ADDR_END(ifap) ;

    /* Notify protocols of changes */
    IF_LINK(ifl) {

	/* Reset the refresh indication */
	BIT_RESET(ifl->ifl_change, IFC_REFRESH);

	/* Display a message and notify the protocols if something has changed */
	if (ifl->ifl_change != IFC_NOCHANGE) {
	    int pri = BIT_TEST(task_state, TASKS_INIT|TASKS_TEST) ? 0 : LOG_INFO;

	    if (ifl->ifl_change != IFC_NOCHANGE) {
		tracef("EVENT <%s> %s index %u <%s>",
		       trace_bits(if_change_bits, ifl->ifl_change),
		       ifl->ifl_name,
		       ifl->ifl_index,
		       trace_bits(if_state_bits, ifl->ifl_state));
		if (ifl->ifl_addr) {
		    tracef(" address %A",
			   ifl->ifl_addr);
		}
		trace_log_tp(tp,
			     TRC_NL_AFTER,
			     pri,
			     (NULL));
	    }
    
	    if (!BIT_TEST(task_state, TASKS_INIT)) {

		/* Notify the protocols */
		task_iflchange(ifl);
	    }
	}
    } IF_LINK_END(ifl) ;

    IF_ADDR(ifap) {
	/* Reset the refresh indication */
	BIT_RESET(ifap->ifa_change, IFC_REFRESH);

	/* Display a message and notify the protocols if something has changed */
	if (ifap->ifa_change != IFC_NOCHANGE) {

	    ifa_display(if_task,
			ifap,
			"EVENT",
			"",
			TR_ALL,
			BIT_TEST(task_state, TASKS_INIT|TASKS_TEST) ? 0 : LOG_INFO);
    
	    if (!BIT_TEST(task_state, TASKS_INIT)) {
		/* Notify the protocols */

		task_ifachange(ifap);
	    }
	}
    } IF_ADDR_END(ifap) ;

    /* Reset change information and delete reference to old interfaces */
    IF_ADDR(ifap) {
	switch (ifap->ifa_change) {
	case IFC_NOCHANGE:
	    break;

	case IFC_DELETE:
	case IFC_DELETE|IFC_UPDOWN:
	    BIT_SET(ifap->ifa_state, IFS_DELETE);
	    ifap->ifa_change = IFC_NOCHANGE;
	    ifap = IFA_FREE(ifap);
	    break;

	default:
	    ifap->ifa_change = IFC_NOCHANGE;
	    break;
	}
    } IF_ADDR_END(ifap) ;

    IF_LINK(ifl) {
	switch (ifl->ifl_change) {
	case IFC_NOCHANGE:
	    break;

	case IFC_DELETE:
	case IFC_DELETE|IFC_UPDOWN:
	    BIT_SET(ifl->ifl_state, IFS_DELETE);
	    ifl->ifl_change = IFC_NOCHANGE;
	    ifl = ifl_free(ifl);
	    break;

	default:
	    ifl->ifl_change = IFC_NOCHANGE;
	    break;
	}
    } IF_LINK_END(ifl) ;
    
    if_conf_all = FALSE;

    if_conf_task = (task *) 0;
}


static void
ifl_insert(if_link *new_ifl, u_int indx)
{
    register if_link *ifl = if_plist.ifl_forw;

    if (ifl == &if_plist) {
	/* First interface */

	ifl = if_plist.ifl_back;
    } else {
	/* Insert in order by index */

	do {
	    if (indx < ifl->ifl_index) {
		break;
	    }
	} while ((ifl = ifl->ifl_forw) != &if_plist) ;

	ifl = ifl->ifl_back;
    }

    INSQUE(new_ifl, ifl);
}

if_link *
ifl_locate_index(u_int indx)
{
    register if_link *ifl;

    IF_LINK(ifl) {
	if (ifl->ifl_index == indx) {
	    return ifl;
	}
    } IF_LINK_END(ifl) ;

    return (if_link *) 0;
}


if_link *
ifl_locate_name(const char *name, size_t nlen)
{
    register if_link *ifl;

    IF_LINK(ifl) {
	if (!strncmp(ifl->ifl_name, name, nlen)
	    && strlen(ifl->ifl_name) == nlen) {
	    return ifl;
	}
    } IF_LINK_END(ifl) ;

    return (if_link *) 0;
}


if_link *
ifl_addup(task *tp, if_link *ifl, u_int indx, flag_t state, metric_t metric,
     mtu_t mtu, char *name, size_t nlen, sockaddr_un *addr, sockaddr_un *handle)
{
    /* Add or update a link-layer interface */

    assert(tp == if_conf_task);

    if (ifl
	&& (!name || !nlen
	    || (strlen(ifl->ifl_name) == nlen
		&& !strncmp(ifl->ifl_name, name, nlen)))) {
	/* Found this one - and the name matches */

	ifl->ifl_change = IFC_NOCHANGE;

	if (!BIT_MASK_MATCH(ifl->ifl_state, state, IFS_UP)) {
	    /* State change */

	    if (BIT_TEST(state, IFS_UP)) {
		/* Was down, now up */

		if (!BIT_TEST(state, IFS_LOOPBACK)) {
		    if_n_link.up++;
		}
	    } else {
		/* Was up, now down */

		if (!BIT_TEST(state, IFS_LOOPBACK)) {
		    if_n_link.up--;
		}
	    }
	    ifl->ifl_change = IFC_UPDOWN;
	}

	if ((addr == 0) != (ifl->ifl_addr == 0)
	    || !sockaddrcmp(addr, ifl->ifl_addr)) {
	    /* Link level address has changed */

	    BIT_SET(ifl->ifl_change, IFC_ADDR);

	    if (ifl->ifl_addr) {
		sockfree(ifl->ifl_addr);
	    }
	    if (addr) {
		ifl->ifl_addr = sockdup(addr);
	    } else {
		ifl->ifl_addr = (sockaddr_un *) 0;
	    }
	}

	if (ifl->ifl_change == IFC_NOCHANGE) {
	    /* No changes, just a refresh */

	    ifl->ifl_change = IFC_REFRESH;
	}
    } else {

	/* Allocate a structure */
	ifl = (if_link *) task_block_alloc(int_link_block_index);

	/* Count this interface */
	if (!BIT_TEST(state, IFS_LOOPBACK)) {
	    if_n_link.all++;
	    if (BIT_TEST(state, IFS_UP)) {
		if_n_link.up++;
	    }
	}

	if (addr) {
	    ifl->ifl_addr = sockdup(addr);
	}
	ifl_insert(ifl, indx);

	ifl->ifl_change = IFC_ADD;

	if (name) {
	    strncpy(ifl->ifl_name, name, nlen);
	    ifl->ifl_name[IFL_NAMELEN] = (char) 0;
	}
    }

    ifl->ifl_index = indx;
    ifl->ifl_state = state;
    ifl->ifl_metric = metric;
    ifl->ifl_mtu = mtu;
    ifl->ifl_ps[RTPROTO_DIRECT] = (void_t)0;
    if (ifl->ifl_handle) {
        if (handle
            && !sockaddrcmp(ifl->ifl_handle, handle)) {
            sockfree(ifl->ifl_handle);
        }
    }
    if (handle) {
        ifl->ifl_handle = sockdup(handle);
    }

    if (ifl->ifl_change == IFC_ADD) {
	(void) ifl_alloc(ifl);
    }
    
    return ifl;
}

/*
 *
 * IN:
 *	kern -- if_list entry
 *	conf -- if_config entry
 * OUT:
 *	TRUE or FALSE
 */
static int
ifi_match(if_info *kern, if_info *conf)
{
   int kun=0, cun=0;
   sockaddr_un *klocal, *clocal;

   /* XXX Determine whether either are unnumbered p2p interfaces 
    * We should probably be keeping a state flag for this.
    */

   klocal = (kun)? inet_mask_default : kern->ifi_addr_local;
   clocal = (cun)? inet_mask_default : conf->ifi_addr_local;

   /* If either are subnets, then compare based on local addr */
   if (!BIT_TEST(kern->ifi_state, IFS_POINTOPOINT)
    || !BIT_TEST(conf->ifi_state, IFS_POINTOPOINT))
      return sockaddrcmp(klocal, clocal);
   
   /* Otherwise, compare based on remote addr */
   return sockaddrcmp(kern->ifi_addr_remote, conf->ifi_addr_remote);
}

/*
 * Compare two descriptions of an interface and check for illegal
 * inconsistencies.  Some discrepancies are legal, in which case
 * gated's view overrides the kernel's view.
 *
 * IN:
 *	kern GateD's previous view (usu. kernel's view)
 *	conf GateD configured info
 * OUT:
 *	TRUE on success, FALSE on error
 */
static int
ifi_merge(if_info *kern, if_info *conf)
{
   /* If kernel says p2p and gated says subnet, this is legal as long as
    * kernel's destination address is within gated's subnet prefix.
    */
   if (BIT_TEST(kern->ifi_state, IFS_POINTOPOINT)
    && !BIT_TEST(conf->ifi_state, IFS_POINTOPOINT)) {
      if (sockaddrcmp_mask(kern->ifi_addr_remote, conf->ifi_addr_remote,
       conf->ifi_netmask)== FALSE)
         return FALSE;

      /* Convert kern entry to a subnet entry */
      BIT_RESET(kern->ifi_state, IFS_POINTOPOINT);
      BIT_SET(kern->ifi_state, IFS_MASKED_POINTOPOINT);
      if (BIT_TEST(conf->ifi_state, IFS_BROADCAST)) {
         BIT_SET(kern->ifi_state, IFS_BROADCAST);
         kern->ifi_addr_broadcast = sockdup(conf->ifi_addr_broadcast);
      }
      kern->ifi_netmask = conf->ifi_netmask;
      sockfree(kern->ifi_addr_remote);
      kern->ifi_addr_remote = sockdup(conf->ifi_addr_remote);
   }

   /* If kernel says subnet, and gated says p2p, this is legal as long as
    * gated's destination address is within kernel's subnet prefix.
    */
   if (!BIT_TEST(kern->ifi_state, IFS_POINTOPOINT)
    && BIT_TEST(conf->ifi_state, IFS_POINTOPOINT)) {
      if (sockaddrcmp_mask(kern->ifi_addr_remote, conf->ifi_addr_remote,
       kern->ifi_netmask)== FALSE)
         return FALSE;

      /* Convert kern entry to a p2p entry */
      BIT_SET(kern->ifi_state, IFS_POINTOPOINT);
      if (BIT_TEST(kern->ifi_state, IFS_BROADCAST)) {
         BIT_RESET(kern->ifi_state, IFS_BROADCAST);
         sockfree(kern->ifi_addr_broadcast);
         kern->ifi_addr_broadcast = 0;
      }
      kern->ifi_netmask = inet_mask_host;
      sockfree(kern->ifi_addr_remote);
      kern->ifi_addr_remote = sockdup(conf->ifi_addr_remote);
   }

   /* Check type flags for consistency */
   if ((kern->ifi_state & (IFS_POINTOPOINT|IFS_LOOPBACK))
    != (conf->ifi_state & (IFS_POINTOPOINT|IFS_LOOPBACK)))
      return FALSE;
   
   /* Gated's netmask overrides kernel's netmask for subnets */
   if (!BIT_TEST(kern->ifi_state, IFS_POINTOPOINT)) {
      if (!sockaddrcmp(kern->ifi_netmask,  conf->ifi_netmask)) {
         sockfree(kern->ifi_addr_remote);
         kern->ifi_netmask     = conf->ifi_netmask;
         kern->ifi_addr_remote = sockdup(conf->ifi_addr_remote);
      }
   }
   
   /* If set, configured broadcast should override kernel's (?) */
   if (BIT_TEST(conf->ifi_state, IFS_BROADCAST)) {
      if (BIT_TEST(kern->ifi_state, IFS_BROADCAST)) {
         if (!sockaddrcmp(kern->ifi_addr_broadcast, conf->ifi_addr_broadcast)) {
            sockfree(kern->ifi_addr_broadcast);
            kern->ifi_addr_broadcast = sockdup(conf->ifi_addr_broadcast);
         }
      } else {
         BIT_SET(kern->ifi_state, IFS_BROADCAST);
         kern->ifi_addr_broadcast = sockdup(conf->ifi_addr_broadcast);
      }
   } 

   /* The multicast/unicast flags should always be the lowest common denom. */
   if (!BIT_TEST(conf->ifi_state, IFS_MULTICAST))
      BIT_RESET(kern->ifi_state, IFS_MULTICAST);
   if (BIT_TEST(conf->ifi_state, IFS_NOROUTE))
      BIT_SET(kern->ifi_state, IFS_NOROUTE);

   /* Check local and remote addresses for consistency */
   if (!sockaddrcmp(kern->ifi_addr_local,  conf->ifi_addr_local)
    || !sockaddrcmp(kern->ifi_addr_remote, conf->ifi_addr_remote))
      return FALSE;

   return TRUE;
}

/*
 *	Used to explicitly delete addresses, normally they are
 *	deleted when they are not added during a complete configuration.
 */
void
if_conf_deladdr(task *tp, if_info *ifi)
{
    register if_addr *ifap;

    assert(tp == if_conf_task);

    if (IFI_UNIQUE_ADDR(ifi)) {
	/* Allow for an interface without an address */
	
	IF_ADDR(ifap) {
	    if (sockaddrcmp(IFA_UNIQUE_ADDR(ifap), IFI_UNIQUE_ADDR(ifi))
		&& ifi->ifi_link == ifap->ifa_link
		&& BIT_MASK_MATCH(ifap->ifa_state, ifi->ifi_state, IFS_POINTOPOINT|IFS_LOOPBACK|IFS_BROADCAST)) {
		if (!BIT_TEST(ifap->ifa_state, IFS_DELETE)) {
		    /* Up - mark it down */
		   if (BIT_TEST(ifap->ifa_state, IFS_UP)) {
			BIT_RESET(ifap->ifa_state, IFS_UP);
			ifap->ifa_change = IFC_DELETE|IFC_UPDOWN;
		   }
		   else {
		        ifap->ifa_change = IFC_DELETE;
		   }
		}
		break;
	    }
	} IF_ADDR_END(ifap) ;
    }

    /* Release the addresses */
    ifi_addr_free(ifi);
}

void
if_conf_addaddr(task *tp, if_info *ifi)
{
    register if_addr *ifap;
    sockaddr_un *network;
    if_info *ifidef;

    assert(tp == if_conf_task);

    /* If we have configuration info which matches this, merge them */
    IF_INFO(ifidef, &if_config) {
       if (ifi_match(ifi, ifidef)) {
          if (!ifi_merge(ifi, ifidef)) {
             /* Found an inconsistency, take it down */
             goto Delete;
          }
          break;
       }
    } IF_INFO_END(ifidef, &if_config);

    /* If the local and remote addresses of a P2P interface are the same */
    /* assume that it is in testing mode and ignore it */
    if (!IFI_UNIQUE_ADDR(ifi) || !ifi->ifi_addr_local
	|| (BIT_TEST(ifi->ifi_state, IFS_POINTOPOINT)
	    && (sockaddrcmp(ifi->ifi_addr_remote, ifi->ifi_addr_local)))) {
	/* Flag it as down */

    Delete:
	tracef("if_conf_addaddr: ignoring %s %A/%A",
	       ifi->ifi_link->ifl_name,
	       ifi->ifi_addr_local,
	       ifi->ifi_netmask);
	
	if (BIT_TEST(ifi->ifi_state, IFS_POINTOPOINT)) {
	    tracef(" -> %A",
		   IFI_UNIQUE_ADDR(ifi));
	} else if (BIT_TEST(ifi->ifi_state, IFS_BROADCAST)) {
	    tracef(" -> %A",
		   ifi->ifi_addr_broadcast);
	}
	trace_only_tp(tp,
		      0,
		      (NULL));
	if_conf_deladdr(tp, ifi);
	return;
    }

    /* Calculate masks and stuff */
    switch (socktype(IFI_UNIQUE_ADDR(ifi))) {
#ifdef	PROTO_INET
    case AF_INET:
	/* Verify the addresses */
	if (sock2ip(IFI_UNIQUE_ADDR(ifi)) == INADDR_ANY
	    || sock2ip(IFI_UNIQUE_ADDR(ifi)) == INADDR_BROADCAST
	    || sock2ip(ifi->ifi_addr_local) == INADDR_ANY
	    || sock2ip(ifi->ifi_addr_local) == INADDR_BROADCAST) {
	    /* Bogus addresses */

	    goto Delete;
	}
	
	/* Calculate the subnet */
	if (BIT_TEST(ifi->ifi_state, IFS_LOOPBACK)) {
	    /* Loopback host is just a host route */

	    network = (sockaddr_un *) 0;
	    ifi->ifi_netmask = inet_mask_host;
	} else if (BIT_TEST(ifi->ifi_state, IFS_POINTOPOINT)) {
	    /* If the netmask looks valid we keep it so protocols */
	    /* that do not pass masks will be able to use it to */
	    /* determine which subnets they can send.  The subnet */
	    /* is always left as zero though */

	    if (ifi->ifi_netmask == inet_mask_natural(ifi->ifi_addr_remote)
		|| ifi->ifi_netmask == inet_mask_host) {
		/* Mask is not valid, assume host mask */

		ifi->ifi_netmask = inet_mask_host;
	    }
	    network = (sockaddr_un *) 0;
	} else {
	    /* This net is subnetted */

	    if (socktype(ifi->ifi_netmask) != AF_INET
		|| sock2ip(ifi->ifi_netmask) == INADDR_ANY) {
		/* Bogus subnet mask */

		goto Delete;
	    }

	    if (BIT_TEST(ifi->ifi_state, IFS_BROADCAST)
		&& (socktype(ifi->ifi_addr_broadcast) != AF_INET
		    || sock2ip(ifi->ifi_addr_broadcast) == INADDR_ANY)) {
		/* Bogus broadcast address */

		goto Delete;
	    }
	    
	    sockmask(network = sockdup(IFI_UNIQUE_ADDR(ifi)), ifi->ifi_netmask);
	}

	/* Adjust the MTU */
	ifi->ifi_mtu -= IP_MAXHDRLEN;
#endif	/* PROTO_INET */
	break;


#ifdef PROTO_IPX
    case AF_IPX:
  /* Unless the interface is PPP, the mask is constant.
   */
  if (BIT_TEST(ifi->ifi_state, IFS_POINTOPOINT)) {
    network = (sockaddr_un *)NULL;
    ifi->ifi_netmask = (sockaddr_un *)ipx_hostmask;
  }
  else {
    ifi->ifi_netmask = (sockaddr_un *)ipx_netmask;
    sockmask(network = sockdup(ifi->ifi_addr_local), ifi->ifi_netmask);
  }
  break;
#endif


#ifdef  PROTO_INET6
    case AF_INET6:
        /* Verify the addresses */
        if (IN6_IS_ADDR_UNSPECIFIED(&sock2in6(ifi->ifi_addr_local))
	    || IN6_IS_ADDR_UNSPECIFIED(&sock2in6(ifi->ifi_addr_remote))) {
            /* Bogus addresses */
            goto Delete;
        }

	if (BIT_TEST(ifi->ifi_state, IFS_LOOPBACK)) {
	    network = (sockaddr_un *)0;
	    ifi->ifi_netmask = inet6_mask_host;
	} else if (BIT_TEST(ifi->ifi_state, IFS_POINTOPOINT)) {
	    network = (sockaddr_un *)0; /* ? */
	} else {

	    /* This net is subnetted */

	    if (IN6_IS_ADDR_UNSPECIFIED(&sock2in6(ifi->ifi_netmask))) {
	        /* Bogus subnet mask */
	        goto Delete;
	}
	    sockmask(network = sockdup(ifi->ifi_addr_local), ifi->ifi_netmask);
	}

        /* Adjust the MTU */
        ifi->ifi_mtu -= IPV6_MAXHDRLEN; /* IPv6 header len = 40 bytes  */

	break;

#endif  /* PROTO_INET6 */

#ifdef	PROTO_ISO
    case AF_ISO:
	if (!ifi->ifi_netmask
	    && BIT_TEST(ifi->ifi_state, IFS_LOOPBACK|IFS_POINTOPOINT)) {
	    /* No mask provided */

	    network = (sockaddr_un *) 0;
	} else {
	    /* Mask provided */

	    sockmask(network = sockdup(IFI_UNIQUE_ADDR(ifi)), ifi->ifi_netmask);
	}
	break;
#endif	/* PROTO_ISO */

    default:
	/* Unknown address - ignore it */
	goto Delete;
    }

    IF_ADDR(ifap) {
	if (sockaddrcmp(IFA_UNIQUE_ADDR(ifap), IFI_UNIQUE_ADDR(ifi))
	    && ifi->ifi_link == ifap->ifa_link
	    && BIT_MASK_MATCH(ifap->ifa_state, ifi->ifi_state, IFS_POINTOPOINT|IFS_LOOPBACK|IFS_BROADCAST)) {
	    /* Old address */

	    ifap->ifa_change = IFC_NOCHANGE;

	    /* MTU */
	    if (ifap->ifa_mtu != ifi->ifi_mtu) {
		/* The MTU has changed */

		ifap->ifa_mtu = ifi->ifi_mtu;
		BIT_SET(ifap->ifa_change, IFC_MTU);
	    }

	    /* Metric */
	    if (ifap->ifa_metric != ifi->ifi_metric) {
		/* The metric has changed */

		ifap->ifa_metric = ifi->ifi_metric;
		BIT_SET(ifap->ifa_change, IFC_METRIC);
	    }

	    /* Subnet mask */
	    if (ifap->ifa_netmask != ifi->ifi_netmask) {
		/* The subnet mask has changed */

 		/* Get the new mask */
  		ifap->ifa_netmask = ifi->ifi_netmask;

		/* Free the old net and subnet mask */
		if (ifap->ifa_addr_remote) {
		    sockfree(ifap->ifa_addr_remote);
		}

		/* Assign new net and mask */
		ifap->ifa_addr_remote = network;
		network = (sockaddr_un *) 0;
 
		/* Fix the flags */
		BIT_SET(ifap->ifa_change, IFC_NETMASK);
	    }

	    /* Broadcast address */
	    if (!sockaddrcmp(ifap->ifa_addr_broadcast, ifi->ifi_addr_broadcast)) {
		/* The broadcast address has changed */

		sockfree(ifap->ifa_addr_broadcast);
		ifap->ifa_addr_broadcast = ifi->ifi_addr_broadcast;
#ifdef PROTO_INET6
		if (ifap->ifa_addr_local != NULL && ifap->ifa_addr_broadcast != NULL
		    && socktype(ifap->ifa_addr_local) != socktype(ifap->ifa_addr_broadcast)) {
		    trace_only_tp(tp,
				  0,
				  ("if_conf_addaddr: INCOMPATIBLE FAMILY %A -> %A at %s line %d",
				   ifap->ifa_addr_local,
				   ifap->ifa_addr_broadcast,
				   __FILE__,
				   __LINE__));
		}
#endif
		BIT_SET(ifap->ifa_change, IFC_BROADCAST);
	    } else if (ifi->ifi_addr_broadcast) {
		/* No change, just free the address */

		sockfree(ifi->ifi_addr_broadcast);
	    }

	    /* Local address (for P2P links) */
	    if (!sockaddrcmp(ifap->ifa_addr_local, ifi->ifi_addr_local)) {
		/* The local address has changed */

		sockfree(ifap->ifa_addr_local);
		ifap->ifa_addr_local = ifi->ifi_addr_local;
		if (ifi->ifi_addr_remote != ifi->ifi_addr_local) {
		    sockfree(ifi->ifi_addr_remote);
		}
		BIT_SET(ifap->ifa_change, IFC_ADDR);
	    } else {
		/* No changes, just free the addresses */
		
		sockfree(ifi->ifi_addr_local);
		if (ifi->ifi_addr_remote != ifi->ifi_addr_local) {
		    sockfree(ifi->ifi_addr_remote);
		}
	    }

	    /* Check for up/down transition */
	    if (!BIT_MASK_MATCH(ifap->ifa_state, ifi->ifi_state, IFS_UP)
             && !BIT_TEST(ifap->ifa_ps[RTPROTO_DIRECT].ips_state, IFPS_NOOUT)) {
		/* Up/Down transition */

		BIT_FLIP(ifap->ifa_state, IFS_UP);
		BIT_SET(ifap->ifa_change, IFC_UPDOWN);
	    }

	    /* Check for private/no-private transition */
	    if (!BIT_MASK_MATCH(ifap->ifa_state, ifi->ifi_state, IFS_PRIVATE)) {

		BIT_FLIP(ifap->ifa_state, IFS_PRIVATE);
		BIT_SET(ifap->ifa_change, IFC_PRIVATE);
	    }
	    
	    /* Check for a previously deleted interface */
	    if (BIT_TEST(ifap->ifa_state, IFS_DELETE)) {
		/* Was deleted - welcome back! */

		ifap->ifa_change = IFC_ADD;
		BIT_RESET(ifap->ifa_state, IFS_DELETE);
		IFA_ALLOC(ifap);
	    }

	    /* If not changes, mark it as refreshed */
	    if (ifap->ifa_change == IFC_NOCHANGE) {
		/* No changes, just a refresh */

		ifap->ifa_change = IFC_REFRESH;
	    }

	    goto Return;
	}
    } IF_ADDR_END(ifap) ;

    /* New address */

    ifap = (if_addr *) task_block_alloc(int_block_index);

    ifap->ifa_info = *ifi;	/* struct copy */
#ifdef  IP_MULTICAST_ROUTING
    ifap->ifa_vif = -1;
#endif	/* IP_MULTICAST_ROUTING */

    /* Bump the reference counts */
    IFA_ALLOC(ifap);
    (void) ifl_alloc(ifap->ifa_link);

    /* Flag it as changed */
    ifap->ifa_change = IFC_ADD;

    /* Set default preferences */
    ifap->ifa_preference = RTPREF_DIRECT;
    ifap->ifa_preference_down = RTPREF_DIRECT_DOWN;

#ifdef	PROTO_INET
    if (BIT_TEST(ifap->ifa_state, IFS_LOOPBACK)
	|| sockaddrcmp(ifap->ifa_addr_local, inet_addr_loopback)
	) {
	/* Make sure loopback bit is set */

	BIT_SET(ifap->ifa_state, IFS_LOOPBACK);
    }
#endif	/* PROTO_INET */
#ifdef PROTO_INET6
    if (socktype(ifap->ifa_addr_local)==AF_INET6)
        if (BIT_TEST(ifap->ifa_state, IFS_LOOPBACK)
	    || sockaddrcmp(ifap->ifa_addr_local, inet6_addr_loopback)){
	    BIT_SET(ifap->ifa_state, IFS_LOOPBACK);
	}
#endif /* PROTO_INET6 */

#if 0
    /* removed 7/10/97 by thaler */
    /* Assign the net and netmask */
    ifap->ifa_net = network;
    network = (sockaddr_un *) 0;
#endif

    /* Insert this interface into the list */
    {
	register if_addr *ifap2 = (if_addr *) if_list.ifa_forw;

	if (ifap2 == &if_list) {
	    /* First interface */

	    ifap2 = (if_addr *) if_list.ifa_back;
	} else {
	    /* Insert in order by index, address family, and finally protocol address */

	    do {
		if (ifap->ifa_link->ifl_index > ifap2->ifa_link->ifl_index) {
		    continue;
		}
		if (ifap->ifa_link->ifl_index == ifap2->ifa_link->ifl_index &&
		    sockaddrcmp2(IFA_UNIQUE_ADDR(ifap), IFA_UNIQUE_ADDR(ifap2)) < 0) {
		    /* Insert before this one */

		    break;
		}
	    } while ((ifap2 = (if_addr *) ifap2->ifa_forw) != &if_list) ;

	    ifap2 = (if_addr *) ifap2->ifa_back;
	}

	INSQUE(ifap, ifap2);
    }
	
 Return:
    if (network) {
	sockfree(network);
	network = (sockaddr_un *) 0;
    }
    ifi->ifi_addr_remote = ifi->ifi_addr_local = ifi->ifi_addr_broadcast = ifi->ifi_netmask = (sockaddr_un *) 0;
}


/**/
/* Support for interface routes */
/*
 *	Delete all routes for an interface (one rt_entry, all RIBs)
 */
static void
if_rtdelete(if_addr *ifap)
{

    rt_entry *rt;
    int i, j, ngw;
    sockaddr_un *routers[RT_N_MULTIPATH];

    switch (socktype(IFA_UNIQUE_ADDR(ifap))) {
#ifdef	PROTO_ISO
    case AF_ISO:
	return;
#endif	/* PROTO_ISO */

#ifdef	PROTO_INET
    case AF_INET:
	if (BIT_TEST(ifap->ifa_state, IFS_NOROUTE)) {
            return;
        }
#endif	/* PROTO_INET */
#ifdef PROTO_INET6
    case AF_INET6:
#endif
    default:
	assert(ifap->ifa_rt);
	break;
    }

    rt = ifap->ifa_rt;

    if (BIT_TEST(ifap->ifa_state, IFS_KEEPALL)) {
       /* find this ifap's router in the its rt_entry
 	* and rt_change() it out.
	*/
 	ngw = rt->rt_n_gw;
	bcopy(rt->rt_routers, routers, (RT_N_MULTIPATH * sizeof(sockaddr_un)));
	for (i = 0; i < rt->rt_n_gw; i++) {
	    if (sockaddrcmp(IFA_UNIQUE_ADDR(ifap), routers[i])) {
		routers[i] = NULL;
		ngw--;
		for(j = i; j < ngw; j++)
			routers[j] = routers[j+1];
		routers[ngw] = NULL;
		break;
	    }
	}
	if (!ngw) {
	    rt_delete(rt);
	} else {
	    rt_change(rt, rt->rt_metric, (metric_t) 0, (metric_t) 0, 
	        rt->rt_preference, rt->rt_preference2, ngw, routers);
	}
    } else {
	rt_delete(rt);
    }

    ifap->ifa_rt = NULL;

    trace_only_tp(if_task, 
		  0,
		  ("if_rtdelete: DELETE route for interface %s %A/%A",
		   ifap->ifa_link->ifl_name,
		   IFA_UNIQUE_ADDR(ifap),
		   ifap->ifa_netmask));
}


/*
 *	Interface is up, make the preference attractive and reset the
 *	RTS_NOADVISE flag.  Also used to change the preference on an
 *	interface
 */
static void
if_rtup(if_addr *ifap)
{
    int gotit, i, ngw, primary, router_changed;
    pref_t pref2;
    if_primary_list_t *ifpl;
    rt_entry *rt;
    rt_head *rth;

		int loopback = FALSE;
    sockaddr_un *routers[RT_N_MULTIPATH];

    gotit = router_changed = primary = FALSE;
    pref2 = (pref_t)0;
    rt = NULL;

    switch (socktype(IFA_UNIQUE_ADDR(ifap))) {
#ifdef	PROTO_ISO
    case AF_ISO:
	return;
#endif	/* PROTO_ISO */

#ifdef	PROTO_INET
    case AF_INET:
#if 0
        if (BIT_TEST(ifap->ifa_state, IFS_NOROUTE)) {
            return;
        }
#endif
#endif	/* PROTO_INET */
#ifdef	PROTO_INET6
    case AF_INET6:
        if (BIT_TEST(ifap->ifa_state, IFS_LOOPBACK) ) {
					loopback = TRUE;
				}
				break;
#endif
    default:
	break;
    }
    if (BIT_TEST(ifap->ifa_state, IFS_USE_PRIMARY) &&
	!BIT_TEST(ifap->ifa_state, IFS_ALIAS_PRIMARY)) {
	/* Try to match a primary address
	 */
	for (ifpl = (if_primary_list_t *)
	    ifap->ifa_link->ifl_ps[RTPROTO_DIRECT];
	    ifpl;
	    ifpl = ifpl->ifpl_forw) {
		if (sockaddrcmp(ifpl->ifpl_addr, IFA_UNIQUE_ADDR(ifap))) {
		    BIT_SET(ifap->ifa_state, IFS_ALIAS_PRIMARY);
		    BIT_SET(ifap->ifa_state, IFS_NOAGE);
		}
	}
	if(ifpl == NULL) {
	    /* make an alias have worse than default direct pref */
	    pref2 = RTPREF_DIRECT_ALIAS;
	}
    }


    if (!ifap->ifa_rt) {
	/* Route not yet installed */

	trace_only_tp(if_task,
		      0,
		      ("if_rtup: ADD route for interface %s %A/%A",
		       ifap->ifa_link->ifl_name,
		       IFA_UNIQUE_ADDR(ifap),
		       ifap->ifa_netmask));

	rth = rt_table_locate(IFA_UNIQUE_ADDR(ifap), ifap->ifa_netmask);

	if (rth) {
	    /* Find the direct rt_entry for this dest */
	    RT_ALLRT(rt, rth) {
		if (BIT_TEST(rt->rt_gwp->gw_proto, RTPROTO_BIT(RTPROTO_DIRECT))
		    && !BIT_TEST(rt->rt_state, RTS_GATEWAY)
		    && !BIT_TEST(rt->rt_state, RTS_DELETE)) {
		    gotit = TRUE;
		    break;
		}
	    } RT_ALLRT_END(rt, rth);
	}
	if (gotit && BIT_TEST(ifap->ifa_state, IFS_KEEPALL)) {
	   /* There should only be two types of routes to direct nets:
	    * kernel remnants and interface routes.  Find the interface
	    * route to this dest and add this ifap as a router if it exists.
	    * Otherwise just rt_add().
	    */
	    if (rt->rt_n_gw == RT_N_MULTIPATH) {
	        task_quit(ENOMEM); /* XXX */
		ngw = 0;	/* keep gcc quiet */
	    } else {
	        ifap->ifa_rt = rt;
	        bcopy(rt->rt_routers, routers, (RT_N_MULTIPATH * sizeof(sockaddr_un)));
	        routers[rt->rt_n_gw] = IFA_UNIQUE_ADDR(ifap);
	        ngw = rt->rt_n_gw + 1;
	    }
       	    (void) rt_change(rt, rt->rt_metric, (metric_t) 0,
		(metric_t) 0, rt->rt_preference, rt->rt_preference2,
		ngw, routers);
	} else {
	    /* first route to dest, first non-remnant, or we are 
	     * not configured to keep all intf routes.
	     */
	    int_rtparms.rtp_router = IFA_UNIQUE_ADDR(ifap);
	    int_rtparms.rtp_state = RTS_RETAIN|RTS_INTERIOR;
	    int_rtparms.rtp_preference = ifap->ifa_preference;
	    int_rtparms.rtp_preference2 = pref2;
	    int_rtparms.rtp_n_gw = 1;

	    int_rtparms.rtp_rtd = (void_t) ifap;
	    RTP_RESET_ELIGIBLE(int_rtparms);
	    RTP_SET_ELIGIBLE(int_rtparms, RIB_UNICAST);
#ifdef RIB_MULTICAST
	    RTP_SET_ELIGIBLE(int_rtparms, RIB_MULTICAST);
#endif /* RIB_MULTICAST */

#ifdef	PROTO_MPASPATHS
	    if (ifap->ifa_as) {
    		int_rtparms.rtp_asp = aspath_create(ifap->ifa_as, NULL);
	    }
#endif /* PROTO_MPASPATHS */
#ifdef	PROTO_ASPATHS
#ifdef	PROTO_ASPATHS_MEMBER
	    if (ifap->ifa_as) {
    		int_rtparms.rtp_asp = aspath_create(ifap->ifa_as, NULL);
	    }
#else /* PROTO_ASPATHS_PUBLIC */
	    if (ifap->ifa_as) {
    		int_rtparms.rtp_asp = aspath_create(ifap->ifa_as);
	    }
#endif /* PROTO_ASPATHS_MEMBER */
#endif /* PROTO_ASPATHS */
	
	    if (BIT_TEST(ifap->ifa_state, IFS_PRIVATE)) {
		/* private intf, do not advertise */
		BIT_SET(int_rtparms.rtp_state, RTS_NOADVISE);
	    }

	    switch (BIT_TEST(ifap->ifa_state, IFS_LOOPBACK|IFS_POINTOPOINT)) {
	    case IFS_LOOPBACK:
	        /* Add a host route to the loopback interface */

	        BIT_SET(int_rtparms.rtp_state, RTS_NOADVISE);
	        int_rtparms.rtp_dest = ifap->ifa_addr_local;
	        int_rtparms.rtp_dest_mask = sockhostmask(ifap->ifa_addr_local);

	    	ifap->ifa_rt = rt_add(&int_rtparms);
	    	break;

	    case IFS_POINTOPOINT:
    	        /*
	         * Add a route to the interface.
		 * 4.2 based systems need the router to be the destination.
		 * 4.3 (and later) based systems like it to be the 
		 * local address.
		 */
	        int_rtparms.rtp_dest = ifap->ifa_addr_remote;
	        int_rtparms.rtp_dest_mask = sockhostmask(ifap->ifa_addr_remote);

#ifndef	P2P_RT_REMOTE
	        /* Interface routes need to point at the local address */
	        int_rtparms.rtp_router = ifap->ifa_addr_local;
#endif	/* P2P_RT_REMOTE */

	        ifap->ifa_rt = rt_add(&int_rtparms);
	        break;
	    default:
		/*  Delete any routes to this subnet and add an 
		 *  interface route to it if we are the most attractive 
		 */
    		int_rtparms.rtp_dest = ifap->ifa_addr_remote;
   	 	int_rtparms.rtp_dest_mask = ifap->ifa_netmask;
   	 	ifap->ifa_rt = rt_add(&int_rtparms);
   	 	break;
	    }
	}
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
	if (int_rtparms.rtp_asp) {
	    ASPATH_FREE(int_rtparms.rtp_asp);
	    int_rtparms.rtp_asp = (as_path *) 0;
	}
#endif	/* PROTO_ASPATHS */
    } else { /* route already installed */

	int do_add_del, paths_diff;
 	sockaddr_un *router;
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
	as_path *asp;
#endif /* PROTO_ASPATHS */
	
	/* Decide if we need to add and delete this route (can't rt_change()) */
	if (BIT_TEST(ifap->ifa_rt->rt_state, RTS_NOADVISE)) {
	    if (BIT_TEST(ifap->ifa_state, IFS_LOOPBACK)
		|| BIT_TEST(ifap->ifa_state, IFS_PRIVATE)) {
		do_add_del = FALSE;
	    } else {
		do_add_del = TRUE;
	    }
	} else {
	    /* Route is currently advertisable */
	    if (BIT_TEST(ifap->ifa_state, IFS_LOOPBACK)
		|| BIT_TEST(ifap->ifa_state, IFS_PRIVATE)) {
		do_add_del = TRUE;
	    } else {
		do_add_del = FALSE;
	    }
	}

	router =
#ifndef	P2P_RT_REMOTE
	    BIT_TEST(ifap->ifa_state, IFS_POINTOPOINT) ?
		ifap->ifa_addr_local :
#endif	/* P2P_RT_REMOTE */
		    IFA_UNIQUE_ADDR(ifap);
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
	asp = (as_path *) 0;
	paths_diff = FALSE;

	if (ifap->ifa_as) {
#ifdef PROTO_ASPATHS_MEMBER
	    asp = aspath_create(ifap->ifa_as, NULL);
#else /* PROTO_ASPATHS_PUBLIC */
	    asp = aspath_create(ifap->ifa_as);
#endif /* PROTO_ASPATHS_MEMBER */
	    if (asp != ifap->ifa_rt->rt_aspath) {
		paths_diff = TRUE;
	    }
	} else if (ifap->ifa_rt->rt_aspath->path_len != 0) {
	    paths_diff = TRUE;
	}
#endif	/* PROTO_ASPATHS */

	if (BIT_TEST(intf_alias_processing, IFALIAS_ALL_KEEPALL)) {
	    /* see if this dest is in the router list */
	    for (i = 0; i < ifap->ifa_rt->rt_n_gw; i++) {
		if (sockaddrcmp(router, ifap->ifa_rt->rt_routers[i]))
		    break;
	    }
	    /* it's not, see if we have too many */
	    if (i == ifap->ifa_rt->rt_n_gw) {
		if (ifap->ifa_rt->rt_n_gw == RT_N_MULTIPATH)
		    task_quit(ENOMEM); /* XXX */
		else 
		    router_changed = TRUE;
	    }
	} else {
		if (!sockaddrcmp(router, RT_ROUTER(ifap->ifa_rt)))
		    router_changed = TRUE;
	}

	if (ifap->ifa_rt->rt_preference != ifap->ifa_preference
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
	    || paths_diff
#endif	/* PROTO_ASPATHS */
	    || ifap->ifa_rt->rt_preference2 != pref2
	    || BIT_TEST(ifap->ifa_rt->rt_state, RTS_DELETE)
	    || (router_changed == TRUE)
	    || do_add_del) {	

	    /* XXX - only log message if it was down */
	    trace_log_tp(if_task,
			 0,
			 LOG_WARNING,
			 ("if_rtup: UP route for interface %s %A/%A",
			  ifap->ifa_link->ifl_name,
			  IFA_UNIQUE_ADDR(ifap),
			  ifap->ifa_netmask));

	    if (do_add_del) {
		rt = ifap->ifa_rt;

		/* This stinks but we can't change the flags with rt_change() */
		int_rtparms.rtp_dest = rt->rt_dest;
		int_rtparms.rtp_dest_mask = rt->rt_dest_mask;

		if (!BIT_TEST(intf_alias_processing, IFALIAS_ALL_KEEPALL))
			int_rtparms.rtp_router = router;
		else {
			/* dup the routers because they are free'd in 
			 * rt_delete()
			 */
			int_rtparms.rtp_n_gw = rt->rt_n_gw;
			for (i = 0; i < rt->rt_n_gw; i++) {
			    int_rtparms.rtp_routers[i] =
			        sockdup(rt->rt_routers[i]);
                        }
		}

		int_rtparms.rtp_metric = rt->rt_metric;
		int_rtparms.rtp_metric2 = (metric_t) 0;
		int_rtparms.rtp_tag = (metric_t) 0;
		int_rtparms.rtp_state = rt->rt_state;
		int_rtparms.rtp_preference = ifap->ifa_preference;
		int_rtparms.rtp_preference2 = pref2;
		int_rtparms.rtp_rtd = (void_t) ifap;

#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
		int_rtparms.rtp_asp = rt->rt_aspath;
#endif	/* PROTO_ASPATHS */
#ifndef    EXTENDED_RIBS
		BIT_RESET(int_rtparms.rtp_state, 
                     RTS_STATEMASK|RTS_ACTIVE_UNICAST|RTS_ACTIVE_MULTICAST);
#else   /* EXTENDED_RIBS */
		BIT_RESET(int_rtparms.rtp_state, RTS_STATEMASK);
                int_rtparms.rtp_eligible_ribs = rt->rt_eligible_ribs;
#endif  /* EXTENDED_RIBS */

		if (BIT_TEST(ifap->ifa_state, IFS_PRIVATE)) {
		    /* private interface, do not advertise */
		    BIT_SET(int_rtparms.rtp_state, RTS_NOADVISE);
		} else {
		    /* Make it advertisable */
		    BIT_RESET(int_rtparms.rtp_state, RTS_NOADVISE);
		}

		ifap->ifa_rt = rt_add(&int_rtparms);    

		if (!BIT_TEST(rt->rt_state, RTS_DELETE)) {
		    /* Remove the old one */
		    rt_delete(rt);
		}
	    } else {

		/* An rt_change() is all that is required */

		if (!BIT_TEST(intf_alias_processing, IFALIAS_ALL_KEEPALL)) {
	   	    /* And the preference normal */
		    (void) rt_change_aspath(ifap->ifa_rt,
				ifap->ifa_rt->rt_metric,
				(metric_t) 0,
				(metric_t) 0,
				ifap->ifa_preference,
				pref2,
				1, &router,
        (if_addr **) 0,
				asp);
		} else {
		    if (router_changed) {
			ngw = ifap->ifa_rt->rt_n_gw;
			bcopy(ifap->ifa_rt->rt_routers, routers, 
			    (RT_N_MULTIPATH * sizeof(sockaddr_un)));
			routers[ngw++] = sockdup(router);
		    }
		    (void) rt_change_aspath(ifap->ifa_rt,
			ifap->ifa_rt->rt_metric,
			(metric_t) 0,
			(metric_t) 0,
			ifap->ifa_preference,
			pref2,
			ngw,
			routers,
      (if_addr **) 0,
			asp);
		}
		rt_refresh(ifap->ifa_rt);
	    }
	}
	
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
	if (asp) {
	    ASPATH_FREE(asp);
	}
#endif	/* PROTO_ASPATHS */
    }
}


/*
 *	Change routes to signify an interface is down.  Set the preference to
 *	be less attractive and set the RTS_NOADVISE bit.
 */
static void
if_rtdown(if_addr *ifap)
{
    sockaddr_un *router =
#ifndef	P2P_RT_REMOTE
	BIT_TEST(ifap->ifa_state, IFS_POINTOPOINT) ?
	    ifap->ifa_addr_local :
#endif	/* P2P_RT_REMOTE */
		IFA_UNIQUE_ADDR(ifap);
    sockaddr_un *rt_rtr[RT_N_MULTIPATH];
    rt_entry *rt = ifap->ifa_rt;
    int i, j, ngw;

    switch (socktype(IFA_UNIQUE_ADDR(ifap))) {
#ifdef	PROTO_ISO
    case AF_ISO:
	return;
#endif	/* PROTO_ISO */

#ifdef	PROTO_INET
    case AF_INET:
        if (BIT_TEST(ifap->ifa_state, IFS_NOROUTE)) {
            return;
        }
#endif	/* PROTO_INET */
#ifdef PROTO_INET6
    case AF_INET6:
#endif
    default:
	assert(rt);
	break;
    }
    
    trace_log_tp(if_task,
		 0,
		 LOG_WARNING,
		 ("if_rtdown: DOWN route for interface %s %A/%A",
		  ifap->ifa_link->ifl_name,
		  IFA_UNIQUE_ADDR(ifap),
		  ifap->ifa_netmask));
    /* XXX
     * If we are keeping all interface routes (RT_N_MULTIPATH)
     * don't add a route with the down pref.  I don't think this will
     * cause any problems. 
     */
    if (BIT_TEST(ifap->ifa_state, IFS_KEEPALL)) {
 	ngw = rt->rt_n_gw;
	bcopy(rt->rt_routers, rt_rtr, RT_N_MULTIPATH * sizeof(sockaddr_un));
	for (i = 0; i < rt->rt_n_gw; i++) {
	    if (sockaddrcmp(router, rt_rtr[i])) {
		sockfree(rt_rtr[i]);
		rt_rtr[i] = NULL;
		ngw--;
		for(j = i; j < ngw; j++)
			rt_rtr[j] = rt_rtr[j+1];
		rt_rtr[ngw] = NULL;
	    }
	}
	rt_change(rt, rt->rt_metric, (metric_t) 0, (metric_t) 0, 
	    rt->rt_preference, rt->rt_preference2, ngw, rt_rtr);
	return;
    }

    if (!BIT_TEST(rt->rt_state, RTS_NOADVISE)) {
	/* Add a new non-advisable interface route with the down */
	/* preference */
	/* This stinks but we can't change the flags with rt_change() */

	int_rtparms.rtp_dest = rt->rt_dest;
	int_rtparms.rtp_dest_mask = rt->rt_dest_mask;
	int_rtparms.rtp_router = router;
	int_rtparms.rtp_metric = rt->rt_metric;
	int_rtparms.rtp_metric2 = (metric_t) 0;
	int_rtparms.rtp_tag = (metric_t) 0;
	int_rtparms.rtp_state = rt->rt_state;
	int_rtparms.rtp_preference = ifap->ifa_preference_down;
	int_rtparms.rtp_preference2 = (pref_t) 0;
	int_rtparms.rtp_rtd = (void_t) ifap;
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
	int_rtparms.rtp_asp = rt->rt_aspath;
#endif	/* PROTO_ASPATHS */
#ifndef    EXTENDED_RIBS
	BIT_RESET(int_rtparms.rtp_state, 
                 RTS_STATEMASK|RTS_ACTIVE_UNICAST|RTS_ACTIVE_MULTICAST);
#else   /* EXTENDED_RIBS */
		BIT_RESET(int_rtparms.rtp_state, RTS_STATEMASK);
                int_rtparms.rtp_eligible_ribs = rt->rt_eligible_ribs;
#endif  /* EXTENDED_RIBS */
	BIT_SET(int_rtparms.rtp_state, RTS_NOADVISE);
	ifap->ifa_rt = rt_add(&int_rtparms);    

	/* Remove the old one */
	rt_delete(rt);
    } else {
	/* Just change the preferences */

	(void) rt_change(ifap->ifa_rt,
			 ifap->ifa_rt->rt_metric,
			 (metric_t) 0,
			 (metric_t) 0,
			 ifap->ifa_preference_down,
			 (pref_t) 0,
			 1, &router);
	rt_refresh(ifap->ifa_rt);
    }
}


/* Check for changes needed on interface routes */
static void
if_rtifachange(if_addr *ifap)
{
    register if_addr_entry *ifae = ifap->ifa_addrent_local;

    if (ifae) {
	switch (socktype(IFA_UNIQUE_ADDR(ifap))) {
#ifdef	PROTO_INET
	case AF_INET:
	    if (ifae->ifae_n_p2p && !ifae->ifae_n_loop) {
		
		int_rtparms.rtp_state = RTS_RETAIN|RTS_GATEWAY|RTS_NOADVISE|RTS_INTERIOR;

		if (ifae->ifae_n_p2p == ifae->ifae_n_if) {
		    /* Need a loopback route for a P2P interface */

		    int_rtparms.rtp_preference = RTPREF_DIRECT_AGGREGATE;
		} else {
		    /* Need a dummy route to prevent bogus routing */

		    int_rtparms.rtp_preference = RTPREF_DIRECT;
		    BIT_SET(int_rtparms.rtp_state, RTS_NOTINSTALL);
		}
		
		if (ifae->ifae_rt
		    && ifae->ifae_rt->rt_preference != int_rtparms.rtp_preference) {
		    /* Wrong type, delete it */

		    ifae->ifae_rt->rt_data = (void_t) 0;
		    rt_delete(ifae->ifae_rt);
		    ifae->ifae_rt = (rt_entry *) 0;
		}

		if (!ifae->ifae_rt) {
		    int_rtparms.rtp_dest = ifap->ifa_addr_local;
		    int_rtparms.rtp_dest_mask = inet_mask_host;
		    int_rtparms.rtp_router = inet_addr_loopback;
#ifndef EXTENDED_RIBS
		    int_rtparms.rtp_state |= ELIGIBLE_BIT(RIB_UNICAST);
#else   /* EXTENDED_RIBS */
		    int_rtparms.rtp_eligible_ribs = ELIGIBLE_BIT(RIB_UNICAST);
#endif  /* EXTENDED_RIBS */

		    ifae->ifae_rt = rt_add(&int_rtparms);
		}
	    }
	    break;
#endif	/* PROTO_INET */

	default:
	    break;
	}
    }
}


/* Called when an interface route is actually deleted */
static void
if_rtfree(rt_entry *rt, void_t rtd)
{
    if_addr *ifap = (if_addr *) rtd;

    if (rt == ifap->ifa_rt) {

	assert(rtd == ifap->ifa_rt->rt_data);
	    
	ifap->ifa_rt = (rt_entry *) 0;
    }
}


/*
 *	We just received a routing packet via an interface.  Make sure
 *	we consider the interface up and reset the timer.
 */
void
if_rtupdate(if_addr *ifap)
{
    sockaddr_un *router =
#ifndef	P2P_RT_REMOTE
	BIT_TEST(ifap->ifa_state, IFS_POINTOPOINT) ?
	    ifap->ifa_addr_local :
#endif	/* P2P_RT_REMOTE */
		IFA_UNIQUE_ADDR(ifap);

    if (ifap->ifa_rt->rt_preference != ifap->ifa_preference
	|| !sockaddrcmp(router, RT_ROUTER(ifap->ifa_rt))
	|| BIT_TEST(ifap->ifa_rt->rt_state, RTS_DELETE)) {
	/* We consider it down */

	trace_only_tp(if_task,
		      0,
		      ("if_rtupdate: UPDATE route for interface %s %A/%A",
		       ifap->ifa_link->ifl_name,
		       IFA_UNIQUE_ADDR(ifap),
		       ifap->ifa_netmask));

	if (BIT_TEST(ifap->ifa_state, IFS_UP)) {
	    /* Kernel thinks it's up */

	    rt_open(if_task);
	    if_rtup(ifap);
	    rt_close(if_task, (gw_entry *) 0, 0, NULL);
	} else {
	    /* Check what kernel thinks about it */

	    krt_ifcheck();
	}
    } else {
	/* We consider it up, refresh it */
	
	rt_refresh(ifap->ifa_rt);
    }
}


/**/
/* Support for pre-configured network-later interfaces */

int
if_parse_add(if_info *ifi2, char *err_msg)
{
    if_info *ifi, *ifiact;

    /* Scan for duplicates */
    IF_INFO(ifi, &if_config) {
	if (sockaddrcmp(IFI_UNIQUE_ADDR(ifi), IFI_UNIQUE_ADDR(ifi2)) &&
	    BIT_MASK_MATCH(ifi->ifi_state, ifi2->ifi_state, IFS_POINTOPOINT|IFS_LOOPBACK|IFS_BROADCAST)) {
	    /* Duplicate address */

	    (void) sprintf(err_msg, "if_parse_add: Duplicate address: %A <%s>",
			   IFI_UNIQUE_ADDR(ifi),
			   trace_bits(if_state_bits, BIT_TEST(ifi->ifi_state, IFS_POINTOPOINT|IFS_LOOPBACK|IFS_BROADCAST)));
	    return TRUE;
	}
    } IF_INFO_END(ifi, &if_config) ;

    /* If the interface is a tunnel, validate it */
    if (BIT_TEST(ifi2->ifi_state, IFS_TUNNEL)) {
#ifdef IP_MULTICAST_ROUTING
        /*
         * Currently only Multicast, No-Unicast, IP-in-IP tunnels are 
         * supported by the kernel.  If we have other encapsulation 
         * protocols, like GRE, then we need to handle those here as well.
         *
         * Should we really be auto-setting these flags here (which wouldn't
         * allow for better kernels), or should we just let the kernel 
         * auto-set them without warning?
         */
        if (!BIT_TEST(ifi2->ifi_state, IFS_MULTICAST)) {
	   tracef("Turning on MULTICAST flag for IPIP tunnel to %A ",
	    ifi2->ifi_addr_remote);
           BIT_SET(ifi2->ifi_state, IFS_MULTICAST);
        }
        if (!BIT_TEST(ifi2->ifi_state, IFS_NOROUTE)) {
	   tracef("Turning on NOUNICAST flag for IPIP tunnel to %A ",
	    ifi2->ifi_addr_remote);
           BIT_SET(ifi2->ifi_state, IFS_NOROUTE);
        }
        if (!ipip_parse_tunnel(ifi2->ifi_addr_local, ifi2->ifi_addr_remote,
         err_msg))
#endif
           return TRUE;
    }

    ifi = (if_info *) task_block_alloc(int_info_block_index);
    *ifi = *ifi2;	/* struct copy */

    /* Mark it up so ifi_with*() routines don't ignore it */
    BIT_SET(ifi->ifi_state, IFS_UP);

    INSQUE(ifi, if_config.ifi_back);

    /* If we have an active ifap which matches this, merge them */
    if (ifi->ifi_netmask && !ifi->ifi_addr_remote) {
       ifi->ifi_addr_remote = sockdup(ifi->ifi_addr_local);
       sockmask(ifi->ifi_addr_remote, ifi->ifi_netmask);
    }
    IF_INFO(ifiact, (if_info*)&if_list) {
       if (ifi_match(ifiact, ifi)) {
          if (!ifi_merge(ifiact, ifi)) {
             /* XXX Found an inconsistency, take it down */
          }
          break;
       }
    } IF_INFO_END(ifiact, (if_info*)&if_list);

    return FALSE;
}


/* Remove all preconfigured network-later interfaces */
static void
if_parse_clear(void)
{
    if_info *ifi;
    
    IF_INFO(ifi, &if_config) {
	if_info *ifi2 = ifi->ifi_back;

	REMQUE(ifi);

	task_block_free(int_info_block_index, (void_t) ifi);

	ifi = ifi2;
    } IF_INFO_END(ifi, &if_config) ;
}

adv_entry *
if_parse_unique_address(sockaddr_un *addr)
{
    register adv_entry *adv = (adv_entry *) 0;
    
    if (!addr
	|| (BIT_TEST(task_state, TASKS_STRICTIFS)
	    && !if_withaddr(addr, FALSE)
	    && !ifi_withaddr(addr, FALSE, &if_config))) {
	return adv;
    }
    
    adv = adv_alloc(ADVFT_IFAE_UNIQUE, (proto_t) 0);
    adv->adv_ifae = ifae_locate(addr, &if_unique_list);

    return adv;
}

adv_entry *
if_parse_local_address(sockaddr_un *addr)
{
    register adv_entry *adv = (adv_entry *) 0;
    
    if (!addr
	|| (BIT_TEST(task_state, TASKS_STRICTIFS)
	    && !if_withlcladdr(addr, FALSE)
	    && !ifi_withlcladdr(addr, FALSE, &if_config))) {
	return adv;
    }
    
    adv = adv_alloc(ADVFT_IFAE_LOCAL, (proto_t) 0);
    adv->adv_ifae = ifae_locate(addr, &if_local_list);

    return adv;
}

adv_entry *
if_parse_remote_address(sockaddr_un *addr)
{
    register adv_entry *adv = (adv_entry *) 0;
    
    if (!addr
	|| (BIT_TEST(task_state, TASKS_STRICTIFS)
	    && !if_withdstaddr(addr)
	    && !ifi_withdstaddr(addr, &if_config))) {
	return adv;
    }
    
    adv = adv_alloc(ADVFT_IFAE_REMOTE, (proto_t) 0);
    adv->adv_ifae = ifae_locate(addr, &if_remote_list);

    return adv;
}


adv_entry *
if_parse_name(char *name, int create)
{
    adv_entry *adv;
    if_addr_entry *ifae;
    
    if (create) {
	/* Lookup and create if necessary */

	ifae = ifae_locate(sockbuild_str(name),
			   &if_name_list);
    } else {
	/* Lookup but don't create */

	ifae = ifae_lookup(sockbuild_str(name),
			   &if_name_list);
    }

    if (ifae) {
	/* Build a policy entry */

	adv = adv_alloc(ADVFT_IFN, (proto_t) 0);
	adv->adv_ifn = ifae;
    } else {
	/* Indicate failure */

	adv = (adv_entry *) 0;
    }

    return adv;
}


static void
if_int_dump(FILE *fd, config_entry *list)
{
    register config_entry *cp;

    CONFIG_LIST(cp, list) {
	switch (cp->config_type) {
	case IF_CONFIG_PREFERENCE_UP:
	    (void) fprintf(fd, " preference up %d",
			   (pref_t) GA2S(cp->config_data));
	    break;
			
	case IF_CONFIG_PREFERENCE_DOWN:
	    (void) fprintf(fd, " preference down %d",
			   (pref_t) GA2S(cp->config_data));
	    break;
			
	case IF_CONFIG_PASSIVE:
	    (void) fprintf(fd, " passive");
	    break;
			
	case IF_CONFIG_SIMPLEX:
	    (void) fprintf(fd, " simplex");
	    break;
			
	case IF_CONFIG_REJECT:
	    (void) fprintf(fd, " reject");
	    break;
			
	case IF_CONFIG_BLACKHOLE:
	    (void) fprintf(fd, " blackhole");
	    break;

	case IF_CONFIG_ALIAS_PRIMARY:
	    (void) fprintf(fd, " primaryalias");
	    break;

	case IF_CONFIG_ALIAS_PRIMARY_NET:
	    (void) fprintf(fd, " primaryalias_net");
	    break;

	case IF_CONFIG_ENABLE:
            (void) fprintf(fd, " %sabled",
                           GA2S(cp->config_data) ? "en" : "dis");
	    break;

#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
	case IF_CONFIG_AS:
	    (void) fprintf(fd, " as %u",
			   (u_int) GA2S(cp->config_data));
	    break;
#endif	/* PROTO_ASPATHS */

	default:
	    assert(FALSE);
	    break;
	}
    } CONFIG_LIST_END(cp, list) ;
}


/*
 *	Dump the interface list
 */
/*ARGSUSED*/
static void
if_dump(task *tp, FILE *fd)
{
    int proto;
    if_link *ifl;
    if_addr *ifap;
    if_addr_entry *ifae;

    /*
     * Print out all of the interface stuff.
     */

    (void) fprintf(fd,
		   "\t\tPhysical interfaces: %u\tUp: %u\n",
		   if_n_link.all,
		   if_n_link.up);

    for (proto = AF_UNSPEC; proto < AF_MAX; proto++) {
	if (if_n_addr[proto].all) {
	    (void) fprintf(fd,
			   "\t\t%s protocol addresses: %u\tUp: %u\n",
			   trace_value(task_domain_bits, proto),
			   if_n_addr[proto].all,
			   if_n_addr[proto].up);
	}
    }
    
    (void) fprintf(fd,
		   "\n");

    /* Print out address lists */
    (void) fprintf(fd,
		   "\tAddresses:\n");

    IF_ADDR_LIST(ifae, &if_unique_list) {
	(void) fprintf(fd,
		       "\t\t%A\n\t\t\tP2P %u\tLoop %u\tTotal %u\tRefcount %u\tRoute: %sinstalled\n",
		       ifae->ifae_addr,
		       ifae->ifae_n_p2p,
		       ifae->ifae_n_loop,
		       ifae->ifae_n_if,
		       ifae->ifae_refcount,
		       ifae->ifae_rt ? "" : "not ");
    } IF_ADDR_LIST_END(ifae, &if_unique_list) ;

    (void) fprintf(fd,
		   "\n\tLocal addresses:\n");

    IF_ADDR_LIST(ifae, &if_local_list) {
	(void) fprintf(fd,
		       "\t\t%A\n\t\t\tP2P %u\tLoop %u\tTotal %u\tRefcount %u\tRoute: %sinstalled\n",
		       ifae->ifae_addr,
		       ifae->ifae_n_p2p,
		       ifae->ifae_n_loop,
		       ifae->ifae_n_if,
		       ifae->ifae_refcount,
		       ifae->ifae_rt ? "" : "not ");
    } IF_ADDR_LIST_END(ifae, &if_local_list) ;

    (void) fprintf(fd,
		   "\n\tPhysical addresses:\n");

    IF_ADDR_LIST(ifae, &if_link_list) {
	(void) fprintf(fd,
		       "\t\t%A\n\t\t\tRefcount %u\n",
		       ifae->ifae_addr,
		       ifae->ifae_refcount,
		       ifae->ifae_rt ? "" : "not ");
    } IF_ADDR_LIST_END(ifae, &if_link_list) ;

    (void) fprintf(fd,
		   "\n\tNames:\n");

    IF_ADDR_LIST(ifae, &if_name_list) {
	(void) fprintf(fd,
		       "\t\t%A\n\t\t\tRefcount %u\n",
		       ifae->ifae_addr,
		       ifae->ifae_refcount,
		       ifae->ifae_rt ? "" : "not ");
    } IF_ADDR_LIST_END(ifae, &if_name_list) ;

    (void) fprintf(fd,
		   "\n\n\tInterfaces:\n\n");

    IF_LINK(ifl) {
	(void) fprintf(fd, "\t%s\tIndex %u%s%A\tChange: <%s>\tState: <%s>\n",
		       ifl->ifl_name,
		       ifl->ifl_index,
		       ifl->ifl_addr ? " Address " : " ",
		       ifl->ifl_addr ? ifl->ifl_addr : sockbuild_str(""),
		       trace_bits(if_change_bits, ifl->ifl_change),
		       trace_bits(if_state_bits, ifl->ifl_state));
	(void) fprintf(fd, "\t\tRefcount: %d\tUp-down transitions: %u\n",
		       ifl->ifl_refcount,
		       ifl->ifl_transitions);
	(void) fprintf(fd, "\n");

	IF_ADDR(ifap) {
	    if (ifap->ifa_link == ifl) {
		(void) fprintf(fd, "\t\t%A\n\t\t\tMetric: %d\tMTU: %d\n",
			       IFA_UNIQUE_ADDR(ifap),
			       ifap->ifa_metric,
			       ifap->ifa_mtu);
		(void) fprintf(fd, "\t\t\tRefcount: %d\tPreference: %d\tDown: %d\n",
			       ifap->ifa_refcount,
			       ifap->ifa_preference,
			       ifap->ifa_preference_down);
		(void) fprintf(fd, "\t\t\tChange: <%s>\tState: <%s>\n",
			       trace_bits(if_change_bits, ifap->ifa_change),
			       trace_bits(if_state_bits, ifap->ifa_state));
		if (ifap->ifa_addr_broadcast) {
		    (void) fprintf(fd, "\t\t\tBroadcast Address:   %A\n",
				   ifap->ifa_addr_broadcast);
		}
		if (ifap->ifa_addr_local
		    && BIT_TEST(ifap->ifa_state, IFS_POINTOPOINT)) {
		    (void) fprintf(fd, "\t\t\tLocal Address: %A\n",
				   ifap->ifa_addr_local);
		}

		if (ifap->ifa_netmask) {
		   if (ifap->ifa_addr_remote) {
		    (void) fprintf(fd, "\t\t\tSubnet Number: %A\t\tSubnet Mask: %A\n",
				   ifap->ifa_addr_remote,
				   ifap->ifa_netmask);
		   } else {
		    (void) fprintf(fd, "\t\t\tSubnet Mask: %A\n",
				   ifap->ifa_netmask);
		   }
		}
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
		if (ifap->ifa_as) {
		    (void) fprintf(fd, "\t\t\tAS %u\n",
				   ifap->ifa_as);
		}
#endif	/* PROTO_ASPATHS */
		if (ifap->ifa_rtactive) {
		    int i = RTPROTO_MAX;

		    (void) fprintf(fd,
				   "\t\t\tRouting protocols active:");
		    while (i--) {
			if (BIT_TEST(ifap->ifa_rtactive, RTPROTO_BIT(i))) {
			    (void) fprintf(fd,
					   " %s",
					   trace_state(rt_proto_bits, i));
			}
		    } ;
		    (void) fprintf(fd,
				   "\n");
		}
		for (proto = 0; proto < RTPROTO_MAX; proto++) {
		    struct ifa_ps *ips = &ifap->ifa_ps[proto];
		    
		    if (ips->ips_state || ips->ips_import || ips->ips_export) {
			(void) fprintf(fd, "\t\t\tproto:  %s\tState: <%s>",
				       trace_state(rt_proto_bits, proto),
				       trace_bits2(if_proto_bits, int_ps_bits[proto], ips->ips_state));
			if (BIT_TEST(ips->ips_state, IFPS_METRICIN)) {
			    (void) fprintf(fd, "\tMetricin: %u",
				       ips->ips_metric_in);
			}
			if (BIT_TEST(ips->ips_state, IFPS_METRICOUT)) {
			    (void) fprintf(fd, "\tMetricout: %u",
				       ips->ips_metric_out);
			}
			(void) fprintf(fd, "\n");
			if (ips->ips_import) {
			    (void) fprintf(fd, "\t\t\t\tImport policy:\n");
			    control_interface_import_dump(fd, 5, ips->ips_import);
			}
			if (ips->ips_export) {
			    (void) fprintf(fd, "\t\t\t\tExport policy:\n");
			    control_interface_export_dump(fd, 5, ips->ips_export);
			}
		    }
		}
		(void) fprintf(fd,
			       "\n");
	    }
	} IF_ADDR_END(ifap) ;
    } IF_LINK_END(ifl) ;

    (void) fprintf(fd,
		   "\n");

    /* Dump policy */
    if (int_policy) {
	(void) fprintf(fd,
		       "\tInterface policy:\n");
	control_interface_dump(fd, 2, int_policy, if_int_dump);
    }
    for (proto = 0; proto < RTPROTO_MAX; proto++) {
	if (int_import[proto] || int_export[proto]) {
	    if (int_import[proto]) {
		(void) fprintf(fd, "\t\t%s Import policy:\n",
			       trace_state(rt_proto_bits, proto));
		control_interface_import_dump(fd, 2, int_import[proto]);
	    }
	    if (int_export[proto]) {
		(void) fprintf(fd, "\t\t%s Export policy:\n",
			       trace_state(rt_proto_bits, proto));
		control_interface_export_dump(fd, 2, int_export[proto]);
	    }
	}
    }
}


/*ARGSUSED*/
static void
if_cleanup(task *tp)
{
    /* Remove the preconfigured interfaces */
    if_parse_clear();

    /* Release policy list */
    adv_free_list(int_policy);
    int_policy = (adv_entry *) 0;

    if_policy_cleanup();

    trace_freeup(tp->task_trace);
}


static void
if_age(task_timer *tip, time_t interval)
{
    rt_entry *rt;
    time_t expire_to = time_sec - IF_T_TIMEOUT;
    time_t nexttime = time_sec + 1;

    if (tip) {
	rt_open(tip->task_timer_task);
    }

    RTQ_LIST(&int_rtparms.rtp_gwp->gw_rtq, rt) {
	if_addr *ifap = RT_IFAP(rt);
	
	if (rt->rt_time > expire_to) {
	    /* This entry is yet to expire */
	    
	    if (rt->rt_time < nexttime) {
		nexttime = rt->rt_time;
	    }
	    break;
	}

	if (!BIT_TEST(ifap->ifa_state, IFS_NOAGE|IFS_LOOPBACK)
	    && ifap->ifa_rtactive
	    && if_n_addr[socktype(IFA_UNIQUE_ADDR(ifap))].up > 1) {
	    /* Interface is elligible for timeout */

	    if (rt->rt_preference != ifap->ifa_preference_down
		&& rt_age(rt) >= IF_T_TIMEOUT) {
		/* Interface has timed out */
		    
		if_rtdown(ifap);
	    }
	} else if (rt->rt_preference != ifap->ifa_preference) {
	    /* Interface should be up */

	    if_rtup(ifap);
	}
    } RTQ_LIST_END(&int_rtparms.rtp_gwp->gw_rtq, rt) ;

    if (tip) {
	rt_close(tip->task_timer_task, (gw_entry *) 0, 0, NULL);

	if (nexttime > time_sec) {
	    /* No routes to expire */

	    nexttime = time_sec;
	}

	task_timer_set(tip, (time_t) 0, nexttime + IF_T_TIMEOUT - time_sec);
    }
}


static void
if_ifachange(task *tp, if_addr *ifap)
{
    rt_open(tp);

    switch (ifap->ifa_change) {
    case IFC_REFRESH:
	assert(FALSE);
	break;

    case IFC_NOCHANGE:
    case IFC_ADD:
	if (BIT_TEST(ifap->ifa_state, IFS_UP)) {
	Up:
	    if_control_set(tp, ifap, "if_ifachange:");
	    if (!BIT_TEST(ifap->ifa_state, IFS_UP))
               break; /* if_control_set may have disabled interface */
	    if_rtup(ifap);
	    if_policy_alloc(ifap);
#ifdef  IP_MULTICAST
            inet_allrouters_join(ifap);
#endif  /* IP_MULTICAST */
	}
	break;
	
    case IFC_DELETE:
	break;
	
    case IFC_DELETE|IFC_UPDOWN:
    Down:
#ifdef  IP_MULTICAST
        inet_allrouters_drop(ifap);
#endif  /* IP_MULTICAST */
	if_control_reset(tp, ifap);
	if (ifap->ifa_rt) {
	    if_rtdelete(ifap);
	}
	if_policy_free(ifap);
	break;

    default:
	/* Something has changed */

	if (!BIT_TEST(ifap->ifa_change, IFC_CCHANGE)) {
	    /* Should not happen */

	    assert(FALSE);
	} else if (BIT_TEST(ifap->ifa_change, IFC_UPDOWN)) {
	    if (BIT_TEST(ifap->ifa_state, IFS_UP)) {
		/* Transition to UP - install the routes */

		goto Up;
	    } else {
		/* Transition to DOWN - delete the routes */

		goto Down;
	    }
	}

	/* the interface's PRIVATE flag has changed */
	if (BIT_TEST(ifap->ifa_change, IFC_PRIVATE)) {
	    if_rtup(ifap);
	}

	/* BROADCAST - no change to route */
	/* MTU - no change to route */
	/* METRIC - no change to route */
	if (BIT_TEST(ifap->ifa_change, IFC_NETMASK)) {
	    /* We need a new route */

	    /* Delete the old route */
	    if (ifap->ifa_rt) {
	        if_rtdelete(ifap);
	    }

	    /* and forget about it (if not already forgotten) */
	    if (ifap->ifa_rt) {
		ifap->ifa_rt->rt_data = (void_t) 0;
		ifap->ifa_rt = (rt_entry *) 0;
	    }

	    /* Then try to add a new route */
	    if_rtup(ifap);
	} else if (BIT_TEST(ifap->ifa_change, IFC_ADDR)) {
	    /* We just need to change the next hop */
	    if_rtup(ifap);
	}
	break;
    }

    if_rtifachange(ifap);

    /* Check for timed out interfaces */
    if_age((task_timer *) 0, (time_t) 0);

    rt_close(tp, (gw_entry *) 0, 0, NULL);
}


/*ARGSUSED*/
static void
if_iflchange(task *tp, if_link *ifl)
{

    /* Check for unusual conditions */

    switch (ifl->ifl_change) {
    case IFC_NOCHANGE:
	/* Assume we are reinitting */
	break;

    case IFC_REFRESH:
    default:
	if (!BIT_TEST(ifl->ifl_change, IFC_CCHANGE)) {
	    /* Should not happen */

	    assert(FALSE);
	}
	break;

    case IFC_DELETE:
    case IFC_DELETE|IFC_UPDOWN:
	assert(!BIT_TEST(ifl->ifl_state, IFS_UP));
	break;

    case IFC_ADD:
	break;

    }
}


static void
if_terminate(task *tp)
{
    if_addr *ifap;

    rt_open(tp);

    /* Reinstall routes for any interfaces that timed out */
    IF_ADDR(ifap) {
	rt_entry *rt = ifap->ifa_rt;

	if (rt
	    && rt->rt_preference != ifap->ifa_preference) {
	    /* Interface should be up */
	    
	    if_rtup(ifap);
	}
    } IF_ADDR_END(ifap) ;

    rt_close(tp, (gw_entry *) 0, 0, NULL);

    if_cleanup(tp);
    
    task_delete(tp);
}


/*
 *	Initialize after configuration before the protocols
 */
void
if_init(void)
{
    /* Pickup the latest tracing options */
    trace_freeup(if_task->task_trace);
    if_task->task_trace = trace_set_global((bits *) 0, (flag_t) 0);
    
/* No need to call if_ifachange since if_notify is invoked initially
 * and during the re-configuration. Since IF is not the first task there is no
 * possible sequencing problems.
 */

#ifdef	notdef
    /* Make sure the kernel is up to date */
    rt_flash_kernel();
#endif	/* notdef */
}


/*
 *	Initialize task for interface check
 */
void
if_family_init(void)
{
    if_link *ifl;
    if_task = task_alloc("IF",
			 TASKPRI_INTERFACE,
			 trace_set_global((bits *) 0, (flag_t) 0));
    if_task->task_rtproto = RTPROTO_DIRECT;
    task_set_dump(if_task, if_dump);
    task_set_cleanup(if_task, if_cleanup);
    task_set_ifachange(if_task, if_ifachange);
    task_set_iflchange(if_task, if_iflchange);
    task_set_terminate(if_task, if_terminate);

    if (!task_create(if_task)) {
	task_quit(EINVAL);
    }

    int_rtparms.rtp_gwp = gw_init((gw_entry *) 0,
				  if_task->task_rtproto,
				  if_task,
				  (as_t) 0,
				  (as_t) 0,
				  (sockaddr_un *) 0,
				  GWF_NOHOLD);
    int_rtparms.rtp_gwp->gw_rtd_free = if_rtfree;

    (void) task_timer_create(if_task,
			     "AGE",
			     0,
			     (time_t) 0,
			     (time_t) IF_T_TIMEOUT,
			     if_age,
			     (void_t) 0);

    /* Free the primary address list */
    IF_LINK(ifl) {
	if (ifl->ifl_ps[RTPROTO_DIRECT]) {
	    ifl_free_primary_list(ifl);
	}
    } IF_LINK_END(ifl);

    int_block_index = task_block_init(sizeof (if_addr), "if_addr");
    int_info_block_index = task_block_init(sizeof (if_info), "if_info");
    int_link_block_index = task_block_init(sizeof (if_link), "if_link");
    int_entry_block_index = task_block_init(sizeof (if_addr_entry),
		"if_addr_entry");
    iflist_block_index = task_block_init(sizeof (iflist_t), "iflist_t");
    intf_primary_list_index = task_block_init(sizeof(if_primary_list_t),
	"if_primary_list_t");
    intf_alias_processing = (flag_t) 0;

#ifdef PRIMARY_ADDR_INTF_ROUTE
    intf_alias_processing = (flag_t) IFALIAS_ALL_PRIMARY;
#endif /* PRIMARY_ADDR_INTF_ROUTE */
}

/* Add an interface to a list of interfaces (if_addr structures).
 * Ther interface is defined by its IP address. Return NULL if the interface
 * does not exist.
 */
if_addr *
iflist_add_addr(iflist_t **iflist, sockaddr_un *addr)
{
	if_addr *ifap;
	iflist_t *newif;

	if (!(ifap = if_withaddr(addr, 1)) &&
			!(ifap = (if_addr *)ifi_withaddr(addr, 1, &if_config)))
		return(NULL);
	newif = (iflist_t *)task_block_alloc(iflist_block_index);
	newif->ifl_next = *iflist;
	*iflist = newif;
	newif->ifl_ifaddr = ifap;

	return(ifap);
}

/* Same as iflist_add_addr(), but the interface is defined by its name.
 * which means that several IP level interfaces can be added to the list.
 */
if_addr *
iflist_add_name(iflist_t **iflist, char *str)
{
	if_addr *ifap;
	if_addr *gotone = NULL;
	iflist_t *newif;

	/* Go through all interfaces. If the name matches, add it.
	 */
	IF_ADDR(ifap) {

		if (strcmp(ifap->ifa_link->ifl_name, str))
			continue;

		newif = (iflist_t *)task_block_alloc(iflist_block_index);
		newif->ifl_next = *iflist;
		*iflist = newif;
		newif->ifl_ifaddr = ifap;
		gotone = ifap;

	} IF_ADDR_END(ifap);

	return(gotone);
}

/* Delete anything left in an interface list.
 */
void
iflist_reset(iflist_t **iflist)
{
	iflist_t *ilfp;

	while(*iflist) {
		ilfp = *iflist;
		*iflist = ilfp->ifl_next;
		task_block_free(iflist_block_index, ilfp);
	}
}

/* Find the ifap for a given ifIndex value */
if_addr *
ifa_locate_index(u_int indx)
{
   register if_addr *ifap;

   IF_ADDR(ifap) {
      if (ifap->ifa_link->ifl_index == indx)
         return ifap;
   } IF_ADDR_END(ifap);

   return (if_addr *) 0;
}

void
if_alias_add_primary(task *tp, if_addr *ifap, if_primary_list_t *newaddr)
{
 	if_primary_list_t *ifpl;
 
 	if (!ifap->ifa_link->ifl_ps[RTPROTO_DIRECT]) {
 		ifap->ifa_link->ifl_ps[RTPROTO_DIRECT] = 
 		    (if_primary_list_t *)task_block_alloc(intf_primary_list_index);
 		ifpl = (if_primary_list_t *)ifap->ifa_link->ifl_ps[RTPROTO_DIRECT];
 		ifpl->ifpl_forw = ifpl->ifpl_back = NULL;
 		ifpl->ifpl_addr = sockdup(newaddr->ifpl_addr);
 		ifpl->ifpl_mask = sockdup(newaddr->ifpl_mask);
 	} else {
 		ifpl = (if_primary_list_t *)
 		    ifap->ifa_link->ifl_ps[RTPROTO_DIRECT];
 		for(;;) {
 			/*
 			 * We need one address per network to be
 			 * specified as primary.  If this address
 			 * is on a network that we already have a 
 			 * primary address for, ignore the new one and warn.
 			 * Note that the actual "primary" address (non-alias)
 			 * can never change, so if an address for that
 			 * subnet appears here it will also be ignored.
 			 */
 			if (sockaddrcmp_mask(newaddr->ifpl_addr,
 			    ifpl->ifpl_addr, newaddr->ifpl_mask)) {
 				/* on same subnet */
 				trace_log_tp(tp, 0, LOG_WARNING,
 				    ("if_alias_add_primary: configured primary %A/%A conflicts with primary address %A/%A for interface %s", newaddr->ifpl_addr, newaddr->ifpl_mask, ifpl->ifpl_addr, ifpl->ifpl_mask, ifap->ifa_link->ifl_name));
 				    return;
 			}
 			if (!ifpl->ifpl_forw)
 				break;
 		}
 		ifpl->ifpl_forw = (if_primary_list_t *)
 		    task_block_alloc(intf_primary_list_index);
 		ifpl->ifpl_forw->ifpl_back = ifpl;
 		ifpl->ifpl_forw->ifpl_forw = NULL;
 		ifpl = ifpl->ifpl_forw;
 		ifpl->ifpl_addr = sockdup(newaddr->ifpl_addr);
                 ifpl->ifpl_mask = sockdup(newaddr->ifpl_mask);
 	}
 }
 
void
ifl_free_primary_list(if_link *ifl)
{
 	if_primary_list_t *ifpl;
 
 	if (!(ifpl = (if_primary_list_t *)ifl->ifl_ps[RTPROTO_DIRECT]))
 		return;
 
 	if (!ifpl->ifpl_forw) {
 		sockfree(ifpl->ifpl_addr);
                 sockfree(ifpl->ifpl_mask);
 		task_block_free(intf_primary_list_index, ifpl);
 		return;
 	}
 
 	while (ifpl) {
 		ifpl = ifpl->ifpl_forw;
 		sockfree(ifpl->ifpl_back->ifpl_addr);
 		sockfree(ifpl->ifpl_back->ifpl_mask);
 		task_block_free(intf_primary_list_index, ifpl->ifpl_back);
 	}
  }


