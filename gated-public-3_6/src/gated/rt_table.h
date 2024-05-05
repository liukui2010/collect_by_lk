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
 * rt_table.h
 *
 * Routing table data and parameter definitions.
 *
 */

/* Target specific information */

extern void rttsi_get(rt_head *, u_int, byte *);
extern void rttsi_set(rt_head *, u_int, byte *);
extern void rttsi_reset(rt_head *, u_int);

/* function for comparing routes in the same protocol */
/*
 * rt_cmp functions take two parameters:  two routes to be compared for
 * preference.  The return value should be less than zero if the first
 * route is to be prefered, greater than zero if the second route is to
 * be prefered, and zero if the two routes are indistinguishable.
 * 
 * There is a global array of rt_cmp pointers in rt_table.c  If a protocol
 * needs to do more checking than gated does by default, add an entry for
 * the protocol in the array.
 */
typedef int rt_cmp_func(struct _rt_entry *, struct _rt_entry *);

/* Macros to support a bit per protocol in the routing structure */

/* Don't change this value here, change it in the config file */
#ifndef	RTBIT_SIZE
#define	RTBIT_SIZE	1
#endif	/* RTBIT_SIZE */

#ifndef	NBBY
#define	RTBIT_NBBY	8
#else	/* NBBY */
#define	RTBIT_NBBY	NBBY
#endif	/* NBBY */

typedef u_int32 rtbit_mask;

#define	RTBIT_NB	(sizeof(rtbit_mask) * RTBIT_NBBY)	/* bits per mask */
#define	RTBIT_NBITS	(RTBIT_SIZE * RTBIT_NB)

#define	RTBIT_MASK(name)	rtbit_mask	name[RTBIT_SIZE]

#define	RTBIT_NSHIFT	5
#define	RTBIT_NBIT(x)	(0x01 << ((x) & (RTBIT_NB-1)))
#define	RTBIT_NBYTE(x)	((x) >> RTBIT_NSHIFT)

#define	RTBIT_SET(n, p)		BIT_SET((p)[RTBIT_NBYTE((n)-1)], RTBIT_NBIT((n)-1))
#define	RTBIT_CLR(n, p)		BIT_RESET((p)[RTBIT_NBYTE((n)-1)], RTBIT_NBIT((n)-1))
#define	RTBIT_ISSET(n, p)	BIT_TEST((p)[RTBIT_NBYTE((n)-1)], RTBIT_NBIT((n)-1))

#define	rtbit_isset(rt, bit)	RTBIT_ISSET(bit, (rt)->rt_bits)

/*
 * The number of multipath routes supported by the forwarding engine.
 */

#ifndef	RT_N_MULTIPATH
#define	RT_N_MULTIPATH	1
#endif	/* RT_N_MULTIPATH */

/* Structure used to indicate changes to a route */

typedef struct _rt_changes {
    struct _rt_changes *rtc_next;
    flag_t      rtc_ribs;	/* Active rib(s) we were created for */
    flag_t	rtc_flags;
    short	rtc_n_gw;
    short	rtc_gw_sel;
    sockaddr_un	*rtc_routers[RT_N_MULTIPATH];
    struct _if_addr	*rtc_ifaps[RT_N_MULTIPATH];
    metric_t	rtc_metric;
    metric_t	rtc_metric2;
    metric_t	rtc_tag;
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
    as_path	*rtc_aspath;
#endif	/* PROTO_ASPATHS */
} rt_changes;

#define FIND_RT_CHANGES(ribs, rth, rtc) 				 \
    do {								 \
        rt_changes *Xrtc;						 \
        for (Xrtc=(rth)->rth_changes; Xrtc; Xrtc=Xrtc->rtc_next) { 	 \
	    if (Xrtc->rtc_ribs&(flag_t)(ribs)) {			 \
		break;							 \
	    }								 \
	}								 \
	(rtc) = Xrtc;							 \
    } while (0)

#define RIB_UNICAST        0
#ifdef     IP_MULTICAST_ROUTING
#define RIB_MULTICAST      1
#ifndef    NUMRIBS
#define NUMRIBS 2
#endif  /* NUMRIBS */
#else   /* IP_MULTICAST_ROUTING */
#ifndef    NUMRIBS
#define NUMRIBS 1
#endif  /* NUMRIBS */
#endif  /* IP_MULTICAST_ROUTING */

#ifndef   EXTENDED_RIBS
#if        (NUMRIBS > 2)
#define   EXTENDED_RIBS
#endif /* (NUMRIBS > 2) */
#endif /* EXTENDED_RIBS */

#ifndef   EXTENDED_RIBS
typedef struct {
   const char *name;
   flag_t active;   /* RTS_ACTIVE_* bit */
   flag_t eligible; /* RTS_ELIGIBLE_* = RTAHF_ELIGIBLE_* bit */
   flag_t advbit;   /* ADVF_ bit */
   flag_t pending;  /* RTS_PENDING_* bit */
   flag_t inferior_med; /* INFERIOR_MED_* bit */
} rib_t;

extern rib_t rib[NUMRIBS];

#else  /* EXTENDED_RIBS */
extern char* rib_names[32];
#endif /* EXTENDED_RIBS */

#define	RTCF_NEXTHOP	BIT(0x01)		/* Next hop change */
#define	RTCF_METRIC	BIT(0x02)		/* Metric change */
#define	RTCF_METRIC2	BIT(0x04)		/* Metric change */
#define	RTCF_ASPATH	BIT(0x08)		/* AS path change */
#define	RTCF_TAG	BIT(0x10)		/* Tag change */

#define RT_CHANGE_ALLOC(rtc)    ((rtc) = task_block_alloc(rtchange_block_index))
#define RT_CHANGE_FREE(rtc)     task_block_free(rtchange_block_index, (rtc))

/* Route aggregation structure */

typedef struct _rt_aggr_entry {
    struct _rt_aggr_entry *rta_forw;
    struct _rt_aggr_entry *rta_back;
    struct _rt_aggr_head *rta_head;		/* Head of the list */
    rt_entry *rta_rt;				/* Back pointer to this route */
    pref_t rta_preference;			/* Saved policy preference */
} rt_aggr_entry;

struct _rt_aggr_head {
    rt_aggr_entry rtah_rta;			/* Aggregate entry and head of list */
#define	rtah_rta_forw		rtah_rta.rta_forw
#define	rtah_rta_back		rtah_rta.rta_back
#define	rtah_rta_rt		rtah_rta.rta_rt
#define	rtah_rta_aggr_rt	rtah_rta.rta_aggr_rt
#define	rtah_rta_preference	rtah_rta.rta_preference
#ifdef    EXTENDED_RIBS
    flag_t      rtah_eligible_ribs;             /* Eligible RIB mask */
#endif /* EXTENDED_RIBS */
    flag_t	rtah_flags;
#define	RTAHF_BRIEF		BIT(0x01)	/* Generate atomic aggregate aspath */
#define	RTAHF_CHANGED		BIT(0x02)	/* The contributors changed */
#define	RTAHF_ASPCHANGED	BIT(0x04)	/* The AS path changed */
#define	RTAHF_ONLIST		BIT(0x08)	/* On our private list */
#define	RTAHF_GENERATE		BIT(0x10)	/* Generate a real route, not an aggregate */
#define RTAHF_NOINSTALL         BIT(0x20)       /* Don't install the generated route in the kernel */
#if (defined(PROTO_BGP) || defined(PROTO_MPBGP)) && defined(GATED_MEMBER)
#define RTAHF_BGP		BIT(0x40)	/* Perform BGP aggregation */
    rt_aggr_entry rtah_failed;			/* Failed contributors */
#define rtah_failed_forw	rtah_failed.rta_forw
#define rtah_failed_back	rtah_failed.rta_back
#define rtah_failed_rt		rtah_failed.rta_rt
#define rtah_failed_aggr_rt	rtah_failed.rta_aggr_rt
#define rtah_failed_preference	rtah_failed.rta_preference
    u_int32 rtah_nexthop;			/* Next hop to match */
    u_int32 rtah_med;				/* MED to match */
    u_int32 rtah_matched;			/* Successful matches */
#else /* defined(PROTO_BGP) || defined(PROTO_MPBGP) */
#define RTAHF_BGP		0
#endif /*defined(PROTO_BGP) || defined(PROTO_MPBGP) */
#ifndef    EXTENDED_RIBS
#define	RTAHF_ELIGIBLE_UNICAST	BIT(0x4000000)	/* = RTS_ELIGIBLE_UNICAST */
#define	RTAHF_ELIGIBLE_MULTICAST BIT(0x800000)	/* = RTS_ELIGIBLE_MULTICAST */
#endif /* EXTENDED_RIBS */
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
    as_path_list *rtah_aplp;	/* AS Path list pointer */
#endif	/* PROTO_ASPATHS */
};

#define	AGGR_LIST(list, rta) \
	do { \
		register rt_aggr_entry *Xrta_next = ((rta) = (list))->rta_forw; \
		while (Xrta_next != (list)) { \
		    (rta) = Xrta_next; \
		    Xrta_next = Xrta_next->rta_forw;
#define	AGGR_LIST_END(rtq, rt)	} } while (0)

#define	ADVF_AGGR_BRIEF		ADVF_USER1
#define	ADVF_AGGR_GENERATE	ADVF_USER2	
#define ADVF_AGGR_NOINSTALL     ADVF_USER3
#define ADVF_AGGR_BGP		ADVF_USER4
/*
 *	Each rt_head entry contains a destination address and the root entry of
 *	a doubly linked lists of type rt_entry.  Each rt_entry contains
 *	information about how this occurance of a destination address was
 *	learned, next hop, ...
 *
 *	The rt_entry structure contains a pointer back to it's rt_head
 *	structure.
 */

/*
 *	Define link field as a macro.  These three fields must be in the same
 *	relative order in the rt_head and rt_entry structures.
 */
#define rt_link struct _rt_entry *rt_forw, *rt_back; struct _rt_head *rt_head

struct _rt_head {
    struct  _radix_node *rth_radix_node;	/* Tree glue and other values */
    sockaddr_un *rth_dest;			/* The destination */
    sockaddr_un *rth_dest_mask;			/* Subnet mask for this route */
    flag_t rth_state;				/* Global state bits */
#ifdef     EXTENDED_RIBS
    flag_t rth_pending_ribs;                    /* Per RIB pending bits */
#endif  /* EXTENDED_RIBS */
    struct _rt_entry *rth_rib_active[NUMRIBS];  /* Ptr to active rt per RIB */
    struct _rt_entry *rth_rib_last_active[NUMRIBS];  /* Pointer to previous active route */
    struct _rt_entry *rth_rib_holddown[NUMRIBS]; /* Pointer to route in holddown */
#ifdef PROTO_DVMRP_ROUTING
    void  *rth1_info;		   		/* RIB 1 info pointer */
#endif /* PROTO_DVMRP_ROUTING */
#ifdef PROTO_WRD
    struct _rr_suppress_hist *rth_hists;	/* Instability history list */
#endif /* PROTO_WRD */
#ifdef IPSEC
	struct _ipsec_param_t *rth_ipsec;	/* IPSEC param for that route */
#endif
    rt_aggr_entry *rth_aggregate;		/* Aggregate list entry */
    rt_changes *rth_changes;			/* Pointer to changes in active route */
    rt_link;					/* Routing table chain */
    struct _rt_tsi *rth_tsi;			/* Target specific information */
    byte            rth_entries;		/* Number of routes for this destintation */
    byte            rth_n_announce;		/* Number of routes with announce bits set */
    byte            rth_aggregate_depth;	/* Depth of this destination as an aggregate */
#ifdef PROTO_WRD
    byte rth_n_hists;                           /* Number of history blocks */
#endif /* PROTO_WRD */
};


/**/

struct _rt_entry {
    rt_link;					/* Chain and head pointers */
#define	rt_dest		rt_head->rth_dest	/* Route resides in rt_head */
#define	rt_dest_mask	rt_head->rth_dest_mask	/* Mask resides in rt_head */
#define	rt_rib_active	rt_head->rth_rib_active	/* Pointer to the active route */
#define	rt_rib_holddown	rt_head->rth_rib_holddown /* Pointer to the route in holddown */
#define	rt_n_announce	rt_head->rth_n_announce
    short rt_n_gw;				/* Number of next hops */
    short rt_gw_sel;				/* Index to selected next hop */
    sockaddr_un *rt_routers[RT_N_MULTIPATH];	/* Next Hops */
    struct _if_addr *rt_ifaps[RT_N_MULTIPATH];	/* Interface to send said packets to */
    gw_entry *rt_gwp;				/* Gateway we learned this route from */
    metric_t rt_metric;				/* Interior metric of this route */
    metric_t rt_metric2;
    metric_t rt_tag;				/* Route tag */
    flag_t rt_state;				/* Gated flags for this route */
#ifdef    EXTENDED_RIBS
    flag_t rt_eligible_ribs;		        /* RIBs in which rt eligible */
    flag_t rt_active_ribs;                      /* RIBs in which rt is active */
    flag_t rt_pending_ribs;                     /* RIBs in which rt is pending*/
    flag_t rt_inferior_med_ribs;                /* RIBs in which rt is pending*/
#else  /* EXTENDED_RIBS */
#define rt_eligible_ribs rt_state  /* To keep import() calls tidy */
#define rt_inferior_med_ribs rt_state  /* To keep bgp_med.c tidy */
#endif /* EXTENDED_RIBS */
    rtq_entry rt_rtq;
#define	rt_time	rt_rtq.rtq_time		/* Time this route was last reset */
#define	rt_age(rt)	(time_sec - (rt)->rt_time)
    void_t rt_datas[2];				/* Protocol specific data */
#define	rt_data	rt_datas[0]
    RTBIT_MASK(rt_bits);			/* Announcement bits */
    u_char	rt_n_bitsset;			/* Count of bits set */
    pref_t rt_preference;			/* Preference for this route */
    pref_t rt_preference2;			/* 2nd preference for route */
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
    struct _as_path *rt_aspath;			/* AS path for this route */
#endif	/* PROTO_ASPATHS */
#ifdef PROTO_WRD
    struct _rr_suppress_hist *rt_hist;		/* Assoc. Instability history */
#endif /* PROTO_WRD */
};

#ifdef PROTO_IPX
#define rt_ipxsap_name	rt_datas[0]
#define rth_ipxsap_name rth_rib_active[ribi]->rt_ipxsap_name
#endif /* PROTO_IPX */


#if	RT_N_MULTIPATH > 1
#define	RT_ROUTER(rt)	((rt)->rt_routers[(rt)->rt_gw_sel])
#define	RT_IFAP(rt)	((rt)->rt_ifaps[(rt)->rt_gw_sel])
#define	RTC_ROUTER(rtc)	((rtc)->rtc_routers[(rtc)->rtc_gw_sel])
#define	RTC_IFAP(rtc)	((rtc)->rtc_ifaps[(rtc)->rtc_gw_sel])
#else	/* RT_N_MULTIPATH > 1 */
#define	RT_ROUTER(rt)	((rt)->rt_routers[0])
#define	RT_IFAP(rt)	((rt)->rt_ifaps[0])
#define	RTC_ROUTER(rtc)	((rtc)->rtc_routers[0])
#define	RTC_IFAP(rtc)	((rtc)->rtc_ifaps[0])
#endif	/* RT_N_MULTIPATH */

/*
 * "State" of routing table entry.
 */

/* First, the flags which apply to all RIBS... */
#define	RTS_REMOTE		BIT(0x01)	/* route is for ``remote'' entity */
#define RTS_NOTINSTALL  	BIT(0x02)	/* don't install this route in kernel */
#define RTS_NOADVISE		BIT(0x04)	/* This route not to be advised */
#define RTS_INTERIOR    	BIT(0x08)	/* an interior route */
#define RTS_EXTERIOR    	BIT(0x10)	/* an exterior route */
#define	RTS_NETROUTE		(RTS_INTERIOR|RTS_EXTERIOR)
#define	RTS_DELETE		BIT(0x20)	/* Route is deleted */
#define	RTS_HIDDEN		BIT(0x40)	/* Route is present but not used because of policy */
#define	RTS_INITIAL		BIT(0x80)	/* This route is being added */
#define	RTS_RELEASE		BIT(0x0100)	/* This route is scheduled for release */
#define	RTS_FLASH		BIT(0x0200)	/* This route is scheduled for a flash */
#define	RTS_ONLIST		BIT(0x0400)	/* This route is on the flash list */
#define	RTS_RETAIN		BIT(0x0800)	/* This static route retained at shutdown */
#define	RTS_GROUP		BIT(0x1000)	/* This is a multicast group */
#define	RTS_GATEWAY		BIT(0x2000)	/* This is not an interface route */
#define	RTS_REJECT		BIT(0x4000)	/* Send unreachable when trying to use this route */
#define	RTS_STATIC		BIT(0x8000)	/* Added by route command */
#define RTS_BLACKHOLE		BIT(0x010000)   /* Silently drop packets to this net */
#define RTS_IFSUBNETMASK	BIT(0x020000)   /* Subnet mask derived from interface */
#define RTS_MED_CHANGE		BIT(0x040000)	/* Get rt_change()'s attention*/
#define RTS_SUPPRESSED		BIT(0x080000)   /* Route is reachable but suppressed */
#ifdef IPSEC
#define RTS_FORCE		BIT(0x100000)	/* force route change */
#else  /* IPSEC */
#define RTS_FORCE		BIT(0x000000)   /* Not used */
#endif /* IPSEC */

#ifndef   EXTENDED_RIBS
/* Now the RIB-specific bits... */
#define	RTS_ELIGIBLE_UNICAST	BIT(0x200000)	/* Route is eligible to become active */
#define	RTS_ELIGIBLE_MULTICAST	BIT(0x400000)	/* Route is eligible to become active */
#define RTS_ELIGIBLE_RIBS       (RTS_ELIGIBLE_UNICAST|RTS_ELIGIBLE_MULTICAST)
#define	RTS_ACTIVE_UNICAST     	BIT(0x800000)	/* Route is active */
#define	RTS_ACTIVE_MULTICAST   	BIT(0x01000000)	/* Route is active */
#define RTS_ACTIVE_RIBS		(RTS_ACTIVE_UNICAST|RTS_ACTIVE_MULTICAST)
#define	RTS_PENDING_UNICAST	BIT(0x02000000)	/* Route is pending because of holddown on another route */

#define	RTS_PENDING_MULTICAST	BIT(0x04000000)	/* Route is pending because of holddown on another route */
#define RTS_INFERIOR_MED_MULTI	BIT(0x08000000)	/* Has inferior Multicast MED */
#define RTS_INFERIOR_MED_UNI	BIT(0x10000000)	/* Has inferior Unicast MED */
#define RTS_INFERIOR_MED_RIBS	(RTS_INFERIOR_MED_UNI|RTS_INFERIOR_MED_MULTI)
#endif /* EXTENDED_RIBS */
#define RTS_AGGR		BIT(0x20000000) /* Contributes to an aggregate */
#if (defined(PROTO_BGP) || defined(PROTO_MPBGP)) && defined(GATED_MEMBER)
#define RTS_BGP_AGGR		BIT(0x40000000) /* Is a BGP aggregate */
#endif /* defined(PROTO_BGP) || defined(PROTO_MPBGP) */

#define RTS_STATEMASK           (RTS_DELETE|RTS_HIDDEN|RTS_INITIAL)

#define	RTPROTO_ANY		0	/* Matches any protocol */
#define RTPROTO_DIRECT		1	/* route is directly connected */
#define RTPROTO_KERNEL		2	/* route was installed in kernel when we started */
#define RTPROTO_REDIRECT	3	/* route was received via a redirect */
#define	RTPROTO_DEFAULT		4	/* deprecated protocol */
#define	RTPROTO_OSPF		5	/* OSPF AS Internal routes */
#define	RTPROTO_OSPF_ASE	6	/* OSPF AS External routes */
#define	RTPROTO_INET6		7	/* For IPv6 specific stuff */
#define RTPROTO_NOSPF_ASE       8       /* OSPF2 AS External routes */
#define RTPROTO_RIP		9	/* Berkeley RIP */
#define	RTPROTO_BGP		10	/* Border gateway protocol */
#define RTPROTO_EGP		11	/* route was received via EGP */
#define	RTPROTO_STATIC		12	/* route is static */
#define	RTPROTO_SNMP		13	/* route was installed by SNMP */
#define	RTPROTO_ICMPV6		14	/* IPv6 ICMPv6 */
#define	RTPROTO_ISIS		15	/* IS-IS */
#define	RTPROTO_SLSP		16	/* Simple Link State Protocol */
#define	RTPROTO_RIPNG		17	/* IPv6 RIP routes*/
#define	RTPROTO_INET		18	/* For INET specific stuff */
#define	RTPROTO_IGMP		19	/* For IGMP stuff */
#define	RTPROTO_AGGREGATE	20	/* Aggregate route */
#define	RTPROTO_DVMRP		21	/* Distance Vector Multicast Routing */
#define	RTPROTO_PIM		22	/* Protocol Independent Multicast */
#define	RTPROTO_RDISC		23	/* Router Discovery */
#define RTPROTO_NOSPF		24      /* OSPF2 AS Internal routes */
#define RTPROTO_CBT		25	/* Core Based Tree */
#define RTPROTO_NOSPF_NSSA	26	/* New OSPF type-7 LSA */
#define	RTPROTO_DVMRP_ROUTING	27	/* DVMRP routing */
#define RTPROTO_MROUTE		28      /* For MBR stuff */
#define RTPROTO_BGMP		29      /* Border Gateway Multicast Protocol */
#define RTPROTO_SMUX		30      /* SNMP SMUX */
#define RTPROTO_MSDP		31      /* Multicast Source Discovery Proto */
#define RTPROTO_MAX		32	/* The number of protocols allocated */

#ifdef not_yet
#define	RTPROTO_NDP		xx	/* IPv6 Neighbor Discovery */
#define	RTPROTO_OSPFV6		xx	/* IPv6 OSPF AS internal routes */
#define	RTPROTO_OSPFV6_ASE	xx	/* IPv6 OSPF AS external routes */
#define	RTPROTO_PIMV6		xx	/* IPv6 PIM */
#endif

#define	RTPROTO_BIT(proto)	((flag_t) (1 << ((proto) - 1)))
#define	RTPROTO_BIT_ANY		((flag_t) -1)
/* Because RTPROTO_ANY is 0 */
#define RTPROTO_CMP(a, b)	((a) == (b) || !(a) || !(b))

/*
 *	Preferences of the various route types
 */
#define	RTPREF_KERNEL_TEMP	0	/* For managing the forwarding table */
#define	RTPREF_DIRECT		0	/* Routes to interfaces */
#define RTPREF_DIRECT_ALIAS	1	/* Routes to interface aliases */
#define	RTPREF_OSPF		10	/* OSPF Internal route */
#define RTPREF_OSPFV6		10	/* OSPFv6 Internal route */
#define	RTPREF_ISIS_L1		15	/* IS-IS level 1 route */
#define	RTPREF_ISIS_L2		18	/* IS-IS level 2 route */
#define	RTPREF_SLSP		19	/* NSFnet backbone SPF */
#define	RTPREF_DEFAULT		20	/* defaultgateway and EGP default */
#define	RTPREF_REDIRECT		30	/* redirects */
#define	RTPREF_KERNEL		40	/* learned via route socket */
#define	RTPREF_SNMP		50	/* route installed by network management */
#define	RTPREF_RDISC		55	/* Router Discovery */
#define	RTPREF_NDP		55	/* IPv6 Neighbor Discovery */
#define	RTPREF_STATIC		60	/* Static routes */
#define RTPREF_DVMRP            70      /* DVMRP (multicast RIB only) */
#define	RTPREF_IGRP		80	/* Cisco IGRP */
#define	RTPREF_HELLO		90	/* DCN Hello */
#define	RTPREF_RIP		100	/* Berkeley RIP */
#define RTPREF_RIPNG		100	/* RIPng */
#define RTPREF_SAP    100 /* IPX's SAP protocol */
#define	RTPREF_DIRECT_AGGREGATE	110	/* P2P interface aggregate routes */
#define	RTPREF_DIRECT_DOWN	120	/* Routes to interfaces that are down */
#define	RTPREF_AGGREGATE	130	/* Aggregate default preference */
#define	RTPREF_OSPF_ASE		150	/* OSPF External route */
#define RTPREF_OSPFV6_ASE	150	/* OSPFv6 EXternal route */
#define	RTPREF_IDPR		160	/* InterDomain Policy Routing */
#define	RTPREF_BGP_EXT		170	/* Border Gateway Protocol - external peer */
#define	RTPREF_EGP		200	/* Exterior Gateway Protocol */
#define	RTPREF_KERNEL_REMNANT	254	/* Routes in kernel at startup */


/**/

/* Structure with route parameters passed to rt_add. */

typedef struct {
    sockaddr_un *rtp_dest;
    sockaddr_un *rtp_dest_mask;
    int		rtp_n_gw;
    sockaddr_un *rtp_routers[RT_N_MULTIPATH];
#define	rtp_router	rtp_routers[0]
    gw_entry	*rtp_gwp;
    metric_t	rtp_metric;
    metric_t	rtp_metric2;
    metric_t	rtp_tag;
    flag_t	rtp_state;
    pref_t	rtp_preference;
    pref_t	rtp_preference2; /* End of order assumption in RTPARMS_INIT */
    void_t	rtp_rtd;
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
    as_path	*rtp_asp;
#endif	/* PROTO_ASPATHS */
#ifdef    EXTENDED_RIBS
    flag_t	rtp_eligible_ribs;
    flag_t	rtp_inferior_med_ribs;
#else  /* EXTENDED_RIBS */
#define rtp_eligible_ribs rtp_state  /* To keep import() calls tidy */
#define rtp_inferior_med_ribs rtp_state  /* To keep bgp_med.c tidy */
#endif /* EXTENDED_RIBS */
#ifdef IPSEC
    sockaddr_un	*rtp_tunnel;
    u_int32	rtp_rtid;
    u_char	rtp_fwant;
    u_char	rtp_rcvalgo;
    u_char	rtp_rcvkeylen;
    time_t	rtp_rcvttl;
    struct sockaddr_key *rtp_key;
#endif
} rt_parms;

#define	RTPARMS_INIT(n_gw, metric, state, preference) \
    { \
	(sockaddr_un *) 0, \
	(sockaddr_un *) 0, \
	n_gw, \
	{ (sockaddr_un *) 0 }, /* XXX RT_N_MULTIPATH? */ \
	(gw_entry *) 0, \
	metric, \
	(metric_t) 0, \
	(metric_t) 0, \
	state, \
	preference \
    }
											     

/* Macros to access the routing table - when the table format changes I */
/* just change these and everything works, right?  */

/*
 *	Change lists
 */

#define	RTL_SIZE	task_pagesize	/* Size of change list (one page) */

struct _rt_list {
    struct _rt_list *rtl_next;			/* Pointer to next on chain */
    struct _rt_list *rtl_root;			/* Pointer to root of list */
    void_t *rtl_fillp;				/* Pointer to last filled location */
    u_int rtl_count;				/* Number of entries on this list */	
    void_t rtl_entries[1];			/* Pointers to routes */
};


extern block_t rtlist_block_index;
extern block_t rtchange_block_index;

/* Reset a list */
#define	RTLIST_RESET(rtl) \
	if (rtl) (rtl) = (rtl)->rtl_root; \
	    while (rtl) { \
		register rt_list *Xrtln = (rtl)->rtl_next; \
		task_block_free(rtlist_block_index, (void_t) (rtl)); \
		(rtl) = Xrtln; \
	    }

/* Scan a change list */
#define	RT_LIST(rth, rtl, type) \
    if (rtl) { \
	rt_list *rtl_root = (rtl)->rtl_root; \
	do { \
	    register void_t *Xrthp; \
	    for (Xrthp = (void_t *) (rtl)->rtl_entries; Xrthp <= (rtl)->rtl_fillp; Xrthp++) \
		if ((rth = (type *) *Xrthp))

#define	RT_LIST_END(rth, rtl, type) \
	    rth = (type *) 0; \
	} while (((rtl) = (rtl)->rtl_next)) ; \
	(rtl) = rtl_root; \
    }

/* Add an entry to a change list */
#define RTLIST_ADD(rtl, data) \
	do { \
	    register void_t Xdata = (void_t) (data); \
	    if (!(rtl)) { \
		(rtl) = (rt_list *) task_block_alloc(rtlist_block_index); \
		(rtl)->rtl_root = (rtl); \
		(rtl)->rtl_fillp = (rtl)->rtl_entries; \
		*(rtl)->rtl_fillp = Xdata; \
		(rtl)->rtl_root->rtl_count++; \
	    } else if ((rtl)->rtl_fillp < (rtl)->rtl_entries || Xdata != *(rtl)->rtl_fillp) { \
	        if (!(rtl) || (caddr_t) ++(rtl)->rtl_fillp == (caddr_t) (rtl) + RTL_SIZE) { \
		    (rtl)->rtl_fillp--; \
		    (rtl)->rtl_next = (rt_list *) task_block_alloc(rtlist_block_index); \
		    (rtl)->rtl_next->rtl_root = (rtl)->rtl_root; \
		    (rtl) = (rtl)->rtl_next; \
		    (rtl)->rtl_fillp = (rtl)->rtl_entries; \
	        } \
	        *(rtl)->rtl_fillp = Xdata; \
	        (rtl)->rtl_root->rtl_count++; \
	    } \
	} while (0)

/* Scan all routes for this destination */
#define	RT_ALLRT(rt, rth)	{ for (rt = (rth)->rt_forw; rt != (rt_entry *) &(rth)->rt_forw; rt = rt->rt_forw)
#define	RT_ALLRT_END(rt, rth)	if (rt == (rt_entry *) &(rth)->rt_forw) rt = (rt_entry *) 0; }

/* Scan all routes for this destination, in reverse order */
#define	RT_ALLRT_REV(rt, rth)	{ for (rt = (rth)->rt_back; rt != (rt_entry *) &(rth)->rt_forw; rt = rt->rt_back)
#define	RT_ALLRT_REV_END(rt, rth)	if (rt == (rt_entry *) &(rth)->rt_forw) rt = (rt_entry *) 0; }

/* Only route in use for this destination */
#define	RT_IFRT(rt, rth)	if ((rt = rth->rth_rib_holddown[ribi]) || (rt = rth->rth_rib_active[ribi]))
#define	RT_IFRT_END

#ifndef    EXTENDED_RIBS

#define	RTH_TEST_PENDING(rth, ribi) \
	BIT_TEST((rth)->rth_state, rib[ribi].pending)
#define	RT_TEST_PENDING(rt, ribi) \
	BIT_TEST((rt)->rt_state, rib[ribi].pending)
#define	RT_TEST_ACTIVE(rt, ribi) \
	BIT_TEST((rt)->rt_state, rib[ribi].active)
#define	RT_TEST_ELIGIBLE(rt, ribi) \
	BIT_TEST((rt)->rt_state, rib[ribi].eligible)
#define RT_TEST_ANY_ACTIVE(rt) \
	BIT_TEST((rt)->rt_state, RTS_ACTIVE_RIBS)
#define RTP_SET_ELIGIBLE(rtp, ribi) \
        BIT_SET((rtp).rtp_state, rib[ribi].eligible)
#define RTP_SET_ELIGIBLE_BITS(rtp, bits) \
        BIT_SET((rtp).rtp_state, bits)
#define RTP_TEST_ANY_ELIGIBLE(rtp) \
	BIT_TEST((rtp).rtp_state, RTS_ELIGIBLE_RIBS)
#define RTP_RESET_ELIGIBLE(rtp) \
        BIT_RESET((rtp).rtp_state, RTS_ELIGIBLE_RIBS)
#define RTP_RESET_ACTIVE(rtp) \
        BIT_RESET((rtp).rtp_state, RTS_ACTIVE_RIBS)
#define RTP_GET_ELIGIBLE(rtp) \
        ((rtp).rtp_state & RTS_ELIGIBLE_RIBS)

#define ELIGIBLE_BIT(ribi) \
        (rib[ribi].eligible)
#define ACTIVE_BIT(ribi) \
        (rib[ribi].active)
#define ADVF_RIB_BIT(ribi) \
        (rib[ribi].advbit)
#define ADVF_ALL_RIBS\
	(ADVF_RIB_UNICAST|ADVF_RIB_MULTICAST)
#define RT_GET_ELIGIBLE(rt) \
        ((rt)->rt_state & RTS_ELIGIBLE_RIBS)
#define RT_GET_ACTIVE(rt) \
        ((rt)->rt_state & RTS_ACTIVE_RIBS)
#define	RT_TEST_INFMED(rt, ribi) \
	BIT_TEST((rt)->rt_state, rib[ribi].inferior_med)
#define RT_INFMED_BIT(ribi) \
        (rib[ribi].inferior_med)
#define RT_RESET_INFMEDS(rt) \
        BIT_RESET((rt)->rt_state, RTS_INFERIOR_MED_RIBS)

#else  /* EXTENDED_RIBS */

#define	RTRIB_BIT(ribi)	((flag_t) (1 << (ribi)))
#define	RTH_TEST_PENDING(rth, ribi) \
	BIT_TEST((rth)->rth_pending_ribs, RTRIB_BIT(ribi))
#define	RT_TEST_PENDING(rt, ribi) \
	BIT_TEST((rt)->rt_pending_ribs, RTRIB_BIT(ribi))
#define	RT_TEST_ACTIVE(rt, ribi) \
	BIT_TEST((rt)->rt_active_ribs, RTRIB_BIT(ribi))
#define	RT_TEST_ELIGIBLE(rt, ribi) \
	BIT_TEST((rt)->rt_eligible_ribs, RTRIB_BIT(ribi))
#define RTP_SET_ELIGIBLE(rtp, ribi) \
        BIT_SET((rtp).rtp_eligible_ribs, RTRIB_BIT(ribi))
#define RTP_SET_ELIGIBLE_BITS(rtp, bits) \
        BIT_SET((rtp).rtp_eligible_ribs, bits)
#define RTP_RESET_ELIGIBLE(rtp) \
        (rtp).rtp_eligible_ribs = 0
#define RTP_GET_ELIGIBLE(rtp) \
	((rtp).rtp_eligible_ribs)
#define ELIGIBLE_BIT(ribi) \
        RTRIB_BIT(ribi)
#define ACTIVE_BIT(ribi) \
        RTRIB_BIT(ribi)
#define ADVF_RIB_BIT(ribi) \
        RTRIB_BIT(ribi)
#define ADVF_ALL_RIBS \
        ( (flag_t)(-1) >> ( RTBIT_NBBY * sizeof(flag_t) - NUMRIBS ) )
#define RT_GET_ELIGIBLE(rt) \
        ((rt)->rt_eligible_ribs)
#define RT_GET_ACTIVE(rt) \
        ((rt)->rt_active_ribs)
#define	RT_TEST_INFMED(rt, ribi) \
	BIT_TEST((rt)->rt_inferior_med_ribs, RTRIB_BIT(ribi))
#define RT_INFMED_BIT(ribi) \
        RTRIB_BIT(ribi)
#define RT_RESET_INFMEDS(rt) \
        ((rt)->rt_inferior_med_ribs = 0)

#endif /* EXTENDED_RIBS */

/*
 *	Aggregate lists
 */

#ifdef	PROTO_INET
extern adv_entry *aggregate_list_inet;	/* Aggregation policy */
#endif	/* PROTO_INET */
#ifdef	PROTO_INET6
extern adv_entry *aggregate_list_inet6;	/* Aggregation policy */
#endif	/* PROTO_INET6 */
#ifdef	PROTO_ISO
extern adv_entry *aggregate_list_iso;	/* Aggregation policy */
#endif	/* PROTO_ISO */

/*  Macro implementation of rt_refresh.  If this is not defined, a	*/
/*  function will be used.						*/
#define	rt_refresh(rt) \
	do { \
	    register rt_entry *Xrt = (rt); \
	     if (Xrt->rt_rtq.rtq_forw) { \
		REMQUE(&Xrt->rt_rtq); \
		INSQUE(&Xrt->rt_rtq, Xrt->rt_gwp->gw_rtq.rtq_back); \
	     } \
	     Xrt->rt_time = time_sec; \
	} while (0)

extern const bits rt_state_bits[];	/* Route state bits */
extern const bits rt_proto_bits[];	/* Protocol types */
extern struct _task *rt_task;
extern gw_entry *rt_gw_list;		/* List of gateways for static routes */
extern gw_entry *rt_gwp;		/* Gateway structure for static routes */


/*
 * Used when walking through the radix tree, to remember where we are :)
 */
typedef struct _rtwalk_t {
        struct _rtwalk_t *rw_forw;      /* Linked chain */
        struct _rtwalk_t *rw_back;
        rt_head        *rw_rth; /* The current route */
        int             rw_way; /* Way to walk the tree (RTW_xx) */
        struct _radix_node *rw_start;   /* Where we started */
        int             rw_len; /* Lentgh of mask where we started */
}               rtwalk_t;

#define RTW_UP          1       /* Go upward the tree */
#define RTW_DOWN        2       /* Go downward */

extern void rt_walk_init(void);
rtwalk_t * rt_walk_alloc(void);
rtwalk_t * rt_walk_free(rtwalk_t *);
rt_head * rt_walk_start(sockaddr_un *, sockaddr_un *, int);
int rt_match(sockaddr_un *, sockaddr_un *, sockaddr_un *);
rt_head * rt_walk(rtwalk_t *);
void rt_walk_delfix(rt_head *);

void rt_family_init(void);
void rt_init_mib(int);
void rt_open(task * tp);
void rt_close(task * tp, gw_entry *, int, const char *);
rt_entry * rt_add(rt_parms *);
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
rt_entry *rt_change_aspath(rt_entry *, metric_t, metric_t, metric_t, pref_t,
    pref_t, int, sockaddr_un **,  if_addr **ifaps, as_path *);
#define rt_change(rt, m, m2, t, p, p2, n_gw, r) \
    rt_change_aspath(rt, m, m2, t, p, p2, n_gw, r, rt->rt_ifaps, rt->rt_aspath)
#else /* PROTO_ASPATHS */
rt_entry *rt_change(rt_entry *, metric_t, metric_t, metric_t, pref_t, pref_t,
     int, sockaddr_un **);
#define rt_change_aspath(rt, m, m2, t, p, p2, n_gw, r, i, a) \
    rt_change(rt, m, m2, t, p, p2, n_gw, r)
#endif  /* PROTO_ASPATHS */

#ifdef LPJ_CHANGE_FLAGS
rt_entry *rt_change_flags(rt_entry *, flag_t);
#endif /* LPJ_CHANGE_FLAGS */
void rt_set_change(rt_entry *);
/* Delete a route from the routing table */
void rt_delete(rt_entry *);
void rt_flash_update(task_job *);
void rt_new_policy(void);
/* Lookup a route the way the kernel would */
#ifndef    EXTENDED_RIBS
rt_entry *rt_lookup(flag_t, flag_t, sockaddr_un *dst, flag_t, int);
#else  /*  EXTENDED_RIBS */
rt_entry *rt_lookup(flag_t, flag_t, flag_t, flag_t, sockaddr_un *dst, flag_t, 
    int);
#endif /*  EXTENDED_RIBS */
/* Locate a route given dst, table and proto */
rt_entry *rt_locate(flag_t, sockaddr_un *, sockaddr_un *, flag_t);
rt_entry *rt_withgw(rt_head *, gw_entry *);
/* Locate a route given dst, table, proto and gwp */
rt_entry *rt_locate_gw(flag_t, sockaddr_un *, sockaddr_un *, gw_entry *);
void rt_reuse(rt_entry *);
int rth_remove(rt_head *);
/* Allocate a bit */
u_int rtbit_alloc(task *tp, int, u_int, void_t,
	   void (*dump)(FILE *, rt_head *, void_t, const char *));
/* Release any routes and free the bit */
void rtbit_reset_all(task *, u_int, gw_entry *);
void rtbit_free(task *, u_int);
/* Get a list of active routes */
rt_list *rthlist_active(int, int);
/* Get a list of all routes */
rt_list *rtlist_all(int);
/* Get a list of all routes */
rt_list *rthlist_all(int);
rt_list *rthlist_match(sockaddr_un *, int);
/* Set an announcement bit */
void rtbit_set(rt_entry *, u_int);
/* Reset and announcement bit */
rt_entry *rtbit_reset(rt_entry *, u_int);
/* Reset and announcement bit */
rt_entry *rtbit_reset_pending(rt_entry *, u_int);
void rt_static_init_family(int);
/* Create a table for family */
void rt_table_init_family(int af);
rt_head *rt_table_locate(sockaddr_un *dst, sockaddr_un *mask);
rt_head *rt_table_locate_parent(rt_head *);
void aggregate_dump(FILE *);
#ifndef    EXTENDED_RIBS
#if 	   defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
int rt_parse_route_aspath(sockaddr_un *, sockaddr_un *, adv_entry *,
    adv_entry *, pref_t, flag_t, as_path *, char *);
#define	rt_parse_route(d, m, g, i, p, s, e) \
	rt_parse_route_aspath(d, m, g, i, p, s, (as_path *) 0, e)
#else   /* PROTO_ASPATHS */
int rt_parse_route(sockaddr_un *, sockaddr_un *, adv_entry *, adv_entry *,
    pref_t, flag_t, char *);
#endif	/* PROTO_ASPATHS */

#else /* EXTENDED_RIBS */

#if 	   defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
int rt_parse_route_aspath(sockaddr_un *, sockaddr_un *, adv_entry *,
    adv_entry *, pref_t, flag_t, flag_t, as_path *, char *);
#define	rt_parse_route(d, m, g, i, p, s, r, e) \
	rt_parse_route_aspath(d, m, g, i, p, s, r, (as_path *) 0, e)
#else	/* PROTO_ASPATHS */
int rt_parse_route(sockaddr_un *, sockaddr_un *, adv_entry *, adv_entry *,
    pref_t, flag_t, flag_t, char *);
#endif	/* PROTO_ASPATHS */
#endif /* EXTENDED_RIBS */

#if   defined(PROTO_SNMP) || defined(PROTO_CMU_SNMP)
rt_entry *rt_table_getnext(sockaddr_un *, sockaddr_un *, int,
	   rt_entry * (*job)(rt_head *, void_t), void_t);
rt_entry * rt_table_get(sockaddr_un *,
	   sockaddr_un *, rt_entry * (*job)(rt_head *, void_t), void_t);
#endif	/* PROTO_SNMP */

/* Redirects */
#define	REDIRECT_CONFIG_IN	1
#define	REDIRECT_CONFIG_MAX	2

extern rt_cmp_func *rt_cmp[];			/* Proto comparison functions */
extern trace *redirect_trace_options;		/* Trace flags from parser */
extern int redirect_n_trusted;			/* Number of trusted ICMP gateways */
extern pref_t redirect_preference;		/* Preference for ICMP redirects */
extern gw_entry *redirect_gw_list;		/* List of learned and defined ICMP gateways */
extern adv_entry *redirect_import_list;		/* List of routes that we can import */
extern adv_entry *redirect_int_policy;		/* List of interface policy */
extern gw_entry *redirect_gwp;			/* Gateway pointer for redirect routes */
extern const bits redirect_trace_types[];	/* Redirect specific trace types */
void redirect(sockaddr_un *, sockaddr_un *, sockaddr_un *, sockaddr_un *);	       	/* Process a redirect */
void redirect_init(void);
void redirect_var_init(void);
void redirect_disable(proto_t);
void redirect_enable(proto_t);
void redirect_delete_router(rt_list *);
u_long rt_table_nodes(int);
u_long rt_table_routes(int);
