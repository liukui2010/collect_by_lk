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




#define	INCLUDE_RT_VAR

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
#ifdef PROTO_DVMRP_ROUTING
#include "dvmrp_routing/dvmrp_routing.h"
#endif /* PROTO_DVMRP_ROUTING */
#include "krt/krt.h"

rt_cmp_func *rt_cmp[RTPROTO_MAX];

static const bits rt_change_bits[] =
{
    { RTCF_NEXTHOP,	"NextHop" },
    { RTCF_METRIC,	"Metric" },
    { RTCF_TAG,		"Tag" },
    { RTCF_ASPATH,	"ASPath" },
    {0}
};

const bits rt_state_bits[] =
{
    {RTS_REMOTE,		"Remote"},
    {RTS_NOTINSTALL,		"NotInstall"},
    {RTS_NOADVISE,		"NoAdvise"},
    {RTS_INTERIOR,		"Int"},
    {RTS_EXTERIOR,		"Ext"},
    {RTS_DELETE,		"Delete"},
    {RTS_HIDDEN,		"Hidden"},
    {RTS_INITIAL,		"Initial"},
    {RTS_RELEASE,		"Release"},
    {RTS_FLASH,			"Flash"},
    {RTS_ONLIST,		"OnList"},
    {RTS_RETAIN,		"Retain"},
    {RTS_GROUP,			"Group"},
    {RTS_GATEWAY,		"Gateway"},
    {RTS_REJECT,		"Reject"},
    {RTS_STATIC,		"Static"},
    {RTS_BLACKHOLE,		"Blackhole"},
    {RTS_IFSUBNETMASK,		"IfSubnetMask"},
    {RTS_MED_CHANGE,		"MEDchange"},
    {RTS_SUPPRESSED,		"Suppressed"},
#ifdef IPSEC
    {RTS_FORCE, 		"Force"},
#endif /* IPSEC */
#ifndef   EXTENDED_RIBS
    {RTS_ACTIVE_UNICAST,	"ActiveU"},
    {RTS_ACTIVE_MULTICAST,   	"ActiveM"},
    {RTS_ELIGIBLE_UNICAST,   	"Unicast"},
    {RTS_ELIGIBLE_MULTICAST, 	"Multicast"},
    {RTS_PENDING_UNICAST,	"PendingU"},
    {RTS_PENDING_MULTICAST,	"PendingM"},
    {RTS_INFERIOR_MED_UNI,	"InferiorMEDU"},
    {RTS_INFERIOR_MED_MULTI,	"InferiorMEDM"},
#endif /* EXTENDED_RIBS */
    {RTS_AGGR,			"Aggr"},
#if (defined(PROTO_BGP) || defined(PROTO_MPBGP)) && defined(GATED_MEMBER)
    {RTS_BGP_AGGR,		"BGPAggr"},
#endif /* defined(PROTO_BGP) || defined(PROTO_MPBGP) */
    {0}
};

const bits rt_proto_bits[] = {
    {RTPROTO_ANY,	"Any" },
    {RTPROTO_DIRECT,	"Direct"},
    {RTPROTO_KERNEL,	"Kernel"},
    {RTPROTO_REDIRECT,	"Redirect"},
    {RTPROTO_DEFAULT,	"Deprecated Protocol"},
    {RTPROTO_OSPF,	"OSPF"},
    {RTPROTO_OSPF_ASE,	"OSPF_ASE"},
    {RTPROTO_INET6,	"INET6"},
    {RTPROTO_NOSPF_ASE,  "NOSPF_ASE"},
    {RTPROTO_RIP,	"RIP"},
    {RTPROTO_BGP,	"BGP"},
    {RTPROTO_EGP,	"EGP"},
    {RTPROTO_STATIC,	"Static"},
    {RTPROTO_SNMP,	"net-mgmt"},
    {RTPROTO_ICMPV6,	"ICMPV6"},
    {RTPROTO_ISIS,	"IS-IS"},
    {RTPROTO_SLSP,	"SLSP"},
    {RTPROTO_RIPNG,	"RIPNG"},
    {RTPROTO_INET,	"INET"},
    {RTPROTO_IGMP,	"IGMP"},
    {RTPROTO_AGGREGATE,	"Aggregate"},
    {RTPROTO_DVMRP,	"DVMRP"},
    {RTPROTO_PIM, 	"PIM"},
    {RTPROTO_RDISC,	"RDISC"},
    {RTPROTO_NOSPF,	"NOSPF"},
    {RTPROTO_CBT, 	"CBT"},
    {RTPROTO_NOSPF_NSSA,"OSPF2_NSSA"},
    {RTPROTO_DVMRP_ROUTING, "DVMRP-routing"},
    {RTPROTO_MROUTE,  "MROUTE"},
    {RTPROTO_BGMP,  "BGMP"},
    {RTPROTO_SMUX,  "net-mgmt"},
    {RTPROTO_MSDP,  "MSDP"},
#ifdef noy_yet
    {RTPROTO_NDP,	"NDP"},
    {RTPROTO_OSPFV6,	"OSPFV6"},
    {RTPROTO_OSPFV6_ASE,"OSPFV6_ASE"},
    {RTPROTO_PIMV6,	"PIMV6"},
#endif
    {0}
};

task *rt_task = (task *) 0;

struct rtaf_info rtaf_info[AF_MAX] = { { 0 } };

static task *rt_opentask = (task *) 0;	/* Protocol that has table open */
static task_job *rt_flash_job = (task_job *) 0;

static block_t rt_block_index = (block_t) 0;		/* Block allocation index for an rt_entry */
static block_t rth_block_index = (block_t) 0;
block_t  rtchange_block_index = (block_t) 0;

#define	rt_check_open(p, name)	assert(rt_opentask)

#define RT_ELIGIBLE_RIBS(rt) \
	do { \
            register int ribi; \
            for (ribi=0; ribi<NUMRIBS; ribi++) { \
                if ( ! RT_TEST_ELIGIBLE(rt, ribi) ) \
                    continue; 

#define RT_ELIGIBLE_RIBS_END(rt) \
            } \
        } while(0)
        
#define RT_ACTIVE_RIBS(rt) \
	do { \
            register int ribi; \
            for (ribi=0; ribi<NUMRIBS; ribi++) { \
                if ( ! RT_TEST_ACTIVE(rt, ribi) ) \
                    continue; 

#define RT_ACTIVE_RIBS_END(rt) \
            } \
        } while(0)
/**/
/* Byte allocation table */
rtbit_info      rtbit_map[RTBIT_NBITS];
typedef u_short	rtbit_type;
/* Bit allocation map */
static rtbit_type rttsi_map[RTBIT_NBITS * MAX(sizeof(u_long), sizeof(u_long *))/RTTSI_SIZE];

static block_t rttsi_block_index;

/* Allocate a tsi field */
static void
rttsi_alloc(rtbit_info *ip)
{
    u_int i;
    rtbit_type mask0 = 0;

    /* Verify that the map size is the same as tsi blocks */
    assert(sizeof (rtbit_type) * NBBY == RTTSI_SIZE);

    /* Generate the mask we are looking for */
    for (i = 1; i <= ip->rtb_length; i++) {
	mask0 |= 1 << (RTTSI_SIZE - i);
    }

    /* Find a place where the mask fits */
    /* This will not find a mask that crosses an 8 byte boundry */
    for (i = 0; i < sizeof (rttsi_map) / sizeof (rtbit_type); i++) {
	rtbit_type mask = mask0;

	ip->rtb_index = i * RTTSI_SIZE;

	do {
	    if (!(rttsi_map[i] & mask)) {
		rttsi_map[i] |= mask;
		return;
	    }
	    ip->rtb_index++;
	} while (!(mask & 1) && (mask >>= 1));
    }

    assert(FALSE);	/* No bits available */
}

/* Get the tsi for a route */
void
rttsi_get(rt_head *rth, u_int bit, u_char *value)
{
	register rtbit_info *ip = &rtbit_map[bit-1];
	register u_int block = ip->rtb_index / RTTSI_SIZE;
	register rt_tsi *tsi = rth->rth_tsi;
	register int i = ip->rtb_length;

	while (tsi && block--) {
		tsi = tsi->tsi_next;
	}
	if (tsi) {
		byte *cp = &tsi->tsi_tsi[ip->rtb_index % RTTSI_SIZE];

		while (i--) {
			*value++ = *cp++;
		}
	} else {
		while (i--) {
			*value++ = (char) 0;
		}
	}
}


/* Set the tsi for a route */
void
rttsi_set(rt_head *rth, u_int bit, u_char *value)
{
    register rtbit_info *ip = &rtbit_map[bit-1];
    register u_int block = ip->rtb_index / RTTSI_SIZE;
    register rt_tsi *tsi = rth->rth_tsi;
    register int i = ip->rtb_length;
    register byte *cp;

    if (!tsi) {
	rth->rth_tsi = (rt_tsi *) task_block_alloc(rttsi_block_index);
	tsi = rth->rth_tsi;
    }
    while (block--) {
	if (!tsi->tsi_next) {
	    tsi->tsi_next = (rt_tsi *) task_block_alloc(rttsi_block_index);
	}
	tsi = tsi->tsi_next;
    }
    cp = &tsi->tsi_tsi[ip->rtb_index % RTTSI_SIZE];
    while (i--) {
	*cp++ = *value++;
    }
}


/* Reset the tsi for a route */
void
rttsi_reset(rt_head *rth, u_int bit)
{
	register rtbit_info *ip = &rtbit_map[bit-1];
	register u_int block = ip->rtb_index / RTTSI_SIZE;
	register rt_tsi *tsi = rth->rth_tsi;
	register int i = ip->rtb_length;
	register byte *cp;

	if (!tsi) {
		return;
	}
	while (block--) {
		if (!tsi->tsi_next) {
			return;
		}
		tsi = tsi->tsi_next;
	}
	cp = &tsi->tsi_tsi[ip->rtb_index % RTTSI_SIZE];
	while (i--) {
		*cp++ = (byte) 0;
	}
}


/* Free the TSI field */
static void
rttsi_release(rt_head *release_rth)
{
    register rt_tsi *tsi = release_rth->rth_tsi;

    while (tsi) {
	register rt_tsi *otsi = tsi;

	tsi = tsi->tsi_next;

	task_block_free(rttsi_block_index, (void_t) otsi);
    }
}


static void
rttsi_free(rtbit_info *ip)
{
    u_int i;
    rtbit_type mask = 0;

    for (i = 1; i <= ip->rtb_length; i++) {
	mask |= 1 << (RTTSI_SIZE - i);
    }

    rttsi_map[ip->rtb_index / RTTSI_SIZE] &= ~(mask >> (ip->rtb_index % RTTSI_SIZE));

    ip->rtb_index = ip->rtb_length = 0;
}


static void
rttsi_dump(FILE *fp, rt_head *rth)
{
    u_int bit;

    (void) fprintf(fp,
		   "\t\t\tTSI:\n");

    for (bit = 1; bit <= RTBIT_NBITS; bit++) {
	if (rtbit_map[bit-1].rtb_dump) {
	    rtbit_map[bit-1].rtb_dump(fp, rth, rtbit_map[bit-1].rtb_data, "\t\t\t\t");
	}
    }
}



/**/
/*
 *	Remove an rt_head pointer.
 */
int
rth_remove(rt_head *remove_rth)
{
    /* Don't free if more rt_entries, histories, or on a list */
    if (remove_rth->rth_entries 
#ifdef PROTO_WRD
	    || remove_rth->rth_hists
#endif /* PROTO_WRD */
            || BIT_TEST(remove_rth->rth_state, RTS_ONLIST)) {
        return 0;
    }

#ifdef DVMRP_ROUTING
    /* Make sure dvmrp_routing is playing by the rules */
    if (remove_rth->rth1_info)
        dvmrp_free_dep_info_list(remove_rth);
#endif /* DVMRP_ROUTING */

    rt_table_delete(remove_rth);

    /* Count this rt_head */
    rtaf_info[socktype(remove_rth->rth_dest)].rtaf_dests--;

    sockfree(remove_rth->rth_dest);

    rttsi_release(remove_rth);

    task_block_free(rth_block_index, (void_t) remove_rth);
    return 1;
}


/*
 *	Locate the rt_head pointer for this destination.  Create one if it does not exist.
 */
static rt_head *
rth_locate(sockaddr_un *locate_dst, sockaddr_un *locate_mask,
    flag_t *locate_state, const char **locate_errmsg)
{
    rt_head *locate_rth = (rt_head *) 0;

    *locate_errmsg = (char *) 0;

    if (BIT_TEST(*locate_state, RTS_GROUP)) {
	assert(!locate_mask);
    } else {
	if (!locate_mask) {
	    *locate_errmsg = "mask not specified";
	    return (rt_head *) 0;
	}
	/* Locate proper mask */
	locate_mask = mask_locate(locate_mask);
    }

    /* Locate this entry in the table */
    locate_rth = rt_table_locate(locate_dst, locate_mask);
    if (locate_rth) {
	/* Existing route */

	if (locate_rth->rth_dest_mask != locate_mask) {
	    *locate_errmsg = "mask conflict";
	    return (rt_head *) 0;
	}
    } else {
	/* New route */
	
	locate_rth = (rt_head *) task_block_alloc(rth_block_index);

	/* Copy destination */
	locate_rth->rth_dest = sockdup(locate_dst);

	/* Clean up the address */
	sockclean(locate_rth->rth_dest);
	
	/* Set the mask */
	if (locate_mask) {
	    locate_rth->rth_dest_mask = locate_mask;
	}

	/* Count this rt_head */
	rtaf_info[socktype(locate_rth->rth_dest)].rtaf_dests++;

	if (BIT_TEST(*locate_state, RTS_GROUP)) {
	    BIT_SET(locate_rth->rth_state, RTS_GROUP);
	} else {
	    switch (socktype(locate_dst)) {
#ifdef	PROTO_INET
	    case AF_INET:
		if (sock2host(locate_rth->rth_dest, locate_rth->rth_dest_mask)) {
		    *locate_errmsg = "host bits not zero";
		    goto Return;
		}
		break;
#endif	/* PROTO_INET */
	    }
	}

	locate_rth->rt_forw = locate_rth->rt_back = (rt_entry *) &locate_rth->rt_forw;
	locate_rth->rt_head = locate_rth;

	/* Add this entry to the table */
	rt_table_add(locate_rth);

    Return:
	if (*locate_errmsg) {
	    if (locate_rth->rth_dest) {
		sockfree(locate_rth->rth_dest);
	    }
	    task_block_free(rth_block_index, (void_t) locate_rth);
	    locate_rth = (rt_head *) 0;
	}
    }

    return locate_rth;
}


/**/
static INLINE void
rtchanges_free (flag_t ribs, rt_head *rth)
{
    rt_changes *rtc, **rtcp;

    /* Look for change entry for given rib(s), if any */
    for (rtcp = &rth->rth_changes; 
	 (rtc = *rtcp) != NULL; 
         rtcp = &rtc->rtc_next) {
        if (rtc->rtc_ribs & ribs) {
	    break;
	}
    }
    if (!rtc) {
	return;
    }

    *rtcp = rtc->rtc_next; /* Unlink change block for specified rt_entry */
    
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
    if (BIT_TEST(rtc->rtc_flags, RTCF_ASPATH) &&
	rtc->rtc_aspath) {
	aspath_unlink(rtc->rtc_aspath);
    }
#endif	/* PROTO_ASPATHS */

    if (BIT_TEST(rtc->rtc_flags, RTCF_NEXTHOP)) {
	int i = rtc->rtc_n_gw;

	/* Free the routers */
	while (i--) {
	    if (rtc->rtc_routers[i]) {
		sockfree(rtc->rtc_routers[i]);
		IFA_FREE(rtc->rtc_ifaps[i]);
	    }
	}
    }

    task_block_free(rtchange_block_index, (void_t) rtc);

}


static INLINE rt_changes *
rtchanges_assert (rt_entry *rt)
{
    rt_changes *rtc;

    /* Look for change entry for given rt_entry, if any */
    for (rtc = rt->rt_head->rth_changes; rtc != NULL; rtc = rtc->rtc_next) {
        if (rtc->rtc_ribs & RT_GET_ACTIVE(rt)) {
	    return rtc;
	}
    }
    if (rt->rt_n_bitsset == 0) {
	return NULL;	/* Nobody is interested in changes */
    }
    rtc = (rt_changes *) task_block_alloc(rtchange_block_index);
    rtc->rtc_ribs = RT_GET_ACTIVE(rt);
    rtc->rtc_next = rt->rt_head->rth_changes;
    rt->rt_head->rth_changes = rtc;
    return rtc;
}
    


/**/


/* Free a route */
static rt_entry *
rt_free(rt_entry *free_rt)
{
	register int free_i;
	register rt_head *free_rth = free_rt->rt_head;
	rt_entry *prev_rt = free_rt->rt_back;

	if (!free_rt)
		return free_rt;

#ifdef PROTO_WRD
	assert (!free_rt->rt_hist);
#endif /* PROTO_WRD */

#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
	/* Free the AS path.  Do it before freeing anything else */
	if (free_rt->rt_aspath) {
		aspath_rt_free(free_rt);
	}
#endif	/* PROTO_ASPATHS */

	if (free_rth) {
		RT_ACTIVE_RIBS(free_rt) {
			if (free_rt == free_rth->rth_rib_last_active[ribi]) {
				/* This is the last active route reset it */
				free_rth->rth_rib_last_active[ribi] = (rt_entry *) 0;

				if (free_rth->rth_changes) { 
					/* Clean up rt_change block */
					rtchanges_free(ACTIVE_BIT(ribi), free_rth);
				}
			}
		} RT_ACTIVE_RIBS_END(free_rt);
		if (rth_remove(free_rth)) {
			prev_rt = (rt_entry *) 0;
		}
	}

#ifdef	PROTO_SNMP
	/* Make sure the SNMP code does not have a cached pointer to this route */
	rt_mib_free_rt(free_rt);
#endif	/* PROTO_SNMP */

	/* Release any route specific data, remove the route from the change */
	/* and free this route */
	if (free_rt->rt_data && free_rt->rt_gwp->gw_rtd_free) {
		free_rt->rt_gwp->gw_rtd_free(free_rt, free_rt->rt_data);
	}

	for (free_i = 0; free_i < free_rt->rt_n_gw; free_i++) {
		sockfree(free_rt->rt_routers[free_i]);
		IFA_FREE(free_rt->rt_ifaps[free_i]);
	}

	/* And finally free the block */
	task_block_free(rt_block_index, (void_t) free_rt);

	free_rt = prev_rt;

	return free_rt;
}

/**/
/* Routing table state machine support routines */

/*
 * rt_trace() traces changes to the routing tables
 */
static void
rt_trace(task *tp, rt_entry *t_rt, const char *action)
{
    /* XXX - Need indication of active and holddown */
    
    tracef("%-8s %-15A ",
	   action,
	   t_rt->rt_dest);
    if (t_rt->rt_dest_mask) {
	tracef(" %-15A ",
	       t_rt->rt_dest_mask);
    }

    switch (t_rt->rt_n_gw) {
	register int i;

    case 0:
	break;

    case 1:
	tracef("gw %-15A",
	       RT_ROUTER(t_rt));
	break;

    default:
	tracef("gw");
	for (i 	= 0; i < t_rt->rt_n_gw; i++) {
	    tracef("%c%A",
		   i ? ',' : ' ',
		   t_rt->rt_routers[i]);
	}

	break;
    }

    tracef(" %-8s pref %d/%d metric %d/%d",
	   trace_state(rt_proto_bits, t_rt->rt_gwp->gw_proto),
	   t_rt->rt_preference,
	   t_rt->rt_preference2,
	   t_rt->rt_metric,
	   t_rt->rt_metric2);

    switch (t_rt->rt_n_gw) {
	register int i;

    case 0:
	break;

    default:
	for (i = 0; i < t_rt->rt_n_gw; i++) {
	    if (t_rt->rt_ifaps[i]) {
		tracef("%c%s",
		       i ? ',' : ' ',
		       t_rt->rt_ifaps[i]->ifa_link->ifl_name);
	    }
	}
	break;
    }

    tracef(" <%s>",
	   trace_bits(rt_state_bits, t_rt->rt_state));
    if (t_rt->rt_gwp->gw_peer_as) {
	tracef("  as %d",
	       t_rt->rt_gwp->gw_peer_as);
    }	

    /* XXX - Format protocol specific information? */

    trace_only_tp(tp,
		  TRC_NOSTAMP,
		  (NULL));
}

static RTBIT_MASK(rt_holddown_bits);	/* Bits that belong to holddown protocols */

static const char *log_change = "CHANGE";
static const char *log_release = "RELEASE";

#define	rt_set_delete(rt)  \
    do { \
	BIT_SET((rt)->rt_state, RTS_DELETE); \
	rtaf_info[socktype((rt)->rt_dest)].rtaf_deletes++; \
    } while (0)
#define	rt_reset_delete(rt) \
    do { \
	BIT_RESET((rt)->rt_state, RTS_DELETE); \
	rtaf_info[socktype((rt)->rt_dest)].rtaf_deletes--; \
    } while (0)

#define	rt_set_release(rt)	BIT_SET((rt)->rt_state, RTS_RELEASE)

#define	rt_set_holddown(rt, ribi) \
    do { \
	if (!(rt)->rt_rib_holddown[ribi]) { \
	    (rt)->rt_rib_holddown[ribi] = (rt); \
	    rtaf_info[socktype((rt)->rt_dest)].rtaf_holddowns++; \
	} \
    } while (0)
#define	rt_reset_holddown(rt, ribi) \
    do { \
	if ((rt)->rt_rib_holddown[ribi] == (rt)) { \
	    (rt)->rt_rib_holddown[ribi] = (rt_entry *) 0; \
	    rtaf_info[socktype((rt)->rt_dest)].rtaf_holddowns--; \
	} \
    } while (0)

#ifndef   EXTENDED_RIBS

#define	rth_set_pending(rth, ribi) \
    do { \
	BIT_SET((rth)->rth_state, rib[ribi].pending); \
    } while (0)
#define	rth_reset_pending(rth, ribi) \
    do { \
	BIT_RESET((rth)->rth_state, rib[ribi].pending); \
    } while (0)
#define	rt_set_pending(rt, ribi) \
    do { \
	BIT_SET((rt)->rt_state, rib[ribi].pending); \
    } while (0)
#define	rt_reset_pending(rt, ribi) \
    do { \
	BIT_RESET((rt)->rt_state, rib[ribi].pending); \
    } while (0)
#define	rt_set_active(rt, ribi) \
    do { \
	BIT_SET((rt)->rt_state, rib[ribi].active); \
	(rt)->rt_rib_active[ribi] = rt; \
	rtaf_info[socktype((rt)->rt_dest)].rtaf_actives++; \
    } while (0)
#define	rt_reset_active(rt, ribi) \
    do { \
	BIT_RESET((rt)->rt_state, rib[ribi].active|rib[ribi].pending); \
	(rt)->rt_rib_active[ribi] = (rt_entry *) 0; \
	rtaf_info[socktype((rt)->rt_dest)].rtaf_actives--; \
    } while (0)

#else  /* EXTENDED_RIBS */ 

#define	rth_set_pending(rth, ribi) \
    do { \
	BIT_SET((rth)->rth_pending_ribs, RTRIB_BIT(ribi)); \
    } while (0)
#define	rth_reset_pending(rth, ribi) \
    do { \
	BIT_RESET((rth)->rth_pending_ribs, RTRIB_BIT(ribi)); \
    } while (0)
#define	rt_set_pending(rt, ribi) \
    do { \
	BIT_SET((rt)->rt_pending_ribs, RTRIB_BIT(ribi)); \
    } while (0)
#define	rt_reset_pending(rt, ribi) \
    do { \
	BIT_RESET((rt)->rt_pending_ribs, RTRIB_BIT(ribi)); \
    } while (0)
#define	rt_set_active(rt, ribi) \
    do { \
	BIT_SET((rt)->rt_active_ribs, RTRIB_BIT(ribi)); \
	(rt)->rt_rib_active[ribi] = rt; \
	rtaf_info[socktype((rt)->rt_dest)].rtaf_actives++; \
    } while (0)
#define	rt_reset_active(rt, ribi) \
    do { \
	BIT_RESET((rt)->rt_active_ribs, RTRIB_BIT(ribi)); \
	BIT_RESET((rt)->rt_pending_ribs, RTRIB_BIT(ribi)); \
	(rt)->rt_rib_active[ribi] = (rt_entry *) 0; \
	rtaf_info[socktype((rt)->rt_dest)].rtaf_actives--; \
    } while (0)

#endif  /* EXTENDED_RIBS */

#define	rt_set_hidden(rt) \
    do { \
	BIT_SET((rt)->rt_state, RTS_HIDDEN); \
	rtaf_info[socktype((rt)->rt_dest)].rtaf_hiddens++; \
    } while (0)
#define	rt_reset_hidden(rt) \
    do { \
	BIT_RESET((rt)->rt_state, RTS_HIDDEN); \
	rtaf_info[socktype((rt)->rt_dest)].rtaf_hiddens--; \
    } while (0)

#ifdef PROTO_WRD
#define	rt_set_suppressed(rt) \
    do { \
	BIT_SET((rt)->rt_state, RTS_SUPPRESSED); \
    } while (0)
#define	rt_reset_suppressed(rt) \
    do { \
	BIT_RESET((rt)->rt_state, RTS_SUPPRESSED); \
    } while (0)
#endif

#define	rt_error(trp, name) \
    do { \
	trace_log_tp(trp, 0, LOG_ERR, ("rt_event_%s: fatal state error", name)); \
	task_quit(EINVAL); \
    } while (0)
#define	rt_set_flash(rt) \
    BIT_SET((rt)->rt_head->rth_state, RTS_FLASH)
#define	rt_reset_flash(rt) \
    BIT_RESET((rt)->rt_head->rth_state, RTS_FLASH)
#define	rt_assert_noflash() \
    assert(!BIT_TEST(task_state, TASKS_FLASH|TASKS_NEWPOLICY))
#define	rt_set_onlist(rt) \
    BIT_SET((rt)->rt_head->rth_state, RTS_ONLIST); RTLIST_ADD(rt_change_list, (rt)->rt_head)

#ifndef   EXTENDED_RIBS
rib_t rib[NUMRIBS] = {
 { "unicast",   RTS_ACTIVE_UNICAST  , 
   RTS_ELIGIBLE_UNICAST, ADVF_RIB_UNICAST, RTS_PENDING_UNICAST, RTS_INFERIOR_MED_UNI }
#ifdef    IP_MULTICAST_ROUTING
,{ "multicast", RTS_ACTIVE_MULTICAST, 
   RTS_ELIGIBLE_MULTICAST, ADVF_RIB_MULTICAST, RTS_PENDING_MULTICAST, RTS_INFERIOR_MED_MULTI }
#endif /* IP_MULTICAST_ROUTING */
};
#else  /* EXTENDED_RIBS */
char* rib_names[32] = { "unicast", "multicast", 
                        "r2",  "r3",  "r4",  "r5",  "r6",  "r7",  "r8",  "r9",
                        "r10", "r11", "r12", "r13", "r14", "r15", "r16", "r17",
                        "r18", "r19", "r20", "r21", "r22", "r23", "r24", "r25",
                        "r26", "r27", "r28", "r29", "r30", "r31" };
#endif /* EXTENDED_RIBS */

/* Select the active route and return a pointer to it or a NULL pointer */

static rt_entry *
rt_select_active(rt_head *rth, int ribi)
{
    register rt_entry *rt = rth->rt_forw;
	
    /* Skip routes which are not eligible for this RIB */
		while ( (rt != (rt_entry *) &rth->rt_forw) &&
						(!RT_TEST_ELIGIBLE(rt, ribi)))
				rt=rt->rt_forw;
	
		if (rt == (rt_entry *) &rth->rt_forw) {
					/* No routes to become active */
					return (rt_entry *) 0;
		}

		if (BIT_TEST(rt->rt_state, RTS_DELETE|RTS_RELEASE|RTS_HIDDEN|RTS_SUPPRESSED)) {
				/*
				* This route is scheduled for delete, release or is hidden.
				* Could also be suppressed by damping code
				*/
					return (rt_entry *) 0;
		}

    /* If this candidate for the active route is from a holddown */
    /* protocol, and the old active route is being announced by a */
    /* holddown protocol, set the RTS_PENDING_* flag to prevent this */
    /* route from being announced until the formerly active route */
    /* leaves holddown.  This does not prevent this route from */
    /* becoming active or being installed in the forwarding table, */
    /* it only prevents it from being announced to other protocols */
    /* because of the chance that it is an echo of an announced route.  */

    if (BIT_TEST(rt->rt_gwp->gw_flags, GWF_NEEDHOLD)
	&& rth->rth_n_announce) {
	register rt_entry *old_rt;

	RT_ALLRT(old_rt, rth) {
	    if (old_rt != rt
		&& old_rt->rt_n_bitsset) {
#if	RTBIT_SIZE > 1
		register int i = RTBIT_SIZE;

		while (i--) {
		    if (BIT_TEST(rt_holddown_bits[i], old_rt->rt_bits[i])) {
			rt_set_pending(rt, ribi);
			return rt;
		    }
		}
#else	/* RTBIT_SIZE > 1 */
		if (BIT_TEST(*rt_holddown_bits, *old_rt->rt_bits)) {
		    rt_set_pending(rt, ribi);
		    return rt;
		}
#endif	/* RTBIT_SIZE > 1 */
	    }
	} RT_ALLRT_END(old_rt, rth) ;
    }

    return rt;
}


/*
 *	Remove an rt_entry structure from the doubly linked list
 *	pointed to by it's rt_head
 */

static void
rt_remove(rt_entry *remove_rt)
{
    if (!--remove_rt->rt_head->rth_entries) {
	rtaf_info[socktype(remove_rt->rt_dest)].rtaf_routes--;
    }
    REMQUE(remove_rt);
}


/*	Insert an rt_entry structure in preference order in the doubly linked	*/
/*	list pointed to by it's rt_head.  If two routes with identical		*/
/*	preference are found, the one witht he shorter as path length is used.	*/
/*	If the as path lengths are the same, the route with the lower next-hop	*/
/*	IP address is prefered. This insures that the selection of the prefered	*/
/*	route is deterministic.							*/
static void
rt_insert(rt_entry *insert_rt)
{
	rt_entry *insert_rt1;
	rt_head *insert_rth = insert_rt->rt_head;

	/*
	 * Sort usable routes before hidden routes, which are sorted before
	 * deleted routes.  Deleted and hidden routes are attached at the
	 * end of their respective lists, usable routes are sorted into
	 * preference order.
	 *
	 * If this is a delete, just hook it to the end and return.  If this
	 * is a hidden route search the list from the end to find the spot
	 * to insert it.
	 */
	if (BIT_TEST(insert_rt->rt_state,
	    (RTS_DELETE|RTS_HIDDEN|RTS_SUPPRESSED))) {
		if (BIT_TEST(insert_rt->rt_state, RTS_DELETE)) {
			/* Insert delete routes at the end of the list */
	    
			INSQUE(insert_rt, insert_rth->rt_back);
		} else {
			/* Insert hidden and suppressed routes before last
			 * deleted or suppressed route.  This will give order:
			 * normal, hidden, suppressed, delete.
			 */
	    
			RT_ALLRT_REV(insert_rt1, insert_rth) {
				if (!BIT_TEST(insert_rt1->rt_state,
				    RTS_DELETE|RTS_SUPPRESSED)) {
					break;
				}
			} RT_ALLRT_REV_END(insert_rt1, insert_rth);

			INSQUE(insert_rt, insert_rt1 ? insert_rt1 :
			    (rt_entry *) &insert_rth->rt_forw);
		}
	} else {
		/* Neither deleted, hidden or suppressed; do the check the */
		/* long way */

		RT_ALLRT(insert_rt1, insert_rth) {
			if (BIT_TEST(insert_rt1->rt_state,
			    (RTS_DELETE|RTS_HIDDEN|RTS_SUPPRESSED))) {
				break;
			}
			if (insert_rt->rt_preference <
			    insert_rt1->rt_preference) {
				/* This preference is better */

				break;
			} else if (insert_rt->rt_preference ==
			    insert_rt1->rt_preference) {
				int prefer_which;

				/*
				 * Break ties with the second preference if
				 * they differ.
				 */
				if (insert_rt->rt_preference2 <
				    insert_rt1->rt_preference2) {
					break;
				}
				if (insert_rt->rt_preference2 >
				    insert_rt1->rt_preference2) {
					continue;
				}

				/*
				 * If these two routes are from the same
				 * protocol, and that protocol has specified
				 * a function to use for route comparison,
				 * see if it can tell us who to use...
				 */
				if ((insert_rt->rt_gwp->gw_proto ==
				    insert_rt1->rt_gwp->gw_proto) &&
				    rt_cmp[insert_rt->rt_gwp->gw_proto]) {
					prefer_which =
					    rt_cmp[insert_rt->rt_gwp->gw_proto]
					    (insert_rt, insert_rt1);
					if (prefer_which < 0) {
						/* new route is better */
						break;
					} else if (prefer_which > 0) {
						/* list route is better */
						continue;
					}
					/* Else, they're the same */
				}
 
				/*
				 * Prefer strictly interior routes over
				 * anything.  Prefer strictly exterior routes
				 * over exterior routes received on an interior
				 * session.  I.e. prefer state bits in this
				 * order:
				 *		RTS_INTERIOR
				 *		RTS_EXTERIOR
				 *		RTS_INTERIOR|RTS_EXTERIOR
				 */
				if (!BIT_MASK_MATCH(insert_rt->rt_state,
				    insert_rt1->rt_state,
				    (RTS_INTERIOR|RTS_EXTERIOR))) {
					if (!BIT_TEST(insert_rt->rt_state,
					    RTS_EXTERIOR)) {
						/* new route is better */
						break;		
					}
					if (!BIT_TEST(insert_rt1->rt_state,
					    RTS_EXTERIOR)) {
						/* current route is better */
						continue;
					}
					if (!BIT_TEST(insert_rt->rt_state,
					    RTS_INTERIOR)) {
						/* new route is better */
						break;
					}
					/* current route is better */
					continue;
				}
				if (insert_rt->rt_gwp->gw_proto ==
				    insert_rt1->rt_gwp->gw_proto
				    && insert_rt->rt_gwp->gw_peer_as ==
				    insert_rt1->rt_gwp->gw_peer_as) {
					/* Same protocol and AS */

					if (insert_rt->rt_metric <
					    insert_rt1->rt_metric) {
						/* Use the lower metric */ 
						break;
					}
					if (insert_rt->rt_metric >
					    insert_rt1->rt_metric) {
						/* Current one is better */
						continue;
					}
				}

				/* Default to comparing the router address to */
				/* be deterministic */
				if (!insert_rt->rt_n_gw ||
				    !insert_rt1->rt_n_gw) {
					/* Only one has a next hop */

					if (insert_rt->rt_n_gw) {
						/* This is the one with the */
						/* next hop, use it */

						break;
					}
				} else if (sockaddrcmp2(RT_ROUTER(insert_rt),
				    RT_ROUTER(insert_rt1)) < 0) {
					/* jgsXXX I think this may be wrong --
					 * are we supposed to use the next hop
					 * with the lower address, or the peer
					 * with the lower address?  This uses
					 * next hop.  Peer would be rtp_gwp.
					 */
					/* This is handled correctly in
					 * bgp_sync.c, but is it correct
					 * for other bgp groups?  (See
					 * bgp_sync.c around line 832 or so)
					 */
					/* This router address is lower, use
					 * it
					 */
					break;
				}
			}
		} RT_ALLRT_END(insert_rt1, insert_rth);

		/* Insert prior to element if found, or behind the element at
		 * the end of a list.
		 */
		/* For an empty list this ends up being behind the first
		 * element.
		 */
		INSQUE(insert_rt, insert_rt1 ? insert_rt1->rt_back :
		    insert_rth->rt_back);
	}

	if (!insert_rth->rth_entries++) {
		rtaf_info[socktype(insert_rt->rt_dest)].rtaf_routes++;
	}
}

/* Make a route entry active */
static void
rt_event_active(rt_entry *rt, int log, int ribi)
{
    if (!RT_TEST_ELIGIBLE(rt, ribi))
	rt_error(rt_opentask, "active");
    
    switch (rt->rt_state & RTS_STATEMASK) {

    case RTS_INITIAL:
    case RTS_HIDDEN:
    case RTS_HIDDEN|RTS_DELETE:
    default:
	rt_error(rt_opentask, "active");
	break;
	    
    case 0:
        if ( RT_TEST_ACTIVE(rt, ribi) ) {
	    rt_reset_pending(rt, ribi);
        } else {
	    rt_set_active(rt, ribi);
	    rt_reset_holddown(rt, ribi);
        }
	break;
    }
    
    rt_set_flash(rt);

    if (log && TRACE_TP(rt_opentask, TR_ROUTE)) {
	rt_trace(rt_opentask, rt, log_change);
    }
}


static void
rt_event_inactive(rt_entry *rt, int ribi)
{
    if (!RT_TEST_ELIGIBLE(rt, ribi))
	rt_error(rt_opentask, "inactive");

    switch (rt->rt_state & RTS_STATEMASK) {
	
    case 0: /* RTS_ELIGIBLE_*CAST */
	if ( RT_TEST_ACTIVE(rt, ribi) ) {    
	    rt_reset_active(rt, ribi);
	    if (rt->rt_n_bitsset) {
	        rt_set_holddown(rt, ribi);
	        rt_set_flash(rt);
	    }
	    break;
        }
        /* Fall thru */
    case RTS_HIDDEN:
    case RTS_DELETE:
    case RTS_HIDDEN|RTS_DELETE:
    case RTS_INITIAL:
    default:
	rt_error(rt_opentask, "inactive");
	break;
	    
    }

    if (TRACE_TP(rt_opentask, TR_ROUTE)) {
	rt_trace(rt_opentask, rt, log_change);
    }
}


static void
rt_event_preference(rt_entry *pref_rt, int gateway_changed)
{
    rt_entry *new_active;
    
    switch (pref_rt->rt_state & RTS_STATEMASK) {

    case 0: /* RTS_ELIGIBLE_*CAST | RTS_ACTIVE_*CAST */
	
	rt_remove(pref_rt);
	if (pref_rt->rt_preference >= 0) {
	    rt_insert(pref_rt);
            RT_ELIGIBLE_RIBS(pref_rt) {
                if ( RT_TEST_ACTIVE(pref_rt, ribi) ) {
                    /* RTS_ACTIVE_*CAST */
	            new_active = rt_select_active(pref_rt->rt_head, ribi);
	            if (new_active != pref_rt) {
		        rt_reset_active(pref_rt, ribi);
		        if (pref_rt->rt_n_bitsset) {
		            rt_set_holddown(pref_rt, ribi);
		            rt_set_flash(pref_rt);
		        }
		        if (new_active) {
		            rt_event_active(new_active, TRUE, ribi);
		        }
	            } else if (gateway_changed) {
		        rt_set_flash(pref_rt);
	            }
                } else {  /* RTS_ELIGIBLE_*CAST only */
                    if (rt_select_active(pref_rt->rt_head, ribi) == pref_rt) {
		        if (pref_rt->rt_rib_active[ribi]) {
		            rt_event_inactive(pref_rt->rt_rib_active[ribi], ribi);
		        }
		        rt_event_active(pref_rt, FALSE, ribi);
                    } 
                }
	    } RT_ELIGIBLE_RIBS_END(pref_rt);
	} else {
	    rt_set_hidden(pref_rt);
	    rt_insert(pref_rt);
            RT_ACTIVE_RIBS(pref_rt) {
	        rt_reset_active(pref_rt, ribi);
	        if (pref_rt->rt_n_bitsset) {
		    rt_set_holddown(pref_rt, ribi);
		    rt_set_flash(pref_rt);
	        }
	        if ((new_active = rt_select_active(pref_rt->rt_head, ribi))) {
		    rt_event_active(new_active, TRUE, ribi);
	        }
            } RT_ACTIVE_RIBS_END(pref_rt);
	}
	break;
	    
    case RTS_HIDDEN:
	rt_remove(pref_rt);
	if (pref_rt->rt_preference >= 0) {
	    rt_reset_hidden(pref_rt);
	    rt_insert(pref_rt);
            RT_ELIGIBLE_RIBS(pref_rt) {
	        if (rt_select_active(pref_rt->rt_head, ribi) == pref_rt) {
		    if (pref_rt->rt_rib_active[ribi]) {
		        rt_event_inactive(pref_rt->rt_rib_active[ribi], ribi);
		    }
		    rt_event_active(pref_rt, FALSE, ribi);
                }
	    } RT_ELIGIBLE_RIBS_END(pref_rt);
	} else {
	    rt_insert(pref_rt);
	}
	break;
	    
    case RTS_DELETE:
	rt_reset_delete(pref_rt);
	rt_remove(pref_rt);
	if (pref_rt->rt_preference >= 0) {
	    rt_insert(pref_rt);
            RT_ELIGIBLE_RIBS(pref_rt) {
	        if (rt_select_active(pref_rt->rt_head, ribi) == pref_rt) {
		    if (pref_rt->rt_rib_active[ribi]) {
		        rt_event_inactive(pref_rt->rt_rib_active[ribi], ribi);
		    }
		    rt_event_active(pref_rt, FALSE, ribi);
	        }
	    } RT_ELIGIBLE_RIBS_END(pref_rt);
	} else {
	    rt_set_hidden(pref_rt);
	    rt_insert(pref_rt);
	}
	break;
	
    case RTS_HIDDEN|RTS_DELETE:
	rt_remove(pref_rt);
	rt_reset_delete(pref_rt);
	if (pref_rt->rt_preference >= 0) {
	    rt_reset_hidden(pref_rt);
	    rt_insert(pref_rt);
            RT_ELIGIBLE_RIBS(pref_rt) {
	        if (rt_select_active(pref_rt->rt_head, ribi) == pref_rt) {
		    if (pref_rt->rt_rib_active[ribi]) {
		        rt_event_inactive(pref_rt->rt_rib_active[ribi], ribi);
		    }
		    rt_event_active(pref_rt, FALSE, ribi);
	        }
	    } RT_ELIGIBLE_RIBS_END(pref_rt);
	} else {
	    rt_insert(pref_rt);
	}
	break;
	
    case RTS_INITIAL:
    default:
	rt_error(rt_opentask, "preference");
    }	
    
    if (BIT_COMPARE(pref_rt->rt_head->rth_state, RTS_FLASH|RTS_ONLIST, RTS_FLASH)) {
	rt_assert_noflash();
	rt_set_onlist(pref_rt);
    }
    rt_reset_flash(pref_rt);
    
    if (TRACE_TP(rt_opentask, TR_ROUTE)) {
	rt_trace(rt_opentask, pref_rt, log_change);
    }
}	

/* Declare a route unreachable (for all ribs) */
static void
rt_event_unreachable(rt_entry *rt)
{
    const char *log_type = (const char *) 0;
    rt_entry *new_active;
    
#ifdef PROTO_WRD
    rr_suppress_record_unreach(rt);
#endif /* PROTO_WRD */

    if ( BIT_TEST(rt->rt_state, RTS_INITIAL|RTS_DELETE) )
	rt_error(rt_opentask, "unreachable");
    else {
	rt_remove(rt);

	/* If it was active, unactivate it */
	if ( RT_GET_ACTIVE(rt) ) {
            RT_ACTIVE_RIBS(rt) {
		rt_reset_active(rt, ribi);
	        if (rt->rt_n_bitsset)
   		   rt_set_holddown(rt, ribi);
	    } RT_ACTIVE_RIBS_END(rt);
	    if (rt->rt_n_bitsset) {
		rt_set_flash(rt);
		rt_set_delete(rt);
		rt_insert(rt);
		log_type = log_change;
	    } else {
		rt_set_release(rt);
		log_type = log_release;
	    }

	    /* Select new active routes */
            RT_ELIGIBLE_RIBS(rt) {
		if ((new_active = rt_select_active(rt->rt_head, ribi)))
		    rt_event_active(new_active, TRUE, ribi);
	    } RT_ELIGIBLE_RIBS_END(rt);
	} else {
	    if (rt->rt_n_bitsset) {
		rt_set_delete(rt);
		rt_insert(rt);
		log_type = log_change;
	    } else {
		if ( BIT_TEST(rt->rt_state, RTS_HIDDEN) )
		    rt_reset_hidden(rt);
		rt_set_release(rt);
		log_type = log_release;
	    }
	}
    }
    
    if (BIT_COMPARE(rt->rt_head->rth_state, RTS_FLASH|RTS_ONLIST, RTS_FLASH)) {
	rt_assert_noflash();
	rt_set_onlist(rt);
    }
    rt_reset_flash(rt);
    
    if (log_type && TRACE_TP(rt_opentask, TR_ROUTE)) {
	rt_trace(rt_opentask, rt, log_type);
    }
}	


static void
rt_event_bit_set(rt_entry *rt, u_int bit)
{
    RTBIT_SET(bit, rt->rt_bits);
    
    switch (rt->rt_state & RTS_STATEMASK) {

    case 0: /* RTS_ELIGIBLE_*CAST | RTS_ACTIVE_*CAST */
	if ( RT_GET_ACTIVE(rt) ) {
	    if (!rt->rt_n_bitsset++) {
	        rt->rt_head->rth_n_announce++;
	    }
	    break;
	}
	/* Fall thru */      
    case RTS_INITIAL:
    case RTS_HIDDEN:
    case RTS_DELETE:
    case RTS_HIDDEN|RTS_DELETE:
    default:
       rt_error(rt_opentask, "bit_set");
    }
}


static void
rt_event_bit_reset(rt_entry *rt, u_int bit, int pending)
{
    const char *log_type = (const char *) 0;
    
    RTBIT_CLR(bit, rt->rt_bits);
    
    switch (rt->rt_state & RTS_STATEMASK) {
	   
    default:
    case RTS_INITIAL:
        rt_error(rt_opentask, "bit_reset");
        break;
	   
    case 0: /* RTS_ELIGIBLE_*CAST | RTS_ACTIVE_*CAST */
	if ( RT_GET_ACTIVE(rt) ) {
	    if (!--rt->rt_n_bitsset) {
		rt->rt_head->rth_n_announce--;
	    }
	    break;
	}
	/* Fall thru */   
    case RTS_HIDDEN:
	if (!--rt->rt_n_bitsset) {
	    rt->rt_head->rth_n_announce--;
#ifdef	notdef
	    rt_remove(rt);
	    rt_insert(rt);
#endif	/* notdef */

	    RT_ELIGIBLE_RIBS(rt) {
		rt_reset_holddown(rt, ribi);
		if (rt->rt_rib_active[ribi]
		    && (pending
			|| RT_TEST_PENDING(rt->rt_rib_active[ribi], ribi))) {
		    if (BIT_TEST(task_state, TASKS_NEWPOLICY|TASKS_FLASH)) {
			rth_set_pending(rt->rt_head, ribi);
		    } else {
			rt_event_active(rt->rt_rib_active[ribi], TRUE, ribi);
		    }
		}
	    } RT_ELIGIBLE_RIBS_END(rt);
	}
	break;
	   
    case RTS_DELETE:
	if (!--rt->rt_n_bitsset) {
	    rt->rt_head->rth_n_announce--;
	    rt_set_release(rt);
	    rt_remove(rt);

	    RT_ELIGIBLE_RIBS(rt) {
		rt_reset_holddown(rt, ribi);
		if (rt->rt_rib_active[ribi]
		    && (pending
			|| RT_TEST_PENDING(rt->rt_rib_active[ribi], ribi))) {
		    if (BIT_TEST(task_state, TASKS_NEWPOLICY|TASKS_FLASH)) {
			rth_set_pending(rt->rt_head, ribi);
		    } else {
			rt_event_active(rt->rt_rib_active[ribi], TRUE, ribi);
		    }
		}
	    } RT_ELIGIBLE_RIBS_END(rt);
	    log_type = log_release;
	}
	break;

    case RTS_HIDDEN|RTS_DELETE:
	if (!--rt->rt_n_bitsset) {
	    rt->rt_head->rth_n_announce--;
            rt_reset_hidden(rt);
	    rt_set_release(rt);
	    rt_remove(rt);

	    RT_ELIGIBLE_RIBS(rt) {
		rt_reset_holddown(rt, ribi);
		if (rt->rt_rib_active[ribi]
		    && (pending
			|| RT_TEST_PENDING(rt->rt_rib_active[ribi], ribi))) {
		    if (BIT_TEST(task_state, TASKS_NEWPOLICY|TASKS_FLASH)) {
			rth_set_pending(rt->rt_head, ribi);
		    } else {
			rt_event_active(rt->rt_rib_active[ribi], TRUE, ribi);
		    }
		}
	    } RT_ELIGIBLE_RIBS_END(rt);
	    log_type = log_release;
	}
	break;
    }
    
    if (log_type && TRACE_TP(rt_opentask, TR_ROUTE)) {
	rt_trace(rt_opentask, rt, log_type);
    }

    if (BIT_COMPARE(rt->rt_head->rth_state, RTS_FLASH|RTS_ONLIST, RTS_FLASH) &&
	!BIT_TEST(task_state, TASKS_NEWPOLICY)) {
	rt_set_onlist(rt);
	rt_n_changes++;
    }
    rt_reset_flash(rt);
}


static void
rt_event_initialize(rt_entry *rt)
{
    if (BIT_TEST(rt->rt_state, RTS_INITIAL)) {
			BIT_RESET(rt->rt_state, RTS_INITIAL);
#ifdef PROTO_WRD
			/* Update history and see if suppressed route */
			if (rr_suppress_record_reach(rt)) { 
				rt_set_suppressed(rt); /* Set flag if it is suppressed */
			}
#endif /* PROTO_WRD */
			if (rt->rt_preference >= 0) {
				rt_insert(rt);
				RT_ELIGIBLE_RIBS(rt) {
					rt_entry *new_active = (rt_entry *) 0;
					new_active = rt_select_active(rt->rt_head, ribi);
					if (new_active != rt->rt_rib_active[ribi]) {
						if (rt->rt_rib_active[ribi]) { 
							rt_event_inactive(rt->rt_rib_active[ribi], ribi);
						}
						if (new_active) {
							rt_event_active(new_active, FALSE, ribi);
						}
					}
				} RT_ELIGIBLE_RIBS_END(rt);
			} else {
				rt_set_hidden(rt);
				rt_insert(rt);
			}
    } else {
			rt_error(rt_opentask, "initialize");
    }

    if (BIT_COMPARE(rt->rt_head->rth_state, RTS_FLASH|RTS_ONLIST, RTS_FLASH)) {
			rt_assert_noflash();
			rt_set_onlist(rt);
    }
    rt_reset_flash(rt);
    
    if (TRACE_TP(rt_opentask, TR_ROUTE)) {
			rt_trace(rt_opentask, rt, "ADD");
    }
}


static int
rt_flash_cleanup(rt_list *list)
{
    register rt_head *rth;
    int resched = 0;

    rt_open(rt_task);
    
    RT_LIST(rth, list, rt_head) {
	/* Indicate no longer on list */
	BIT_RESET(rth->rth_state, RTS_ONLIST);

	if (!rth_remove(rth)) { 	/* If head not freed */
            register int ribi;
            for (ribi=0; ribi<NUMRIBS; ribi++) {
		/* Free any rth_changes entry for this rib */
		rtchanges_free(ACTIVE_BIT(ribi), rth);
	        /* Reset last active pointer */
		rth->rth_rib_last_active[ribi] = rth->rth_rib_active[ribi];
                if (RTH_TEST_PENDING(rth, ribi)) {
		    /* Need to reflash a pending route */
		    assert(rth->rth_rib_active[ribi]);
		    rt_event_active(rth->rth_rib_active[ribi], TRUE, ribi);
		    rth_reset_pending(rth, ribi);
		    resched++;
		}
	    }
	}
    } RT_LIST_END(rth, list, rt_head) ;

    rt_close(rt_task, (gw_entry *) 0, resched, NULL);
    
    return resched;
}


/*
 *
 */
void
rt_new_policy(void)
{
    register rt_list *list = rt_change_list;
    register rt_head *rth;
	
    if (list) {
	/* Discard the flash list */
	
	/* Get the root of the list */
	list = list->rtl_root;

	RTLIST_RESET(list);

	rt_change_list = (rt_list *) 0;
    }

    /* Get a full list */
    list = rthlist_all(AF_UNSPEC);

    if (list) {

	/* Update the  protocols */
	if (TRACE_TF(trace_global, TR_ROUTE)) {
	    trace_only_tf(trace_global,
			  TRC_NL_BEFORE,
			  ("rt_new_policy: new policy started with %d entries",
			   list->rtl_count));
	}

	/* Flag the routes as being on the list in case any are deleted */
	RT_LIST(rth, list, rt_head) {
	    BIT_SET(rth->rth_state, RTS_ONLIST);
	} RT_LIST_END(rth, list, rt_head) ;

	/* Recalculate aggregates based on policy */
	rt_aggregate_flash(list, 0);

	/* Let the kernel see everything */
	krt_flash(list);

	/* Now flash the protocols */
	task_newpolicy(list);

	/* Make sure no one changed anything while we were flashing */
	assert(!rt_change_list);

	if (TRACE_TF(trace_global, TR_ROUTE)) {
	    trace_only_tf(trace_global,
			  TRC_NL_AFTER,
			  ("rt_new_policy: new policy ended with %d entries",
			   list->rtl_count));
	}

	if (list->rtl_count
	    && rt_flash_cleanup(list)) {
	    
	    rt_flash_job = task_job_create(rt_task,
					   TASK_JOB_PRIO_FLASH,
					   "flash_update",
					   rt_flash_update,
					   (void_t) 0);
	}

	/* And reset this list */
	RTLIST_RESET(list);
    }
}


/*
 * Cause a flash update to happen
 */
void
rt_flash_update(task_job *jp)
{
    int delete = TRUE;

    rt_list *list = rt_change_list;
    
    if (list) {
	/* Get the root of the list */
	list = list->rtl_root;

	/* Run aggregation policy */
	rt_aggregate_flash(list, 0);

	/* Reset the change list */
	rt_change_list = (rt_list *) 0;
	
	/* Update the kernel */
	if (TRACE_TF(trace_global, TR_ROUTE)) {
	    trace_only_tf(trace_global,
			  TRC_NL_BEFORE,
			  ("rt_flash_update: updating kernel with %d entries",
			   list->rtl_count));
	}
	krt_flash(list);

	if (!BIT_TEST(task_state, TASKS_TERMINATE)) {
	    /* Update the protocols */

	    if (TRACE_TF(trace_global, TR_ROUTE)) {
		trace_only_tf(trace_global,
			      TRC_NL_BEFORE,
			      ("rt_flash_update: flash update started with %d entries",
			       list->rtl_count));
	    }

	    task_flash(list);

	    if (TRACE_TF(trace_global, TR_ROUTE)) {
		trace_only_tf(trace_global,
			      TRC_NL_AFTER,
			      ("rt_flash_update: flash update ended with %d entries",
			       list->rtl_count));
	    }
	}

	/* Make sure no one changed anything while we were flashing */
	assert(!rt_change_list);

	if (list->rtl_count
	    && rt_flash_cleanup(list)) {
	    delete = FALSE;
	}
		    
	/* And reset this list */
	RTLIST_RESET(list);
    }

    if (jp && delete) {
	task_job_delete(jp);
	rt_flash_job = (task_job *) 0;
    }
}


/**/
/* Allocate a bit for the protocol specific bit in the routing table */
u_int
rtbit_alloc(task *tp, int holddown, u_int size, void_t data,
    void (*dump)(FILE *, rt_head *, void_t, const char *))
{
	u_int bit;
	rtbit_info *ip = rtbit_map;

	for (bit = 1; bit <= RTBIT_NBITS; ip++, bit++) {
		if (!ip->rtb_task) {
			break;
		}
	}

	assert(bit <= RTBIT_NBITS);

	/* Indicate this bit has been allocated */
	ip->rtb_task = tp;
	ip->rtb_data = data;
	ip->rtb_dump = dump;

	if (size) {
		ip->rtb_length = size;
		rttsi_alloc(ip);
	}

	/* If this protocol does holddowns we must remember it's bits */
	if (holddown) {
		RTBIT_SET(bit, rt_holddown_bits);
	}
	return bit;
}

/* Free an allocated bit */
void
rtbit_free(task *tp, u_int bit)
{
    register rtbit_info *ip = &rtbit_map[bit-1];

    assert(ip->rtb_task == tp);

    ip->rtb_task = (task *) 0;
    ip->rtb_data = (void_t) 0;
    ip->rtb_dump = 0;

    /* Indicate that this bit no longer does holddowns */
    RTBIT_CLR(bit, rt_holddown_bits);
    
    if (ip->rtb_length) {
	rttsi_free(ip);
    }
}


/* Set the announcement bit for this network */
void
rtbit_set(rt_entry *set_rt, u_int set_bit)
{
    rt_check_open(set_rt->rt_gwp->gw_proto, "rtbit_set");

    if (!RTBIT_ISSET(set_bit, set_rt->rt_bits)) {
	rt_event_bit_set(set_rt, set_bit);
    }

#ifdef	RT_SANITY
    rt_sanity();
#endif	/* RT_SANITY */
    return;
}


/* Reset the announcement bit for this network */
rt_entry *
rtbit_reset(rt_entry *reset_rt, u_int reset_bit)
{
    rt_check_open(reset_rt->rt_gwp->gw_proto, "rtbit_reset");

    if (RTBIT_ISSET(reset_bit, reset_rt->rt_bits)) {
	rt_event_bit_reset(reset_rt, reset_bit, FALSE);

	if (BIT_TEST(reset_rt->rt_state, RTS_RELEASE)) {
	    reset_rt = rt_free(reset_rt);
	}
    }
    
#ifdef	RT_SANITY
    rt_sanity();
#endif	/* RT_SANITY */
    return reset_rt;
}


/* Reset announcment bit and cause the active route to be put on a new */
/* list */
rt_entry *
rtbit_reset_pending(rt_entry *reset_rt, u_int reset_bit)
{
    rt_check_open(reset_rt->rt_gwp->gw_proto, "rtbit_reset_pending");

    if (RTBIT_ISSET(reset_bit, reset_rt->rt_bits)) {
	rt_event_bit_reset(reset_rt, reset_bit, TRUE);

	if (BIT_TEST(reset_rt->rt_state, RTS_RELEASE)) {
	    reset_rt = rt_free(reset_rt);
	}
    }
    
#ifdef	RT_SANITY
    rt_sanity();
#endif	/* RT_SANITY */
    return reset_rt;
}


/* Reset the bits on all routes and free the bit */
void
rtbit_reset_all(task *tp, u_int bit, gw_entry *gwp)
{
    int changes = 0;
    register rt_entry *rt;
    register rt_list *rtl = rtlist_all(AF_UNSPEC);
    
    rt_open(tp);

    RT_LIST(rt, rtl, rt_entry) {
	if (rtbit_isset(rt, bit)) {
	    changes++;

	    /* Clear the TSI field */
	    rttsi_reset(rt->rt_head, bit);

	    /* Reset this bit */
	    (void) rtbit_reset(rt, bit);
	}
    } RT_LIST_END(rt, rtl, rt_entry);

    RTLIST_RESET(rtl) ;
    
    rt_close(tp, gwp, changes, NULL);
    
    rtbit_free(tp, bit);
}


static void
rtbit_dump(FILE *fd)
{
    u_int bit;
    rtbit_info *ip = rtbit_map;

    (void) fprintf(fd,
		   "\tBit allocations:\n");

    for (bit = 1; bit <= RTBIT_NBITS; ip++, bit++) {
	if (ip->rtb_task) {
	    (void) fprintf(fd,
			   "\t\t%d\t%s",
			   bit,
			   task_name(ip->rtb_task));
	    if (ip->rtb_length) {
		(void) fprintf(fd,
			       "\tbyte index: %d\tlength: %d",
			       ip->rtb_index,
			       ip->rtb_length);
	    }
	    (void) fprintf(fd, "\n");
	}
    }
    (void) fprintf(fd, "\n");
}


/**/

int rt_n_changes = 0;		/* Number of changes to routing table */
rt_list *rt_change_list = (rt_list *) 0;

/*
 *	rt_open: Make table available for updating
 */
void
rt_open(task *tp)
{
	assert(!rt_opentask);
	rt_opentask = tp;
	rt_n_changes = 0;
}


/*
 *	rt_close: Clean up after table updates
 */
void
rt_close(task *tp, gw_entry *gwp, int changes, const char *message)
{
	assert(rt_opentask == tp);

	rt_opentask = (task *) 0;
	if (rt_n_changes) {
		if (TRACE_TP(tp, TR_ROUTE)) {
			tracef("rt_close: %d", rt_n_changes);
			if (changes) {
				tracef("/%d", changes);
			}
			tracef(" route%s proto %s",
			       rt_n_changes > 1 ? "s" : "",
			       task_name(tp));
			if (gwp && gwp->gw_addr) {
				tracef(" from %A", gwp->gw_addr);
			}
			if (message) { 
				tracef(" %s", message);
			}
			trace_only_tp(tp, TRC_NL_AFTER, (NULL));
		}
		rt_n_changes = 0;
	}

	/* Create a flash job */
	if (rt_change_list && !rt_flash_job
	     && !BIT_TEST(task_state, TASKS_INIT|TASKS_RECONFIG|TASKS_TERMINATE)) {
		/* Schedule a flash update */

		rt_flash_job = task_job_create(rt_task,
		                               TASK_JOB_PRIO_FLASH,
		                               "flash_update",
		                               rt_flash_update,
		                               (void_t) 0);
	}

	return;
}


/**/

/* Looks up a destination network route with a specific protocol mask. */
/* Specifying a protocol of zero will match all protocols. */

rt_entry *
rt_locate(flag_t state, sockaddr_un *dst, sockaddr_un *mask, flag_t proto_mask)
{
    register rt_head *rth = rt_table_locate(dst, mask);

    if (rth) {
	register rt_entry *rt;

	RT_ALLRT(rt, rth) {
	    if (!BIT_TEST(rt->rt_state, RTS_DELETE)
		&& rt->rt_state & state & (RTS_NETROUTE|RTS_GROUP)
		&& BIT_TEST(proto_mask, RTPROTO_BIT(rt->rt_gwp->gw_proto))) {
		return rt;
	    }
	} RT_ALLRT_END(rt, rth);
    }

    return (rt_entry *) 0;
}

/* Given a rth, find the rt_entry corresponding to a certain gateway.
 */
rt_entry *
rt_withgw(rt_head *rth, gw_entry *gwp)
{
	rt_entry *rt;

	RT_ALLRT(rt, rth) {
		if (rt->rt_gwp == gwp)
			return(rt);
	} RT_ALLRT_END(rt, rth);

	return(NULL);
}

/* Look up a route with a destination address, protocol and source gateway */
rt_entry *
rt_locate_gw(flag_t state, sockaddr_un *dst, sockaddr_un *mask, gw_entry *gwp)
{
    register rt_head *rth = rt_table_locate(dst, mask);

    if (rth) {
	register rt_entry *rt;
	
	RT_ALLRT(rt, rth) {
	    if (!BIT_TEST(rt->rt_state, RTS_DELETE)
		&& rt->rt_state & state & (RTS_NETROUTE|RTS_GROUP) 
		&& (rt->rt_gwp == gwp)) {
		return rt;
	    }
	} RT_ALLRT_END(rt, rth);
    }

    return (rt_entry *) 0;
}



/*
 *	Look up the most specific route that matches the supplied
 *	criteria
 */  
#ifndef EXTENDED_RIBS
rt_entry *
rt_lookup(flag_t good, flag_t bad, sockaddr_un *dst, flag_t proto_mask,
    int ribi)
{
    register rt_list *rtl = rthlist_match(dst, ribi);
    register rt_head *rth;
    register rt_entry *rt = (rt_entry *) 0;

    RT_LIST(rth, rtl, rt_head) {

	RT_ALLRT(rt, rth) {
	    if (!BIT_TEST(rt->rt_state, bad) &&
		BIT_TEST(rt->rt_state, good) &&
		BIT_TEST(proto_mask, RTPROTO_BIT(rt->rt_gwp->gw_proto))) {
		/* Found it */

		goto Return;
	    }
	} RT_ALLRT_END(rt, rth) ;
    } RT_LIST_END(rth, rtl, rt_head) ;
 Return:
    RTLIST_RESET(rtl);
    return rt;
}
#else /* EXTENDED_RIBS */
rt_entry *
rt_lookup(flag_t good, flag_t active, flag_t eligible, flag_t bad,
    sockaddr_un *dst, flag_t proto_mask, int ribi)
{
    register rt_list *rtl = rthlist_match(dst, ribi);
    register rt_head *rth;
    register rt_entry *rt = (rt_entry *) 0;

    RT_LIST(rth, rtl, rt_head) {

	RT_ALLRT(rt, rth) {
	    if (!BIT_TEST(rt->rt_state, bad)
             && BIT_TEST(proto_mask, RTPROTO_BIT(rt->rt_gwp->gw_proto))
	     && (BIT_TEST(rt->rt_state, good) 
                 || BIT_TEST(eligible, rt->rt_eligible_ribs)
                 || BIT_TEST(active, rt->rt_active_ribs) )) {
		/* Found it */

		goto Return;
	    }
	} RT_ALLRT_END(rt, rth) ;
    } RT_LIST_END(rth, rtl, rt_head) ;
 Return:
    RTLIST_RESET(rtl);
    return rt;
}
#endif /* EXTENDED_RIBS */


/**/
#if	RT_N_MULTIPATH > 1
/*
 *	Do a linear sort of the routers to get them in ascending order
 */
static void
rt_routers_sort(sockaddr_un **routers, int nrouters)
{
    register int i, j;
    
    for (i = 0; i < (nrouters-1); i++) {
	for (j = i+1; j < nrouters; j++) {
	    if (sockaddrcmp2(routers[i], routers[j]) > 0) {
		register sockaddr_un *swap = routers[i];

		routers[i] = routers[j];
		routers[j] = swap;
	    }
	}
    }
}

int
rt_routers_compare(rt_entry *rt, sockaddr_un **routers)
{
    register int i = rt->rt_n_gw;

    /* Get them into the same order */
    rt_routers_sort(routers, i);
		
    while (i--) {
	if (!sockaddrcmp(routers[i], rt->rt_routers[i])) {
	    /* Found one that was different */
	    return FALSE;
	}
    }

    return TRUE;
}
#endif	/* RT_N_MULTIPATH > 1 */


/*  Add a route to the routing table after some checking.  The route	*/
/*  is added in preference order.  If the active route changes, the	*/
/*  kernel routing table is updated.					*/
rt_entry *
rt_add(register rt_parms *pp)
{
    int i;
    const char *errmsg = (char *) 0;
    rt_entry *rt = (rt_entry *) 0;
    task *tp = pp->rtp_gwp->gw_task;

    rt_check_open(pp->rtp_gwp->gw_proto, "rt_add");

    /* Allocate an entry */
    rt = (rt_entry *) task_block_alloc(rt_block_index);

    /* Locate the head for this entry */
    rt->rt_head = rth_locate(pp->rtp_dest, pp->rtp_dest_mask, &pp->rtp_state, &errmsg);
    if (errmsg) {
	goto Error;
    }

    for (i = 0; i < pp->rtp_n_gw; i++) {
	rt->rt_routers[i] = sockdup(pp->rtp_routers[i]);

	/* Clean up the address */
	switch (socktype(rt->rt_routers[i])) {
#ifdef	PROTO_INET
	case AF_INET:
	    sock2port(rt->rt_routers[i]) = 0;
	    break;
#endif	/* PROTO_INET */

#ifdef	PROTO_INET6
	case AF_INET6:
	    sock2port6(rt->rt_routers[i]) = 0;
	    sock2flow6(rt->rt_routers[i]) = 0;
	    break;
#endif /* PROTO_INET6 */

#ifdef	PROTO_ISO
	case AF_ISO:
	    /* XXX - What do we need here? */
	    break;
#endif	/* PROTO_ISO */
	}
    }
    rt->rt_n_gw = pp->rtp_n_gw;
#if	RT_N_MULTIPATH > 1
    rt_routers_sort(rt->rt_routers, (int) rt->rt_n_gw);
    rt->rt_gw_sel = (pp->rtp_n_gw > 1) ? (short) grand((u_int32) rt->rt_n_gw) : 0;
#endif	/* RT_N_MULTIPATH > 1 */

    rt->rt_gwp = pp->rtp_gwp;
    rt->rt_metric = pp->rtp_metric;
    rt->rt_metric2 = pp->rtp_metric2;
    rt->rt_tag = pp->rtp_tag;

    /* Add the route to the gateway queue and count */
    INSQUE(&rt->rt_rtq, rt->rt_gwp->gw_rtq.rtq_back);
    rt->rt_gwp->gw_n_routes++;
    rt->rt_time = time_sec;

    rt->rt_state = pp->rtp_state | (rt->rt_head->rth_state & ~(RTS_ONLIST));
    rt->rt_state |= RTS_INITIAL;
#ifdef EXTENDED_RIBS
    rt->rt_eligible_ribs = pp->rtp_eligible_ribs;
#endif /* EXTENDED_RIBS */
    rt->rt_preference = pp->rtp_preference;
    rt->rt_preference2 = pp->rtp_preference2;
    if (!BIT_MATCH(rt->rt_state, rt->rt_head->rth_state)) {
	/* XXX - this route does not match */
    }

    /* Set the gateway flags */
    if (BIT_TEST(rt->rt_state, RTS_EXTERIOR)) {
	BIT_SET(rt->rt_state, RTS_GATEWAY);
    } else {
	switch (rt->rt_gwp->gw_proto) {
	    case RTPROTO_KERNEL:
	    case RTPROTO_STATIC:
	    case RTPROTO_DIRECT:
		break;

	    default:
		BIT_SET(rt->rt_state, RTS_GATEWAY);
		break;
	}
    }

    /* Check for martians */
    if (is_martian(pp->rtp_dest, pp->rtp_dest_mask)
	&& !BIT_TEST(pp->rtp_state, RTS_NOADVISE)) {
	/* It's a martian!  Make sure it does not get used */

	BIT_SET(rt->rt_state, RTS_NOTINSTALL|RTS_NOADVISE);
	errmsg = "MARTIAN will not be propagated";
    }

    for (i = 0; i < pp->rtp_n_gw; i++) {
#if 0  /*  %%%%%%%% was #ifdef PROTO_INET6 wfs  */
      if (socktype(rt->rt_routers[i]) == AF_INET6 &&
	   		  inet6_scope_of(rt->rt_routers[i]) == INET6_SCOPE_LINKLOCAL &&
					pp->rtp_ifaps[i]) {
						IFA_ALLOC(rt->rt_ifaps[i] = pp->rtp_ifaps[i]); /* XXX Shimojou */
			} else 
#endif /* PROTO_INET6 */
						IFA_ALLOC(rt->rt_ifaps[i] = if_withroute(rt->rt_dest, rt->rt_routers[i], rt->rt_state));
	
			if (!rt->rt_ifaps[i]) {
	    	/* This is an off-net gateway */
				if (BIT_TEST(rt->rt_state, RTS_NOTINSTALL)) {
				/* Allow if flaged as not installable */
					continue;
				}

	    	/* XXX - which interface */
	   		errmsg = "interface not found for";
	    	goto Error;
			}
	/* If this is not an interface route, ignore routes to the destination(s) of this interface */
	if (BIT_TEST(rt->rt_state, RTS_GATEWAY)
	    && !BIT_MATCH(rt->rt_state, RTS_NOTINSTALL|RTS_NOADVISE|RTS_REJECT)
	    && if_myaddr(rt->rt_ifaps[i], rt->rt_dest, rt->rt_dest_mask)
	    && (!BIT_TEST(rt->rt_ifaps[i]->ifa_state, IFS_POINTOPOINT)
		|| !sockaddrcmp(rt->rt_dest, rt->rt_ifaps[i]->ifa_addr_local))) {
	    /* Make it unusable */

	    BIT_SET(rt->rt_state, RTS_NOTINSTALL|RTS_NOADVISE);
	    if (rt->rt_preference > 0) {
		rt->rt_preference = -rt->rt_preference;
	    }
	}
    }

    rt->rt_data = pp->rtp_rtd;
    
    rt_n_changes++;

#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
    /* Create an AS path for this route */
    aspath_rt_build(rt, pp->rtp_asp);
#endif	/* PROTO_ASPATHS */

    rt_event_initialize(rt);

 Message:
    if (errmsg) {
	tracef("rt_add: %s ",
	       errmsg);
	if (BIT_TEST(pp->rtp_state, RTS_GROUP)) {
	    tracef("group %A",
		   pp->rtp_dest);
	} else {
	    tracef("%A",
		   pp->rtp_dest);
	    if (pp->rtp_dest_mask) {
		tracef("/%A",
		       pp->rtp_dest_mask);
	    }
	}
	tracef(" gw");
	for (i 	= 0; i < pp->rtp_n_gw; i++) {
	    tracef("%c%A",
		   i ? ',' : ' ',
		   pp->rtp_routers[i]);
	}

	if (pp->rtp_gwp->gw_addr && (pp->rtp_n_gw > 1 || !sockaddrcmp(pp->rtp_routers[0], pp->rtp_gwp->gw_addr))) {
	    tracef(" from %A",
		   pp->rtp_gwp->gw_addr);
	}
	
	tracef(" %s",
	       trace_state(rt_proto_bits, pp->rtp_gwp->gw_proto));
	if (pp->rtp_gwp->gw_peer_as) {
	    tracef(" AS %d",
		   pp->rtp_gwp->gw_peer_as);
	}

	trace_log_tp(tp,
		     0,
		     LOG_WARNING,
		     (NULL));
    }

#ifdef	RT_SANITY
    rt_sanity();
#endif	/* RT_SANITY */
    
    return rt;

 Error:
    if (rt) {
	if (rt->rt_rtq.rtq_forw) {
	    /* We added it to the queue, remove it */

	    REMQUE(&rt->rt_rtq);
	    rt->rt_gwp->gw_n_routes--;
	}
	(void) rt_free(rt);
	rt = (rt_entry *) 0;
    }
    goto Message;
}



 /* rt_change() changes a route &/or notes that an update was received.	*/
 /* returns 1 if change made.  Updates the kernel's routing table if	*/
 /* the router has changed, or a preference change has made another	*/
 /* route active							*/
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
rt_entry *
rt_change_aspath(rt_entry *rt, metric_t metric, metric_t metric2, metric_t tag,
    pref_t preference, pref_t preference2, int n_gw, sockaddr_un **gateway,
    if_addr **ifaps, as_path *asp)
#else /* PROTO_ASPATHS */
rt_entry *
rt_change(rt_entry *rt, metric_t metric, metric_t metric2, metric_t tag,
    pref_t preference, pref_t preference2, int n_gw, sockaddr_un **gateway)
#endif  /* PROTO_ASPATHS */
{
    rt_changes *rtcp = NULL;
    int gateway_changed = FALSE;
    int preference_changed = FALSE;

    rt_check_open(rt->rt_gwp->gw_proto, "rt_change");

    /* Put at the end of the gateway queue and timestamp the route */
    if (!rt->rt_rtq.rtq_forw) {
	/* It was not on the list, put it on and count new route */
	
	rt->rt_gwp->gw_n_routes++;
	INSQUE(&rt->rt_rtq, rt->rt_gwp->gw_rtq.rtq_back);
	rt->rt_time = time_sec;
    }

    /* Allocate a change block if necessary */
    RT_ACTIVE_RIBS(rt) {
        if (rt == rt->rt_head->rth_rib_last_active[ribi]) {
	    rtcp = rtchanges_assert(rt); /* Won't get it if rt_n_bitsset == 0 */
            break;
        }
    } RT_ACTIVE_RIBS_END(rt);

    if (n_gw != rt->rt_n_gw
	|| gateway != rt->rt_routers) {
	int should_copy = rtcp && !BIT_TEST(rtcp->rtc_flags, RTCF_NEXTHOP);
	if_addr *ifap;
#if	RT_N_MULTIPATH > 1
	sockaddr_un **routers = gateway;
	sockaddr_un *sorted_routers[RT_N_MULTIPATH];
	if_addr *sorted_ifaps[RT_N_MULTIPATH];
	register int i;

	if (n_gw > 1) {
	    for (i = 0; i < n_gw; i++) {
		sorted_routers[i] = *gateway++;
#ifdef PROTO_INET6  
		if(socktype(sorted_routers[i]) == AF_INET6
		   && inet6_scope_of(sorted_routers[i])
		   == INET6_SCOPE_LINKLOCAL
		   && *ifaps) {
		    sorted_ifaps[i] = *ifaps++;
		} else {
		    sorted_ifaps[i] = if_withroute(rt->rt_dest, sorted_routers[i], rt->rt_state);
		}
#endif
	    }
	    rt_routers_sort(sorted_routers, n_gw);
	    routers = sorted_routers;
	}

	/*
	 * Check to see if anything has changed.
	 */
	if ((i = n_gw) == rt->rt_n_gw) {
	    while (i--) {
		if (!sockaddrcmp(rt->rt_routers[i], routers[i])) {
		    break;
		}
	    }
	}

	/*
	 * Copy his routers.  If we need to save them, do that too.
	 */
	if (i >= 0) {
	    /* Compute the ifap's for the new routes */
	    for (i = 0; i < n_gw; i++) {
		sorted_routers[i] = sockdup(*routers);
		sockclean(sorted_routers[i]);
		routers++;
#ifdef PROTO_INET6
		if(socktype(sorted_routers[i]) == AF_INET6
		   && inet6_scope_of(sorted_routers[i])
		   == INET6_SCOPE_LINKLOCAL
		   && sorted_ifaps[i]) {
		    ifap = sorted_ifaps[i];
		} else {
		    ifap = if_withroute(rt->rt_dest, sorted_routers[i], rt->rt_state);
		}
#else
		ifap = if_withroute(rt->rt_dest, sorted_routers[i], rt->rt_state);
#endif
		if (!ifap) {
		    int j;

		    trace_log_tp(rt->rt_gwp->gw_task,
				 0,
				 LOG_WARNING,
				 ("rt_change: interface not found for net %-15A gateway %A",
				  rt->rt_dest,
				  sorted_routers[i]));
		    for (j = 0; j < i; j++) {
			sockfree(sorted_routers[j]);
			IFA_FREE(sorted_ifaps[j]);
		    }
		    sockfree(sorted_routers[i]);
		    return (rt_entry *) 0;
		}
		IFA_ALLOC(sorted_ifaps[i] = ifap);
	    }

	    for (i = 0; i < n_gw; i++) {
		if (i < rt->rt_n_gw) {
		    if (should_copy) {
			rtcp->rtc_routers[i] = rt->rt_routers[i];
			rtcp->rtc_ifaps[i] = rt->rt_ifaps[i];
		    } else {
			sockfree(rt->rt_routers[i]);
			IFA_FREE(rt->rt_ifaps[i]);
		    }
		}
		rt->rt_routers[i] = sorted_routers[i];
		rt->rt_ifaps[i] = sorted_ifaps[i];
	    }
	    for ( ; i < rt->rt_n_gw; i++) {
		if (should_copy) {
		    rtcp->rtc_routers[i] = rt->rt_routers[i];
		    rtcp->rtc_ifaps[i] = rt->rt_ifaps[i];
		} else {
		    sockfree(rt->rt_routers[i]);
		    IFA_FREE(rt->rt_ifaps[i]);
		}
		rt->rt_routers[i] = NULL;
	    }
	    if (should_copy) {
		rtcp->rtc_n_gw = rt->rt_n_gw;
		rtcp->rtc_gw_sel = rt->rt_gw_sel;
		rt->rt_gw_sel = (n_gw > 1) ? (short) grand((u_int32) n_gw) : 0;
		BIT_SET(rtcp->rtc_flags, RTCF_NEXTHOP);
	    } else if (rtcp) {
		/*
		 * Check to see if we have changed the next hop back to what it was
		 * previously.  If so, delete the change information.
		 */
		if (rtcp->rtc_n_gw == n_gw) {
		    for (i = 0; i < n_gw; i++) {
			if (!sockaddrcmp(rtcp->rtc_routers[i], rt->rt_routers[i])) {
			    break;
			}
		    }
		    if (i == n_gw) {
			/*
			 * Same as before, delete change info.
			 */
			BIT_RESET(rtcp->rtc_flags, RTCF_NEXTHOP);
			rt->rt_gw_sel = rtcp->rtc_gw_sel;
			for (i = 0; i < n_gw; i++) {
			    sockfree(rtcp->rtc_routers[i]);
			    IFA_FREE(rtcp->rtc_ifaps[i]);
			    rtcp->rtc_routers[i] = NULL;
			}
			rtcp->rtc_n_gw = 0;
			rtcp->rtc_gw_sel = 0;
		    }
		}
		if (BIT_TEST(rtcp->rtc_flags, RTCF_NEXTHOP)) {
		    rt->rt_gw_sel = (n_gw > 1) ? (short) grand((u_int32) n_gw) : 0;
		}
	    }

	    rt->rt_gw_sel = (n_gw > 1) ? (short) grand((u_int32) n_gw) : 0;
	    rt->rt_n_gw = n_gw;
	    gateway_changed = TRUE;
	}
#else	/* RT_N_MULTIPATH == 1 */
	if (n_gw != rt->rt_n_gw ||
	  (n_gw > 0 && !sockaddrcmp(RT_ROUTER(rt), *gateway))) {
	    sockaddr_un *newrouter;

	    /* XXX - We check for interface change only in this case? */

	    if (n_gw > 0) {
		newrouter = sockdup(*gateway);
		sockclean(newrouter);
		ifap = if_withroute(rt->rt_dest, newrouter, rt->rt_state);
		if (!ifap) {
		    trace_log_tp(rt->rt_gwp->gw_task,
				 0,
				 LOG_WARNING,
				 ("rt_change: interface not found for net %-15A gateway %A",
				  rt->rt_dest,
				  newrouter));
		    return (rt_entry *) 0;
		}
		IFA_ALLOC(ifap);
	    } else {
		newrouter = (sockaddr_un *) 0;
		ifap = (if_addr *) 0;
	    }

	    if (should_copy) {
		if ((rtcp->rtc_n_gw = rt->rt_n_gw) > 0) {
		    rtcp->rtc_routers[0] = RT_ROUTER(rt);
		    rtcp->rtc_ifaps[0] = RT_IFAP(rt);
		}
		BIT_SET(rtcp->rtc_flags, RTCF_NEXTHOP);
	    } else {
		if (rt->rt_n_gw) {
		    sockfree(RT_ROUTER(rt));
		    IFA_FREE(RT_IFAP(rt));
		}
		if (rtcp
		  && BIT_TEST(rtcp->rtc_flags, RTCF_NEXTHOP)
		  && n_gw == rtcp->rtc_n_gw) {
		    /*
		     * If the new router is the same as the changed
		     * version, deleted the changed.
		     */
		    if (n_gw == 0) {
			BIT_RESET(rtcp->rtc_flags, RTCF_NEXTHOP);
		    } else if ((rt && RT_ROUTER(rt)) &&
                       (sockaddrcmp(RT_ROUTER(rt), rtcp->rtc_routers[0]))) {
			BIT_RESET(rtcp->rtc_flags, RTCF_NEXTHOP);
			sockfree(rtcp->rtc_routers[0]);
			IFA_FREE(rtcp->rtc_ifaps[0]);
			rtcp->rtc_routers[0] = (sockaddr_un *) 0;
			rtcp->rtc_ifaps[0] = (if_addr *) 0;
			rtcp->rtc_n_gw = 0;
		    }
		}
	    }
	    RT_ROUTER(rt) = newrouter;
	    RT_IFAP(rt) = ifap;
	    rt->rt_n_gw = n_gw;
	    gateway_changed = TRUE;
	}
#endif	/* RT_N_MULTIPATH */
    }

    if (preference != rt->rt_preference) {
	rt->rt_preference = preference;
	preference_changed = TRUE;
    }
    if (preference2 != rt->rt_preference2) {
	rt->rt_preference2 = preference2;
	preference_changed = TRUE;
    }
    /* If MED value has changed for route, just want to reorder routes */
    if (BIT_TEST(rt->rt_state, RTS_MED_CHANGE)) {
        BIT_RESET(rt->rt_state, RTS_MED_CHANGE);
	preference_changed = TRUE;
    }

    if (metric != rt->rt_metric) {
	if (rtcp) {
	    if (!BIT_TEST(rtcp->rtc_flags, RTCF_METRIC)) {
		BIT_SET(rtcp->rtc_flags, RTCF_METRIC);
		rtcp->rtc_metric = rt->rt_metric;
	    } else if (rtcp->rtc_metric == metric) {
		BIT_RESET(rtcp->rtc_flags, RTCF_METRIC);
	    }
	}
	rt->rt_metric = metric;
	gateway_changed = TRUE;
    }

    if (metric2 != rt->rt_metric2) {
	if (rtcp) {
	    if (!BIT_TEST(rtcp->rtc_flags, RTCF_METRIC2)) {
		BIT_SET(rtcp->rtc_flags, RTCF_METRIC2);
		rtcp->rtc_metric2 = rt->rt_metric2;
	    } else if (rtcp->rtc_metric2 == metric2) {
		BIT_RESET(rtcp->rtc_flags, RTCF_METRIC2);
	    }
	}
	rt->rt_metric2 = metric2;
	gateway_changed = TRUE;
    }

    if (tag != rt->rt_tag) {
	if (rtcp) {
	    if (!BIT_TEST(rtcp->rtc_flags, RTCF_TAG)) {
		BIT_SET(rtcp->rtc_flags, RTCF_TAG);
		rtcp->rtc_tag = rt->rt_tag;
	    } else if (rtcp->rtc_tag == tag) {
		BIT_RESET(rtcp->rtc_flags, RTCF_TAG);
	    }
	}
	rt->rt_tag = tag;
	gateway_changed = TRUE;
    }

#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
    if (asp != rt->rt_aspath) {
	/* Path has changed */

	if (rtcp) {
	    if (!BIT_TEST(rtcp->rtc_flags, RTCF_ASPATH)) {
		/* Save the path, don't unlink it */
		rtcp->rtc_aspath = rt->rt_aspath;
		BIT_SET(rtcp->rtc_flags, RTCF_ASPATH);
		rt->rt_aspath = (as_path *) 0;
	    } else if (asp == rtcp->rtc_aspath) {
		/* AS path changed back.  Unlink the route's AS path then */
		/* simply transfer the changed path back to the route */
		/* This assumes an INTERNAL_IGP route will never have been active */
		if (rt->rt_aspath) {
		    aspath_rt_free(rt);
		}
		rt->rt_aspath = asp;
		rtcp->rtc_aspath = NULL;
		BIT_RESET(rtcp->rtc_flags, RTCF_ASPATH);
	    }
	}

	if (rtcp == NULL || BIT_TEST(rtcp->rtc_flags, RTCF_ASPATH)) {
	    if (rt->rt_aspath) {
		aspath_rt_free(rt);
	    }
	    aspath_rt_build(rt, asp);
	}
        gateway_changed = TRUE;
    }
#endif	/* PROTO_ASPATHS */

#ifdef PROTO_WRD
    if (rtcp != NULL  /* Implies active route changing */
       && (gateway_changed || BIT_TEST(rt->rt_state, RTS_DELETE))) {
	/*
	 * Something changed so do a little damping in case this happens
	 * quite frequently
	 */
	rr_suppress_record_unreach(rt);
	if (rr_suppress_record_reach(rt)) {
	    rt_set_suppressed(rt);
	}
    }
#endif /* PROTO_WRD */
    if (preference_changed 
	|| gateway_changed || BIT_TEST(rt->rt_state, RTS_DELETE)) {

	rt_event_preference(rt, gateway_changed);
	rt_n_changes++;
    }

    if (rtcp && !rtcp->rtc_flags) {
	/* No changes - release */
	rtchanges_free(RT_GET_ACTIVE(rt), rt->rt_head);
    }
    
#ifdef	RT_SANITY
    rt_sanity();
#endif	/* RT_SANITY */
    return rt;
}

#ifdef LPJ_CHANGE_FLAGS

/* Same as rt_change, except the caller tells gated is the route have changed,
 * and what has changed.
 */
rt_entry *
rt_change_flags(rt, changes)
	rt_entry * rt;
	flag_t changes;
{
    rt_changes *rtcp;
    int i;

	/* I guess i do like rt_change() and pray gated not to crash.  */
    rt_check_open(rt->rt_gwp->gw_proto, "rt_change_flags");

    /* Put at the end of the gateway queue and timestamp the route */
    if (!rt->rt_rtq.rtq_forw) {
	/* It was not on the list, put it on and count new route */
	rt->rt_gwp->gw_n_routes++;
	INSQUE(&rt->rt_rtq, rt->rt_gwp->gw_rtq.rtq_back);
	rt->rt_time = time_sec;
    }

    /* Allocate a change block if necessary */
    if (rt == rt->rt_head->rth_rib_last_active[ribi]) {
	rtcp = rt->rt_head->rth_changes;
	if (!rtcp && rt->rt_n_bitsset) {
		rtcp = rt->rt_head->rth_changes =
		   (rt_changes *)task_block_alloc(rtchange_block_index);
	}
    } else
        rtcp = (rt_changes *) 0;

    /* write all the change flags to the rtcp structure. Some fields need
      to be set in order not to crash gated! */
    if (rtcp) {
	BIT_SET(rtcp->rtc_flags, changes);
	for(i = 0; i < rt->rt_n_gw; i++) {
	    rtcp->rtc_routers[i] = rt->rt_routers[i];
	    rtcp->rtc_ifaps[i] = rt->rt_ifaps[i];
	}
    }

    /* Call the route event handler.  */
    if (changes) {
	rt_event_preference(rt, BIT_TEST(changes, RTCF_NEXTHOP|RTCF_TAG));
	rt_n_changes++;
    }

    /* Get rid of the rtcp structure if there is no change.  */
    if (rtcp && !rtcp->rtc_flags)
	    rtchanges_free(RT_GET_ACTIVE(rt), rt->rt_head);

#ifdef  RT_SANITY
        rt_sanity();
#endif /* RT_SANITY */
        return rt;
}
#endif /* LPJ_CHANGE_FLAGS */

/* force a route into the rt_change_list. I.e. mark a route as changed and
 * send it to all the flash() routines.
 */
void
rt_set_change(rt_entry *rt)
{
	if (!BIT_TEST(rt->rt_head->rth_state, RTS_ONLIST)) {
		rt_set_onlist(rt);
	}
}

/* User has declared a route unreachable (for all ribs).  */
void
rt_delete(rt_entry *delete_rt)
{
	rt_check_open(delete_rt->rt_gwp->gw_proto, "rt_delete");

	rt_event_unreachable(delete_rt);

	/* Remove from the queue and timestamp */
	if (delete_rt->rt_rtq.rtq_forw) {
		REMQUE(&delete_rt->rt_rtq);
		delete_rt->rt_rtq.rtq_forw = delete_rt->rt_rtq.rtq_back = (rtq_entry *) 0;
		delete_rt->rt_gwp->gw_n_routes--;
	}
	delete_rt->rt_time = time_sec;

	if (BIT_TEST(delete_rt->rt_state, RTS_RELEASE)) {
		(void) rt_free(delete_rt);
	}
	rt_n_changes++;
    
#ifdef	RT_SANITY
	rt_sanity();
#endif	/* RT_SANITY */
}

#ifdef PROTO_WRD
/*
 * rt_reuse: cause a route to be reused after it has been suppressed
 * for a while.
 */

void
rt_reuse(rt_entry *rt)
{
    rt_open(rt_task);
    rt_reset_suppressed(rt);
    rt_event_preference(rt, TRUE);
    rt_n_changes++;
    rt_close(rt_task, (gw_entry *) 0, 0, NULL);
}
#endif /* PROTO_WRD */
/**/
/*
 *	In preparation for a re-parse, reset the NOAGE flags on static routes
 *	so they will be deleted if they are not refreshed.
 */
/*ARGSUSED*/
static void
rt_cleanup(task *tp)
{

    rt_static_cleanup(tp);

    /* Save old route dampening configuration */
#ifdef PROTO_WRD
    rr_suppress_cleanup(tp);
#endif /* PROTO_WRD */

    /* Cleanup our tracing */
    trace_freeup(rt_task->task_trace);
}


/*
 *	Delete any static routes that do not have the NOAGE flag.
 */
/*ARGSUSED*/
static void
rt_reinit(task *tp)
{
    /* Update tracing */
    trace_freeup(rt_task->task_trace);
    rt_task->task_trace = trace_set_global((bits *) 0, (flag_t) 0);
    
    rt_static_reinit(tp);

    /* Reinitialize route dampening configuration */
#ifdef PROTO_WRD
    rr_suppress_reinit(tp);
#endif /* PROTO_WRD */

#ifdef	PROTO_SNMP
    /* Make sure the MIB is registered */
    rt_init_mib(TRUE);
#endif	/* PROTO_SNMP */
}


/*
 *	Deal with an interface state change
 */
static void
rt_ifachange(task *tp, if_addr *ifap)
{
    rt_static_ifachange(tp);
}


/*
 *	Do this just before shutdown
 */
static void
rt_shutdown(task *tp)
{
    /* Update the kernel with any changes made */
    rt_flash_update((task_job *) 0);

    /* Cleanup our tracing */
    trace_freeup(rt_task->task_trace);
    
    /* And we're outa here... */
    task_delete(tp);
}


/*
 *	Terminating - clean up
 */
static void
rt_terminate(task *tp)
{
    rt_static_terminate(tp);
}


/*
 *	Dump routing table to dump file
 */
static void
rt_dump(task *tp, FILE *fd)
{
    int af = 0;
    register rt_head *rth;
    register rt_list *rtl = rthlist_all(AF_UNSPEC);

    /*
     * Dump the static routes
     */
    rt_static_dump(tp, fd);
    
    /*
     * Dump the static gateways
     */
    if (rt_gw_list) {
	(void) fprintf(fd, "\tGateways referenced by static routes:\n");

	gw_dump(fd,
		"\t\t",
		rt_gw_list,
		RTPROTO_STATIC);

	(void) fprintf(fd, "\n");
    }
    (void) fprintf(fd, "\n");

    /* Print the bit allocation info */
    rtbit_dump(fd);
    
    /* Print netmasks */
    mask_dump(fd);

    /* Routing table information */
    (void) fprintf(fd, "Routing Tables:\n");

    rt_table_dump(tp, fd);
    
    (void) fprintf(fd, "\n");

    /*
     * Dump all the routing information
     */

    (void) fprintf(fd,
		   "\n\t%s\n%s\n",
		   "+ = Active Route, - = Last Active, * = Both",
#if	RT_N_MULTIPATH > 1
		   "\t* = Next hop in use\n");
#else	/* RT_N_MULTIPATH */
		   "");
#endif	/* RT_N_MULTIPATH */
    
    RT_LIST(rth, rtl, rt_head) {
	register u_int i;
	register rt_entry *rt;
	rt_changes *rtcp;

	if (socktype(rth->rth_dest) != af) {
	    af = socktype(rth->rth_dest);

	    (void) fprintf(fd, "\n\tRouting table for %s (%d):\n",
			   gd_lower(trace_value(task_domain_bits, af)),
			   af);
	    (void) fprintf(fd, "\t\tDestinations: %d\tRoutes: %d\n",
			   rtaf_info[af].rtaf_dests,
			   rtaf_info[af].rtaf_routes);
	    (void) fprintf(fd, "\t\tHolddown: %d\tDelete: %d\tHidden: %d\n\n",
			   rtaf_info[af].rtaf_holddowns,
			   rtaf_info[af].rtaf_deletes,
			   rtaf_info[af].rtaf_hiddens);
	}
	
	(void) fprintf(fd,
		  "\t%-15A",
		       rth->rth_dest);
	if (!BIT_TEST(rth->rth_state, RTS_GROUP)) {
	    (void) fprintf(fd,
			   "\tmask %-15A",
			   rth->rth_dest_mask);
	}
	(void) fprintf(fd,
		  "\n\t\t\tentries %d\tannounce %d",
		       rth->rth_entries,
		       rth->rth_n_announce);
	if (rth->rth_state) {
	    (void) fprintf(fd,
			   "\tstate <%s>",
			   trace_bits(rt_state_bits, rth->rth_state));
	}
	(void) fprintf(fd, "\n");

	/* Print change information */
	for (rtcp = rth->rth_changes; rtcp; rtcp = rtcp->rtc_next) {

	    (void) fprintf(fd, "\t\tPrevious state: RIBs %0X %s\n",
			   rtcp->rtc_ribs, 
			   trace_bits(rt_change_bits, rtcp->rtc_flags));
	    
	    if (BIT_TEST(rtcp->rtc_flags, RTCF_NEXTHOP)) {
		if (rtcp->rtc_n_gw) {
		    for (i = 0; i < (u_short)rtcp->rtc_n_gw; i++) {
			if (rtcp->rtc_ifaps[i]) {
			    (void) fprintf(fd,
					   "\t\t\t%sNextHop: %-15A\tInterface: %A(%s)\n",
#if	RT_N_MULTIPATH > 1
					   i == (u_short)rtcp->rtc_gw_sel ? "*" :
#endif	/* RT_N_MULTIPATH > 1 */
					   "",
					   rtcp->rtc_routers[i],
					   IFA_UNIQUE_ADDR(rtcp->rtc_ifaps[i]),
					   rtcp->rtc_ifaps[i]->ifa_link->ifl_name);
			} else {
			    (void) fprintf(fd,
					   "\t\t\t%sNextHop: %-15A\n",
#if	RT_N_MULTIPATH > 1
					   i == (u_short)rtcp->rtc_gw_sel ? "*" :
#endif	/* RT_N_MULTIPATH > 1 */
					   "",
					   rtcp->rtc_routers[i]);
			}
		    }
		} else {
		    (void) fprintf(fd, "\t\t\tNextHop: none\tInterface: none\n");
		}
	    }

	    if (BIT_TEST(rtcp->rtc_flags, RTCF_METRIC|RTCF_METRIC2|RTCF_TAG)) {
		(void) fprintf(fd, "\t\t");
		if (BIT_TEST(rtcp->rtc_flags, RTCF_METRIC)) {
		    (void) fprintf(fd,
				   "\tMetric: %u",
				   rtcp->rtc_metric);
		}
		if (BIT_TEST(rtcp->rtc_flags, RTCF_METRIC2)) {
		    (void) fprintf(fd,
				   "\tMetric2: %u",
				   rtcp->rtc_metric2);
		}
		if (BIT_TEST(rtcp->rtc_flags, RTCF_TAG)) {
		    (void) fprintf(fd,
				   "\tTag: %u\n",
				   rtcp->rtc_tag);
		}
		(void) fprintf(fd, "\n");
	    }
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
	    /* Format AS path */
	    if (BIT_TEST(rtcp->rtc_flags, RTCF_ASPATH) && rtcp->rtc_aspath) {
		aspath_dump(fd, rtcp->rtc_aspath, "\t\t\t", "\n");
	    }
#endif	/* PROTO_ASPATHS */
	}

	rt_aggregate_rth_dump(fd, rth);

	rttsi_dump(fd, rth);

#ifdef PROTO_WRD
	rr_suppress_dump(fd, rth);  /* Dump instability histories */
#endif /* PROTO_WRD */

	(void) fprintf(fd, "\n");

	RT_ALLRT(rt, rth) {
            register int ribi;

	    (void) fprintf(fd, "\t\t");
/* ACR - Following loop needs to be fixed to properly indicate rib name */
           for (ribi=0; ribi<NUMRIBS; ribi++) {
	    const char *active;
	    if (rt == rth->rth_rib_active[ribi] && rt == rth->rth_rib_last_active[ribi]) {
		active = "*";
	    } else if (rt == rth->rth_rib_active[ribi]) {
		active = "+";
	    } else if (rt == rth->rth_rib_last_active[ribi]) {
		active = "-";
	    } else {
		active = "";
	    }
	    (void) fprintf(fd, "%s", active);
           }
	    (void) fprintf(fd,
			   "%s\tPreference: %3d",
			   trace_state(rt_proto_bits, rt->rt_gwp->gw_proto),
			   rt->rt_preference);
	    if (rt->rt_preference2) {
		(void) fprintf(fd, "/%d", rt->rt_preference2);
	    }
	    if (rt->rt_gwp->gw_addr && (rt->rt_n_gw == 0
	      || !sockaddrcmp(rt->rt_gwp->gw_addr, RT_ROUTER(rt)))) {
		(void) fprintf(fd,
			       "\t\tSource: %A\n",
			       rt->rt_gwp->gw_addr);
	    } else {
		(void) fprintf(fd,
			       "\n");
	    }

	    for (i = 0; i < (u_short)rt->rt_n_gw; i++) {
		if (rt->rt_ifaps[i]) {
		    (void) fprintf(fd,
				   "\t\t\t%sNextHop: %-15A\tInterface: %A(%s)\n",
#if	RT_N_MULTIPATH > 1
				   i == (u_short)rt->rt_gw_sel ? "*" :
#endif	/* RT_N_MULTIPATH > 1 */
				   "",
				   rt->rt_routers[i],
				   IFA_UNIQUE_ADDR(rt->rt_ifaps[i]),
				   rt->rt_ifaps[i]->ifa_link->ifl_name);
		} else {
		    (void) fprintf(fd,
				   "\t\t\t%sNextHop: %-15A\n",
#if	RT_N_MULTIPATH > 1
				   i == (u_short)rt->rt_gw_sel ? "*" :
#endif	/* RT_N_MULTIPATH > 1 */
				   "",
				   rt->rt_routers[i]);
		}
	    }

	    (void) fprintf(fd,
			   "\t\t\tState: <%s>\n",
			   trace_bits(rt_state_bits, rt->rt_state));

	    if (rt->rt_gwp->gw_peer_as || rt->rt_gwp->gw_local_as) {
		(void) fprintf(fd,
			       "\t\t");
		if (rt->rt_gwp->gw_local_as) {
		    (void) fprintf(fd,
				   "\tLocal AS: %5u",
				   rt->rt_gwp->gw_local_as);
		}
		if (rt->rt_gwp->gw_peer_as) {
		    (void) fprintf(fd,
				   "\tPeer AS: %5u",
				   rt->rt_gwp->gw_peer_as);
		}
		(void) fprintf(fd,
			       "\n");
	    }
	    (void) fprintf(fd,
			   "\t\t\tAge: %#T",
			   rt_age(rt));
	    (void) fprintf(fd,
			   "\tMetric: %d\tMetric2: %d\tTag: %u\n",
			   rt->rt_metric,
			   rt->rt_metric2,
			   rt->rt_tag);

	    if (rt->rt_gwp->gw_task) {
		(void) fprintf(fd,
			       "\t\t\tTask: %s\n",
			       task_name(rt->rt_gwp->gw_task));
	    }

	    if (rt->rt_n_bitsset) {
		(void) fprintf(fd,
			       "\t\t\tAnnouncement bits(%d):",
			       rt->rt_n_bitsset);
		for (i = 1; i <= RTBIT_NBITS; i++)  {
		    if (rtbit_isset(rt, i)) {
			(void) fprintf(fd,
				       " %d-%s",
				       i,
				       task_name(rtbit_map[i-1].rtb_task));
		    }
		}
		(void) fprintf(fd,
			       "\n");
	    }

#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
	    /* Format AS path */
	    if (rt->rt_aspath) {
		aspath_dump(fd, rt->rt_aspath, "\t\t\t", "\n");
	    }
#endif	/* PROTO_ASPATHS */

	    /* Format protocol specific data */
	    if (rt->rt_data && rt->rt_gwp->gw_rtd_dump) {
		rt->rt_gwp->gw_rtd_dump(fd, rt);
	    }

	    rt_aggregate_rt_dump(fd, rt);

	    (void) fprintf(fd, "\n");

#ifdef PROTO_DVMRP_ROUTING
	    if (rth->rth_rib_active[RIB_MULTICAST] == rt) {
	        dvmrp_rt_dump(fd, rt);
	    }
#endif /* PROTO_DVMRP_ROUTING */

	    (void) fprintf(fd, "\n");
	} RT_ALLRT_END(rt, rth);

	(void) fprintf(fd, "\n");

    } RT_LIST_END(rth, rtl, rt_head) ;
    RTLIST_RESET(rtl);
}


/*
 *  Initialize the routing table.
 *
 *  Also creates a timer and task for the job of aging the routing table
 */
void
rt_family_init(void)
{

    /* Init the routing table */
    rt_table_init();
    
    /* Allocate the routing table task */
    rt_task = task_alloc("RT",
			 TASKPRI_RT,
			 trace_set_global((bits *) 0, (flag_t) 0));
    task_set_cleanup(rt_task, rt_cleanup);
    task_set_reinit(rt_task, rt_reinit);
    task_set_dump(rt_task, rt_dump);
    task_set_terminate(rt_task, rt_terminate);
    task_set_shutdown(rt_task, rt_shutdown);
    task_set_ifachange(rt_task, rt_ifachange);
    if (!task_create(rt_task)) {
	task_quit(EINVAL);
    }

    rt_block_index = task_block_init(sizeof (rt_entry), "rt_entry");
    rth_block_index = task_block_init(sizeof (rt_head), "rt_head");
    rtchange_block_index = task_block_init(sizeof (rt_changes), "rt_changes");
    rtlist_block_index = task_block_init((size_t) RTL_SIZE, "rt_list");
    rttsi_block_index = task_block_init(sizeof (struct _rt_tsi), "rt_tsi");

    rt_static_init(rt_task);

    rt_aggregate_init();

    redirect_init();
}

