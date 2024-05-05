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
#include "parse.h"
#ifdef	PROTO_INET
#include "inet/inet.h"
#endif	/* PROTO_INET */
#ifdef PROTO_INET6
#include "inet6/inet6.h"
#endif
#ifdef	PROTO_ISO
#include "iso/iso.h"
#endif	/* PROTO_ISO */

/**/


/* Aggregate routes */


#ifdef	PROTO_INET
adv_entry *aggregate_list_inet;		/* Aggregation policy */
#endif	/* PROTO_INET */
#ifdef	PROTO_INET6
adv_entry *aggregate_list_inet6;		/* Aggregation policy */
#endif	/* PROTO_INET6 */
#ifdef	PROTO_ISO
adv_entry *aggregate_list_iso;		/* Aggregation policy */
#endif	/* PROTO_ISO */

struct rt_aggregate_family {
    u_int rtaf_family;
    adv_entry **rtaf_list;
    u_int rtaf_depth;
};

static struct rt_aggregate_family rt_aggregate_families[] = {
#ifdef	PROTO_INET
    { AF_INET, &aggregate_list_inet },
#endif	/* PROTO_INET */
#ifdef	PROTO_INET6
    { AF_INET6, &aggregate_list_inet6 },
#endif	/* PROTO_INET6 */
#ifdef	PROTO_ISO
    { AF_ISO, &aggregate_list_iso },
#endif	/* PROTO_ISO */
    { 0 }
};

#define	AGGR_FAMILIES(afp) \
	{ \
	     struct rt_aggregate_family *(afp) = rt_aggregate_families; \
	     do

#define	AGGR_FAMILIES_END(afp) \
	     while ((++afp)->rtaf_family); \
	}

static block_t rt_aggregate_entry_block = (block_t) 0;
static block_t rt_aggregate_head_block = (block_t) 0;
static gw_entry *rt_aggregate_gwp = (gw_entry *) 0;
static task *rt_aggregate_task = (task *) 0;
static rt_parms rt_aggregate_rtparms = { 0 } ;

static const bits rt_aggregate_flag_bits[] = {
    { RTAHF_BRIEF,	"Brief" },
    { RTAHF_CHANGED,	"Changed" },
    { RTAHF_ASPCHANGED,	"ASPathChanged" },
    { RTAHF_ONLIST,	"OnList" },
    { RTAHF_GENERATE,	"Generate" },
    { RTAHF_NOINSTALL, "Noinstall" },
    { 0, NULL }
};

/*
 * Aggregate routes that come in on a change list/get changed while
 * processing a change list.
 */
static rt_list *rt_aggregate_changes = NULL;
#if (defined(PROTO_BGP) || defined(PROTO_MPBGP)) && defined(GATED_MEMBER)
/*
 * Contributing routes that need to be added to the flash list because
 * of changes to the aggregate.
 */
static rt_list *rt_aggregate_contrib_changes = NULL;
#endif /* (defined(PROTO_BGP) || defined(PROTO_MPBGP)) */


/**/

#if	!defined(PROTO_ASPATHS) && !defined(PROTO_MPASPATHS)
#define	aspath_aggregate_changed(rtah, oasp, nasp)	0
#endif	/* PROTO_ASPATHS */

#define	RT_CHANGE(art, rtah, old_asp, new_asp) \
	do { \
	     if (aspath_aggregate_changed((rtah), (old_asp), (new_asp)) \
		 || (art)->rt_preference != (rtah)->rtah_rta_forw->rta_preference) { \
		 BIT_SET((rtah)->rtah_flags, RTAHF_CHANGED); \
	     } else if (BIT_COMPARE((rtah)->rtah_flags, RTAHF_GENERATE|RTAHF_CHANGED, RTAHF_GENERATE)) { \
	         register rt_entry *Xrt = (rtah)->rtah_rta_forw->rta_rt; \
		 register int Xi = (art)->rt_n_gw; \
		 while (Xi--) { \
		     if (!sockaddrcmp((art)->rt_routers[Xi], Xrt->rt_routers[Xi])) { \
			 BIT_SET((rtah)->rtah_flags, RTAHF_CHANGED); \
			 break; \
		     } \
		 } \
	     } \
	     if (BIT_COMPARE((rtah)->rtah_flags, RTAHF_CHANGED|RTAHF_ONLIST, RTAHF_CHANGED)) { \
		 RTLIST_ADD(rt_aggregate_changes, (art)->rt_head); \
		 BIT_SET((rtah)->rtah_flags, RTAHF_ONLIST); \
	     } \
	 } while(0)

#if (defined(PROTO_BGP) || defined(PROTO_MPBGP)) && defined(GATED_MEMBER)
static int
rt_aggregate_options_match(rt_entry *rt, rt_aggr_head *rtah)
{
	if (!BIT_TEST(rtah->rtah_flags, RTAHF_BGP)) {
		return TRUE;
	}
	if (!rt->rt_gwp->gw_proto == RTPROTO_BGP) {
		return TRUE;
	}
	if (!rtah->rtah_matched) {
		rtah->rtah_med = rt->rt_aspath->path_med;
		rtah->rtah_nexthop = rt->rt_aspath->nexthop;
		return TRUE;
	}
	if (rt->rt_aspath->path_med == rtah->rtah_med &&
	    rt->rt_aspath->nexthop == rtah->rtah_nexthop) {
		return TRUE;
	}
	return FALSE;
}
#endif /* defined(PROTO_BGP) || defined(PROTO_MPBGP) */


/*****************************************************************************/
/* Find our aggregate 
 * Called by rt_aggregate_putonlist() and rt_aggregate_flash_aggregate()
 */
static rt_aggr_head *
rt_aggregate_get(register rt_head *rth, rt_entry **aggr_rtp)
{
    rt_entry *aggr_rt;
    rt_aggr_head *rtah = (rt_aggr_head *) 0;

    RT_ALLRT(aggr_rt, rth) {
	if (aggr_rt->rt_gwp == rt_aggregate_gwp) {
	    /* Found it */

	    rtah = rt_aggregate_head(aggr_rt);
	    break;
	}
    } RT_ALLRT_END(aggr_rt, rth) ;
    assert(rtah);
    if (aggr_rtp)
	*aggr_rtp = aggr_rt;
    return rtah;
}

/*****************************************************************************/
/* Called by rt_aggregate_flash() 
 * Adds an aggregate route to our own list if it isn't there already.
 */
static void
rt_aggregate_putonlist(register rt_head *rth)
{
    rt_aggr_head *rtah = rt_aggregate_get(rth, NULL);

    /* Add to our private list */
    if (!BIT_TEST(rtah->rtah_flags, RTAHF_ONLIST)) {
	RTLIST_ADD(rt_aggregate_changes, rth);
	BIT_SET(rtah->rtah_flags, RTAHF_ONLIST);
    }
}

/*****************************************************************************/
/* Called by rt_aggregate_flash() 
 * Checks to see if this aggregate route has changed 
 */
static void
rt_aggregate_flash_aggregate(register rt_head *rth)
{
	rt_entry *aggr_rt;
        rt_aggr_head *rtah = rt_aggregate_get(rth, &aggr_rt);
	assert(BIT_TEST(rtah->rtah_flags, RTAHF_ONLIST));

	if (BIT_TEST(rtah->rtah_flags, RTAHF_CHANGED)) {
	    int n_gw = 0;
	    int noinstall_change = FALSE; 
	    sockaddr_un **routers = (sockaddr_un **) 0;
	    rt_entry *rt = rtah->rtah_rta_forw->rta_rt;
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
	    as_path *asp;
#endif	/* PROTO_ASPATHS */

	    if (BIT_TEST(rtah->rtah_flags, RTAHF_GENERATE)) {
		/* A generated route needs next hops */
		
		if (rt == aggr_rt) {
		    n_gw = 0;
		} else if (!BIT_TEST(rt->rt_state, RTS_GATEWAY)) {
		    /* Interface routes are special */

		    if (rt->rt_n_gw
			&& BIT_TEST(RT_IFAP(rt)->ifa_state, IFS_POINTOPOINT)) {
			/* On a P2P interface we need to point at the remote address */

			n_gw = 1;
			routers = &RT_IFAP(rt)->ifa_addr_remote;
		    } else {
			/* Other interfaces just end up with an aggregate route */

			n_gw = 0;
		    }
		} else {
		    /* Not an interface route, use its next hops */
		    
		    n_gw = rt->rt_n_gw;
		    routers = rt->rt_routers;
		}
	    }
	    if ((BIT_TEST(rtah->rtah_flags, RTAHF_NOINSTALL) && 
		 !BIT_TEST(aggr_rt->rt_state, RTS_NOTINSTALL)) ||
		 (!BIT_TEST(rtah->rtah_flags, RTAHF_NOINSTALL) &&
		  BIT_TEST(aggr_rt->rt_state, RTS_NOTINSTALL))) { 
	        noinstall_change = TRUE;
	    }
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
	    asp = aspath_do_aggregation(rtah);
#endif	/* PROTO_ASPATHS */

	    if (((n_gw != 0) != (aggr_rt->rt_n_gw != 0)) || noinstall_change) {
		rt_entry *old_rt = aggr_rt;
                register rt_aggr_entry *rta;

		/* Changing to and from a REJECT route requires a delete and re-add */

		/* Set REJECT flag */
		if (n_gw) {
		    BIT_RESET(rt_aggregate_rtparms.rtp_state, RTS_REJECT);
		} else {
		    BIT_SET(rt_aggregate_rtparms.rtp_state, RTS_REJECT);
		}
		/* Changing to and from a NOINSTALL route(also) requires a delete and re-add. */
		if (BIT_TEST(rtah->rtah_flags, RTAHF_NOINSTALL)) {
		  BIT_SET(rt_aggregate_rtparms.rtp_state, RTS_NOTINSTALL);
		} else {
		  BIT_RESET(rt_aggregate_rtparms.rtp_state,
			    RTS_NOTINSTALL);
		}

		/* Set rib bits to the union of contributors' ribs */
		RTP_RESET_ELIGIBLE(rt_aggregate_rtparms);
		AGGR_LIST(&rtah->rtah_rta, rta) {
#ifndef    EXTENDED_RIBS
		    rt_aggregate_rtparms.rtp_state |= (rta->rta_rt->rt_state
		     & RTS_ELIGIBLE_RIBS & rtah->rtah_flags);
#else   /* EXTNEDED_RIBS */
		    rt_aggregate_rtparms.rtp_eligible_ribs 
                            |= (rta->rta_rt->rt_eligible_ribs 
                                & rtah->rtah_eligible_ribs);
#endif  /* EXTNEDED_RIBS */
		} AGGR_LIST_END(&rtah->rtah_rta, rta);
		rt_aggregate_rtparms.rtp_dest = aggr_rt->rt_dest;
		rt_aggregate_rtparms.rtp_dest_mask = aggr_rt->rt_dest_mask;
		rt_aggregate_rtparms.rtp_rtd = aggr_rt->rt_data;
		rt_aggregate_rtparms.rtp_n_gw = n_gw;
		bzero((caddr_t) rt_aggregate_rtparms.rtp_routers, 
		 sizeof(rt_aggregate_rtparms.rtp_routers));
		if (n_gw) {
#if	RT_N_MULTIPATH > 1
		    register int i = n_gw - 1;

		    do {
			rt_aggregate_rtparms.rtp_routers[i] = routers[i];
		    } while (i--) ;
#else	/* RT_N_MULTIPATH == 1 */
		    rt_aggregate_rtparms.rtp_router = *routers;
#endif	/* RT_N_MULTIPATH */
		}
		rt_aggregate_rtparms.rtp_tag = aggr_rt->rt_tag;
		rt_aggregate_rtparms.rtp_metric = aggr_rt->rt_metric;
		rt_aggregate_rtparms.rtp_metric2 = aggr_rt->rt_metric2;
		rt_aggregate_rtparms.rtp_preference =
			rtah->rtah_rta_forw->rta_preference;
		rt_aggregate_rtparms.rtp_preference2 =
			aggr_rt->rt_preference2;
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
		rt_aggregate_rtparms.rtp_asp = asp;
#endif	/* PROTO_ASPATHS */
			
		aggr_rt = rtah->rtah_rta_rt = rt_add(&rt_aggregate_rtparms);
		assert(aggr_rt);

                /*
                 * Since we are deleting and re-adding the route, we
		 * must update the corresponding policy (adv_entry)
		 * to point to the new route.
                 */
                AGGR_FAMILIES(afp) {
                    /* Find aggregate route address family. */
                    if (afp->rtaf_family == socktype(old_rt->rt_dest)) {
                        register dest_mask_internal *dmi;

                        if (!*afp->rtaf_list) {
                            continue;
                        }
                        /* Walk the aggregate list looking for adv
			 * entries matching the old route
			 */
                        DMI_WALK_ALL( adv_dml_get_root(*afp->rtaf_list,
			    afp->rtaf_family), dmi,
			    aggr_adv) {
                            if (aggr_adv->adv_result.res_void ==
						(void_t) old_rt) {
                                aggr_adv->adv_result.res_void =
					(void_t) aggr_rt;
                                break;
                             }
                         }
                         DMI_WALK_ALL_END( adv_dml_get_root(*afp->rtaf_list)
			     afp->rtaf_family, dmi, aggr_adv) ;
                    }
                } AGGR_FAMILIES_END(afp) ;

		rt_delete(old_rt);
	    } else {
		aggr_rt = rt_change_aspath(aggr_rt,
					   aggr_rt->rt_metric,
					   aggr_rt->rt_metric2,
					   aggr_rt->rt_tag,
					   rtah->rtah_rta_forw->rta_preference,
					   (pref_t) 0,
					   n_gw, routers,
						 (if_addr **) 0,
					   asp);
		rt_refresh(aggr_rt);
	    }
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
	    if (asp) {
		ASPATH_FREE(asp);
	    }
#endif	/* PROTO_ASPATHS */
	    assert(aggr_rt);
	}

	/* Zero this pointer so we will skip this route later */
	BIT_RESET(rtah->rtah_flags, RTAHF_ONLIST|RTAHF_CHANGED);
}

/*****************************************************************************/
/* Search for aggregate route (if any) covering this contributor
 * Called by rt_aggregate_flash_contributor() 
 */
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
static rt_entry *
rt_aggregate_match_contributor(rt_entry *new_rt, rt_head *rth, dest_mask **dmp,
    as_path **new_aspp, pref_t *preferencep)
#else	/* PROTO_ASPATHS */
static rt_entry *
rt_aggregate_match_contributor(rt_entry *new_rt, rt_head *rth, dest_mask **dmp,
    pref_t *preferencep)
#endif
{
	rt_entry *aggr_rt = (rt_entry *) 0;
	*preferencep = (pref_t) RTPREF_AGGREGATE;

	/* If we have a new route, search policy for a match */
	if (new_rt && RT_IFAP(new_rt)
	    && (!new_rt->rt_n_gw
		|| !BIT_TEST(RT_IFAP(new_rt)->ifa_state, IFS_LOOPBACK))) {
	    adv_entry *aggr;

	    AGGR_FAMILIES(afp) {
		/* Skip families that don't apply */
		if (afp->rtaf_family == socktype(rth->rth_dest)
		    && (aggr = adv_aggregate_match(*afp->rtaf_list, new_rt, preferencep))) {
		    /* Found one */
			    
		    *dmp = adv_dml_get_dm(aggr);
		    aggr_rt = (rt_entry *) aggr->adv_result.res_void;
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
		    *new_aspp = new_rt->rt_aspath;
#endif	/* PROTO_ASPATHS */
                    return aggr_rt;
		}
	    } AGGR_FAMILIES_END(afp) ;
	}

	/* No match */
	*dmp = (dest_mask *) 0;
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
	*new_aspp = (as_path *) 0;
#endif	/* PROTO_ASPATHS */

	return aggr_rt;
}

/*****************************************************************************/
/* Called by rt_aggregate_flash() 
 * Delete this route from contributor list 
 */
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
static void
rt_aggregate_delete_contributor(register rt_head *rth, rt_entry *old_rt,
    as_path *old_asp)
#else
static void
rt_aggregate_delete_contributor(register rt_head *rth, rt_entry *old_rt)
#endif
{
    rt_aggr_entry *rta = rth->rth_aggregate, *rtb;
    rt_aggr_head *rtah = rta->rta_head;
    task *tp = rt_aggregate_task;

    /* Release the route */
    rtbit_reset(old_rt, tp->task_rtbit);

    /* Remove this entry from the queue */
    REMQUE(rta);

#if (defined(PROTO_BGP) || defined(PROTO_MPBGP)) && defined(GATED_MEMBER)
    if (!BIT_TEST(old_rt->rt_state, RTS_AGGR)) {
	goto Done;
    }
    /*
     * If we are keeping track of options for this aggregate, and
     * this route is from a protocol where that matters, and
     * it is the last matching route, and we have routes that failed
     * only because of options...
     */
    if (BIT_TEST(rtah->rtah_flags, RTAHF_BGP) && old_rt->rt_gwp->gw_proto
	== RTPROTO_BGP && !--(rtah->rtah_matched) && rtah->rtah_failed_forw !=
	&rtah->rtah_failed) {
	    /*
	     * Take all of the failed contributors, and throw them
	     * onto the change list for re-evaluation, if they're not
	     * already on the change list.
	     */
	    AGGR_LIST(&rtah->rtah_failed, rtb) {
		REMQUE(rtb);
		rtbit_reset(rtb->rta_rt, tp->task_rtbit);
		rtb->rta_rt->rt_head->rth_aggregate = NULL;
		if (!BIT_TEST(rtb->rta_rt->rt_head->rth_state, RTS_ONLIST)) {
			BIT_SET(rtb->rta_rt->rt_head->rth_state, RTS_ONLIST);
			RTLIST_ADD(rt_aggregate_contrib_changes,
			    rtb->rta_rt->rt_head);
		}
		task_block_free(rt_aggregate_entry_block, (void_t) rtb);
	    } AGGR_LIST_END(&rtah->rtah_failed, rtb);
    }
#endif /* defined(PROTO_BGP) || defined(PROTO_MPBGP) */
    /* Reset rib bits to the union of other contributors' ribs */
    RTP_RESET_ELIGIBLE(rt_aggregate_rtparms);
    AGGR_LIST(&rta->rta_head->rtah_rta, rtb) {
#ifndef    EXTENDED_RIBS
	rt_aggregate_rtparms.rtp_state |= (rtb->rta_rt->rt_state
	 & RTS_ELIGIBLE_RIBS & rtb->rta_head->rtah_flags);
#else   /* EXTENDED_RIBS */
	rt_aggregate_rtparms.rtp_eligible_ribs 
         |= (rtb->rta_rt->rt_eligible_ribs & rtb->rta_head->rtah_eligible_ribs);
#endif  /* EXTENDED_RIBS */
    } AGGR_LIST_END(&rta->rta_head->rtah_rta, rtb);

    /* Update the aggregate route */
    RT_CHANGE(rta->rta_head->rtah_rta_rt, rta->rta_head, old_asp, 0);

Done:
    /* Free the block and reset pointers to it */
    task_block_free(rt_aggregate_entry_block, (void_t) rta);
    rth->rth_aggregate = (rt_aggr_entry *) 0;
}

/*****************************************************************************/
/* Called by rt_aggregate_flash() 
 * Delete this route from contributor list 
 */
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
static void
rt_aggregate_add_contributor(register rt_head *rth, rt_entry *new_rt,
    rt_entry *aggr_rt, pref_t preference, as_path *new_asp)
#else
static void
rt_aggregate_add_contributor(register rt_head *rth, rt_entry *new_rt,
    rt_entry *aggr_rt, pref_t preference)
#endif
{
    register rt_aggr_entry *rta1;
    rt_aggr_entry *rta;
    rt_aggr_head *rtah;
    task *tp = rt_aggregate_task;
    int matched = TRUE;

    /* Add this route to the contributor list */

    /* We stored the aggregate route pointer in the policy structure */
    assert(aggr_rt);

    /* Get aggregate head pointer */
    rtah = rt_aggregate_head(aggr_rt);

    /* Head better be there and this route must not be a contributor */
    assert(rtah && !rth->rth_aggregate);

    /* Get a block */
    rth->rth_aggregate = rta = (rt_aggr_entry *) task_block_alloc(rt_aggregate_entry_block);

    /* Set our bit on this route so it does not go away */
    /* without us noticing */
    rtbit_set(new_rt, tp->task_rtbit);

    /* Link the list entry to us */
    rta->rta_rt = new_rt;

    /* Set the preference */
    rta->rta_preference = preference;

#if (defined(PROTO_BGP) || defined(PROTO_MPBGP)) && defined(GATED_MEMBER)
    if (!rt_aggregate_options_match(new_rt,rtah)) {
	    matched = FALSE;
	    /* Add this route to the failed contributor list */
	    for (rta1 = rtah->rtah_failed_back; rta1 != &rtah->rtah_failed;
		rta1 = rta1->rta_back) {
		    if (rta1->rta_rt->rt_aspath->nexthop <
			new_rt->rt_aspath->nexthop) {
			    break;
		    } else if (rta1->rta_rt->rt_aspath->nexthop ==
			new_rt->rt_aspath->nexthop) {
			    if (rta1->rta_rt->rt_aspath->path_med <
				new_rt->rt_aspath->path_med) {
				    break;
			    }
		    }
	    }
    } else {
	if (new_rt->rt_gwp->gw_proto == RTPROTO_BGP) {
		rtah->rtah_matched++;
	}
#endif /* defined(PROTO_BGP) || defined(PROTO_MPBGP) */
        /* Find a good place, insert us and point back to the head */
        for (rta1 = rtah->rtah_rta.rta_back; rta1 != &rtah->rtah_rta;
	    rta1 = rta1->rta_back) {
		if (rta1->rta_preference < preference
	    	    || (rta1->rta_preference == preference
		    && rta1->rta_rt->rt_preference < new_rt->rt_preference)) {
	    		/* Insert after this one */

	    		break;
		}
    	}
#if (defined(PROTO_BGP) || defined(PROTO_MPBGP)) && defined(GATED_MEMBER)
    }
#endif /* defined(PROTO_BGP) || defined(PROTO_MPBGP) */
    INSQUE(rta, rta1);
    rta->rta_head = rtah;

    if (matched) {
    /* Update rib bits */
#ifndef    EXTENDED_RIBS
        aggr_rt->rt_state |= (new_rt->rt_state & RTS_ELIGIBLE_RIBS &
	    rtah->rtah_flags);
#else   /* EXTNEDED_RIBS */
    	aggr_rt->rt_eligible_ribs |= (new_rt->rt_eligible_ribs &
	    rtah->rtah_eligible_ribs);
#endif  /* EXTNEDED_RIBS */
	BIT_SET(new_rt->rt_state, RTS_AGGR);

        RT_CHANGE(aggr_rt, rtah, 0, new_asp);
    }
}

/*****************************************************************************/
/* Called by rt_aggregate_flash() 
 * Sees if this route contributes to any aggregates 
 */
static void
rt_aggregate_flash_contributor(register rt_head *rth)
{
    rt_entry *new_rt[NUMRIBS];
    rt_entry *old_rt[NUMRIBS];
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
    as_path *new_asp[NUMRIBS], *old_asp[NUMRIBS];
#endif	/* PROTO_ASPATHS */
    rt_entry *aggr_rt, *tmp_rt;
    dest_mask *dm, *dm2;
    pref_t preference, preference2;
    int add, delete;
    task *tp;
    register int ribi, ribi2;

    tp = rt_aggregate_task;
    aggr_rt = 0;	/* causes real init below */
    preference = 0;	/* quite gcc warnings */
    dm = 0;		/* quite gcc warnings */

    /* Locate aggregate and fill in rib-specific arrays */
    for (ribi=0; ribi<NUMRIBS; ribi++) {
	new_rt[ribi] = rth->rth_rib_active[ribi];
	old_rt[ribi] = rth->rth_rib_last_active[ribi];

	/* We only consider the old route if it was contributing to an */
	/* aggregate. */

	if (old_rt[ribi] && (!rtbit_isset(old_rt[ribi], tp->task_rtbit))) {
		old_rt[ribi] = (rt_entry *) 0;
	}

        tmp_rt = rt_aggregate_match_contributor(new_rt[ribi], rth, &dm2, 
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
	     &new_asp[ribi], 
#endif	/* PROTO_ASPATHS */
	     &preference2);
	if (!aggr_rt) {
		aggr_rt = tmp_rt;
		dm = dm2;
		preference = preference2;
	}

#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
	if (old_rt[ribi]) {
	    rt_changes *rtcp = rth->rth_changes;

	    if (rtcp && BIT_TEST(rtcp->rtc_flags, RTCF_ASPATH)) {
		    old_asp[ribi] = rtcp->rtc_aspath;
	    } else {
		    old_asp[ribi] = old_rt[ribi]->rt_aspath;
	    }
	} else {
	    old_asp[ribi] = (as_path *) 0;
	}
#endif	/* PROTO_ASPATHS */
    }

    for (ribi=0; ribi<NUMRIBS; ribi++) {
	int oldisok=FALSE, newwasok=FALSE;
	rt_aggr_entry *rta = rth->rth_aggregate;
	add = delete = FALSE;

	if (old_rt[ribi]) {
	    for (ribi2=0; ribi2<NUMRIBS; ribi2++) {
	    	if (old_rt[ribi]==new_rt[ribi2]) {
		    oldisok=TRUE;
		    break;
		}
	    }
	}

	if (new_rt[ribi]) {
	    newwasok = rtbit_isset(new_rt[ribi], tp->task_rtbit);
	}

	if (old_rt[ribi] && old_rt[ribi] == new_rt[ribi]) {
	    /* Update the preference */
	    rta->rta_preference = preference;

	    RT_CHANGE(aggr_rt, rt_aggregate_head(aggr_rt), old_asp[ribi], 
	     new_asp[ribi]);
	} else if (old_rt[ribi] && !oldisok && new_rt[ribi] && !newwasok && dm 
	 && aggr_rt == rta->rta_head->rtah_rta_rt) {
	    /* Same aggregate */

	    /* Need to set bit in correct route and fix */
	    /* router pointer in aggregate structure */
		
	    rtbit_set(new_rt[ribi], tp->task_rtbit);
	    rtbit_reset(old_rt[ribi], tp->task_rtbit);
	    rta->rta_rt = new_rt[ribi];

	    /* Update the preference */
	    rta->rta_preference = preference;

	    RT_CHANGE(aggr_rt, rt_aggregate_head(aggr_rt), old_asp[ribi], 
	     new_asp[ribi]);
	} else {
	    if (old_rt[ribi]) {
		delete = TRUE;

	        /* if it's still valid in any other rib, just recalculate
	         * rib bits for aggregate 
	         */
	        if (oldisok) {
		    delete = FALSE;

		    /* Reset rib bits to the union of contributors' ribs */
		    RTP_RESET_ELIGIBLE(rt_aggregate_rtparms);
		    AGGR_LIST(&rta->rta_head->rtah_rta, rta) {
#ifndef    EXTENDED_RIBS
		        rt_aggregate_rtparms.rtp_state |= (rta->rta_rt->rt_state
		        & RTS_ELIGIBLE_RIBS & rta->rta_head->rtah_flags);
#else   /* EXTNEDED_RIBS */
		        rt_aggregate_rtparms.rtp_eligible_ribs 
                                      |= (rta->rta_rt->rt_eligible_ribs 
                                          & rta->rta_head->rtah_eligible_ribs);
#endif  /* EXTNEDED_RIBS */
		    } AGGR_LIST_END(&rta->rta_head->rtah_rta, rta);
		    break;
	        }
	    }
	    if (new_rt[ribi]) {
	        /* If route was already contributing (in another rib),
	         * just add rib bit to aggregate 
	         */
	        if (rtbit_isset(new_rt[ribi], tp->task_rtbit)) {
#ifndef    EXTENDED_RIBS
		    if (rta->rta_head->rtah_flags & rib[ribi].eligible)
	    		BIT_SET(aggr_rt->rt_state, rib[ribi].eligible);
#else   /* EXTNEDED_RIBS */
		    if (rta->rta_head->rtah_eligible_ribs & RTRIB_BIT(ribi))
	    		BIT_SET(aggr_rt->rt_eligible_ribs, RTRIB_BIT(ribi));
#endif  /* EXTNEDED_RIBS */
	        } else {
	            add = TRUE;
	        }
	    }
	}

	if (delete) {
	    rt_aggregate_delete_contributor(rth, old_rt[ribi]
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
	    , old_asp[ribi] 
#endif
	    );
	}

	if (add && dm) {
            rt_aggregate_add_contributor(rth, new_rt[ribi], aggr_rt, preference
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
            , new_asp[ribi] 
#endif
            );
	}
    }
}

/*****************************************************************************/
/* This here routine re-evaluates routes that may contribute to aggregate 
 * routes.  It is a bit too complex in order to avoid any unnecessary routine 
 * calls and be as fast as possible.  It does recurse, but only one level deep.
 */
void
rt_aggregate_flash(rt_list *list, u_int starting_depth)
{
    register rt_head *rth;
    task *tp = rt_aggregate_task;
    register u_int depth = starting_depth;

    if (!tp) {
	/* We must be shutting down */
	return;
    }

    if (!starting_depth) {
	rt_aggregate_changes = NULL;
#if (defined(PROTO_BGP) || defined(PROTO_MPBGP)) && defined(GATED_MEMBER)
	rt_aggregate_contrib_changes = NULL;
#endif /* defined(PROTO_BGP) || defined(PROTO_MPBGP)) */
	rt_open(tp);
    }
    
    RT_LIST(rth, list, rt_head) {
       if (!starting_depth && rth->rth_aggregate_depth) {
          rt_aggregate_putonlist(rth);
       } else {
	    /* If this is an aggregate, check to see if it has changed */
	    if (starting_depth && depth == rth->rth_aggregate_depth) {
                rt_aggregate_flash_aggregate(rth);
	        RTLIST_REMOVE(list);
            }

	    /* See if this route contributes to any aggregates */
	    if (!starting_depth || depth == rth->rth_aggregate_depth)
                rt_aggregate_flash_contributor(rth);
       }
    } RT_LIST_END(rth, list, rt_head) ;
#if (defined(PROTO_BGP) || defined(PROTO_MPBGP)) && defined(GATED_MEMBER)
    if (!starting_depth) {
    	RT_LIST(rth, rt_aggregate_contrib_changes, rt_head) {
		/*
		 * Reevaluate all routes that were changed, then
		 * Stick them on the flash list to let everybody else
		 * know that they might have changed.
		 */
		rt_aggregate_flash_contributor(rth);
		RTLIST_REMOVE(rt_aggregate_contrib_changes);
		RTLIST_ADD(list, rth);
	} RT_LIST_END(rth, rt_aggregate_contrib_changes, rt_head);
    }
#endif /* defined(PROTO_BGP) || defined(PROTO_MPBGP) */

    /* If not recursing, process any aggregates we have on our */
    /* private list.  Then close the routing table. */
    if (!starting_depth) {

	if (rt_aggregate_changes) {
	    while (rt_aggregate_changes->rtl_root->rtl_count) {
		/* At end of flash list, go down a level */
		rt_aggregate_flash(rt_aggregate_changes->rtl_root, ++depth);
	    }

	    /* Free the list */
	    RTLIST_RESET(rt_aggregate_changes);
	}
#if (defined(PROTO_BGP) || defined(PROTO_MPBGP)) && defined(GATED_MEMBER)
	RTLIST_RESET(rt_aggregate_contrib_changes);
#endif /* defined(PROTO_BGP) || defined(PROTO_MPBGP) */

	rt_close(tp, (gw_entry *) 0, 0, NULL);
    }
}


/*****************************************************************************/
/* Called by: rt_aggregate_reinit() and rt_aggregate_terminate()
 */
static void
rt_aggregate_delete(rt_entry *aggr_rt)
{
    register rt_aggr_head *rtah = (rt_aggr_head *) rt_aggregate_head(aggr_rt);
    register rt_aggr_entry *rta;
    task *tp = rt_aggregate_task;
    
    /* Remove all routes from list */
    AGGR_LIST(&rtah->rtah_rta, rta) {
	rt_entry *rt = rta->rta_rt;
	rt_head *rth = rt->rt_head;

	rtbit_reset(rt, tp->task_rtbit);
	REMQUE(rta);
	task_block_free(rt_aggregate_entry_block, (void_t) rta);
	(rth)->rth_aggregate = (rt_aggr_entry *) 0;
    } AGGR_LIST_END(&rtah->rtah_rta, rta) ;

#if (defined(PROTO_BGP) || defined(PROTO_MPBGP)) && defined(GATED_MEMBER)
    AGGR_LIST(&rtah->rtah_failed, rta) {
	rt_entry *rt = rta->rta_rt;
	rt_head *rth = rt->rt_head;

	rtbit_reset(rt, tp->task_rtbit);
	REMQUE(rta);
	task_block_free(rt_aggregate_entry_block, (void_t) rta);
	(rth)->rth_aggregate = NULL;
    } AGGR_LIST_END(&rtah->rtah_failed, rta);
#endif /* defined(PROTO_BGP) || defined(PROTO_MPBGP) */

    /* Indicate that there is no longer an aggregate for this destination */
    aggr_rt->rt_head->rth_aggregate_depth = 0;

#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
    aspath_aggregate_free(rtah);
#endif	/* PROTO_ASPATHS */

    task_block_free(rt_aggregate_head_block, aggr_rt->rt_data);
    aggr_rt->rt_data = (void_t) 0;

    rt_delete(aggr_rt);
}

/*****************************************************************************/
/* Called from task.c as a callback */
static void
rt_aggregate_reinit(task *tp)
{
    register rt_entry *rt;
    rtq_entry rtq;

    /* Update tracing */
    trace_freeup(tp->task_trace);
    tp->task_trace = trace_set_global((bits *) 0, (flag_t) 0);

    /* Save the list of routes */
    RTQ_MOVE(rt_aggregate_gwp->gw_rtq, rtq);

    /* Re-init the rt_add parameters; rt_aggregate_init() is only called once
     */
    bzero((caddr_t)&rt_aggregate_rtparms, sizeof(rt_aggregate_rtparms));
    rt_aggregate_rtparms.rtp_gwp = rt_aggregate_gwp;
    rt_aggregate_rtparms.rtp_state = RTS_INTERIOR | RTS_REJECT;
    rt_aggregate_rtparms.rtp_preference = (pref_t) -1;

    rt_open(tp);

    /* Verify that the routes we have all have policy */
    AGGR_FAMILIES(afp) {
	register dest_mask_internal *dmi;
	
	if (!*afp->rtaf_list) {
	    continue;
	}
	
	/* Calculate the depths of all nodes on the tree */
	adv_destmask_depth(*afp->rtaf_list);

	/* Walk the aggregate list and look up the route */
	DMI_WALK_ALL(adv_dml_get_root(*afp->rtaf_list, afp->rtaf_family), dmi,
	    aggr) {
	    u_int depth = aggr->adv_result.res_metric;

	    afp->rtaf_depth = MAX(afp->rtaf_depth, depth);
	    
	    rt = rt_locate_gw(RTS_NETROUTE,
			      adv_dml_get_dm(aggr)->dm_dest,
			      adv_dml_get_dm(aggr)->dm_mask,
			      rt_aggregate_rtparms.rtp_gwp);
	    if (rt) {
		flag_t flags = 0;
		rt_aggr_head *rtah = rt_aggregate_head(rt);
		
		/* Update the route */

		/* A refresh will move it off our list */
		rt_refresh(rt);
		
		/* Update a few things */
		if (BIT_TEST(aggr->adv_flag, ADVF_AGGR_BRIEF)) {
		    BIT_SET(flags, RTAHF_BRIEF);
		}
		if (BIT_TEST(aggr->adv_flag, ADVF_AGGR_GENERATE)) {
		    BIT_SET(flags, RTAHF_GENERATE);
		}
#if (defined(PROTO_BGP) || defined(PROTO_MPBGP)) && defined(GATED_MEMBER)
		if (BIT_TEST(aggr->adv_flag, ADVF_AGGR_BGP)) {
		    BIT_SET(flags, RTAHF_BGP);
		    if (!BIT_TEST(rt->rt_state, RTS_BGP_AGGR)) {
			/* Changing to BGP aggregation */
			rt_aggr_entry *rtae;
			rtah->rtah_matched = 0;
			AGGR_LIST(&rtah->rtah_rta, rtae) {
			   rt_entry *rte = rtae->rta_rt;
			   if (rte->rt_gwp->gw_proto == RTPROTO_BGP) {
				if (!rtah->rtah_matched) {
				    rtah->rtah_matched++;
				    rtah->rtah_med = rte->rt_aspath->path_med;
				    rtah->rtah_nexthop =
					rte->rt_aspath->nexthop;
				} else if (rtah->rtah_med ==
				    rte->rt_aspath->path_med &&
				    rtah->rtah_nexthop ==
				    rte->rt_aspath->nexthop) {
					rtah->rtah_matched++;
				} else {
				    REMQUE(rtae);
				    rte->rt_head->rth_aggregate = NULL;
				    rtbit_reset(rte, tp->task_rtbit);
				    BIT_RESET(rte->rt_state, RTS_AGGR);
				    aspath_aggregate_unlink(rtah,
					rte->rt_aspath);
				    task_block_free(rt_aggregate_entry_block,
					(void_t) rtae);
				}
			   }
			} AGGR_LIST_END(&rtah->rtah_rta, rtae);
		    }
		    BIT_SET(rt->rt_state, RTS_BGP_AGGR);
		} else {
		    if (BIT_TEST(rt->rt_state, RTS_BGP_AGGR)) {
			/* Changing from BGP aggregation */
			rt_aggr_entry *rtae;
			AGGR_LIST(&rtah->rtah_failed, rtae) {
			    rt_entry *rte = rtae->rta_rt;
			    rtbit_reset(rte,tp->task_rtbit);
			    REMQUE(rtae);
			    rte->rt_head->rth_aggregate = NULL;
			    task_block_free(rt_aggregate_entry_block,
				(void_t) rtae);
			} AGGR_LIST_END(&rtah->rtah_failed, rtae);
			rtah->rtah_matched = 0;
		    }
		    BIT_RESET(rt->rt_state, RTS_BGP_AGGR);
		}
#endif /* defined(PROTO_BGP) || defined(PROTO_MPBGP) */
		if (BIT_TEST(aggr->adv_flag, ADVF_AGGR_NOINSTALL)) {
		  BIT_SET(flags, RTAHF_NOINSTALL);
		}
		if (!BIT_MASK_MATCH(flags, rtah->rtah_flags, RTAHF_BRIEF|
		    RTAHF_GENERATE|RTAHF_NOINSTALL|RTAHF_BGP)) {
		    BIT_RESET(rtah->rtah_flags, RTAHF_BRIEF|RTAHF_GENERATE|
		        RTAHF_NOINSTALL|RTAHF_BGP);
		    BIT_SET(rtah->rtah_flags, RTAHF_CHANGED|flags);
		}
	    } else {	    
		rt_aggr_head *rtah;

		/* Need to add a route */

		rt_aggregate_rtparms.rtp_dest = adv_dml_get_dm(aggr)->dm_dest;
		rt_aggregate_rtparms.rtp_dest_mask =
		    adv_dml_get_dm(aggr)->dm_mask;

		/* Allocate rt_data info plus head of list */
		rtah = (rt_aggr_head *) (rt_aggregate_rtparms.rtp_rtd = task_block_alloc(rt_aggregate_head_block));
		rtah->rtah_rta_forw = rtah->rtah_rta_back = &rtah->rtah_rta;
		rtah->rtah_rta_preference = (pref_t) -1;	/* So aggr_rt becomes hidden */
#if (defined(PROTO_BGP) || defined(PROTO_MPBGP)) && defined(GATED_MEMBER)
		rtah->rtah_failed_forw = rtah->rtah_failed_back =
		    &rtah->rtah_failed;
		rtah->rtah_matched = 0;
		if (BIT_TEST(aggr->adv_flag, ADVF_AGGR_BGP)) {
		    BIT_SET(rtah->rtah_flags, RTAHF_BGP);
		    BIT_SET(rt_aggregate_rtparms.rtp_state, RTS_BGP_AGGR);
		}
#endif /* defined(PROTO_BGP) || defined(PROTO_MPBGP) */
		if (BIT_TEST(aggr->adv_flag, ADVF_AGGR_BRIEF)) {
		    BIT_SET(rtah->rtah_flags, RTAHF_BRIEF);
		}
		if (BIT_TEST(aggr->adv_flag, ADVF_AGGR_GENERATE)) {
		    BIT_SET(rtah->rtah_flags, RTAHF_GENERATE);
		}

		/* Save rib limit bitmask.*/
		{
#ifndef    EXTENDED_RIBS
		    register int ribi;
		    for (ribi=0; ribi<NUMRIBS; ribi++) {
			if (aggr->adv_flag & rib[ribi].advbit)
			    rtah->rtah_flags |= rib[ribi].eligible;
		    }
#else   /* EXTNEDED_RIBS */
                    rtah->rtah_eligible_ribs |= aggr->adv_result.res_flag;
#endif  /* EXTNEDED_RIBS */
		}

		if (BIT_TEST(aggr->adv_flag, ADVF_AGGR_NOINSTALL)) {
		  BIT_SET(rtah->rtah_flags, RTAHF_NOINSTALL);
		  BIT_SET(rt_aggregate_rtparms.rtp_state, RTS_NOTINSTALL);
		} else {
		  BIT_RESET(rt_aggregate_rtparms.rtp_state, RTS_NOTINSTALL);
		}

		/* There aren't any contributors yet, so clear all rib bits */
                RTP_RESET_ELIGIBLE(rt_aggregate_rtparms);

		/* Now add it to the routing table */
		rt = rtah->rtah_rta_rt = rt_add(&rt_aggregate_rtparms);
		assert(rt);
	    }

	    /* Save the pointer to the route */
	    aggr->adv_result.res_void = (void_t) rt;

	    /* Save the depth */
	    rt->rt_head->rth_aggregate_depth = depth;
	} DMI_WALK_ALL_END(adv_dml_get_root(*afp->rtaf_list,
	    afp->rtaf_family), dmi, aggr) ;

    } AGGR_FAMILIES_END(afp) ;

    /* Now delete any routes that were not refreshed */
    RTQ_LIST(&rtq, rt) {
	rt_aggregate_delete(rt);
    } RTQ_LIST_END(&rtq, rt);

    rt_close(tp, (gw_entry *) 0, 0, NULL);
}


/*****************************************************************************/
/* Called from task.c as a callback, and by rt_aggregate_terminate() */
static void
rt_aggregate_cleanup(task *tp)
{

    AGGR_FAMILIES(afp) {
	if (*afp->rtaf_list) {
	    adv_free_list(*afp->rtaf_list);
	    *afp->rtaf_list = (adv_entry *) 0;
	}
	afp->rtaf_depth = 0;
    } AGGR_FAMILIES_END(afp) ;

    
    /* Cleanup our tracing */
    trace_freeup(tp->task_trace);
}


/*****************************************************************************/
/* Called from task.c as a callback */
static void
rt_aggregate_terminate(task *tp)
{
    register rt_entry *rt;

    rt_open(tp);
    
    /* Delete all our routes */
    RTQ_LIST(&rt_aggregate_gwp->gw_rtq, rt) {
	rt_aggregate_delete(rt);
    } RTQ_LIST_END(&rt_aggregate_gwp->gw_rtq, rt) ;

    rt_close(tp, (gw_entry *) 0, 0, NULL);

    /* Free policy and other cleanup */
    rt_aggregate_cleanup(tp);
    
    task_delete(tp);
    rt_aggregate_task = (task *) 0;
}


/**/

/*****************************************************************************/
/* Called from task.c as a callback */
static void
rt_aggregate_dump(task *tp, FILE *fp)
{
    /* For each address family... */
    AGGR_FAMILIES(afp) {
	register dest_mask_internal *dmi;

	if (!*afp->rtaf_list) {
	    continue;
	}
	
	(void) fprintf(fp, "\tAggregation policy for %s, maximum depth %u:\n\n",
#ifndef PROTO_INET6
		       trace_state(task_domain_bits, afp->rtaf_family),
#else  /* PROTO_INET6 */
	               trace_value(task_domain_bits, afp->rtaf_family),
#endif /* PROTO_INET6 */
		       afp->rtaf_depth);

	DMI_WALK_ALL(adv_dml_get_root(*afp->rtaf_list,
	    afp->rtaf_family), dmi, aggr) {
	    adv_entry *proto;

	    (void) fprintf(fp, "\t\t%A/%A",
			   adv_dml_get_dm(aggr)->dm_dest,
			   adv_dml_get_dm(aggr)->dm_mask);
	    if (BIT_TEST(aggr->adv_flag, ADVF_AGGR_BRIEF)) {
		(void) fprintf(fp, " brief");
	    }
#if (defined(PROTO_BGP) || defined(PROTO_MPBGP)) && defined(GATED_MEMBER)
	    if (BIT_TEST(aggr->adv_flag, ADVF_AGGR_BGP)) {
		(void) fprintf(fp, " bgpaggr");
	    }
#endif /* defined(PROTO_BGP) || defined(PROTO_MPBGP) */
	    if (BIT_TEST(aggr->adv_flag, ADVF_AGGR_GENERATE)) {
		(void) fprintf(fp, " generate");
	    }
	    if (BIT_TEST(aggr->adv_flag, ADVF_AGGR_NOINSTALL)) {
	      (void) fprintf(fp, " noinstall");
	    }

	    /* Show ribs */
	    {
		register int ribi;
		for (ribi=0; ribi<NUMRIBS; ribi++) {
#ifndef    EXTENDED_RIBS
		    if (BIT_TEST(aggr->adv_flag, rib[ribi].advbit)) {
			(void) fprintf(fp, " %s", rib[ribi].name);
#else   /* EXTNEDED_RIBS */
		    if (BIT_TEST(aggr->adv_result.res_flag, RTRIB_BIT(ribi))) {
			(void) fprintf(fp, " %s", rib_names[ribi]);
#endif  /* EXTNEDED_RIBS */
		    }
		}
	    }

	    if (BIT_TEST(aggr->adv_flag, ADVF_NO)) {
		(void) fprintf(fp,
			       " restrict\n");
	    } else if (BIT_TEST(aggr->adv_flag, ADVFOT_PREFERENCE)) {
		(void) fprintf(fp,
			       " preference %d\n",
			       aggr->adv_result.res_preference);
	    } else {
		(void) fprintf(fp, "\n");
	    }

	    ADV_LIST(aggr->adv_list, proto) {
		(void) fprintf(fp, "\t\t\tproto %s",
			       trace_state(rt_proto_bits, proto->adv_proto));

		if (BIT_TEST(proto->adv_flag, ADVF_NO)) {
		    (void) fprintf(fp,
				   " restrict\n");
		} else if (BIT_TEST(proto->adv_flag, ADVFOT_PREFERENCE)) {
		    (void) fprintf(fp,
				   " preference %d\n",
				   proto->adv_result.res_preference);
		} else {
		    (void) fprintf(fp, "\n");
		}

		control_dmlist_dump(fp,
				    4,
				    proto->adv_list,
				    (adv_entry *) 0,
				    (adv_entry *) 0);

	    } ADV_LIST_END(aggr->adv_list, proto) ;
	} DMI_WALK_ALL_END(adv_dml_get_root(*afp->rtaf_list,
	    afp->rtaf_family), dmi, aggr) ;

	fprintf(fp, "\n");

    } AGGR_FAMILIES_END(afp) ;

    fprintf(fp, "\n");
}


/*****************************************************************************/
/* Called by rt_dump() */
void
rt_aggregate_rth_dump(FILE *fp, rt_head *rth)
{
    if (rth->rth_aggregate_depth) {
	(void) fprintf(fp,
		       "\t\t\tAggregate Depth: %u\n",
		       rth->rth_aggregate_depth);
    }
    if (rth->rth_aggregate) {
	rt_entry *aggr_rt = rth->rth_aggregate->rta_head->rtah_rta_rt;
		
	(void) fprintf(fp,
		       "\t\t\tAggregate: %A mask %A metric %u preference %d\n",
		       aggr_rt->rt_dest,
		       aggr_rt->rt_dest_mask,
		       aggr_rt->rt_metric,
		       aggr_rt->rt_preference);
    }
}


/*****************************************************************************/
/* Called by rt_dump() */
void
rt_aggregate_rt_dump(FILE *fp, rt_entry *rt)
{
    if (rt->rt_gwp == rt_aggregate_gwp) {
	rt_aggr_entry *rta;
	rt_aggr_head *rtah = rt_aggregate_head(rt);
	int first = TRUE;

	if (rtah->rtah_flags) {
	    (void) fprintf(fp,
			   "\t\t\tFlags: %s\n",
			   trace_bits(rt_aggregate_flag_bits, rtah->rtah_flags));
	}

#if (defined(PROTO_BGP) || defined(PROTO_MPBGP)) && defined(GATED_MEMBER)
	if (BIT_TEST(rtah->rtah_flags, RTAHF_BGP)) {
		if (rtah->rtah_matched) {
			fprintf(fp,"\t\t\t%d matches with Med: %d\tNexthop: %-15A\n",
			   rtah->rtah_matched,rtah->rtah_med,
			   sockbuild_in(0,rtah->rtah_nexthop));
		};
	};
#endif /* defined(PROTO_BGP) || defined(PROTO_MPBGP) */

#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
	if (rtah->rtah_aplp) {
	    aspath_list_dump(fp, rtah);
	}
#endif	/* PROTO_ASPATHS */

	AGGR_LIST(&rtah->rtah_rta, rta) {
	    if (first) {
		first = FALSE;
		(void) fprintf(fp,
			       "\t\t\tContributing Routes:\n");
	    }

	    fprintf(fp,
		    "\t\t\t\t%-15A mask %-15A  proto %s  metric %d preference %d\n",
		    rta->rta_rt->rt_dest,
		    rta->rta_rt->rt_dest_mask,
		    trace_state(rt_proto_bits, rta->rta_rt->rt_gwp->gw_proto),
		    rta->rta_rt->rt_metric,
		    rta->rta_rt->rt_head->rth_aggregate->rta_preference);
	} AGGR_LIST_END(&rtah->rtah_rta, rta);
#if (defined(PROTO_BGP) || defined(PROTO_MPBGP)) && defined(GATED_MEMBER)
	if (!BIT_TEST(rtah->rtah_flags, RTAHF_BGP)) {
		return;
	}
	first = TRUE;
	AGGR_LIST(&rtah->rtah_failed, rta) {
	    if (first) {
		first = FALSE;
		(void) fprintf(fp,
			       "\t\t\tFailed Contributors:\n");
	    }
	    fprintf(fp,
		    "\t\t\t\t%-15A mask %-15A  proto %s  metric %d preference %d\n",
		    rta->rta_rt->rt_dest,
		    rta->rta_rt->rt_dest_mask,
		    trace_state(rt_proto_bits, rta->rta_rt->rt_gwp->gw_proto),
		    rta->rta_rt->rt_metric,
		    rta->rta_rt->rt_head->rth_aggregate->rta_preference);
	} AGGR_LIST_END(&rtah->rtah_rta, rta);
#endif /* defined(PROTO_BGP) || defined(PROTO_MPBGP) */
    }
}

/**/


/*****************************************************************************/
/* Called by rt_family_init() */
void
rt_aggregate_init(void)
{
    task *tp;
    
    /* Allocate the routing table task */
    tp = task_alloc("Aggregate",
		    TASKPRI_RT,
		    trace_set_global((bits *) 0, (flag_t) 0));
    task_set_cleanup(tp, rt_aggregate_cleanup);
    task_set_reinit(tp, rt_aggregate_reinit);
    task_set_dump(tp, rt_aggregate_dump);
    task_set_terminate(tp, rt_aggregate_terminate);
    tp->task_rtbit = rtbit_alloc(tp,
				 FALSE,
				 (size_t) 0,
				 (void_t) 0,
				 (void (*)(FILE *,
					     rt_head *,
					     void_t,
					     const char *)) 0);
    if (!task_create(tp)) {
	task_quit(EINVAL);
    }

    rt_aggregate_task = tp;

    rt_aggregate_gwp = gw_init((gw_entry *) 0,
			       RTPROTO_AGGREGATE,
			       tp,
			       (as_t) 0,
			       (as_t) 0,
			       (sockaddr_un *) 0,
			       GWF_NOHOLD);
    
    /* Init the rt_add init parameters */
    rt_aggregate_rtparms.rtp_n_gw = 0;
    rt_aggregate_rtparms.rtp_gwp = rt_aggregate_gwp;
    rt_aggregate_rtparms.rtp_metric = (metric_t) 0;
    rt_aggregate_rtparms.rtp_tag = (metric_t) 0;
    rt_aggregate_rtparms.rtp_state = RTS_INTERIOR | RTS_REJECT;
    rt_aggregate_rtparms.rtp_preference = (pref_t) -1;

    rt_aggregate_entry_block = task_block_init(sizeof (rt_aggr_entry), "rt_aggr_entry");
    rt_aggregate_head_block = task_block_init(sizeof (rt_aggr_head), "rt_aggr_head");
}
