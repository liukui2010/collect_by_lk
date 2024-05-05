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


/* A number is allocated by each routing protocol per destination, one for */
/* link-state protocols, one per peer for peer/neighbor based protocols, */
/* and one per interface and sourcegateway for distance vector protocols. */

/* These bits index into the rt_bits structure in each rt_entry and into */
/* the rt_unreach array of unsigned chars in each rt_head.  The intended */
/* use is that a protocol will set it's bit when it decides to announce a */
/* route to a destination and reset it when it is nolonger announcing it. */
/* When a bit is reset the count of set bits in the rt_entry is */
/* decremented.  When this count reaches zero, the count of routes */
/* announcing a route to this destination is decremented.  If an rt_entry */
/* is scheduled for delete when it's count of announcement bits reaches */
/* zero it is released. */

/* The intended use of the rt_unreach array is that the protocol sets a */
/* value in it when a route to a destination goes into holddown and counts */
/* it down during periodic events (such as sending non-flash updates). */
/* When it's value reaches zero, the announcement bit in the held-down */
/* rt_entry is reset. */

/* Don't change this value here, change it in the config file */
#define	RTTSI_SIZE	16

typedef struct _rt_tsi {
    struct _rt_tsi *tsi_next;
    byte tsi_tsi[RTTSI_SIZE];
} rt_tsi;

typedef struct _rtbit_info {
    task	*rtb_task;	/* Task that owns this bit */
    void_t	rtb_data;	/* Task specific data */
    void (*rtb_dump)(FILE *,
		rt_head *,
		void_t,
		const char *);	/* To display what it means */
    u_short	rtb_index;	/* Offset to bytes */
    u_short	rtb_length;	/* Number of bytes */
} rtbit_info;


struct rtaf_info {
    u_int	rtaf_routes;		/* Count of rt_entrys */
    u_int	rtaf_dests;	       	/* Count of rt_heads */
    u_int	rtaf_actives;		/* Count of active rt_entrys */
    u_int	rtaf_holddowns;		/* Count of holddown rt_entrys */
    u_int	rtaf_hiddens;		/* Count of hidden rt_entrys */
    u_int	rtaf_deletes;		/* Count of deleted rt_entrys */

    /* XXX - Should have all the family specific routines in it */
};
extern struct rtaf_info rtaf_info[AF_MAX];


void rt_table_delete(rt_head *);
void rt_table_add(rt_head *rth);
void rt_table_init(void);
void rt_table_dump(task *,
	   FILE *);
#if	RT_N_MULTIPATH > 1
int rt_routers_compare(rt_entry *, sockaddr_un **);
#else	/* RT_N_MULTIPATH > 1 */
#define	rt_routers_compare(rt, routers)	sockaddrcmp(RT_ROUTER(rt), routers[0])
#endif	/* RT_N_MULTIPATH */

/* Remove the current entry from the change list */
#define	RTLIST_REMOVE(rtl) \
	{ \
	    if (*Xrthp) { \
		*Xrthp = (void_t) 0; \
		(rtl)->rtl_root->rtl_count--; \
	    } \
	}

/* True if this is currently the last entry on the list */
#define	RTLIST_ATEND(rtl) (Xrthp == (rtl)->rtl_fillp && !(rtl)->rtl_next)

extern rt_list *rt_change_list;
extern int rt_n_changes;

#ifdef	PROTO_CMU_SNMP
void rt_mib_init(void);
#endif	/* PROTO_CMU_SNMP */
#ifdef	PROTO_SNMP
void rt_mib_free_rt(rt_entry *);
void init_route_vars(void);
#endif	/* PROTO_SNMP */

/**/

/* Static routes */

void rt_static_cleanup(task *);
void rt_static_reinit(task *);
void rt_static_ifachange(task *);
void rt_static_terminate(task *);
void rt_static_dump(task *, FILE *);
void rt_static_init(task *);
#ifdef        IBM_6611
#define       UNDEFINED_PREF  -1
int rt_static_delete(sockaddr_un *, sockaddr_un *, pref_t, task *);
void rt_static_update(task *);
#endif        /* IBM_6611 */

/**/

/* Aggregate routes */

#define	rt_aggregate_head(aggr_rt)	((rt_aggr_head *) aggr_rt->rt_data)

void rt_aggregate_init(void);
void rt_aggregate_flash(rt_list *, u_int);
void rt_aggregate_rt_dump(FILE *, rt_entry *);
void rt_aggregate_rth_dump(FILE *, rt_head *);
