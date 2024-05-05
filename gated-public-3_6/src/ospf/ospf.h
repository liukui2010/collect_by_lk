/*
 * Gated Release 4.x, 5.x, 6.x, 7.x
 * 
 * $Id: ospf.h,v 1.9 2000/02/18 01:49:41 naamato Exp $
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
 * ------------------------------------------------------------------------
 * 
 *                 U   U M   M DDDD     OOOOO SSSSS PPPPP FFFFF
 *                 U   U MM MM D   D    O   O S     P   P F
 *                 U   U M M M D   D    O   O  SSS  PPPPP FFFF
 *                 U   U M M M D   D    O   O     S P     F
 *                  UUU  M M M DDDD     OOOOO SSSSS P     F
 * 
 *     		          Copyright 1989, 1990, 1991
 *     	       The University of Maryland, College Park, Maryland.
 * 
 * 			    All Rights Reserved
 * 
 *      The University of Maryland College Park ("UMCP") is the owner of all
 *      right, title and interest in and to UMD OSPF (the "Software").
 *      Permission to use, copy and modify the Software and its documentation
 *      solely for non-commercial purposes is granted subject to the following
 *      terms and conditions:
 * 
 *      1. This copyright notice and these terms shall appear in all copies
 * 	 of the Software and its supporting documentation.
 * 
 *      2. The Software shall not be distributed, sold or used in any way in
 * 	 a commercial product, without UMCP's prior written consent.
 * 
 *      3. The origin of this software may not be misrepresented, either by
 *         explicit claim or by omission.
 * 
 *      4. Modified or altered versions must be plainly marked as such, and
 * 	 must not be misrepresented as being the original software.
 * 
 *      5. The Software is provided "AS IS". User acknowledges that the
 *         Software has been developed for research purposes only. User
 * 	 agrees that use of the Software is at user's own risk. UMCP
 * 	 disclaims all warrenties, express and implied, including but
 * 	 not limited to, the implied warranties of merchantability, and
 * 	 fitness for a particular purpose.
 * 
 *     Royalty-free licenses to redistribute UMD OSPF are available from
 *     The University Of Maryland, College Park.
 *       For details contact:
 * 	        Office of Technology Liaison
 * 		4312 Knox Road
 * 		University Of Maryland
 * 		College Park, Maryland 20742
 * 		     (301) 405-4209
 * 		FAX: (301) 314-9871
 * 
 *     This software was written by Rob Coltun
 *      rcoltun@ni.umd.edu
 *
 * __END_OF_COPYRIGHT__
 */

#include "ospf_log.h"

/*
 * state transition routines from ospf_state.c
 */

/* state and event ranges - states.c */

#define	NINTF_STATES	7
#define	NINTF_EVENTS	7

#define NNBR_STATES	8
#define NNBR_EVENTS	14

#include "ospf_rtab.h"
#include "ospf_timer_calls.h"	/* timer calls */
#include "ospf_pkts.h"		/* packet formats */
#include "ospf_lsdb.h"		/* link-state database */
#include "ospf_const.h"		/* OSPF constants */

#define OSPF_VERSION 2

#include "ospf_gated.h"


/* Flag first for fast flooding functions or rubber baby buggy bumpers */
#define FLOOD		0
#define DONTFLOOD	1

/* default values */
#define 	OSPF_NBMA_DFLT_HELLO	30
#define  	OSPF_BC_DFLT_HELLO	10
#define 	OSPF_PTP_DFLT_HELLO	30
#define 	OSPF_VIRT_DFLT_HELLO	60

#define ADV_NETNUM(A)  	((A)->ls_hdr.ls_id & (A)->net_mask)
#define RTR_ADV_NETNUM(A)  ((A)->lnk_id & (A)->lnk_data)


/***************************************************************************

	   		PROTOCOL DATA STRUCTURES

****************************************************************************/


struct LSDB_SUM {
    struct LSDB_SUM *next;
    struct OSPF_HDR *dbpkt;	/* for dbsum pkts */
    u_int16 len;		/* length of this pkt including ospf hdr size */
    u_int16 cnt;		/* number of lsdb entries in this pkt */
};

#define LSDB_SUM_NULL ((struct LSDB_SUM *)0)

struct LS_REQ {
    struct LS_REQ *ptr[2];
    u_int32 ls_id;
    u_int32 adv_rtr;
    u_int32 ls_seq;
    u_int16 ls_chksum;
    u_int16 ls_age;
};

#define LS_REQ_NULL ((struct LS_REQ *) 0)


/*
 *		Events causing neighbor state changes
 */

#define		HELLO_RX	0
#define		START		1
#define		TWOWAY		2
#define		ADJ_OK		3
#define		NEGO_DONE	4
#define		EXCH_DONE	5
#define		SEQ_MISMATCH	6
#define		BAD_LS_REQ	7
#define		LOAD_DONE	8
#define		ONEWAY		9
#define		RST_ADJ		10
#define		KILL_NBR	11
#define		INACT_TIMER	12
#define		LLDOWN		13

struct NBR {
    struct NBR *next;
    struct INTF *intf;
#ifdef	notdef
    if_addr *ifap;
#endif	/* notdef */
    u_int8 I_M_MS;		/* for passing init, more and mast/slave bits */
    u_int8 mode;		/* master or slave mode */
#define		SLAVE		1
#define		MASTER		2
#define		SLAVE_HOLD	4	/* holding the last dbsum delay */
    u_int state;
#define		NDOWN		0
#define		NATTEMPT 	1
#define		NINIT		2
#define		N2WAY		3
#define		NEXSTART	4
#define		NEXCHANGE	5
#define		NLOADING	6
#define		NFULL		7

    u_int32 seq;
    sockaddr_un *nbr_id;
#define	NBR_ID(nbr)	sock2ip((nbr)->nbr_id)
    sockaddr_un *nbr_addr;
#define	NBR_ADDR(nbr)	sock2ip((nbr)->nbr_addr)
    struct NH_BLOCK *nbr_nh;	/* The NH entry we installed for this neighbor */
    u_int32 nbr_sequence;	/* The last received sequence */
    time_t last_hello;		/* time of rx last hello */
    time_t last_exch;		/* time rx last exchange - hold tmr */
    /* for multi-access nets */
    u_int16 pri;		/* 0 means not elig */
    u_int16 rtcnt;		/* retrans queue cnt */
    u_int32 dr;
    u_int32 bdr;
    struct ospf_lsdb_list retrans[OSPF_HASH_QUEUE];	/* LSAs waiting for acks */
    u_int16 dbcnt;		/* dbsum queue cnt */
    u_int16 reqcnt;		/* ls_req queue cnt */
    struct LSDB_SUM *dbsum;	/* dbsum pkts that make up area db */
    struct LS_REQ *ls_req[6];	/* the ones this rtr wants from this nbr */
    int events;
};

#define	REM_NBR_RETRANS(nbr)	if ((nbr)->rtcnt) rem_nbr_retrans(nbr);

#define	NBRNULL	((struct NBR *) 0)

#define	NBRS_LIST(nbr, intf)	for (nbr = FirstNbr(intf); nbr; nbr = nbr->next)
#define	NBRS_LIST_END(nbr, intf)

#define NO_REQ(N)      ((N)->reqcnt == 0)

/* txpkt defines for NBMA sends */
#define ALL_UP_NBRS 	1
#define ALL_ELIG_NBRS   2
#define ALL_EXCH_NBRS   3
#define DR_and_BDR	4


/*
 * 		Events causing IF state changes
 */
#define		INTF_UP		0
#define		WAIT_TIMER	1
#define		BACKUP_SEEN	2
#define		NBR_CHANGE	3
#define		LOOP_IND	4
#define		UNLOOP_IND	5
#define		INTF_DOWN	6


typedef struct _ospf_nbr_node {
    struct _ospf_nbr_node *left;
    struct _ospf_nbr_node *right;
    struct NBR *ospf_nbr_nbr;
    u_int32 ospf_nbr_mask;		/* Bit to test */
    u_int32 ospf_nbr_key;		/* Address, in host byte order */
} ospf_nbr_node;

/*
 * OSPF Authentication constants and structs
 */

/*
 * old configs allows 2 simple auth keys to be given.  These are
 * represented by the ID's OSPF_AUTH_FIRST_ID and OSPF_AUTH_SECOND_ID.
 * These id's are mutually exclusive with MD5.  Therefore an interface
 * can have either 1 or both of FIRST_ID and SECOND_ID or neither and
 * instead a list of up to 256 MD5 keys.
 */
#define	OSPF_MD5_MIN_KEY_ID	0
#define	OSPF_MD5_MAX_KEY_ID	255
#define	OSPF_AUTH_FIRST_ID	256
#define	OSPF_AUTH_SECOND_ID	257

typedef struct {
    time_t tr_start;		/* start time */
    time_t tr_stop;		/* stop time can be (time_t)-1 for inf. */
} ospf_time_range;

/*
 * All keys must be on the "acc" (accept) list and a subset of keys may
 * exist on the "gen" (generate) list.  This fact is used for, amoung
 * other things, free'ing.
 */
typedef struct _ospf_auth {
    struct _ospf_auth *auth_gen_next;	/* next pointer for gen list */
    struct _ospf_auth *auth_acc_next;	/* next pointer for acc list */
    u_int16 auth_type;			/* Type of authentication */
    u_int16 auth_length;		/* Length of key */
    u_int32 auth_id;			/* authentication id (e.g., key id) */
    u_int32 auth_key[OSPF_AUTH_SIZE];	/* Authentication */
    ospf_time_range auth_generate;	/* generating durring this range */
    ospf_time_range auth_accept;	/* accept durring this range */
} ospf_auth;


struct INTF {			/* structure contained within the area */
    struct INTF *intf_forw;
    struct INTF *intf_back;
    if_addr *ifap;
    struct AREA *area;		/* The area I am in */
    flag_t flags;
#define	OSPF_INTFF_NETSCHED		0x01	/* When DR: semaphor for generating LSAs */
#define	OSPF_INTFF_ENABLE		0x02	/* Interface is enabled */
#define	OSPF_INTFF_BUILDNET		0x04	/* Flag to build_net_lsa */
#define	OSPF_INTFF_NBR_CHANGE		0x08	/* Schedule neighbor change */
#define	OSPF_INTFF_MULTICAST		0x10	/* Interface is multicast capable */    
#define	OSPF_INTFF_COSTSET		0x20	/* Cost was manually configured */
#define OSPF_INTFF_PASSIVE		0x100	/* Don't send or receive packets on this interface */
    u_int8 type;
#define		BROADCAST	1
#define		NONBROADCAST	2
#define		POINT_TO_POINT	3
#define		VIRTUAL_LINK	4
    u_int8 state;
#define		IDOWN		0
#define		ILOOPBACK	1
#define		IWAITING	2
#define		IPOINT_TO_POINT	3
#define		IDr		4
#define		IBACKUP		5
#define		IDrOTHER	6
    time_t lock_time;		/* net lock timer */
    u_int16 cost;		/* one for each tos */
    u_int8 pollmod;		/* poll timer is 4 * hello timer */
#define 	STATUS_MOD 4
    u_int8 status_mod;		/* check status 4 * hello timer */
    time_t wait_time;		/* interface is in waiting state */
    time_t hello_timer;		/* interface sends hello (seconds) */
    time_t poll_timer;		/* nbma reduced hello tmr, nbr gone */
    time_t dead_timer;		/* time since last recieved hello */
    time_t up_time;		/* Time interface came up */
    time_t retrans_timer;	/* retransmit interval */
    time_t transdly;		/* seconds to transmit a lsu over IF */
    ospf_auth *auth_gen_list;	/* Authentication */
    ospf_auth *auth_acc_list;	/* Authentication */
    int nbrIcnt;		/* Count of neighbors > NINIT */
    u_int16 nbrEcnt;		/* Count of neighbors >= EXCHAGE */
    u_int16 nbrFcnt;		/* Count of neighbors == NFULL */
    int events;			/* Cound of state changes */
    struct LS_HDRQ acks;	/* Delayed ack list */
    int ack_cnt;		/* Number of acks queued on this interface */
    ospf_nbr_node *nbr_tree;	/* patricia tree for fast nbr lookups */
    struct NBR nbr;		/* linked list of nbrs; if we have to select
				 * dr then head is fake 'this rtr' nbr if
				 * this IF is virtual or point to point use
				 * head of list */
    /* the following are used for interfaces that select dr and bdr */
    u_int16 pri;		/* if priority - if 0 not elig */
    struct AREA *trans_area;	/* Virtual link transit area ndx */
    u_int32 trans_area_id;	/* ID of trans area */
    struct NBR *dr;		/* ptr to dr */
    struct NBR *bdr;		/* ptr to bdr */
    task_timer *timer_hello;		/* Hello timer */
    task_timer *timer_adjacency;	/* Adjacency timer */
    task_timer *timer_retrans;		/* Retransmit timer */
};
#define INTFNULL ((struct INTF *) 0)

/* Multi-access nets use intf nbr structure for electing dr */
#define FirstNbr(I) ( (((I)->type == BROADCAST) ||\
		      ((I)->type == NONBROADCAST)) ?\
			 (I)->nbr.next : &(I)->nbr )

#define	INTF_LIST(i, a) \
	do { \
	    register struct INTF *Xi_next; \
	    for ((i) = (a)->intf.intf_forw; (i) != &(a)->intf; (i) = Xi_next) { \
	        Xi_next = (i)->intf_forw;

#define	INTF_LIST_END(i, a) } } while (0)

#define	VINTF_LIST(vi) \
	do { \
	    register struct INTF *Xvi_next; \
	    for ((vi) = ospf.vl.intf_forw; (vi) != &ospf.vl; (vi) = Xvi_next) {\
		Xvi_next = (vi)->intf_forw;

#define	VINTF_LIST_END(vi) } } while (0)

/*
 *  list of configured hosts
 */
struct OSPF_HOSTS {
    struct OSPF_HOSTS *ptr[2];
    u_int32 host_if_addr;
    u_int32 host_cost;
};

#define HOSTSNULL ((struct OSPF_HOSTS *) 0)

/*
 *  list of nets associated with an area
 */
struct NET_RANGE {
    struct NET_RANGE *ptr[2];
    u_int32 nr_id;		/* normalized nr_net for lsid */
    u_int32 nr_net;
    u_int32 nr_mask;
    u_int32 nr_cost;
    u_int32 nr_status;
#define Advertise	0
#define DoNotAdvertise	1
    rt_entry *nr_rt;
};

#define NRNULL ((struct NET_RANGE *) 0)

#define	RANGE_LIST(nrp, area)	for (nrp = (area)->area_nr.ptr[NEXT]; nrp; nrp = nrp->ptr[NEXT])
#define	RANGE_LIST_END(nr, area)

struct AREA {
    struct AREA *area_forw;
    struct AREA *area_back;
    u_int32 area_id;
    u_int16 area_nrcnt;		/* count of net ranges defined for this area */
    flag_t	area_flags;	/* Various state bits */
#define	OSPF_AREAF_TRANSIT	0x01	/* This is a transit area */
#define	OSPF_AREAF_VIRTUAL_UP	0x02	/* One or more virtual links in this area are up */
#define	OSPF_AREAF_STUB		0x04	/* This is a stub area (NO ASEs) */
#define	OSPF_AREAF_NSSA		0x08	/* This is a not so stubby area */
#define	OSPF_AREAF_STUB_DEFAULT	0x10	/* Inject default into this stub area */

    struct NET_RANGE area_nr;	/* list of component networks */
    u_int32 spfcnt;		/* # times spf has been run for this area */
    u_short db_int_cnt; 	/* Intra + inter LSDB entry count */
    u_short db_cnts[5];		/* Counts for each type of LSDB entry */
    u_int32 db_chksumsum;	/* Checksum sum */
    u_int16 asbr_cnt;		/* count of as bdr rtrs local to this area */
    u_int16 abr_cnt;		/* count of area bdr rtrs local to this area */
    struct OSPF_ROUTE asbrtab;	/* as bdr rtrs within this area */
    struct OSPF_ROUTE abrtab;	/* area bdr rtr within this area */
    u_int16 nbrIcnt;		/* Count of neighbors >= NINIT (area) */
    u_int16 nbrEcnt;		/* neighbors >= EXCHANGE (area) */
    u_int16 nbrFcnt;		/* neighbors == NFULL (area) */
    u_int16 ifcnt;		/* will allocate an array at config */
    adv_entry *intf_policy;	/* Interface matching */
    struct INTF intf;		/* setup at config time  */
    struct LSDB_HEAD *htbl[LS_ASE + 1];	/* the lsdb - 0 is for stub nets */
    struct LSDB_HEAD htbls[LS_ASE][HTBLSIZE];
    struct LSDB_HEAD sum_net_masked[HTBLSIZE];	/* ordered using mask */
#if defined(PROTO_SNMP)  || defined(OSPF_HPMIB)
    u_int	mib_lsdb_size[LS_ASE];
    u_int	mib_lsdb_cnt[LS_ASE];
    struct LSDB	**mib_lsdb_list[LS_ASE];	/* Sorted list of lsdbs */
    u_int32 	mib_chksumsum;
#endif	/* PROTO_SNMP || OSPF_HPMIB */
    u_int16 authtype;		/* authentication type */
    u_int16 ifUcnt;           	/* count of up INTFs include virt lnks for BB */
    struct _qelement spf;		/* area's spf tree; head is this rtr */
    struct _qelement candidates;	/* area'scandidate list for dijkstra */
    struct _qelement asblst;		/* reachable asbs (connected areas) */
    struct _qelement sumnetlst;		/* reachable nets from attached areas */
    struct _qelement interlst;		/* reahcable inter-area routes from backbone */
    struct LSDB *dflt_sum;	/* used if ABRtr and stub area */
    u_int32 dflt_metric;	/* metric for default route */
    struct ospf_lsdb_list *txq;	/* for building and sending sum lsa */
    time_t lock_time;		/* rtr lock timer */
    struct OSPF_HOSTS hosts;
    u_int8 hostcnt;
    u_int8 lsalock;		/* MinLsInterval semaphore for LSA
				 * origination */
    u_int8 spfsched;		/* Schedule flags for spf algorithm */
    u_int8 build_rtr;		/* Schedule build_rtr_lsa */

#define 	RTRSCHED 	0x02
#define 	NETSCHED 	0x04
#define 	INTRASCHED 	0x07
#define 	SUMNETSCHED 	0x08
#define 	SUMASBSCHED 	0x10
#define 	SUMSCHED 	(SUMNETSCHED | SUMASBSCHED)
#define 	INTSCHED 	(INTRASCHED | SUMSCHED)
#define 	ASESCHED 	0x20
#define 	SUMASESCHED 	(SUMSCHED | ASESCHED)
#define 	ALLSCHED 	(INTSCHED | ASESCHED)
#define		FLAG_NO_PROBLEM	0x0
#define		FLAG_BUILD_RTR	0x40
#define		FLAG_BUILD_NET	0x80
#define		FLAG_LOAD_DONE	0x100
#define 	FLAG_FOUND_REQ	0x400
#define		FLAG_NO_BUFS	0x800
#define		FLAG_BAD_REQ	0x1000
#define		FLAG_RERUN_NETSUM 0x2000
#define 	SCHED_BIT(T) 	(1 << (T))
#define 	RTRLOCK  	0x40
#define 	NETLOCK  	0x80

    task_timer *timer_lock;	/* Lock timer */
};

#define AREANULL ((struct AREA *)0)

#define	AREA_LIST(a) \
	do { \
	    register struct AREA *Xarea_next; \
	    for ((a) = ospf.area.area_forw; (a) != &ospf.area; (a) = Xarea_next) { \
		Xarea_next = (a)->area_forw;

#define	AREA_LIST_END(area)	} } while(0)

/* GLOBAL FOR THE PROTOCOL */

struct OSPF {
    sockaddr_un *router_id;	/* My router ID */
#define	MY_ID	sock2ip(ospf.router_id)
    int ospf_admin_stat;	/* Enabled or Disabled */
#define OSPF_ENABLED 	1
#define OSPF_DISABLED 	0
    int nintf;			/* number of ospf interfaces */
    int nbrcnt;			/* number of neighbors known to this router */
    int nbrIcnt;		/* number of neighbors >= Init state */
    int nbrEcnt;		/* number of neighbors >= Exchange state */
    int nbrFcnt;		/* number of neighbors == Full state */
    int acnt;			/* number of areas, 0 will allways be bacbone */
    struct AREA backbone;	/* Backbone area */
    struct AREA area;		/* areas connected to this router - an array
				 * which will be allocated at init time, area
				 * 0 is the backbone */
    int vcnt;			/* number of virtual links */
    int vUPcnt;
    struct INTF vl;		/* list of configured virtal links */
    struct LSDB_HEAD ase[HTBLSIZE];	/* external ls advertisements */
    struct LSDB_HEAD ase_masked[HTBLSIZE];	/* ordered with mask */
#if defined(PROTO_SNMP)  || defined(OSPF_HPMIB)
    u_int	mib_ase_size;
    u_int	mib_ase_cnt;
    struct LSDB	**mib_ase_list;		/* Sorted list of ASEs */
    u_int32 	mib_ase_chksumsum;
#endif	/* PROTO_SNMP || OSPF_HPMIB */
    int ase_age_ndx;		/* starting index of next dbage */
    u_int ase_refresh_bucket;	/* starting bucket of next ASE refresh */
    struct _qelement my_ase_list;	/* self generated ase list */
    struct _qelement db_free_list;	/* list of LSAs to be freed */
    int asbr;			/* as border rtr flag */

    task *task;			/* task for lsa generataion and lsdb aging */
    task_job *spf_job;		/* control block pointer for the SPF job */
    task_timer *timer_ack;
    task_timer *timer_ase;
    task_timer *timer_spf;

    pref_t preference;		/* Preference for intra and inter area routes */
    pref_t preference_ase;	/* Preference for ASE routes */
    flag_t ospf_ribs;		/* ribs to import routes into */
    adv_entry *import_list;	/* Networks to import */
    adv_entry *export_list;	/* Networks to export */
    gw_entry *gwp;		/* Gateway structure for AS Internal routes */
    gw_entry *gwp_ase;		/* Gateway structure for ASE routes */
    metric_t export_metric;	/* Default metric for external routes */
    metric_t export_tag;		/* Default tag for external routes (in host byte order) */
    metric_t export_type;	/* Default type for external routes */
    flag_t   export_flags;	/* External route export flags  */
#define OSPF_EXPORTF_INHERIT	0x00000001
    trace *trace_options;	/* Trace options for OSPF */
    gw_entry *gw_list;		/* List of gateways */
    u_int32 rtab_rev;		/* Rev number of ospf's portion of the rtab */
    time_t export_interval;	/* Minimum interval between ASE exports into OSPF */
    int export_limit;		/* Maximum number of ASEs to import into OSPF per interval */
    int export_queue_size;	/* Number in queue */
    ospf_export_entry export_queue;	/* List of routes queued for exportation into OSPF */
    ospf_export_entry *export_queue_delete; /* Place to insert deleted routes */
    ospf_export_entry *export_queue_change; /* Place to insert changed routes */
#define  OSPF_BACKBONE	0
#define  SPFCNT  	(ospf.rtab_rev)
#define  RTAB_REV	(ospf.rtab_rev)
#define 	GOTBACKBONE	(ospf.vcnt || ospf.backbone.intf_policy)
#define 	IAmBorderRtr	(GOTBACKBONE && ospf.acnt > 1)

    struct NH_BLOCK nh_list;

    ospf_auth *mon_auth;	/* Authentication for monitor packets */

    /* A few stats for the MIB */
    int db_cnt;			/* Total number of entries in the LSDB */
    u_int32 db_chksumsum;	/* Checksum sum of external ASEs */
    u_int32 db_ase_cnt;		/* Number of ASEs in the LSDB */
    u_int32 rx_new_lsa;		/* Number of new LSAs received */
    u_int32 orig_new_lsa;	/* Number of self originated LSAs */
    u_int32 orig_lsa_cnt[LS_MAX];	/* Number of LSAs by type */

    struct OSPF_ROUTE sum_asb_rtab;		/* summary as bdr rtr table */

    int intf_offset;		/* To prevent all the interfaces from firing at the same time */

    /*
     * A single trap is generated per event where an event is a 
     * timer expiring or a packet being received 
     */
#define TRAP_REF_LEN		2
#define TRAP_REF_UPDATE \
	ospf.trap_ref[1] += !++(ospf.trap_ref[0]) ? 1 : 0
#define TRAP_REF_CURRENT(T) \
	( ((T)[0] == ospf.trap_ref[0]) && ((T)[1] == ospf.trap_ref[1]) )
	/* Set T to equal ospf.trap_ref */
#define TRAP_REF_SET(T) \
	{ (T)[0] = ospf.trap_ref[0]; (T)[1] = ospf.trap_ref[1]; }
    u_int32	trap_ref[TRAP_REF_LEN];	

    /* LSDB limits */
    int		lsdb_limit;	/* Configured upper limit of LSDBs */
    int		lsdb_overflow;	/* We're in lsdb overflow mode */
    int		lsdb_hiwater;	/* Hi water mark for LSDB. 95% of lsdb_limit */
    int		lsdb_hiwater_exceeded;

    /* Logging limits */
    u_int	log_first;	/* Log the first # messages per type */
    u_int	log_every;	/* then log one every # messages per type */

#ifdef	notdef
    /* Sort block for INTFs */
    struct IF_SB *if_sb;
    int 	if_sb_nel;

    /* Sort block for virtual INTFs */
    struct IF_SB *virt_if_sb;
    int 	virt_if_sb_nel;

    /* Sort block for NBRs */
    struct NBR 	**nbr_sb;
    int 	nbr_sb_nel;
    u_int16	nbr_sb_not_valid;
    u_int16	nbr_sb_size;

    /* Sort block for lsdb */
    struct LSDB **ls_sb;	/* ptr to array of LSDB ptrs for MIB sorting */
    int	sb_size;		/* Size of allocated ls_sb */
    int	sb_nel;			/* Number of elements in sb */
    struct AREA *sb_area;	/* Area and ls type sorted in ls_sb */
    u_int8	sb_ls_type;
    u_int8	sb_not_valid;	/* If a new db entry has been added within
				   the range of area and type mark sb invalid */
#endif	/* notdef */
}; 

extern struct OSPF ospf;

extern block_t ospf_router_index;	/* For allocating router config block */
extern block_t ospf_intf_index; 	/* For allocating interface structures */
extern block_t ospf_area_index;	/* For allocating area structures */
extern block_t ospf_nbr_index;		/* For allocating neighbor structures */
extern block_t ospf_nbr_node_index;	/* For allocating neighbor tree structures */
extern block_t ospf_nh_block_index;	/* For allocating next hop block */
extern block_t ospf_lsdb_index;
extern block_t ospf_route_index;
extern block_t ospf_dbsum_index;
extern block_t ospf_netrange_index;
extern block_t ospf_hosts_index;
extern block_t ospf_hdrq_index;
extern block_t ospf_lsdblist_index;
extern block_t ospf_nbrlist_index;
extern block_t ospf_lsreq_index;
extern block_t *ospf_lsa_index_4;
extern block_t *ospf_lsa_index_16;
extern block_t ospf_auth_index;

/**/

/* Prototype */
extern int build_dbsum(struct INTF *, struct NBR *);

/* ospf_build_ls.c */
extern int build_rtr_lsa(struct AREA *, struct ospf_lsdb_list **, int);
extern int build_net_lsa(struct INTF *, struct ospf_lsdb_list **, int);
extern int build_sum_net(struct AREA *);
extern int build_sum_asb(struct AREA *, struct OSPF_ROUTE *, struct AREA *);
extern int build_sum(void);
extern int build_inter(struct LSDB *, struct AREA *, int);
extern void build_sum_dflt(struct AREA *);
extern int beyond_max_seq(struct AREA *, struct INTF *, struct LSDB *,
    struct ospf_lsdb_list **, struct ospf_lsdb_list **, int);

/* ospf_choose_dr.c */
extern void ospf_choose_dr(struct INTF *);

/* ospf_flood.c */
extern void area_flood(struct AREA *, struct ospf_lsdb_list *, struct INTF *,
    struct NBR *, int);
extern int self_orig_area_flood(struct AREA *, struct ospf_lsdb_list *, int);

/* ospf_gated_rxmon.c */
extern int ospf_rx_mon(struct MON_HDR *, struct INTF *, sockaddr_un *,
    sockaddr_un *, size_t);

/* ospf_rxlinkup.c */
extern int ospf_rx_lsupdate(struct LS_UPDATE_HDR *, struct NBR *,
    struct INTF *, sockaddr_un *, sockaddr_un *, sockaddr_un *, size_t);

/* ospf_rxpkt.c */
extern void ospf_rxpkt(struct ip *, struct OSPF_HDR *, sockaddr_un *,
    sockaddr_un *);

/* ospf_gated_trace.c */
extern void ospf_trace(struct OSPF_HDR *, size_t, u_int, int, struct INTF *,
    sockaddr_un *, sockaddr_un *, int);
extern void ospf_trace_build(struct AREA *, struct AREA *, union LSA_PTR, int);

/* ospf_lsdb.h */
/* Memory */
extern struct LSDB_SUM * dbsum_alloc(struct INTF *, size_t);
extern void dbsum_free(struct LSDB_SUM *);

#define	findroute(rt, dest, mask) \
{ \
    rt = rt_locate(RTS_NETROUTE, \
		   sockbuild_in(0, (dest)), \
		   inet_mask_locate((mask)), \
		   (flag_t) (RTPROTO_BIT(RTPROTO_OSPF)|RTPROTO_BIT(RTPROTO_OSPF_ASE))); \
}

extern void rvbind(rt_entry *rt, struct LSDB *v, struct AREA *a);
extern void ospf_route_update(rt_entry *rt, struct AREA *a, int level);
extern void ntab_update(struct AREA *, int);
extern int ospf_build_route(struct AREA *, struct LSDB *, rt_entry *, int);

/* ospf_states.c */
extern void (*if_trans[NINTF_EVENTS][NINTF_STATES])(struct INTF *);
extern void (*nbr_trans[NNBR_EVENTS][NNBR_STATES])(struct INTF *, struct NBR *);

/* ospf_spf.c */
extern int ospf_add_parent(struct LSDB *, struct LSDB *, u_int32, struct AREA *, u_int32, struct OSPF_ROUTE *, struct AREA *);
extern void ospf_spf_run(struct AREA *, int);
extern void ospf_spf_sched(void);

/* ospf_spf_leaves.c */
extern int netsum(struct AREA *, int, struct AREA *, int);
extern int asbrsum(struct AREA *, int, struct AREA *, int);
extern int ase(struct AREA *, int, int);

/* ospf_gated_rxmon.c */
extern void ospf_log_rx(int, struct INTF *, sockaddr_un *, sockaddr_un *);
extern void ospf_log_ls_hdr(struct LS_HDR *, const char *, time_t, time_t);
extern sockaddr_un * ospf_addr2str(sockaddr_un *);

/* ospf_newq.c */
extern int rem_db_ptr(struct NBR *, struct LSDB *);
extern struct ospf_lsdb_list * find_db_ptr(struct NBR *, struct LSDB *);
extern int rem_nbr_ptr(struct LSDB *, struct NBR *);
extern void ospf_freeq(struct Q **, block_t);
extern void add_nbr_retrans(struct NBR *, struct LSDB *);
extern void add_db_retrans(struct LSDB *, struct NBR *);
extern void rem_db_retrans(struct LSDB *);
extern void rem_nbr_retrans(struct NBR *);
extern void freeDbSum(struct NBR *);
extern void freeLsReq(struct NBR *);
extern void freeAckList(struct INTF *);

/* ospf_txpkt.c */
extern void send_hello(struct INTF *, struct NBR *, int);
extern void send_exstart(struct INTF *, struct NBR *, int);
extern void send_dbsum(struct INTF *, struct NBR *, int);
extern void send_req(struct INTF *, struct NBR *, int);
extern int send_ack(struct INTF *, struct NBR *, struct LS_HDRQ *);
extern int send_lsu(struct ospf_lsdb_list *, int hash, struct NBR *,
    struct INTF *, int);
extern void range_enq(struct AREA *, struct NET_RANGE *);
extern void host_enq(struct AREA *, struct OSPF_HOSTS *);

/* ospf_nbr.c */
extern void ospf_nbr_add(struct INTF *, struct NBR *);
extern void ospf_nbr_delete(struct INTF *, struct NBR *);
extern void ospf_nbr_dump(FILE *, struct INTF *);

#define	OSPF_NBR_LOOKUP(nbr, intf, addr) \
    do { \
	register ospf_nbr_node *Xdp = (intf)->nbr_tree; \
	register u_int32 Xkey = sock2ip(addr); \
	if (Xdp) { \
	    register u_int32 Xmask; \
	    do { \
		Xmask = Xdp->ospf_nbr_mask; \
		Xdp = (Xkey & Xmask) ? Xdp->right : Xdp->left; \
	    } while (Xmask > Xdp->ospf_nbr_mask) ; \
	} \
	if (Xdp && Xdp->ospf_nbr_key == Xkey) { \
	    (nbr) = Xdp->ospf_nbr_nbr; \
	} else { \
	    (nbr) = (struct NBR *) 0; \
	} \
    } while (0)
	

#ifdef	notdef
extern void ospf_discard_delete(struct NET_RANGE *);
extern int ospf_discard_add(struct NET_RANGE *);
#endif	/* notdef */
