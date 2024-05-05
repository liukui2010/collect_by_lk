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
 * MIB compilation for egp (oid mgmt.1.8)
 * compiled via mibcomp.pl (Revision: 1.2)
 * on Fri May 17 09:15:05 EDT 1996 on wolfe.bbn.com
 */

#define	INCLUDE_CMU_SNMP
#include "include.h"

#if	defined(PROTO_EGP) && defined(PROTO_SNMP) 
#include "inet/inet.h"
#include "egp.h"

#if defined(PROTO_CMU_SNMP)
#include "snmp_cmu/snmp_cmu.h"
#elif defined(PROTO_SMUX)
#include "smux/smux_snmp.h"
#endif

static u_char *var_egp();
static u_char *var_egpNeighTable();
#if 0 /* writable variables not handled yet */
static int     writeTrigger();
#endif /* 0 */

/* Magic number defines for egp */
#define EGPINMSGS                               	1
#define EGPINERRORS                             	2
#define EGPOUTMSGS                              	3
#define EGPOUTERRORS                            	4
#define EGPAS                                   	5

/* Magic number defines for egpNeighTable */
#define EGPNEIGHSTATE                           	1
#define EGPNEIGHADDR                            	2
#define EGPNEIGHAS                              	3
#define EGPNEIGHINMSGS                          	4
#define EGPNEIGHINERRS                          	5
#define EGPNEIGHOUTMSGS                         	6
#define EGPNEIGHOUTERRS                         	7
#define EGPNEIGHINERRMSGS                       	8
#define EGPNEIGHOUTERRMSGS                      	9
#define EGPNEIGHSTATEUPS                        	10
#define EGPNEIGHSTATEDOWNS                      	11
#define EGPNEIGHINTERVALHELLO                   	12
#define EGPNEIGHINTERVALPOLL                    	13
#define EGPNEIGHMODE                            	14
#define EGPNEIGHEVENTTRIGGER                    	15

static struct variable egp_variables[] = {
    {EGPINMSGS, COUNTER, RONLY, var_egp, 1, {1}},
    {EGPINERRORS, COUNTER, RONLY, var_egp, 1, {2}},
    {EGPOUTMSGS, COUNTER, RONLY, var_egp, 1, {3}},
    {EGPOUTERRORS, COUNTER, RONLY, var_egp, 1, {4}},

    {EGPNEIGHSTATE, INTEGER, RONLY, var_egpNeighTable, 3, {5, 1, 1}},
    {EGPNEIGHADDR, IPADDRESS, RONLY, var_egpNeighTable, 3, {5, 1, 2}},
    {EGPNEIGHAS, INTEGER, RONLY, var_egpNeighTable, 3, {5, 1, 3}},
    {EGPNEIGHINMSGS, COUNTER, RONLY, var_egpNeighTable, 3, {5, 1, 4}},
    {EGPNEIGHINERRS, COUNTER, RONLY, var_egpNeighTable, 3, {5, 1, 5}},
    {EGPNEIGHOUTMSGS, COUNTER, RONLY, var_egpNeighTable, 3, {5, 1, 6}},
    {EGPNEIGHOUTERRS, COUNTER, RONLY, var_egpNeighTable, 3, {5, 1, 7}},
    {EGPNEIGHINERRMSGS, COUNTER, RONLY, var_egpNeighTable, 3, {5, 1, 8}},
    {EGPNEIGHOUTERRMSGS, COUNTER, RONLY, var_egpNeighTable, 3, {5, 1, 9}},
    {EGPNEIGHSTATEUPS, COUNTER, RONLY, var_egpNeighTable, 3, {5, 1, 10}},
    {EGPNEIGHSTATEDOWNS, COUNTER, RONLY, var_egpNeighTable, 3, {5, 1, 11}},
    {EGPNEIGHINTERVALHELLO, INTEGER, RONLY, var_egpNeighTable, 3, {5, 1, 12}},
    {EGPNEIGHINTERVALPOLL, INTEGER, RONLY, var_egpNeighTable, 3, {5, 1, 13}},
    {EGPNEIGHMODE, INTEGER, RONLY, var_egpNeighTable, 3, {5, 1, 14}},
    {EGPNEIGHEVENTTRIGGER, INTEGER, RWRITE, var_egpNeighTable, 3, {5, 1, 15}},

    {EGPAS, INTEGER, RONLY, var_egp, 1, {6}},
};

#define STATE_IDLE		1
#define STATE_ACQUISITION	2
#define STATE_DOWN		3
#define STATE_UP		4
#define STATE_CEASE		5

static struct subtree hooked_subtrees[] = {
    {{MIB, 8}, 7,
	(struct variable *)egp_variables,
	sizeof(egp_variables)/sizeof(*egp_variables),
	sizeof(*egp_variables)}
};

/*
 * var_egp: Callbacks for oid mgmt.1.8
 * Single-instanced
 */
static u_char *
var_egp(vp, name, length, exact, var_len, write_method)
    register struct variable *vp; /* IN- corresponding variable entry */
    oid *name;         /* IN/OUT- input name requested, output name found */
    int *length;       /* IN/OUT- length of input and output oid's */
    int  exact;        /* IN- TRUE if an exact match was requested */
    int *var_len;      /* OUT- length of variable or 0 if function returned */
    PWM *write_method; /* OUT- ptr to function to set variable, otherwise 0 */
{

    if ( !single_inst_check(vp, name, length, exact) )
        return NULL;

    *var_len = sizeof(int32_return); /* default length */

    switch (vp->magic) {
    case EGPINMSGS:
	/* C type COUNTER, MIB type Counter */
	return O_INTEGER(egp_stats.inmsgs);

    case EGPINERRORS:
	/* C type COUNTER, MIB type Counter */
	return O_INTEGER(egp_stats.inerrors);

    case EGPOUTMSGS:
	/* C type COUNTER, MIB type Counter */
	return O_INTEGER(egp_stats.outmsgs);

    case EGPOUTERRORS:
	/* C type COUNTER, MIB type Counter */
	return O_INTEGER(egp_stats.outerrors);

    case EGPAS:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(inet_autonomous_system);

    default:
	/* The magic number is not valid */
	ERROR_MSG("");
    }
    return NULL;
}
/**/

static egp_neighbor  **egp_sort;	/* Sorted list of pointers to neighbors */
static u_int egp_sort_size = 0;
static egp_neighbor *egp_mib_last_ngp;
static unsigned int *egp_mib_last;


/* Collect the list of egp neighbors and make a sorted list */
void
egp_sort_neighbors (egp_neighbor * old_ngp)
{

    /* XXX - do this with a chain through the peers */

    if (old_ngp
	&& old_ngp == egp_mib_last_ngp) {
	snmp_last_free(&egp_mib_last);
	egp_mib_last_ngp = (egp_neighbor *) 0;
    }

    /* Build a sorted list of neighbors for network monitoring */
    if (egp_sort_size < egp_neighbors) {
	if (egp_sort) {
	    task_mem_free((task *) 0, (void_t) egp_sort);
	}

	egp_sort_size = egp_neighbors;
	egp_sort = (egp_neighbor **) task_mem_calloc((task *) 0, (u_int) (egp_sort_size + 1), sizeof(egp_neighbor *));
    }
    if (egp_neighbors) {
	register egp_neighbor *ngp;
	register egp_neighbor **pl = egp_sort;

	EGP_LIST(ngp) {
	    u_int32 dst = ntohl(sock2ip(ngp->ng_addr));
	    register egp_neighbor **p;

	    for (p = egp_sort;
		 p < pl;
		 p++) {
		if (dst < ntohl(sock2ip((*p)->ng_addr))) {
		    register egp_neighbor **q = pl;

		    /* Copy the list */
		    do {
			*q = *(q - 1);
		    } while (q-- > p) ;

		    break;
		}
	    }

	    *p = ngp;
	    pl++;
	} EGP_LIST_END(ngp);
    }
}


static egp_neighbor *
egp_get_neigh (register unsigned int * ip, u_int len, int isnext)
{
    u_int32 ngp_addr;

    if (snmp_last_match(&egp_mib_last, ip, len, isnext)) {
	return egp_mib_last_ngp;
    }

    if (len) {
	register egp_neighbor **p = egp_sort;
	register egp_neighbor **pl = egp_sort + egp_neighbors;

	oid2ipaddr(ip, &ngp_addr, len);

	GNTOHL(ngp_addr);

	if (isnext) {
	    register egp_neighbor *new = (egp_neighbor *) 0;
	    register u_int32 new_addr = 0;

	    for (; p < pl; p++) {
		register u_int32 cur_addr = ntohl(sock2ip((*p)->ng_addr));

		if ((cur_addr > ngp_addr 
                     || cur_addr == ngp_addr && len < sizeof(struct in_addr))
                    && (!new || cur_addr < new_addr)) {
		    new = *p;
		    new_addr = cur_addr;
		}
	    }

	    egp_mib_last_ngp = new;
	} else {
	    for (; p < pl; p++) {
		register u_int32 cur_addr = ntohl(sock2ip((*p)->ng_addr));
		
		if (cur_addr == ngp_addr) {
		    egp_mib_last_ngp = *p;
		    break;
		} else if (cur_addr > ngp_addr) {
		    egp_mib_last_ngp = (egp_neighbor *) 0;
		    break;
		}
	    }
	}
    } else {
	egp_mib_last_ngp = egp_neighbors ? *egp_sort : (egp_neighbor *) 0;
    }

    return egp_mib_last_ngp;
}

egp_neighbor *saved_ngp_for_write = 0;
int           quantum_for_write = 0;

/*
 * var_egpNeighTable: Callbacks for oid mgmt.1.8.5
 * Entry indexes are
 * unknown
 */
static u_char *
var_egpNeighTable(vp, name, length, exact, var_len, write_method)
    register struct variable *vp; /* IN- corresponding variable entry */
    oid *name;         /* IN/OUT- input name requested, output name found */
    int *length;       /* IN/OUT- length of input and output oid's */
    int  exact;        /* IN- TRUE if an exact match was requested */
    int *var_len;      /* OUT- length of variable or 0 if function returned */
    PWM *write_method; /* OUT- ptr to function to set variable, otherwise 0 */
{
/* INDEX   { egpNeighAddr } */
#define	NDX_SIZE	(int)(sizeof (struct in_addr))
    register egp_neighbor *ngp;
    int len;

    if (exact) {
	if (*length != vp->namelen + NDX_SIZE)
	    return NULL;		/* can not find it */

	if (!(ngp = egp_get_neigh((unsigned int *) &name[vp->namelen], NDX_SIZE, FALSE)))
	    return NULL;		/* can not find it */
    } else {
	
	if ((*length < vp->namelen)
	    || (compare_oid(name, vp->namelen, vp->name, vp->namelen) < 0)) {
	    len = 0;
	} else {
	    len = *length - vp->namelen;
	}
	if (!(ngp = egp_get_neigh((unsigned int *) &name[vp->namelen], len, TRUE)))
	    return NULL;		/* nothing to find */
	bcopy(vp->name, name, vp->namelen * sizeof(oid));
	put_ipaddr(sock2ip(ngp->ng_addr), vp->namelen, name);
	*length = vp->namelen + NDX_SIZE;
    }


    *var_len = sizeof(int32_return); /* default length */

    switch (vp->magic) {
    case EGPNEIGHSTATE: {
	/* C type INTEGER, MIB type INTEGER */
	int state;

	switch (ngp->ng_state) {
	case NGS_IDLE:
	    state = STATE_IDLE;
	    break;
		
	case NGS_ACQUISITION:
	    state = STATE_ACQUISITION;
	    break;
		
	case NGS_DOWN:
	    state = STATE_DOWN;
	    break;
		
	case NGS_UP:
	    state = STATE_UP;
	    break;
		
	case NGS_CEASE:
	    state = STATE_CEASE;
	    break;

	default:
	    state = -1;
	}
	    
	return O_INTEGER(state);
    }

    case EGPNEIGHADDR:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR(ngp->ng_addr);

    case EGPNEIGHAS:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(ngp->ng_peer_as);

    case EGPNEIGHINMSGS:
	/* C type COUNTER, MIB type Counter */
	return O_INTEGER(ngp->ng_stats.inmsgs);

    case EGPNEIGHINERRS:
	/* C type COUNTER, MIB type Counter */
	return O_INTEGER(ngp->ng_stats.inerrors);

    case EGPNEIGHOUTMSGS:
	/* C type COUNTER, MIB type Counter */
	return O_INTEGER(ngp->ng_stats.outmsgs);

    case EGPNEIGHOUTERRS:
	/* C type COUNTER, MIB type Counter */
	return O_INTEGER(ngp->ng_stats.outerrors);

    case EGPNEIGHINERRMSGS:
	/* C type COUNTER, MIB type Counter */
	return O_INTEGER(ngp->ng_stats.inerrmsgs);

    case EGPNEIGHOUTERRMSGS:
	/* C type COUNTER, MIB type Counter */
	return O_INTEGER(ngp->ng_stats.outerrmsgs);

    case EGPNEIGHSTATEUPS:
	/* C type COUNTER, MIB type Counter */
	return O_INTEGER(ngp->ng_stats.stateups);

    case EGPNEIGHSTATEDOWNS:
	/* C type COUNTER, MIB type Counter */
	return O_INTEGER(ngp->ng_stats.statedowns);

    case EGPNEIGHINTERVALHELLO:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(ngp->ng_T1);

    case EGPNEIGHINTERVALPOLL:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(ngp->ng_T2);

    case EGPNEIGHMODE:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(ngp->ng_M);

    case EGPNEIGHEVENTTRIGGER:
	/* C type INTEGER, MIB type INTEGER */
#if 0 /* not yet */
	*write_method = (PWM)writeTrigger;
#endif /* 0 */
	if (write_method)
		*write_method = NULL;
	saved_ngp_for_write = ngp;
	quantum_for_write = snmp_quantum;
	return O_INTEGER(ngp->ng_stats.trigger);

    default:
	/* The magic number is not valid */
	ERROR_MSG("");
    }
    return NULL;
}

#if 0
/* writable variables not supported at this time */

/*
 * Writes the egp trigger variable EGPNEIGHEVENTTRIGGER
 */
static int
writeTrigger(action, var_val, var_val_type, var_val_len, name, name_len)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   oid      *name;
   int      name_len;
{
    int        trigger;
    int        buffersize = 1000;

    if (var_val_type != INTEGER){
	return SNMP_ERR_WRONGTYPE;
    }

    (void) asn_parse_int(var_val, &buffersize, &var_val_type, (u_int32 *) &trigger,
			 sizeof(trigger));

    switch (trigger) {
    case EGP_TRIGGER_START:
    case EGP_TRIGGER_STOP:
	break;

    default:
	return SNMP_ERR_BADVALUE;
    }

    if (quantum_for_write != snmp_quantum
	|| saved_ngp_for_write == (egp_neighbor *)0)
	return SNMP_ERR_GENERR; /* quantum changed or no neighbor */

    if (action == RESERVE1){
	saved_ngp_for_write->reserved_for_set = 0;
    } else if (action == RESERVE2){
	saved_ngp_for_write->reserved_for_set++;
	if (saved_ngp_for_write->reserved_for_set > 1)
	    return SNMP_ERR_INCONSISTENTVALUE;
    } else if (action == COMMIT){
	saved_ngp_for_write->ng_stats.trigger = trigger;
	switch (trigger) {
	case EGP_TRIGGER_START:
	    egp_event_start(saved_ngp_for_write->ng_task);
	    break;

	case EGP_TRIGGER_STOP:
	    /* 
	     * NOTE: calling egp_event_stop() will cause an egpNeighLoss
	     * 	trap to be generated, before the responsePDU is sent.
	     */
	    egp_event_stop(saved_ngp_for_write, EGP_STATUS_GOINGDOWN);
	    break;
	}

    }
    return SNMP_ERR_NOERROR;
}
#endif /* 0 */

/**/

#if 0 /* traps not supported at this time */

/* Traps */
void
egp_trap_neighbor_loss (egp_neighbor * ngp)
{
    /* mib-2.egp.egpNeighTable.egpNeighEntry.egpNeighAddr */
    static oid egpneighaddrOid[] = {1,3,6,1,2,1,8,5,1,2,0,0,0,0};
    oid *oid_addr = &egpneighaddrOid[10]; /* points to the first .0 */
    u_int32 neigh_addr = sock2ip(ngp->ng_addr); /* get neighbor address */
    u_int32 n_neigh_addr = htonl(neigh_addr);

    /* insert the egp neighbor ip address into the oid */
    oid_addr[0] = (u_char)((n_neigh_addr >> 24) & 0xff);
    oid_addr[1] = (u_char)((n_neigh_addr >> 16) & 0xff);
    oid_addr[2] = (u_char)((n_neigh_addr >>  8) & 0xff);
    oid_addr[3] = (u_char)((n_neigh_addr      ) & 0xff);

    snmp_trap_1var((oid*)NULL, 0, SNMP_TRAP_EGPNEIGHBORLOSS, 0,
                   egpneighaddrOid, sizeof(egpneighaddrOid)/sizeof(oid),
                   IPADDRESS, (u_char *)&neigh_addr, 4);
}
#endif /* 0 */

void 
init_egp_vars()
{
    add_all_subtrees(hooked_subtrees,
		     sizeof(hooked_subtrees)/sizeof(struct subtree));
}

/**/

void
egp_mib_init (int enabled)
{
    if (enabled) {
/* $$$ nothing to do to unregister??? */
    } else {
/* $$$ nothing to do to unregister??? */
    }
}

#endif /* PROTO_EGP && PROTO_SNMP */

