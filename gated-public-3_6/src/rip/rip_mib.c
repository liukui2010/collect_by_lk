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
 * MIB compilation for rip (oid 1.3.6.1.2.1.23)
 * compiled via mibcomp.pl (Revision: 1.2)
 * on Thu May  2 16:43:48 EDT 1996 on wolfe.bbn.com
 */

#define	INCLUDE_CMU_SNMP
#include "include.h"

#if	defined(PROTO_SNMP) && defined(PROTO_RIP)
#ifdef MIB_RIP

#include "inet/inet.h"
#include "rip.h"

#if defined(PROTO_CMU_SNMP)
#include "snmp_cmu/snmp_cmu.h"
#elif defined(PROTO_SMUX)
#include "smux/smux_snmp.h"
#endif

static u_char *var_rip2GlobalGroup();
static u_char *var_rip2IfStatTable();
static u_char *var_rip2IfConfTable();
static u_char *var_rip2PeerTable();

/* Magic number defines for rip2GlobalGroup */
#define RIP2GLOBALROUTECHANGES                  	1
#define RIP2GLOBALQUERIES                       	2

/* Magic number defines for rip2IfStatTable */
#define RIP2IFSTATADDRESS                       	1
#define RIP2IFSTATRCVBADPACKETS                 	2
#define RIP2IFSTATRCVBADROUTES                  	3
#define RIP2IFSTATSENTUPDATES                   	4
#define RIP2IFSTATSTATUS                        	5

/* Magic number defines for rip2IfConfTable */
#define RIP2IFCONFADDRESS                       	1
#define RIP2IFCONFDOMAIN                        	2
#define RIP2IFCONFAUTHTYPE                      	3
#define RIP2IFCONFAUTHKEY                       	4
#define RIP2IFCONFSEND                          	5
#define RIP2IFCONFRECEIVE                       	6
#define RIP2IFCONFDEFAULTMETRIC                 	7
#define RIP2IFCONFSTATUS                        	8
#define RIP2IFCONFSRCADDRESS                        	9

/* Magic number defines for rip2PeerTable */
#define RIP2PEERADDRESS                         	1
#define RIP2PEERDOMAIN                          	2
#define RIP2PEERLASTUPDATE                      	3
#define RIP2PEERVERSION                         	4
#define RIP2PEERRCVBADPACKETS                   	5
#define RIP2PEERRCVBADROUTES                    	6

static struct variable rip2GlobalGroup_variables[] = {
    {RIP2GLOBALROUTECHANGES, COUNTER, RONLY, var_rip2GlobalGroup, 1, {1}},
    {RIP2GLOBALQUERIES, COUNTER, RONLY, var_rip2GlobalGroup, 1, {2}},
};

static struct variable rip2IfStatTable_variables[] = {
    {RIP2IFSTATADDRESS, IPADDRESS, RONLY, var_rip2IfStatTable, 2, {1, 1}},
    {RIP2IFSTATRCVBADPACKETS, COUNTER, RONLY, var_rip2IfStatTable, 2, {1, 2}},
    {RIP2IFSTATRCVBADROUTES, COUNTER, RONLY, var_rip2IfStatTable, 2, {1, 3}},
    {RIP2IFSTATSENTUPDATES, COUNTER, RONLY, var_rip2IfStatTable, 2, {1, 4}},
    {RIP2IFSTATSTATUS, INTEGER, RWRITE, var_rip2IfStatTable, 2, {1, 5}},
};

static struct variable rip2IfConfTable_variables[] = {
    {RIP2IFCONFADDRESS, IPADDRESS, RONLY, var_rip2IfConfTable, 2, {1, 1}},
    {RIP2IFCONFDOMAIN, STRING, RWRITE, var_rip2IfConfTable, 2, {1, 2}},
    {RIP2IFCONFAUTHTYPE, INTEGER, RWRITE, var_rip2IfConfTable, 2, {1, 3}},
    {RIP2IFCONFAUTHKEY, STRING, RWRITE, var_rip2IfConfTable, 2, {1, 4}},
    {RIP2IFCONFSEND, INTEGER, RWRITE, var_rip2IfConfTable, 2, {1, 5}},
    {RIP2IFCONFRECEIVE, INTEGER, RWRITE, var_rip2IfConfTable, 2, {1, 6}},
    {RIP2IFCONFDEFAULTMETRIC, INTEGER, RWRITE, var_rip2IfConfTable, 2, {1, 7}},
    {RIP2IFCONFSTATUS, INTEGER, RWRITE, var_rip2IfConfTable, 2, {1, 8}},
    {RIP2IFCONFSRCADDRESS, IPADDRESS, RWRITE, var_rip2IfConfTable, 2, {1, 9}},
};

static struct variable rip2PeerTable_variables[] = {
    {RIP2PEERADDRESS, IPADDRESS, RONLY, var_rip2PeerTable, 2, {1, 1}},
    {RIP2PEERDOMAIN, STRING, RONLY, var_rip2PeerTable, 2, {1, 2}},
    {RIP2PEERLASTUPDATE, UINTEGER, RONLY, var_rip2PeerTable, 2, {1, 3}},
    {RIP2PEERVERSION, INTEGER, RONLY, var_rip2PeerTable, 2, {1, 4}},
    {RIP2PEERRCVBADPACKETS, COUNTER, RONLY, var_rip2PeerTable, 2, {1, 5}},
    {RIP2PEERRCVBADROUTES, COUNTER, RONLY, var_rip2PeerTable, 2, {1, 6}},
};

static struct subtree hooked_subtrees[] = {
    {{MIB, 23, 1}, 8,
	(struct variable *)rip2GlobalGroup_variables,
	sizeof(rip2GlobalGroup_variables)/sizeof(*rip2GlobalGroup_variables),
	sizeof(*rip2GlobalGroup_variables)},

    {{MIB, 23, 2}, 8,
	(struct variable *)rip2IfStatTable_variables,
	sizeof(rip2IfStatTable_variables)/sizeof(*rip2IfStatTable_variables),
	sizeof(*rip2IfStatTable_variables)},
    {{MIB, 23, 3}, 8,
	(struct variable *)rip2IfConfTable_variables,
	sizeof(rip2IfConfTable_variables)/sizeof(*rip2IfConfTable_variables),
	sizeof(*rip2IfConfTable_variables)},

    {{MIB, 23, 4}, 8,
	(struct variable *)rip2PeerTable_variables,
	sizeof(rip2PeerTable_variables)/sizeof(*rip2PeerTable_variables),
	sizeof(*rip2PeerTable_variables)}
};


#define	DOMAIN_LENGTH	2

#define	STATUS_Valid		1
#define	STATUS_Invalid		2

#define	AUTHTYPE_NoAuthentication	1
#define	AUTHTYPE_SimplePassword		2

#define	SEND_DoNotSend		1
#define	SEND_RipVersion1	2
#define	SEND_Rip1Compatible	3
#define	SEND_RipVersion2	4    
#define SEND_RipV1Demand        5
#define SEND_RipV2Demand        6

#define	RECEIVE_Rip1	1
#define	RECEIVE_Rip2	2
#define	RECEIVE_Rip1OrRip2	3    
#define RECEIVE_DoNotReceive    4

/*
 * var_rip2GlobalGroup: Callbacks for oid 1.1.3.1.1.3.6.1.2.1.23.1
 * Single-instanced
 */
/* IN- corresponding variable entry */
/* IN/OUT- input name requested, output name found */
/* IN/OUT- length of input and output oid's */
/* IN- TRUE if an exact match was requested */
/* OUT- length of variable or 0 if function returned */
/* OUT- ptr to function to set variable, otherwise 0 */
static u_char *
var_rip2GlobalGroup(register struct variable *vp, oid *name, int *length, 
    int exact, int *var_len, PWM *write_method)
{

    if ( !single_inst_check(vp, name, length, exact) )
        return NULL;

    *var_len = sizeof(int32_return); /* default length */

    switch (vp->magic) {
    case RIP2GLOBALROUTECHANGES:
	/* C type COUNTER, MIB type Counter */
	return O_INTEGER(rip_global_changes);

    case RIP2GLOBALQUERIES:
	/* C type COUNTER, MIB type Counter */
	return O_INTEGER(rip_global_responses);

    default:
	/* The magic number is not valid */
	ERROR_MSG("");
    }
    return NULL;
}
/**/
/* 
 * Routines for handling rip2IfStatTable and rip2IfConfTable. 
 *
 */
/*
 * A sorted list of rip interfaces will be maintained to facilitate retrieval 
 * and implementation of unnumbered point-to-point links. 
 */
struct rip_intf_entry	{
    struct rip_intf_entry *forw;
    struct rip_intf_entry *back;
    u_int32 rip_intf_ip_addr;
    if_addr *rip_ifap;
};

static struct rip_intf_entry rip_intf_list = 	{&rip_intf_list, 
						  &rip_intf_list, 
						  (u_int32) 0,
						  (if_addr *) 0};

#define RIP_INTF_LIST(intfp) for (intfp = rip_intf_list.forw; \
				  intfp != &rip_intf_list; \
				  intfp = intfp->forw) 

#define RIP_INTF_LIST_END(intfp)

static int rip_intf_cnt;		/* Count of rip interfaces. */
static block_t rip_intf_block_index;	/* Storage allocation block index
					   for rip interface list. */ 
static unsigned int *rip_intf_last;	/* Pointer to last interface. */

/*
 * Function which will build a sorted list of all the GateD interfaces 
 * configured for rip. It is invoked during protocol initialization and 
 * when interfaces changes are detected.
 */
void
o_rip_intf_get (void)
{
    register struct rip_intf_entry *rip_intfp; 	/* Pointer to rip interface. */
    register if_addr 	*ifap; 			/* Pointer to GateD interface.*/
    register int unnumbered_index = 0;		/* Index for unnumbered i/f. */
    /* 
     * Free storage allocated to the prior rip inteface list successively 
     * removing the first element of the queue until only the head-tail entry 
     * remains.
     */
    RIP_INTF_LIST(rip_intfp) {
	REMQUE((struct qelem *) rip_intfp);
	task_block_free(rip_intf_block_index, (void_t) rip_intfp);
	rip_intfp = &rip_intf_list;
    } RIP_INTF_LIST_END(rip_intfp);
    
    snmp_last_free(&rip_intf_last);
    rip_intf_cnt = 0;
    /*
     * Scan the list of interface currently known to GateD and build a local 
     * list sorted by IP Address or interface-index (for configurations with 
     * more than one interface having the same local IP address).
     */
    IF_ADDR(ifap) {
	register u_int32 current_intf_addr; 
	register u_int32 save_intf_addr = 0; 
	if (!BIT_TEST(ifap->ifa_state, (IFS_LOOPBACK|IFS_DELETE))) { 
	    /*
	     * Set interface address dependent on whether or not the 
	     * current interface is a Frame Relay Point-to-Point interface,
	     * normal Point-to-Point, or non-Point-to-Point interface.
	     */
	    if (BIT_TEST(ifap->ifa_state, IFS_POINTOPOINT) && 
		BIT_TEST(ifap->ifa_link->ifl_state, IFS_BROADCAST)) {
		current_intf_addr = (ifap->ifa_link->ifl_index << 8);
	    } else {
		current_intf_addr = sock2ip(ifap->ifa_addr_local);
		/* Save the current interface address for duplicate handling. */
		save_intf_addr = current_intf_addr;  
	    }
	    /*
	     * Insert an interface entry onto the rip interface list sorted by
	     * IP address. If the IP address is the same as that of a previous 
	     * interface, use the interface index. The case of multiple PPP 
	     * links originating from the same frame relay physical interface 
	     * is already handled above.
	     */
	   /* Find the correct position in the list to insert the current i/f.*/
	    RIP_INTF_LIST(rip_intfp) {
		if (current_intf_addr < rip_intfp->rip_intf_ip_addr) {
		    break;
		} else if (current_intf_addr == rip_intfp->rip_intf_ip_addr) {
		    if (current_intf_addr == save_intf_addr) {
			current_intf_addr = ifap->ifa_link->ifl_index; 
			/* Re-insert from the list start.	*/
			rip_intfp = &rip_intf_list; 
		    } else {
			current_intf_addr++;
		    }
		}	
	    } RIP_INTF_LIST_END(rip_intfp);

	    /* Actually insert and build the interface entry in our list 
             * of rip interfaces. 
      	     */
	    INSQUE((struct qelem *) task_block_alloc(rip_intf_block_index), rip_intfp->back);
	    rip_intfp->back->rip_ifap = ifap;
	    rip_intfp->back->rip_intf_ip_addr = current_intf_addr;
	    rip_intf_cnt++;
	}
    } IF_ADDR_END(ifap);
}

static struct rip_intf_entry *
o_rip_intf_lookup (oid *iparg, int len, int isnext)
{
    register unsigned int *ip = (unsigned int *) iparg;
    static struct rip_intf_entry *last_rip_intfp;
    static int last_quantum;
    u_int32 requested_intf_ip_addr = (u_int32)  0;
    int requested_intf_index;
    register struct rip_intf_entry *rip_intfp;

    if (last_quantum != snmp_quantum) {
	last_quantum = snmp_quantum;

	if (rip_intf_last) {
	    task_mem_free((task *) 0, (caddr_t) rip_intf_last);
	    rip_intf_last = (unsigned int *) 0;
	}
    }
    /* Return a null pointer if no rip interfaces or get with no ip addr */
    if ( !rip_intf_cnt
         || (!isnext && len < sizeof(struct in_addr)) ) {
	return last_rip_intfp = (struct rip_intf_entry *) 0;
    }
    /*
     * Determine if the last interface is being requested again. 
     */
    if (snmp_last_match(&rip_intf_last, ip, len, isnext)) {
	return last_rip_intfp;
    }

    oid2ipaddr(ip, &requested_intf_ip_addr, len);
    GNTOHL(requested_intf_ip_addr);
    /*
     * The following statement will be needed when the interface lists 
     * in the rip mib are indexed by ip address and interface index. For now,
     * retrieve the first interface with the specified ip address.
     *
     *	intf_index = ip[sizeof (struct in_addr)];
     */
    requested_intf_index = 0;
    RIP_INTF_LIST(rip_intfp) {
        /*
         * If the requested address and index match the current
         * entry's values and an SNMP Get operation is being processed, 
         * return the current entry. 
         */
        if (ntohl(rip_intfp->rip_intf_ip_addr) == requested_intf_ip_addr) {
            /* A match if get or a getnext with incomplete addr specification */
	    if ( !isnext || len < sizeof(struct in_addr) ) {
	        return last_rip_intfp = rip_intfp;
	    }
        } else if (ntohl(rip_intfp->rip_intf_ip_addr) > requested_intf_ip_addr) {
	    /*
	     * If the current entry's address surpasses the requested 
	     * values and the powerful SNMP Get-Next operation is being 
	     * processed, return the current entries. For the SNMP Get 
	     * operation, the search has failed and a no interface will
	     * be returned.
	     */
	    return last_rip_intfp = isnext ? rip_intfp 
				           : (struct rip_intf_entry *) 0;
        }
    } RIP_INTF_LIST_END(rip_intfp);
    /* All interfaces have been scanned without success, a null value 
     * will be returned. 
     */
    return last_rip_intfp = (struct rip_intf_entry *) 0;
}

/**/
/*
 * var_rip2IfStatTable: Callbacks for oid rip.2
 */
/* IN- corresponding variable entry */
/* IN/OUT- input name requested, output name found */
/* IN/OUT- length of input and output oid's */
/* IN- TRUE if an exact match was requested */
/* OUT- length of variable or 0 if function returned */
/* OUT- ptr to function to set variable, otherwise 0 */
static u_char *
var_rip2IfStatTable(register struct variable *vp, oid *name, int *length, 
    int exact, int *var_len, PWM *write_method)
{

/* INDEX { rip2IfStatAddress } */
#define	NDX_SIZE	(sizeof (struct in_addr))

    register struct rip_intf_entry *rip_intfp; 	/* Pointer to rip interface. */
    int len;

    if (exact) {
	if (*length != vp->namelen + NDX_SIZE)
	    return NULL;		/* can not find it */

	if (!(rip_intfp = o_rip_intf_lookup(&name[vp->namelen], NDX_SIZE, 0)))
	    return NULL;		/* can not find it */
    } else {
	
	if ((*length < vp->namelen)
	      || (compare_oid(name, vp->namelen, vp->name, vp->namelen) < 0)) {
	    len = 0;
	} else {
	    len = *length - vp->namelen;
	}
	if (!(rip_intfp = o_rip_intf_lookup(&name[vp->namelen], len, TRUE)))
	    return NULL;		/* nothing to find */
	bcopy(vp->name, name, vp->namelen * sizeof(oid));
	put_ipaddr(rip_intfp->rip_intf_ip_addr, vp->namelen, name);
	*length = vp->namelen + NDX_SIZE;
    }
#undef NDX_SIZE

    *var_len = sizeof(int32_return); /* default length */

    switch (vp->magic) {

    case RIP2IFSTATADDRESS:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR_RAW(rip_intfp->rip_intf_ip_addr);

    case RIP2IFSTATRCVBADPACKETS:
	/* C type COUNTER, MIB type Counter */
	return O_INTEGER((int)rip_intfp->rip_ifap->ifa_rip_bad_packets);

    case RIP2IFSTATRCVBADROUTES:
	/* C type COUNTER, MIB type Counter */
	return O_INTEGER((int)rip_intfp->rip_ifap->ifa_rip_bad_routes);

    case RIP2IFSTATSENTUPDATES:
	/* C type COUNTER, MIB type Counter */
	return O_INTEGER((int)rip_intfp->rip_ifap->ifa_rip_triggered_updates);

    case RIP2IFSTATSTATUS:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(STATUS_Valid);

    default:
	/* The magic number is not valid */
	ERROR_MSG("");
    }
    return NULL;
}
/**/

/*
 * var_rip2IfConfTable: Callbacks for oid rip.3
 */
/* IN- corresponding variable entry */
/* IN/OUT- input name requested, output name found */
/* IN/OUT- length of input and output oid's */
/* IN- TRUE if an exact match was requested */
/* OUT- length of variable or 0 if function returned */
/* OUT- ptr to function to set variable, otherwise 0 */
static u_char *
var_rip2IfConfTable(register struct variable *vp, oid *name, int *length, 
    int exact, int *var_len, PWM *write_method)
{
/* INDEX { rip2IfConfAddress } */
#define	NDX_SIZE	(sizeof (struct in_addr))

    register struct rip_intf_entry *rip_intfp; 	/* Pointer to rip interface. */
    as_t domain = 0;
    int len;

    if (exact) {
	if (*length != vp->namelen + NDX_SIZE)
	    return NULL;		/* can not find it */

	if (!(rip_intfp = o_rip_intf_lookup(&name[vp->namelen], NDX_SIZE, 0)))
	    return NULL;		/* can not find it */
    } else {
	
	if ((*length < vp->namelen)
	      || (compare_oid(name, vp->namelen, vp->name, vp->namelen) < 0)) {
	    len = 0;
	} else {
	    len = *length - vp->namelen;
	}
	if (!(rip_intfp = o_rip_intf_lookup(&name[vp->namelen], len, TRUE)))
	    return NULL;		/* nothing to find */
	bcopy(vp->name, name, vp->namelen * sizeof(oid));
	put_ipaddr(rip_intfp->rip_intf_ip_addr, vp->namelen, name);
	*length = vp->namelen + NDX_SIZE;
    }
#undef NDX_SIZE

/*
 * Constants for rip2IfConfSend and rip2ifConfReceive
 */
#define SEND_doNotSend 1
#define SEND_ripVersion1 2
#define SEND_rip1Compatible 3
#define SEND_ripVersion2 4
#define RECEIVE_rip1 1
#define RECEIVE_rip2 2
#define RECEIVE_rip1OrRip2 3
#define RECEIVE_NoRipIn 4

    *var_len = sizeof(int32_return); /* default length */

    switch (vp->magic) {
    case RIP2IFCONFADDRESS:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR_RAW(rip_intfp->rip_intf_ip_addr);

    case RIP2IFCONFDOMAIN:
	/* C type STRING, MIB type OctetString */
	bcopy((char*)&domain, return_buf, DOMAIN_LENGTH);
        *var_len = DOMAIN_LENGTH;
	return return_buf;

    case RIP2IFCONFAUTHTYPE:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(
	      (struct rip_authinfo *) rip_intfp->rip_ifap->ifa_rip_auth
	      ? ((struct rip_authinfo *) 
				rip_intfp->rip_ifap->ifa_rip_auth)-> auth_type
	      :	AUTHTYPE_NoAuthentication);

    case RIP2IFCONFAUTHKEY:
	/* C type STRING, MIB type OctetString */
	*var_len = 0;
	return return_buf;

    case RIP2IFCONFSEND: {
	/* C type INTEGER, MIB type INTEGER */
	u_int32 conf_send;
	if (BIT_TEST(rip_intfp->rip_ifap->ifa_ps[RTPROTO_RIP].ips_state,IFPS_NOOUT) ||
	    !BIT_TEST(rip_intfp->rip_ifap->ifa_rtactive, RTPROTO_BIT(RTPROTO_RIP))) {
	    conf_send = SEND_doNotSend;
	} else	{
	    if (BIT_TEST(rip_intfp->rip_ifap->ifa_ps[RTPROTO_RIP].ips_state,RIP_IFPS_V2)) {
		if (BIT_TEST(rip_intfp->rip_ifap->ifa_ps[RTPROTO_RIP].ips_state,RIP_IFPS_V2MC)) {
		    conf_send = SEND_ripVersion2;
		} else {
		    conf_send = SEND_rip1Compatible;
		}
       	    } else {
		conf_send = SEND_ripVersion1;
	    }
	}
	return O_INTEGER(conf_send);
    }

    case RIP2IFCONFRECEIVE:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(BIT_TEST(rip_intfp->rip_ifap->ifa_ps[RTPROTO_RIP].ips_state,IFPS_NOIN) ?
	 		  RECEIVE_DoNotReceive : RECEIVE_Rip1OrRip2);
	 
    case RIP2IFCONFDEFAULTMETRIC:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(0);

    case RIP2IFCONFSTATUS:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(STATUS_Valid);

    case RIP2IFCONFSRCADDRESS:
	return O_IPADDR(rip_intfp->rip_ifap->ifa_addr_local);

    default:
	/* The magic number is not valid */
	ERROR_MSG("");
    }
    return NULL;
}

/**/

/* 
 * rip2PeerTable Processing routines.
 */
#define RIP_GW_LIST(p) for (p = rip_gw_list; p != (gw_entry *) 0; p = p->gw_next)
#define RIP_GW_LIST_END(p)

/*
 * Routine to find the specified or next peer gateway. 
 */
static gw_entry *
o_rip_get_peer (oid *iparg, int len, int isnext)
{
    register unsigned int *ip = (unsigned int *) iparg;
    static gw_entry *last_gwp;
    static unsigned int *last;
    static int last_quantum;
    u_int32 rip_peer_addr;
    register gw_entry *p;
    struct timezone time_zone;
    struct timeval current_time;

    if (last_quantum != snmp_quantum) {
	last_quantum = snmp_quantum;

	if (last) {
	    task_mem_free((task *) 0, (caddr_t) last);
	    last = (unsigned int *) 0;
	}
    }

    if (snmp_last_match(&last, ip, len, isnext)) {
	return last_gwp;
    }

    oid2ipaddr(ip, &rip_peer_addr, len);
    GNTOHL(rip_peer_addr);

    /* 
     * Get the current time of day so that gateways from which we have not heard
     * from can be ommitted from the gateways returned.
     */
    gettimeofday(&current_time,
		 &time_zone);

    if (isnext) {
	register gw_entry *new = (gw_entry *) 0;
	register u_int32 new_addr = 0;
	/*
	 * Traverse Rip Gateway List and in one pass find the next element
	 * by finding the Gateway with lowest IP address which exceeds the
	 * the last IP address. This logic is in support of the powerful
	 * SNMP Get Next operation.
	 *
	 * Note that the gateway is not cleaned up as interfaces come and go.
	 * Consequently, we must assure that the gateway is still on an 
	 * attached network and is not a local interface. Additionally, we 
	 * assure that we have heard from the gateway in the last rip expiration
	 * interval (currently 180 seconds).
	 */

	RIP_GW_LIST(p) {
	    if (!if_withlcladdr(p->gw_addr, FALSE)  &&
		if_withdst(p->gw_addr) &&
		((current_time.tv_sec - p->gw_last_update_time.tv_sec) < RIP_T_EXPIRE)){
		register u_int32 cur_addr = ntohl(sock2ip(p->gw_addr));

	        if ((cur_addr > rip_peer_addr
                     || (len < sizeof(struct in_addr) 
                         && cur_addr == rip_peer_addr))
                    && (!new || cur_addr < new_addr)) {
		    new = p;
		    new_addr = cur_addr;
		}
	    }	
	} RIP_GW_LIST_END(p) ;

	last_gwp = new;
    } else {
	/*
	 * Traverse Rip Gateway List simply search for the specified element. 
	 * This logic is in support of the SNMP Get operation. 
	 *
	 * Note that the gateway is not cleaned up as interfaces come and go.
	 * Consequently, we must assure that the gateway is still on an 
	 * attached network and is not a local interface. Additionally, we 
	 * assure that we have heard from the gateway in the last rip expiration 
	 * interval (currently 180 seconds).
	 */
	last_gwp = (gw_entry *) 0;
        if (len < sizeof(struct in_addr))
            return last_gwp;

	RIP_GW_LIST(p) {
	    if (!if_withlcladdr(p->gw_addr, FALSE) &&
		if_withdst(p->gw_addr) &&
		((current_time.tv_sec - p->gw_last_update_time.tv_sec) < RIP_T_EXPIRE)) {
		register u_int32 cur_addr = ntohl(sock2ip(p->gw_addr));
		
		if (cur_addr == rip_peer_addr) {
		    last_gwp = p;
		    break;
		}
	    } 
	} RIP_GW_LIST_END(p) ;
    }
   return last_gwp;
}

/*  */
/*
 * var_rip2PeerTable: Callbacks for oid rip.4
 */
/* IN- corresponding variable entry */
/* IN/OUT- input name requested, output name found */
/* IN/OUT- length of input and output oid's */
/* IN- TRUE if an exact match was requested */
/* OUT- length of variable or 0 if function returned */
/* OUT- ptr to function to set variable, otherwise 0 */
static u_char *
var_rip2PeerTable(register struct variable *vp, oid *name, int *length, 
    int exact, int *var_len, PWM *write_method)
{
/* INDEX { rip2PeerAddress rip2PeerDomain } */
#define	NDX_SIZE	(sizeof (struct in_addr) + DOMAIN_LENGTH)

    gw_entry *gwp;
    as_t domain = 0;	/* It's depricated so always set to 0 */
    int len;

    if (exact) {
	if (*length != vp->namelen + NDX_SIZE)
	    return NULL;		/* can not find it */

	if (!(gwp = o_rip_get_peer(&name[vp->namelen], NDX_SIZE, FALSE)))
	    return NULL;		/* can not find it */
    } else {
	
	if ((*length < vp->namelen)
	      || (compare_oid(name, vp->namelen, vp->name, vp->namelen) < 0)) {
	    len = 0;
	} else {
	    len = *length - vp->namelen;
	}
	if (!(gwp = o_rip_get_peer(&name[vp->namelen], len, TRUE)))
	    return NULL;		/* nothing to find */
	bcopy(vp->name, name, vp->namelen * sizeof(oid));
	put_ipaddr(sock2ip(gwp->gw_addr), vp->namelen, name);
	/* encode domain as a two subid string (after 4 element ipaddr) */
	name[vp->namelen + 4 + 0] = (u_char)((domain >> 8) & 0xff);
	name[vp->namelen + 4 + 1] = (u_char)(domain & 0xff);
	*length = vp->namelen + NDX_SIZE;
    }
#undef NDX_SIZE

    *var_len = sizeof(int32_return); /* default length */

    switch (vp->magic) {

    case RIP2PEERADDRESS:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR(gwp->gw_addr); 

    case RIP2PEERDOMAIN:
	/* C type STRING, MIB type OctetString */
	bcopy((char*)&domain, return_buf, DOMAIN_LENGTH);
	*var_len = DOMAIN_LENGTH;
	return return_buf;

    case RIP2PEERLASTUPDATE: {
	/* C type UINTEGER, MIB type TimeTicks */

	/* 
	 * RFC 1155 Timeticks are defined as the number of hundreths of a second
	 * since some epoch. In the case of rip2PeerLastUpdate, this epoch is 
	 * sysUpTime. Since sysUpTime is not available, we use GateD start time
	 * which should be close to sysUpTime.         
	 */
#define CENTI_SECONDS_IN_SECOND 100
#define NANO_SECOND_ROUNDING_CONSTANT 500000
	u_int32 normalized_last_update_time;
	if (gwp->gw_last_update_time.tv_sec) {
	    normalized_last_update_time = 
		((gwp->gw_last_update_time.tv_sec - time_boot) * 
		 CENTI_SECONDS_IN_SECOND) +
	     (gwp->gw_last_update_time.tv_usec > NANO_SECOND_ROUNDING_CONSTANT);
	} else {
	    normalized_last_update_time = 0;
	}
	return O_INTEGER(normalized_last_update_time);
    }

    case RIP2PEERVERSION:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(gwp->gw_last_version_received);

    case RIP2PEERRCVBADPACKETS:
	/* C type COUNTER, MIB type Counter */
	return O_INTEGER(gwp->gw_bad_packets);

    case RIP2PEERRCVBADROUTES:
	/* C type COUNTER, MIB type Counter */
	return O_INTEGER(gwp->gw_bad_routes);

    default:
	/* The magic number is not valid */
	ERROR_MSG("");
    }
    return NULL;
}

/**/
void 
init_rip_vars(void)
{
    add_all_subtrees(hooked_subtrees,
		     sizeof(hooked_subtrees)/sizeof(struct subtree));
}

void
rip_init_mib (int enabled)
{
    if (enabled) {
	if (!rip_intf_block_index) {
            rip_intf_block_index = task_block_init(sizeof (struct rip_intf_entry
),
                                                   "rip_intf_entry");
        }
    } else {
/* $$$ nothing to do to unregister??? */
    }
}
#endif /* PROTO_SNMP && PROTO_RIP */
#endif /* MIB_RIP */
