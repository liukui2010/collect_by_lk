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

#define INCLUDE_CMU_SNMP
#define	INCLUDE_RT_VAR
#include "include.h"

#if defined(PROTO_SNMP)

#include "inet/inet.h"
#ifdef	PROTO_OSPF
#include "ospf/ospf.h"
#endif	/* PROTO_OSPF */

#if defined(PROTO_CMU_SNMP)
#include "snmp_cmu/snmp_cmu.h"
#elif defined(PROTO_SMUX)
#include "smux/smux_snmp.h"
#endif

/**/

/* IP routine table (MIB-II) */

static u_char *var_ipRouteEntry();
static u_char *var_ipForwardTable();
static u_char *var_ipForwardSingle();

oid snmp_nullSpecific[] = { 0,0};
int snmp_nullSpecificLen = sizeof(snmp_nullSpecific)/sizeof(oid);

/*
 * Common definitions for the ipRoutingTable
 */
#define IPROUTEDEST	1
#define IPROUTEIFINDEX	2
#define IPROUTEMETRIC1	3
#define IPROUTEMETRIC2	4
#define IPROUTEMETRIC3	5
#define IPROUTEMETRIC4	6
#define IPROUTENEXTHOP	7
#define IPROUTETYPE	8
#define IPROUTEPROTO	9
#define IPROUTEAGE	10
#define IPROUTEMASK	11
#define IPROUTEMETRIC5	12
#define IPROUTEINFO	13

#define IPFORWARDNUMBER                                 1

/* Magic number defines for ipForwardTable */
#define IPFORWARDDEST                           	1
#define IPFORWARDMASK                           	2
#define IPFORWARDPOLICY                         	3
#define IPFORWARDNEXTHOP                        	4
#define IPFORWARDIFINDEX                        	5
#define IPFORWARDTYPE                           	6
#define IPFORWARDPROTO                          	7
#define IPFORWARDAGE                            	8
#define IPFORWARDINFO                           	9
#define IPFORWARDNEXTHOPAS                      	10
#define IPFORWARDMETRIC1                        	11
#define IPFORWARDMETRIC2                        	12
#define IPFORWARDMETRIC3                        	13
#define IPFORWARDMETRIC4                        	14
#define IPFORWARDMETRIC5                        	15


struct variable ipRoute_variables[] = {
    {IPROUTEDEST, IPADDRESS, RWRITE, var_ipRouteEntry, 3, {21, 1, 1}},
    {IPROUTEIFINDEX, INTEGER, RWRITE, var_ipRouteEntry, 3, {21, 1, 2}},
    {IPROUTEMETRIC1, INTEGER, RWRITE, var_ipRouteEntry, 3, {21, 1, 3}},
    {IPROUTEMETRIC2, INTEGER, RWRITE, var_ipRouteEntry, 3, {21, 1, 4}},
    {IPROUTEMETRIC3, INTEGER, RWRITE, var_ipRouteEntry, 3, {21, 1, 5}},
    {IPROUTEMETRIC4, INTEGER, RWRITE, var_ipRouteEntry, 3, {21, 1, 6}},
    {IPROUTENEXTHOP, IPADDRESS, RWRITE, var_ipRouteEntry, 3, {21, 1, 7}},
    {IPROUTETYPE, INTEGER, RWRITE, var_ipRouteEntry, 3, {21, 1, 8}},
    {IPROUTEPROTO, INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 9}},
    {IPROUTEAGE, INTEGER, RWRITE, var_ipRouteEntry, 3, {21, 1, 10}},
    {IPROUTEMASK, IPADDRESS, RWRITE, var_ipRouteEntry, 3, {21, 1, 11}},
    {IPROUTEMETRIC5, INTEGER, RWRITE, var_ipRouteEntry, 3, {21, 1, 12}},
    {IPROUTEINFO, OBJID, RONLY, var_ipRouteEntry, 3, {21, 1, 13}},

    {IPFORWARDNUMBER, GAUGE, RONLY, var_ipForwardSingle, 2, {24, 1}},

    {IPFORWARDDEST, IPADDRESS, RONLY, var_ipForwardTable, 4, {24,2,1, 1}},
    {IPFORWARDMASK, IPADDRESS, RWRITE, var_ipForwardTable, 4, {24,2,1, 2}},
    {IPFORWARDPOLICY, INTEGER, RONLY, var_ipForwardTable, 4, {24,2,1, 3}},
    {IPFORWARDNEXTHOP, IPADDRESS, RONLY, var_ipForwardTable, 4, {24,2,1, 4}},
    {IPFORWARDIFINDEX, INTEGER, RWRITE, var_ipForwardTable, 4, {24,2,1, 5}},
    {IPFORWARDTYPE, INTEGER, RWRITE, var_ipForwardTable, 4, {24,2,1, 6}},
    {IPFORWARDPROTO, INTEGER, RONLY, var_ipForwardTable, 4, {24,2,1, 7}},
    {IPFORWARDAGE, INTEGER, RONLY, var_ipForwardTable, 4, {24,2,1, 8}},
    {IPFORWARDINFO, OBJID, RWRITE, var_ipForwardTable, 4, {24,2,1, 9}},
    {IPFORWARDNEXTHOPAS, INTEGER, RWRITE, var_ipForwardTable, 4, {24,2,1, 10}},
    {IPFORWARDMETRIC1, INTEGER, RWRITE, var_ipForwardTable, 4, {24,2,1, 11}},
    {IPFORWARDMETRIC2, INTEGER, RWRITE, var_ipForwardTable, 4, {24,2,1, 12}},
    {IPFORWARDMETRIC3, INTEGER, RWRITE, var_ipForwardTable, 4, {24,2,1, 13}},
    {IPFORWARDMETRIC4, INTEGER, RWRITE, var_ipForwardTable, 4, {24,2,1, 14}},
    {IPFORWARDMETRIC5, INTEGER, RWRITE, var_ipForwardTable, 4, {24,2,1, 15}},
};

static struct subtree hooked_subtrees[] = {
    {{MIB, 4}, 7, (struct variable *)ipRoute_variables,
	 sizeof(ipRoute_variables)/sizeof(*ipRoute_variables),
	 sizeof(*ipRoute_variables)},
};

#define METRIC_NONE	(-1)
#define RTYPE_OTHER	1
#define RTYPE_INVALID	2
#define	RTYPE_DIRECT	3
#define RTYPE_INDIRECT	4
#define SPROTO_OTHER	1
#define SPROTO_LOCAL	2
#define SPROTO_NETMGMT	3
#define	SPROTO_ICMP	4
#define	SPROTO_EGP	5
#define	SPROTO_GGP	6
#define	SPROTO_HELLO	7
#define SPROTO_RIP	8
#define	SPROTO_ISIS	9
#define	SPROTO_ESIS	10
#define	SPROTO_CISCO	11
#define	SPROTO_BBN	12
#define	SPROTO_OSPF	13
#define	SPROTO_BGP	14

static rt_entry *
o_ip_route_match(rt_head *rth, void_t data)
{
    return rth->rth_rib_active[RIB_UNICAST];
}


static rt_entry *
o_rt_lookup(sockaddr_un *l_dst, int l_isnext, int len)
{
    rt_entry *rt;
    
    if (l_isnext) {
	sockaddr_un *msk;
	u_int32 ip;
	if (len < 4) {
	    switch (len) {
	    case 3: 
		ip = 0xff000000;
		ip = 0x00ff;
		break;
	    case 2: 
		ip = 0xffff0000;
		ip = 0x00ffff;
		break;
	    case 1: 
		ip = 0xffffff00;
		ip = 0x00ffffff;
		break;
	    case 0: 
		ip = 0xffffffff;
		break;
	    }
	    msk = inet_mask_locate(ip);
	}
	else
	    msk = (sockaddr_un *) 0;
	rt = rt_table_getnext(l_dst,
			      msk,
			      AF_INET,
			      o_ip_route_match,
			      (void_t) 0);
    } else {
	rt = rt_table_get(l_dst,
			  (sockaddr_un *) 0,
			  o_ip_route_match,
			  (void_t) 0);
    }

    return rt;
}


static rt_entry *o_ip_route_last_rt;
static unsigned int *o_ip_route_last;

static rt_entry *
o_ip_route_lookup(register unsigned int *ip, u_int len, int isnext)
{
    sockaddr_un *dst;
	
    if (ip)
	switch (len) {
	case 0: 
	    ip[0] = 0;		/* fall through... */
	case 1: 
	    ip[1] = 0;		/* fall through... */
	case 2: 
	    ip[2] = 0;		/* fall through... */
	case 3: 
	    ip[3] = 0;
	    break;
	default:
	    break;
	}

#ifdef DJW
    fprintf(stderr, "ip_route_lookup: ip: %x, len: %d, isnext:%d",
	    ip,len,isnext);
    if (ip) {
	switch (len) {
	case 4: 
	    fprintf(stderr, ", %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
	    break;
	case 3: 
	    fprintf(stderr, ", %d.%d.%d.*\n", ip[0], ip[1], ip[2]);
	    break;
	case 2: 
	    fprintf(stderr, ", %d.%d.*.*\n", ip[0], ip[1]);
	    break;
	case 1: 
	    fprintf(stderr, ", %d.*.*.*\n", ip[0]);
	    break;
	case 0: 
	    fprintf(stderr, ", [zero]\n");
	    break;
	}
    } else
	fprintf(stderr, "\n");
#endif /* DJW */

    if (snmp_last_match(&o_ip_route_last, ip, len, isnext)) {
#ifdef DJW
	fprintf(stderr, "(last match) ");
	if (o_ip_route_last_rt)
	{
	    struct in_addr in;
	    in.s_addr = sock2ip(o_ip_route_last_rt->rt_dest);
	    fprintf(stderr, "=> dest %s\n", inet_ntoa(in));
	} else
	    fprintf(stderr, "=> dest NONE\n");
#endif /* DJW */
	return o_ip_route_last_rt;
    }

    dst = sockbuild_in(0, 0);
    oid2ipaddr(ip, &sock2in(dst), len);
    o_ip_route_last_rt = o_rt_lookup(dst, isnext, len);

#ifdef DJW
    if (o_ip_route_last_rt)
    {
	struct in_addr in;
	in.s_addr = sock2ip(o_ip_route_last_rt->rt_dest);
	fprintf(stderr, "=> dest %s\n", inet_ntoa(in));
    } else
	fprintf(stderr, "=> dest NONE\n");
#endif /* DJW */
    return o_ip_route_last_rt;
}

/*
 *
 * IN:
 *	vp -- pointer to variable entry that points here
 *	exact -- TRUE if an exact match was requested.
 * IN/OUT:
 *	name -- input name requested, output name found
 *	length -- length of input and output oid's
 * OUT:
 *	var_len -- length of variable or 0 if function returned.
 * 	write_method -- pointer to function to set variable, otherwise 0
 */
static u_char *
var_ipRouteEntry(struct variable *vp, oid *name, int *length, int exact,
    int *var_len, PWM *write_method)
{
/* INDEX   { ipRouteDest } */
#define	NDX_SIZE	((int) sizeof (struct in_addr))

    /*
     * object identifier is of form:
     * 1.3.6.1.2.1.4.21.1.1.A.B.C.D,  where A.B.C.D is IP address.
     * IPADDR starts at offset 10.
     */
    register rt_entry *rt;
    int len;

    if (exact) {
	if (*length != vp->namelen + NDX_SIZE)
	    return NULL;		/* can not find it */

	if (!(rt = o_ip_route_lookup((unsigned int *) &name[vp->namelen], NDX_SIZE, FALSE)))
	    return NULL;		/* can not find it */
    } else {
	
	if ((*length < vp->namelen)
	    || (compare_oid(name, vp->namelen, vp->name, vp->namelen) < 0)) {
	    len = 0;
	} else {
	    len = *length - vp->namelen;
	}
	if (!(rt = o_ip_route_lookup((unsigned int *) &name[vp->namelen], len, TRUE)))
	    return NULL;		/* nothing to find */
	bcopy(vp->name, name, vp->namelen * sizeof(oid));
	put_ipaddr(sock2ip(rt->rt_dest), vp->namelen, name);
	*length = vp->namelen + NDX_SIZE;
    }

    *var_len = sizeof(int32_return);

    switch(vp->magic){
    case IPROUTEDEST:
	return O_IPADDR(rt->rt_dest);

    case IPROUTEIFINDEX:
	if (BIT_TEST(rt->rt_state, RTS_REJECT) || !RT_IFAP(rt)) {
	    return O_INTEGER(0);
	} else {
	    return O_INTEGER(RT_IFAP(rt)->ifa_link->ifl_index);
	}
    case IPROUTEMETRIC1:
	return O_INTEGER(rt->rt_metric);
    case IPROUTEMETRIC2:
	return O_INTEGER(rt->rt_metric2);

    case IPROUTEMETRIC3:
    case IPROUTEMETRIC4:
    case IPROUTEMETRIC5:
	return O_INTEGER(METRIC_NONE);

    case IPROUTENEXTHOP:
	return O_IPADDR(
	    (!RT_ROUTER(rt) || BIT_TEST(rt->rt_state, RTS_REJECT))
	     ? inet_addr_default : RT_ROUTER(rt));

    case IPROUTETYPE:
	if (BIT_TEST(rt->rt_state, RTS_REJECT)) {
	    return O_INTEGER(RTYPE_OTHER);
	} else if (BIT_TEST(rt->rt_state, RTS_GATEWAY)) {
	    return O_INTEGER(RTYPE_INDIRECT);
	} else {
	    return O_INTEGER(RTYPE_DIRECT);
	}

    case IPROUTEPROTO:
	switch (rt->rt_gwp->gw_proto) {
	default:
	case RTPROTO_DIRECT:
	    return O_INTEGER(SPROTO_LOCAL);

	case RTPROTO_STATIC:
	    return O_INTEGER(SPROTO_LOCAL);

	case RTPROTO_KERNEL:
	    if (BIT_TEST(rt->rt_state, RTS_NOADVISE)) {
		return O_INTEGER(SPROTO_OTHER);
	    } else {
		return O_INTEGER(SPROTO_LOCAL);
	    }

	case RTPROTO_AGGREGATE:
	    return O_INTEGER(SPROTO_OTHER);
	    
	case RTPROTO_SNMP:
	    return O_INTEGER(SPROTO_NETMGMT);
		
	case RTPROTO_REDIRECT:
	    return O_INTEGER(SPROTO_ICMP);

	case RTPROTO_EGP:
	    return O_INTEGER(SPROTO_EGP);

	case RTPROTO_RIP:
	    return O_INTEGER(SPROTO_RIP);

	case RTPROTO_OSPF:
	case RTPROTO_OSPF_ASE:
	    return O_INTEGER(SPROTO_OSPF);

	case RTPROTO_BGP:
	    return O_INTEGER(SPROTO_BGP);

	case RTPROTO_ISIS:
	    return O_INTEGER(SPROTO_ISIS);
	}

    case IPROUTEAGE:
	return O_INTEGER(rt_age(rt));

    case IPROUTEMASK:
	return O_IPADDR(rt->rt_dest_mask);

    case IPROUTEINFO:
	*var_len = snmp_nullSpecificLen;
	return (u_char *) snmp_nullSpecific;

    default:
	ERROR_MSG("");
   }
   return NULL;
}

#undef	NDX_SIZE


/**/
/* IP Forwarding table */

#define FTYPE_OTHER	1
#define FTYPE_INVALID	2
#define	FTYPE_LOCAL	3
#define FTYPE_REMOTE	4
#define FPROTO_OTHER	1
#define FPROTO_LOCAL	2
#define FPROTO_NETMGMT	3
#define	FPROTO_ICMP	4
#define	FPROTO_EGP	5
#define	FPROTO_GGP	6
#define	FPROTO_HELLO	7
#define FPROTO_RIP	8
#define	FPROTO_ISIS	9
#define	FPROTO_ESIS	10
#define	FPROTO_CISCO	11
#define	FPROTO_BBN	12
#define	FPROTO_OSPF	13
#define	FPROTO_BGP	14
#define	FPROTO_IDPR	15


static int
o_ip_forward_proto(rt_entry *p_rt)
{
    int proto;
    
    switch (p_rt->rt_gwp->gw_proto) {
    default:
    case RTPROTO_DIRECT:
	proto = FPROTO_LOCAL;
	break;

    case RTPROTO_STATIC:
	proto = FPROTO_NETMGMT;
	break;
	
    case RTPROTO_KERNEL:
	if (BIT_TEST(p_rt->rt_state, RTS_NOADVISE)) {
	    proto = FPROTO_OTHER;
	} else {
	    proto = FPROTO_NETMGMT;
	}
	break;

    case RTPROTO_AGGREGATE:
	proto = FPROTO_OTHER;
	break;
	
    case RTPROTO_SNMP:
	proto = FPROTO_NETMGMT;
	break;
		
    case RTPROTO_REDIRECT:
	proto = FPROTO_ICMP;
	break;

    case RTPROTO_EGP:
	proto = FPROTO_EGP;
	break;

    case RTPROTO_RIP:
	proto = FPROTO_RIP;
	break;

    case RTPROTO_OSPF:
    case RTPROTO_OSPF_ASE:
	proto = FPROTO_OSPF;
	break;

    case RTPROTO_BGP:
	proto = FPROTO_BGP;
	break;

    case RTPROTO_ISIS:
	proto = FPROTO_ISIS;
	break;
    }

    return proto;
}


static rt_entry *o_ip_forward_last_rt;
static unsigned int *o_ip_forward_last;

static rt_entry *
o_ip_forward_lookup(register unsigned int *ip, u_int len, int isnext,
    int *router_index)
{
    static int last_index;
    sockaddr_un *dst;

    if (snmp_last_match(&o_ip_forward_last, ip, len, isnext)) {
	goto Return;
    }

    if (len) {
	int proto = 0;
	u_int32 addr;
	sockaddr_un *gw;

	dst = sockbuild_in(0, 0);
	oid2ipaddr(ip, &addr, len);
	dst = sockbuild_in(0, addr);
        if (len > sizeof(struct in_addr))
	    proto = ip[sizeof (struct in_addr)];
	if (len > sizeof(struct in_addr) + 1) {
	    if (ip[sizeof (struct in_addr) + 1]) {
	        /* We don't support TOS */
		*router_index = last_index = 0;
		o_ip_forward_last_rt = (rt_entry *) 0;
		goto Return;
	    }
        }
	oid2ipaddr(ip + sizeof (struct in_addr) + 1 + 1, &addr,
                                        len - (sizeof(struct in_addr) + 1 + 1));
	gw = sockbuild_in(0, addr);
	if (!sock2ip(gw)) {
	    goto Next;
	}

	o_ip_forward_last_rt = o_rt_lookup(dst, FALSE, 0);
	if (o_ip_forward_last_rt) {
	    register int i;
	    
	    for (i = 0; i < o_ip_forward_last_rt->rt_n_gw; i++) {
		switch (sockaddrcmp2(o_ip_forward_last_rt->rt_routers[i], gw)){
		case 0:
		    if (!isnext) {
			last_index = i;
			goto Return;
		    }
		    break;

		case 1:
		    if (isnext) {
			last_index = i;
			goto Return;
		    } else {
			goto Next;
		    }
		}
	    }
	}

    Next: ;
    } else {
	dst = (sockaddr_un *) 0;
    }

    o_ip_forward_last_rt = o_rt_lookup(dst, TRUE, len);
    last_index = 0;

 Return:
    *router_index = last_index;
    return o_ip_forward_last_rt;
}

/*
 * var_ipForwardSingle: Callbacks for oid ip.24
 * Single-instanced
 *
 * IN:
 *	vp -- pointer to variable entry that points here
 *	exact -- TRUE if an exact match was requested.
 * IN/OUT:
 *	name -- input name requested, output name found
 *	length -- length of input and output oid's
 * OUT:
 *	var_len -- length of variable or 0 if function returned.
 * 	write_method -- pointer to function to set variable, otherwise 0
 */
static u_char *
var_ipForwardSingle(struct variable *vp, oid *name, int *length, int exact,
    int *var_len, PWM *write_method)
{
    if ( !single_inst_check(vp, name, length, exact) )
        return NULL;

    *var_len = sizeof(int32_return); /* default length */

    switch (vp->magic) {
        case IPFORWARDNUMBER:
            /* C type INTEGER, MIB type Gauge */
#if   RT_N_MULTIPATH > 1
	    /* XXX - This is slow, but is the only way to get a correct result
	     * right now
	     */
	    for (forward_number = 0, dst = (sockaddr_un *) 0;
		 (rt = o_rt_lookup(dst, TRUE, len));
		 dst = rt->rt_dest) {
		forward_number += rt->rt_n_gw;
	    }
	    return O_INTEGER(forward_number);
#else /* RT_N_MULTIPATH > 1 */
	    return O_INTEGER(rtaf_info[AF_INET].rtaf_actives);
#endif        /* RT_N_MULTIPATH */
    default:
	/* The magic number is not valid */
	ERROR_MSG("");
    }
    return NULL;
}

/*
 * var_ipForwardTable: Callbacks for oid ip.24.2
 * Entry indexes are
 * ipForwardDest, ipForwardProto, ipForwardPolicy, ipForwardNextHop
 *
 * IN:
 *	vp -- pointer to variable entry that points here
 *	exact -- TRUE if an exact match was requested.
 * IN/OUT:
 *	name -- input name requested, output name found
 *	length -- length of input and output oid's
 * OUT:
 *	var_len -- length of variable or 0 if function returned.
 * 	write_method -- pointer to function to set variable, otherwise 0
 */
static u_char *
var_ipForwardTable(struct variable *vp, oid *name, int *length, int exact,
    int *var_len, PWM *write_method)
{
/* INDEX {ipForwardDest, ipForwardProto, ipForwardPolicy, ipForwardNextHop} */
#define	NDX_SIZE (int)(sizeof (struct in_addr) + 1 + 1 + sizeof (struct in_addr))

    register rt_entry *rt;
    int router_index;
    int len;

    if (exact) {
	if (*length != vp->namelen + NDX_SIZE)
	    return NULL;		/* can not find it */

	if (!(rt = o_ip_forward_lookup((unsigned int *) &name[vp->namelen], NDX_SIZE, FALSE,
				       &router_index)))
	    return NULL;		/* can not find it */
    } else {
	
	if ((*length < vp->namelen)
	    || (compare_oid(name, vp->namelen, vp->name, vp->namelen) < 0)) {
	    len = 0;
	} else {
	    len = *length - vp->namelen;
	}
	if (!(rt = o_ip_forward_lookup((unsigned int *) &name[vp->namelen], len, TRUE,
				       &router_index)))
	    return NULL;		/* nothing to find */
	bcopy(vp->name, name, vp->namelen * sizeof(oid));
	put_ipaddr(sock2ip(rt->rt_dest), vp->namelen, name);
	name[vp->namelen + 4] = o_ip_forward_proto(rt);
	name[vp->namelen + 5] = 0;		/* No support for TOS */
	if (len == 0) {  /* First call for this part of tree */
	    if (BIT_TEST(rt->rt_state, RTS_GATEWAY)) {
		put_ipaddr(sock2ip(rt->rt_routers[router_index]),
			   vp->namelen + 6, name);
	    } else {
		put_ipaddr(sock2ip(inet_addr_default),
			   vp->namelen + 6, name);
	    }
	} else {
	    if (rt->rt_routers[router_index]
		&& !BIT_TEST(rt->rt_state, RTS_REJECT)) {
		put_ipaddr(sock2ip(rt->rt_routers[router_index]),
			   vp->namelen + 6, name);
	    } else {
		put_ipaddr(sock2ip(inet_addr_default),
			   vp->namelen + 6, name);
	    }
	}
	*length = vp->namelen + NDX_SIZE;
    }

    *var_len = sizeof(int32_return); /* default length */

    switch (vp->magic) {
    case IPFORWARDDEST:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR(rt->rt_dest);

    case IPFORWARDMASK:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR(rt->rt_dest_mask);

    case IPFORWARDPOLICY:
	/* C type INTEGER, MIB type INTEGER */
	/* No TOS support */
	return O_INTEGER(0);

    case IPFORWARDNEXTHOP:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR(
	    	(   rt->rt_routers[router_index]
		 && !BIT_TEST(rt->rt_state, RTS_REJECT))
	        ? rt->rt_routers[router_index] : inet_addr_default);

    case IPFORWARDIFINDEX:
	/* C type INTEGER, MIB type INTEGER */
	if (BIT_TEST(rt->rt_state, RTS_REJECT)
	    || !rt->rt_ifaps[router_index]) {
	    return O_INTEGER(0);
	} else {
	    return O_INTEGER(rt->rt_ifaps[router_index]->ifa_link->ifl_index);
	}

    case IPFORWARDTYPE:
	/* C type INTEGER, MIB type INTEGER */
	if (BIT_TEST(rt->rt_state, RTS_REJECT)) {
	    return O_INTEGER(FTYPE_OTHER);
	} else if (BIT_TEST(rt->rt_state, RTS_GATEWAY)) {
	    return O_INTEGER(FTYPE_REMOTE);
	} else {
	    return O_INTEGER(FTYPE_LOCAL);
	}

    case IPFORWARDPROTO:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(o_ip_forward_proto(rt));

    case IPFORWARDAGE:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(rt_age(rt));

    case IPFORWARDINFO:
	/* C type OBJID, MIB type ObjectID */
	/* XXX - Need to ask the protocols */
	*var_len = snmp_nullSpecificLen;
	return (u_char *) snmp_nullSpecific;

    case IPFORWARDNEXTHOPAS:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(rt->rt_gwp->gw_peer_as);

    case IPFORWARDMETRIC1:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(rt->rt_metric);

    case IPFORWARDMETRIC2:
	/* C type INTEGER, MIB type INTEGER */
	switch (rt->rt_gwp->gw_proto) {
#ifdef	PROTO_OSPF
	case RTPROTO_OSPF_ASE:
	    if (ORT_ETYPE(rt)) {
		return O_INTEGER(ORT_COST(rt));
	    }
	    /* Fall through */
#endif	/* PROTO_OSPF */
	    
	default:
	    return O_INTEGER(METRIC_NONE);
	}
	
    case IPFORWARDMETRIC3:
    case IPFORWARDMETRIC4:
    case IPFORWARDMETRIC5:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(METRIC_NONE);

    default:
	/* The magic number is not valid */
	ERROR_MSG("");
    }
    return NULL;
}

/**/

void
rt_mib_free_rt(rt_entry *rt)
{
    if (o_ip_route_last_rt == rt) {
	o_ip_route_last_rt = (rt_entry *) 0;
	snmp_last_free(&o_ip_route_last);
    }
    if (o_ip_forward_last_rt == rt) {
	o_ip_forward_last_rt = (rt_entry *) 0;
	snmp_last_free(&o_ip_forward_last);
    }
}

void 
init_route_vars(void)
{
    add_all_subtrees(hooked_subtrees,
		     sizeof(hooked_subtrees)/sizeof(struct subtree));
}


void
rt_init_mib(int enabled)
{
    if (enabled) {
/* $$$ nothing to do to unregister??? */
    } else {
/* $$$ nothing to do to unregister??? */
    }
}
#endif
