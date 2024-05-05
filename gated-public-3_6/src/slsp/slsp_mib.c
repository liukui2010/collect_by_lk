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

#ifdef not_used
/*
 * this module was not converted to the new Merit SNMP/SMUX protocol
 */
#define	INCLUDE_ISODE_SNMP
#include "include.h"
#include "inet/inet.h"
#include "slsp_proto.h"
#include "slsp.h"
#include "slsp_var.h"
#include "snmp_isode.h"

static int o_slsp_group(OI,
	   struct type_SNMP_VarBind *,
	   int);
static int o_slsp_nbr(OI,
	   struct type_SNMP_VarBind *,
	   int);
static int o_slsp_counters(OI,
	   struct type_SNMP_VarBind *,
	   int);

static struct object_table slsp_objects[] = {
#define	ImaximumRouterLSPGenerationInterval	0
#define	ImaximumEndSystemLSPGenerationInterval	1
#define	IminimumLSPTransmissionInterval		2
#define	IminimumLSPGenerationInterval		3
    OTE(maximumRouterLSPGenerationInterval, o_slsp_group, NULL),
    OTE(maximumEndSystemLSPGenerationInterval, o_slsp_group, NULL),
    OTE(minimumLSPTransmissionInterval, o_slsp_group, NULL),
    OTE(minimumLSPGenerationInterval, o_slsp_group, NULL),

#define	IslspisisNeighAddr			4
#define	Icost					5
#define	IhelloTimer				6
#define	Istate					7
#define	IholdTime				8
#define	IslspisisIndex				9
#define	IslspisisLocalAddr			10
    OTE(slspisisNeighAddr, o_slsp_nbr, NULL),
    OTE(cost, o_slsp_nbr, NULL),
    OTE(helloTimer, o_slsp_nbr, NULL),
    OTE(state, o_slsp_nbr, NULL),
#define	STATE_ON	1
#define	STATE_OFF	2
    OTE(holdTime, o_slsp_nbr, NULL),
    OTE(slspisisIndex, o_slsp_nbr, NULL),
    OTE(slspisisLocalAddr, o_slsp_nbr, NULL),

#define	IrouterCounterGroup			11
#define	IrouterLSPins				12
#define	IrouterLSPouts				13
#define	IendSystemLSPins				14
#define	IendSystemLSPouts			15
#define	IsequenceNumberPDUins			16
#define	IsequenceNumberPDUouts			17
#define	IcorruptedPDUs				18
#define	IslspisesHelloins			19
#define	IslspisesHelloouts			20
#define	IslspisisHelloins			21
#define	IslspisisHelloouts			22
    OTE(routerLSPins, o_slsp_counters, NULL),
    OTE(routerLSPouts, o_slsp_counters, NULL),
    OTE(endSystemLSPins, o_slsp_counters, NULL),
    OTE(endSystemLSPouts, o_slsp_counters, NULL),
    OTE(sequenceNumberPDUins, o_slsp_counters, NULL),
    OTE(sequenceNumberPDUouts, o_slsp_counters, NULL),
    OTE(corruptedPDUs, o_slsp_counters, NULL),
    OTE(slspisesHelloins, o_slsp_counters, NULL),
    OTE(slspisesHelloouts, o_slsp_counters, NULL),
    OTE(slspisisHelloins, o_slsp_counters, NULL),
    OTE(slspisisHelloouts, o_slsp_counters, NULL),


    { NULL }
};

static struct snmp_tree slsp_mib_tree = {
    NULL, NULL,
    "slspisis",
    NULLOID,
    readWrite,
    slsp_objects,
    0
};

static slsp_neighbour *slsp_mib_last_snp = (slsp_neighbour *) 0;
static unsigned int *slsp_mib_last;


/**/

void
slsp_mib_remove_nbr (slsp_neighbour * nbr)
{
    if (slsp_mib_last_snp == nbr) {
	snmp_last_free(&slsp_mib_last);
	slsp_mib_last_snp = (slsp_neighbour *) 0;
    }
}

static int
o_slsp_group (OI oi, register struct type_SNMP_VarBind * v, int offset)
{
    register OID    oid = oi->oi_name;
    register OT	    ot = oi->oi_type;

    switch (offset) {
    case type_SNMP_SMUX__PDUs_get__request:
	if (oid->oid_nelem != ot->ot_name->oid_nelem + 1
	    || oid->oid_elements[oid->oid_nelem - 1]) {
	    return int_SNMP_error__status_noSuchName;
	}
	break;

    case type_SNMP_SMUX__PDUs_get__next__request:
	if (oid->oid_nelem == ot->ot_name->oid_nelem) {
	    OID new;

	    if ((new = oid_extend(oid, 1)) == NULLOID) {
		return int_SNMP_error__status_genErr;
	    }
	    new->oid_elements[new->oid_nelem - 1] = 0;

	    if (v->name) {
		free_SNMP_ObjectName(v->name);
	    }
	    v->name = new;
	} else {
	    return NOTOK;
	}
	break;

    default:
	return int_SNMP_error__status_genErr;
    }

    switch (ot2object(ot)->ot_info) {
    case ImaximumRouterLSPGenerationInterval:
	return o_integer(oi, v, SLSP_LIFE_REORIGINATE);
	
    case ImaximumEndSystemLSPGenerationInterval:
	return o_integer(oi, v, SLSP_LIFE_REORIGINATE);

    case IminimumLSPTransmissionInterval:
	return o_integer(oi, v, SLSP_MIN_SEND_INTERVAL);

    case IminimumLSPGenerationInterval:
	return o_integer(oi, v, SLSP_MIN_SEND_INTERVAL);
    }

    return int_SNMP_error__status_noSuchName;
}


/**/

static slsp_neighbour *
o_slsp_get_nbr (register unsigned int * ip, u_int len, int isnext)
{
    slsp_instance *inp = slsp_instance_list;
    u_long snp_addr;

    if (snmp_last_match(&slsp_mib_last, ip, len, isnext)) {
	return slsp_mib_last_snp;
    }

    if (!inp) {
	slsp_mib_last_snp = (slsp_neighbour *) 0;
	return (slsp_neighbour *) 0;
    }

    oid2ipaddr(ip, &snp_addr, len);

    /* XXX - this code doesn't handle getnext right but nobody cares... */
    if (!len || isnext) {
	register slsp_neighbour *nbr;
	register u_long best_addr = 0xffffffff;
	register slsp_neighbour *best_nbr = (slsp_neighbour *) 0;

	GNTOHL(snp_addr);

	for (nbr = inp->slsp_nbrs; nbr; nbr = nbr->slsp_nbr_next) {
	    if (SLSP_NBR_PTP_TYPE(nbr)) {
		register u_long tmp = ntohl(sock2ip(nbr->slsp_nbr_addr));

		if (tmp > snp_addr && tmp <= best_addr) {
		    best_nbr = nbr;
		    best_addr = tmp;
		}
	    } else {
		register slsp_neighbour *nnbr;

		for (nnbr = nbr->slsp_nbr_list;
		     nnbr;
		     nnbr = nnbr->slsp_nbr_next) {
		    register u_long tmp = ntohl(sock2ip(nnbr->slsp_nbr_addr));

		    if (tmp > snp_addr && tmp <= best_addr) {
			best_nbr = nnbr;
			best_addr = tmp;
		    }
		}
	    }
	}
	slsp_mib_last_snp = best_nbr;
    } else {
	register slsp_neighbour *nbr;

	for (nbr = inp->slsp_nbrs; nbr; nbr = nbr->slsp_nbr_next) {
	    if (SLSP_NBR_PTP_TYPE(nbr)) {
		if (sock2ip(nbr->slsp_nbr_addr) == snp_addr) {
		    break;
		}
	    } else {
		register slsp_neighbour *nnbr;

		for (nnbr = nbr->slsp_nbr_list;
		     nnbr;
		     nnbr = nnbr->slsp_nbr_next) {
		    if (sock2ip(nnbr->slsp_nbr_addr) == snp_addr) {
			break;
		    }
		}
		if (nnbr) {
		    nbr = nnbr;
		    break;
		}
	    }
	}
	slsp_mib_last_snp = nbr;
    }

    return slsp_mib_last_snp;
}


static int
o_slsp_nbr (OI oi, register struct type_SNMP_VarBind * v, int offset)
{
    register int    i;
    register unsigned int *ip,
			  *jp;
    register slsp_neighbour *snp;
    register OID    oid = oi->oi_name;
    register OT	    ot = oi->oi_type;
    OID		    new;

    /* INDEX { slspisisNeighAddr } */
#define	NDX_SIZE	(sizeof (struct in_addr))

    switch (offset) {
    case type_SNMP_SMUX__PDUs_get__request:
	if (oid->oid_nelem != ot->ot_name->oid_nelem + NDX_SIZE) {
		return int_SNMP_error__status_noSuchName;
	    }
	snp = o_slsp_get_nbr(oid->oid_elements + oid->oid_nelem - NDX_SIZE,
			     sizeof (struct in_addr),
			     0);
	if (!snp) {
	    return int_SNMP_error__status_noSuchName;
	}
	break;

    case type_SNMP_SMUX__PDUs_get__next__request:
	/* next request with incomplete instance? */
	if ((i = oid->oid_nelem - ot->ot_name->oid_nelem) != 0 && i < NDX_SIZE) {
	    for (jp = (ip = oid->oid_elements + 
		       ot->ot_name->oid_nelem - 1) + i;
		 jp > ip;
		 jp--) {
		if (*jp != 0) {
		    break;
		}
	    }
	    if (jp == ip) {
		oid->oid_nelem = ot->ot_name->oid_nelem;
	    } else {
		if ((new = oid_normalize(oid, NDX_SIZE - i, 256)) == NULLOID) {
			return NOTOK;
		    }
		if (v->name) {
		    free_SNMP_ObjectName(v->name);
		}
		v->name = oid = new;
	    }
	}

	/* next request with no instance? */
	if (oid->oid_nelem == ot->ot_name->oid_nelem) {
	    snp = o_slsp_get_nbr((unsigned int *) 0,
				 0,
				 TRUE);
	    if (!snp) {
		return NOTOK;
	    }

	    if ((new = oid_extend(oid, NDX_SIZE)) == NULLOID) {
		return int_SNMP_error__status_genErr;
	    }

	    ip = new->oid_elements + new->oid_nelem - NDX_SIZE;
	    STR_OID(ip, &sock2ip(snp->slsp_nbr_addr), sizeof (sock2ip(snp->slsp_nbr_addr)));
		
	    if (v->name) {
		free_SNMP_ObjectName(v->name);
	    }
	    v->name = new;
	} else {
	    int j;

	    snp = o_slsp_get_nbr(ip = oid->oid_elements + ot->ot_name->oid_nelem,
				 (u_int) (j = oid->oid_nelem - ot->ot_name->oid_nelem),
				 TRUE);
	    if (!snp) {
		return NOTOK;
	    }

	    if ((i = j - NDX_SIZE) < 0) {
		if ((new = oid_extend(oid, -i)) == NULLOID) {
		    return int_SNMP_error__status_genErr;
		}
		if (v->name) {
		    free_SNMP_ObjectName(v->name);
		}
		v->name = oid = new;
	    } else if (i > 0) {
		oid->oid_nelem -= i;
	    }
		
	    ip = oid->oid_elements + ot->ot_name->oid_nelem;
	    STR_OID(ip, &sock2ip(snp->slsp_nbr_addr), sizeof (sock2ip(snp->slsp_nbr_addr)));
	}
	break;

    default:
	return int_SNMP_error__status_genErr;
    }
#undef	NDX_SIZE

    switch (ot2object(ot)->ot_info) {
    case IslspisisNeighAddr:
	return o_ipaddr(oi,
			v,
			sock2unix(snp->slsp_nbr_addr,
				  (int *) 0));

    case Icost:
	return o_integer(oi, v, snp->slsp_nbr_cost);

    case IhelloTimer:
	return o_integer(oi, v, snp->slsp_nbr_hellointerval);

    case Istate:
	return o_integer(oi, v,
	  ((snp->slsp_nbr_state == SLSP_NBR_STATE_ADJACENT)
	    ? STATE_ON : STATE_OFF));

    case IholdTime:
	return o_integer(oi, v, snp->slsp_nbr_routerdeadinterval);

    case IslspisisIndex:
	return o_integer(oi, v, snp->slsp_nbr_index);

    case IslspisisLocalAddr:
	return o_ipaddr(oi,
			v,
			sock2unix(snp->slsp_nbr_if->ifa_addr_local,
				  (int *) 0));
    }

    return int_SNMP_error__status_noSuchName;
}

/**/
static int
o_slsp_counters (OI oi, register struct type_SNMP_VarBind * v, int offset)
{
    register OID    oid = oi->oi_name;
    register OT	    ot = oi->oi_type;
    slsp_instance   *inp = slsp_instance_list;

    switch (offset) {
    case type_SNMP_SMUX__PDUs_get__request:
	if (oid->oid_nelem != ot->ot_name->oid_nelem + 1
	    || oid->oid_elements[oid->oid_nelem - 1]) {
	    return int_SNMP_error__status_noSuchName;
	}
	break;

    case type_SNMP_SMUX__PDUs_get__next__request:
	if (oid->oid_nelem == ot->ot_name->oid_nelem) {
	    OID new;

	    if ((new = oid_extend(oid, 1)) == NULLOID) {
		return int_SNMP_error__status_genErr;
	    }
	    new->oid_elements[new->oid_nelem - 1] = 0;

	    if (v->name) {
		free_SNMP_ObjectName(v->name);
	    }
	    v->name = new;
	} else {
	    return NOTOK;
	}
	break;

    default:
	return int_SNMP_error__status_genErr;
    }

    switch (ot2object(ot)->ot_info) {
    case IrouterCounterGroup:	/* XXX */
	return o_integer(oi, v, 0);

    case IrouterLSPins:
	return o_integer(oi, v, inp->slsp_stats.slsp_st_in_lsps);

    case IrouterLSPouts:
	return o_integer(oi, v, inp->slsp_stats.slsp_st_out_lsps);

    case IendSystemLSPins:
	return o_integer(oi, v, 0);

    case IendSystemLSPouts:
	return o_integer(oi, v, 0);

    case IsequenceNumberPDUins:
	return o_integer(oi, v, inp->slsp_stats.slsp_st_in_seqs);

    case IsequenceNumberPDUouts:
	return o_integer(oi, v, inp->slsp_stats.slsp_st_out_seqs);

    case IcorruptedPDUs:
	return o_integer(oi, v, inp->slsp_stats.slsp_st_bad_lsps);

    case IslspisesHelloins:
	return o_integer(oi, v, inp->slsp_stats.slsp_st_in_hellos);

    case IslspisesHelloouts:
	return o_integer(oi, v, inp->slsp_stats.slsp_st_out_hellos);

    case IslspisisHelloins:
	return o_integer(oi, v, inp->slsp_stats.slsp_st_in_ihus);

    case IslspisisHelloouts:
	return o_integer(oi, v, inp->slsp_stats.slsp_st_out_ihus);

    }

    return int_SNMP_error__status_noSuchName;
}


/**/

void
slsp_init_mib (int enabled)
{
    if (enabled) {
	snmp_tree_register(&slsp_mib_tree);
    } else {
	snmp_tree_unregister(&slsp_mib_tree);
    }
}
#endif /* not_used */

