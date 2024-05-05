/*
 * Gated Release 4.x, 5.x, 6.x, 7.x
 * 
 * $Id: ospf_lsdb.c,v 1.8 2000/02/18 01:49:44 naamato Exp $
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

#include "include.h"

#ifdef PROTO_OSPF
#include "inet/inet.h"
#include "ospf.h"

/*
 * 		Link State Db stuff
 */


/*
 * addLSA 		Add lsa to the linked list
 */
int
addLSA (struct LSDB ** db, struct AREA * area, u_int32 ls_id, u_int32 mask, u_int32 key1, u_int type)
{
    register struct LSDB **e, **me;
    struct LSDB_HEAD *hp;
    u_int32 mls_id;
    int hash, mhash;

    hash = XHASH(ls_id, ls_id);
    hp = &area->htbl[type][hash];

    assert(type <= LS_ASE);

    /* First key */
    for (e = &DBH_LIST(hp); *e; e = &(*e)->lsdb_next) {
	if (ls_id == LS_ID(*e)) {
	    if (type == LS_NET || type == LS_RTR) {
		/* Just one key for these types */
		*db = *e;
		return TRUE;
	    }

	    /* Second key */
	    for (; *e && ls_id == LS_ID(*e); e = &(*e)->lsdb_next) {
		if (key1 == ADV_RTR(*e)) {
		    /* Found it */
		    *db = *e;
		    return TRUE;
		} else if (key1 > ADV_RTR(*e)) {
		    /* Install here */

		    break;
		}
	    }
	    break;
	} else if (ls_id > LS_ID(*e)) {
	    /* Install here */

	    break;
	}
    }
    /*
     * If summary networks or AS externals we need to add
     * the LSA to its masked queue.  Find the insertion location
     */
    if (type != LS_SUM_NET && type != LS_ASE)
	me = 0;
    else {
	mls_id = ls_id & mask;
	mhash = XHASH(mls_id, mls_id);
	if (type == LS_SUM_NET)
	    hp = &area->sum_net_masked[mhash];
	else
	    hp = &ospf.ase_masked[mhash];

	/* first key -- masked LSID*/
	for (me = &DBH_LIST(hp); *me; me = &(*me)->lsdb_next_masked) {
	    if (mls_id > (LS_ID(*me) & mask))
		break;			/* Install here */
	    else if (mls_id != (LS_ID(*me) & mask))
		continue;

	    for (; *me && mls_id == (LS_ID(*me) & mask);
		 me = &(*me)->lsdb_next_masked) {
		/*
		 * we sort less specific to most specific
		 * so that we are more likely to be in the
		 * same order as the unmasked list.  This is
		 * becuase the suggested (and our implmeneted)
		 * normalization code turns less specific nets
		 * into larger LSIDs.
		 */
		if (mask < DB_MASK(*me))
		    break;		/* install here */
		else if (mask != DB_MASK(*me))
		    continue;

		/* third key -- advertising router */
		for (; *me && mls_id == (LS_ID(*me) & mask)
			 && mask == DB_MASK(*me);
		     me = &(*me)->lsdb_next_masked) {
		    if (key1 > ADV_RTR(*me))
			break; /* Install here */
		}
		break;
	    }
	    break;
	}

    }

    *db = (struct LSDB *) task_block_alloc(ospf_lsdb_index);
    if (!(*db))
	return FALSE;

    /* link into queue */
    (*db)->lsdb_next = *e;
    *e = *db;

    /* link into masked queue if needed and store hash value */
    if (me) {
	(*db)->lsdb_next_masked = *me;
	*me = *db;
	(*db)->lsdb_hash_masked = mhash;
    }

    DB_FREEME(*db) = FALSE;
    (*db)->lsdb_dist = (type < LS_SUM_NET) ? RTRLSInfinity : SUMLSInfinity;
    (*db)->lsdb_hash = hash;
    (*db)->lsdb_area = area;

    switch(type) {
    case LS_STUB:
	assert(FALSE);
	break;

    case LS_RTR:
    case LS_NET:
    case LS_SUM_NET:
    case LS_SUM_ASB:
	ospf.db_cnt++;
	area->db_cnts[type]++;
	area->db_int_cnt++;
	break;

    case LS_ASE:
	ospf.db_cnt++;
	ospf.db_ase_cnt++;
	break;
    }

    /* 
     * successful add, not found 
     */
    return FALSE;
}


/*
 * findLSA 		Add sum lsa or ase lsa to the linked list
 */
struct LSDB *
findLSA (struct LSDB_HEAD * hp, u_int32 ls_id, u_int32 key1, u_int type)
{
    register struct LSDB *e;

    assert(type <= LS_ASE);

    LSDB_LIST(hp, e) {
	if (ls_id == LS_ID(e)) {
	    if (type == LS_NET || type == LS_RTR) {
		/* These types use only one key */

		return e;
	    }
	    
	    for (; e && ls_id == LS_ID(e); e = e->lsdb_next) {
		if (key1 == ADV_RTR(e)) {
		    /* Found the one we are looking for */

		    return e;
		} else if (key1 > ADV_RTR(e)) {
		    /* Does not exist */
		    
		    break;
		}
	    }

	    /* Can not find the second key */

	    break;
	} else if (ls_id > LS_ID(e)) {
	    /* Can not find the first key */

	    break;
	}
    } LSDB_LIST_END(hp, e) ;

    return (struct LSDB *)  0;
}


/*
 *	Add a stub network lsa
 */
int
ospf_add_stub_lsa (struct LSDB ** db, struct AREA * area,
    u_int32 net, u_int32 advrtr, u_int32 mask)
{
    struct LSDB **e;
    int hash = XHASH(advrtr, advrtr);
    struct LSDB_HEAD *hp = &area->htbl[LS_STUB][hash];

    for (e = &DBH_LIST(hp); *e; e = &(*e)->lsdb_next) {
	if (advrtr > ADV_RTR(*e)) {
	    /* Insert here */

	    break;
	} else if (advrtr == ADV_RTR(*e)
		   && net == DB_NETNUM(*e)) {
	    if (mask == DB_MASK(*e)) {
		*db = *e;
		return TRUE;
	    }
	} 
    }
    
    *db = (struct LSDB *) task_block_alloc(ospf_lsdb_index);
    if (!(*db)) {
	return FALSE;
    }
    (*db)->lsdb_next = *e;
    *e = *db;
    DB_RTR(*db) = (struct RTR_LA_HDR *) 0;
    DB_FREEME(*db) = FALSE;
    (*db)->lsdb_dist = RTRLSInfinity;
    (*db)->lsdb_hash = hash;
    (*db)->lsdb_area = area;

    area->db_cnts[LS_STUB]++;

    /* 
     * successful add, not found 
     */
    return FALSE;
}


/**/

/*
 * free a db entry
 *	- called by RxLsAck, RxLinkUp or tq_dbage
 *	- spf will have just been run so parent list and routes will have
 * 	  been freed
 *	- leave entry around db age will free the rest for
 *	  LS_ASE and LS_SUM_NET else since most other entries may be back
 *	  just free structure
 */
void
db_free (struct LSDB * db, int type)
{
    struct AREA *area = db->lsdb_area;
    u_int16 chksum;
    struct LSDB_HEAD *hp = (struct LSDB_HEAD *) 0;
    struct LSDB_HEAD *mhp = (struct LSDB_HEAD *) 0;
    register struct LSDB *sp;

    if (DB_RTR(db)) {
	if (TRACE_TF(ospf.trace_options, TR_OSPF_LSA_BLD)) {
	    ospf_trace_build(area, area, db->lsdb_adv, TRUE);
	}
	type = LS_TYPE(db);
	chksum = LS_CKS(db);
	DBADV_FREE(db);
    } else {
	assert(type);
	chksum = 0;
    }

    switch(type) {
    case LS_STUB:
	area->db_cnts[LS_STUB]--;
	hp = &area->htbl[type][db->lsdb_hash];
	break;

    case LS_RTR:
    case LS_NET:
    case LS_SUM_NET:
    case LS_SUM_ASB:
	ospf.db_cnt--;
	area->db_cnts[type]--;
	area->db_int_cnt--;
	area->db_chksumsum -= chksum;
	hp = &area->htbl[type][db->lsdb_hash];
	if (type == LS_SUM_NET)
	    mhp = &area->sum_net_masked[db->lsdb_hash_masked];
	break;

    case LS_ASE:
	ospf.db_cnt--;
	ospf.db_ase_cnt--;
	ospf.db_chksumsum -= chksum;
	hp = &ospf.ase[db->lsdb_hash];
	mhp = &ospf.ase_masked[db->lsdb_hash_masked];
	break;

    default:
	assert(FALSE);
    }

    /* Remove from LSDB */
    LSDB_LIST(hp, sp) {
	if (sp == db) {
	    LSDB_LIST_DELETE(hp, db);
	    /*
	     * XXX shouldn't we terminate the search now?
	     */
	}
    } LSDB_LIST_END(hp, sp);

    /* Remove from masked queue if on one */
    if (mhp) {
	LSDB_MASKED_LIST(mhp, sp) {
	    if (sp == db) {
		LSDB_MASKED_LIST_DELETE(hp, db);
		break;
	    }
	} LSDB_MASKED_LIST_END(hp, sp);
    }

    ospf_nh_free_list(db->lsdb_nhcnt, db->lsdb_nh);

    DB_REMQUE(db);

    task_block_free(ospf_lsdb_index, (void_t) db);
}
#endif /* PROTO_OSPF */
