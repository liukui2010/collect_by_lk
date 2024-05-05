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
 * SLSP private implementation definitions
 */

/*
 * Maximum amount of a broken packet we dump, and the amount to dump to a line.
 */
#define	SLSP_PKTDUMP_LINE	16
#define	SLSP_PKTDUMP_MAX	(SLSP_PKTDUMP_LINE * 6)

/*
 * Macros to deal with LSP AS payload lists.
 */

/*
 * Insert a new AS entry after the current entry
 */
#define	SLSP_ASL_APPEND(current, new) \
    do { \
	register slsp_db_as *Xn = (new); \
	register slsp_db_as *Xc = (current); \
	Xn->slspdb_as_prev = Xc; \
	Xn->slspdb_as_next = Xc->slspdb_as_next; \
	Xc->slspdb_as_next->slspdb_as_prev = Xn; \
	Xc->slspdb_as_next = Xn; \
    } while (0)

/*
 * Insert a new AS entry before the current entry
 */
#define SLSP_ASL_PREPEND(current, new) \
    do { \
	register slsp_db_as *Xn = (new); \
	register slsp_db_as *Xc = (current); \
	Xn->slspdb_as_next = Xc; \
	Xn->slspdb_as_prev = Xc->slspdb_as_prev; \
	Xc->slspdb_as_prev->slspdb_as_next = Xn; \
	Xc->slspdb_as_prev = Xn; \
    } while (0)

/*
 * Remove an AS entry from its list.
 */
#define	SLSP_ASL_REMOVE(current) \
    do { \
	register slsp_db_as *Xc = (current); \
	Xc->slspdb_as_prev->slspdb_as_next = Xc->slspdb_as_next; \
	Xc->slspdb_as_next->slspdb_as_prev = Xc->slspdb_as_prev; \
    } while (0)

/*
 * For received AS lists, rather than the local one, we don't bother
 * maintaining the back pointer.  This adds an AS to a list and bumps
 * the count.
 */
#define	SLSP_ASL_ADD(list, new) \
    do { \
	register slsp_db_as *Xl = (list); \
	register slsp_db_as *Xn = (new); \
	Xn->slspdb_as_next = Xl; \
	Xl->slspdb_as_prev->slspdb_as_next = Xn; \
	Xl->slspdb_as_prev = Xn; \
	Xl->slspdb_as_count++; \
    } while (0)

/*
 * Macro to initialize the head of a list
 */
#define	SLSP_ASL_INIT(list) \
    do { \
	register slsp_db_as *Xl = (list); \
	Xl->slspdb_as_prev = Xl->slspdb_as_next = Xl; \
	Xl->slspdb_as_nextlist = (slsp_db_as *)0; \
	Xl->slspdb_as = Xl->slspdb_as_count = 0; \
    } while (0)

/*
 * The local set of ASes is hashed so we can find individual AS entries
 * quickly.  The hash is a simple power-of-two hash.
 */
#define	SLSP_ASL_HASHSIZE	32
#define	SLSP_ASL_HASHMASK	(SLSP_ASL_HASHSIZE-1)
#define	SLSP_ASL_HASH(as)	((as) & SLSP_ASL_HASHMASK)


/*
 * Macros to deal with the links payload lists
 */

/*
 * Insert a new link entry after the current entry
 */
#define	SLSP_LINK_APPEND(current, new) \
    do { \
	register slsp_db_link *Xn = (new); \
	register slsp_db_link *Xc = (current); \
	Xn->slspdb_link_prev = Xc; \
	Xn->slspdb_link_next = Xc->slspdb_link_next; \
	Xc->slspdb_link_next->slspdb_link_prev = Xn; \
	Xc->slspdb_link_next = Xn; \
    } while (0)

/*
 * Insert a new link entry before the current entry
 */
#define SLSP_LINK_PREPEND(current, new) \
    do { \
	register slsp_db_link *Xn = (new); \
	register slsp_db_link *Xc = (current); \
	Xn->slspdb_link_next = Xc; \
	Xn->slspdb_link_prev = Xc->slspdb_link_prev; \
	Xc->slspdb_link_prev->slspdb_link_next = Xn; \
	Xc->slspdb_link_prev = Xn; \
    } while (0)

/*
 * Remove a link entry from its list.
 */
#define	SLSP_LINK_REMOVE(current) \
    do { \
	register slsp_db_link *Xc = (current); \
	Xc->slspdb_link_prev->slspdb_link_next = Xc->slspdb_link_next; \
	Xc->slspdb_link_next->slspdb_link_prev = Xc->slspdb_link_prev; \
    } while (0)

/*
 * For received linked lists, rather than the local one, we don't bother
 * maintaining the back pointer.  This adds a link to the end of the list.
 */
#define	SLSP_LINK_ADD(list, new) \
    do { \
	register slsp_db_link *Xl = (list); \
	register slsp_db_link *Xn = (new); \
	Xn->slspdb_link_next = Xl; \
	Xl->slspdb_link_prev->slspdb_link_next = Xn; \
	Xl->slspdb_link_prev = Xn; \
    } while (0)

/*
 * Initialize the first link added to the list.
 */
#define	SLSP_LINK_INIT(new) \
    do { \
	register slsp_db_link *Xn = (new); \
	Xn->slspdb_link_next = Xn->slspdb_link_prev = Xn; \
    } while (0)


/*
 * Macros to manipulate LSP lists
 */

/*
 * Insert a node in a route list after the current entry
 */
#define	SLSP_RT_APPEND(current, new) \
    do { \
	register slsp_rtlist *Xn = (slsp_rtlist *)(new); \
	register slsp_rtlist *Xc = (slsp_rtlist *)(current); \
	Xn->slsp_rtprev = Xc; \
	Xn->slsp_rtnext = Xc->slsp_rtnext; \
	Xc->slsp_rtnext->slsp_rtprev = Xn; \
	Xc->slsp_rtnext = Xn; \
    } while (0)

/*
 * Insert a node in a route list before the current entry
 */
#define SLSP_RT_PREPEND(current, new) \
    do { \
	register slsp_rtlist *Xn = (slsp_rtlist *)(new); \
	register slsp_rtlist *Xc = (slsp_rtlist *)(current); \
	Xn->slsp_rtnext = Xc; \
	Xn->slsp_rtprev = Xc->slsp_rtprev; \
	Xc->slsp_rtprev->slsp_rtnext = Xn; \
	Xc->slsp_rtprev = Xn; \
    } while (0)

/*
 * Remove a node from its route list.
 */
#define	SLSP_RT_REMOVE(current) \
    do { \
	register slsp_rtlist *Xc = (slsp_rtlist *)(current); \
	Xc->slsp_rtprev->slsp_rtnext = Xc->slsp_rtnext; \
	Xc->slsp_rtnext->slsp_rtprev = Xc->slsp_rtprev; \
    } while (0)

/*
 * Initialize the head of a route list
 */
#define	SLSP_RT_INIT(head) \
    do { \
	register slsp_rtlist *Xh = (slsp_rtlist *)(head); \
	Xh->slsp_rtnext = Xh->slsp_rtprev = Xh; \
    } while (0)

/*
 * Find the next node in a route list.
 */
#define	SLSP_RT_NEXT(head, current) \
    ((((slsp_rtlist *)(current))->slsp_rtnext == (slsp_rtlist *)(head)) ? \
      (slsp_db_node *)0 : ((slsp_db_node *)(((slsp_rtlist *)(current))->slsp_rtnext)))

/*
 * Find the previous node in a route list
 */
#define	SLSP_RT_PREV(head, current) \
    ((((slsp_rtlist *)(current))->slsp_rtprev == (slsp_rtlist *)(head)) ? \
      (slsp_db_node *)0 : ((slsp_db_node *)(((slsp_rtlist *)(current))->slsp_rtprev)))

/*
 * Determine if a route list is empty or not.
 */
#define	SLSP_RT_EMPTY(head) \
    (((slsp_rtlist *)(head))->slsp_rtprev == ((slsp_rtlist *)(head)))

/*
 * Insert a node in the transmit list after the current entry
 */
#define	SLSP_XMT_APPEND(current, new) \
    do { \
	register slsp_list *Xn = (slsp_list *)(new); \
	register slsp_list *Xc = (slsp_list *)(current); \
	Xn->slsp_xmt_prev = Xc; \
	Xn->slsp_xmt_next = Xc->slsp_xmt_next; \
	Xc->slsp_xmt_next->slsp_xmt_prev = Xn; \
	Xc->slsp_xmt_next = Xn; \
    } while (0)

/*
 * Insert a node in the transmit list before the current entry
 */
#define SLSP_XMT_PREPEND(current, new) \
    do { \
	register slsp_list *Xn = (slsp_list *)(new); \
	register slsp_list *Xc = (slsp_list *)(current); \
	Xn->slsp_xmt_next = Xc; \
	Xn->slsp_xmt_prev = Xc->slsp_xmt_prev; \
	Xc->slsp_xmt_prev->slsp_xmt_next = Xn; \
	Xc->slsp_xmt_prev = Xn; \
    } while (0)

/*
 * Remove a node from its transmit list.
 */
#define	SLSP_XMT_REMOVE(current) \
    do { \
	register slsp_list *Xc = (slsp_list *)(current); \
	Xc->slsp_xmt_prev->slsp_xmt_next = Xc->slsp_xmt_next; \
	Xc->slsp_xmt_next->slsp_xmt_prev = Xc->slsp_xmt_prev; \
    } while (0)

/*
 * Initialize the head of the transmit list
 */
#define	SLSP_XMT_INIT(head) \
    do { \
	register slsp_list *Xh = (slsp_list *)(head); \
	Xh->slsp_xmt_next = Xh->slsp_xmt_prev = Xh; \
    } while (0)

/*
 * Find the next node in the transmit list.
 */
#define	SLSP_XMT_NEXT(head, current) \
    ((((slsp_list *)(current))->slsp_xmt_next == (slsp_list *)(head)) ? \
      (slsp_db_node *)0 : ((slsp_db_node *)(((slsp_list *)(current))->slsp_xmt_next)))

/*
 * Find the previous node in the transmit list
 */
#define	SLSP_XMT_PREV(head, current) \
    ((((slsp_list *)(current))->slsp_xmt_prev == (slsp_list *)(head)) ? \
      (slsp_db_node *)0 : ((slsp_db_node *)(((slsp_list *)(current))->slsp_xmt_prev)))

/*
 * Insert a node in the lifetime list after the current entry
 */
#define	SLSP_LIFE_APPEND(current, new) \
    do { \
	register slsp_list *Xn = (slsp_list *)(new); \
	register slsp_list *Xc = (slsp_list *)(current); \
	Xn->slsp_life_prev = Xc; \
	Xn->slsp_life_next = Xc->slsp_life_next; \
	Xc->slsp_life_next->slsp_life_prev = Xn; \
	Xc->slsp_life_next = Xn; \
    } while (0)

/*
 * Insert a node in the lifetime list before the current entry
 */
#define SLSP_LIFE_PREPEND(current, new) \
    do { \
	register slsp_list *Xn = (slsp_list *)(new); \
	register slsp_list *Xc = (slsp_list *)(current); \
	Xn->slsp_life_next = Xc; \
	Xn->slsp_life_prev = Xc->slsp_life_prev; \
	Xc->slsp_life_prev->slsp_life_next = Xn; \
	Xc->slsp_life_prev = Xn; \
    } while (0)

/*
 * Remove a node from the lifetime list.
 */
#define	SLSP_LIFE_REMOVE(current) \
    do { \
	register slsp_list *Xc = (slsp_list *)(current); \
	Xc->slsp_life_prev->slsp_life_next = Xc->slsp_life_next; \
	Xc->slsp_life_next->slsp_life_prev = Xc->slsp_life_prev; \
    } while (0)

/*
 * Initialize the head of the lifetime list
 */
#define	SLSP_LIFE_INIT(head) \
    do { \
	register slsp_list *Xh = (slsp_list *)(head); \
	Xh->slsp_life_next = Xh->slsp_life_prev = Xh; \
    } while (0)

/*
 * Find the next node in the lifetime list.
 */
#define	SLSP_LIFE_NEXT(head, current) \
    ((((slsp_list *)(current))->slsp_life_next == (slsp_list *)(head)) ? \
     (slsp_db_node *)0 : ((slsp_db_node *)(((slsp_list *)(current))->slsp_life_next)))

/*
 * Find the previous node in the lifetime list
 */
#define	SLSP_LIFE_PREV(head, current) \
    ((((slsp_list *)(current))->slsp_life_prev == (slsp_list *)(head)) ? \
     (slsp_db_node *)0 : ((slsp_db_node *)(((slsp_list *)(current))->slsp_life_prev)))


/*
 * Insert a node in the full list after the current entry
 */
#define	SLSP_FULL_APPEND(current, new) \
    do { \
	register slsp_list *Xn = (slsp_list *)(new); \
	register slsp_list *Xc = (slsp_list *)(current); \
	Xn->slsp_full_prev = Xc; \
	Xn->slsp_full_next = Xc->slsp_full_next; \
	Xc->slsp_full_next->slsp_full_prev = Xn; \
	Xc->slsp_full_next = Xn; \
    } while (0)

/*
 * Insert a node in the full list before the current entry
 */
#define SLSP_FULL_PREPEND(current, new) \
    do { \
	register slsp_list *Xn = (slsp_list *)(new); \
	register slsp_list *Xc = (slsp_list *)(current); \
	Xn->slsp_full_next = Xc; \
	Xn->slsp_full_prev = Xc->slsp_full_prev; \
	Xc->slsp_full_prev->slsp_full_next = Xn; \
	Xc->slsp_full_prev = Xn; \
    } while (0)

/*
 * Remove a node from the full list.
 */
#define	SLSP_FULL_REMOVE(current) \
    do { \
	register slsp_list *Xc = (slsp_list *)(current); \
	Xc->slsp_full_prev->slsp_full_next = Xc->slsp_full_next; \
	Xc->slsp_full_next->slsp_full_prev = Xc->slsp_full_prev; \
    } while (0)

/*
 * Initialize the head of the lifetime list
 */
#define	SLSP_FULL_INIT(head) \
    do { \
	register slsp_list *Xh = (slsp_list *)(head); \
	Xh->slsp_full_next = Xh->slsp_full_prev = Xh; \
    } while (0)

/*
 * Clear the full pointers in the current node to mark it not on
 * the list.
 */
#define	SLSP_FULL_CLEAR(current) \
    do { \
	register slsp_list *Xc = (slsp_list *)(current); \
	Xc->slsp_full_prev = Xc->slsp_full_next = (slsp_list *) 0; \
    } while (0)

/*
 * Find the next node in the full list.
 */
#define	SLSP_FULL_NEXT(head, current) \
    ((((slsp_list *)(current))->slsp_full_next == (slsp_list *)(head)) ? \
     (slsp_db_node *)0 : ((slsp_db_node *)(((slsp_list *)(current))->slsp_full_next)))

/*
 * Find the previous node in the full list
 */
#define	SLSP_FULL_PREV(head, current) \
    ((((slsp_list *)(current))->slsp_full_prev == (slsp_list *)(head)) ? \
     (slsp_db_node *)0 : ((slsp_db_node *)(((slsp_list *)(current))->slsp_full_prev)))

/*
 * Macros to deal with the full sequence numbers transmission list
 */

/*
 * Insert a new full sequence queue entry after the current entry
 */
#define	SLSP_FSQ_APPEND(current, new) \
    do { \
	register slsp_full_seq_q *Xn = (new); \
	register slsp_full_seq_q *Xc = (current); \
	Xn->slsp_fq_prev = Xc; \
	Xn->slsp_fq_next = Xc->slsp_fq_next; \
	Xc->slsp_fq_next->slsp_fq_prev = Xn; \
	Xc->slsp_fq_next = Xn; \
    } while (0)

/*
 * Insert a new full sequence queue entry before the current entry
 */
#define SLSP_FSQ_PREPEND(current, new) \
    do { \
	register slsp_full_seq_q *Xn = (new); \
	register slsp_full_seq_q *Xc = (current); \
	Xn->slsp_fq_next = Xc; \
	Xn->slsp_fq_prev = Xc->slsp_fq_prev; \
	Xc->slsp_fq_prev->slsp_fq_next = Xn; \
	Xc->slsp_fq_prev = Xn; \
    } while (0)

/*
 * Remove a full sequence queue entry from the list
 */
#define	SLSP_FSQ_REMOVE(current) \
    do { \
	register slsp_full_seq_q *Xc = (current); \
	Xc->slsp_fq_prev->slsp_fq_next = Xc->slsp_fq_next; \
	Xc->slsp_fq_next->slsp_fq_prev = Xc->slsp_fq_prev; \
    } while (0)

/*
 * Initialize the full sequence queue head
 */
#define	SLSP_FSQ_INIT(new) \
    do { \
	register slsp_full_seq_q *Xn = (new); \
	Xn->slsp_fq_next = Xn->slsp_fq_prev = Xn; \
    } while (0)


/*
 * Full sequence numbers packets on point-to-point links go out
 * several times to make sure they got though.  This is not in
 * the standard so it goes here.  On broadcast interfaces we wait
 * a small time before sending them.
 */
#define	SLSP_FULL_SEQ_MIN_TIME	6	/* minimum interval to send FSQ pkts */
#define	SLSP_FULL_SEQ_COUNT	3	/* send them three times */
#define	SLSP_FULL_SEQ_BCAST_INIT_TIME	1	/* time before sending bcast */


/*
 * The slsp bits structure is used to indicate the list of interfaces
 * an LSP needs to be transmitted from.  It is a fixed size, from
 * which derives the limitation on the number of local interfaces
 * a machine may have.
 *
 * The bits are numbered from 1 to SLSP_MAXINTERFACES
 */
#define	SLSP_BITMASK	(SLSP_BITSIZE-1)
#define	SLSP_WORDINDEX(x)	((x) >> SLSP_BITSHIFT)
#define	SLSP_BITINDEX(x)	((x) & SLSP_BITMASK)
#define	SLSP_BITINMASK(x)	(((slsp_bit_t)1) << SLSP_BITINDEX((x)))

/*
 * Test a nbr bit in the bit mask
 */
#define	SLSP_BIT_TEST(bits, nbr) \
    (((bits)->slsp_bit_set[(nbr)->slsp_nbr_offset] \
      & (nbr)->slsp_nbr_bitmask) != 0)
/*
 * Set a nbr bit in the bit mask.
 */
#define	SLSP_BIT_SET(bits, nbr) \
    do { \
	register slsp_bits *Xbits = (bits); \
	register slsp_neighbour *Xnbr = (nbr); \
	if (!SLSP_BIT_TEST(Xbits, Xnbr)) { \
	    Xbits->slsp_bit_set[Xnbr->slsp_nbr_offset] \
	      |= Xnbr->slsp_nbr_bitmask; \
	    Xbits->slsp_bit_n_set++; \
	} \
    } while (0)

/*
 * Clear a bit in the bit mask.
 */
#define	SLSP_BIT_CLR(bits, nbr) \
    do { \
	register slsp_bits *Xbits = (bits); \
	register slsp_neighbour *Xnbr = (nbr); \
	if (SLSP_BIT_TEST(Xbits, Xnbr)) { \
	    Xbits->slsp_bit_set[Xnbr->slsp_nbr_offset] \
	      &= ~(Xnbr->slsp_nbr_bitmask); \
	    Xbits->slsp_bit_n_set--; \
	} \
    } while (0)


/*
 * Mask value to use when the node contains no internal linkage information
 * (there is one node like this in every tree).
 */
#define	SLSP_NOMASK	0xffffffff

/*
 * Locate the candidate node in the node tree.
 */
#define	SLSP_NODE_LOCATE(slsp, addr, node) \
    do { \
	register slsp_db_node *Xnp = (slsp)->slsp_nodes; \
	register u_long Xmask = SLSP_NOMASK; \
	register u_long Xkey = ntohl(sock2ip((addr))); \
	if (Xnp != NULL) { \
	    while (Xmask > Xnp->slsp_node_mask) { \
		Xmask = Xnp->slsp_node_mask; \
		if (Xmask & Xkey) { \
		    Xnp = Xnp->slsp_node_right; \
		} else { \
		    Xnp = Xnp->slsp_node_left; \
		} \
	    } \
	} \
	(node) = Xnp; \
    } while (0)


/*
 * SPF scheduling.  We wait a minimum of 1 second from the time an SPF
 * run is first requested.  We try to wait until we've had a full second
 * without a change to the database, but defer no more than 5 seconds total.
 */
#define	SLSP_SPF_WAIT		(1)
#define	SLSP_SPF_LONG_WAIT	(2)
#define	SLSP_SPF_MAX_DEFER	(5)

#define	SLSP_SPF_SCHEDULE(inp) \
    do { \
	register slsp_instance *Xinp = (inp); \
	if (BIT_TEST(Xinp->slsp_flags, SLSPF_SPF)) { \
	    Xinp->slsp_spf_requested = time_sec; \
	} else { \
	    slsp_spf_schedule(inp); \
	} \
    } while (0)

/*
 * Function and variable declarations
 */

/*
 * From slsp_rt.c
 */
extern void slsp_spf_schedule(slsp_instance *);
extern void slsp_rt_reinit(task *);
extern void slsp_rt_terminate(slsp_instance *);
extern void slsp_rt_dump(FILE *,
	   slsp_instance *);

/*
 * From slsp_nbr.c
 */
extern void slsp_nbr_terminate(slsp_neighbour *);
extern void slsp_nbr_terminate_all(slsp_instance *);
extern void slsp_nbr_ptp_hello(slsp_neighbour *,
	   byte *,
	   size_t);
extern void slsp_nbr_ptp_ihu(slsp_neighbour *,
	   byte *,
	   size_t);
extern void slsp_nbr_bcast_ihu(slsp_neighbour *,
	   byte *,
	   size_t);
extern void slsp_nbr_new_bcast_ihu(slsp_neighbour *,
	   sockaddr_un *,
	   byte *,
	   size_t);
extern void slsp_ifachange(task *,
	   if_addr *);
extern void slsp_nbr_dump(FILE *,
	   slsp_instance *);

/*
 * From slsp_db.c
 */
extern const byte slsp_bit_table[];
extern slsp_neighbour *slsp_db_ack_nbr;

#define	SLSP_DB_ACK_FLUSH() \
    do { \
	if (slsp_db_ack_nbr) { \
	    slsp_db_ack_flush((slsp_neighbour *) 0); \
	} \
    } while (0)

extern void slsp_db_bit_alloc(slsp_neighbour *);
extern void slsp_db_bit_free(slsp_neighbour *);
extern void slsp_db_ack_flush(slsp_neighbour *);
extern void slsp_db_dr_inform(slsp_neighbour *,
	   slsp_neighbour *);
extern void slsp_db_down(slsp_neighbour *);
extern void slsp_db_ptp_up(slsp_neighbour *);
extern void slsp_db_bcast_up(slsp_neighbour *);
extern void slsp_db_lsp(slsp_neighbour *,
	   byte *,
	   size_t);
extern void slsp_db_seq(slsp_neighbour *,
	   byte *,
	   size_t);
extern void slsp_db_lsp_useless(slsp_neighbour *,
	   byte *,
	   size_t);
extern void slsp_db_dump(FILE *,
	   slsp_instance *);
extern void slsp_db_init(slsp_instance *);
extern void slsp_db_terminate(slsp_instance *);
extern void slsp_db_link_changed(slsp_neighbour *);

/*
 * From slsp_io.c
 */
extern void slsp_pktdump(trace *,
	   const char *,
	   byte *,
	   size_t);
extern void slsp_send(slsp_neighbour *,
	   byte *,
	   size_t);
extern void slsp_io_add(slsp_neighbour *);
extern void slsp_io_remove(slsp_neighbour *);
extern void slsp_io_start(void);
extern void slsp_io_stop(void);

/*
 * From slsp_init.c
 */
extern const bits slsp_nbr_types[];
extern const bits slsp_nbr_states[];
extern const bits slsp_node_types[];
extern const bits slsp_route_lists[];
extern const bits slsp_instance_flags[];
extern slsp_instance *slsp_instance_list;


#ifdef	PROTO_SNMP
/*
 * From slsp_mib.c
 */
extern void slsp_init_mib(int);
extern void slsp_mib_remove_nbr(slsp_neighbour *);
#endif	/* PROTO_SNMP */

