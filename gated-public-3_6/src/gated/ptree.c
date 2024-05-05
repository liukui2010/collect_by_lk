/*
 * Consortium Release 4
 *
 * $Id: ptree.c,v 1.14 2000/03/17 07:54:52 naamato Exp $
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
 * __END_OF_COPYRIGHT__
 */
/*
 * Originally based on new_ospf, which was based on bgp_rt
 *
 * Unlike these previous implementations this one sorts the keys
 * (and the walks) in ascending order.
 *
 * TODO: implement partial walks.  One property of the tree is that
 * all nodes below a node N found with a key of variable length L
 * have the same prefix of length L.  Therefore a walk rooted
 * on such a node can yield all nodes which match said prefix.
 * 
 * Written by: Christian E. Hopps
 */

#ifdef	PTREE_TEST
#include <sys/types.h>
#include <assert.h>
#include <stdio.h>
#else	/* PTREE_TEST */
#include "include.h"
#endif	/* PTREE_TEST */
#include "gqueue.h"
#include "ptree.h"


/*
 * -----------------------------------------------------
 *      Local Prototypes
 * -----------------------------------------------------
 */
static pindex_t bitdiff(u_char *, u_char *, int);
static void walk_rebuild(pwalk_t *, pnode_t *);

/*
 * -----------------------------------------------------
 *      Local Functions
 * -----------------------------------------------------
 */

/* extract the key pointer from the node */
#define	PTREE_GETKEY(tp, np)	\
    (((tp)->t_dataoff) ?	\
    (*((u_char **)((u_char *)(np) + (tp)->t_dataoff)) + (tp)->t_keyoff) \
    : ((u_char *)(np) + (tp)->t_keyoff))

/* compare keys */
#define PTREE_KEYCMP(kp1, kp2, len) (memcmp(kp1, kp2, len) == 0)

/* sorts less than any valid bitindex, indicates no children on node */
#define PTREE_NOBIT	((pindex_t)(-1))

#if PTREE_NBBY == 8

/* get the bit mask */
#define PTREE_BIT(bi)	(1 << (7 - ((bi) & 0x07)))

/* get the byte index */
#define PTREE_OFF(bi)	((bi) >> 3)

#else

/* get the bit mask */
#define PTREE_BIT(bi)	(1 << ((PTREE_NBBY - 1) - ((bi) % PTREE_NBBY)))

/* get the byte index */
#define PTREE_OFF(bi)	((bi) / PTREE_NBBY)

#endif

/* test the given bit in the key */
#define PTREE_BITTEST(bi, key) \
    (BIT_TEST((key)[PTREE_OFF(bi)], PTREE_BIT(bi)) != 0)


/*
 * Find out where kp1 and kp2 differ.
 */
static pindex_t
bitdiff(u_char *kp1, u_char *kp2, int klen)
{
	u_char *ekp, *skp;
	u_char diff, mask;
	pindex_t idx;

	/* increment idx by NBBY for each byte the same */
	idx = 0;
	skp = kp1;
	ekp = skp + klen;
	for (; kp1 < ekp; kp1++, kp2++) {
		if (*kp1 != *kp2)
			break;
		idx += PTREE_NBBY;
	}

	/* if not true this means no difference */
	GASSERT(kp1 != ekp);

	/* Add in the differing bit number */
	diff = *kp1 ^ *kp2;
	mask = PTREE_BIT(0);
	for (;;) {
		if (diff & mask)
			break;
		mask >>= 1;
		idx++;
	}
	return (idx);
}

/*
 * find a node in the tree, intializing a walk structure.
 * `fnp' must be in the tree.  This is used to fix a walk
 * stack after a removal or insertion.
 */
static void
walk_rebuild(pwalk_t *wp, pnode_t *fnp)
{
	ptree_t *tp;
	pnode_t *np;
	pindex_t bi;
	u_char *kp;

	tp = wp->w_tree;
	np = tp->t_root;
	GASSERT(np);

	/* push the root */
	wp->w_size = 0;
	wp->w_stack[wp->w_size++] = np;

	/*
	 * search to where the child pointer loops back up
	 */
	bi = PTREE_NOBIT;
	kp = PTREE_GETKEY(tp, fnp);
	while(bi < np->pn_bitindex) {
		bi =  np->pn_bitindex;

		if (PTREE_BITTEST(bi, kp))
			np = np->pn_right;
		else
			np = np->pn_left;	

		/* push the new node */
		wp->w_stack[wp->w_size++] = np;
	}

	GASSERT(np == fnp);
}

/*
 * -----------------------------------------------------
 *      Global Functions
 * -----------------------------------------------------
 */

/*
 * Initialize a ptree_t structure
 */
void
ptree_init(ptree_t *tp, int dataoff, int keyoff, int keylen)
{
	tp->t_root = 0;
	tp->t_nnodes = 0;
	tp->t_dataoff = dataoff;
	tp->t_keyoff = keyoff;
	tp->t_keylen = keylen;
	GQ_INIT(&tp->t_walkq);
}

/*
 * insert node 'nnp' in tree 'tp' using the search data found in 'sp'
 * 'sp' should have been initialized from a previous failed search for the
 * key.
 */
void
ptree_insert(ptree_t *tp, pnode_t *nnp, psearch_t *sp)
{
	pnode_t *np, *pnp, *fnp;
	pindex_t bitindex, diffbit;
	u_char *nkey, *fkey;
	pwalk_t *wp;

	/* if we want to support generic trees check for nnp == 0 here */

	/* handle empty tree */
	if ((fnp = sp->ps_last) == 0) {
		GASSERT(tp->t_nnodes == 0);
		GASSERT(tp->t_root == 0);
		tp->t_root = nnp;
		tp->t_nnodes = 1;
		nnp->pn_left = nnp->pn_right = nnp;
		nnp->pn_bitindex = PTREE_NOBIT;
		return;
	}

	/* get the keys from the nodes */
	nkey = PTREE_GETKEY(tp, nnp);
	fkey = PTREE_GETKEY(tp, fnp);

	/*
	 * figure out where the found node and the new node differ
	 */
	diffbit = bitdiff(nkey, fkey, tp->t_keylen);

	/*
	 * search in tree until we find the correct insertion location
	 */
	pnp = 0;
	np = tp->t_root;
	bitindex = PTREE_NOBIT;
	while (bitindex < np->pn_bitindex) {
		bitindex = np->pn_bitindex;

		/* stop just before the nodes differ */
		if (diffbit <= bitindex)
			break;
		pnp = np;
		if (PTREE_BITTEST(bitindex, nkey))
			np = np->pn_right;
		else
			np = np->pn_left;
	}

#ifndef	NDEBUG
	/* sanity check */
	if (!(diffbit - bitindex))
		GASSERT(0);
#endif
	/*
	 * insert the node
	 */
	if (PTREE_BITTEST(diffbit, nkey)) {
		nnp->pn_left = np;	/* to the node we inserted before */
		nnp->pn_right = nnp;	/* back to us */
	} else {
		nnp->pn_left = nnp;	/* back to us */
		nnp->pn_right = np;	/* to the node we inserted before */
	}
	nnp->pn_bitindex = diffbit;

	/*
	 * fix up previous node pointer
	 */
	if (!pnp)
		tp->t_root = nnp;
	else if (pnp->pn_left == np)
		pnp->pn_left = nnp;
	else
		pnp->pn_right = nnp;

	tp->t_nnodes++;

	/* make sure this wasn't a root insertion on empty tree */
	GASSERT(nnp->pn_left != nnp || nnp->pn_right != nnp);
	/* make sure the root isn't the only node in the tree */
	GASSERT(tp->t_root->pn_left != tp->t_root
	    || tp->t_root->pn_right != tp->t_root);

	/*
	 * Rebuild all walks stacks
	 */
	for (wp = GQ_FIRST(&tp->t_walkq); wp; wp = GQ_NEXT(wp, w_next)) {
		if (wp->w_size == 0)
			continue;
		walk_rebuild(wp, wp->w_stack[wp->w_size - 1]);
	}
}

/*
 * find a node in the tree. If not found, nextnode is the point of failure.
 */
pnode_t *
ptree_find(ptree_t *tp, const u_char *kp, psearch_t *sp)
{
	pnode_t *np;
	pindex_t bi;
	u_char *nkp;

	/*
	 * check for empty tree
	 */
	if ((np = tp->t_root) == 0) {
		sp->ps_last = 0;
		return (0);
	}

	/*
	 * search to where the child pointer loops back up
	 */
	bi = PTREE_NOBIT;
	while(bi < np->pn_bitindex) {
		bi =  np->pn_bitindex;

		if (PTREE_BITTEST(bi, kp))
			np = np->pn_right;
		else
			np = np->pn_left;	
	}

	sp->ps_last = np;

	/*
	 * see if keys are the same
	 */
	nkp = PTREE_GETKEY(tp, np);
	if (PTREE_KEYCMP(kp, nkp, tp->t_keylen))
		return (np);
	else
		return (0);
}

/*
 * Remove a node from a tree. The node is not freed. Uses the tough algorithm
 * found in bgp_rt.c. node point to the node we want to kill, so we do not
 * need to compare the keys!
 */
void
ptree_remove(ptree_t *tp, pnode_t *dnp)
{
	pwalk_t *wp;
	pnode_t *np, *tmp, *pnp, *pinp;
	pindex_t bi;
	u_int8 *kp;

	np = tp->t_root;
	GASSERT(np);

	/*
	 * check for one node tree
	 */
	if (np->pn_bitindex == PTREE_NOBIT) {
		GASSERT(np == dnp);
		GASSERT(tp->t_nnodes == 1);
		tp->t_root = 0;
		tp->t_nnodes = 0;

		/*
		 * Zero all walks since this was the last node
		 */
		for (wp = GQ_FIRST(&tp->t_walkq); wp; wp = GQ_NEXT(wp, w_next))
			wp->w_size = 0;

		return;
	}

	/* make sure that the root doesn't think its alone */
	GASSERT(np->pn_right != np || np->pn_left != np);

	/*
	 * Advance any walks that are pointing to the dead node
	 */
	for (wp = GQ_FIRST(&tp->t_walkq); wp; wp = GQ_NEXT(wp, w_next)) {
		if (wp->w_size == 0)
			continue;
		if (wp->w_stack[wp->w_size - 1] == dnp)
			(void)ptree_walk_next(wp);
	}

	/*
	 * find all nodes we need to remove dnp
	 */
	kp = PTREE_GETKEY(tp, dnp);
	bi = np->pn_bitindex;
	pnp = pinp = 0;
	for(;;) {
		if (PTREE_BITTEST(bi, kp))
			tmp = np->pn_right;
		else
			tmp = np->pn_left;

		if (tmp == dnp) {
			/* are we coming from a upward link? */
			if (tmp->pn_bitindex <= bi)
				break;

			/* we are coming down. Set pinp  */
			pinp = np;
		}
		pnp = np;
		np = tmp;
		bi = np->pn_bitindex;
	}

	/*
	 * 'np' points to the node before 'dnp' (dead node), such that
	 * the link from 'np' to 'dnp' is an upward one.  i.e., 'np'
	 * is at the bottom of the tree.
	 *
	 * 'pnp' is the node before 'np' and is downward.
	 *
	 * 'pinp' is the node before 'dnp' such that the link
	 * from 'pinp' to 'dnp' is downward. i.e., pinp is the internal
	 * node above dnp.
	 *
	 *        pinp                     pinp
	 *           \                        \
	 *        /-->dnp                 /--> np
	 *        |   / \        ===>     |   / \
	 *        | ynp  ...              | ynp  ...
	 *        |       /               |       /
	 *        |      pnp              |      pnp
	 *        |      / \              |      / \
	 *        |     np  ...           |    tmp  ...
	 *        |____/^ \               |
	 *              | tmp             |
	 *              |                 ...
	 *              ...
	 *
	 * The goal is to replace 'dnp' with 'np'.
	 *
	 * To do so we must update the links as such:
	 * 	'pinp' points to 'np',
	 *	'np' points to whatever 'dnp' pointed to
	 *	'pnp' points to whatever 'np' was pointing to
	 */

	/* remember where 'np' was pointing to (beside dnp) */
	if (np->pn_right == dnp)
		tmp = np->pn_left;
	else
		tmp = np->pn_right;

	/* update 'pnp' */
	if (!pnp)
		tp->t_root = tmp;
	else if (pnp->pn_right == np)
		pnp->pn_right = tmp;
	else
		pnp->pn_left = tmp;

	/* update 'np' */
	if (np != dnp) {
		/* catch the case where we are removing the lowest node */
		if (dnp->pn_bitindex == PTREE_NOBIT) {
			np->pn_bitindex = PTREE_NOBIT;
			np->pn_right = np->pn_left = np;
		} else {
			np->pn_bitindex = dnp->pn_bitindex;
			np->pn_left = dnp->pn_left;
			np->pn_right = dnp->pn_right;
			/*
			 * update 'pinp'. It seems to me that if
			 * np == dnp then pinp == pnp.
		 	 */
			if (!pinp)
				tp->t_root = np;
			else if (pinp->pn_right == dnp)
				pinp->pn_right = np;
			else
				pinp->pn_left = np;
		}
	} else {
		/*
		 * this will only fail if there where no nodes above
		 * and this is leaf.. i.e. if dnp == tree which is caught
		 * above
		 */
		GASSERT(dnp->pn_bitindex != PTREE_NOBIT);
	}

	/* decrement the node count */
	tp->t_nnodes--;

	/*
	 * Rebuild all walks stacks
	 */
	for (wp = GQ_FIRST(&tp->t_walkq); wp; wp = GQ_NEXT(wp, w_next)) {
		if (wp->w_size == 0)
			continue;
		walk_rebuild(wp, wp->w_stack[wp->w_size - 1]);
	}
}

/*
 * returns the value that ptree_walk_next() would but doesn't actually
 * advance the walk
 */
pnode_t *
ptree_walk_peek(pwalk_t *wp)
{
	if (wp->w_size == 0)
		return (0);

	return (wp->w_stack[wp->w_size - 1]);
}

/*
 * returns the current (on entry) top of the stack and advances
 * to the next element.
 *
 * when we are called the element on the bottom of the stack has
 * just been processed.  pop it off then based on whether it was
 *	left or right of the parent:
 *
 *	if it was left: push right node and then left until we loop,
 *	pushing the nodes.
 *
 *	otherwise it was right, pop it off and repeat
 *
 * note: If the root is the only node it may not appear twice in the
 *	stack, as happens with all other nodes.
 */
pnode_t *
ptree_walk_next(pwalk_t *wp)
{
	pnode_t *np, *pnp, *rnp, *rvnp;

	/* handle size == 0, incase deletion occured */
	if (wp->w_size == 0)
		return (0);

	/*
	 * remember the top of the stack so that we can return it
	 */
	rvnp = wp->w_stack[--wp->w_size];

	/* pop the element, if none left we are done */
	if (wp->w_size == 0)
		return (rvnp);

	/*
	 * while the previous top is equal to the right branch -- pop
	 * this also handles leaf node where both pointers point back
	 * at themselves
	 */
	pnp = rvnp;
	np = wp->w_stack[wp->w_size - 1];
	while (np->pn_right == pnp) {
		if (--wp->w_size == 0)
			return (rvnp);
		pnp = np;
		np = wp->w_stack[wp->w_size - 1];
	}

	/*
	 * we are now at a node from which we previously went left
	 * and the right is valid -- push this node
	 */
	rnp = np->pn_right;
	wp->w_stack[wp->w_size++] = rnp;

	/* if we have looped back we are done */
	if (np->pn_bitindex >= rnp->pn_bitindex)
		return (rvnp);

	/* find the leftmost */
	np = rnp;
	while (np->pn_bitindex < np->pn_left->pn_bitindex) {
		np = np->pn_left;

		/* push the left node */
		wp->w_stack[wp->w_size++] = np;
	}

	/* push the looped back node */
	wp->w_stack[wp->w_size++] = np->pn_left;

	return (rvnp);
}

/*
 * initializes walk structure.  The stack contains the leftmost branch
 */
void
ptree_walk_init(pwalk_t *wp, ptree_t *tp, pnode_t **sp, pnode_t *np)
{
	wp->w_tree = tp;
	wp->w_stack = sp;

	/* add this walk to the head of the tree */
	GQ_ADDHEAD(&tp->t_walkq, wp, w_next);

	/* if a node was provided use that */
	if (np) {
		walk_rebuild(wp, np);
		return;
	}

	wp->w_size = 0;

	/* otherwise find the leftmost node */
	if ((np = tp->t_root) == 0)
		return;

	/* push the root -- analogous to the right push in ptree_walk_next */
	wp->w_stack[wp->w_size++] = np;

	/* find the leftmost node */
	while (np->pn_bitindex < np->pn_left->pn_bitindex) {
		np = np->pn_left;

		/* push the left node */
		wp->w_stack[wp->w_size++] = np;
	}

	/* push the looped back node */
	wp->w_stack[wp->w_size++] = np->pn_left;
}

/*
 * cleanup the walk structure
 */
void
ptree_walk_cleanup(pwalk_t *wp)
{
	/* remove walk from the tree */
	GQ_REMOVE(wp, w_next);
}

#ifdef PTREE_TEST
static void
ptree_dump_rec_logical_print(rtp, np)
	ptree_t *rtp;
	pnode_t *np;
{
	u_char *keyp;
	u_long lv;

	keyp = PTREE_GETKEY(rtp, np);
	lv = keyp[0] << 24 | keyp[1] << 16 | keyp[2] << 8 | keyp[3];

	fprintf(stdout, "%lu\n", lv);
}

static void
ptree_dump_rec_logical(rtp, np)
	ptree_t *rtp;
	pnode_t *np;
{

	if (np->pn_bitindex == PTREE_NOBIT) {
		ptree_dump_rec_logical_print(rtp, np);
		return;
	}

	/* if the left branch is not back into the tree take it */
	if (np->pn_bitindex < np->pn_left->pn_bitindex)
		ptree_dump_rec_logical(rtp, np->pn_left);
	else
		ptree_dump_rec_logical_print(rtp, np->pn_left);

	/* if the right branch is not back into the tree, take it */
	if (np->pn_bitindex < np->pn_right->pn_bitindex)
		ptree_dump_rec_logical(rtp, np->pn_right);
	else
		ptree_dump_rec_logical_print(rtp, np->pn_right);
}

void
ptree_dump_logical(rtp)
	ptree_t *rtp;
{
	if (rtp->t_root)
		ptree_dump_rec_logical(rtp, rtp->t_root);
}



void
ptree_dump_core(rtp)
	ptree_t *rtp;
{
}
#endif	/* PTREE_TEST */
