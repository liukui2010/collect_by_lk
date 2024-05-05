/*
 * Consortium Release 4
 *
 * $Id: ptree.h,v 1.11 2000/03/17 07:54:52 naamato Exp $
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

#ifdef PTREE_TEST
typedef	u_int32_t	u_int32;
typedef	u_int8_t	u_int8;
typedef	int16_t		s_int16;
#define	GASSERT		assert
#define	BIT_TEST(f,bm)	((f) & (bm))
#endif

/* number of bits per byte -- doesn't need to be 8 :) */
#define PTREE_NBBY	NBBY

/* bit index -- supports up to 32768 bits, i.e., 4096 byte key lengths */
typedef	s_int16	pindex_t;

/*
 * 10-12 bytes (depending on rounding)
 */
typedef struct _pnode_t {
	struct _pnode_t	*pn_left;
	struct _pnode_t	*pn_right;
	pindex_t	pn_bitindex;	/* support up to 256 bit key length */
} pnode_t;

/*
 * used when searching to report failed location for faster adds
 */
typedef struct _psearch_t {
	pnode_t	*ps_last;
} psearch_t;

/*
 * root tree structure, contains information on how to access the nodes
 *
 * 	p_dataoff -- if non-null indicates offset in pnode_t of pointer to
 *		object that contains key, otherwise the node itself is
 *		the object and is expected to contain the key
 *	p_keyoff -- offset into object where key starts
 *	p_keylen -- length of the key
 *
 */
typedef struct _ptree_t {
	struct _pnode_t		*t_root;
	GQ_HEAD(,_pwalk_t)	t_walkq;
	u_int32			t_nnodes;
	u_int8		t_dataoff;
	u_int8		t_keyoff;
	u_int8		t_keylen;
} ptree_t;

typedef	struct _pwalk_t {
	GQ_LINK(_pwalk_t)	w_next;	/* link to next walk */
	ptree_t		*w_tree;	/* the tree */
	pnode_t		**w_stack;	/* the walk stack */
	int		w_size;		/* the current stack size */
} pwalk_t;

/*
 * prototypes
 */
void	ptree_init(ptree_t *, int, int, int);
void	ptree_insert(ptree_t *, pnode_t *, psearch_t *);
pnode_t	*ptree_find(ptree_t *, const u_char *, psearch_t *);
void	ptree_remove(ptree_t *, pnode_t *);
void	ptree_walk_init(pwalk_t *, ptree_t *, pnode_t **, pnode_t *);
pnode_t *ptree_walk_next(pwalk_t *);
pnode_t *ptree_walk_peek(pwalk_t *);
void	ptree_walk_cleanup(pwalk_t *);
