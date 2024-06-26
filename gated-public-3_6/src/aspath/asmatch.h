/*
 * Public Release 3
 * 
 * $Id: asmatch.h,v 1.8 2000/02/18 20:57:58 swright Exp $
 */

/*
 * ------------------------------------------------------------------------
 * 
 * Copyright (c) 1996,1997,1998,1999 The Regents of the University of Michigan
 * All Rights Reserved
 *  
 * Royalty-free licenses to redistribute GateD Release
 * 3 in whole or in part may be obtained by writing to:
 * 
 * 	Merit GateDaemon Project
 * 	4251 Plymouth Road, Suite C
 * 	Ann Arbor, MI 48105
 *  
 * THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE REGENTS OF THE
 * UNIVERSITY OF MICHIGAN AND MERIT DO NOT WARRANT THAT THE
 * FUNCTIONS CONTAINED IN THE SOFTWARE WILL MEET LICENSEE'S REQUIREMENTS OR
 * THAT OPERATION WILL BE UNINTERRUPTED OR ERROR FREE. The Regents of the
 * University of Michigan and Merit shall not be liable for
 * any special, indirect, incidental or consequential damages with respect
 * to any claim by Licensee or any third party arising from use of the
 * software. GateDaemon was originated and developed through release 3.0
 * by Cornell University and its collaborators.
 * 
 * Please forward bug fixes, enhancements and questions to the
 * gated mailing list: gated-people@gated.merit.edu.
 * 
 * ------------------------------------------------------------------------
 * 
 * Copyright (c) 1990,1991,1992,1993,1994,1995 by Cornell University.
 *     All rights reserved.
 * 
 * THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT
 * LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.
 * 
 * GateD is based on Kirton's EGP, UC Berkeley's routing
 * daemon	 (routed), and DCN's HELLO routing Protocol.
 * Development of GateD has been supported in part by the
 * National Science Foundation.
 * 
 * ------------------------------------------------------------------------
 * 
 * Portions of this software may fall under the following
 * copyrights:
 * 
 * Copyright (c) 1988 Regents of the University of California.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms are
 * permitted provided that the above copyright notice and
 * this paragraph are duplicated in all such forms and that
 * any documentation, advertising materials, and other
 * materials related to such distribution and use
 * acknowledge that the software was developed by the
 * University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote
 * products derived from this software without specific
 * prior written permission.  THIS SOFTWARE IS PROVIDED
 * ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 *  controls avl_tree - originally from avl.h
 */
struct avl_tree {
    struct avl_tree *back, *mid, *forw;
};

#define ASP_SKIP_SET 0x0001	/* part of a skip set */

struct _asp_trans {
  struct _asp_trans *next;
  struct _asp_state *state;
  u_short flags;
};

struct _asp_state {
  u_short asps_use_count;
  struct _asp_state *asps_grp;
  struct _asp_state *asps_grp_prev, *asps_grp_next;
  u_char asps_min, asps_max;
  /* u_char next_min, next_max; */
  struct _asp_table *asps_tree;
};

struct _asp_table {
  struct avl_tree search;	/* must be first */
  u_short use_count;
  as_t lo_as, hi_as;
  struct _asp_trans *trans;
};

typedef struct _asp_table asp_table;
typedef struct _asp_state asp_state;
typedef struct _asp_trans asp_trans;

struct _asmatch_t {
  flag_t origin_mask;
  struct _asp_table *first;
};

union _asp_alloc_blk {
  struct _asp_state state;
  struct _asp_table table;
  struct _asmatch_t regex;
};

typedef struct _asmatch_t asmatch_t;

struct _asp_range {
  u_short begin;
  u_short end;
};

typedef struct _asp_range asp_range;

typedef struct _asp_table * asp_stack; /* backward compatibility w/ parser.y */

void aspath_init_regex(void);
asmatch_t * aspath_consume_current(asp_stack);
void aspath_simple_regex(asp_stack *, asp_stack *);
void aspath_copy_regex(asp_stack *, asp_stack *);
void aspath_merge_regex(asp_stack *, asp_stack *, asp_stack *);
int aspath_prepend_regex(asp_stack *, asp_stack *, asp_stack *);
void aspath_zero_or_more_term(asp_stack *, asp_stack *);
void aspath_one_or_more_term(asp_stack *, asp_stack *);
void aspath_zero_or_one_term(asp_stack *, asp_stack *);
int aspath_range_term(asp_stack *, asp_stack *, asp_range *);
int aspath_as_transition(asp_stack *, int);
int aspath_any_transition(asp_stack *);


/* Routines to handle control information */

extern int aspath_adv_match(void_t, as_path *);
extern int aspath_adv_compare(void_t, void_t);
void aspath_adv_print(FILE *, void_t);
extern void aspath_adv_free(void_t);
extern char * aspath_adv_origins(flag_t);

void init_asmatch_alloc(void);
