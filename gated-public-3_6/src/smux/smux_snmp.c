/*
 * Gated Release 4.x, 5.x, 6.x, 7.x
 *
 * $Id: smux_snmp.c,v 1.7 2000/02/06 19:07:25 naamato Exp $
 */
/*
 * Copyright (c) 1996, 1997, 1998, 1999 The Regents of the University of Michigan.
 * All Rights Reserved.
 *
 * License to use, copy, modify, and distribute this software and its
 * documentation can be obtained from Merit at the University of Michigan.
 *
 * Merit GateDaemon Project
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
 * GateDaemon was originated and developed through release 3.0 by Cornell
 * University and its collaborators.
 *
 * Please forward bug fixes, enhancements and questions to the
 * gated mailing list: gated-people@gated.merit.edu.
 */
/*
 * GateD data structure support for SMUX module.
 * Author: Nick Amato <naamato@merit.net>
 *
 */

#include "include.h"
#ifdef PROTO_SMUX

#include "smux_snmp.h"

static int qsort_compare(const void *, const void *);

struct subtree *strees;
int strees_alloc = 0, strees_used = 0;
extern task *smux_task;

/*
 * Register this subtree for SNMP queries.
 */
void
add_all_subtrees(struct subtree *trees, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		if (!strees_alloc) {
			strees_alloc = 16;
			strees = task_mem_malloc(smux_task,
	 		    (size_t)(strees_alloc * sizeof(struct subtree)));
		} else if (strees_used == strees_alloc) {
			strees_alloc += 16;
			strees = task_mem_realloc(smux_task, (void_t)strees,
		    	    (size_t)(strees_alloc * sizeof(struct subtree)));
		}
		strees[strees_used++] = trees[i];
	}
}

static int
qsort_compare(const void *t1, const void *t2)
{
	return compare_oid(((struct subtree *)t1)->st_name,
	    ((struct subtree *)t1)->st_namelen,
	    ((struct subtree *)t2)->st_name,
	    ((struct subtree *)t2)->st_namelen);
}

void
finalize_tree(void)
{
	int i, j;
	struct variable *vp;

	for (i = 0; i < strees_used; i++) {
		    for (j = 0; j < strees[i].st_n_vars; j++) {
			vp = &(strees[i].st_vars[j]);
			bcopy(strees[i].st_name, vp->name,
			    (strees[i].st_namelen * sizeof(oid)));
			bcopy(vp->suf_name, 
			    &(vp->name[strees[i].st_namelen]),
			    (vp->suf_namelen * sizeof(oid)));
			vp->namelen = strees[i].st_namelen + vp->suf_namelen;
		}
	}
	qsort(strees, strees_used, sizeof(struct subtree),
	    qsort_compare);
}

int
compare_oid(oid *n1, int n1_len, oid *n2, int n2_len)
{
	int i, least;

	least = n1_len < n2_len ? n1_len : n2_len;

	for (i = 0; i < least; i++) {
		if (n1[i] < n2[i])
			return -1;
		else if (n1[i] > n2[i])
			return 1;
	}

	if (n1_len < n2_len)
		return -1;
	else if (n1_len > n2_len)
		return 1;
	else
		return 0;
}

int
compare_partial(oid *n1, int n1_len, oid *n2, int n2_len)
{
	int i, least;

	least = n1_len < n2_len ? n1_len : n2_len;

	for (i = 0; i < least; i++) {
		if (n1[i] < n2[i])
			return -1;
		else if (n1[i] > n2[i])
			return 1;
	}

	if (n1_len < n2_len)
		return -1;

	return 0;
}

int
single_inst_check(struct variable *v, oid *name, int *namelen, int exact)
{
	oid tnam[32];
	int res, tnam_len;

	bcopy(v->name, tnam, (v->namelen * sizeof(oid)));
	tnam[v->namelen] = 0;
	tnam_len = v->namelen + 1;

	res = compare_oid(name, *namelen, tnam, tnam_len);
	if (((res != 0) && exact) || (!exact && res >= 0))
		return 0;
	else {
		/* get next, fill in variable name */
		bcopy(tnam, name, (tnam_len * sizeof(oid)));
		*namelen = tnam_len;
	}
	return 1;
}

void
put_ipaddr(u_int32 addr, int spot, oid *name)
{
	name[spot] =   (oid)((addr & 0xFF000000) >> 24);
	name[spot+1] = (oid)((addr & 0x00FF0000) >> 16);
	name[spot+2] = (oid)((addr & 0x0000FF00) >> 8);
	name[spot+3] =   (oid)(addr & 0x000000FF);
}

int
get_ipaddr(oid *name, int len, int spot, u_int32 *addr)
{
	byte *caddr;
	int i, j;

	*addr = 0;
	caddr = (byte *)addr;

	if (len < (spot + 4))
		return 0;
	else {
		for (i = spot, j = 0; (i < spot + 4); i++, j++)
			caddr[j] = (u_char)name[i];
	}
	return 1;
}

/*
 * This implements a one-level OID-instance cache
 * See the snmp_last_free macro in snmp_cmu.h for how the memory
 * allocated here is freed
 *
 * (from snmp_cmu.c -- macro inline)
 */
int
snmp_last_match(unsigned int ** last, register unsigned int *in_oid,
    u_int len, int isnext)
{
    register unsigned int *lp = *last;
    register unsigned int *ip = in_oid;
    int last_len, last_isnext;
    unsigned int *llp;

    if (*last) {
	last_len = *lp++;

	if (last_len == len) {
	    last_isnext = *lp++;

	    if (last_isnext == isnext) {
		llp = lp + last_len;
		
		while (lp < llp) {
		    if (*lp++ != *ip++) {
			ip = in_oid;
			goto free_up;
		    }
		}

		return TRUE;
	    }
	}

#define snmp_last_free(last) \
        do { \
                 task_mem_free((task *) 0, (caddr_t) *(last)); \
                 *(last) = (unsigned int *) 0; \
         } while (0)

    free_up:
	snmp_last_free(last);
    }

    /* XXX - Could we figure out the max size? */
    *last = lp = (unsigned int *) task_mem_malloc((task *) 0,
						  (len + 2) * sizeof (int));
    llp = lp + len + 2;
    
    *lp++ = len;
    *lp++ = isnext;

    while (lp < llp) {
	*lp++ = *ip++;
    }
    return FALSE;
}

int	
oid2mediaddr(u_int *ip, byte *addr, int len, int islen)
{
    register int i;

    if (islen) {
	len = *ip++;
    } else {
	len = len ? len : 4;		/* len, else ipaddress, is default */
    }

    for (i = len; i > 0; i--) {
	*addr++ = *ip++;
    }

    return len + (islen ? 1 : 0);
}


#endif /* PROTO_SMUX */
