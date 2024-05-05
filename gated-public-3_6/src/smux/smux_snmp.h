/*
 * Gated Release 4.x, 5.x, 6.x, 7.x
 *
 * $Id: smux_snmp.h,v 1.6 2000/03/17 07:55:23 naamato Exp $
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
 */

#ifndef _SMUX_SNMP_H
#define _SMUX_SNMP_H
#include "smux_asn1.h"

typedef int (*PWM) (
    int      action,
    u_char  *var_val,
    u_char   var_val_type,
    int      var_val_len,
    oid     *name,
    int      name_len);

/*
 * An SNMP variable
 */
struct variable {
    u_char	magic;	/* passed to function as a hint */
    char	type;	/* type of variable from snmp_impl.h */
    u_short	acl;	/* access control list for variable */
    u_char	*(*findVar)(struct variable *, oid *, int *, int, int *, PWM *);
    int		suf_namelen;	/* suffix: length of name below */
    oid		suf_name[16];	/* suffix: object identifier of variable */
    int		namelen;	/* length of name below */
    oid		name[16 * 2];	/* object identifier of variable */
};


typedef u_char *(PFindVar) (
    struct variable *vp,
    oid *name,
    int *length,
    int  exact,
    int *var_len,
    PWM *write_method);

/* 
 * An SNMP subtree
 */
struct subtree {
	oid 	st_name[16];		/* name of the subree */
	u_short	st_namelen;		/* length of above name */
	struct 	variable *st_vars;	/* variable head pointer */
	int 	st_n_vars;		/* number of vars */
	int 	st_v_width;		/* width of variables */
	u_char 	st_flags;		/* flags for SMUX */
#define SMUX_TREE_REGISTER      0x01    /* Tree needs to be registered */
#define SMUX_TREE_REGISTERED    0x02    /* Tree has been registered */
#define SMUX_TREE_REG_FAILED    0x04    /* A previous reg. attempt failed */
};

/*
 *	*var_len = sizeof(int32_return);    *** assumed done by default
 *	int32_return = rt->rt_metric;
 *	return (u_char *)&int32_return;
 */
#define O_INTEGER(I) (int32_return = (I), (u_char *)&int32_return)

/*
 * mapping of smux's:
 *	return o_ipaddr(oi, v, sock2unix(rt->rt_dest, (int *) 0))
 * into cmu's:
 *	*var_len = sizeof(int32);
 *	return (u_char *)&sock2ip(rt->rt_dest);
 */
#define O_IPADDR(I) (*var_len = sizeof(int32), (u_char *)&sock2ip(I))
/*
 * For addresses which are stored directly as an int32 use:
 */
#define O_IPADDR_RAW(I) (*var_len = sizeof(int32), (u_char *)&I)

#define	oid2ipaddr(ip, addr, len) \
        do { \
           register int Xlen = (len); \
           if (Xlen <= 0) \
              bzero((void_t *)(addr), sizeof(struct in_addr)); \
           else { \
              register int Xi; \
              Xlen = MIN(sizeof(struct in_addr), Xlen); \
	      oid2mediaddr ((ip), (byte*) (addr), Xlen, 0); \
              for (Xi = sizeof(struct in_addr) - Xlen; Xi > 0; --Xi) \
                 ((byte*)(addr))[Xlen + Xi -1] = 0; \
           } \
        } while (0)

#define	snmp_last_free(last) \
	do { \
		 task_mem_free((task *) 0, (caddr_t) *(last)); \
		 *(last) = (unsigned int *) 0; \
	 } while (0)


#define	RETURN_BUF_SIZE	1024
int32	int32_return;
u_char 	return_buf[RETURN_BUF_SIZE];
extern int snmp_quantum;

#define ERROR_MSG(x)	fprintf(stderr, "%s\n", x);

void add_all_subtrees(struct subtree *, int);
void finalize_tree(void);
int compare_oid(oid *, int, oid *, int);
int compare_partial(oid *, int, oid *, int);
int single_inst_check(struct variable *, oid *, int *, int);
void put_ipaddr(u_int32, int, oid *);
int get_ipaddr(oid *, int, int, u_int32 *);
int oid2mediaddr(u_int *, byte *, int, int);
#endif /* _SMUX_SNMP_H */
