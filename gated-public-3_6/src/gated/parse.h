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


/* Tracing */

#define	TR_PARSE	TR_USER_1
#define	TR_ADV		TR_USER_2


#define	PS_INITIAL	0
#define	PS_OPTIONS	1
#define	PS_INTERFACE	2
#define	PS_DEFINE	3
#define	PS_PROTO	4
#define	PS_ROUTE	5
#define	PS_CONTROL	6
#define	PS_MIN		PS_OPTIONS
#define	PS_MAX		PS_CONTROL

#define	LIMIT_AS		1, 65534
#define	LIMIT_PREFERENCE	0, 255
#define	LIMIT_PORT		0, 65535
#define	LIMIT_NATURAL		0, (u_int) -1
#define	LIMIT_MINUTES		0, 59
#define	LIMIT_SECONDS		0, 59
#define LIMIT_ASCOUNT		1, 25

#define	FI_MAX	10			/* Maxiumum %include nesting level */

typedef struct {
    metric_t metric;			/* Actual metric */
    int state;				/* Metric state */
} pmet_t;

typedef struct {
    byte *ptr;			/* Pointer to the byte string */
    size_t len;				/* Length of string */
    char *strptr;			/* Ptr to matched input string */
    flag_t type;			/* Original format of string */
} bytestr;

typedef struct {
    char *ptr;				/* Pointer to the byte string */
    size_t len;				/* Length of string */
    flag_t type;			/* Original format of string */
} charstr;

#define	PARSE_METRIC_CLEAR(x)		(x)->metric = (metric_t) 0, (x)->state = PARSE_METRICS_UNSET
#define	PARSE_METRIC_SET(x, y)		(x)->metric = y, (x)->state = PARSE_METRICS_SET
#define	PARSE_METRIC_INFINITY(x)	(x)->state = PARSE_METRICS_INFINITY
#define	PARSE_METRIC_RESTRICT(x)	(x)->state = PARSE_METRICS_RESTRICT
#define	PARSE_METRIC_CONTINUE(x)	(x)->state = PARSE_METRICS_CONTINUE
#define	PARSE_METRIC_ALTERNATE(x, y)	(x)->metric = y, (x)->state = PARSE_METRICS_ALTERNATE
#define	PARSE_METRIC_ISSET(x)		((x)->state != PARSE_METRICS_UNSET)
#define	PARSE_METRIC_ISINFINITY(x)	((x)->state == PARSE_METRICS_INFINITY)
#define	PARSE_METRIC_ISRESTRICT(x)	((x)->state == PARSE_METRICS_RESTRICT)
#define	PARSE_METRIC_ISALTERNATE(x)	((x)->state == PARSE_METRICS_ALTERNATE)
#define	PARSE_METRIC_ISCONTINUE(x)	((x)->state == PARSE_METRICS_CONTINUE)

#define	PARSE_METRICS_UNSET		0		/* Metric has not yet been set */
#define	PARSE_METRICS_SET		1		/* Metric has been set */
#define	PARSE_METRICS_INFINITY		2		/* Metric set to infinity */
#define	PARSE_METRICS_RESTRICT		3		/* Metric is set to restrict (policy) */
#define	PARSE_METRICS_ALTERNATE		4		/* Alternate metric */

#define	PARSE_METRICS_CONTINUE		5		/* Metric is set to continue (policy) */ 

extern u_int parse_state;

extern char * parse_where(void);
extern int parse_open(char *);
extern int yylex(void);
void init_parser(void);

extern int yynerrs;
extern int yylineno;
extern char parse_error[];
extern char *parse_filename;
extern char *parse_directory;
extern flag_t protos_seen;
extern sockaddr_un parse_addr;

int yyparse(void);
int parse_keyword(char *, u_int);	/* Lookup a token given a keyword */
const char *parse_keyword_lookup(int);	/* Lookup a keyword given a token */
int parse_parse(const char *);		/* Parse the config file */
char *parse_strdump(char *);	/* Return a pointer to a duplicate string */
	/* Return pointer to a string giving current file and line */
char *parse_where(void); 
	/* Limit check an integer */
int parse_limit_check(const char *type, u_int value, u_int lower, u_int upper);
int parse_limit_check_tok(charstr *tokstr, u_int value, u_int lower, u_int upper);
	/* Lookup a string as a host name */
sockaddr_un *parse_addr_hostname(char *, char *);
	/* Lookup a string as a network name */
#ifdef PROTO_INET6
sockaddr_un *parse_addr6_hostname(char *, char *);
  /* Lookup a string as a network name */
#endif
sockaddr_un *parse_addr_netname(char *, char *);
	/* Append one advlist to another */
int parse_adv_append(adv_entry **, adv_entry *);
	/* Set flag in gw_entry for each element in list */
int parse_gw_flag(adv_entry *, proto_t, flag_t);
	/* Switch to a new state if it is a logical progression */
	/* from the current state */
int parse_new_state(int);
int parse_metric_check(proto_t, pmet_t *);	/* Verify a specified metric */
	/* Set metric in list for elements without metrics */
adv_entry * parse_adv_propagate_metric(adv_entry *, proto_t, pmet_t *,
    adv_entry *);
#if defined(PROTO_ASPATHS_MEMBER) || defined(PROTO_MPASPATHS)
	/* Set as path info in list for elements without */
adv_entry * parse_adv_propagate_api(adv_entry *, as_path_info *);
#endif /* defined(PROTO_ASPATHS_MEMBER) || defined(PROTO_MPASPATHS) */
	/* Set preference in list for elements without metrics */
adv_entry * parse_adv_propagate_preference(adv_entry *, proto_t, pmet_t *,
    adv_entry *, flag_t);
adv_entry * parse_adv_propagate_config(adv_entry *, config_list *, proto_t);
	/* Set preference in list for elements without preference */
void parse_adv_preference(adv_entry *, proto_t, pref_t);
	/* Append this list to the list for the specified exterior protocol */
int parse_adv_as(adv_entry **, adv_entry *);
int parse_args(int, char **);

