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


/* Generic double linked list structure
 */
typedef struct _list_t {
        struct _list_t *l_prev;
        struct _list_t *l_next;
} list_t;

#define LIST_REM(start, elm) { \
        if (((list_t *)elm)->l_next) \
                ((list_t *)elm)->l_next->l_prev = ((list_t *)elm)->l_prev; \
        if (((list_t *)elm)->l_prev) \
                ((list_t *)elm)->l_prev->l_next = ((list_t *)elm)->l_next; \
        if (((list_t *)start) == ((list_t *)elm)) \
                ((list_t *)start) = ((list_t *)elm)->l_next; \
}

#define LIST_ADD(start, elm) { \
        ((list_t *)elm)->l_prev = (list_t *)NULL; \
        ((list_t *)elm)->l_next = ((list_t *)start); \
        if (((list_t *)elm)->l_next) \
                ((list_t *)elm)->l_next->l_prev = ((list_t *)elm); \
        ((list_t *)start) = ((list_t *)elm); \
}

#define LIST_ADD_LAST(start, elm) { \
	list_t *l; \
	if (!((list_t *)(start))) { \
		((list_t *)start) = ((list_t *)elm); \
		((list_t *)elm)->l_prev = NULL; \
	} \
	else { \
		for(l = ((list_t *)start); l->l_next; l = l->l_next); \
		l->l_next = ((list_t *)elm); \
		((list_t *)elm)->l_prev = l; \
	} \
	((list_t *)elm)->l_next = NULL; \
}

#define LIST_INSERT(prev, elm) { \
	((list_t *)elm)->l_next = ((list_t *)prev)->l_next; \
	((list_t *)elm)->l_prev = ((list_t *)prev); \
	if (((list_t *)elm)->l_next) \
		((list_t *)elm)->l_next->l_prev = ((list_t *)elm); \
	((list_t *)prev)->l_next = ((list_t *)elm); \
}
	

#define MALLOC(new, type, size, msg) { \
        if (((new) = (type)malloc((size))) == NULL) \
                PrintError(EXT, EXIT, "Malloc failed for %s", (msg)); \
}

#define FREE(new, size, msg) { \
        free((char *)(new)); \
}

#define REALLOC(new, type, oldsize, newsize, msg) { \
        if (((new) = (type)realloc((new), (newsize))) == NULL) \
                PrintError(EXT, EXIT, "Realloc failed for %s", (msg)); \
}

