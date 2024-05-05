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

#define INCLUDE_IOCTL
#define INCLUDE_SOCKIO  /* to get SIOCDELRT */
#define INCLUDE_ROUTE
#include "include.h"

#ifdef KRT_RT_IOCTL
#ifdef  PROTO_INET
#include "inet/inet.h"
#endif  /* PROTO_INET */
#ifdef  PROTO_ISO
#include "iso/iso.h"
#endif  /* PROTO_ISO */
#include "krt/krt.h"
#include "krt/krt_var.h"

flag_t krt_rt_support = KRTS_HOST|KRTS_MULTIPATH
#ifdef	VARIABLE_MASKS
	| KRTS_VAR_MASK
#endif	/* VARIABLE_MASKS */
	;

static struct rtentry krt[RT_N_MULTIPATH];

static inline int
krt_action (task * tp, u_long type, int nrt)
{
    int i, request_error = 0;

    for (i = 0; i < nrt; i++) {
    if ((!BIT_TEST(task_state, TASKS_TEST)
	 && !BIT_TEST(krt_options, KRT_OPT_NOINSTALL))
	 && (task_ioctl(krt_task->task_socket,
			type,
			(caddr_t) &krt[i], 
			sizeof (krt[i])) < 0)) {
	request_error = errno;
    }
    }
    return request_error;
}


static void
krt_build (task * tp, sockaddr_un * dest, sockaddr_un * mask, krt_parms * krtp, sockaddr_un ** routers, int ngw)
{
	int i, ishost;

	ishost = FALSE;

	assert(ngw <= RT_N_MULTIPATH);

	if (sockishost(dest, mask))
		ishost = TRUE;

	for (i = 0; i < ngw; i++) {
		bzero((caddr_t) &krt[i], sizeof(&krt[i]));
		krt[i].rt_dst = *sock2unix(dest, (int *) 0);		/* struct copy */
		krt[i].rt_flags = krt_state_to_flags(krtp->krtp_state);
	
#ifdef linux
		if (BIT_TEST(krt[i].rt_flags, RTF_GATEWAY))
			krt[i].rt_gateway = *sock2unix(routers[i],(int *) 0);  /*struct copy */
		krt[i].rt_genmask = *sock2unix(mask, (int *) 0);
#else
		krt[i].rt_gateway = *sock2unix(routers[i], (int *) 0);   /* struct copy */
#endif /* linux */

#ifdef HP_VARIABLE_MASKS
		krt[i].rt_subnetmask = mask->in.gin_addr.s_addr;
#endif  /* HP_VARIABLE_MASKS */
		if (ishost)
			BIT_SET(krt[i].rt_flags, RTF_HOST);
		if (krtp->krtp_n_gw && krtp->krtp_ifaps
			&& krtp->krtp_ifap && BIT_TEST(krtp->krtp_ifap->ifa_state, IFS_UP))
			BIT_SET(krt[i].rt_flags, RTF_UP);
#ifdef linux
		/*
		 * XXX
		 *
		 * krtp_ifaps is only supplied when deleting... 
		 * the below code may not be correct
		 */
		krt[i].rt_dev = krtp->krtp_ifaps[i] ?
		    krtp->krtp_ifaps[i]->ifa_link->ifl_name : NULL ;
#endif /* linux */
#ifdef	RTF_DYNAMIC
		if (krtp->krtp_protocol == RTPROTO_REDIRECT) {
			BIT_SET(krt[i].rt_flags, RTF_DYNAMIC);
		}
#endif	/* RTF_DYNAMIC */
	}
}


int
krt_change_start (task * tp)
{
    return KRT_OP_SUCCESS;
}


int
krt_change_end (task * tp)
{
    return KRT_OP_SUCCESS;
}


int
krt_change (task * tp, sockaddr_un * dest, sockaddr_un * mask, krt_parms * old_krtp, krt_parms * new_krtp)
{
    int i, pri = 0;
    int rc = KRT_OP_SUCCESS;
    sockaddr_un *new_router = (sockaddr_un *) 0;
    sockaddr_un *old_router = (sockaddr_un *) 0;
    sockaddr_un **new_routers = &new_router;
    sockaddr_un **old_routers = &old_router;

    if (new_krtp) {
	if (!new_krtp->krtp_n_gw) {
	    *new_routers = krt_make_router(socktype(dest), new_krtp->krtp_state);
	    assert(*new_routers);
	} else {
	    new_routers = new_krtp->krtp_routers;
	}
    }

    if (old_krtp) {
	if (!old_krtp->krtp_n_gw) {
	    *old_routers = krt_make_router(socktype(dest), old_krtp->krtp_state);
	    assert(*old_routers);
	} else {
	    old_routers = old_krtp->krtp_routers;
	}
    }
    
#if	RT_N_MULTIPATH > 1
    if (old_krtp && new_krtp && (!old_krtp->krtp_n_gw || old_krtp->krtp_ifap)
	&& old_krtp->krtp_state == new_krtp->krtp_state
	&& (BIT_TEST(new_krtp->krtp_state, RTS_REJECT|RTS_BLACKHOLE)
	    || (!krt_routers_changed(old_routers, old_krtp->krtp_n_gw, 
		    new_routers, new_krtp->krtp_n_gw)
		&& new_krtp->krtp_ifap == old_krtp->krtp_ifap))) {
#else
    if (old_krtp && new_krtp && (!old_krtp->krtp_n_gw || old_krtp->krtp_ifap)
	&& old_krtp->krtp_state == new_krtp->krtp_state
	&& (BIT_TEST(new_krtp->krtp_state, RTS_REJECT|RTS_BLACKHOLE)
	    || (sockaddrcmp(old_routers[0], new_routers[0])
		&& new_krtp->krtp_ifap == old_krtp->krtp_ifap))) {
#endif /* RT_N_MULTIPATH > 1 */
	/* If nothing has changed, there isn't anything to do */

	return rc;
    }

    if (old_krtp) {
	
	krt_build(tp, dest, mask, old_krtp, old_routers, old_krtp->krtp_n_gw);

	switch (krt_action(tp, RTM_DELETE, old_krtp->krtp_n_gw)) {
	case ENOBUFS:
	    /* Not enough resources to perform the action */
	    return KRT_OP_FULL;

	case ENETUNREACH:
	case EEXIST:
	default:
	    /* Should not happen */
	    pri = LOG_CRIT;
	    goto log_delete;

	case ESRCH:
	    /* Route not found. */
	    if (BIT_TEST(old_krtp->krtp_state, RTS_GATEWAY)) {
		/* Not really a problem, but lets complain */

		pri = LOG_CRIT;
		goto log_delete;
	    }

	    /* Probably an interface route deleted by ifconfig */
	    pri = LOG_NOTICE;
	    /* Fall through */

	case 0:
	    krt_n_routes -= old_krtp->krtp_n_gw;
	    
	    if (TRACE_TP(tp, TR_KRT_REQUEST)) {
	    log_delete:
		for (i = 0; i < old_krtp->krtp_n_gw; i++) {
		krt_trace(tp,
			  "SEND",
			  "DELETE",
			  dest,
			  mask,
				  old_routers[i],
				  (flag_t) krt[0].rt_flags,
			  pri ? (const char *) strerror(errno) : (char *) 0,
			  pri);
	    }
	    }
	    pri = 0;
	    break;
	}
    }
    
    if (new_krtp) {
	int retry = 5;

	if (krt_n_routes > krt_limit_routes) {
	    /* Too many routes */

	    return KRT_OP_FULL;
	}
	
	krt_build(tp, dest, mask, new_krtp, new_routers, new_krtp->krtp_n_gw);
	
    retry_add:
	if (!--retry) {
	    /* Give up */
	    return KRT_OP_NOCANDO;
	}

	switch (krt_action(tp, RTM_ADD, new_krtp->krtp_n_gw)) {
	case ENOBUFS:
	    /* No resources */
	    rc = KRT_OP_FULL;
	    break;

	case ENETUNREACH:
	    /* Probably an interface down. */
	    /* If we defer this the higher levels will remove this from the queue */
	    rc = KRT_OP_DEFER;
	    break;

	default:
	    pri = LOG_CRIT;
	    goto log_add;

	case EEXIST:
	    if (BIT_TEST(new_krtp->krtp_state, RTS_GATEWAY)) {
		/* Route already exists - delete and re-install */

		switch (krt_action(tp, RTM_DELETE, new_krtp->krtp_n_gw)) {
		case ENOBUFS:
		    /* Not enough resources to perform the action */
		    rc = KRT_OP_FULL;
		    break;

		default:
		case EEXIST:
		case ENETUNREACH:
		case ESRCH:
		    pri = LOG_CRIT;
		    goto log_add_delete;

		case 0:
		    if (TRACE_TP(tp, TR_KRT_REQUEST)) {
		    log_add_delete:
			for (i = 0; i < new_krtp->krtp_n_gw; i++) {
			krt_trace(tp,
				  "SEND",
				  "DELETE",
				  dest,
				  mask,
				  new_routers[i],
				  (flag_t) krt[0].rt_flags,
				  pri ? (const char *) strerror(errno) : (char *) 0,
				  pri);
		    }
		    }
		    pri = 0;
		    goto retry_add;
		}
		break;
	    }
	    /* An interface route - assume it is correct */
	    pri = LOG_NOTICE;
	    /* Fall through */

	case 0:
	    krt_n_routes += new_krtp->krtp_n_gw;
	    
	    if (TRACE_TP(tp, TR_KRT_REQUEST)) {
	    log_add:
		for (i = 0; i < new_krtp->krtp_n_gw; i++) {
		krt_trace(tp,
			  "SEND",
			  "ADD",
			  dest,
			  mask,
				  *new_routers,
				  (flag_t) krt[0].rt_flags,
			  pri ? (const char *) strerror(errno) : (char *) 0,
			  pri);
		}
		pri = 0;
	    }
	}

	if (rc != KRT_OP_SUCCESS && old_krtp) {
	    rc |= KRT_OP_PARTIAL;
	}
    }

    return rc;
}


void
krt_delete_dst (task * tp, sockaddr_un * dest, sockaddr_un * mask, proto_t proto, flag_t state, int n_gw, sockaddr_un ** routers, if_addr ** ifaps)
{
    krt_parms krtp;

    krtp.krtp_protocol = proto;
    krtp.krtp_state = state | RTS_GATEWAY;
    krtp.krtp_n_gw = n_gw;
    krtp.krtp_routers = routers;
    krtp.krtp_ifaps = ifaps;

    (void) krt_change(tp,
		      dest,
		      mask,
		      &krtp,
		      (krt_parms *) 0);
}
#endif /* KRT_RT_IOCTL */
