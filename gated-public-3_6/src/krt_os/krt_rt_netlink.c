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
#define INCLUDE_LINUX_H
#include "include.h"

#ifdef KRT_RT_NETLINK

#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/rtnetlink.h>

#ifdef  PROTO_INET
#include "inet/inet.h"
#endif  /* PROTO_INET */
#ifdef 	PROTO_INET6
#include "inet6/inet6"
#endif 	/* PROTO_INET6 */
#ifdef  PROTO_ISO
#include "iso/iso.h"
#endif  /* PROTO_ISO */
#include "krt/krt.h"
#include "krt/krt_var.h"

flag_t krt_rt_support = KRTS_HOST | KRTS_MULTIPATH | KRTS_VAR_MASK;

/* Most routes use three attributes as found from testing, 
 * not including multi exits
 */
#define NL_MAX_ATTRIBS 5

#ifdef PROTO_INET6
#define NL_ATTRIB_SIZE ( sizeof(struct rtattr) + sizeof(struct sockaddr_in6))
#else
#define NL_ATTRIB_SIZE ( sizeof(struct rtattr) + sizeof(__u32))
#endif /* PROTO_INET6 */

#define NL_HEAD_SIZE ( sizeof(struct nlmsghdr) + sizeof(struct rtmsg) )
#define NL_BUF_SIZE ( NL_HEAD_SIZE + RT_N_MULTIPATH * NL_ATTRIB_SIZE + NL_MAX_ATTRIBS * NL_ATTRIB_SIZE )

void
krt_add_attrib_if(struct nlmsghdr *nlhdr, __u32 data)
{
	struct rtattr *rta = (struct rtattr *)((char *)nlhdr + 
	    NLMSG_ALIGN(nlhdr->nlmsg_len));

	assert((nlhdr->nlmsg_len + NL_ATTRIB_SIZE) <= NLMSG_ALIGN(NL_BUF_SIZE));

	rta->rta_len = RTA_LENGTH(sizeof(__u32));
	rta->rta_type = RTA_OIF;
	*(__u32*)RTA_DATA(rta) = data;
	nlhdr->nlmsg_len += NLMSG_ALIGN(rta->rta_len);
}

void
krt_add_attrib(struct nlmsghdr *nlhdr, int type, sockaddr_un* data)
{
	struct rtattr *rta = (struct rtattr *)((char *)nlhdr + 
	    NLMSG_ALIGN(nlhdr->nlmsg_len));

	assert((nlhdr->nlmsg_len + NL_ATTRIB_SIZE) <= NLMSG_ALIGN(NL_BUF_SIZE));

	switch (socktype(data)) {
		case AF_INET:
			rta->rta_len = RTA_LENGTH(sizeof(__u32));
			*(__u32*)RTA_DATA(rta) = sock2ip(data);
			break;
#ifdef PROTO_INET6
		case AF_INET6:
			rta->rta_len = RTA_LENGTH(sizeof(struct sockaddr_in6));
			memcpy(RTA_DATA(rta), &sock2ip(data), 
			    sizeof(struct sockaddr_in6));
#endif /* PROTO_INET6 */
		default:
			return;
	}
	rta->rta_type = type;
	nlhdr->nlmsg_len += NLMSG_ALIGN(rta->rta_len);
}

int
krt_request(task *tp, u_int type, sockaddr_un *dest, sockaddr_un *mask,
		krt_parms *krtp, sockaddr_un **routers)
{
	/* This should give us more then enough room */
	char nl_buf[NLMSG_ALIGN(NL_BUF_SIZE * 2)];

	struct nlmsghdr *nl_msg;
	struct rtmsg *rt_msg;
	__u32 maskval;
	int masklen = 0;
	if_info *ifi;

	struct sockaddr_nl nl_addr;
	struct iovec iov = { nl_buf, sizeof(nl_buf)};
	struct msghdr msg = {
		(void *)&nl_addr, sizeof(nl_addr),
		&iov, 1, NULL, 0, 0
	};

	bzero(nl_buf, sizeof(nl_buf));
	
	nl_msg = (struct nlmsghdr*) nl_buf;
	rt_msg = NLMSG_DATA(nl_msg);

	nl_msg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	nl_msg->nlmsg_type = type;
	nl_msg->nlmsg_flags = NLM_F_CREATE|NLM_F_REPLACE|NLM_F_REQUEST;
	rt_msg->rtm_family = socktype(dest);
	rt_msg->rtm_type = RTN_UNICAST;
	rt_msg->rtm_scope = RT_SCOPE_UNIVERSE;
	rt_msg->rtm_protocol = RTPROT_GATED;

	if(type == RTM_DELROUTE) {
		rt_msg->rtm_protocol = 0;
		rt_msg->rtm_scope = RT_SCOPE_NOWHERE;
	} else {
		if(!BIT_TEST(krtp->krtp_state, RTS_GATEWAY)) 
			rt_msg->rtm_scope = RT_SCOPE_LINK;
		if(BIT_TEST(krtp->krtp_state, RTS_REJECT))
			rt_msg->rtm_type = RTN_UNREACHABLE;
		if(BIT_TEST(krtp->krtp_state, RTS_BLACKHOLE))
			rt_msg->rtm_type = RTN_BLACKHOLE;

		if (krtp->krtp_protocol == RTPROTO_KERNEL)
			rt_msg->rtm_protocol = RTPROT_KERNEL;
		else if (BIT_TEST(krtp->krtp_state, RTS_STATIC))
			rt_msg->rtm_protocol = RTPROT_STATIC;
	}

	/* Calc masklen from netmask */
	for (maskval = sock2ip(mask) ; maskval ; maskval = maskval >> 1)  
		if(maskval & 0x01) masklen++;

	rt_msg->rtm_dst_len = masklen;

	/* Insert Dest into message */
	krt_add_attrib(nl_msg, RTA_DST, dest);

	/* Insert GW into message */
	if(rt_msg->rtm_type != RTN_BLACKHOLE && 
	    rt_msg->rtm_type != RTN_UNREACHABLE) {
		if(krtp->krtp_n_gw && krtp->krtp_ifaps && *krtp->krtp_ifaps
		    && !BIT_TEST(krtp->krtp_state, RTS_GATEWAY)) {
			krt_add_attrib_if(nl_msg, 
			    krtp->krtp_ifap->ifa_info.ifi_link->ifl_index);
			if (sockaddrcmp(krtp->krtp_ifap->ifa_addr_local, 
			    *routers)
			    || sockaddrcmp(krtp->krtp_ifap->ifa_addr_remote, 
			    dest)
			    || !(krtp->krtp_ifap->ifa_state & IFS_LOOPBACK)) {
				rt_msg->rtm_scope = RT_SCOPE_LINK;
			} else {
				rt_msg->rtm_scope = RT_SCOPE_HOST;
			} 
		}
		else if (rt_msg->rtm_scope <= RT_SCOPE_LINK &&
		    *routers) {
			krt_add_attrib(nl_msg, RTA_GATEWAY, *routers);
		}
		else if (rt_msg->rtm_scope == RT_SCOPE_HOST && 
		    type != RTM_DELROUTE && *routers) {
			krt_add_attrib(nl_msg, RTA_PREFSRC, *routers);
		} else {
			/* we were expecting a gateway or interface, but
			 * none were to be found, so log it!
			 */
			trace_log_tp(tp, 0, LOG_ERR,
		     	    ("Could not find a valid egress for route"));

		}
	}

	if(masklen == 0) rt_msg->rtm_table = RT_TABLE_DEFAULT;
	else rt_msg->rtm_table = RT_TABLE_MAIN;

	if (BIT_TEST(task_state, TASKS_TEST) || 
	    BIT_TEST(krt_options, KRT_OPT_NOINSTALL)) {
		return KRT_OP_SUCCESS;
	}

	nl_addr.nl_family = AF_NETLINK;
	nl_addr.nl_pid = 0;
	nl_addr.nl_groups = 0;

	if (sendmsg(tp->task_socket, &msg, MSG_DONTWAIT) < 0) {
		return errno;
	} else {
		return KRT_OP_SUCCESS;
	}
}

int
krt_change_start (task *tp)
{
    return KRT_OP_SUCCESS;
}


int
krt_change_end (task *tp)
{
    return KRT_OP_SUCCESS;
}


int
krt_change (task *tp, sockaddr_un *dest, sockaddr_un *mask, 
	    krt_parms *old_krtp, krt_parms *new_krtp)
{
	int i, pri = 0;
	int rc = KRT_OP_SUCCESS;

	/* These are just dummy vals */
	sockaddr_un *new_router = (sockaddr_un *) 0;
	sockaddr_un *old_router = (sockaddr_un *) 0;

	sockaddr_un **new_routers = &new_router;
	sockaddr_un **old_routers = &old_router;

	if (new_krtp) {
		if (!new_krtp->krtp_n_gw) {
			*new_routers = 
			  krt_make_router(socktype(dest), new_krtp->krtp_state);
			assert(*new_routers);
		} else {
			new_routers = new_krtp->krtp_routers;
		}
	}

	if (old_krtp) {
		if (!old_krtp->krtp_n_gw) {
			*old_routers = 
			  krt_make_router(socktype(dest), old_krtp->krtp_state);
			assert(*old_routers);
		} else {
			old_routers = old_krtp->krtp_routers;
		}
	}
    
	#if	RT_N_MULTIPATH > 1
	if (old_krtp && new_krtp && (!old_krtp->krtp_n_gw 
	    || old_krtp->krtp_ifap)
	    && old_krtp->krtp_state == new_krtp->krtp_state
	    && (BIT_TEST(new_krtp->krtp_state, RTS_REJECT|RTS_BLACKHOLE)
	    || (!krt_routers_changed(old_routers, old_krtp->krtp_n_gw, 
	    new_routers, new_krtp->krtp_n_gw)
	    && new_krtp->krtp_ifap == old_krtp->krtp_ifap))) {
	#else
	if (old_krtp && new_krtp && (!old_krtp->krtp_n_gw 
	    || old_krtp->krtp_ifap)
	    && old_krtp->krtp_state == new_krtp->krtp_state
	    && (BIT_TEST(new_krtp->krtp_state, RTS_REJECT|RTS_BLACKHOLE)
	    || (sockaddrcmp(old_routers[0], new_routers[0])
	    && new_krtp->krtp_ifap == old_krtp->krtp_ifap))) {
	#endif /* RT_N_MULTIPATH > 1 */
	/* If nothing has changed, there isn't anything to do */
		return rc;
	}

	if (old_krtp) {
	
		switch (krt_request(tp, RTM_DELROUTE, 
			dest, mask, old_krtp, old_routers)) {
			case ENOBUFS:
			/* Not enough resources to perform the action */
				return KRT_OP_FULL;
				break;

			default:
				for (i = 0; i < old_krtp->krtp_n_gw; i++) {
					krt_trace(tp, "SEND", "CHANGE", dest, 
					mask, old_routers[i], 
					(flag_t) krt_state_to_flags(
					old_krtp->krtp_state), 
					(char *)strerror(errno), LOG_CRIT);
				}
				break;

			case 0:
				for (i = 0; i < old_krtp->krtp_n_gw; i++) {	
					krt_trace(tp, "SEND", "CHANGE", dest, 
					mask, old_routers[i], 
					(flag_t) krt_state_to_flags(
					old_krtp->krtp_state), NULL, 0);
				}
				break;
		}
	}
    
	if (new_krtp) {
		int retry = 5;

		if (krt_n_routes > krt_limit_routes) {
		/* Too many routes */
			return KRT_OP_FULL;
		}
	
		retry_add:
		if (!--retry) {
			/* Give up */
			return KRT_OP_NOCANDO;
		}

		switch (krt_request(tp, RTM_NEWROUTE, dest, mask, 
		    new_krtp, new_routers)) {
			case ENOBUFS:
			/* No resources */
				rc = KRT_OP_FULL;
				break;

			case ENETUNREACH:
			/* Probably an interface down.
			* If we defer this the higher levels will remove 
			*  this from the queue 
			*/
				rc = KRT_OP_DEFER;
				break;

			default:
				for(i = 0; i < new_krtp->krtp_n_gw; i++) {
					krt_trace(tp, "SEND", "CHANGE", dest, 
					mask, new_routers[i], 
					(flag_t) krt_state_to_flags
				    	(new_krtp->krtp_state), 
				    	(char *)strerror(errno),
				    	LOG_CRIT);
				}
				break;

			case 0:
				for(i = 0; i < new_krtp->krtp_n_gw; i++) {
					krt_trace(tp, "SEND", "CHANGE", dest, 
					mask, new_routers[i], 
					(flag_t) krt_state_to_flags
				    	(new_krtp->krtp_state), NULL, 0);
				}
				break;
		}

		if (rc != KRT_OP_SUCCESS && old_krtp) {
			rc |= KRT_OP_PARTIAL;
		}
	}

	return rc;
}


void
krt_delete_dst (task *tp, sockaddr_un *dest, sockaddr_un *mask,
		     proto_t proto, flag_t state, int n_gw,
		     sockaddr_un **routers, if_addr **ifaps)
{
	krt_parms krtp;

	krtp.krtp_protocol = proto;
	krtp.krtp_state = state | RTS_GATEWAY;
	krtp.krtp_n_gw = n_gw;
	krtp.krtp_routers = routers;
	krtp.krtp_ifaps = ifaps;

	(void) krt_change(tp, dest, mask, &krtp, (krt_parms *) 0);
}
#endif /* KRT_RT_NETLINK */
