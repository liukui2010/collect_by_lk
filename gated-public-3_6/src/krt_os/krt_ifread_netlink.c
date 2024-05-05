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

#ifdef  PROTO_INET
#include "inet/inet.h"
#endif  /* PROTO_INET */
#include "krt/krt.h"
#include "krt/krt_var.h"
#include <linux/if_arp.h>

/* This routine is found in krt_rtread_netlink.c 
 */
int krt_process_netlink(task *tp, int sockfd, __u16 nl_type);
int maincnt = 0;

void krt_ifread_netlink(task *tp, struct nlmsghdr *nldata)
{
	struct rtattr *rta;
	int rta_len;
	struct _if_info ifi;

	struct ifaddrmsg *ifamsg = NLMSG_DATA(nldata);
	if_link *ifl = ifl_locate_index(ifamsg->ifa_index);

	if(!ifl) {
		trace_log_tp(tp, TRC_NL_BEFORE|TRC_NL_AFTER, LOG_ERR,
		    ("krt_ifread_nelink: Interface not in list %d\n",
		     ifamsg->ifa_index));
		return;
	}

	bzero(&ifi, sizeof(ifi));

	ifi.ifi_state = ifl->ifl_state;
	ifi.ifi_metric = ifl->ifl_metric;
	ifi.ifi_mtu = ifl->ifl_mtu;
	ifi.ifi_link = ifl;
	ifi.ifi_netmask = 
 	    inet_masklen_locate(ifamsg->ifa_prefixlen);

	for(rta = IFLA_RTA(ifamsg), rta_len = IFLA_PAYLOAD(nldata);
	    RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
		switch(rta->rta_type) {
			case IFA_LOCAL:
				ifi.ifi_addr_local = 
				    sockdup(
				      sockbuild_in(0, *(__u32*)RTA_DATA(rta)));
				break;
			case IFA_BROADCAST:
				ifi.ifi_addr_broadcast = 
				    sockdup(
				      sockbuild_in(0, *(__u32*)RTA_DATA(rta)));
				ifi.ifi_state |= IFS_BROADCAST;
				break;
			case IFA_ADDRESS:
				ifi.ifi_addr_remote = 
				    sockdup(
				       sockbuild_in(0, *(__u32*)RTA_DATA(rta)));
				ifi.ifi_state |= IFS_POINTOPOINT;
				break;
		}
	}
	if(!ifi.ifi_addr_local){
		return;
	}
	if(!ifi.ifi_addr_broadcast){
		ifi.ifi_addr_broadcast = sockdup(sockbuild_in(0,0));
	}
 	if(!ifi.ifi_addr_remote) {
		ifi.ifi_addr_remote = sockdup(ifi.ifi_addr_local);
		sockmask(ifi.ifi_addr_remote, ifi.ifi_netmask);
	}
	if_conf_addaddr(tp, &ifi);
}
	
void krt_llread_netlink(task *tp, struct nlmsghdr *nldata) 
{
	struct ifinfomsg *ifimsg = NLMSG_DATA(nldata);
	struct rtattr *rta;
	int rta_len;
	mtu_t if_mtu = 0;
	static char dummy[4] = "nil";
	char *if_name = dummy;
	char *lladdr = dummy;
	int lla_len = 3;
	int if_type;

	for(rta = IFLA_RTA(ifimsg), rta_len = IFLA_PAYLOAD(nldata);
	    RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
		switch(rta->rta_type) {
			case IFLA_MTU:
				if_mtu = *(mtu_t *)RTA_DATA(rta);
				break;
			case IFLA_IFNAME:
				if_name = RTA_DATA(rta);
				break;
			case IFLA_ADDRESS:
				lladdr = RTA_DATA(rta); 
				lla_len = RTA_PAYLOAD(rta); 
				break;
		}
	}

	switch(ifimsg->ifi_type) {
		case ARPHRD_ETHER:
		case ARPHRD_EETHER:
		case ARPHRD_IEEE802:
			if_type = LL_8022;
			break;
		case ARPHRD_X25:
			if_type = LL_X25;
			break;
		case ARPHRD_PRONET:
			if_type = LL_PRONET;
			break;
		default:
			if_type = LL_OTHER;
			break;
	}
			
	ifl_addup(tp, ifl_locate_index(ifimsg->ifi_index),
	    ifimsg->ifi_index, krt_if_flags(ifimsg->ifi_flags),
	    0, if_mtu, if_name, strlen(if_name),
	    sockbuild_ll(if_type, lladdr, lla_len), (sockaddr_un *)0);
}

int 
krt_ifread (flag_t save_task_state)
{
	static int sockfd = -1;
	static struct sockaddr_nl nl_addr;
	int addr_len;
	
	task *tp = krt_task;

	if (sockfd < 0) {
		if ((sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) 
		    < 0) {
			tracef("krt_ifread_netlink: socket error %s\n", 
			    (char *)strerror(errno));
			task_quit(0);
		}
		task_floating_socket (tp, sockfd, "krt_ifread");

/*		sockfd = task_floating_socket (tp, 
		    task_get_socket(tp, AF_NETLINK, SOCK_RAW, NETLINK_ROUTE),
		    "krt_ifread_netlink");
*/
		/* Init our sockaddr_nl struct */
		memset(&nl_addr, 0, sizeof(struct sockaddr_nl));
		nl_addr.nl_family = AF_NETLINK;
		nl_addr.nl_groups = 0;
		nl_addr.nl_pid = 0;

		if (bind(sockfd, (struct sockaddr*)&nl_addr, 
		    sizeof(struct sockaddr_nl)) 
		    < 0) {
			tracef("krt_ifread_netlink: error in  bind %s\n", 
			    (char *)strerror(errno));
			task_quit(0);
		}

		addr_len = sizeof(struct sockaddr_nl);
		if (getsockname(sockfd, (struct sockaddr*)&nl_addr, &addr_len) 
	  	     < 0) {
			tracef("krt_ifread_netlink: getsockname %s\n", 
			    (char *)strerror(errno));
			task_quit(0);
		}

		/* Check to see if we got an unexpected size or family on 
		 * return from getsockname 
	 	*/
		if (addr_len != sizeof(struct sockaddr_nl) || 
		    nl_addr.nl_family != AF_NETLINK) {
			tracef("krt_ifread_netlink: error in size/family %s\n", 
			    (char *)strerror(errno));
			task_quit(0);
		}
	}

	if_conf_open(tp, TRUE);
	krt_process_netlink(tp, sockfd, RTM_GETLINK);
	krt_process_netlink(tp, sockfd, RTM_GETADDR);
	if_conf_close(tp, FALSE);

	return (1);
}
