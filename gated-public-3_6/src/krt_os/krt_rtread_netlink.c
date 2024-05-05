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

int
krt_rtread_netlink(task *tp, struct nlmsghdr *nldata) 
{
	int ecmp_cnt;
	__u32 if_index;
	
	struct rtmsg *rtm;
	int rta_len; 
	
	struct rtattr *rta_data;
	rt_parms rtparms;
	if_addr *ifap;
	

	rtm = NLMSG_DATA(nldata);
	if (rtm->rtm_table != RT_TABLE_MAIN 
	    && rtm->rtm_table != RT_TABLE_DEFAULT
	    && rtm->rtm_protocol <= RTPROT_STATIC)
		return 0;

	bzero(&rtparms, sizeof(rtparms));
	rtparms.rtp_gwp = krt_gwp_remnant;
	rtparms.rtp_state = krt_flags_to_state(rtm->rtm_flags);
	rtparms.rtp_preference = RTPREF_KERNEL_REMNANT;
	RTP_RESET_ELIGIBLE(rtparms);
	RTP_SET_ELIGIBLE(rtparms, RIB_UNICAST);

	ecmp_cnt = 0;
	
	rta_len = RTM_PAYLOAD(nldata);
	for(rta_data = RTM_RTA(rtm); RTA_OK(rta_data, rta_len);
	    rta_data = RTA_NEXT(rta_data, rta_len)) {
		switch(rta_data->rta_type) {
			case RTA_DST:
				rtparms.rtp_dest =
			    	   sockbuild_in(0, *(__u32*)RTA_DATA(rta_data));
				rtparms.rtp_dest_mask = 
				   inet_masklen_locate(rtm->rtm_dst_len);
				break;
			case RTA_GATEWAY:
				rtparms.rtp_router = 
				   sockbuild_in(0, *(__u32*)RTA_DATA(rta_data));
				BIT_SET(rtparms.rtp_state, RTS_EXTERIOR);
				ecmp_cnt++;
				break;
			case RTA_PREFSRC:
				rtparms.rtp_router = 
				   sockbuild_in(0, *(__u32*)RTA_DATA(rta_data));
				BIT_SET(rtparms.rtp_state, RTS_INTERIOR);
				ecmp_cnt++;
				break;
			case RTA_OIF:
				if_index = *(__u32*)RTA_DATA(rta_data);
				break;
		}
	}

	if(rtparms.rtp_router == NULL && rtparms.rtp_dest == NULL &&
	    if_index == 0) return 0;

	if(rtparms.rtp_router == NULL && rtparms.rtp_dest != NULL) {
		BIT_SET(rtparms.rtp_state, RTS_INTERIOR);
		if(if_index) {
			ifap = if_withindex2(if_index, 
			    (byte)socktype(rtparms.rtp_dest));
		} else {
			ifap = if_withsubnet(rtparms.rtp_dest);
		}
		if(!ifap) return 0;
		rtparms.rtp_router = IFA_UNIQUE_ADDR(ifap);
		ecmp_cnt++;
	}

	if(rtparms.rtp_dest == NULL) {
		rtparms.rtp_dest = sockbuild_in(0, 0);
		rtparms.rtp_dest_mask = inet_mask_locate(0);
	}
	
	rtparms.rtp_n_gw = ecmp_cnt;
	krt_rtread_add(tp, &rtparms, 0, FALSE, "REMNANT");
}

int
krt_process_netlink(task *tp, int sockfd, __u16 nl_type)
{
	struct sockaddr_nl snl_addr, peer;

	char cbuf[64];
	char nlbuf[1024 * 8]; /* 8k bytes */
	
	struct iovec iov = { nlbuf, sizeof(nlbuf) };
	struct cmsghdr *cmsg;
	struct ucred *cmsg_data;
	struct nlmsghdr *nl_msg;
	struct nlmsgerr *nl_err;
	
	struct msghdr msg;
	int msglen;

	/* This is our netlink request structure */
	struct {
		struct nlmsghdr nlheader;
		struct rtgenmsg rtmsg;
	} nl_req;
	
	int true = 1;


	/* Enable the receiving of credentials on this socket 
	 * as need for netlink 
	 */
	setsockopt(sockfd, SOL_SOCKET, SO_PASSCRED, (void*)&true, sizeof(true));

	/* Initalize our request to netlink */
	bzero(&nl_req, sizeof(nl_req));
	nl_req.rtmsg.rtgen_family = AF_INET;
	nl_req.nlheader.nlmsg_type = nl_type;
	nl_req.nlheader.nlmsg_flags = NLM_F_ROOT|NLM_F_REQUEST;
	nl_req.nlheader.nlmsg_len = sizeof(nl_req);
	nl_req.nlheader.nlmsg_seq = 1;

	/* Init our netlink addr */
	bzero(&snl_addr, sizeof(snl_addr));
	snl_addr.nl_family = AF_NETLINK;

	if (sendto(sockfd, (void*)&nl_req, sizeof(nl_req), 0, 
	  (struct sockaddr*)&snl_addr, sizeof(snl_addr)) != sizeof(nl_req)) {
		task_quit(EINVAL);
	}

	/* Just loop and process what we get on the netlink socket */
	for(;;) {

		/* Init the msg struct */	
		msg.msg_name = (void *)&peer;
		msg.msg_namelen = sizeof(peer);
		iov.iov_base = (void *) nlbuf;
		iov.iov_len = sizeof(nlbuf);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = &cbuf;
		msg.msg_controllen = sizeof(cbuf);
		msg.msg_flags = 0;
			  
		if ((msglen = recvmsg(sockfd, &msg, 0)) <= 0) {
			task_quit(EINVAL);
		}

		/* Check to see if the buffers in msg get truncated */
		if(msg.msg_namelen != sizeof(peer) || 
		  (msg.msg_flags & (MSG_TRUNC|MSG_CTRUNC))) {
			task_quit(EINVAL);
		}

		/* Walk through cmsg to see if the data we need 
		 * is present
		 */
		cmsg_data = NULL;
		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
		  cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (cmsg->cmsg_level != SOL_SOCKET ||
			    cmsg->cmsg_type != SCM_CREDENTIALS ||
			    cmsg->cmsg_len < CMSG_LEN(sizeof(struct ucred))) {
				continue;
			}
			cmsg_data = (struct ucred*) CMSG_DATA(cmsg);
		}
		if (cmsg_data == NULL) {
			task_quit(EINVAL);
		}

		/* If we are here, we got route data.  Walk through nlbuf 	
	 	 * for the info we want 
		 */
		for ( nl_msg = (struct nlmsghdr *) nlbuf; 
		    NLMSG_OK(nl_msg, msglen);
		    nl_msg = NLMSG_NEXT(nl_msg, msglen)) {

			switch (nl_msg->nlmsg_type) {
				
				/* This is the clean way out */
				case NLMSG_DONE: 	
				 	return 0;
				 	break;

				case NLMSG_ERROR:	
					/* This is crude and needs thought */
					nl_err = (struct nlmsgerr *) 
					    NLMSG_DATA(nl_msg);
					/* Is there still data to process */
				 	if (nl_msg->nlmsg_len >= 
					  NLMSG_LENGTH(sizeof(struct nlmsgerr)))
						continue;
					task_quit(EINVAL);
				 	break;

				/* Route data */	
				case RTM_NEWROUTE: 
					krt_rtread_netlink(tp, nl_msg);
					break;

#ifdef KRT_IFREAD_NETLINK
				/* Physical Interface Data */
				case RTM_NEWLINK:
					krt_llread_netlink(tp, nl_msg);
					break;

				/* Logical Interface Data */
				case RTM_NEWADDR:
					krt_ifread_netlink(tp, nl_msg);
					break;
#endif /* KRT_IFREAD_NETLINK */
			}
		}
	}
}


int 
krt_rtread (task *tp)
{
	int sockfd;
	struct sockaddr_nl nl_addr, snl_addr, peer;

	int addrlen;

	trace_only_tp (tp, TRC_NL_BEFORE,
	  ("krt_read: Initial routes read from kernel (via NETLINK):"));

	if ((sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
		tracef("krt_rtread_netlink: socket error %s\n", 
		    (char *)strerror(errno));
		task_quit(0);
	}

	/* Init our sockaddr_nl struct */
	memset(&nl_addr, 0, sizeof(sizeof nl_addr));
	nl_addr.nl_family = AF_NETLINK;
	nl_addr.nl_groups = 0;
	nl_addr.nl_pid = 0;

	if (bind(sockfd, (struct sockaddr*)&nl_addr, sizeof(nl_addr)) < 0) {
		close(sockfd);
		tracef("krt_rtread_netlink: bind error %s\n", 
		    (char *)strerror(errno));
		task_quit(0);
	}

	addrlen = sizeof(nl_addr);
	if (getsockname(sockfd, (struct sockaddr*)&nl_addr, &addrlen) < 0) {
		close(sockfd);
		tracef("krt_rtread_netlink: getsockname error %s\n", 
		    (char *)strerror(errno));
		task_quit(0);
	}

	/* Check to see if we got an unexpected size or family on return	
	 * from getsockname 
	 */
	if (addrlen != sizeof(nl_addr) || nl_addr.nl_family != AF_NETLINK) {
		close(sockfd);
		tracef("krt_rtread_netlink: socket size/family error %s\n", 
		    (char *)strerror(errno));
		task_quit(0);
	}

	krt_process_netlink(tp, sockfd, RTM_GETROUTE);

	close(sockfd);
	return 0;
}
