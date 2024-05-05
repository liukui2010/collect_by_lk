/*
 *  Consortium Release 4
 *
 *  $Id: krt_ifread_combo.c,v 1.10 2000/03/17 07:55:06 naamato Exp $
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

/* 
 * This krt_ifread is for systems that can use ioctls
 * to obtain interface information, but do not use the
 * xxx:y aliasing scheme.  Currently this is only HP-UX 10.x,
 * and BSD/OS 2.x.
 * 
 * Instead of using ioctl(SIOCGIFCONF) to read the interface
 * list we look at the ifnet structures in kmem, and then
 * use ioctl to fill in the remaining info (netmask, etc).
 * IFS_ALIAS_PRIMARY is set on the first ifaddr.
 * 
 * Author:  Nick Amato <naamato@merit.edu>
 */

#define INCLUDE_IOCTL
#define INCLUDE_IF
#define INCLUDE_KVM
#include "include.h"

#ifdef KRT_IFREAD_COMBO

#ifdef  PROTO_INET
#include "inet/inet.h"
#endif  /* PROTO_INET */

#include "include.h"
#include "krt/krt.h"
#include "krt/krt_var.h"

#include <nlist.h>

/* 
 * MTUs from krt_ifread_ioctl.c
 */
#define LOOPBACK_MTU	1536
#define POINTOPOINT_MTU	256
#define ETHER_MTU	1500
#define DEFAULT_MTU	256

/*
 * undef ifa_addr because it's used in ifaps
 */
#undef ifa_addr

static struct nlist nlp[] = { {"ifnet"}, {""} };

int krt_ifread(flag_t);
int kernel_read(task *, int, off_t, void *, int);
void ifread_dump(task *, if_info *, short);


int
krt_ifread(flag_t save_task_state)
{
	
	char name[10], fname[IFNAMSIZ];
	int count, first, len, testing;
	static int sfd = -1;
	u_long addr, addr2;
	task *tp;
	struct _if_info ifi;
	struct ifnet ifn;
	struct ifaddr ifad;
	struct ifreq ifr;
	if_link *iflp, *clp;
	sockaddr_un *sap;
#ifdef PROTO_ISO
	struct sockaddr_iso *siso;
	byte *dp;
#endif

	tp = krt_task;
	count = testing = 0;

	if (!kd) {
		return EBADF;
	}

	if (nlist(_PATH_UNIX, nlp) < 0) {
		trace_log_tp(tp, 0, LOG_ERR,
		    ("krt_ifread: nlist failed for kernel %s", _PATH_UNIX));
		return errno;
	}

	if (BIT_TEST(task_state, TASKS_TEST)) {
		BIT_RESET(task_state, TASKS_TEST);
		testing = TRUE;
	}
	if (sfd < 0) {
		sfd = task_floating_socket(tp,
	  	    task_get_socket(tp, AF_INET, SOCK_DGRAM, 0),
		    "krt_ifread_task");
	}

	if (tp->task_socket < 0) {
		return EBADF;
	}

	if (testing)
		BIT_SET(task_state, TASKS_TEST);

	if (KVM_READ(kd, nlp[0].n_value, &addr,
	    sizeof(u_long)) != sizeof(u_long)) {
		trace_log_tp(tp, 0, LOG_ERR,
		    ("krt_ifread: reading ifnet global: %s",
		    KVM_GETERR(kd, "kvm_read_error")));
		return errno;
	}

	trace_tp(tp, TR_KRT_IFLIST, TRC_NL_BEFORE,
	    ("krt_ifread: address of first ifnet: %x", (int)addr));

	if_conf_open(tp, TRUE);

	/* read the ifnet */
	if (KVM_READ(kd, addr, &ifn,
	    sizeof(struct ifnet)) != sizeof(struct ifnet)) {
		trace_log_tp(tp, 0, LOG_ERR,
		    ("krt_ifread: reading first ifnet: %s",
		    KVM_GETERR(kd, "kvm_read_error")));
		return errno;
	}

	/* read the name */
	if (KVM_READ(kd, ifn.if_name, name, IFNAMSIZ) != IFNAMSIZ) {
		trace_log_tp(tp, 0, LOG_ERR,
		    ("krt_ifread: reading interface name: %s",
		    KVM_GETERR(kd, "kvm_read_error")));
		return errno;
	}

	for (;;) {
		/* handle the physical interface */
		count++;

		sprintf(fname, "%s%d", name, ifn.if_unit);
		len = strlen(fname);
		iflp = ifl_locate_name(fname, len);

		ifi.ifi_state = krt_if_flags(ifn.if_flags);
		ifi.ifi_mtu = ifn.if_mtu;
		ifi.ifi_metric = ifn.if_metric;
	
		/* make an ifreq */
		strcpy(ifr.ifr_name, fname);
		bzero(&ifr.ifr_addr, sizeof(struct sockaddr));

		/* add the physical intf */
		clp = ifl_addup(tp, iflp, count, ifi.ifi_state,
		    ifn.if_metric, ifn.if_mtu, fname, len,
		    krt_lladdr(&ifr), NULL);

		if (BIT_TEST(ifn.if_flags, IFS_LOOPBACK)) {
			BIT_SET(clp->ifl_state, IFS_LOOPBACK);
			clp->ifl_mtu = LOOPBACK_MTU;
		}

		addr2 = (u_long)ifn.if_addrlist;
		first = TRUE;

		/* Get the addresses, mark the first as primary */
		while(addr2) {

			/* handle the logical interfaces */
			if (KVM_READ(kd, (off_t)addr2, &ifad,
			    sizeof(struct ifaddr)) != sizeof(struct ifaddr)) {
				trace_log_tp(tp, 0, LOG_ERR,
				    ("krt_ifread: ifaddr: %s",
				    KVM_GETERR(kd, "kvm_read_error")));
				return errno;
			}

			switch (ifad.ifa_addr.sa_family) {
			default:
				/* skip this addr, unknown family */
				goto skip_addr;
#if PROTO_INET
			case AF_INET:
#endif /* PROTO_INET */
#if PROTO_ISO
			case AF_ISO:
#endif /* PROTO_ISO */
				ifi.ifi_addr_local = 
				    sockdup(sock2gated(&ifad.ifa_addr, 
				    unix_socksize(&ifad.ifa_addr,
				    ifad.ifa_addr.sa_family)));

				ifi.ifi_link = clp;
				ifi.ifi_addr_remote = 0;
				ifi.ifi_addr_broadcast = 0;
				ifi.ifi_netmask = 0;

				/* make a new ifreq */
				bzero(&ifr.ifr_addr, sizeof(struct sockaddr));
				bcopy(&ifad.ifa_addr,
				    &ifr.ifr_addr, sizeof(struct sockaddr));
				
				if (BIT_TEST(ifi.ifi_state, IFS_POINTOPOINT)) {
					ifi.ifi_mtu = POINTOPOINT_MTU;
					ifi.ifi_addr_remote =
					    sock2gated(&ifad.ifa_dstaddr, 
					    unix_socksize(&ifad.ifa_dstaddr,
					    ifad.ifa_addr.sa_family));
				}

				if (BIT_TEST(ifi.ifi_state, IFS_BROADCAST)) {
					ifi.ifi_addr_broadcast = sock2gated(
					    &ifad.ifa_broadaddr,
					    unix_socksize(&ifad.ifa_broadaddr,
					    ifad.ifa_addr.sa_family));
				}

				if (ifi.ifi_addr_broadcast) {
                                        ifi.ifi_addr_broadcast =
					    sockdup(ifi.ifi_addr_broadcast);
				}
#ifdef  SIOCGIFNETMASK
				bzero(&ifr.ifr_addr, sizeof(struct sockaddr));
				bcopy(&ifad.ifa_addr, &ifr.ifr_addr,
				    sizeof(struct sockaddr));

				if (task_ioctl(sfd, SIOCGIFNETMASK, &ifr,
				    sizeof(ifr)) < 0) {
					trace_log_tp(tp, 0, LOG_ERR, 
					    ("krt_ifread: %s:"
					    " ioctl SIOCGIFNETMASK: %m",
					    ifr.ifr_name));
				 } else {
					sap = sock2gated(&ifr.ifr_addr, 
					    unix_socksize(&ifr.ifr_addr,
					    ifad.ifa_addr.sa_family));
					if (sap)
						ifi.ifi_netmask =
						    mask_locate(sap);
					else 
						trace_log_tp(tp, 0, LOG_ERR,
						    ("krt_ifread: no network"
						    " mask for %A (%s)",
						    ifi.ifi_addr_local,
						    ifr.ifr_name));
				}
#endif
			}

			if (!ifi.ifi_addr_remote) {
				ifi.ifi_addr_remote =
				    sockdup(ifi.ifi_addr_local);

				/* XXX there may not be a netmask...
				 * but I doubt it could ever happen.
				 */ 
				sockmask(ifi.ifi_addr_remote, ifi.ifi_netmask);
			}

			if (first) {
				BIT_SET(ifi.ifi_state, IFS_ALIAS_PRIMARY);
				BIT_SET(ifi.ifi_state, IFS_NOAGE);
				first = FALSE;
			}
			/* trace if necessary */
			if (TRACE_TP(krt_task, TR_KRT_IFLIST)) {
				ifread_dump(tp, &ifi, ifad.ifa_addr.sa_family);
			}

			if_conf_addaddr(tp, &ifi);
skip_addr:
			BIT_RESET(ifi.ifi_state, IFS_ALIAS_PRIMARY);
			BIT_RESET(ifi.ifi_state, IFS_NOAGE);
			addr2 = (u_long)ifad.ifa_next;
		}
		if (!(addr = (u_long)ifn.if_next))
			break;

		if (KVM_READ(kd, (off_t)addr, &ifn,
		    sizeof(struct ifnet)) != sizeof(struct ifnet)) {
			trace_log_tp(tp, 0, LOG_ERR,
			    ("krt_ifread: reading first ifnet: %s",
			    KVM_GETERR(kd, "kvm_read_error")));
			return errno;
        	}

		if (KVM_READ(kd, ifn.if_name, name, IFNAMSIZ) != IFNAMSIZ) {
			trace_log_tp(tp, 0, LOG_ERR,
			    ("krt_ifread: reading interface name: %s",
			    KVM_GETERR(kd, "kvm_read_error")));
			return errno;
		}
	}
	if_conf_close(tp, FALSE);
	return(1);
}

void
ifread_dump(task *tp, if_info *ifi, short family)
{
	trace_tp(tp, TR_ALL, 0, ("krt_ifread:\tINTERFACE  name %.*s  family %d",
           IFNAMSIZ, ifi->ifi_link->ifl_name, family));
	trace_tp(tp, TR_ALL, 0,
	("krt_ifread:\tINTERFACE  address: %A  netmask %A",
	    BIT_TEST(ifi->ifi_state, IFS_POINTOPOINT) ?
	    ifi->ifi_addr_remote : ifi->ifi_addr_local, ifi->ifi_netmask));
}
#endif /* KRT_IFREAD_COMBO */
