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


#define	INCLUDE_UDP
#include "include.h"

#include "inet/inet.h"
#include "targets.h"
#define	RIPCMDS
#include "rip.h"
#include "krt/krt.h"

/* UPDATE types for rip_supply() */
#define RIP_OTHER_UPDATE 0
#define RIP_FLASH_UPDATE 1
#define RIP_FULL_UPDATE  2

/* Prototypes */
static void rip_target_list(task_job *);
static void rip_target_list_build(task *);
rip_auth * rip_get_best_md5_key(rip_auth *);
rip_auth * rip_find_md5_key(u_int8, rip_auth *);
void rip_add2accepted_keys(task *, gw_entry *, rip_auth *);
void rip_remove_from_accepted_keys(task *, gw_entry *);
void rip_free_accepted_keys(task *);
rip_auth * rip_build_keys(task *, rip_auth *, rip_auth *);
int rip_auth_check (task *, struct rip *, struct rip_netinfo **, 
  void_t *, gw_entry *, rip_auth *, rip_auth *);
void rip_send_auth (task *, if_addr *, flag_t , sockaddr_un *, 
  struct rip *, size_t , rip_auth *, struct rip_authinfo *);

static u_short rip_port;
flag_t rip_flags = 0;		  /* Options */
trace *rip_trace_options = { 0 }; /* Trace flags */
metric_t rip_default_metric = 0;  /* Default metric to use when propogating */
pref_t rip_preference = 0;        /* Preference for RIP routes */
u_int  rip_max_routes = 0;        /* Number of rip rts to maintain per prefix */

static task_timer *rip_timer_update;		/* To send updates */
static task_timer *rip_timer_flash;		/* To send flash updates */
static task_timer *rip_timer_age;		/* To age routes */

static task_job *rip_target_list_job;		/* To rebuild target list after interface changes */
static target rip_targets = { &rip_targets, &rip_targets };		/* Target list */

static int rip_unicast_ttl = -1;

#ifdef	IP_MULTICAST
static if_addr *rip_multicast_ifap = (if_addr *) 0;
static sockaddr_un *rip_addr_mc;	/* Multicast address */
static int rip_mc_count;
#endif	/* IP_MULTICAST */

int rip_n_trusted = 0;			/* Number of trusted gateways */
int rip_n_source = 0;			/* Number of source gateways */
gw_entry *rip_gw_list = 0;		/* List of RIP gateways */
adv_entry *rip_import_list = 0;		/* List of nets to import from RIP */
adv_entry *rip_export_list = 0;		/* List of sources to exports routes to RIP */
adv_entry *rip_int_policy = 0;		/* List of interface policy */

#if	defined(PROTO_SNMP) && defined(MIB_RIP)
u_int rip_global_changes;
u_int rip_global_responses;
#endif	/* defined(PROTO_SNMP) && defined(MIB_RIP) */

static const bits rip_flag_bits[] = {
    { RIPF_ON,		"ON" },
    { RIPF_BROADCAST,	"Broadcast" },
    { RIPF_SOURCE,	"Source" },
    { RIPF_CHOOSE,	"Choose" },
    { RIPF_NOCHECK,	"NoCheck" },
    { RIPF_FLASHDUE,	"FlashDue" },
    { RIPF_NOFLASH,	"NoFlash" },
    { RIPF_RECONFIG,	"ReConfig" },
    { RIPF_TERMINATE,	"Terminate" },
    { 0 }
} ;

static const bits rip_target_bits[] = {
    { RIPTF_POLL,	"Poll" },
    { RIPTF_V2MC,	"V2Multicast" },
    { RIPTF_V2BC,	"V2Broadcast" },
    { RIPTF_MCSET,	"MCEnabled" },
    { 0 }
} ;

static const bits rip_if_bits[] = {
    { RIP_IFPS_V2MC,	"V2Multicast" },
    { RIP_IFPS_V2BC,	"V2Broadcast" },
    { 0 }
} ;

static const flag_t rip_trace_masks[RIPCMD_MAX] = {
    TR_ALL,			/* 0 - Invalid */
    TR_RIP_DETAIL_REQUEST,	/* 1 - REQUEST */
    TR_RIP_DETAIL_RESPONSE,	/* 2 - RESPONSE */
    TR_RIP_DETAIL_OTHER,	/* 3 - TRACEON */
    TR_RIP_DETAIL_OTHER,	/* 4 - TRACEOFF */
    TR_RIP_DETAIL_REQUEST,	/* 5 - POLL */
    TR_RIP_DETAIL_OTHER,	/* 6 - POLLENTRY */
} ;

const bits rip_trace_types[] = {
    { TR_DETAIL,		"detail packets" },
    { TR_DETAIL_SEND,	"detail send packets" },
    { TR_DETAIL_RECV,	"detail recv packets" },
    { TR_PACKET,		"packets" },
    { TR_PACKET_SEND,	"send packets" },
    { TR_PACKET_RECV,	"recv packets" },
    { TR_DETAIL_1,	"detail request" },
    { TR_DETAIL_SEND_1,	"detail send request" },
    { TR_DETAIL_RECV_1,	"detail recv request" },
    { TR_PACKET_1,	"request" },
    { TR_PACKET_SEND_1,	"send request" },
    { TR_PACKET_RECV_1,	"recv request" },
    { TR_DETAIL_2,	"detail response" },
    { TR_DETAIL_SEND_2,	"detail send response" },
    { TR_DETAIL_RECV_2,	"detail recv response" },
    { TR_PACKET_2,	"response" },
    { TR_PACKET_SEND_2,	"send response" },
    { TR_PACKET_RECV_2,	"recv response" },
    { TR_DETAIL_3,	"detail other" },
    { TR_DETAIL_SEND_3,	"detail send other" },
    { TR_DETAIL_RECV_3,	"detail recv other" },
    { TR_PACKET_3,	"other" },
    { TR_PACKET_SEND_3,	"send other" },
    { TR_PACKET_RECV_3,	"recv other" },
    { 0, NULL }
};

/* Authentication stuff */

block_t rip_auth_block_index;
rip_auth *rip_auth_query;   /* Authorization expected for user queries */
static rip_gw_auth *rip_accepted_list = NULL;

/*
 *	Trace RIP packets
 */
static void
rip_trace (trace *trp, int dir, if_addr *ifap, sockaddr_un *who, 
    register struct rip *rpmsg, register size_t size, int detail)
{
	int limit;
	int check_zero;
	register struct rip_netinfo *n = 
	  (struct rip_netinfo *) ((void_t) (rpmsg + 1));
	register const char *cmd = 
	  trace_state(rip_cmd_bits, rpmsg->rip_cmd < RIPCMD_MAX ? 
	  rpmsg->rip_cmd : 0);

	switch (rpmsg->rip_vers) {
		case RIP_VERSION_0:
			limit = 4;
			check_zero = FALSE;
			break;

		case RIP_VERSION_1:
			limit = 4;
			check_zero = 
			  BIT_TEST(rip_flags, RIPF_NOCHECK) ? FALSE : TRUE;
			break;

		default:
			limit = 1;
			check_zero = FALSE;
	}

	if (dir) {
		/* Trace packet transmission */
		tracef("RIP %sSENT %A -> %#A ", dir > 0 ? "" : "*NOT* ",
		  ifap ? ifap->ifa_addr_local : sockbuild_str("Response"), who);
	} else {
		/* Trace packet reception */
		tracef("RIP RECV %#A ", who);
		if (task_recv_dstaddr) {
			/* Some systems report the destination address */
			tracef("-> %A ", task_recv_dstaddr);
		}
	}
	tracef("vers %d, cmd %s, length %d", rpmsg->rip_vers, cmd, size);
	if (check_zero && rpmsg->rip_zero2) {
		tracef(" reserved fields not zero");
	}
	switch (rpmsg->rip_cmd) {
		case RIPCMD_POLL:
		case RIPCMD_REQUEST:
		case RIPCMD_RESPONSE:
			trace_only_tf(trp, 0, (NULL));
			if (detail) {
				int n_routes = 0;

				for (size -= (sizeof (struct rip));
				  size >= sizeof(struct rip_netinfo);
				  n++, size -= sizeof(struct rip_netinfo)) {
					char zero = ' ';
					int family = ntohs(n->rip_family);
					metric_t metric = ntohl(n->rip_metric);

					/* Verify that all reserved fields are 
					 * zero 
					 */
					if (check_zero && (n->rip_tag || n->rip_dest_mask
					  || n->rip_router)) {
						zero = '?';
					}

					switch (family) {
						case RIP_AF_INET:
							if (rpmsg->rip_vers < RIP_VERSION_2) {
								tracef("\t%15A%c%2d", 
								  sockbuild_in(0, n->rip_dest), zero, metric);
							} else {
								tracef("\t%15A/%-15A router %-15A metric %2d tag %#04X",
								  sockbuild_in(0, n->rip_dest), 
								  sockbuild_in(0, n->rip_dest_mask),
								  sockbuild_in(0, n->rip_router), metric,
								  ntohs(n->rip_tag));
		    				}
							break;

						case RIP_AF_UNSPEC:
							if (metric == RIP_METRIC_UNREACHABLE) {
								tracef("\trouting table request%c", zero);
								break;
							}
							goto bogus;

						case RIP_AF_AUTH:
							if (rpmsg->rip_vers > RIP_VERSION_1 && n == 
							     (struct rip_netinfo *)((void_t) (rpmsg + 1))) {
									struct rip_authinfo *ap = 
									  (struct rip_authinfo *) n;
								int auth_type = ntohs(ap->auth_type);

								switch (auth_type) {
									case RIP_AUTH_NONE:
										tracef("\tAuthentication: None");
										break;	

									case RIP_AUTH_SIMPLE:
										tracef("\tAuthentication: %.*s",
										  RIP_AUTH_NUM_BYTE,
										  (char *) ap->auth_data);
											break;

#ifdef	MD5_CHECKSUM
									case RIP_AUTH_MD5:
									{
										struct rip_trailer *rtp;
										struct rip_md5info *md5 = 
										  (struct rip_md5info*) ap;
				
										if (size % sizeof (struct rip_netinfo) 
										  >= sizeof (*rtp)) {
											rtp = (struct rip_trailer *) 
											  (n + size / sizeof 
											  (struct rip_netinfo));
											size -= sizeof (struct rip_trailer);
											tracef("\tAuthentication: MD5 Digest: %08x.%08x.%08x.%08x Sequence: ",
											rtp->auth_data[0], 
											rtp->auth_data[1],
											rtp->auth_data[2], 
											rtp->auth_data[3]);
											tracef("%08x (%T)",
											  ntohl(md5->md5_sequence),
											  ntohl(md5->md5_sequence) - 
											  time_boot);
										} else {
											tracef("\tAuthentication: MD5 Digest: ???");
										}
									}
									break;
#endif	/* MD5_CHECKSUM	*/
			    
									default:
										tracef("\tInvalid auth type: %d",
										  auth_type);
								}
								break;
							}
							/* Fall through */
	
						default:
bogus:
							tracef("\tInvalid family: %d", family);
					}
					if (++n_routes == limit) {
						n_routes = 0;
						trace_only_tf(trp, TRC_NOSTAMP, (NULL));
					}
				}
				if (n_routes) {
					trace_only_tf(trp, TRC_NOSTAMP, (NULL));
				}
				tracef("RIP %s end of packet", dir ? "SENT" : "RECV");
				if (size) {
					tracef(" %d residual bytes", size);
				}
				trace_only_tf(trp, TRC_NOSTAMP, (NULL));
			}
			break;

		case RIPCMD_TRACEON:
		case RIPCMD_TRACEOFF:
			trace_only_tf(trp, 0, (", file %*s", size, (char *) (rpmsg + 1)));
			break;

		case RIPCMD_POLLENTRY:
			trace_only_tf(trp, 0, (", net %A", sockbuild_in(0, n->rip_dest)));
			break;

		default:
			trace_only_tf(trp, 0, (NULL));
			break;
	}
	trace_only_tf(trp, 0, (NULL));
}

#ifdef	IP_MULTICAST
/* Remove ourselves from the MC group on this interface if necessary */
static void
rip_mc_reset (task *tp, target *tlp)
{
	int *count = (int *) &tlp->target_ifap->ifa_rip_mccount;

	if (BIT_TEST(tlp->target_flags, RIPTF_MCSET) && !--(*count)) {
		(void) task_set_option(tp, TASKOPTION_GROUP_DROP,
		    tlp->target_ifap, rip_addr_mc);
		BIT_RESET(tlp->target_flags, RIPTF_MCSET);
		if (!--rip_mc_count) {
			krt_multicast_delete(rip_addr_mc);
		}
	}
}

/* Add ourselves to the MC group on this interface */
static int
rip_mc_set (task *tp, target *tlp)
{
	flag_t ifps_state = 
	    tlp->target_ifap->ifa_ps[tp->task_rtproto].ips_state;
	int *count = (int *) &tlp->target_ifap->ifa_rip_mccount;
	int rc = FALSE;

	if (BIT_TEST(tlp->target_flags, RIPTF_MCSET)) {
		/* Indicate MC is already set */

		rc = TRUE;
	} else if (!BIT_TEST(ifps_state, RIP_IFPS_NOMC) && !(*count)++) {
		/* Try to join the MC group on this interface */

		if (!BIT_TEST(tlp->target_ifap->ifa_state, IFS_MULTICAST)
		    || ((task_set_option(tp, TASKOPTION_GROUP_ADD, 
		    tlp->target_ifap, rip_addr_mc) < 0) 
		    && (errno != EADDRNOTAVAIL) && (errno != EADDRINUSE))) {
			/* Indicate that this interface is not capable of MC */

			BIT_SET(ifps_state, RIP_IFPS_NOMC);

			if (BIT_TEST(ifps_state, RIP_IFPS_V2MC)) {
				/* If V2 was explicitly enabled, complain */

				trace_log_tp(tp, 0, LOG_WARNING,
				    ("rip_mc_set: Multicast not available on %A (%s); reverting to RIP V1 compatability",
				    IFA_UNIQUE_ADDR(tlp->target_ifap),
				    tlp->target_ifap->ifa_link->ifl_name));
			}
		} else {
			/* Indicate that we successfully enabled the MC 
			 * address 
			 */

			BIT_SET(tlp->target_flags, RIPTF_MCSET);
			tlp->target_reset = rip_mc_reset;
			if (!rip_mc_count++) {
				krt_multicast_add(rip_addr_mc);
			}
			rc = TRUE;
		}
	}
	return rc;
}
#endif	/* IP_MULTICAST */

/* This routine finds the best key we have for sending.
 *
 * note:  all else equal, we choose based on the order 
 * they are inputed.  We may need to do this on key-id
 * instead to be more compatable with other vendors, or
 * perhaps perfer non-timed keys above timed ones (or 
 * visa-versa)
 */
rip_auth *
rip_get_best_md5_key(rip_auth *auth)
{
	rip_auth *rap, *b_rap = NULL;
	double diff, best;
	time_t curtime;

	curtime = (time_t)(time_sec + time_boot);

	for(rap = auth; rap; rap = rap->auth_acc_next) {
		if(DIFFTIME(curtime, rap->auth_generate.tr_start) >= 0)
			break;
	}

	b_rap = rap;

	if(rap && rap->auth_generate.tr_stop != (time_t)-1 ) {
		diff = best = DIFFTIME(rap->auth_generate.tr_stop, curtime);
		for(; diff < 0;) {
			if(diff > best) {
				b_rap = rap;
				best = diff;
			}
			if(!(rap = rap->auth_acc_next))
				break;
			else if (rap->auth_generate.tr_stop == (time_t)-1) {
				b_rap = rap;
				break;
			} else
				diff = DIFFTIME(rap->auth_generate.tr_stop, curtime);
		}
	}

	return(b_rap);
}

/* find the key with the matching key id for sending */
rip_auth *
rip_find_md5_key(u_int8 keyid, rip_auth *auth) {
	rip_auth *rap, *b_rap = NULL;
	time_t curtime;
	
	curtime = (time_t)(time_sec + time_boot);

	for (rap = auth; rap; rap = rap->auth_acc_next) {
		if(keyid == rap->auth_id) {
			b_rap = rap;
			break;
		}
	}

	/** Check to see if key has expired, continue to use but log warning*/
	if(b_rap && b_rap->auth_generate.tr_stop != (time_t) -1  &&
		DIFFTIME(b_rap->auth_generate.tr_stop, curtime) < 0) {
		tracef("rip_find_md5_key: Requested key has expired! Key ID %d",
		  b_rap->auth_id);
	}
	
	return (b_rap);
}

/* make sure our gateway/auth pair is complete and up to date */
void
rip_add2accepted_keys(task *tp, gw_entry *gw, rip_auth *auth) 
{
	rip_gw_auth *rgap, *e_rgap = NULL;

	if(!rip_accepted_list) {
		rip_accepted_list = task_mem_malloc(tp, sizeof(rip_gw_auth));
		rip_accepted_list->auth = auth;
		rip_accepted_list->gw = gw;
		rip_accepted_list->gw_auth_next = NULL;
	} else {
		for(rgap = rip_accepted_list; rgap; rgap = rgap->gw_auth_next) {
			if(rgap->gw == gw) {
				rgap->auth = auth;
				return;
			}
			e_rgap = rgap;
		}
		if(e_rgap) {
			rgap = task_mem_malloc(tp, sizeof(rip_gw_auth));
			rgap->auth = auth;
			rgap->gw = gw;
			rgap->gw_auth_next = NULL;
			e_rgap->gw_auth_next = rgap;
		}
	}
}

void rip_remove_from_accepted_keys(task *tp, gw_entry *gw)
{
	rip_gw_auth *rgap, *p_rgap;

	rgap = rip_accepted_list;
	p_rgap = NULL;
	while (rgap) {
		if(rgap->gw == gw) {
			/* I am at the head of the list */
			if(p_rgap == NULL) {
				rip_accepted_list = rgap->gw_auth_next;
				task_mem_free(tp, rgap);
				rgap = rip_accepted_list;
			/* I am inside the list */
			} else {
				p_rgap->gw_auth_next = rgap->gw_auth_next;
				task_mem_free(tp, rgap);
				rgap = p_rgap->gw_auth_next;
			}
		} else {
			p_rgap = rgap;
			rgap = rgap->gw_auth_next;
		}
	}
}

/* Free our list of gateway/auth pairs */
void
rip_free_accepted_keys(task *tp)
{
	rip_gw_auth *rgap = rip_accepted_list;
	rip_gw_auth *n_rgap;

	while (rgap) {
		n_rgap = rgap->gw_auth_next;
		task_mem_free(tp, rgap);
		rgap = n_rgap;
	}
}

/* This builds a list of keys we need to send to */
rip_auth * 
rip_build_keys(task *tp, rip_auth *new_rap, rip_auth *auth) {
	rip_auth *rap, *k_rap, *got_rap;
	rip_gw_auth *rgap;
	time_t curtime = (time_t)(time_sec + time_boot);

	/* This is our best key , we allways use it */
	rap = new_rap;
	rap->auth_gen_next = NULL;

	/* We will loop through our list of gateway/auth pairs and 
	 * build a list of need keys, not allowing for duplicates.
	 * We will also check for expired times.
	 */
	for(rgap = rip_accepted_list; rgap; rgap = rgap->gw_auth_next) {
		got_rap = NULL;
		/* new_rap is always the head of the list */
		for(k_rap = new_rap; k_rap; k_rap = k_rap->auth_gen_next) {
			if(rgap->auth == k_rap) {
				got_rap = k_rap;
				break;
			}
		}
		if(!got_rap) {
			if(DIFFTIME(curtime, rgap->auth->auth_accept.tr_stop) 
			  >= 0) {
				rap->auth_gen_next = rgap->auth;
				rap = rgap->auth;
				rap->auth_gen_next = NULL;
				trace_log_tp(tp, 0, LOG_WARNING, ("rip_build_keys:Gateway useing keyid %d, will respond with that key", rgap->auth->auth_id));
			} else {
				trace_log_tp(tp, 0, LOG_WARNING,("rip_build_keys:Gateway useing expired key keyid %d, will not respond with that key", rgap->auth->auth_id));
			}
		}
	}
	return(new_rap);	
}

/* Check authentincation in a packet */
int
rip_auth_check (task *tp, struct rip *ripmsg, struct rip_netinfo **nets, 
  void_t *limit, gw_entry *gwp, rip_auth *auth1, rip_auth *auth2)
{
	struct rip_authinfo *ap = (struct rip_authinfo *) *nets;
	rip_auth *auths[2];
	int i, authcnt = 0;

	if(!auth1) {
		if (ap->auth_family != RIP_AF_AUTH) {
			return (TRUE);
		} else {
			return (FALSE);
		}
	}

	/* Is there auth here? */
	if(ripmsg->rip_vers == RIP_VERSION_0 || 
	   ripmsg->rip_vers == RIP_VERSION_1 ||
	   ap->auth_family != RIP_AF_AUTH) {
		return (FALSE);
	}

	/* Move to the next pointer */
	(*nets)++;

	/* Get heads of configured authentication list */
	if (auth1) {
		auths[authcnt++] = auth1;
	}
	if (auth2) {
		auths[authcnt++] = auth2;
	}

	for (i = 0; i < authcnt; i++) {
		if (ap->auth_type == htons(auths[i]->auth_type)) {
			switch (auths[i]->auth_type) {
				case RIP_AUTH_SIMPLE:
					if(!memcmp(auths[i]->auth_key, ap->auth_data, 
					   RIP_AUTH_NUM_BYTE)) { 
						/* Simple password match */
						return TRUE;
					}
					break;

#ifdef	MD5_CHECKSUM
				case RIP_AUTH_MD5: {
					struct rip_md5info *md5 = (struct rip_md5info*) ap;
					struct rip_trailer *rtp = (struct rip_trailer *) ((void_t) 
					  ((byte *) *limit - sizeof (struct rip_trailer)));
					u_int32 sequence = (u_int32) 0;
					u_int32 digest[RIP_AUTH_NUM_LONG];
					rip_auth *rap;
					size_t size;

					/* Fail if sequence number is lower then last if we
					 * have heard from this gw recently.  If time is 
					 * large (possible neighbor down/up) accept zero or 
					 * larger (or equal).
					 * rfc2082 sec 3.2.2
					 */
					if (gwp) {
						if (time_sec - gwp->gw_time < RIP_T_EXPIRE) {
							if(ntohl(md5->md5_sequence) < RIP2U32(gwp->gw_data)) {
								return FALSE;
							}
						} else {
							if(ntohl(md5->md5_sequence) < RIP2U32(gwp->gw_data) ||
							  ntohl(md5->md5_sequence) != 0) {
								return FALSE;
							}
						}
					}

					/* Find a key and test for validity */
					rap = rip_find_md5_key(md5->md5_keyid, auths[i]);
					if(!rap) return FALSE;

					/* Save the digest */
					memcpy(digest, rtp->auth_data, RIP_AUTH_NUM_BYTE);

					/* Put the secret in */
					memcpy(rtp->auth_data, rap->auth_key, RIP_AUTH_NUM_BYTE);

					/* size = ntohs(md5->rip_packlen) + sizeof(* rtp); */
					size = ntohs(md5->rip_packlen) + sizeof(struct rip_trailer);

					if(rtp->auth_family != RIP_AF_AUTH || 
					  ntohs(rtp->auth_type) != 1) {
						return FALSE;
					}

					md5_cksum((byte *) ripmsg, size, size, 
					  rtp->auth_data, NULL);

					if(!memcmp(digest, rtp->auth_data, RIP_AUTH_NUM_BYTE)) {
						/* Success! 
						 * Remove trailer length from limit size 
						 */
						*limit = (void_t) rtp;

						if (gwp) {
						/* Save the sequence number */
							gwp->gw_data = GS2A(sequence);
						}
						/* Put this key on a list of keys we need to send with 
						 * only if it is primary (auth1) auth
 						 */
						if(auths[i] == auth1 && gwp) {
							rip_add2accepted_keys(tp, gwp, rap);
						}
						return TRUE;
					}
					} /* end case */
					break;
#endif	/* MD5_CHECKSUM	*/
			}
		}
	}

	/* Nothing matched (or to match) */
	return FALSE;
}

/* Set authentication in a packet */
static size_t
rip_auth_set (struct rip *ripmsg, rip_auth *auth, 
    struct rip_authinfo *ap, size_t size)
{
	if (auth && ap) {
		/* Add authentication */
	
		ap->auth_family = htons(RIP_AF_AUTH);
		ap->auth_type = htons(auth->auth_type);

		switch (auth->auth_type) {
			case RIP_AUTH_SIMPLE:
				memcpy(ap->auth_data, auth->auth_key, RIP_AUTH_NUM_BYTE);
				break;

#ifdef	MD5_CHECKSUM
			case RIP_AUTH_MD5:
				{
				struct rip_md5info *md5 = (struct rip_md5info*) ap;
				struct rip_trailer *rtp = 
				    (struct rip_trailer *) ((void_t) 
				    ((byte *) ripmsg + size));
								 
				md5->rip_packlen = htons(size);
				md5->md5_keyid = auth->auth_id; 	
				md5->md5_authlen = sizeof(struct rip_trailer);
				md5->md5_sequence = htonl((u_long) 
				    (time_boot + time_sec));
				md5->rip_zero = 0;
				md5->rip_zero1 = 0;
				rtp->auth_family = RIP_AF_AUTH;
				rtp->auth_type = htons((u_int16) 1);

				memcpy(rtp->auth_data, auth->auth_key, RIP_AUTH_NUM_BYTE);

				/* Add trailer to length */
				size += sizeof (*rtp);

				/* Calculate and add digest */
				md5_cksum((byte *) ripmsg, size, size,
				    rtp->auth_data, (u_int32 *) 0);
				}
				break;
#endif	/* MD5_CHECKSUM */
		}
	}

	return size;
}

/* this sends the rip packets */
static void
rip_send  (task *tp, if_addr *ifap, flag_t flags, sockaddr_un *addr, 
    struct rip *msg, size_t size)
{
	u_short port = sock2port(addr);
	int rc;

	if (!port) {
		sock2port(addr) = rip_port;
	}

#ifdef	IP_MULTICAST
	if (inet_class_of(addr) == INET_CLASSC_MULTICAST) {

		/* Multicast sends fail if MSG_DONTROUTE is set */
		BIT_RESET(flags, MSG_DONTROUTE);
	
		if (rip_multicast_ifap != ifap) {
			IFA_FREE(rip_multicast_ifap);
			IFA_ALLOC(rip_multicast_ifap = ifap);
			(void) task_set_option(tp, TASKOPTION_MULTI_IF,
			    rip_multicast_ifap);
		}
	} else
#endif	/* IP_MULTICAST */
	{
		int ttl = BIT_TEST(flags, MSG_DONTROUTE) ? 1 : MAXTTL;
	
		/* Unicast processing */

		if (ttl != rip_unicast_ttl) {
			/* Set the TTL */

			(void) task_set_option(tp, TASKOPTION_TTL, 
			    rip_unicast_ttl = ttl);
		}
	}

	rc = task_send_packet(tp, (void_t) msg, size, flags, addr);

	if (TRACE_PACKET_SEND_TP(tp, msg->rip_cmd, RIPCMD_MAX, 
	    rip_trace_masks)) {
		rip_trace(tp->task_trace, rc, ifap, addr, msg, size,
		    TRACE_DETAIL_SEND_TP(tp, msg->rip_cmd, RIPCMD_MAX,
		    rip_trace_masks));
	}

	sock2port(addr) = port;
}

/* This is a wrapper for rip_send to handle multiple md5 keys */
void
rip_send_auth (task *tp, if_addr *ifap, flag_t flags, sockaddr_un *addr, 
  struct rip *msg, size_t size, rip_auth *auth, struct rip_authinfo *ap) 
{
	if(auth && auth->auth_type == RIP_AUTH_MD5) {
		rip_auth *rap;
	
		/* Build a list of keys to use, also add our best key */
		for (rap = rip_build_keys(tp, rip_get_best_md5_key(auth), auth);
		  rap; rap = rap->auth_gen_next) {
			rip_send(tp, ifap, flags, addr, (void_t) msg, 
			  rip_auth_set(msg, rap, ap, size));	
		}
	} else {
		rip_send(tp, ifap, flags, addr, (void_t) msg, 
		  rip_auth_set(msg, auth, ap, size));	
	}
}

/* Send RIP updates to all targets on the list */
/*ARGSUSED*/
static int
rip_supply (target *tlp, sockaddr_un *dest, flag_t flags, flag_t send_flags, 
    int update_type, rip_auth *auth)
{
	int count = 0;
	int changes = 0;
	size_t size;
	struct rip *ripmsg = task_get_send_buffer(struct rip *);
	struct rip_netinfo *start = (struct rip_netinfo *) 
	    ((void_t) (ripmsg + 1)), *fillp;
	struct rip_authinfo *ap = NULL;
	register td_entry *tdp;
	size_t max_size;

	/* Calculate max size */
	max_size = tlp->target_ifap->ifa_mtu - sizeof (struct udphdr);
	if (max_size > RIP_PKTSIZE) {
		max_size = RIP_PKTSIZE;
	}

	/* Initialize some fields in all the packets */
	bzero((caddr_t) ripmsg, sizeof *ripmsg);
	    
	ripmsg->rip_cmd = RIPCMD_RESPONSE;
	if (BIT_TEST(flags, RIPTF_V2)) {
		/* Set version 2 and authentication */

		ripmsg->rip_vers = RIP_VERSION_2;
		if (auth) {
			ap = (struct rip_authinfo *) ((void_t) start++);
			max_size -= sizeof (struct rip_trailer);
		}
	} else {
		/* Set version 1 */
		ripmsg->rip_vers = RIP_VERSION_1;
	}
	/* Round out to size of route entry */
	max_size -= (max_size - sizeof (struct rip)) % 
	    sizeof (struct rip_netinfo);
	fillp = start;

	/* Open the routing table in case a holddown is over */
	rt_open(tlp->target_task);

	TD_LIST(tdp, &tlp->target_td) {
		int cleanup = 0;
	
		if (update_type == RIP_FLASH_UPDATE) {
			if (!BIT_TEST(tdp->td_flags, TDF_CHANGED)) {
				/* End of changes for this target */
				break;
			}			
		} else if (update_type == RIP_FULL_UPDATE) {
			/* Check for termination of holddown */
			if (!BIT_TEST(rip_flags, RIPF_TERMINATE)
			    && BIT_TEST(tdp->td_flags, TDF_HOLDDOWN|TDF_POISON)
			    && !--tdp->td_metric) {
				/* Holddown is over - queue it to be released */
				cleanup++;
			}
		}

		if (BIT_TEST(tdp->td_flags, TDF_CHANGED)) {
			/* Reset the changed field */
			BIT_RESET(tdp->td_flags, TDF_CHANGED);
		}

		size = (byte *) fillp - (byte *) ripmsg;
		if (size >= max_size) {
			/* Send packet */

			rip_send_auth(tlp->target_task, tlp->target_ifap, send_flags, 
			  dest, ripmsg, size, auth, ap);

			count++;

			/* Reset the fill pointer for the next time */
			fillp = start;
#if	defined(PROTO_SNMP) && defined(MIB_RIP)
			/*
			 * Save the number of flash updates on the interface 
			 * for the target
			 */
			if (update_type == RIP_FLASH_UPDATE) {
				u_int *rip_triggered_updates = 
				     (u_int*) &tlp->target_ifap->ifa_rip_triggered_updates;
				(*rip_triggered_updates)++;
			}
#endif	/* PROTO_SNMP && MIB_RIP	*/
		}

		/* Put this entry in the packet */
		{
			register struct rip_netinfo *n = 
			    (struct rip_netinfo *) ((void_t) fillp);
	
			n->rip_family = htons(RIP_AF_INET);
			/* XXX - need to pick out of  per entry structure */
			n->rip_tag = htons(0);	
			n->rip_dest = sock2ip(tdp->td_rt->rt_dest);
			if (BIT_TEST(flags, RIPTF_V2)) {
				n->rip_dest_mask = 
				    sock2ip(tdp->td_rt->rt_dest_mask);

				if (RT_IFAP(tdp->td_rt) == tlp->target_ifap) {
					n->rip_router = 
					    sock2ip(RT_ROUTER(tdp->td_rt));
				} else {
					n->rip_router = 
					    sock2ip(*tlp->target_src);
				}
			} else {
				n->rip_dest_mask = 0;
				n->rip_router = 0;
			}

			if (BIT_TEST(tdp->td_flags, TDF_HOLDDOWN|TDF_POISON)) {
				n->rip_metric = htonl(RIP_METRIC_UNREACHABLE);
			} else {
				if (BIT_TEST(rip_flags, RIPF_TERMINATE)) {
					n->rip_metric = 
					    htonl(RIP_METRIC_SHUTDOWN);
				} else {
					n->rip_metric = 
					    htonl((u_int32) tdp->td_metric);
				}
			}
	
			/* Update the fill pointer */
			fillp++;
		}

		if (cleanup) {
			if (TRACE_TP(tlp->target_task, TR_POLICY)) {
				if (!changes) {
					trace_only_tp(tlp->target_task, 
					  TRC_NL_BEFORE,
				  	("rip_supply: Policy for target %A(%s)",
				   	 *tlp->target_dst,
					 BIT_TEST(tlp->target_flags, RIPTF_V2MC)
					 ?  "mc " : ""));
			}
			trace_only_tp(tlp->target_task, 0, ("\t%A/%A %s ended",
			    tdp->td_rt->rt_dest, tdp->td_rt->rt_dest_mask,
			    BIT_TEST(tdp->td_flags, TDF_POISON) ? 
			    "poison" : "holddown"));
			}
			changes++;
			TD_CLEANUP(tlp, tdp, TRUE);
		}
	} TD_LIST_END(tdp, &tlp->target_td) ;

	if (fillp > start) {
		/* OK to reply to a RIPQUERY with an empty packet */
		size = (byte *) fillp - (byte *) ripmsg;
		rip_send_auth(tlp->target_task, tlp->target_ifap, send_flags, dest, 
		  ripmsg, size, auth, ap);
		count++;
#if	defined(PROTO_SNMP) && defined(MIB_RIP)
		/* Save the number of flash updates on the interface for 
		 * the target
		 */
		if (update_type == RIP_FLASH_UPDATE) {
			u_int *rip_triggered_updates = 
			(u_int*) &tlp->target_ifap->ifa_rip_triggered_updates;
			(*rip_triggered_updates)++;
		}
#endif	/* PROTO_SNMP && MIB_RIP	*/
	}

	if (TRACE_TP(tlp->target_task, TR_POLICY) || changes) {
		trace_only_tp(tlp->target_task, 0, (NULL));
	}
    
	rt_close(tlp->target_task, (gw_entry *) 0, changes, NULL);

	return count;
}

/*
 *	Process a valid response
 */
static void
rip_recv_response  (task *tp, gw_entry *gwp, sockaddr_un *src_addr, 
    if_addr *ifap, struct rip *msg, register struct rip_netinfo *n, 
    void_t limit)
{
	int routes = 0;
	rt_parms rtparms;
	struct ifa_ps *ips = &ifap->ifa_ps[tp->task_rtproto];
	struct rip_netinfo *endp = (struct rip_netinfo *) limit;

#if	defined(PROTO_SNMP) && defined(MIB_RIP)
	u_int *rip_bad_routes = (u_int*) &ifap->ifa_rip_bad_routes;
	u_int *rip_bad_packets = (u_int*) &ifap->ifa_rip_bad_packets;
	struct timezone	time_zone;	/* Local variable for time zone */
	/*
	 * Retrieve the current Greenwich Mean Time and save it so the 
	 * RFC1155 TimeTick value can be calculated for rip2PeerLastUpdate.
	 */
	gettimeofday(&gwp->gw_last_update_time, &time_zone);
#endif	/* PROTO_SNMP && MIB_RIP	*/

	bzero((caddr_t) &rtparms, sizeof (rtparms));

	rtparms.rtp_n_gw = 1;
	rtparms.rtp_gwp = gwp;

	rt_open(tp);

	for (; n < endp; n++) {
		rt_entry *rt, *active_rt, *gw_rt, *first_rip_rt, *last_rip_rt;
		rt_head  *rth;
		int       rip_rt_cnt;

		routes++;
		
		if (ntohs(n->rip_family) != RIP_AF_INET) {
			/* Only interested in inet routes */
#if	defined(PROTO_SNMP) && defined(MIB_RIP)
			gwp->gw_bad_routes++;
			(*rip_bad_routes)++;
#endif	/* PROTO_SNMP && MIB_RIP */
			continue;
		}

		rtparms.rtp_dest = sockbuild_in(0, n->rip_dest);
		if (!inet_class_valid(rtparms.rtp_dest)) {
#if	defined(PROTO_SNMP) && defined(MIB_RIP)
			gwp->gw_bad_routes++;
			(*rip_bad_routes)++;
#endif	/* PROTO_SNMP && MIB_RIP */
			continue;
		}

		rtparms.rtp_preference = rip_preference;

		/* Convert metric to host byte order */
		rtparms.rtp_metric = ntohl(n->rip_metric);

		/* Verify that metric is valid */
		if (!rtparms.rtp_metric || rtparms.rtp_metric > 
		    RIP_METRIC_UNREACHABLE) {
			trace_log_tp(tp, 0, LOG_NOTICE,
			("rip_recv_response: bad metric (%u) for net %A from %#A",
			  rtparms.rtp_metric, rtparms.rtp_dest, src_addr));
#if	defined(PROTO_SNMP) && defined(MIB_RIP)
			gwp->gw_bad_routes++;
			(*rip_bad_routes)++;
#endif	/* PROTO_SNMP && MIB_RIP */
			continue;
		}
		
		/* Now add hop count to metric */
		rtparms.rtp_metric += ips->ips_metric_in;
		if (rtparms.rtp_metric > RIP_METRIC_UNREACHABLE) 
			rtparms.rtp_metric = RIP_METRIC_UNREACHABLE;

		rtparms.rtp_state = RTS_INTERIOR;
		RTP_RESET_ELIGIBLE(rtparms);
		RTP_SET_ELIGIBLE(rtparms, RIB_UNICAST);

		/* Determine the mask and router */
		switch (msg->rip_vers) {
			default:
				/* Mask */
				if (n->rip_dest_mask || 
				  sock2ip(rtparms.rtp_dest) == INADDR_DEFAULT) {
					/* Mask is supplied */

					rtparms.rtp_dest_mask = inet_mask_locate(n->rip_dest_mask);

					if (!rtparms.rtp_dest_mask) {
						trace_log_tp(tp, 0, LOG_NOTICE,
						("rip_recv_response: bad mask (%A) for net %A from %#A",
						rtparms.rtp_dest_mask, rtparms.rtp_dest, src_addr));
#if	defined(PROTO_SNMP) && defined(MIB_RIP)
						gwp->gw_bad_routes++;
						(*rip_bad_routes)++;
#endif	/* PROTO_SNMP && MIB_RIP */
						continue;
					}
				} else {
					/* Lookup the mask the old fashioned way */

					rtparms.rtp_dest_mask = 
						inet_mask_withif(rtparms.rtp_dest, ifap, 
					    &rtparms.rtp_state);
				}

				/* Router */
				if (n->rip_router) {
					/* Router was supplied */

					rtparms.rtp_router = sockbuild_in(0, n->rip_router);

					if (sockaddrcmp(ifap->ifa_addr_local, rtparms.rtp_router)) {
						/* Router is me! */

						continue;
					}
		
					if (if_withdst(rtparms.rtp_router) != ifap) {
						/* Supplied router is invalid */
						trace_log_tp(tp, 0, LOG_NOTICE,
						  ("rip_recv_response: bad router (%A) for net %A from %#A",
						  rtparms.rtp_router, rtparms.rtp_dest, src_addr));
#if	defined(PROTO_SNMP) && defined(MIB_RIP)
					gwp->gw_bad_routes++;
					(*rip_bad_routes)++;
#endif	/* PROTO_SNMP && MIB_RIP */
					continue;
				}

				/* Router is OK */
				break;
			} else {
				/* Router is source address */

				rtparms.rtp_router = gwp->gw_addr;
			}
			break;
	    
		case RIP_VERSION_0:
		case RIP_VERSION_1:
			/* Derive mask and router the old fashioned way */
			rtparms.rtp_dest_mask = 
			  inet_mask_withif(rtparms.rtp_dest, ifap, &rtparms.rtp_state);
			rtparms.rtp_router = gwp->gw_addr;
		}
		if (!rtparms.rtp_dest_mask) {
			/* No mask means zero subnet, ignore it */
#if	defined(PROTO_SNMP) && defined(MIB_RIP)
			gwp->gw_bad_routes++;
			(*rip_bad_routes)++;
#endif	/* PROTO_SNMP && MIB_RIP */
			continue;
		}

		if (if_myaddr(ifap, rtparms.rtp_dest, rtparms.rtp_dest_mask)) {
			/* Ignore route to interface */
#if	defined(PROTO_SNMP) && defined(MIB_RIP)
			if (!BIT_TEST(ifap->ifa_state,IFS_POINTOPOINT)) {
				gwp->gw_bad_routes++;
				(*rip_bad_routes)++;
			}
#endif	/* PROTO_SNMP && MIB_RIP */
			continue;
		}
		
		rtparms.rtp_tag = ntohs(n->rip_tag);

		/* Find and count all existing rip routes */
		rip_rt_cnt = 0;
		active_rt = gw_rt = first_rip_rt = NULL;
		rth = rt_table_locate(rtparms.rtp_dest, rtparms.rtp_dest_mask);
		if (rth) {
			active_rt = rth->rth_rib_active[RIB_UNICAST];
			RT_ALLRT(rt, rth) {
				if ( BIT_TEST(rt->rt_state, 
				  RTS_DELETE|RTS_HIDDEN|RTS_SUPPRESSED) )
					break;
				if ( (rt->rt_gwp->gw_proto == RTPROTO_RIP) ) { 
					if ( !first_rip_rt )
						first_rip_rt = rt;
					if (rt->rt_gwp == gwp) {
						gw_rt = rt;
						break;
					}

					/* Remember last non-deleted rip rt for this prefix */
					last_rip_rt = rt;
					rip_rt_cnt++;
				}
			} RT_ALLRT_END(rt, rth);
		}
		    
		/* Find 1st rip route (deleted routes are ignored) */
		if ( !first_rip_rt ) {
			/* No rip route installed so add rip rt if importable */
			if (rtparms.rtp_metric == RIP_METRIC_UNREACHABLE) {
				continue;
			}
			if (import(rtparms.rtp_dest, rtparms.rtp_dest_mask, 
			  rip_import_list, ips->ips_import, rtparms.rtp_gwp->gw_import, 
			  &rtparms.rtp_preference, &rtparms.rtp_eligible_ribs, ifap,
			  (void_t) 0)) {
				/* Add new route */
				rt = rt_add(&rtparms);
#if	defined(PROTO_SNMP) && defined(MIB_RIP)
				if (active_rt != rt->rt_rib_active[RIB_UNICAST])
					rip_global_changes++;
#endif	/* PROTO_SNMP && MIB_RIP */
			} else {
				BIT_SET(rtparms.rtp_gwp->gw_flags, GWF_IMPORT);
			}
			continue;
		} 

/* Rip route(s) already exist. */

		if ( gw_rt ) {  
			/* Route from this gw is already in list */
			if (rtparms.rtp_metric == RIP_METRIC_UNREACHABLE) {
				rt_delete(gw_rt);

#if	defined(PROTO_SNMP) && defined(MIB_RIP)
				if ( active_rt == gw_rt )
					rip_global_changes++;
#endif	/* PROTO_SNMP && MIB_RIP */

				continue;
			}
			if (rtparms.rtp_metric != gw_rt->rt_metric
			  || !sockaddrcmp_in(rtparms.rtp_router, RT_ROUTER(rt))
			  || rtparms.rtp_tag != gw_rt->rt_tag) {
				(void) rt_change(gw_rt, rtparms.rtp_metric, rtparms.rtp_metric2,
				  rtparms.rtp_tag, gw_rt->rt_preference, gw_rt->rt_preference2,
				  1, &rtparms.rtp_router);

#if	defined(PROTO_SNMP) && defined(MIB_RIP)
				if ( active_rt == gw_rt )
					rip_global_changes++;
#endif	/* PROTO_SNMP && MIB_RIP */

			}
			rt_refresh(gw_rt);
			continue;
		} 

		/* Route is not already in list of rt_entries for this prefix.
		 * We may be configured to keep backup routes so we need to
		 * see if we should hold onto this route.  This may require
		 * us to delete one that we're already holding onto.
		 * Configuration allows for all rip routes to be kept as backups
		 * or for a fixed number (including just 1) to be kept.
		 */ 

		if (rtparms.rtp_metric == RIP_METRIC_UNREACHABLE) {
			/* Don't add unreachable routes */
			continue;  
		} else if ( (rip_max_routes == 0) || (rip_rt_cnt < rip_max_routes) ) {
			/* We haven't hit limit yet so keep it and don't toss any route.
			 */
			rt = NULL;  
		} else if (rtparms.rtp_metric < last_rip_rt->rt_metric) {
			/* Metric is better than last in list; keep this one
			 * and toss last rip route 
			 */
			rt = last_rip_rt;  
		} else if ((rt_age(first_rip_rt) > (RIP_T_EXPIRE / 2))
		  && (first_rip_rt->rt_metric == rtparms.rtp_metric)) {
			/* Best rip route may expire soon; Keep new one
			 * and toss 1st rip route (the one that is expiring)
			 */
			rt = first_rip_rt; 
		} else {
			/* No reason to keep this route */
			continue;
		}
       
		/* See if it's importable before adding it */
		if (!import(rtparms.rtp_dest, rtparms.rtp_dest_mask, rip_import_list,
		  ips->ips_import, rtparms.rtp_gwp->gw_import, &rtparms.rtp_preference,
		  &rtparms.rtp_eligible_ribs, ifap, (void_t) 0)) {
			continue;
		}

		/* Add the new route to prefix */
		(void) rt_add(&rtparms);
		/* Complete the replacement if a route displaced existing one */
		if (rt)
			rt_delete(rt);

#if	defined(PROTO_SNMP) && defined(MIB_RIP)
		if (active_rt != rth->rth_rib_active[RIB_UNICAST])
			rip_global_changes++;
#endif	/* PROTO_SNMP && MIB_RIP */

	}        /*  for each route */

	rt_close(tp, rtparms.rtp_gwp, routes, NULL);
}


/*
 *	Process a valid request
 */
static void
rip_recv_request (task *tp, sockaddr_un *src_addr, if_addr *ifap, target *tlp, 
    struct rip *msg, register struct rip_netinfo *n, void_t limit, int poll, 
    rip_auth *auth)
{
	struct rip_netinfo *first = n;
	struct ifa_ps *ips = &ifap->ifa_ps[tp->task_rtproto];
	struct rip_netinfo *last = (struct rip_netinfo *) limit - 1;

	msg->rip_cmd = RIPCMD_RESPONSE;

	if (n == last && n->rip_family == ntohs(RIP_AF_UNSPEC)
	    && n->rip_metric == ntohl(RIP_METRIC_UNREACHABLE)) {
		/* A routing table request */

		if (poll) {
			int count = 0;
			gw_entry *gwp;
	    
			/* Dump all the rip routes */

			/* We can fill the whole packet -  
			 * (Vernon Schryver: 3/20/96) 
			 */
			last = (struct rip_netinfo *) ((void_t) 
			    ((caddr_t) msg + RIP_MAXSIZE(ifap))) - 1;

			GW_LIST(rip_gw_list, gwp) {
				rt_entry *rt;

				RTQ_LIST(&gwp->gw_rtq, rt) {
					if (n > last) {
						rip_send(tp, (if_addr *) 0, 0, 
						  src_addr, (void_t) msg,
						  (size_t) ((caddr_t) n - 
						  (caddr_t) msg));
#if	defined(PROTO_SNMP) && defined(MIB_RIP)
						rip_global_responses++;
#endif	/* PROTO_SNMP && MIB_RIP */    
						n = first;
						count++;
					}

					n->rip_family = 
						htons(socktype(rt->rt_dest));
					/* XXX - need to pick out of per entry 
					 * structure */
					n->rip_tag = htons(0);	
					n->rip_dest = sock2ip(rt->rt_dest);
					if (msg->rip_vers > RIP_VERSION_1) {
						n->rip_dest_mask = 
						  sock2ip(rt->rt_dest_mask ? 
						  rt->rt_dest_mask : 
						  inet_mask_host);
						if (RT_IFAP(rt) == ifap) {
							n->rip_router = 
							 sock2ip(RT_ROUTER(rt));
						} else {
							n->rip_router = 
							  sock2ip(ifap->ifa_addr_local);
						}
					} else {
						n->rip_dest_mask = 0;
						n->rip_router = 0;
					}
					n->rip_metric = htonl(rt->rt_metric);

					n++;
				} RTQ_LIST_END(&gwp->gw_rtq, rt) ;
			} GW_LIST_END(rip_gw_list, gwp) ;

			if (!count || n > first) {
				/* Send an empty packet or remaining data */
				rip_send(tp, (if_addr *) 0, 0, src_addr, 
				  (void_t) msg, (size_t) ((caddr_t) n - 
				  (caddr_t) msg));
#if	defined(PROTO_SNMP) && defined(MIB_RIP)
				rip_global_responses++;
#endif	/* PROTO_SNMP && MIB_RIP */    
			}
		} else {
			/* Request - dump full routing table */

			if (tlp) {
				flag_t flags = tlp->target_flags;
		
				if (msg->rip_vers < RIP_VERSION_2) {
					/* Do not respond to version 1 requests 
					 * with version 2 packets 
					 */

					BIT_RESET(flags, RIPTF_V2);
				} else if (sock2port(task_recv_srcaddr) 
				    != rip_port && !BIT_TEST(flags, RIPTF_V2)) {
					/* Answer V2 queries with V2 
					 * information 
					 */

					BIT_SET(flags, RIPTF_V2BC);
				}

				(void) rip_supply(tlp, src_addr, flags, 
				    (flag_t) 0, RIP_OTHER_UPDATE, auth);

			} else {
				/* If nothing to send him, provide an empty 
				 * packet 
				 */
				rip_send(tp, (if_addr *) 0, 0, src_addr, 
				(void_t) msg, (size_t) ((caddr_t) 
				n - (caddr_t) msg));
#if	defined(PROTO_SNMP) && defined(MIB_RIP)
				rip_global_responses++;
#endif	/* PROTO_SNMP && MIB_RIP */    
			}
		}
	} else {

		/* Specific request */

		while (n <= last) {
			/* Process each one */

			n->rip_metric = RIP_METRIC_UNREACHABLE;
	    
			if (n->rip_family == htons(RIP_AF_INET)) {
				sockaddr_un *addr = 
				    sockbuild_in(0, n->rip_dest);
				sockaddr_un *mask;
				flag_t table = RTS_INTERIOR;

				if (msg->rip_vers > RIP_VERSION_1
				    && n->rip_dest_mask) {
					mask = 
					    inet_mask_locate(n->rip_dest_mask);
				} else {
					mask = 
					    inet_mask_withif(addr, ifap, 
					    (flag_t *) 0);
				}
				if (mask) {
					rt_entry *rt = 
					  rt_locate(table, addr, mask,
				    	  poll ? RTPROTO_BIT(tp->task_rtproto) :
				    	  RTPROTO_BIT_ANY);

					if (rt && !BIT_TEST(rt->rt_state, 
					    RTS_HIDDEN|RTS_SUPPRESSED)) {
						n->rip_metric = rt->rt_metric;
						n->rip_metric += ips->ips_metric_out;
						n->rip_dest = sock2ip(rt->rt_dest);
						if(msg->rip_vers > RIP_VERSION_1) {
							n->rip_dest_mask = sock2ip(
							  rt->rt_dest_mask ?  rt->rt_dest_mask : 
							  inet_mask_host);
	  						if(RT_IFAP(rt) == ifap) {
								n->rip_router = sock2ip( RT_ROUTER(rt));
							} else  {
								n->rip_router = sock2ip( ifap->ifa_addr_local);
							}
						} else {
							n->rip_dest_mask = 0;
							n->rip_router = 0;
						}
						if (n->rip_metric > RIP_METRIC_UNREACHABLE) {
							n->rip_metric = RIP_METRIC_UNREACHABLE;
						}
					}
				}
			}
			GHTONL(n->rip_metric);
			n++;
		}

		rip_send(tp, (if_addr *) 0, 0, src_addr, (void_t) msg, (size_t) 
		    ((caddr_t) n - (caddr_t) msg));
#if	defined(PROTO_SNMP) && defined(MIB_RIP)
		rip_global_responses++;
#endif	/* PROTO_SNMP && MIB_RIP */    
	}
}


/*
 *	Process a valid poll-entry packet
 */
static void
rip_recv_pollentry (task *tp, sockaddr_un *src_addr, if_addr *ifap, 
    struct rip *msg)
{
	rt_entry *rt = (rt_entry *) 0;
	struct rip_netinfo *n = (struct rip_netinfo *) ((void_t) (msg + 1));

	if (n->rip_family == RIP_AF_INET) {
		sockaddr_un *addr = sockbuild_in(0, n->rip_dest);
		sockaddr_un *mask = inet_mask_withif(addr, ifap, (flag_t *) 0);
		flag_t table = RTS_INTERIOR;

		if (mask) {
			rt = rt_locate(table, addr, mask, RTPROTO_BIT_ANY);
		}
	}

	if (rt) {
		/* don't bother to check rip_vers */

		struct entryinfo *e = (struct entryinfo *) n;

		bzero((caddr_t) &e->rtu_dst, sizeof (e->rtu_dst));
		e->rtu_dst.rip_family = htons(socktype(rt->rt_dest));
		/* struct copy */
		e->rtu_dst.rip_addr = sock2ip(rt->rt_dest);    
		bzero((caddr_t) &e->rtu_router, sizeof (e->rtu_router));
		e->rtu_router.rip_family = htons(socktype(RT_ROUTER(rt)));
		/* struct copy */
		e->rtu_router.rip_addr = sock2ip(RT_ROUTER(rt));
		e->rtu_flags = 
		    htons((unsigned short) krt_state_to_flags(rt->rt_state));
		e->rtu_state = htons((unsigned short) rt->rt_state);
		e->rtu_timer = htonl((unsigned long) rt_age(rt));
		e->rtu_metric = htonl(rt->rt_metric);
		if (RT_IFAP(rt)) {
			e->rtu_int_flags = 
			    htonl((unsigned long) RT_IFAP(rt)->ifa_state);
			(void) strncpy(e->rtu_int_name, 
			    RT_IFAP(rt)->ifa_link->ifl_name, IFL_NAMELEN);
		} else {
			e->rtu_int_flags = 0;
			(void) strncpy(e->rtu_int_name, "(none)", IFL_NAMELEN);
		}
	} else {
		bzero((char *) n, sizeof (struct entryinfo));
	}

	rip_send(tp, (if_addr *) 0, 0, src_addr, (void_t) msg, 
	    sizeof (struct rip) + sizeof (struct entryinfo));
#if	defined(PROTO_SNMP) && defined(MIB_RIP)
	rip_global_responses++;
#endif	/* PROTO_SNMP && MIB_RIP */    
}


/*
 * 	Check out a newly received RIP packet.
 */
static void
rip_recv (task *tp)
{
	size_t size;
	int n_packets = TASK_PACKET_LIMIT;

#define	REJECT(p, m)	{ reject_msg = (m); pri = (p); goto Reject; }

	while (n_packets-- && !task_receive_packet(tp, &size)) {
		register if_addr *ifap = (if_addr *) 0;
		gw_entry *gwp = (gw_entry *) 0;
		register int OK = TRUE;
		struct rip *inripmsg = task_get_recv_buffer(struct rip *);
		int pri = 0;
		const char *reject_msg = (char *) 0;
		int check_zero = FALSE;
		int poll = FALSE;
		struct rip_netinfo *nets = 
		  (struct rip_netinfo *) ((void_t) (inripmsg + 1));
		void_t limit = (void_t) ((byte *) inripmsg + size);

		if (socktype(task_recv_srcaddr) != RIP_AF_INET) {
			REJECT(0, "protocol not INET");
		}

		/* Locate or create a gateway structure for this gateway */
		gwp = gw_locate(&rip_gw_list, tp->task_rtproto, tp, (as_t) 0, (as_t) 0, 
		  task_recv_srcaddr, GWF_NEEDHOLD);

		switch (inripmsg->rip_vers) {
			case RIP_VERSION_0:
				REJECT(LOG_NOTICE, "ignoring version 0 packets");

			case RIP_VERSION_1:
				check_zero = BIT_TEST(rip_flags, RIPF_NOCHECK) ? FALSE : TRUE;
				break;

			default:
				check_zero = FALSE;
		}

		/* If we have a list of trusted gateways, verify that this 
		 * gateway is trusted 
		 */
		if (rip_n_trusted && !BIT_TEST(gwp->gw_flags, GWF_TRUSTED)) {
			OK = FALSE;
		}
		if (TRACE_PACKET_RECV_TP(tp, inripmsg->rip_cmd, RIPCMD_MAX, 
		  rip_trace_masks)) {
			rip_trace(tp->task_trace, 0, ifap, gwp->gw_addr, inripmsg, size, 
			  TRACE_DETAIL_RECV_TP(tp, inripmsg->rip_cmd, RIPCMD_MAX, 
			  rip_trace_masks));
		}

		if (check_zero) {
			/* Verify that all reserved fields are zero */
			register struct rip_netinfo *n;

			if (inripmsg->rip_zero2) {
				goto not_zero;
			}

			switch (inripmsg->rip_cmd) {
				case RIPCMD_REQUEST:
				case RIPCMD_RESPONSE:
				/* Check the fields in the entries */

				for (n = (struct rip_netinfo *) ((void_t) (inripmsg + 1));
				(byte *) n < (byte *) limit; n++) {
					if (n->rip_tag || n->rip_dest_mask || n->rip_router) {
not_zero:
						pri = BIT_TEST(gwp->gw_flags, GWF_FORMAT) ? 0 : 
						  LOG_WARNING;
						BIT_SET(gwp->gw_flags, GWF_FORMAT);
						REJECT(pri, "reserved field not zero");
					}
				}
				break;
			}
		}

		/* Subtract header length from size */
		size -= sizeof (struct rip);
	
		/* Process packet */
		switch (inripmsg->rip_cmd) {
			case RIPCMD_POLL:
				poll = TRUE;
				/* Fall through */

			case RIPCMD_REQUEST:
	    	{
				target *tlp = NULL;
				rip_auth *auth = NULL;

				if (poll || sock2port(task_recv_srcaddr) != rip_port) {
					/* We should answer this request */

					/* BSD 4.3 Reno has a bug causing the address to be zero */
					if (task_recv_dstaddr && sock2ip(task_recv_dstaddr)
#ifdef	IP_MULTICAST
					  && !sockaddrcmp(task_recv_dstaddr, rip_addr_mc)
#endif	/* IP_MULTICAST */
					  ) {
						/* On some systems we can find the destination 
						 * address of the packet 
						 */
						ifap = if_withlcladdr(task_recv_dstaddr, TRUE);
						if (!ifap) {
							REJECT(0, 
							  "can not find interface for source address");
						}
					} else {
						ifap = if_withdst(gwp->gw_addr);
						if (!ifap) {
							/* This host does not share a network */
							rt_entry *rt;
			    
#ifndef EXTENDED_RIBS
							rt = rt_lookup(RTS_NETROUTE, (flag_t) 0, 
							  gwp->gw_addr, RTPROTO_BIT_ANY, RIB_UNICAST);
#else /* EXTENDED_RIBS */
							rt = rt_lookup(RTS_NETROUTE, (flag_t) 0, (flag_t) 0,
							  (flag_t) 0, gwp->gw_addr, RTPROTO_BIT_ANY, 
							  RIB_UNICAST);
#endif /* EXTENDED_RIBS */

							if (!rt) {
								REJECT(0, "can not find interface for route");
							}
							ifap = RT_IFAP(rt);
						}
					}
				}

				if (!poll) {
					target *tlp2;

					if (sock2port(task_recv_srcaddr) == rip_port) {
						/* This is a request from a router, 
						 * make sure we should and are allowed to reply 
						 */

						if (if_withlcladdr(gwp->gw_addr, FALSE)) {
							/* Ignore my own requests */
							continue;
						}
						if (!OK) {
							REJECT(0, "not on trustedgateways list");
						}
						if (!(ifap = if_withdst(gwp->gw_addr))) {
							REJECT(0, "not on attached network");
						}
						if (BIT_TEST(ifap->ifa_ps[tp->task_rtproto].ips_state, 
						  IFPS_NOIN|IFPS_NOOUT)) {
							REJECT(0, "interface marked for no RIP in/out");
						}

						/* Verify authentication */
						if (rip_auth_check(tp, inripmsg, &nets, &limit, NULL,
						  RIP_GET_IF_AUTH(ifap), RIP_GET_IF_AUTH2(ifap))) {
			    			/* Success - GateD allways replies with the
							 * primary authentication 
							 */
							auth = RIP_GET_IF_AUTH(ifap);
						} else {
							/* Failed */
							pri = RIP_TEST2LOG_WARN(gwp, GWF_AUTHFAIL);
							REJECT(pri, "authentication failure");
						}
					}

					/* Find the Target for this host */
					TARGET_LIST(tlp2, &rip_targets) {
						/* Look for target for this interface */
						if (BIT_TEST(tlp2->target_flags, TARGETF_SUPPLY)) {
							if (tlp2->target_gwp == gwp) {
								/* Found a target for this gateway! */

								tlp = tlp2;
								break;
							} else if (tlp2->target_ifap == ifap) {
								/* Found a target for this interface */
								/* remember it, but keep looking in case */
								/* there is one for the gateway */

								tlp = tlp2;
							}
						}
					} TARGET_LIST_END(tlp2, &rip_targets) ;

					/* Verify that we can respond */
					if (tlp && inripmsg->rip_vers < RIP_VERSION_2
					  && BIT_TEST(tlp->target_flags, RIPTF_V2)) {
						/* Do not respond to version 1 packets if we */
						/* are configured to send version 2 */
						REJECT(0, "not sending RIP 1");
					}
			
					if (sock2port(task_recv_srcaddr) == rip_port) {
						/* More sanity check on a request from a router */
						if (!tlp) {
							REJECT(0, "not supplying RIP");
						}

#ifdef	IP_MULTICAST
						/* Caveat: */
	
						if (BIT_TEST(tlp->target_flags, RIPTF_V2MC)
						  && inripmsg->rip_vers < RIP_VERSION_2) {
						/* If we are configured to send version 2 multicast 
						 * packet to this target, do not reply to queries 
						 * from sources that would not normally hear our 
						 * multicasts 
						 */
							if (!task_recv_dstaddr || 
							  !sock2ip(task_recv_dstaddr)) {
								/* Systems earlier than BSD 4.3 Reno (and Reno 
								 * itself without a bug fix) do not report the 
								 * destination address of UDP packets.  In this 
								 * case it is not  possible to determine if a 
								 * V2 requests was multicast, so to be safe we 
								 * will not even reply to version 2 requests 
								 * unless we  can determine that it was 
								 * multicast 
								 */
								REJECT(0, "unable to verify that sender is fully RIP v2 capable");
							}

							if (!sockaddrcmp(task_recv_dstaddr, rip_addr_mc)) {
								/* Request was not multicast */

								REJECT(0, "not configured for RIP-1 compatiblity");
							}
						}
#endif	/* IP_MULTICAST */
					}
				}

				if (!auth) {
					/* Authenticate as a user query */
					if (rip_auth_check(tp, inripmsg, &nets, &limit, gwp, 
					  rip_auth_query, NULL)) {
						/* Success - indicate the type we reply with */
						auth = rip_auth_query;
					} else {
						/* Failed */
						pri = RIP_TEST2LOG_WARN(gwp, GWF_AUTHFAIL);
						REJECT(pri, "authentication failure");
					}
				}
		
				if (((byte *) limit - (byte *) nets) % sizeof *nets) {
					REJECT(0, "not an even multiple of network entry size");
				}

				BIT_SET(gwp->gw_flags, GWF_QUERY | GWF_ACCEPT);

				rip_recv_request(tp, task_recv_srcaddr, ifap, tlp, inripmsg, 
				  nets, limit, poll, auth);
			}
			continue;

		case RIPCMD_TRACEON:
		case RIPCMD_TRACEOFF:
			if (!OK) {
				REJECT(0, "not on trustedgateways list");
			}
			if (ntohs(sock2port(task_recv_srcaddr)) > IPPORT_RESERVED) {
				REJECT(0, "not from a trusted port");
			}
			if (!(ifap = if_withdst(gwp->gw_addr))) {
				REJECT(0, "not on same net");
			}
			if (BIT_TEST(ifap->ifa_ps[tp->task_rtproto].ips_state, IFPS_NOIN)) {
				REJECT(0, "not listening to RIP on this interface");
			}
			REJECT(LOG_NOTICE, "TRACE packets not supported");

		case RIPCMD_POLLENTRY:
			/* BSD 4.3 Reno has a bug causing the address to be zero */
			if (task_recv_dstaddr && sock2ip(task_recv_dstaddr)
#ifdef	IP_MULTICAST
			  && !sockaddrcmp(task_recv_dstaddr, rip_addr_mc)
#endif	/* IP_MULTICAST */
			  ) {
				/* On some systems we can find the destination address of 
				 * the packet 
				 */
					ifap = if_withlcladdr(task_recv_dstaddr, TRUE);
					if (!ifap) {
						REJECT(0, "can not find interface for source address");
					}
				} else {
					ifap = if_withdst(gwp->gw_addr);
					if (!ifap) {
						/* This host does not share a network */
						rt_entry *rt;
			    
#ifndef EXTENDED_RIBS
						rt = rt_lookup(RTS_NETROUTE, (flag_t) 0, gwp->gw_addr,
						  RTPROTO_BIT_ANY, RIB_UNICAST);
#else /* EXTENDED_RIBS */
						rt = rt_lookup((flag_t) 0, RTS_NETROUTE, (flag_t) 0, 
						  (flag_t) 0, gwp->gw_addr, RTPROTO_BIT_ANY, 
						  RIB_UNICAST);
#endif /* EXTENDED_RIBS */

						if (!rt) {
							REJECT(0, "can not find interface for route");
						}
						ifap = RT_IFAP(rt);
					}
				}
				BIT_SET(gwp->gw_flags, GWF_QUERY | GWF_ACCEPT);
				if (rip_auth_query) {
					/* Authentication failure */
					pri = RIP_TEST2LOG_WARN(gwp, GWF_AUTHFAIL); 
					REJECT(pri, "authentication failure");
				}
				rip_recv_pollentry(tp, task_recv_srcaddr, ifap, inripmsg);
				continue;

			case RIPCMD_RESPONSE:
				if (!(ifap = if_withdst(gwp->gw_addr))) {
					REJECT(0, "not on same net");
				}
				/* If this packet is addressed from us, flag the interface 
				 * as up and ignore the packet 
				 */
				if (sockaddrcmp_in(gwp->gw_addr, ifap->ifa_addr_local)) {
					/* A packet from us */

					if (!BIT_TEST(ifap->ifa_state, IFS_SIMPLEX)) {
						/* If this interface is not simplex, indicate that 
						 * the media 
						 */
						/* is functioning */
						if_rtupdate(ifap);
					}

					/* Ignore the packet */
					continue;
				}

				/* update interface timer on interface that packet came in 
				 * on 
				 */
				if_rtupdate(ifap);

				if (!OK) {
#ifndef	notdef
					REJECT(0, "not on trustedgateways list");
#else	/* notdef */
					continue;
#endif	/* notdef */
				}

				if (sock2port(task_recv_srcaddr) != rip_port) {
					REJECT(0, "not from a trusted port");
				}

				if (BIT_TEST(ifap->ifa_ps[tp->task_rtproto].ips_state, 
				  IFPS_NOIN)) {
					REJECT(0, "interface marked for no RIP in");
				}

				/* Verify authentication */
				if (!rip_auth_check(tp, inripmsg, &nets, &limit, gwp,
				  RIP_GET_IF_AUTH(ifap), RIP_GET_IF_AUTH2(ifap))) {
					/* Failed */
					pri = RIP_TEST2LOG_WARN(gwp, GWF_AUTHFAIL);
					REJECT(pri, "authentication failure");
				}
		
				if (((byte *) limit - (byte *) nets) % sizeof *nets) {
					REJECT(0, "not an even multiple of network entry size");
				}

				BIT_SET(gwp->gw_flags, GWF_ACCEPT);
				gwp->gw_time = time_sec;

				rip_recv_response(tp, gwp, task_recv_srcaddr, ifap, 
				  inripmsg, nets, limit);
#if	defined(PROTO_SNMP) && defined(MIB_RIP)
				if (gwp) {
					/* save rip version for message from gateway */
					gwp->gw_last_version_received =	inripmsg->rip_vers;
				}
#endif	/* PROTO_SNMP && MIB_RIP */
				break;

			default:
				pri = RIP_TEST2LOG_WARN(gwp, GWF_FORMAT);
				REJECT(0, "invalid or not implemented command");
		}
		continue;

Reject:
#if	defined(PROTO_SNMP) && defined(MIB_RIP)
		if (gwp) {
			ifap = if_withdst(gwp->gw_addr);
			if (ifap && !BIT_TEST(ifap->ifa_ps[tp->task_rtproto].ips_state, 
			  IFPS_NOIN)) {
				u_int *rip_bad_packets = (u_int*) &ifap->ifa_rip_bad_packets;
				(*rip_bad_packets)++;
			}	    
			gwp->gw_bad_packets++;
		}
#endif	/* PROTO_SNMP && MIB_RIP */
		tracef("rip_recv: ignoring RIP ");
		if (inripmsg->rip_cmd < RIPCMD_MAX) {
			tracef("%s", trace_state(rip_cmd_bits, inripmsg->rip_cmd));
		} else {
			tracef("#%d", inripmsg->rip_cmd);
		}
		trace_log_tp(tp, 0, pri, (" packet from %#A - %s", task_recv_srcaddr,
		  reject_msg));
		trace_only_tp(tp, 0, (NULL));
		if (gwp) {
			BIT_SET(gwp->gw_flags, GWF_REJECT);
		}
	}
}

/**/
/*
 *	Deal with interface policy
 */
static void
rip_control_reset (task *tp, if_addr *ifap)
{
	struct ifa_ps *ips = &ifap->ifa_ps[tp->task_rtproto];

	BIT_RESET(ips->ips_state, IFPS_RESET);
	ips->ips_metric_in = ifap->ifa_metric + RIP_HOP;
	ips->ips_metric_out = (metric_t) 0;
	ifap->ifa_rip_auth = ifap->ifa_rip_auth2 = (void_t) 0;
}


static void
rip_control_set (task *tp, if_addr *ifap)
{
	struct ifa_ps *ips = &ifap->ifa_ps[tp->task_rtproto];
	config_entry **list = config_resolv_ifa(rip_int_policy, ifap, 
	    RIP_CONFIG_MAX);

	/* Reset */
	rip_control_reset(tp, ifap);

	/* Set defaults */
	switch (BIT_TEST(ifap->ifa_state, 
	    IFS_POINTOPOINT|IFS_LOOPBACK|IFS_BROADCAST)) {
		case IFS_LOOPBACK:
			/* By default we do not send or listen on the loopback
			 * interface.  This does not prevent us from processing
			 * diagnostic POLL and REQUEST packets. 
			 */
			BIT_SET(ips->ips_state, IFPS_NOIN|IFPS_NOOUT);
			break;

		case IFS_POINTOPOINT:
			/* By default we do not send RIP out a P2P interface. */
			BIT_SET(ips->ips_state, IFPS_NOOUT);
			break;

		case IFS_BROADCAST:
		default:
			/* On broadcast and NBMA interfaces we default to 
			 * sending and receiving responses. 
			 */
			break;
	}

	/* Process configuration info */
	if (list) {
		int type = RIP_CONFIG_MAX;
		config_entry *cp;

		/* Fill in the parameters */
		while (--type) {
			if ((cp = list[type])) {
				switch (type) {
					case RIP_CONFIG_IN:
						if (GA2S(cp->config_data)) {
							BIT_RESET(ips->ips_state, IFPS_NOIN);
						} else {
							BIT_SET(ips->ips_state, IFPS_NOIN);
						}
						break;

					case RIP_CONFIG_OUT:
						if (GA2S(cp->config_data)) {
							BIT_RESET(ips->ips_state, IFPS_NOOUT);
						} else {
							BIT_SET(ips->ips_state, IFPS_NOOUT);
						}
						break;

					case RIP_CONFIG_METRICIN:
						BIT_SET(ips->ips_state, IFPS_METRICIN);
						ips->ips_metric_in = (metric_t) GA2S(cp->config_data);
						break;

					case RIP_CONFIG_METRICOUT:
						BIT_SET(ips->ips_state, IFPS_METRICOUT);
						ips->ips_metric_out = (metric_t) GA2S(cp->config_data);
						break;

					case RIP_CONFIG_FLAG:
						BIT_SET(ips->ips_state, (flag_t) GA2S(cp->config_data));
						break;

					case RIP_CONFIG_AUTH:
						/* Primary authentication */
						ifap->ifa_rip_auth = cp->config_data;
						break;

					case RIP_CONFIG_AUTH2:
						/* Secondary authentication */
						ifap->ifa_rip_auth2 = cp->config_data;
						break;
				}
			}
		}

		config_resolv_free(list, RIP_CONFIG_MAX);
	}
}


void
rip_config_free (config_entry *cp)
{
	switch (cp->config_type) {
		case RIP_CONFIG_AUTH:
		case RIP_CONFIG_AUTH2:
			if ((rip_auth *) cp->config_data) {
				task_block_free(rip_auth_block_index, 
				    cp->config_data);
			}
			break;
	
		default:
			/* Not allocated */
			break;
	}
}

/* Routine to check after interface parsing if we have specified 
 * authentication without specifying RIPv2 (since v1 is default).
 */

int
rip_auth_policy (config_list *cp_list)
{
	int test_auth=0;
	int test_version=0;

	config_entry *cp;

	for (cp = cp_list->conflist_list; cp; cp = cp->config_next) {
		switch (cp->config_type) {

			/* Check to see whether either primary or secondary 
			 * authentication have been set.  If they haven't then 
			 * we don't care.  If they have then it's important 
			 * that we are not RIPv1.
			 */

			case RIP_CONFIG_AUTH:
				if (cp->config_data) {
					test_auth++;
				}
				break;
			case RIP_CONFIG_AUTH2:
				if (cp->config_data) {
					test_auth++;
				}
				break;

			/* RIP_CONFIG_FLAG is where our version information 
			 * comes in.  We mark if we see version 2 in any of 
			 * it's variations so that we know it's ok to use 
			 * authentication.  The check for whether version is 
			 * within appropriate limits occurs elswhere, so as 
			 * long as we're not version 1, we're good to go.
			 */
			case RIP_CONFIG_FLAG:
				if (cp->config_data != RIP_IFPS_V1) {
					test_version++;
				}
				break;
		}
	} 

	/* After examining the interface options, we perform the test.  If 
	 * authentication was specified, and v2 wasn't, then error.
	 */
	if (test_auth && !test_version) {
		return 1;
	}
	return 0;
}

/*
 *	Cleanup before re-init
 */
/*ARGSUSED*/
static void
rip_cleanup (task *tp)
{
	adv_cleanup(RTPROTO_RIP, &rip_n_trusted, &rip_n_source, rip_gw_list, 
	    &rip_int_policy, &rip_import_list, &rip_export_list);

	if (rip_auth_query) {
		task_block_free(rip_auth_block_index, (void_t) rip_auth_query);
		rip_auth_query = (rip_auth *) NULL;
	}
    
#ifdef	IP_MULTICAST
	if (rip_multicast_ifap) {
		IFA_FREE(rip_multicast_ifap);
		rip_multicast_ifap = (if_addr *) NULL;
	}
#endif	/* IP_MULTICAST */

	if (tp) {
		trace_freeup(tp->task_trace);
	}
	trace_freeup(rip_trace_options);
}


static void
rip_exit (task *tp)
{
	gw_entry *gwp;
	if_addr *ifap;

	/* Release the target list, bit assignments, and buffers */
	target_free_list(tp, &rip_targets);

	/* Reset the policy */
	IF_ADDR(ifap) {
		if (socktype(IFA_UNIQUE_ADDR(ifap)) == AF_INET) {
			rip_control_reset(tp, ifap);
		}
	} IF_ADDR_END(ifap) ;

	rt_open(tp);

	GW_LIST(rip_gw_list, gwp) {
		rt_entry *rt;

		RTQ_LIST(&gwp->gw_rtq, rt) {
			rt_delete(rt);
#if	defined(PROTO_SNMP) && defined(MIB_RIP)
			rip_global_changes++;
#endif	/* PROTO_SNMP && MIB_RIP */
		} RTQ_LIST_END(&gwp->gw_rtq, rt) ;
	} GW_LIST(rip_gw_list, gwp) ;

	rt_close(tp, (gw_entry *) 0, 0, NULL);

	rip_cleanup(tp);

	/* Free our gateway/auth list */
	rip_free_accepted_keys(tp);

#ifdef	IP_MULTICAST
	if (rip_addr_mc) {
		/* Initialize address constant */
		sockfree(rip_addr_mc);
		rip_addr_mc = (sockaddr_un *) 0;
	}
#endif	/* IP_MULTICAST */

	task_delete(tp);
	rip_timer_update = rip_timer_flash = rip_timer_age = (task_timer *) 0;
}

/*
 *	Evaluate policy for changed routes.
 */
static int
rip_policy (task *tp, target *tlp, rt_list *change_list)
{
	if_addr *ifap = tlp->target_ifap;
	u_long if_net = inet_net_natural(IFA_UNIQUE_ADDR(ifap));
	int same_net = if_net == inet_net_natural(ifap->ifa_addr_local);
	int changes = 0;
	int logged = 0;
	rt_head *rth;
	struct ifa_ps *ips = &ifap->ifa_ps[tp->task_rtproto];

	RT_LIST(rth, change_list, rt_head) {
		register rt_entry *new_rt = rth->rth_rib_active[RIB_UNICAST];
		adv_results result;
		td_entry *tdp;
		int exportable = FALSE;
		int holddown = 0;
		int poison = 0;
		int set_metric = 0;
		int move_bit = 0;

		trace_tp(tp, TR_POLICY, 0, 
		    ("rip_policy: evaluating %A/%A", 
		    rth->rth_dest, rth->rth_dest_mask));

		TD_TSI_GET(tlp, rth, tdp);

		/* Can we announce the new route (if there is one)? */
		if (new_rt) {
			if (socktype(new_rt->rt_dest) != AF_INET) {
				goto no_export;
			}
	    
			if (BIT_TEST(new_rt->rt_state, RTS_NOADVISE|RTS_GROUP)){
				/* Absolutely not */
				goto no_export;
			}

			if (RT_IFAP(new_rt) == ifap &&
			    new_rt->rt_gwp->gw_proto == RTPROTO_DIRECT) {
				/* Do not send interface routes back to the 
				 * same interface 	
				 */
				goto no_export;
			}

			if (RT_IFAP(new_rt) == ifap 
			    && sockaddrcmp(RT_ROUTER(new_rt), 
			    *tlp->target_dst)) {
				/* Sending a route back to the router you are 
				 * using could cause a routing loop 
				 */
				goto no_export;
			}

			/* RIP version 2 sends everything everywhere by default.
			 * If we are multicasting, we're ok.  Otherwise, there 
			 * are two options:  If we are using RIPv2, then if we 
			 * have source gateways, we're ok.  In all other cases,
			 * we need to send RIPv1 comaptible packets, so we 
			 * check for subnets 
			 */
 
			if (!BIT_TEST(tlp->target_flags, RIPTF_V2MC)
			  && !(BIT_TEST(tlp->target_flags, RIPTF_V2BC)
			  &&  BIT_TEST(tlp->target_flags, TARGETF_SOURCE))) {

				/* Host routes go everywhere, 
				 * subnets and nets may need to be restricted 
				 */
				if (new_rt->rt_dest_mask != inet_mask_host) {
					sockaddr_un *natural_mask = 
					  inet_mask_natural(new_rt->rt_dest);

					if (new_rt->rt_dest_mask > natural_mask) {
						/* This is a subnet */

						if (!same_net || 
						  (sock2ip(rth->rth_dest) & 
						  sock2ip(natural_mask)) != if_net) {
							/* Only send subnets to i/f's of the same net */
							goto no_export;
						}
						if (rth->rth_dest_mask != ifap->ifa_netmask) {
							/* Only send subnets that have the same mask */
							goto no_export;
						}
					} else if ((sock2ip(rth->rth_dest) == if_net)) {
						/* Do not send the whole net to a subnet */
						goto no_export;
					}
				}
			}

			if ((new_rt->rt_gwp->gw_proto == tp->task_rtproto) 
			  && (ifap == RT_IFAP(new_rt))) {
				/* Split horizon */
				goto no_export;
			}

			if (RT_IFAP(new_rt)
			  && !BIT_TEST(RT_IFAP(new_rt)->ifa_state, IFS_UP)) {
				/* The interface is down */
				goto no_export;
			}

			/* Assign default metric */
			if (new_rt->rt_gwp->gw_proto == RTPROTO_AGGREGATE) {
				/* Originate aggregates with a metric of one */
				result.res_metric = RIP_HOP;
			} else if (!RT_IFAP(new_rt)
			  || (BIT_TEST(RT_IFAP(new_rt)->ifa_state, IFS_LOOPBACK) 
			  && sock2ip(RT_IFAP(new_rt)->ifa_addr_local) 
			  == INADDR_LOOPBACK)) {
				/* Routes via the loopback int. must have an explicit metric */ 
				result.res_metric = RIP_METRIC_UNREACHABLE;
			} else if (new_rt->rt_gwp->gw_proto == RTPROTO_DIRECT) {
				/* Interface routes */
				if (BIT_TEST(RT_IFAP(new_rt)->ifa_state, IFS_POINTOPOINT)) {
					/* Add a hop for the P2P link */
					result.res_metric = RIP_HOP * 2;
				} else {
					/* Default to one hop */
					result.res_metric = RIP_HOP;
				}
			} else {
				/* Use configured default metric */
				result.res_metric = rip_default_metric;
			}

			if (!export(new_rt, tp->task_rtproto, rip_export_list,
			  ips->ips_export, tlp->target_gwp ? tlp->target_gwp->gw_export 
			  : (adv_entry *) 0, &result)) {
				/* Policy prohibits announcement */
				goto no_export;
			} else {
				/* Add the interface metric */
				result.res_metric += ips->ips_metric_out;
			}

			if (result.res_metric < RIP_METRIC_UNREACHABLE) {
				exportable = TRUE;
			}

no_export: ;
		}

		/*
		 * Now that we have determined the exportablility of the new
		 * route, we decide what changes need to be made.  The
		 * complexity is required to surpress routing loops both
		 * within RIP and between RIP and other protocols. 
		 *
		 * There are two types of holddowns used; the first one is
		 * called HOLDDOWN and is used when a route goes away or is
		 * overridden by a route that is not suspected to be an echo
		 * of a route we are announcing.  The second is called POISON
		 * and is used when a route is overridden by a route suspected
		 * to be an echo of a route we are announcing.
		 */

		if (!tdp) {
			/* New route */
			if (exportable) {
				/* and it is exportable
				 * Allocate new entry and fill it in
				 */
				TD_ALLOC(tdp);
				TD_TSI_SET(tlp, rth, tdp);
				rtbit_set(new_rt, tlp->target_rtbit);
				set_metric++;
			}
		} else if (!new_rt) {
			/* No new route, just an old one */
			if ( !BIT_TEST(tdp->td_flags, TDF_POISON|TDF_HOLDDOWN) ) {
				if (BIT_TEST(tdp->td_rt->rt_state, 
				  RTS_DELETE|RTS_HIDDEN|RTS_SUPPRESSED)) {
					/* Put into holddown if old route was deleted */
					holddown++;
				} else {
					/* Poison the old route */
					poison++;
				}
			}
		} else if (new_rt == tdp->td_rt) {
			/* Something has changed with the route we are announcing */
			if (BIT_TEST(tdp->td_flags, TDF_POISON|TDF_HOLDDOWN)) {
				if (exportable) {
					/* Announcing as unreachable; Ok to take out of holddown */
					set_metric++;
				}
			} else {
				if (!exportable) {
					poison++;
				} else if (tdp->td_metric != result.res_metric) {
					set_metric++;
				}
			}
		} else if (!RT_TEST_PENDING(new_rt, RIB_UNICAST)) {
			/* The new route can be announced right away (not from a holddown
			 * proto).  Actually pending test is: new active from a holddown 
			 * proto and old active being announced by holddown proto.  Since
			 * we are the latter, pending clear implies the new active is
			 * not from a holddown protocol.
			 */
			if (!exportable) {  /* Except it might not be exportable */
				if (!BIT_TEST(tdp->td_flags, TDF_POISON|TDF_HOLDDOWN)) {
					poison++;
				}
			} else if ( !BIT_TEST(tdp->td_flags, TDF_HOLDDOWN) ) {
				/* Don't prematurely end holddown; Wait for reflash when
				 * we end holddown for old route.
				 *
				 * If not holding down old route, announce new one now.
				 */
				move_bit++;
				set_metric++;
			}
		} else {
			/* New route is pending (from a holddown protocol) */
			if ( BIT_TEST(tdp->td_flags, TDF_POISON|TDF_HOLDDOWN) ) {
				/* Being helddown or poisoned.  Let it complete */
				;
			} else if ( exportable && ( (new_rt->rt_metric <= tdp->td_metric) 
			  || (BIT_TEST(new_rt->rt_gwp->gw_flags, GWF_NOHOLD)
			  || BIT_TEST(tdp->td_rt->rt_gwp->gw_flags, GWF_NOHOLD)) ) ) {
				/* New rt has a better metric than old so it probably isn't
				 * an echo.  We can use it right away.  
				 * Or the new route or old route is a ``static'' route, 
				 * in which case we override immediately.
				 */
				move_bit++;
				set_metric++;
			} else {
				/* Poison the current route.  Reflash of new active won't 
				 * occur until poison is over.
				 */
				poison++;
			}
		}

		if (set_metric || holddown || poison) {
			if (TRACE_TP(tp, TR_POLICY)) {
				if (!logged) {
					logged++;
					trace_only_tp(tp, TRC_NL_BEFORE, 
					  ("rip_policy: Policy for target %A%s", *tlp->target_dst, 
					  BIT_TEST(tlp->target_flags, RIPTF_V2MC) ? "mc " : ""));
				}
				tracef("\t%A/%A ", rth->rth_dest, rth->rth_dest_mask);
			}

			/* Changed entries need to be at the head of the queue to 
			 * make triggered updates quick
			 */
			if (tdp->td_rt)
				TD_DEQUE(tdp);
			TD_ENQUE(tlp, tdp);

			if (set_metric) {
				if (move_bit) {
					rtbit_set(new_rt, tlp->target_rtbit);
					(void) rtbit_reset(tdp->td_rt, tlp->target_rtbit);
				}
				tdp->td_rt = new_rt;
				target_set_metric(tdp, result.res_metric);
				trace_tp(tp, TR_POLICY, 0, ("metric %u", tdp->td_metric));
			} else if (holddown) {
				target_set_holddown(tdp, RIP_HOLDCOUNT);
				trace_tp(tp, TR_POLICY, 0, ("starting holddown"));
			} else if (poison) {
				target_set_poison(tdp, RIP_HOLDCOUNT);
				trace_tp(tp, TR_POLICY, 0, ("starting poison"));
			} 
			changes++;
		}
	} RT_LIST_END(rth, change_list, rt_head) ;

	if (logged) {
		trace_tp(tp, TR_POLICY, 0, (NULL));
	}

	return changes;
}


/*
 *	send RIP packets
 */
/*ARGSUSED*/
static void
rip_job (task_timer *tip UNUSED, time_t interval UNUSED)
{
	target *tlp;
    
	TARGET_LIST(tlp, &rip_targets) {
		if (BIT_TEST(tlp->target_flags, TARGETF_SUPPLY)) {
			(void) rip_supply(tlp,
#ifdef	IP_MULTICAST
			BIT_TEST(tlp->target_flags, RIPTF_V2MC) ? rip_addr_mc :
#endif	/* IP_MULTICAST */
			*tlp->target_dst,
			tlp->target_flags,
			MSG_DONTROUTE,
			RIP_FULL_UPDATE,
			tlp->target_ifap->ifa_rip_auth);
		}
	} TARGET_LIST_END(tlp, &rip_targets) ;

	/* Indicate that flash updates are possible as soon as the timer i
	 * fires 
	 */
	BIT_RESET(rip_flags, RIPF_NOFLASH|RIPF_FLASHDUE);
	task_timer_set(rip_timer_flash, RIP_T_FLASH, (time_t) 0);
}


/*
 *	send a flash update packet
 */
/*ARGSUSED*/
static void
rip_do_flash (task_timer *tip, time_t interval UNUSED)
{
	static int term_updates = 4;
	task *tp = tip->task_timer_task;

	if (BIT_TEST(rip_flags, RIPF_FLASHDUE|RIPF_TERMINATE)) {
		int count = 0;
		target *tlp;

		trace_tp(tp, TR_TASK, 0, 
		    ("rip_do_flash: Doing flash update for RIP"));

		TARGET_LIST(tlp, &rip_targets) {
			if (BIT_TEST(tlp->target_flags, TARGETF_SUPPLY)) {
				count += rip_supply(tlp,
#ifdef	IP_MULTICAST
				BIT_TEST(tlp->target_flags, RIPTF_V2MC) ? 
				    rip_addr_mc :
#endif	/* IP_MULTICAST */
				*tlp->target_dst,
				tlp->target_flags,
				MSG_DONTROUTE,
				/* Set "flash" if not terminating */
				BIT_TEST(rip_flags, RIPF_TERMINATE) 
				? RIP_FULL_UPDATE 
				: RIP_FLASH_UPDATE,
				tlp->target_ifap->ifa_rip_auth);
			}
		} TARGET_LIST_END(tlp, &rip_targets) ;

		trace_tp(tp, TR_TASK, 0, ("rip_do_flash: Flash update done"));

		if (BIT_TEST(rip_flags, RIPF_TERMINATE) && 
		    (!count || !--term_updates)) {
			/* Sent the requisite number of updates or nothing 
			 * to send
			 */
			rip_exit(tp);
			return;
		}

		/* Indicate no flash update is due */
		BIT_RESET(rip_flags, RIPF_FLASHDUE);

		/* Schedule the next flash update */
		if (BIT_TEST(rip_flags, RIPF_TERMINATE) ||
		    time_sec + RIP_T_MIN + RIP_T_MAX < 
		    rip_timer_update->task_timer_next_time) {
			/* We can squeeze another flash update in before 
			 * the full update 
			 */
			task_timer_set(tip, RIP_T_FLASH, (time_t) 0);
		} else {
			/* The next flash update will be scheduled after 
			 * the next full update 
			 */
			task_timer_reset(tip);
			BIT_SET(rip_flags, RIPF_NOFLASH);
		}
	} else {
		task_timer_reset(tip);
	}
}


/*
 *	Do or schedule a flash update
 */
static void
rip_need_flash (task *tp UNUSED)
{
	task_timer *tip = rip_timer_flash;

	if (!tip) {
		BIT_RESET(rip_flags, RIPF_FLASHDUE);
		return;
	}
    
	/* Indicate we need a flash update */
	BIT_SET(rip_flags, RIPF_FLASHDUE);

	/* And see if we can do it now */
	if (BIT_TEST(tip->task_timer_flags, TIMERF_INACTIVE)
	    && !BIT_TEST(rip_flags, RIPF_NOFLASH)) {
		/* Do it now */

		rip_do_flash(tip, (time_t) 0);
	}
}


/*
 *	Process changes in the routing table.
 */
static void
rip_flash (task *tp, rt_list *change_list)
{
	int changes = 0;
	target *tlp;
    
	/* Re-evaluate policy */
	rt_open(tp);

	TARGET_LIST(tlp, &rip_targets) {
		if (BIT_TEST(tlp->target_flags, TARGETF_SUPPLY)) {
			changes += rip_policy(tp, tlp, change_list);
		}
	} TARGET_LIST_END(tlp, &rip_targets) ;
    
	/* Close the table */
	rt_close(tp, (gw_entry *) 0, 0, NULL);

	if (changes) {
		/* Schedule a flash update */

		rip_need_flash(tp);
	}
}


/*
 *	Re-evaluate routing table
 */
static void
rip_newpolicy (task *tp, rt_list *change_list)
{
	/* Need to setup targets from mainline during init so rip_flash()
	 * will see them.
	 */
	if (BIT_TEST(rip_flags, RIPF_RECONFIG)) {
		rip_target_list_build(tp);
		BIT_RESET(rip_flags, RIPF_RECONFIG);
	}

	/* And evaluate policy */
	rip_flash(tp, change_list);
}

/*
 *  Age out RIP routes
 */
static void
rip_age (task_timer *tip, time_t interval UNUSED)
{
	time_t expire_to = time_sec - RIP_T_EXPIRE;
	time_t nexttime = time_sec + 1;

	if (expire_to > 0) {
		gw_entry *gwp;

		rt_open(tip->task_timer_task);
    
		GW_LIST(rip_gw_list, gwp) {
			rt_entry *rt;

			if (!gwp->gw_n_routes) {
				/* No routes for this gateway */

				if (!gwp->gw_import && !gwp->gw_export && 
				    !BIT_TEST(gwp->gw_flags, 
				    GWF_SOURCE|GWF_TRUSTED)) {
					/* No routes, delete this gateway */

					/* XXX */
				}
				continue;
			}

			/* Age any routes for this gateway */
			RTQ_LIST(&gwp->gw_rtq, rt) {
				if (rt->rt_time <= expire_to) {
					/* This route has expired */

					rt_delete(rt);

#if	defined(PROTO_SNMP) && defined(MIB_RIP)
					rip_global_changes++;
#endif	/* PROTO_SNMP && MIB_RIP */

				} else {
					/* This is the next route to expire */
					if (rt->rt_time < nexttime) {
						nexttime = rt->rt_time;
					}
					break;
				}
			} RTQ_LIST_END(&gwp->gw_rtq, rt) ;
		} GW_LIST_END(rip_gw_list, gwp) ;

		/* Remove this GW from our GW/AUTH pair list if exists */
		rip_remove_from_accepted_keys(tip->task_timer_task, gwp);

		rt_close(tip->task_timer_task, (gw_entry *) 0, 0, NULL);
	}

	if (nexttime > time_sec) {
		/* No routes to expire */
		nexttime = time_sec;
	}

	task_timer_set(tip, (time_t) 0, nexttime + RIP_T_EXPIRE - time_sec);
}

/*
 *	Initialize static variables
 */
void
rip_var_init(void)
{
#ifdef RIP_DEFAULT_OFF
	rip_flags = RIPF_CHOOSE;
#else  /* RIP_DEFAULT_OFF */
	rip_flags = RIPF_ON|RIPF_CHOOSE;
#endif /* RIP_DEFAULT_OFF */

	rip_default_metric = 1;
	rip_preference = RTPREF_RIP;
	rip_max_routes = RIP_MAX_ROUTES;

	/* Set up interface bits to be printed */
	int_ps_bits[RTPROTO_RIP] = rip_if_bits;

	/* Set up authentication block type */
	if (!rip_auth_block_index) {
		rip_auth_block_index = 
		    task_block_init(sizeof (rip_auth), 
		    "rip_rip_auth");
	}
}

static void
rip_tsi_dump (FILE *fp, rt_head *rth, void_t data, const char *pfx)
{
	target *tlp = (target *) data;
	td_entry *tdp;

	TD_TSI_GET(tlp, rth, tdp);

	if (tdp) {
		if (BIT_TEST(tdp->td_flags, TDF_HOLDDOWN|TDF_POISON)) {
			(void) fprintf(fp, "%sRIP %A%s <%s> remaining %#T", 
			    pfx, *tlp->target_dst, BIT_TEST(tlp->target_flags, 
			    RIPTF_V2MC) ? "mc " : "", 
			    trace_bits(target_entry_bits, tdp->td_flags), 
			    tdp->td_metric * RIP_T_UPDATE);
		} else {
			(void) fprintf(fp, "%sRIP %A%s <%s> metric %u", pfx, 
			    *tlp->target_dst, BIT_TEST(tlp->target_flags, 
			    RIPTF_V2MC) ? "mc " : "", 
			    trace_bits(target_entry_bits, tdp->td_flags),
				  tdp->td_metric);
		}
	}
    
	return;
}


/*
 *	Update the target list
 */
static void
rip_target_list (task_job *jp)
{
	rip_target_list_build(jp->task_job_task);
}

static void
rip_target_list_build (register task *tp)
{
	int targets;
	target *tlp;
	flag_t target_flags = TARGETF_ALLINTF;
	static int n_targets, n_source;

	/* If broadcast/nobroadcast not specified, figure out if we */
	/* need to broadcast packets */
	if (BIT_TEST(rip_flags, RIPF_CHOOSE)) {
		if (if_n_addr[AF_INET].up > 1 && inet_ipforwarding) {

			BIT_SET(rip_flags, RIPF_BROADCAST);
		} else {

			BIT_RESET(rip_flags, RIPF_BROADCAST);
		}
	}

	if (!rip_timer_age) {
		/* Create route age timer */

		rip_timer_age = task_timer_create(tp, "Age", (flag_t) 0, 
		    (time_t) 0, RIP_T_EXPIRE, rip_age, (void_t) 0);
	}

	if (BIT_TEST(rip_flags, RIPF_SOURCE|RIPF_BROADCAST)) {
		/* We are supplying updates */

		/* Gateways do not listen to redirects */
		redirect_disable(tp->task_rtproto);
	
		/* Make sure the timers are active */
		if (!rip_timer_update) {
			/* Create the update timer */

			rip_timer_update = task_timer_create(tp, "Update", 0, 
			    (time_t) RIP_T_UPDATE, (time_t) RIP_T_MAX, rip_job,
			    (void_t) 0);
		}

		if (!rip_timer_flash) {
			/* Create flash update timer */

			rip_timer_flash = task_timer_create(tp, "Flash", 
			    (flag_t) 0, (time_t) RIP_T_FLASH, (time_t) 
			    RIP_T_MAX, rip_do_flash, (void_t) 0);
		}
	} else {
		/* We are not supplying updates */
	
		/* Hosts do listen to redirects */
		redirect_enable(tp->task_rtproto);

		/* Make sure the timers do not exist */
		if (rip_timer_update) {
			task_timer_delete(rip_timer_update);
			rip_timer_update = (task_timer *) 0;
		}

		if (rip_timer_flash) {
			task_timer_delete(rip_timer_flash);
			rip_timer_flash = (task_timer *) 0;
		}
	}

    
	/* Set flags for target list build */
	if (BIT_TEST(rip_flags, RIPF_BROADCAST)) {
		BIT_SET(target_flags, TARGETF_BROADCAST);
	}
	if (BIT_TEST(rip_flags, RIPF_SOURCE)) {
		BIT_SET(target_flags, TARGETF_SOURCE);
	}

	/* Build or update target list */
	targets = target_build(tp, &rip_targets, rip_gw_list, rip_int_policy, 
	    target_flags, rip_tsi_dump);

#ifdef	IP_MULTICAST
	TARGET_LIST(tlp, &rip_targets) {
		/* Enable or disable v1 compatible v2 extensions */
		if (BIT_TEST(
		    tlp->target_ifap->ifa_ps[tp->task_rtproto].ips_state, 
		    RIP_IFPS_V2BC)) {
			BIT_SET(tlp->target_flags, RIPTF_V2BC);
		} else {
			BIT_RESET(tlp->target_flags, RIPTF_V2BC);
		}

		if (BIT_TEST(tlp->target_flags, TARGETF_BROADCAST)
		    && BIT_TEST(tlp->target_ifap->ifa_state, IFS_MULTICAST)
		    && BIT_TEST(tlp->target_ifap->ifa_state, 
		    IFS_BROADCAST|IFS_POINTOPOINT)) {
			/* Enable transmission and reception of packets to 
			 * the RIP multicast group
			 */

			if (BIT_TEST(
			   tlp->target_ifap->ifa_ps[tp->task_rtproto].ips_state,
	 		   RIP_IFPS_V2MC) && rip_mc_set(tp, tlp)) {
				/* Interface is MC capable and sending of V2 
				 * packets requested
				 */

				BIT_SET(tlp->target_flags, RIPTF_V2MC);
			} else {
				/* Can not send MC V2 packets */

				BIT_RESET(tlp->target_flags, RIPTF_V2MC);
			}
		} 

		if (tlp->target_ifap->ifa_rip_auth) {
			switch (BIT_TEST(tlp->target_flags, RIPTF_V2)) {
				case RIPTF_V2MC:
					break;
		
				case RIPTF_V2BC:
					trace_log_tp(tp, 0, LOG_WARNING, 
					 ("rip_target_list: %A (%s): authentication not recommended w/o multicast", 
					 *tlp->target_dst, 
					 tlp->target_ifap->ifa_link->ifl_name));
					break;
		
				default:
					trace_log_tp(tp, 0, LOG_WARNING, 
					 ("rip_target_list: %A (%s): ignoring authentication", 
					 *tlp->target_dst, 
					 tlp->target_ifap->ifa_link->ifl_name));
					break;
			}
		}
	} TARGET_LIST_END(tlp, &rip_targets) ;
#endif	/* IP_MULTICAST */

	/* Send a RIP REQUEST for everyone's routing table */
	if (!BIT_TEST(task_state, TASKS_TEST)) {
		byte buffer[sizeof (struct rip) + sizeof (struct rip_netinfo) 
		  + sizeof (struct rip_authinfo) + sizeof (struct rip_trailer)];
		struct rip *ripmsg = (struct rip *) ((void_t) buffer);
		struct rip_authinfo *ap;
		rip_auth *auth;

		bzero((caddr_t) buffer, sizeof buffer);
		ripmsg->rip_cmd = RIPCMD_REQUEST;

		TARGET_LIST(tlp, &rip_targets) {
			struct rip_netinfo *nets = 
			    (struct rip_netinfo *) ((void_t) (ripmsg + 1));

			if ((BIT_TEST(rip_flags, RIPF_RECONFIG) || 
			    !BIT_TEST(tlp->target_flags, RIPTF_POLL)) && 
			    BIT_TEST(tlp->target_flags, TARGETF_BROADCAST) && 
			    !BIT_TEST(tlp->target_ifap->ifa_ps[tp->task_rtproto].ips_state, 
			    IFPS_NOIN|IFPS_NOOUT)) {
				/* Do a poll if one has not been done on this 
				 * interface, or we are reconfiguring 
				 */

				/* Set the version */
				if (BIT_TEST(tlp->target_flags, RIPTF_V2)) {
					/* Set version 2 */
		    
					ripmsg->rip_vers = RIP_VERSION_2;
					auth = (rip_auth *) 
					    tlp->target_ifap->ifa_rip_auth;
					if (auth) {
						ap = 
						 (struct rip_authinfo *) nets++;
					} else {
						ap = (struct rip_authinfo *) NULL;
						auth = (rip_auth *) NULL;
					}
				} else {
					/* Set version 1 */

					ripmsg->rip_vers = RIP_VERSION_1;
					ap = (struct rip_authinfo *) NULL;
					auth = (rip_auth *) NULL;
				}
				bzero((caddr_t) nets, sizeof (*nets));
				nets->rip_family = htons(RIP_AF_UNSPEC);
				nets->rip_metric = 
				    htonl(RIP_METRIC_UNREACHABLE);

				rip_send_auth(tp, tlp->target_ifap, MSG_DONTROUTE,
#ifdef	IP_MULTICAST
				BIT_TEST(tlp->target_flags, RIPTF_V2MC) ? 
				    rip_addr_mc :
#endif	/* IP_MULTICAST */
				*tlp->target_dst, (void_t) ripmsg, 
				  (size_t) ((byte *) (nets + 1) - (byte *) buffer), 
				  auth, ap);
				BIT_SET(tlp->target_flags, RIPTF_POLL);
			}
		} TARGET_LIST_END(tlp, &rip_targets) ;
	}

	/* Evaluate policy for new targets */
	{
		int changes = 0;
		int have_list = 0;
		rt_list *rthl = (rt_list *) 0;

		rt_open(tp);

		TARGET_LIST(tlp, &rip_targets) {
			if (BIT_TEST(tlp->target_flags, TARGETF_BROADCAST)) {
				if (BIT_TEST(tlp->target_ifap->ifa_ps[tp->task_rtproto].ips_state, IFPS_NOIN)) {
					gw_entry *gwp;

					GW_LIST(rip_gw_list, gwp) {
						register rt_entry *rt;

						RTQ_LIST(&gwp->gw_rtq, rt) {
							if (RT_IFAP(rt) == 
							    tlp->target_ifap) {
								rt_delete(rt);
#if	defined(PROTO_SNMP) && defined(MIB_RIP)
								rip_global_changes++;
#endif	/* PROTO_SNMP && MIB_RIP */
								changes++;
							}
						} RTQ_LIST_END(&gwp->gw_rtq, rt) ;
					} GW_LIST_END(rip_gw_list, gwp) ;
				}
			}
			switch (BIT_TEST(tlp->target_flags, 
			    TARGETF_POLICY|TARGETF_SUPPLY)) {
				case TARGETF_SUPPLY:
					/* Need to run policy for this target */

					if (!have_list) {
						/* Get target list */
						rthl = 
						   rthlist_active(AF_INET, RIB_UNICAST);
						have_list++;
					}
	
					if (rthl) {
						/* and run policy */
						changes += rip_policy(tp, tlp, rthl);
					}

					/* Indicate policy has been run */
					BIT_SET(tlp->target_flags, TARGETF_POLICY);
					break;

				case TARGETF_POLICY:
					/* Indicate policy run on this target */

					BIT_RESET(tlp->target_flags, TARGETF_POLICY);
					break;

				default:
					break;
			}
		} TARGET_LIST_END(tlp, &rip_targets) ;

		if (rthl) {
			RTLIST_RESET(rthl);
		}

		rt_close(tp, (gw_entry *) 0, 0, NULL);

		if (changes && !BIT_TEST(rip_flags, RIPF_RECONFIG)) {
			rip_need_flash(tp);
		}
	}

	if (targets != n_targets || rip_n_source != n_source) {

		tracef("rip_target_list: ");
		if (targets) {
			tracef("supplying updates to");
			if (targets - rip_n_source) {
				tracef(" %d interface%s", targets - rip_n_source, 
				  (targets - rip_n_source) > 1 ? "s" : "");
			}
			if (rip_n_source) {
				tracef(" %d gateways", rip_n_source);
			}
		} else {
			tracef("just listening");
		}	
		n_targets = targets;
		n_source = rip_n_source;
		trace_log_tp(tp, TRC_NL_AFTER, LOG_INFO, (NULL));
	}

	rip_target_list_job = (task_job *) 0;
	/* XXX - Send a full update if anything has changed */
}


/*
 *	Reinit after parse
 */
/*ARGSUSED*/
static void
rip_reinit (task *tp)
{
	int entries = 0;
	gw_entry *gwp;

	if (!rip_auth_query) {
		rip_auth_query = NULL;
	}
    
	trace_set(tp->task_trace, rip_trace_options);

	/* Open the routing table */
	rt_open(tp);

	GW_LIST(rip_gw_list, gwp) {
		rt_entry *rt;

		RTQ_LIST(&gwp->gw_rtq, rt) {
			pref_t preference = rip_preference;

			/* Calculate preference of this route */
			if (import(rt->rt_dest, rt->rt_dest_mask, 
			    rip_import_list, 
			    RT_IFAP(rt)->ifa_ps[tp->task_rtproto].ips_import, 
			    rt->rt_gwp->gw_import, &preference, 	
			    &rt->rt_eligible_ribs, RT_IFAP(rt), (void_t) 0)) {
				if (rt->rt_preference != preference) {
					/* The preference has changed, change 
					 * the route	
					 */
					(void) rt_change(rt, rt->rt_metric, 
					    rt->rt_metric2, rt->rt_tag, 
					    preference, 
				    	    rt->rt_preference2, rt->rt_n_gw, 
					    rt->rt_routers);

#if	defined(PROTO_SNMP) && defined(MIB_RIP)
					rip_global_changes++;
#endif	/* PROTO_SNMP && MIB_RIP */

				}
				entries++;
			} else {
				/* This route is now restricted */
				rt_delete(rt);
			}
		} RTQ_LIST_END(&gwp->gw_rtq, rt) ;
	} GW_LIST_END(rip_gw_list, gwp) ;

	/* Close the routing table */
	rt_close(tp, (gw_entry *) 0, entries, NULL);

	/* Free our gateway/auth table */
	rip_free_accepted_keys(tp);

	/* Indicate a reconfig in process */
	BIT_SET(rip_flags, RIPF_RECONFIG);
}


/*
 *	Terminating - clean up
 */
static void
rip_terminate (task *tp)
{
	BIT_SET(rip_flags, RIPF_TERMINATE);
    
	if (BIT_TEST(rip_flags, RIPF_SOURCE|RIPF_BROADCAST)) {
		/* Disable receive */
		task_set_recv(tp, 0);
		task_set_socket(tp, tp->task_socket);
		task_timer_reset(rip_timer_update);

		/* Start shutdown procedure */
		rip_do_flash(rip_timer_flash, (time_t) 0);

		/* Make sure we don't try this again */
		task_set_terminate(tp, 0);
	} else {
		/* Not supplying, go away now */
		rip_exit(tp);
	}
}


/*
 *	Dump info about RIP
 */
static void
rip_int_dump (FILE *fd, config_entry *list)
{
	register config_entry *cp;

	CONFIG_LIST(cp, list) {
		switch (cp->config_type) {
			case RIP_CONFIG_IN:
				(void) fprintf(fd, " %sripin", 
				    GA2S(cp->config_data) ? "" : "no");
				break;

			case RIP_CONFIG_OUT:
				(void) fprintf(fd, " %sripout", 
				    GA2S(cp->config_data) ? "" : "no");
				break;

			case RIP_CONFIG_METRICIN:
				(void) fprintf(fd, " metricin %u", (metric_t) 
				    GA2S(cp->config_data));
				break;

			case RIP_CONFIG_METRICOUT:
				(void) fprintf(fd, " metricout %u", (metric_t) 
				    GA2S(cp->config_data));
				break;

			case RIP_CONFIG_FLAG:
				(void) fprintf(fd, " <%s>", 
				    trace_bits(rip_if_bits, (flag_t) 	
				    GA2S(cp->config_data)));
				break;

			case RIP_CONFIG_AUTH2:
				(void) fprintf(fd, " secondary");
				/* Fall through */
	    
			case RIP_CONFIG_AUTH:
			{
				rip_auth *rap = 
				    (rip_auth *) cp->config_data;

				if(!rap) {
					(void) fprintf(fd,
					  " authentication none");
					break;
				}
		
				switch (rap->auth_type) {
					case RIP_AUTH_SIMPLE:
						(void) fprintf(fd, " authentication simple \"%.*s\"", 
						  RIP_AUTH_NUM_BYTE, (char *) rap->auth_key);
						break;

					case RIP_AUTH_MD5:
						(void) fprintf(fd, " authentication md5 { ");
						for(; rap ; rap = rap->auth_acc_next) {
							(void) fprintf(fd, "key \"%.*s\" id %d , ",
							  RIP_AUTH_NUM_BYTE, (char *) rap->auth_key, 
							  rap->auth_id);
						}
						(void) fprintf(fd, "} \n");
						break;
		    
					default:
						(void) fprintf(fd, " unknown authentication type %u\n",
						  rap->auth_type);
						break;
				}
			}
			break;

			default:
				assert(FALSE);
				break;
		}
	} CONFIG_LIST_END(cp, list) ;
}


static void
rip_dump (task *tp, FILE *fd)
{
	(void) fprintf(fd, 
	    "\tFlags: %s\tDefault metric: %d\t\tDefault preference: %d\n",
	    trace_bits(rip_flag_bits, rip_flags), rip_default_metric, 
	    rip_preference);
	target_dump(fd, &rip_targets, rip_target_bits);
	if (rip_gw_list) {
		(void) fprintf(fd, "\tActive gateways:\n");
		gw_dump(fd, "\t\t", rip_gw_list, tp->task_rtproto);
		(void) fprintf(fd, "\n");
	}
	if (rip_int_policy) {
		(void) fprintf(fd, "\tInterface policy:\n");
		control_interface_dump(fd, 2, rip_int_policy, rip_int_dump);
	}
	control_import_dump(fd, 1, RTPROTO_RIP, rip_import_list, rip_gw_list);
	control_export_dump(fd, 1, RTPROTO_RIP, rip_export_list, rip_gw_list);
	(void) fprintf(fd, "\n");
}


/*
 *	Deal with an interface status change
 */
static void
rip_ifachange (task *tp, if_addr *ifap)
{
	int changes = 0;
	gw_entry *gwp;

	if (socktype(IFA_UNIQUE_ADDR(ifap)) != AF_INET) {
		return;
	}
    
	rt_open(tp);
    
	switch (ifap->ifa_change) {
		case IFC_NOCHANGE:
		case IFC_ADD:
			if (BIT_TEST(ifap->ifa_state, IFS_UP)) {
				rip_control_set(tp, ifap);
			}
			break;
	
		case IFC_DELETE:
		case IFC_DELETE|IFC_UPDOWN:
Down:
			GW_LIST(rip_gw_list, gwp) {
				rt_entry *rt;

				RTQ_LIST(&gwp->gw_rtq, rt) {
					if (RT_IFAP(rt) == ifap) {
						rt_delete(rt);

#if	defined(PROTO_SNMP) && defined(MIB_RIP)
						rip_global_changes++;
#endif	/* PROTO_SNMP && MIB_RIP */

						changes++;
					}
				} RTQ_LIST_END(&gwp->gw_rtq, rt) ;
			} GW_LIST_END(rip_gw_list, gwp) ;

			rip_control_reset(tp, ifap);

#ifdef	IP_MULTICAST
			if (ifap == rip_multicast_ifap) {
				IFA_FREE(rip_multicast_ifap);
				rip_multicast_ifap = (if_addr *) 0;
			}
#endif	/* IP_MULTICAST */

			break;

		default:
			/* Something has changed */

			if (BIT_TEST(ifap->ifa_change, IFC_UPDOWN)) {
				if (BIT_TEST(ifap->ifa_state, IFS_UP)) {
					rip_control_set(tp, ifap);
				} else {
					goto Down;
				}
			}
			if (BIT_TEST(ifap->ifa_change, IFC_METRIC)) {
				struct ifa_ps *ips = 
				    &ifap->ifa_ps[tp->task_rtproto];

				/* The metric has changed, reset the POLL bit 
				 * on any targets using this interface so we'll
				 * send another POLL 
				 */

				if (!BIT_TEST(ips->ips_state, IFPS_METRICIN)) {
					target *tlp;

					ips->ips_metric_in = ifap->ifa_metric +
					     RIP_HOP;

					TARGET_LIST(tlp, &rip_targets) {
						if (tlp->target_ifap == ifap) {
							BIT_RESET(tlp->target_flags, 
							    RIPTF_POLL);
						}
					} TARGET_LIST_END(tlp, &rip_targets) ;
				}
		}
		if (BIT_TEST(ifap->ifa_change, IFC_NETMASK)) {
			/* The netmask has changed, delete any routes that */
			/* point at gateways that are no longer reachable */
	
			target *tlp;
    
			GW_LIST(rip_gw_list, gwp) {
				rt_entry *rt;

				RTQ_LIST(&gwp->gw_rtq, rt) {
					if (RT_IFAP(rt) == ifap
					    && (if_withdstaddr(RT_ROUTER(rt)) 
					    != ifap
					    || BIT_TEST(rt->rt_state, 
					    RTS_IFSUBNETMASK))) {
						/* Interface for this route has
						 * changed or we derived the 
						 * subnet mask 
						 */
#if	defined(PROTO_SNMP) && defined(MIB_RIP)
						rip_global_changes++;
#endif	/* PROTO_SNMP && MIB_RIP */

						rt_delete(rt);
						changes++;
					}
				} RTQ_LIST_END(&gwp->gw_rtq, rt) ;
			} GW_LIST_END(rip_gw_list, gwp) ;

			TARGET_LIST(tlp, &rip_targets) {
				if (tlp->target_ifap == ifap && 
				    BIT_COMPARE(tlp->target_flags, 
				    TARGETF_SUPPLY|RIPTF_V2MC, TARGETF_SUPPLY)){
					/* Some subnet masks may have been 
					 * derrived, indicate that policy needs 					 * to be rerun 
					 */

					BIT_RESET(tlp->target_flags, 
					    TARGETF_POLICY);
				}
			} TARGET_LIST_END(tlp, &rip_targets) ;
		}
		if (BIT_TEST(ifap->ifa_change, IFC_BROADCAST)) {
		/* The broadcast address has changed.  Since target_dst 
		 * Is a pointer to the pointer to the broadcast address 
		 * the change is automatic.  But we should reset the POLL 
		 * bit so we'll POLL this new address in case there are 
		 * routers we did not yet hear from 
		 */

			target *tlp = target_locate(&rip_targets, ifap, 
			    (gw_entry *) 0);

			if (tlp && !BIT_TEST(tlp->target_flags, RIPTF_V2MC)) {
				/* Using the broadcast address on this 
				 * interface 
				 */

				BIT_RESET(tlp->target_flags, RIPTF_POLL);
			}
		}
	    
		/* A LOCALADDR change will take effect when the peers notice 
		 * that the old address is no longer sending  An MTU change 
		 * will take effece on output A SEL change is not possible in 
		 * IP 
		 */
		break;
	}

	rt_close(tp, (gw_entry *) 0, changes, NULL);

	/* Schedule a target list rebuild if necessary */
	if (!rip_target_list_job && ! BIT_TEST(rip_flags, RIPF_RECONFIG)) {
		rip_target_list_job = 
			task_job_create(tp, TASK_JOB_FG, "Target_Build", 
			    rip_target_list, (void_t) 0);
	}
#if	defined(PROTO_SNMP) && defined(MIB_RIP)
	/*
	 * Rebuild the list of rip interfaces supporting the RIP II MIB. 
	 * Refer to RFC 1389 or rip-mib.c for more information.
	 */
	o_rip_intf_get();
#endif	/* PROTO_SNMP && MIB_RIP */
}


/*
 * initialize RIP socket and RIP task
 */

/*ARGSUSED*/
void
rip_init(void)
{
	static task *rip_task;
	/* Hack for UTX/32 and Ultrix */
	void (*flash)(task *, rt_list *) = rip_flash;	
	void (*newpolicy)(task *, rt_list *) = rip_newpolicy;	

	if (BIT_TEST(rip_flags, RIPF_ON)) {
		trace_inherit_global(rip_trace_options, rip_trace_types, 
		    (flag_t) 0);
		if (!rip_task) {
			rip_task = 
			    task_alloc("RIP", TASKPRI_PROTO, rip_trace_options);
			rip_task->task_rtfamily = AF_INET;
			if (!inet_udpcksum) {
				trace_log_tp(rip_task, 0, LOG_ERR, 
				  ("rip_init: UDP checksums *DISABLED* in kernel; RIP disabled"));
				task_delete(rip_task);
				rip_timer_update = rip_timer_flash = 
				    rip_timer_age = (task_timer *) 0;
				rip_task = (task *) 0;
				return;
			}
			if (!rip_port) {
				rip_port = task_get_port(rip_trace_options, 
				    "route", "udp", htons(RIP_PORT));
			}
			rip_task->task_addr = sockdup(inet_addr_any);
			sock2port(rip_task->task_addr) = rip_port;
			rip_task->task_rtproto = RTPROTO_RIP;
			task_set_recv(rip_task, rip_recv);
			task_set_cleanup(rip_task, rip_cleanup);
			task_set_reinit(rip_task, rip_reinit);
			task_set_dump(rip_task, rip_dump);
			task_set_terminate(rip_task, rip_terminate);
			task_set_ifachange(rip_task, rip_ifachange);
			task_set_flash(rip_task, flash);
			task_set_newpolicy(rip_task, newpolicy);

			if ((rip_task->task_socket = 
			    task_get_socket(rip_task, AF_INET, SOCK_DGRAM, 0)) 
			    < 0) {
				task_quit(errno);
			}
			if (!task_create(rip_task)) {
				task_quit(EINVAL);
			}

			if (task_set_option(rip_task, TASKOPTION_BROADCAST, 
			    TRUE) < 0) {
				task_quit(errno);
			}
			if (task_set_option(rip_task, TASKOPTION_RECVBUF, 
			    task_maxpacket) < 0) {
				task_quit(errno);
			}
			(void) task_set_option(rip_task, TASKOPTION_RCVDSTADDR, 
			    TRUE);
			if (task_set_option(rip_task, TASKOPTION_NONBLOCKING, 
			    TRUE) < 0) {
				task_quit(errno);
			}
			if (task_addr_local(rip_task, rip_task->task_addr)) {
				trace_log_tp(rip_task, 0, LOG_ERR, 
				    ("rip_init: is routed or an old copy of gated running?"));
				task_quit(errno);
			}

			/* Allocate the buffers */
			task_alloc_send(rip_task, RIP_PKTSIZE);
			task_alloc_recv(rip_task, RIP_PKTSIZE);

#if	defined(PROTO_SNMP) && defined(MIB_RIP)
			rip_init_mib(TRUE);
#endif	/* PROTO_SNMP && MIB_RIP */

#ifdef	IP_MULTICAST
			if (!rip_addr_mc) {
				/* Initialize address constant */

				rip_addr_mc = 
				   sockdup(sockbuild_in(0, htonl(RIP_ADDR_MC)));
			}
#endif	/* IP_MULTICAST */

		}
	} else {
		rip_cleanup((task *) 0);

#if	defined(PROTO_SNMP) && defined(MIB_RIP)
		rip_init_mib(FALSE);
#endif	/* PROTO_SNMP && MIB_RIP */
		if (rip_task) {
			rip_terminate(rip_task);

			rip_task = (task *) 0;
		}
	}
}
