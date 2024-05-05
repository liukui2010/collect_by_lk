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


/* Kernel interface definitions */

extern char *krt_version_kernel;
extern gw_entry *krt_gw_list;
extern task *krt_task;
extern task_timer *krt_timer_ifcheck;
extern const bits kernel_trace_types[];
extern const bits kernel_option_bits[];
extern const bits kernel_support_bits[];
extern trace *kernel_trace_options;
extern u_long krt_n_routes;		/* Number of routes currently in the kernel */

#ifdef	KRT_IFREAD_KINFO
/* Scan less frequently because we should see notification */
#define	KRT_T_IFCHECK	(time_t) 60
#else	/* KRT_IFREAD_KINFO */
/* Scan often so we notice changes quickly */
#define	KRT_T_IFCHECK	(time_t) 15
#endif	/* KRT_IFREAD_KINFO */
#define	KRT_T_EXPIRE_DEFAULT	(time_t) 180

/* For parser */
#define	KRT_LIMIT_SCANTIMER	KRT_T_IFCHECK, 3600
#define	KRT_LIMIT_EXPIRE	0,900

extern time_t krt_t_expire;

/**/

#define	KRT_COUNT_UNLIMITED	((u_long) -1)

/*
 * Routes to install in flash routine
 */
#define	KRT_FLASH_INTERFACE	0	/* Only interface routes in flash */
#define	KRT_FLASH_INTERNAL	1	/* Interface and internal routes */
#define	KRT_FLASH_ALL		2	/* All routes */

#define	KRT_FLASH_DEFAULT	KRT_FLASH_INTERFACE

/*
 * Number of routes to install in the flash routine
 */
#define	KRT_MIN_FLASH_INSTALL_COUNT	0
#define	KRT_MAX_FLASH_INSTALL_COUNT	KRT_COUNT_UNLIMITED
#define	KRT_LIMIT_FLASH		KRT_MIN_FLASH_INSTALL_COUNT, (u_int) KRT_MAX_FLASH_INSTALL_COUNT
#define	KRT_DEF_FLASH_INSTALL_COUNT	20

/*
 * Priority for the background job
 */
#define	KRT_INSTALL_PRIO_LOW	0	/* Low priority */
#define	KRT_INSTALL_PRIO_FLASH	1	/* Flash priority */
#define	KRT_INSTALL_PRIO_HIGH	2	/* High priority */

#define	KRT_INSTALL_PRIO_DEFAULT	KRT_INSTALL_PRIO_LOW

/*
 * Number of routes to install at a shot in background
 */
#define	KRT_MIN_INSTALL_COUNT	1
#define	KRT_MAX_INSTALL_COUNT	KRT_COUNT_UNLIMITED
#define	KRT_LIMIT_INSTALL	KRT_MIN_INSTALL_COUNT, (u_int) KRT_MAX_INSTALL_COUNT
#define	KRT_DEF_INSTALL_COUNT	120

extern int krt_flash_routes;	
extern u_long krt_flash_install_count;
extern int krt_install_priority;
extern u_long krt_install_count;

#define	KRT_LIMIT_ROUTES	0, (u_int) KRT_COUNT_UNLIMITED

extern u_long krt_limit_routes;	/* Maximum number of routes allowed in kernel */

/*
 * Krt options
 */
#define	KRT_OPT_NOCHANGE	BIT(0x01)	/* Always do delete/add's */
#define	KRT_OPT_NOFLUSH		BIT(0x02)	/* Don't flush at termination */
#define	KRT_OPT_NOINSTALL	BIT(0x04)	/* Don't install routes in kernel */

extern flag_t krt_options;

/**/

/* Kernel routing table interface */

typedef struct _krt_parms {
    proto_t krtp_protocol;
    flag_t krtp_state;
#ifdef	IP_MULTICAST_ROUTING
    pref_t krtp_preference;
    metric_t krtp_metric;
#endif	/* IP_MULTICAST_ROUTING */
    int krtp_n_gw;
    sockaddr_un **krtp_routers;
#define krtp_router     krtp_routers[0]
    if_addr **krtp_ifaps;
#define krtp_ifap       krtp_ifaps[0]
#ifdef IPSEC
	sockaddr_un *krtp_tunnel;
	u_char  krtp_fwant;
	u_char  krtp_rcvalgo;
	u_char  krtp_rcvkeylen;
	time_t  krtp_rcvttl;
	struct sockaddr_key *krtp_key;
#endif

} krt_parms;


/* Tracing */

#define	TR_KRT_INDEX_PACKETS	0	/* All packets */
#define	TR_KRT_INDEX_ROUTES	1	/* Routing table changes */
#define	TR_KRT_INDEX_REDIRECT	2	/* Redirect packets we receive */
#define	TR_KRT_INDEX_INTERFACE	3	/* Interface status changes */
#define	TR_KRT_INDEX_OTHER	4	/* Anything else */

#define	TR_KRT_PACKET_ROUTE	 	TR_DETAIL_1
#define	TR_KRT_PACKET_REDIRECT		TR_DETAIL_2
#define	TR_KRT_PACKET_INTERFACE		TR_DETAIL_3
#define	TR_KRT_PACKET_OTHER		TR_DETAIL_4

#define	TR_KRT_INFO		TR_USER_1
#define	TR_KRT_REQUEST		TR_USER_2
#define	TR_KRT_REMNANTS		TR_USER_3
#define	TR_KRT_SYMBOLS		TR_USER_4
#define	TR_KRT_IFLIST		TR_USER_5

/**/

/* Prototypes */
extern void krt_family_init(void);
extern void krt_init(void);
extern void krt_var_init(void);
extern void krt_flash(rt_list *rtl);
extern void krt_delete_dst(task *, sockaddr_un *, sockaddr_un *, proto_t,
	   flag_t, int, sockaddr_un **, if_addr **);
extern krt_parms * krt_kernel_rt(rt_head *);
extern flag_t krt_state_to_flags(flag_t);
extern void krt_ifcheck(void);
#ifdef	IP_MULTICAST
void krt_multicast_add(sockaddr_un *);
void krt_multicast_delete(sockaddr_un *);
int krt_multicast_install(sockaddr_un *, sockaddr_un *);
#ifdef RTM_CHANGE
void krt_multicast_change(int, rt_parms *);
#endif
void krt_multicast_dump(task *, FILE *);
#ifndef USE_NEWMBR
void krt_generate_mrt(int, sockaddr_un *, if_addr *, sockaddr_un *);
#endif
struct source_;
struct krt_request;
int krt_request_cache(task *, struct source_ *);
int krt_delete_cache(sockaddr_un *, sockaddr_un *);
if_addr *krt_add_ipip_tunnel(if_addr *, sockaddr_un *);
#endif	/* IP_MULTICAST */
#ifdef PROTO_INET6
void krt_multicast6_add(sockaddr_un *);
void krt_multicast6_delete(sockaddr_un *group);
#endif /* PROTO_INET6 */
