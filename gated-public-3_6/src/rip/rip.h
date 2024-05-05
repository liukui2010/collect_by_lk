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


#ifdef	PROTO_RIP
/*
 * Routing Information Protocol
 *  
 * Originally derived from Xerox NS Routing Information Protocol by
 * changing 32-bit net numbers to sockaddr's and padding stuff to 32-bit
 * boundaries.
 */

#define	RIP_VERSION_0	0
#define	RIP_VERSION_1	1
#define	RIP_VERSION_2	2

struct rip_sockaddr {
    u_int16	rip_family;
    u_int16	rip_zero;
    u_int32	rip_addr;
    u_int32	rip_zero1[2];
} ;

struct rip_netinfo {
    u_int16	rip_family;
    u_int16	rip_tag;
    u_int32	rip_dest;
    u_int32	rip_dest_mask;
    u_int32	rip_router;
    u_int32	rip_metric;			/* cost of route */
};

#define RIP_METRIC_UNREACHABLE	16
#define	RIP_METRIC_SHUTDOWN	(RIP_METRIC_UNREACHABLE - 1)

#define RIP_AUTH_NUM_BYTE 16	/* Number of bytes          */
#define RIP_AUTH_NUM_LONG 4	/* Number of 32 bit words   */
				/* in a rip auth head */

#define RIP_MD5_DIGEST_LEN      16
#define RIP_MD5_MIN_KEY_ID      0
#define RIP_MD5_MAX_KEY_ID      255

typedef struct {
	time_t tr_start;            /* start time */
	time_t tr_stop;             /* stop time can be (time_t)-1 for inf. */
} rip_time_range;

typedef struct _rip_auth {
	struct _rip_auth *auth_gen_next;	/* next pointer for gen list */
	struct _rip_auth *auth_acc_next;	/* next pointer for acc list */
	u_int16 auth_type;			/* Type of authentication */
	u_int16 auth_length;			/* Length of key */
	u_int32 auth_id;			/* authentication id (key id) */
	u_int32 auth_key[RIP_AUTH_NUM_LONG];	/* Authentication */
	rip_time_range auth_generate;		/* gen during this range */
	rip_time_range auth_accept;		/* accept during this range */
} rip_auth;

typedef struct _rip_gw_auth {
	struct _rip_gw_auth *gw_auth_next;	/* next pointer	*/
	gw_entry *gw;				/* pointer to gw entry we recv
						 * from */
	rip_auth *auth;				/* Pointer to auth info we got 
						 * from this gw */
} rip_gw_auth;

struct rip_authinfo {
	u_int16	auth_family;			/* RIP_AF_AUTH */
	u_int16	auth_type;
	u_int32	auth_data[RIP_AUTH_NUM_LONG];
};

struct rip_md5info {
	u_int16		auth_family;
	u_int16		auth_type;
	u_int16		rip_packlen;
	u_int8		md5_keyid;
	u_int8		md5_authlen;
	u_int32		md5_sequence;
	u_int32		rip_zero;
	u_int32		rip_zero1;
};

struct rip_trailer {
	u_int16         auth_family;
	u_int16         auth_type;
	u_int32         auth_data[RIP_AUTH_NUM_LONG];
} ;

#define	RIP_AF_UNSPEC	0
#define	RIP_AF_INET	2
#define	RIP_AF_AUTH	0xffff

#define	RIP_AUTH_NONE	0
#define	RIP_AUTH_SIMPLE	2
#define	RIP_AUTH_MD5	3

struct rip {
    /* XXX - using bytes causes alignment problems */
    byte	rip_cmd;		/* request/response */
    byte	rip_vers;		/* protocol version # */
    u_int16	rip_zero2;		/* unused */
};

struct entryinfo {
    struct rip_sockaddr rtu_dst;
    struct rip_sockaddr rtu_router;
    u_int16	rtu_flags;
    s_int16	rtu_state;
    s_int32	rtu_timer;
    s_int32		rtu_metric;
    u_int32	rtu_int_flags;
    char rtu_int_name[IFL_NAMELEN];
};

/*
 * Packet types.
 */
#define	RIPCMD_REQUEST		1	/* want info */
#define	RIPCMD_RESPONSE		2	/* responding to request */
#define	RIPCMD_TRACEON		3	/* turn tracing on */
#define	RIPCMD_TRACEOFF		4	/* turn it off */
#define	RIPCMD_POLL		5	/* like request, but anyone answers */
#define	RIPCMD_POLLENTRY	6	/* like poll, but for entire entry */
#define	RIPCMD_MAX		7

#ifdef RIPCMDS
static const bits rip_cmd_bits[] = {
    { 0,		"Invalid" },
    { RIPCMD_REQUEST,	"Request" } ,
    { RIPCMD_RESPONSE,	"Response" },
    { RIPCMD_TRACEON,	"TraceOn" },
    { RIPCMD_TRACEOFF,	"TraceOff" },
    { RIPCMD_POLL,	"Poll" },
    { RIPCMD_POLLENTRY,	"PollEntry" },
    { 0 }
};    
#endif	/* RIPCMDS */

#define RIP_PKTSIZE	512
#define	RIP_MAXSIZE(ifap)	MIN(RIP_PKTSIZE, ifap->ifa_mtu - sizeof (struct udphdr))

#define	RIP_ADDR_MC	0xe0000009	/* 224.0.0.9 */

#define RIP_T_UPDATE	(time_t) 30
#define	RIP_T_HOLDDOWN	(time_t) 120
#define	RIP_T_FLASH	(time_t) (grand((u_int32) (RIP_T_MAX - RIP_T_MIN + 1)) + RIP_T_MIN)
#define	RIP_T_MAX	(time_t) 5
#define	RIP_T_MIN	(time_t) 1
#define	RIP_T_EXPIRE	(time_t) 180

#define RIP_PORT	520
#define	RIP_HOP		1	/* Minimum hop count when passing through */
#define	RIP_LIMIT_METRIC	RIP_HOP, RIP_METRIC_UNREACHABLE	/* For parser */
#define	RIP_MAX_ROUTES 	1 	/* Default num. of rip routes per dest */

#define	RIP_CONFIG_IN			1
#define	RIP_CONFIG_OUT			2
#define	RIP_CONFIG_METRICIN		3
#define	RIP_CONFIG_METRICOUT		4
#define	RIP_CONFIG_FLAG			5
#define	RIP_CONFIG_AUTH			6
#define	RIP_CONFIG_AUTH2		7
#define	RIP_CONFIG_MAX			8

extern flag_t rip_flags;		/* Option flags */
extern trace *rip_trace_options;	/* RIP tracing configuration */
extern metric_t rip_default_metric;	/* Default metric to use when propogating */
extern u_int rip_max_routes;            /* Max number of rip routes per dest. */
extern pref_t rip_preference;		/* Preference for RIP routes */
extern int rip_n_trusted;		/* Number of Trusted RIP gateways */
extern int rip_n_source;		/* Number of gateways to receive explicate RIP info */
extern adv_entry *rip_import_list;	/* List of nets to import and not import */
extern adv_entry *rip_export_list;	/* List of nets to export */
extern adv_entry *rip_int_policy;	/* List of interface policy */
extern gw_entry *rip_gw_list;		/* List of RIP gateways */
extern block_t rip_auth_block_index;
extern const bits rip_trace_types[];	/* List of RIP specific trace flags */
extern rip_auth *rip_auth_query;	/* Password for user queries */

/* Values for rip_flags */
#define	RIPF_ON			BIT(0x01)		/* RIP is enabled */
#define	RIPF_BROADCAST		BIT(0x02)		/* Broadcast to all interfaces */
#define	RIPF_SOURCE		BIT(0x04)		/* Source packets to our peers */
#define	RIPF_CHOOSE		BIT(0x08)		/* Broadcast if more than one interface */
#define	RIPF_NOCHECK		BIT(0x10)		/* Don't check zero fields */
#define	RIPF_FLASHDUE		BIT(0x20)		/* Flash update is due */
#define	RIPF_NOFLASH		BIT(0x40)		/* Can not do a flash update until after the next normal update */
#define	RIPF_RECONFIG		BIT(0x80)		/* Initial processing or reconfiguration */
#define	RIPF_TERMINATE		BIT(0x0100)		/* RIP is terminating */

#define	RIP_HOLDCOUNT		(RIP_T_HOLDDOWN/RIP_T_UPDATE)	/* Number of updates per holddown */

#define	RIPTF_POLL		TARGETF_USER1	/* Target has been polled */
#define	RIPTF_V2MC		TARGETF_USER2	/* Use v2 MC for this target */
#define	RIPTF_V2BC		TARGETF_USER3	/* Use v1 compatible v2 features */
#define	RIPTF_V2		(RIPTF_V2MC|RIPTF_V2BC)
#define	RIPTF_MCSET		TARGETF_USER4	/* MC has been enabled on this interface */

#define	RIP_IFPS_V2MC	IFPS_JOINMC	/* Should send V2 MC packets */
#define	RIP_IFPS_V2BC	IFPS_POLICY1	/* Should send V1 compatible V2 BC packets */
#define	RIP_IFPS_V2	(RIP_IFPS_V2MC|RIP_IFPS_V2BC)
#define	RIP_IFPS_V1	0

#define	ifa_rip_mccount	ifa_ps[RTPROTO_RIP].ips_datas[0]
#define	ifa_rip_auth	ifa_ps[RTPROTO_RIP].ips_datas[1]
#define	ifa_rip_auth2	ifa_ps[RTPROTO_RIP].ips_datas[2]
#if defined(PROTO_SNMP) && defined(MIB_RIP)
#define ifa_rip_bad_packets ifa_ps[RTPROTO_RIP].ips_datas[3]
#define ifa_rip_bad_routes ifa_ps[RTPROTO_RIP].ips_datas[4]
#define ifa_rip_triggered_updates ifa_ps[RTPROTO_RIP].ips_datas[5]
#endif	/* defined(PROTO_SNMP) && defined(MIB_RIP) */


#define	RIP_IFPS_NOMC	IFPS_KEEP1	/* Unable to enable MC on this IF */

/* Tracing */
#define	TR_RIP_INDEX_PACKETS	0	/* All packets */
#define	TR_RIP_INDEX_REQUEST	1	/* Request packets (REQUEST, POLL, POLLENTRY) */
#define	TR_RIP_INDEX_RESPONSE	2	/* Response packets (RESPONSE) */
#define	TR_RIP_INDEX_OTHER	3	/* Other packets (TRACE_ON, TRACE_OFF) */

#define	TR_RIP_DETAIL_REQUEST	TR_DETAIL_1
#define	TR_RIP_DETAIL_RESPONSE	TR_DETAIL_2
#define	TR_RIP_DETAIL_OTHER	TR_DETAIL_3

/**/
extern void rip_init(void);
extern void rip_var_init(void);
extern void rip_config_free(config_entry *);

/*
 * Some handy defines
 */
#define RIP2U32(t) ((u_int32)GA2S(t))
#define RIP_GET_IF_AUTH(i) (i) ? (rip_auth *)(i)->ifa_rip_auth : NULL
#define RIP_GET_IF_AUTH2(i) (i) ? (rip_auth *)(i)->ifa_rip_auth2 : NULL
#define RIP_TEST2LOG_WARN(g,f) BIT_TEST((g)->gw_flags, (f)) ? 0 : LOG_WARNING; \
				BIT_SET((g)->gw_flags, (f)) 

#if defined(PROTO_SNMP)
u_int rip_global_changes;
u_int rip_global_responses;

/* Protos */
extern void rip_init_mib(int);
int rip_auth_policy(config_list *);

#endif

#endif	/* PROTO_RIP */

