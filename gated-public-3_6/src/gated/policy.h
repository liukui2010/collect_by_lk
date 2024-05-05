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


/*
 *  destination mask internal stuff is for radix trie policy lists
 */
typedef struct _dest_mask_internal {
    struct _dest_mask_internal *dmi_left;	/* where to go when bit zero */
    struct _dest_mask_internal *dmi_right;	/* where to go when bit one */
    adv_entry *dmi_external;			/* external info for node */
    u_short dmi_bit;				/* bit num to test */
    u_char dmi_offset;				/* offset of byte to test */
    u_char dmi_mask;				/* mask to test bit in byte */
} dest_mask_internal;


#define	DMI_WALK(tree, dmi, external_only) \
	do { \
	    dest_mask_internal *Xstack[SOCK_MAX_ADDRESS_LEN*NBBY+1]; \
	    dest_mask_internal **Xsp = Xstack; \
	    dest_mask_internal *Xnext; \
	    (dmi) = (tree); \
	    while ((dmi)) { \
		if ((dmi)->dmi_left) { \
		    Xnext = (dmi)->dmi_left; \
		    if ((dmi)->dmi_right) { \
			*Xsp++ = (dmi)->dmi_right; \
		    } \
		} else if ((dmi)->dmi_right) { \
		    Xnext = (dmi)->dmi_right; \
		} else if (Xsp != Xstack) { \
		    Xnext = *(--Xsp); \
		} else { \
		    Xnext = (dest_mask_internal *) 0; \
		} \
		if (!(external_only) || dmi->dmi_external) do

#define	DMI_WALK_END(tree, dmi, external_only) \
		while (0); \
		(dmi) = Xnext; \
	    } \
	} while (0)
		 
#define	DMI_WALK_ALL(tree, dmi, adv) \
	do { \
	      DMI_WALK(tree, dmi, TRUE) { \
		  register adv_entry *adv = dmi->dmi_external; \
		  do {
					 
#define	DMI_WALK_ALL_END(list, dmi, adv) \
		  } while ((adv = adv->adv_next)) ; \
	      } DMI_WALK_END(tree, dmi, TRUE) ; \
	 } while (0)

/*
 *	dest/mask list entry
 */
typedef struct _dest_mask {
    flag_t dm_flags;
    flag_t dm_ribs;			/* Ribs that this route fits into */
    /* The following four must remain in this order */
#define	DMF_REFINE	BIT(0x01)	/* Mask must refine our mask */
#define	DMF_EXACT	BIT(0x02)	/* Mask must match exactly */
#define DMF_BETWEEN	BIT(0x04)	/* Mask must refine ours within the given range only */
#define	DMF_ORDERMASK	(DMF_REFINE|DMF_EXACT|DMF_BETWEEN)
#define DMF_NONCONTIG	BIT(0x08)	/* Mask is non-contiguous */
    sockaddr_un *dm_dest;
    sockaddr_un *dm_mask;
    sockaddr_un *dm_mask_lo;		/* Low end of range we'll match if using BETWEEN */
    sockaddr_un *dm_mask_hi;		/* High end of range if using BETWEEN */
    dest_mask_internal *dm_internal;	/* Internal node on tree */
} dest_mask;

typedef struct _dest_mask_list {
	struct _dest_mask_list *dml_next;
	dest_mask *dml_dm;
	byte dml_family;
} dest_mask_list;

/**/

/* Route queues */

struct _rtq_entry {
    struct _rtq_entry *rtq_forw;
    struct _rtq_entry *rtq_back;
    time_t rtq_time;
};

#define	RT_OFFSET(member)	offsetof(rt_entry, member)

#define	RTQ_RT(rtqp)	((rt_entry *) ((void_t) ((byte *) (rtqp) - RT_OFFSET(rt_rtq))))

#define	RTQ_LIST(rtq, rt) \
	do { \
		register rtq_entry *Xrtq_next = (rtq)->rtq_forw; \
		while (Xrtq_next != (rtq)) { \
		    (rt) = RTQ_RT(Xrtq_next); \
		    Xrtq_next = Xrtq_next->rtq_forw;
#define	RTQ_LIST_END(rtq, rt)	} } while (0)

#define	RTQ_MOVE(old, new) \
	do { \
	    if ((old).rtq_forw != &(old)) { \
		((new).rtq_forw = (old).rtq_forw)->rtq_back = &(new); \
		((new).rtq_back = (old).rtq_back)->rtq_forw = &(new); \
	    } else { \
		(new).rtq_forw = (new).rtq_back = &(new); \
	    } \
	    (old).rtq_forw = (old).rtq_back = &(old); \
	} while (0)

/**/

/*
 *	Structure describing a gateway
 */
typedef struct _gw_entry {
    struct _gw_entry *gw_next;
    proto_t	gw_proto;		/* Protocol of this gateway */
    sockaddr_un *gw_addr;		/* Address of this gateway */
    flag_t	gw_flags;		/* Flags for this gateway */
    task	*gw_task;	    /* The task associated with this gateway */
    as_t	gw_peer_as;		/* The AS of this gateway */
    as_t	gw_local_as;		/* The AS advertised to this gateway */
    u_int	gw_n_routes;		/* Number of routes */
    rtq_entry	gw_rtq;			/* Queue of routes we own */
#define	gw_time	gw_rtq.rtq_time	    /* Time this gateway was last heard from */
    void_t	gw_data;		/* Protocol specific */
    struct _adv_entry *gw_import;	/* What to import from this gateway */
    struct _adv_entry *gw_export;	/* What to export to this gateway */
    void (*gw_rtd_dump)(FILE *, 
		rt_entry *);		/* Routine to format data */
    void (*gw_rtd_free)(rt_entry *, 
		void_t);		/* Routine to cleanup and free */
#if defined(PROTO_SNMP) && defined(MIB_RIP)
    u_int	gw_bad_packets;		/* Bad packets received from this GW */
    u_int	gw_bad_routes;		/* Bad routes received from this GW */
    u_int    gw_last_version_received;  /* rip version of last packet from this GW */
    struct timeval gw_last_update_time; /* Last update received time for this GW */
#endif  /* PROTO_SNMP && MIB_RIP  */
#ifdef PROTO_OSPF2
    struct _ospf_ngb_t *gw_ospf;	/* Stuff needed by 0spf */
#endif 
} gw_entry;

#define	GWF_SOURCE	0x01		/* This is a source gateway */
#define	GWF_TRUSTED	0x02		/* This is a trusted gateway */
#define	GWF_ACCEPT	0x04		/* We accepted a packet from this gateway */
#define	GWF_REJECT	0x08		/* We rejected a packet from this gateway */
#define	GWF_QUERY	0x10		/* RIP query packet received */
#define	GWF_IMPORT	0x20		/* Rejected a network due to import restrictions */
#define	GWF_FORMAT	0x40		/* Packet format error */
#define	GWF_CHECKSUM	0x80		/* Bad checksum */
#define	GWF_AUXPROTO	0x100		/* This is an auxilary protocol */
#define	GWF_AUTHFAIL	0x200		/* Authentication failure */
#define	GWF_NEEDHOLD	0x400		/* This protocol requires holddowns */
#define	GWF_NOHOLD	0x800		/* This protocol (static) should not invoke holddowns */


/*
 *	Structure defining routines to use to process protocol specific data
 */
typedef struct _adv_psfunc {
				/* Routine to match data against route */
	int (*ps_rtmatch)(void_t, rt_entry *);
				/* Routine to match data against destination */
	int (*ps_dstmatch)(void_t, sockaddr_un *, void_t);
				/* Routine to compare two sets of data */
	int (*ps_compare)(void_t, void_t);
				/* Routine to display data */
	const char *(*ps_print)(void_t, int);
				/* Routine to free data */
	void (*ps_free)(adv_entry *);
} adv_psfunc;

#define	PS_FUNC(adv, func)	control_psfunc[(adv)->adv_proto]->func
#define	PS_FUNC_VALID(adv, func)	(control_psfunc[(adv)->adv_proto] && PS_FUNC(adv, func))
    
extern const adv_psfunc *control_psfunc[];


/* Description of results of a policy search */
typedef struct _adv_results {
    union {
	metric_t	resu_metric;
	void_t		resu_void;
    } res_u1;
#define	res_metric	res_u1.resu_metric
#define	res_void	res_u1.resu_void
    union {
	metric_t	resu_metric;
	pref_t		resu_preference;
    } res_u2;
#define	res_metric2	res_u2.resu_metric
#define	res_preference	res_u2.resu_preference

/* skh - this stays , valid for idrp and bgp */
 
    void_t	ps_info;	/* store protocol-specific for WHOLE trie */ 
    flag_t	res_flag;
} adv_results;


/* Description of config file info */

typedef struct _config_entry {
    struct _config_entry *config_next;
    short config_type;
    short config_priority;
    void_t config_data;
} config_entry;

#define	CONFIG_LIST(cp, list)	for (cp = list; cp; cp = cp->config_next)
#define	CONFIG_LIST_END(cp, list)


typedef struct _config_list {
    int conflist_refcount;
    config_entry *conflist_list;
    void (*conflist_free)(config_entry *);
} config_list;


#define	CONFIG_PRIO_ANY		1
#define	CONFIG_PRIO_WILD	2
#define	CONFIG_PRIO_NAME	3
#define	CONFIG_PRIO_ADDR	4
#define	CONFIG_PRIO_MAX		5

/*
 *	Structure used for all control lists.  Nested unions are used
 *	to minimize unused space.
 *
 *	adv_data can be used if neither config or result information
 *	will be stored.  this is useful if using adv's for custom dm trees.
 */
struct _adv_entry {
	struct _adv_entry *adv_next; /* Pointer to next entry in list */
	int adv_refcount;            /* Number of references */
	flag_t adv_flag;             /* Flags */
	proto_t adv_proto;           /* Protocol for this match */

	union {
		adv_results	advru_result;  /* Result of the lookup */
#define	adv_result adv_ru.advru_result
		config_list	*advru_config; /* Config list */
#define	adv_config adv_ru.advru_config
		void		*advru_data[3];
#define adv_data adv_ru.advru_data
	} adv_ru;

	struct _adv_entry *adv_list;	/* List of functions to match */

	union adv_union {
		dest_mask_list *advu_dml;
#define adv_dml adv_u.advu_dml
		gw_entry *advu_gwp;          /* Match a gateway address */
#define	adv_gwp adv_u.advu_gwp
    if_addr *advu_ifap;          /* Match an interface */
#define	adv_ifap adv_u.advu_ifap
		if_addr_entry *advu_ifn;     /* Match an interface name */
#define	adv_ifn	adv_u.advu_ifn
		if_addr_entry *advu_ifae;	   /* Match on interface address */
#define	adv_ifae	adv_u.advu_ifae
		struct _ast_entry {
			union _as_type {
				as_t advu_as;                /* Match an AS */
#define	adv_as adv_u.ast_entry.as_type.advu_as
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
				asmatch_t	*advu_aspath;      /* Match with AS path pattern */
#define	adv_aspath	adv_u.ast_entry.as_type.advu_aspath
#endif /* PROTO_ASPATHS || PROTO_MPASPATHS */
			} as_type;
#if (defined(PROTO_BGP) || defined(PROTO_MPBGP)) && defined(GATED_MEMBER)
			as_path_info *advu_asinfop;
#define adv_asinfop adv_u.ast_entry.advu_asinfop
#endif /* defined(PROTO_BGP) || defined(PROTO_MPBGP) */
		} ast_entry;
		tag_t advu_tag;              /* Match on tag */
#define	adv_tag		adv_u.advu_tag
		void_t advu_ps;			         /* Protocol specific data */
#define	adv_ps adv_u.advu_ps
	} adv_u;
};

#define	ADVF_TYPE		BIT(0x0f)	/* Type to match */
#define	ADVFT_ANY		BIT(0x00)	/* No type specified */
#define	ADVFT_GW		BIT(0x01)	/* Match gateway address */
#define	ADVFT_IFN		BIT(0x02)	/* Match on interface name */
#define	ADVFT_IFAE_UNIQUE	BIT(0x03)	/* Match on unique address */
#define	ADVFT_AS		BIT(0x04)	/* Match on AS */
#define	ADVFT_DM		BIT(0x05)	/* Match on dest/mask pair */
#define	ADVFT_ASPATH		BIT(0x06)	/* Match on AS path */
#define	ADVFT_TAG		BIT(0x07)	/* Match on tag */
#define	ADVFT_PS		BIT(0x08)	/* Match on protocol specific data */
#define	ADVFT_IFAE_LOCAL	BIT(0x09)	/* Match on local address */
#define	ADVFT_IFAE_REMOTE	BIT(0x0A)	/* Match on remote address */

#define	ADVFO_TYPE		BIT(0xf0)	/* Option type */
#define	ADVFOT_NONE		BIT(0x00)	/* No option specified */
#define	ADVFOT_METRIC		BIT(0x10)	/* Result Metric option */
#define	ADVFOT_PREFERENCE	BIT(0x20)	/* Result Preference option */
#define	ADVFOT_METRIC2		ADVFOT_PREFERENCE
#define	ADVFOT_FLAG		BIT(0x40)	/* Result Flag option */
#define	ADVFOT_CONFIG		BIT(0x80)	/* Config structure */

#define	ADVF_NO			BIT(0x1000)	/* Negative (i.e. noannounce, nolisten, nopropogate) */
#define	ADVF_FIRST		BIT(0x2000)	/* First entry in a sequence (of gateways or interfaces) */

#define	ADVF_CONT		BIT(0x4000)	/* Don't stop matching */
#define ADVFOT_METRIC3		BIT(0x8000)	/* Res has metric3 */
#define	ADVFOT_METRIC4		BIT(0xC000)	/* Res has metric4 */ 	
#define ADVF_RIB_UNICAST        BIT(0x10000)
#define ADVF_RIB_MULTICAST      BIT(0x20000)
#define ADVF_NOAGG		BIT(0x40000)
#define ADVF_USER4		BIT(0x10000000)
#define ADVF_USER3              BIT(0x20000000)
#define	ADVF_USER2		BIT(0x40000000)
#define	ADVF_USER1		BIT(0x80000000)

#define	GW_LIST(list, gwp)	for (gwp = list; gwp; gwp = gwp->gw_next)
#define	GW_LIST_END(list, gwp)

#define	ADV_LIST(list, adv)	for (adv = list; adv; adv = adv->adv_next)
#define	ADV_LIST_END(list, adv)


#define FIND_ADV_LIST_END(list, adv)	for((adv) = (list); (adv) && ((adv)->adv_next); (adv) = (adv)->adv_next)

extern unsigned int adv_n_allocated;

void control_import_dump(FILE *, int, proto_t, adv_entry *, gw_entry *);
void control_export_dump(FILE *, int, proto_t, adv_entry *, gw_entry *);
void control_entry_dump(FILE *, int, adv_entry *);
void control_dmlist_dump(FILE *, int, adv_entry *, adv_entry *, adv_entry *);
void control_interior_dump(FILE *, int,
    void (*func)(FILE *, int, proto_t, adv_entry *, gw_entry *),
    adv_entry * list);
void control_exterior_dump(FILE *, int, void (*func)(FILE *, int, proto_t,
    adv_entry *, gw_entry *), adv_entry * list);
void control_interface_dump(FILE *, int, adv_entry *list,
    void (*func)(FILE *, config_entry *));
void control_interface_import_dump(FILE *, int, adv_entry *);
void control_interface_export_dump(FILE *, int, adv_entry *);
adv_entry *control_exterior_locate(adv_entry * list, as_t as);
int import(sockaddr_un *, sockaddr_un *, adv_entry *, adv_entry *, adv_entry *,
    pref_t *, flag_t *, if_addr *, void_t);
int import_ribs(sockaddr_un *, sockaddr_un *, flag_t, adv_entry *, adv_entry *,
    adv_entry *, pref_t *, flag_t *, if_addr *, void_t);
int export(struct _rt_entry *, proto_t, adv_entry *, adv_entry *, adv_entry *,
    adv_results *);
int is_martian(sockaddr_un *, sockaddr_un *);
INLINE void martian_add(sockaddr_un *, sockaddr_un *, flag_t, flag_t);
void martian_add_ribs(sockaddr_un *, sockaddr_un *, flag_t, flag_t, flag_t);

adv_entry * adv_alloc(flag_t, proto_t);
void adv_free_list(adv_entry * adv);
void adv_cleanup(proto_t, int *, int *, gw_entry *, adv_entry **, adv_entry **,
    adv_entry **);
void adv_psfunc_add(proto_t, const adv_psfunc *);
int adv_same(adv_entry *, adv_entry *);
#ifdef	DMFEOL
adv_entry * adv_destmask_finish(adv_entry *);
#else	/* DMF_EOL */
#define	adv_destmask_finish(x)	(x)
#endif	/* DMF_EOL */
void adv_destmask_depth(adv_entry *);
void adv_set_dm(adv_entry *, dest_mask *);
void adv_dm_bit_set(adv_entry *, flag_t);
void adv_dm_bit_reset(adv_entry *, flag_t);
void adv_get_dml(adv_entry *);
byte adv_dm_bit_test(adv_entry *, flag_t);
dest_mask_internal * adv_dml_get_root(adv_entry *, byte);
dest_mask * adv_dml_get_dm(adv_entry *);
void adv_dml_set_root(adv_entry *, dest_mask_internal *, byte);
adv_entry *adv_destmask_insert(char *, adv_entry *, adv_entry *);
adv_entry *adv_destmask_match(adv_entry *, sockaddr_un *, sockaddr_un *);
adv_entry *adv_destmask_match_ribs(adv_entry *, sockaddr_un *, sockaddr_un *,
    flag_t);
adv_entry *adv_aggregate_match(adv_entry *, rt_entry *, pref_t *);
gw_entry *gw_locate(gw_entry **, proto_t, task *, as_t, as_t, sockaddr_un *,
    flag_t);
gw_entry *gw_lookup(gw_entry **, proto_t, sockaddr_un *);
gw_entry *gw_timestamp(gw_entry **, proto_t, task *, as_t, as_t, sockaddr_un *,
    flag_t);
gw_entry *gw_init(gw_entry *, proto_t, task *, as_t, as_t, sockaddr_un *,
    flag_t);
void gw_dump(FILE *, const char *, gw_entry *, proto_t);
void gw_freelist(gw_entry *);

/* Config info */
config_entry *config_alloc(int, void_t);
config_entry *config_append(config_entry *, config_entry *);
config_entry **config_resolv_ifa(adv_entry *, if_addr *, int);
config_entry **config_resolv_ifl(adv_entry *, if_link *, int);
void config_resolv_free(config_entry **, int);
config_list *config_list_alloc(config_entry *,
    void (*entry_free)(config_entry *));
void config_list_free(config_list *);
config_list *config_list_add(config_list *, config_entry *,
    void (*entry_free)(config_entry *));

config_entry **config_resolv_list(config_list *, int);

extern void policy_family_init(void);

extern const byte first_bit_set[256];

