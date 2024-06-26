/*
 * Public Release 3
 * 
 * $Id: aspath.h,v 1.11 2000/02/18 20:57:58 swright Exp $
 */

/*
 * ------------------------------------------------------------------------
 * 
 * Copyright (c) 1996,1997,1998,1999 The Regents of the University of Michigan
 * All Rights Reserved
 *  
 * Royalty-free licenses to redistribute GateD Release
 * 3 in whole or in part may be obtained by writing to:
 * 
 * 	Merit GateDaemon Project
 * 	4251 Plymouth Road, Suite C
 * 	Ann Arbor, MI 48105
 *  
 * THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE REGENTS OF THE
 * UNIVERSITY OF MICHIGAN AND MERIT DO NOT WARRANT THAT THE
 * FUNCTIONS CONTAINED IN THE SOFTWARE WILL MEET LICENSEE'S REQUIREMENTS OR
 * THAT OPERATION WILL BE UNINTERRUPTED OR ERROR FREE. The Regents of the
 * University of Michigan and Merit shall not be liable for
 * any special, indirect, incidental or consequential damages with respect
 * to any claim by Licensee or any third party arising from use of the
 * software. GateDaemon was originated and developed through release 3.0
 * by Cornell University and its collaborators.
 * 
 * Please forward bug fixes, enhancements and questions to the
 * gated mailing list: gated-people@gated.merit.edu.
 * 
 * ------------------------------------------------------------------------
 * 
 * Copyright (c) 1990,1991,1992,1993,1994,1995 by Cornell University.
 *     All rights reserved.
 * 
 * THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT
 * LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.
 * 
 * GateD is based on Kirton's EGP, UC Berkeley's routing
 * daemon	 (routed), and DCN's HELLO routing Protocol.
 * Development of GateD has been supported in part by the
 * National Science Foundation.
 * 
 * ------------------------------------------------------------------------
 * 
 * Portions of this software may fall under the following
 * copyrights:
 * 
 * Copyright (c) 1988 Regents of the University of California.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms are
 * permitted provided that the above copyright notice and
 * this paragraph are duplicated in all such forms and that
 * any documentation, advertising materials, and other
 * materials related to such distribution and use
 * acknowledge that the software was developed by the
 * University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote
 * products derived from this software without specific
 * prior written permission.  THIS SOFTWARE IS PROVIDED
 * ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * Path attributes are currently used by BGP, but are maintained
 * separately to allow other protocols which may carry the same
 * information to share this data.  In here we record AS path
 * and Origin information as well as unrecognized optional
 * transitive attributes.
 *
 * The current structure will do for BGP3 and BGP4, but a potential
 * IDRP for IP is still problematic.  The latter may require us
 * to keep track of a lot of additional shit that I didn't want
 * to think about, and there are problems dealing with things like
 * unrecognized optional transitive attributes.  Better to leave
 * this until we need it.
 *
 * To reduce the workload on malloc() and free() the variable
 * length data is stored in a fixed length data area, with 32
 * and 128 byte areas being maintained.  Longer data areas are
 * malloc()'d and free()'d as needed.
 *
 * All path attributes are sorted in ascending order by attribute
 * type code.  This allows the use of bcmp() to compare types.
 */

/*
 * This describes usage of the path_* routines.  The code maintains
 * an internal hash table of path attribute structures, and uses the
 * hash table to match up AS path structures with identical attributes
 * such that only one copy of each distinct, referenced set of path
 * attributes should exist in the path hash table.
 *
 * Note the word "referenced".  A reference count is maintained in
 * each path structure which is intended to count the number of holders
 * of a pointer to this AS path structure.  Only AS path structures
 * which are referenced (i.e. have a reference count of 1 or more) are
 * actually linked into the hash table.  An unreferenced AS path structure
 * (reference count of zero) will be linked into the hash table only when
 * its reference count is incremented, and by default it is only when
 * an AS path structure becomes referenced and is inserted in the hash
 * table that a matching referenced structures is searched for.  Thus
 * referencing an AS path structure may result in a pointer to different,
 * already-referenced structure being returned to you.
 *
 * The routine to use to decode received AS path attributes and store
 * them in a newly-allocated AS path structure is:
 *
 *    as_path *aspath_attr();
 *
 * This routine takes a byte pointer to a buffer, a buffer length, a
 * version number for the raw format and some other info about the caller,
 * allocates a structure and decodes the attribute information into that
 * structure.  Note that the structure which is returned is unreferenced.
 * It is not linked into the hash table, and it has *not* yet been
 * determined whether a structure with identical attributes already exists
 * in the table.
 *
 */

/*
 * We define a type for the hash key so that we can make the tables bigger
 * than 256 entries in the future if we want to.  However, there are plenty
 * of places which use the hash value but declare it as a byte, left over
 * from the old days.  To expand the key and table, it will be necessary to
 * fix this.
 */
typedef byte aspath_hash_key;

#define ASPATHHASHSIZE    128 /* must be power of two */
#define AS_COMM_MAX       25  /* maximum of 25 ASs */

/*
 * We embed these as the first thing in data types that may get linked in to
 * hash tables (e.g., as_path).
 */
typedef struct _aspath_hash {
  struct _aspath_hash *next;
  u_int32     id;    /* path ID, for pretty printing */
  u_int32         refcount;  /* reference count for this path */
  aspath_hash_key hash;    /* hash value for this path */
  byte      path_size; /* index into size list, 0 if malloc */
  size_t          size;      /* really size_t?  could be u_int16 too */
} aspath_hash;

/*
 * Data type for keeping local AS bit masks
 */
typedef	u_int16	aslocal_t;

/*
 * Fixed length attribute block.  Variable length data is appended to this.
 */
typedef struct _as_path {
    aspath_hash pathhash; /* hash table and memory allocation stuff */
    struct _as_path *path_next;	/* pointer to next in chain */
    u_int32 path_id;		/* path ID, for pretty printing */
    u_int32 path_refcount;	/* reference count for this path */
    u_int32 router_id;		/* router id of peer we learned from */
    aslocal_t path_looped;	/* looped local ASes */
    aslocal_t path_local_as;	/* AS of the recipient(s) of the path */
    byte path_hash;		/* hash value for this path */
    byte path_size;		/* index into size list, 0 if malloc */
    byte path_flags;		/* flags (local aggregate, atomic aggregate) */
    byte path_origin;		/* path origin type (BGP, IGP, XX) */
    u_int16 path_aggr_len;	/* Length of aggregator attribute, if any */
    u_int16 path_len;		/* length of the AS path */
    u_int16 path_seg_len;	/* length of segment descriptors */
    u_int16 path_attr_len;	/* length of unrecognized data */
} as_path;

/* Limit on specification of maximum loop count */
#define	LIMIT_AS_LOOPS		1, 10

/*
 * Structures related to multiple local ASes.  We allow the router to
 * run in a limited number of local ASes (currently 16) and identify
 * the particular local AS instance by a bit number.  This lets us
 * keep track of items such as local AS of recipients of routes, and
 * aggregators, with a minimum of fuss.
 */
#define	PATH_N_LOCAL_AS		(sizeof(aslocal_t) * NBBY)

typedef struct _as_local {
    as_t asl_as_net;		/* local AS in network order */
    as_t asl_as;		/* local AS number */
    u_int16 asl_loop;		/* the loop termination count for this AS */
    u_int16 asl_found;		/* temporary for loop termination */
} as_local;

/*
 * Macros for testing, setting and resetting local AS bits
 */
#define	AS_LOCAL_BIT(i)		(((aslocal_t)(0x01)) << (i))

#define	AS_LOCAL_TEST(aslocal, i)	(((aslocal) & AS_LOCAL_BIT(i)) != 0)

#define	AS_LOCAL_SET(aslocal, i)	((aslocal) |= AS_LOCAL_BIT(i))

#define	AS_LOCAL_RESET(aslocal, i)	((aslocal) &= (~AS_LOCAL_BIT(i)))

/*
 * For allocating and freeing an AS path attribute which was originally
 * connected to a route.  I.e. someone had better have called the path_alloc
 * routine before this.
 */
#define	ASPATH_ALLOC(asp)	((asp)->path_refcount++)

#define	ASPATH_FREE(asp) \
    do { \
	register as_path *Xasp = (asp); \
	if (Xasp->path_refcount <= 1) { \
	    aspath_unlink(Xasp); \
	} else { \
	    Xasp->path_refcount--; \
	} \
    } while (0)

/*
 * Origin codes (these should match the BGP codes for versions 2-4!)
 */
#define	PATH_ORG_IGP		0	/* route learned from IGP */
#define	PATH_ORG_EGP		1	/* route learned from EGP */
#define	PATH_ORG_XX		2	/* god only knows */

/* needed by asmatch.[hc] */
extern bits path_Orgs[];

/* needed to walk aspaths */
extern as_path *path_list[]; 


/*
 * Path flags (only a few of these)
 */
#define	PATH_FLAG_LOCAL_AGG	0x01	/* path created by local aggregation */
#define	PATH_FLAG_ATOMIC_AGG	0x02	/* atomic aggregate was/should be set */
/* N.B. only bits above included in the hash */
#define	PATH_FLAG_ASLOOP	0x80	/* path has AS loop, not for BGP3 */

/*
 * Macros for scanning the AS paths we have.
 */
#define ASPATH_LIST(asp) \
    do { \
        int Xi; \
        as_path *Xasp; \
        for (Xi = 0; Xi < PATHHASHSIZE; Xi++) { \
            if (!(Xasp = path_list[Xi])) { \
                continue; \
            } \
            do { \
                (asp) = Xasp; \
                Xasp = Xasp->path_next; do

#define ASPATH_LIST_END(asp) \
                while (0); \
            } while (Xasp); \
        } \
    } while (0)

/*
 * Template for an attribute block with data
 */
typedef struct _as_path_data {
    as_path aspd_info;
    union {
    	u_short Xaspd_short_data[2];
	byte Xaspd_data[4];
    } aspd_Xdata;
#define	aspd_data	aspd_Xdata.Xaspd_data
#define	aspd_short_data	aspd_Xdata.Xaspd_short_data
} as_path_data;


/*
 * Fetch pointers to the AS path, segment and attribute data
 */
#define	PATH_PTR(asp) \
    (&(((as_path_data *)(asp))->aspd_data[0]))
#define	PATH_SHORT_PTR(asp) \
    (&(((as_path_data *)(asp))->aspd_short_data[0]))
#define	PATH_SEG_PTR(asp) \
    (&(((as_path_data *)(asp))->aspd_short_data[((asp)->path_len) >> 1]))
#define	PATH_ATTR_PTR(asp) \
  (&(((as_path_data *)(asp))->aspd_data[(asp)->path_len + (asp)->path_seg_len]))

/*
 * Compare path attributes to see if they are the same
 */
#define	PATH_SAME(asp1, asp2) \
    (  ((asp1)->path_origin == (asp2)->path_origin) \
     && ((asp1)->path_len == (asp2)->path_len) \
     && ((asp1)->path_seg_len == (asp2)->path_seg_len) \
     && ((asp1)->path_attr_len == (asp2)->path_attr_len) \
     && ((asp1)->path_aggr_len == (asp2)->path_aggr_len) \
     && ((asp1)->path_local_as == (asp2)->path_local_as) \
     && ((asp1)->path_aggr_len == (asp2)->path_aggr_len) \
     && ((asp1)->path_flags == (asp2)->path_flags) \
     && ((((asp1)->path_len + (asp1)->path_seg_len \
       + (asp1)->path_attr_len) == 0) \
     || (bcmp((caddr_t) PATH_PTR((asp1)), (caddr_t) PATH_PTR((asp2)), \
	      (size_t)((asp1)->path_len+(asp1)->path_seg_len \
		+(asp1)->path_attr_len)) == 0)))

/*
 * The size of the path hash index.  asp->path_hash above will be a value
 * between 0 and PATHHASHSIZE-1, inclusive.
 */
#define	PATHHASHSIZE	128

/*
 * A structure to hold non-transitive AS path info which is of interest.
 * This is used for passing such info back and forth when encoding or
 * decoding AS paths.
 */
typedef struct _as_path_info {
    flag_t api_flags;
    sockaddr_un *api_nexthop;
    metric_t api_metric;
    metric_t api_localpref;
    u_int32 api_localid;
#if defined(PROTO_BGP4MP) || defined(PROTO_MPBGP)
  byte *    api_mpunreach_nlri;  /* multipoint unreachable addrs */
  byte *    api_mpreach_nlri;    /* multipoint reachable addrs */
#endif
} as_path_info;

#ifdef  PROTO_INET6
#define API_NULL { 0, NULL, 0, 0, 0, NULL, NULL }
#else
#define API_NULL { 0, NULL, 0, 0, 0 }
#endif  /* PROTO_INET6 */



/*
 * Data type for walking the path_list from outside
 */
typedef struct _pathwalk_t {
    struct _pathwalk_t *pw_forw;
    struct _pathwalk_t *pw_back;
    as_path *curr_asp;
   int curr_entry;
} pathwalk_t;

/*
 * Flag definitions for the above.
 */
#define	APIF_UNREACH		0x1	/* unreachable attribute present */
#define	APIF_NEXTHOP		0x2	/* next hop present */
#define	APIF_METRIC		0x4	/* metric present */
#define	APIF_LOCALPREF		0x8	/* local preference present */

#define	APIF_INTERNAL		0x100	/* internal BGP AS path discipline */
#define	APIF_LOCALID		0x200	/* local router ID included */


/*
 * A structure to keep track of the paths attached to an aggregate.
 */
typedef struct _as_path_list {
    struct _as_path_list *apl_next;	/* Next path in the list */
    as_path *apl_asp;			/* The AS path in question */
    u_int apl_refcount;			/* Number of routes in list with path */
} as_path_list;


/*
 * Definitions for decoding path attributes.  These come from
 * the BGP protocol definition, RFC1163.
 *
 * Each attribute consists of a flag byte, followed by an attribute
 * type code, followed by a one- or two-byte length, followed by
 * the data.
 */

/*
 * Bit definitions for the attribute flags byte
 */
#define	PA_FLAG_OPT	0x80	/* attribute is optional */
#define	PA_FLAG_TRANS	0x40	/* attribute is transitive */
#define	PA_FLAG_PARTIAL	0x20	/* incomplete optional, transitive attribute */
#define	PA_FLAG_EXTLEN	0x10	/* extended length flag */

#define	PA_FLAG_ALL  (PA_FLAG_OPT|PA_FLAG_TRANS|PA_FLAG_PARTIAL|PA_FLAG_EXTLEN)
#define	PA_FLAG_OPTTRANS	(PA_FLAG_OPT|PA_FLAG_TRANS)


/*
 * BGP version 2/3 attribute type codes we know about
 */
#define	PA_TYPE_INVALID		0
#define	PA_TYPE_ORIGIN		1
#define	PA_TYPE_ASPATH		2
#define	PA_TYPE_NEXTHOP		3
#define	PA_TYPE_UNREACH		4
#define	PA_TYPE_METRIC		5
#define	PA_MAXTYPE		5	/* highest known type code */

/*
 * Lengths for a few of the attributes (the fixed length ones)
 */
#define	PA_LEN_ORIGIN		1
#define	PA_LEN_NEXTHOP		4
#define	PA_LEN_UNREACH		0
#define	PA_LEN_METRIC		2
#define	PA_LEN_AS		2
#if defined(PROTO_INET6) || defined(PROTO_MPBGP)
#define PA4_LEN_MPREACHNLRI_OLD 7 /* length for old draft */
#define PA4_LEN_MPUNREACHNLRI_OLD 5 /* length for old draft */
#define PA4_LEN_MPREACHNLRI 5 /* family(2)+subfamily(1)+NHlen(1)+#snpa(1) */
#define PA4_LEN_MPUNRNLRI 3 /* family(2) + subfamily(1) */
#endif /* PROTO_INET6 */

/*
 * BGP version 4 attribute type codes (the dorks moved metric!).
 */
#define	PA4_TYPE_INVALID	0
#define	PA4_TYPE_ORIGIN		1
#define	PA4_TYPE_ASPATH		2
#define	PA4_TYPE_NEXTHOP	3
#define	PA4_TYPE_METRIC		4
#define	PA4_TYPE_LOCALPREF	5
#define	PA4_TYPE_ATOMICAGG	6
#define	PA4_TYPE_AGGREGATOR	7
#define PA4_TYPE_COMMUNITY      8
#define PA4_TYPE_ORIGINATOR_ID	9
#define PA4_TYPE_CLUSTER_LIST	10
#define PA4_TYPE_DPA            11
#define PA4_TYPE_ADVERTISER	12
#define PA4_TYPE_RCID_PATH	13
#define PA4_TYPE_MPREACHNLRI    14
#define PA4_TYPE_MPUNRNLRI      15
#define PA4_MAXTYPE             15

#if defined(PROTO_MPBGP) || defined(PROTO_BGP4MP)
#define PA4_TYPE_MPREACHNLRI    14
#define PA4_TYPE_MPUNREACHNLRI  15
 
#define PA4MP_SAFI_RESERVED    0 /* Don't touch! */
#define PA4MP_SAFI_UNI         1 /* Subsequent Addr. Family ID for unicast */
#define PA4MP_SAFI_MULTI       2 /* SAFI for multicast NLRI */ 
#define PA4MP_SAFI_UNI_MULTI   3 /* SAFI for both uni and multicast NLRI */
#define PA4MP_SAFI_UNI_MAX     3 /* Maximum valid safi value */
                                 /* RFC allows vendor specificuse of 129-255 */
 
#define PA4_MP_BUMP             0x100
#define PA4_MP_MASK             0xff
#endif


/*
 * BGP4 subcodes for the AS_PATH attribute
 */
#define	PA_PATH_NOTSETORSEQ	0	/* not a valid path type */
#define	PA_PATH_SET		1
#define	PA_PATH_SEQ		2
#define	PA_PATH_MAXSEGLEN	255	/* maximum segment length */

/*
 * Lengths for a few of the version 4 attributes (the fixed length ones)
 */
#define	PA4_LEN_ORIGIN		1
#define	PA4_LEN_NEXTHOP		4
#define	PA4_LEN_UNREACH		0
#define	PA4_LEN_METRIC		4
#define	PA4_LEN_LOCALPREF	4
#define	PA4_LEN_ATOMICAGG	0
#define	PA4_LEN_AGGREGATOR	6
#define PA4_LEN_COMMUNITY       0
#define PA4_LEN_ORIGINATOR_ID 4
#define PA4_LEN_COMM_MIN	4
#define PA4_LEN_COMM_AS		4	        /* length of Communities */ 
#define PA4_LEN_COMM_MAX	4*AS_COMM_MAX	/* total length of COMsM */ 
#define PA4_LEN_DPA             6
#if defined(PROTO_INET6)
#define PA4_LEN_MPREACHNLRI_OLD	7 /* length for old draft */
#define PA4_LEN_MPUNRNLRI_OLD	5 /* length for old draft */
#define PA4_LEN_MPREACHNLRI	5 /* family(2)+subfamily(1)+NHlen(1)+#snpa(1) */
#define PA4_LEN_MPUNRNLRI	3 /* family(2) + subfamily(1) */
#endif /* PROTO_INET6 */

#define	PA4_LEN_SEGMENT		2

/*
 * Path segment descriptors.  These contain an indication of whether
 * the segment is an AS_SEQUENCE or an AS_SET, and an offset into
 * the AS array.
 */
#define	PATH_AS_SET		0x8000
#define	PATH_SEG_LEN(x)		((x) & 0x3fff)
#define	PATH_ISSEQUENCE(x)	(((x) & PATH_AS_SET) == 0)
#define	PATH_ISSET(x)		(((x) & PATH_AS_SET) != 0)

/*
 * Version specifier for path attributes
 */
#define	PATH_VERSION_2OR3	1	/* version 2/3 format */
#define	PATH_VERSION_4		2	/* version 4 format */
#define	PATH_OKAY_VERSION(v) \
	((v) == PATH_VERSION_2OR3 || (v) == PATH_VERSION_4)

/*
 * Path error codes.  These are essentially the UPDATE subcodes from
 * the BGP spec.  BGP knows this.
 */
#define	PA_ERR_MALFORMED	1	/* Malformed attribute list */
#define	PA_ERR_UNKNOWN		2	/* Unknown well-known attribute */
#define	PA_ERR_MISSING		3	/* Missing well-known attribute */
#define	PA_ERR_FLAGS		4	/* Flags in error */
#define	PA_ERR_LENGTH		5	/* Goofy length */
#define	PA_ERR_ORIGIN		6	/* Unrecognized ORIGIN attr */
#define	PA_ERR_ASLOOP		7	/* AS appeared twice in path */
#define	PA_ERR_NEXTHOP		8	/* NEXTHOP screwed up */
#define	PA_ERR_OPTION		9	/* optional attribute error */
#define	PA_ERR_NETWORK		10	/* network field screwed */
#define	PA_ERR_ASPATH		11	/* Malformed AS_PATH **BGP4 ONLY** */

/*
 * Length of fields making up a path attribute.
 */
#define PA_LEN_FLAGS		1 	/* Length of path attribute flags */
#define PA_LEN_TYPE		1 	/* Length of path attribute type */
#define PA_LEN_LEN		1 	/* Length of path attribute length */
#define PA_LEN_ELEN		2 	/* Length of path attribute extended length */

/*
 * Macro for retrieving attribute information from a byte stream
 */
#define	GET_PATH_ATTR(flags, code, len, cp) \
    do { \
        register u_int Xtmp; \
        Xtmp = (u_int)(*(cp)++); \
        (flags) = Xtmp & ~((u_int)(PA_FLAG_EXTLEN)); \
        (code) = *(cp)++; \
        if (Xtmp & PA_FLAG_EXTLEN) { \
	    Xtmp = (int)((*(cp)++) << 8); \
	    Xtmp |= (int)(*(cp)++); \
	    (len) = Xtmp; \
	} else { \
	     (len) = (*(cp)++); \
	} \
    } while (0)

/*
 * Macro for determining the full length of an attribute given
 * the length of the data portion.
 */
#define	PATH_ATTR_LEN(len)	(((len) > 255) ? ((len)+4) : ((len)+3))

/*
 * Macro for determining the minimum length of an attribute given
 * the flags field.
 */
#define	PATH_ATTR_MINLEN(flags)	(((flags) & PA_FLAG_EXTLEN) ? 4 : 3)

/*
 * Macro for skipping over total attributes length field.
 */
#define	PATH_ATTR_TOTAL_LEN_SIZE	(2)
#define	PATH_ATTR_SKIP_LEN(cp)	((cp) += PATH_ATTR_TOTAL_LEN_SIZE)

/*
 * Macro for fetching an AS from a message.
 */
#define	PATH_GET_AS(as, cp) \
    do { \
	register u_short Xtmp; \
	Xtmp = (*(cp)++) << 8; \
	Xtmp |= (*(cp)++) & 0xff; \
	(as) = (as_t)Xtmp; \
    } while (0)

/*
 * Macro for writing an AS into the message.
 */
#define	PATH_PUT_AS(as, cp) \
    do { \
	register u_short Xtmp = (u_short)(as); \
	*(cp)++ = Xtmp >> 8; \
	*(cp)++ = Xtmp & 0xff; \
    } while (0)

/*
 * Writing a metric into the message
 */
#define	PATH_PUT_METRIC(metric, cp) \
    do { \
	register u_int16 Xtmp = (u_int16)(metric); \
	*(cp)++ = Xtmp >> 8; \
	*(cp)++ = Xtmp & 0xff; \
    } while (0)

/*
 * Fetching a version 4 metric from the attributes
 */
#define	PATH_GET_V4_METRIC(metric, cp) \
    do { \
	register u_int32 Xmet; \
	Xmet = ((u_int32) *(cp)++) << 24; \
	Xmet |= ((u_int32) *(cp)++) << 16; \
	Xmet |= ((u_int32) *(cp)++) << 8; \
	Xmet |= *(cp)++; \
	(metric) = Xmet; \
    } while (0)

/*
 * Writing a version 4 metric into the message
 */
#define	PATH_PUT_V4_METRIC(metric, cp) \
    do { \
	register u_int32 Xtmp = (u_int32)(metric); \
	*(cp)++ = Xtmp >> 24; \
	*(cp)++ = Xtmp >> 16; \
	*(cp)++ = Xtmp >> 8; \
	*(cp)++ = Xtmp; \
    } while (0)

/*
 * Writing an ID into a message
 */
#define	PATH_PUT_ID(id, cp) \
    do { \
	u_int32 Xid = (id); \
	byte *Xidp = (byte *)&Xid; \
	*(cp)++ = *Xidp++; \
	*(cp)++ = *Xidp++; \
	*(cp)++ = *Xidp++; \
	*(cp)++ = *Xidp++; \
    } while (0)

/*
 * Writing a next hop into the message.
 */
#define	PATH_PUT_NEXTHOP(nexthop, cp) \
    do { \
	register byte *Xhp = (byte *)&sock2ip(nexthop); \
	*(cp)++ = *Xhp++; \
	*(cp)++ = *Xhp++; \
	*(cp)++ = *Xhp++; \
	*(cp)++ = *Xhp++; \
    } while (0);

/*
 * Macro for inserting a path attribute header into a buffer.  The
 * extended length bit is set in the flag as appropriate.
 */
#define	PATH_PUT_ATTR(flag, code, len, cp) \
    do { \
        register u_int Xtmp; \
        Xtmp = (len); \
        if (Xtmp > 255) { \
	    *(cp)++ = (byte)((flag) | PA_FLAG_EXTLEN); \
	    *(cp)++ = (byte)(code); \
	    *(cp)++ = (byte) (Xtmp >> 8); \
	    *(cp)++ = (byte) Xtmp; \
	} else { \
	    *(cp)++ = (byte)((flag) & ~((u_int)(PA_FLAG_EXTLEN))); \
	    *(cp)++ = (byte)(code); \
	    *(cp)++ = (byte) Xtmp; \
	} \
    } while (0)

/*
 * Protocol-specific attribute-related processing
 */

/*
 * OSPF uses a tag format which can be translated as path attributes.
 * We maintain a knowlege of this here since this is about the only
 * place which needs to understand this.
 */
#define	PATH_OSPF_TAG_TRUSTED	0x80000000	/* tag set to standard format */
#define	PATH_OSPF_TAG_COMPLETE	0x40000000	/* attributes are complete */

#define	PATH_OSPF_TAG_LEN_MASK	0x30000000	/* mask for the path length */
#define	PATH_OSPF_TAG_LEN_0	  0x00000000	/* zero length path */
#define	PATH_OSPF_TAG_LEN_1	  0x10000000	/* path length 1 */
#define	PATH_OSPF_TAG_LEN_2	  0x20000000	/* path length 2 */
#define	PATH_OSPF_TAG_LEN_X	  0x30000000	/* invalid */

#define	PATH_OSPF_TAG_USR_MASK	0x0fff0000	/* arbitrary user bits */
#define	PATH_OSPF_TAG_USR_SHIFT	16		/* shift to normalize user */
#define	PATH_OSPF_TAG_AS_MASK	0x0000ffff	/* mask for AS */
#define	PATH_OSPF_TAG_USR_LIMIT	0, (u_int) (PATH_OSPF_TAG_USR_MASK >> PATH_OSPF_TAG_USR_SHIFT)
#define	PATH_OSPF_TAG_LIMIT	0, ~PATH_OSPF_TAG_TRUSTED
#define PATH_RIPNG_TAG_LIMIT  1, 65535  /* ripng tag is 16 bit value */
#define PATH_OSPF_ISTRUSTED(tag)	(((tag) & PATH_OSPF_TAG_TRUSTED) != 0)
#define	PATH_OSPF_ISCOMPLETE(tag)	(((tag) & PATH_OSPF_TAG_COMPLETE) != 0)


/*
 * Entries into the path module
 */
extern void aspath_init(void);
extern void aspath_family_init(void);
extern void aspath_dump(FILE *, as_path *, const char *, const char *);
extern void aspath_trace(trace *, const char *, int, byte *, int);
extern as_path * aspath_alloc(size_t);
extern as_path * aspath_insert(as_path *);
extern void aspath_rt_free(rt_entry *);
extern void aspath_unlink(as_path *);
extern void aspath_rt_build(rt_entry *, as_path *);

#ifdef	PROTO_OSPF
extern u_long aspath_tag_ospf(as_t, rt_entry *, metric_t);
extern char * aspath_tag_dump(as_t, u_long);
#endif	/* PROTO_OSPF */
#ifdef	PROTO_BGP
extern int aspath_adv_ibgp(as_t, proto_t, rt_entry *);
#endif	/* PROTO_BGP */
extern void aspath_free(as_path *);
as_path * aspath_find(as_path *);
extern byte * aspath_format(as_t, as_path *, as_path_info *, byte **, byte *);
extern byte * aspath_format_v4(as_t, as_path *, as_path_info *, byte **,
    byte *);
extern size_t aspath_v4_estimate_len(as_t, as_path *, as_path_info *);
extern int aspath_prefer(rt_entry *, rt_entry *);
extern int aspath_aggregate_changed(rt_aggr_head *, as_path *, as_path *);
extern as_path * aspath_do_aggregation(rt_aggr_head *);
void aspath_aggregate_free(rt_aggr_head *);
void aspath_list_dump(FILE *, rt_aggr_head *);
as_path * aspath_create(as_t);

/* Local AS processing */
extern void aslocal_set(as_t, size_t);
extern int aslocal_bit(as_t);

/* Tag support */
extern tag_t tag_rt(rt_entry *);

#ifdef  PROTO_INET6 /* HITACHI_INET6 */
byte * aspath_mp_reachable_format(size_t, as_path_info *, byte **, byte *,
    int);

size_t aspath_mp_reach_estimate_len(as_path_info *, int);

size_t aspath_zap_mp_attr(as_path *, as_path_info *, size_t, int);

#endif  /* PROTO_INET6 */
