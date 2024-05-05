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


/* defs.h
 *
 * Compiler switches and miscellaneous definitions.
 */

#if	!defined(__STDC__) && !defined(volatile)
#define	volatile
#endif	/* !defined(__STDC__) && !defined(volatile) */

#if	defined(__STRICT_ANSI__) || !defined(__GNUC__)
#define	INLINE
#if	defined(__NetBSD__)
#undef	ntohl
#undef	ntohs
#undef	htonl
#undef	htons
#endif
#else
#define INLINE __inline__
#endif

#ifndef LINE_MAX 
#ifdef  _POSIX2_LINE_MAX
#define LINE_MAX        _POSIX2_LINE_MAX
#else   /* _POSIX2_LINE_MAX */
#define LINE_MAX        256
#endif
#endif  /* LINE_MAX */

#ifdef NetBSD
#if NetBSD >= 199712 && _MACHINE == sparc
#undef NTOHL
#undef NTOHS
#undef HTONL
#undef HTONS
#endif
#endif

#ifdef HAVE_AIX
#undef NTOHL
#undef NTOHS
#undef HTONL
#undef HTONS
#endif

#ifndef WORDS_BIGENDIAN
#if     !defined(NTOHL)
#define NTOHL(x)        ((x) = ntohl(x))
#define NTOHS(x)        ((x) = ntohs(x))
#define HTONL(x)        ((x) = htonl(x))
#define HTONS(x)        ((x) = htons(x))
#endif  /* !defined(NTOHL) */
#define GNTOHL(x)       NTOHL(x)
#define GNTOHS(x)       NTOHS(x)
#define GHTONL(x)       HTONL(x)
#define GHTONS(x)       HTONS(x)
#else   /* WORDS_BIGENDIAN */
#if     !defined(NTOHL)
#define NTOHL(x)        (x)
#define NTOHS(x)        (x)
#define HTONL(x)        (x)
#define HTONS(x)        (x)
#endif  /* !defined(NTOHL) */
#define GNTOHL(x)	(x)
#define GNTOHS(x)	(x)
#define GHTONL(x)	(x)
#define GHTONS(x)	(x)
#endif  /* WORDS_BIGENDIAN */

#define GS2A(x) ((void_t)(u_long)(x))
#define GA2S(x) ((u_long)(void_t)(x))

#define PID_T   pid_t

/* Common types */

typedef	U_INT8	u_int8;
typedef	S_INT8	s_int8;
typedef	U_INT16	u_int16;
typedef	S_INT16	s_int16;
typedef	S_INT32	s_int32;
#ifdef	U_INT64
typedef	U_INT64	u_int64;
#endif	/* u_int64 */
#ifdef	S_INT64
typedef	S_INT64	s_int64;
#endif	/* S_INT64 */

typedef u_int16 as_t;		/* 16 bits unsigned */
typedef s_int32 pref_t;		/* 32 bits signed */
typedef u_int32 flag_t;		/* 32 bits unsigned */
typedef u_int16 proto_t;	/* 16 bits unsigned */
typedef u_int16 mtu_t;		/* 16 bits unsigned */
typedef u_int32 metric_t;	/* 32 bits unsigned */
typedef	u_int32 tag_t;		/* 32 bits unsigned */
#ifdef	notdef
typedef int asmatch_t;		/* Temporary for now */
#endif
typedef        VOID_T  void_t;

#ifndef byte
#define byte u_char
#endif

typedef	struct _if_link if_link;
typedef struct _if_info if_info;
typedef	struct _if_addr if_addr;
typedef struct _if_addr_entry if_addr_entry;
typedef struct _rt_head rt_head;
typedef struct _rt_entry rt_entry;
typedef struct _rt_aggr_head rt_aggr_head;
typedef struct _rt_list rt_list;
typedef struct _rtq_entry rtq_entry;
typedef struct _task task;
typedef struct _task_timer task_timer;
typedef struct _task_job task_job;
typedef struct _adv_entry adv_entry;
typedef struct task_block *block_t;
typedef struct _trace trace;
typedef struct _trace_file trace_file;

/* Gated uses it's own version of *printf */
#define	fprintf	gd_fprintf
#define	sprintf	gd_sprintf
#define	vsprintf	gd_vsprintf

extern const char *gated_version;
extern const char *build_date;

/* general definitions for GATED user process */

#ifndef	TRUE
#define TRUE	 1
#define FALSE	 0
#endif	/* TRUE */

#ifndef NULL
#define NULL	 0
#endif

#define MAXHOSTNAMELENGTH 64		/*used in init_egpngh & rt_dumb_init*/

#undef  MAXPACKETSIZE

#ifndef	MIN
#define	MIN(a, b)	((a) < (b) ? (a) : (b))
#endif	/* MIN */
#ifndef	MAX
#define	MAX(a, b)	((a) > (b) ? (a) : (b))
#endif	/* MAX */
#ifndef	ABS
#define	ABS(a)		((a) < 0 ? -(a) : (a))
#endif	/* ABS */

/* how many things of y size to hold x */
#define	HOWMANY(x,y)	(((x) + ((y) - 1)) / (y))
/* x rounded up to the nearest y */
/*
 * for now don't want to redefine the power of 2 one without changing code..
 * don't want to lose the optimization
 */
/* #define	ROUNDUP(x,y)	(HOWMANY(x,y) * (y)) */

#ifdef	__STDC__
#define	BIT(b)	b ## ul
#define	STRINGIFY(s)	#s
#else	/* __STDC__ */
#define	BIT(b)	b
#define	STRINGIFY(s)	"s"
#endif	/* __STDC__ */
#define	BIT_SET(f, b)	((f) |= b)
#define	BIT_RESET(f, b)	((f) &= ~(b))
#define	BIT_FLIP(f, b)	((f) ^= (b))
#define	BIT_TEST(f, b)	((f) & (b))
#define	BIT_MATCH(f, b)	(((f) & (b)) == (b))
#define	BIT_COMPARE(f, b1, b2)	(((f) & (b1)) == b2)
#define	BIT_MASK_MATCH(f, g, b)	(!(((f) ^ (g)) & (b)))

#ifndef	offsetof
#ifdef	__HIGHC__
#define	offsetof(type, member) _offsetof(type, member)
#else	/* __HIGHC__ */
#define offsetof(type, member) ((size_t) &((type *)0)->member)
#endif	/* __HIGHC__ */
#endif	/* offsetof */

#ifdef HAVE_RADIX_NODE_HEAD
# define VARIABLE_MASKS
#else
# ifdef USE_IRE_DEFAULT
#  define VARIABLE_MASKS
# endif
#endif

#define	ROUNDUP(a, size) (((a) & ((size)-1)) ? (1 + ((a) | ((size)-1))) : (a))

#ifdef VXWORKS
/* On some platforms (e.g. vxWorks) time_t is "unsigned long".
 * The original GateD DIFFTIME() macro works properly over all inputs
 * only when time_t is a signed quantity.  Thus the original
 * DIFFTIME() macro doesn't work properly on vxWorks.
 * Fortunately vxWorks supports the ISO-C "difftime()" function,
 * which returns a "double" and hence preserves the appropriate sign
 * of the difftime result.
 * Hence on vxWorks DIFFTIME() just calls difftime().
 * For more information on difftime() see section 18.5 (page 402)
 * of "C, a reference manual", fourth edition, by Samuel P. Harbison
 * and Guy L. Steele Jr.  ISBN 0-13-326224-3
 */
#define DIFFTIME(t1, t0)	difftime(t1, t0)
#else
#define DIFFTIME(t1, t0)	((t1 >= t0) ? (t1 - t0) : -(t0 - t1))
#endif /* VXWORKS */

/* Error message defines */

#ifndef	errno
extern int errno;
#endif	/* errno */

/*
 *	Definitions of descriptions of bits
 */

typedef struct {
    u_int t_bits;
    const char *t_name;
} bits;


/* Our version of assert */
#define assert(ex) do { \
    if (!(ex)) { \
	task_assert(__FILE__, __LINE__, STRINGIFY(ex)); \
    } \
} while(0)


/*
 *	Routines defined in grand.c
 */
extern void grand_seed(u_int32);
extern u_int32 grand(u_int32);
extern u_int32 grand_log2(int);
/*
 *	Routines defined in checksum.c
 */
extern u_int16 inet_cksumv(struct iovec *v, int, size_t);
extern u_int16 inet_cksum(void_t, size_t);
#ifdef	FLETCHER_CHECKSUM
extern u_int32 iso_cksum(void_t, size_t, byte *);
#endif	/* FLETCHER_CHECKSUM */
#ifdef	MD5_CHECKSUM
extern void md5_cksum(void_t, size_t, size_t, void_t, u_int32 *);
extern size_t md5_cksum_partial(void_t, void_t, int, u_int32 *);
#endif	/* MD5_CHEKCSUM */

/**/


/* Our versions of INSQUE/REMQUE */

/* The structure */
typedef struct _qelement {
    struct _qelement *q_forw;
    struct _qelement *q_back;
} *qelement;


#ifndef	INSQUE
/* Define INSQUE/REMQUE if not already defined (as maybe assembler code) */
#define INSQUE(elem, pred) { \
				 register qelement Xe = (qelement) (elem); \
				 register qelement Xp = (qelement) (pred); \
				 Xp->q_forw = (Xe->q_forw = (Xe->q_back = Xp)->q_forw)->q_back = Xe; \
			      }

#define	REMQUE(elem)	{ \
    			     register qelement Xe = (qelement) elem; \
			     (Xe->q_back->q_forw = Xe->q_forw)->q_back = Xe->q_back; \
			 }
#endif	/* INSQUE */

/* For now lets assume that the overhead of being non-interruptable is minimal*/
#define NON_INTR(rc, syscall)	while ((rc = (syscall)) == -1 && errno == EINTR)

