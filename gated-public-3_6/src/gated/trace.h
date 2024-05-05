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
 * trace.h
 */

#define	TRACE_LIMIT_FILE_SIZE	(u_int) 10*1024, (u_int) -1
#define	TRACE_LIMIT_FILE_COUNT	2, (u_int) -1

/*
 * Tracing structures
 */

struct _trace_file {
    struct _trace_file *trf_forw;
    struct _trace_file *trf_back;
    FILE *trf_FILE;		/* FILE pointer we use */
    char *trf_file;		/* File name we have open */
    off_t trf_size;		/* Size of current trace file */
    off_t trf_limit_size;	/* Maximum desired file size */
    u_int trf_limit_files;	/* Maximum number of files desired */
    flag_t trf_flags;		/* State info */
    int	trf_refcount;
};

#define	TRF_REPLACE	BIT(0x01)	/* Replace trace file instead of appending to it */

struct _trace {
    flag_t tr_flags;		/* Tracing flags */
    flag_t tr_control;		/* Control flags */
    const bits *tr_names;	/* Names of trace flags */
    trace_file *tr_file;	/* Pointer to trace file we are using */
    int tr_refcount;		/* Reference count */
};

#define	TRC_NOSTAMP	BIT(0x80000000)	/* Don't provide timestamp */
#define	TRC_LOGONLY	BIT(0x40000000)	/* Don't trace, only log */
#define	TRC_NL_BEFORE	BIT(0x20000000)	/* Skip a line before */
#define	TRC_NL_AFTER	BIT(0x10000000)	/* Skip a line after */

#define	TRC_INHERIT	TRC_NOSTAMP

/* For parsing */
#define	TR_PARSE_DETAIL		1
#define	TR_PARSE_RECV		1
#define	TR_PARSE_SEND		2
#define	TR_PARSE_PACKETS	0
#define	TR_PARSE_PACKETS_1	1
#define	TR_PARSE_PACKETS_2	2
#define	TR_PARSE_PACKETS_3	3
#define	TR_PARSE_PACKETS_4	4
#define	TR_PARSE_PACKETS_5	5

/* Macros to help convert old code */
#define	trace_stamp()
#define	trace_nostamp()
#define	trace_all()
#define	trace_nl()
#define	trace_logonly()
#define	trace_log()

/**/

/*
 * Main trace flags
 */

#define	TR_PACKET_RECV_1	BIT(0x01)
#define	TR_PACKET_RECV_2	BIT(0x02)
#define	TR_PACKET_RECV_3	BIT(0x04)
#define	TR_PACKET_RECV_4	BIT(0x08)
#define	TR_PACKET_RECV_5	BIT(0x10)
#define	TR_PACKET_RECV	(TR_PACKET_RECV_1|TR_PACKET_RECV_2|TR_PACKET_RECV_3|TR_PACKET_RECV_4|TR_PACKET_RECV_5)

#define	TR_PACKET_SEND_1	BIT(0x20)
#define	TR_PACKET_SEND_2	BIT(0x40)
#define	TR_PACKET_SEND_3	BIT(0x80)
#define	TR_PACKET_SEND_4	BIT(0x0100)
#define	TR_PACKET_SEND_5	BIT(0x0200)
#define	TR_PACKET_SEND	(TR_PACKET_SEND_1|TR_PACKET_SEND_2|TR_PACKET_SEND_3|TR_PACKET_SEND_4|TR_PACKET_SEND_5)

#define	TR_PACKET	(TR_PACKET_RECV|TR_PACKET_SEND)
#define	TR_PACKET_1	(TR_PACKET_RECV_1|TR_PACKET_SEND_1)
#define	TR_PACKET_2	(TR_PACKET_RECV_2|TR_PACKET_SEND_2)
#define	TR_PACKET_3	(TR_PACKET_RECV_3|TR_PACKET_SEND_3)
#define	TR_PACKET_4	(TR_PACKET_RECV_4|TR_PACKET_SEND_4)
#define	TR_PACKET_5	(TR_PACKET_RECV_5|TR_PACKET_SEND_5)


#define	TR_DETAIL_RECV_1	(BIT(0x0400)|TR_PACKET_RECV_1)
#define	TR_DETAIL_RECV_2	(BIT(0x0800)|TR_PACKET_RECV_2)
#define	TR_DETAIL_RECV_3	(BIT(0x1000)|TR_PACKET_RECV_3)
#define	TR_DETAIL_RECV_4	(BIT(0x2000)|TR_PACKET_RECV_4)
#define	TR_DETAIL_RECV_5	(BIT(0x4000)|TR_PACKET_RECV_5)
#define	TR_DETAIL_RECV	(TR_DETAIL_RECV_1|TR_DETAIL_RECV_2|TR_DETAIL_RECV_3|TR_DETAIL_RECV_4|TR_DETAIL_RECV_5)

#define	TR_DETAIL_SEND_1	(BIT(0x8000)|TR_PACKET_SEND_1)
#define	TR_DETAIL_SEND_2	(BIT(0x010000)|TR_PACKET_SEND_2)
#define	TR_DETAIL_SEND_3	(BIT(0x020000)|TR_PACKET_SEND_3)
#define	TR_DETAIL_SEND_4	(BIT(0x040000)|TR_PACKET_SEND_4)
#define	TR_DETAIL_SEND_5	(BIT(0x080000)|TR_PACKET_SEND_5)
#define	TR_DETAIL_SEND	(TR_DETAIL_SEND_1|TR_DETAIL_SEND_2|TR_DETAIL_SEND_3|TR_DETAIL_SEND_4|TR_DETAIL_SEND_5)

#define	TR_DETAIL	(TR_DETAIL_RECV|TR_DETAIL_SEND)
#define	TR_DETAIL_1	(TR_DETAIL_RECV_1|TR_DETAIL_SEND_1)
#define	TR_DETAIL_2	(TR_DETAIL_RECV_2|TR_DETAIL_SEND_2)
#define	TR_DETAIL_3	(TR_DETAIL_RECV_3|TR_DETAIL_SEND_3)
#define	TR_DETAIL_4	(TR_DETAIL_RECV_4|TR_DETAIL_SEND_4)
#define	TR_DETAIL_5	(TR_DETAIL_RECV_5|TR_DETAIL_SEND_5)


#define	TR_USER_1		BIT(0x100000)
#define	TR_USER_2		BIT(0x200000)
#define	TR_USER_3		BIT(0x400000)
#define	TR_USER_4		BIT(0x800000)
#define	TR_USER_5		BIT(0x01000000)
#define	TR_USER_6		BIT(0x02000000)

#define	TR_STATE		BIT(0x04000000)		/* State machine transistions */
#define	TR_NORMAL		BIT(0x08000000)		/* Normal events */
#define	TR_POLICY		BIT(0x10000000)		/* Policy decisions */
#define	TR_TASK			BIT(0x20000000)		/* Task and job functions */
#define	TR_TIMER		BIT(0x40000000)		/* Timer functions */
#define	TR_ROUTE		BIT(0x80000000)		/* Routing table changes */

#define	TR_ALL			BIT(0xffffffff)
#define	TR_GENERAL		(TR_NORMAL|TR_ROUTE)

#define	TR_INHERIT	(TR_STATE|TR_NORMAL|TR_POLICY|TR_TASK|TR_TIMER|TR_ROUTE)

/**/

/*
 *	Trace routines
 */

void trace_init(void);
void trace_init2(void);
void trace_cleanup(void);
void trace_reinit(void);
const char *trace_string(flag_t, const bits *);
void trace_display(trace *, flag_t);
void trace_off(trace_file *);
void trace_toggle(void);
void trace_close_all(void);
void trace_on(trace_file *);
trace_file *trace_file_locate(char *, off_t, u_int, flag_t);
flag_t trace_args(char *);
const char *trace_value(const bits *, int);
char *trace_bits(const bits *, flag_t);
char *trace_bits2(const bits *, const bits *, flag_t);
void trace_task_dump(FILE *, trace *);
void trace_dump(int);
void tracef(const char *, ...);
void trace_trace(trace *, flag_t);
trace *trace_free(trace *);
trace *trace_alloc(trace *);
trace *trace_create(void);
void trace_file_free(trace_file *);
trace * trace_set_global(const bits *, flag_t);

#define	trace_set(to, from)	\
	do { trace_freeup(to); (to) = trace_alloc(from); } while (0)
#define	trace_inherit(to, from)	\
	do { if (!(to)) { (to) = trace_alloc(from); } } while (0)
#define	trace_file_alloc(tfp)	((tfp)->trf_refcount++, (tfp))
#define	trace_store(trp, tf, cf, tfp, types) do {	\
	if (tfp) {					\
		trace_freeup(trp);			\
		(trp) = trace_create();			\
		(trp)->tr_names = types;		\
		(trp)->tr_flags = tf;			\
		(trp)->tr_control = cf;			\
		(trp)->tr_file = tfp;			\
	}						\
    } while (0)

#define	trace_inherit_global(trp, bits, inherit) do {		\
	if (!(trp)) {						\
		(trp) = trace_set_global(bits, inherit);	\
	}							\
    } while (0)

#define	trace_freeup(trp) do {			\
	  if (trp) {				\
	      (trp) = trace_free((trp));	\
	  }					\
    } while (0)

flag_t trace_parse_packet(u_int, u_int, u_int);
void trace_syslog(int);

#define trace_state(bits, mask) bits[mask].t_name

/**/

/* Macros for various trace functions: */

/* trace_clear -
 *  Reset the trace buffer for the next message
 */
#define	trace_clear()	(*(trace_ptr = trace_buffer) = (char) 0)

/* trace_tf -
 * Issue this message to the trace only,
 * arg 1 is either the pointer to the trace options for this task or the global trace options
 */
#define	trace_tf(trp, tf, cf, msg) do { \
	if (TRACE_TF((trp), (tf))) { \
	    tracef msg; \
	    trace_trace((trp), (trp)->tr_control|(cf)); \
	} \
	trace_clear(); \
    } while(0)

/* trace_tp -
 * Issue this message to the trace only
 * arg 1 the pointer to the job_task
 */
#define	trace_tp(tp, tf, cf, msg)	trace_tf((tp)->task_trace, (tf), (cf), msg)

/* trace_only_tf -
 * Always trace - this is used inside code that has already tested trace flags
 */
#define	trace_only_tf(trp, cf, msg) do { \
	if ((trp) && (trp)->tr_file->trf_FILE) { \
	    tracef msg; \
	    trace_trace((trp), (trp)->tr_control|cf); \
	} \
	trace_clear(); \
    } while(0)

/* trace_only_tp */
#define	trace_only_tp(tp, cf, msg)	trace_only_tf((tp)->task_trace, (cf), msg)

/* trace_log_tf -
 * Always trace and log
 */
#define	trace_log_tf(trp, cf, pri, msg) do { \
	tracef msg; \
	if ((trp) && (trp)->tr_file->trf_FILE && !BIT_TEST((trp)->tr_control|(cf), TRC_LOGONLY)) { \
	     trace_trace((trp), (trp)->tr_control|(cf)); \
	} \
	if (pri) { \
	    if (trace_nosyslog) { \
	    	trace_syslog((pri)); \
	    } else { \
		syslog((pri), trace_buffer); \
	    } \
	} \
	trace_clear(); \
    } while (0)

/* trace_log_tp */
#define	trace_log_tp(tp, cf, pri, msg) \
	trace_log_tf((tp) ? (tp)->task_trace : trace_global, (cf), (pri), msg)

/* Quick tests to see if tracing is on */
#define	TRACE_TF(trp, tf)	((trp) \
				 && (trp)->tr_file->trf_FILE \
				 && (((trp)->tr_flags == TR_ALL) \
				     || BIT_TEST((trp)->tr_flags, (tf))))
#define	TRACE_TP(tp, tf)	TRACE_TF((tp)->task_trace, (tf))

#define	TRACE_PACKET_TEST(trp, type, max, masks, mask) \
	TRACE_TF(trp, ((type < max) ? masks[type] : TR_ALL) & (mask|TR_NORMAL))

#define	TRACE_PACKET_RECV(trp, type, max, masks)	TRACE_PACKET_TEST(trp, type, max, masks, TR_PACKET_RECV)
#define	TRACE_PACKET_SEND(trp, type, max, masks)	TRACE_PACKET_TEST(trp, type, max, masks, TR_PACKET_SEND)
#define	TRACE_PACKET(trp, type, max, masks)		TRACE_PACKET_TEST(trp, type, max, masks, TR_PACKET)
#define	TRACE_DETAIL_RECV(trp, type, max, masks)	TRACE_PACKET_TEST(trp, type, max, masks, TR_DETAIL_RECV)
#define	TRACE_DETAIL_SEND(trp, type, max, masks)	TRACE_PACKET_TEST(trp, type, max, masks, TR_DETAIL_SEND)
#define	TRACE_DETAIL(trp, type, max, masks)		TRACE_PACKET_TEST(trp, type, max, masks, TR_DETAIL)

#define	TRACE_PACKET_RECV_TP(tp, type, max, masks)	TRACE_PACKET_TEST((tp)->task_trace, type, max, masks, TR_PACKET_RECV)
#define	TRACE_PACKET_SEND_TP(tp, type, max, masks)	TRACE_PACKET_TEST((tp)->task_trace, type, max, masks, TR_PACKET_SEND)
#define	TRACE_PACKET_TP(tp, type, max, masks)		TRACE_PACKET_TEST((tp)->task_trace, type, max, masks, TR_PACKET)
#define	TRACE_DETAIL_RECV_TP(tp, type, max, masks)	TRACE_PACKET_TEST((tp)->task_trace, type, max, masks, TR_DETAIL_RECV)
#define	TRACE_DETAIL_SEND_TP(tp, type, max, masks)	TRACE_PACKET_TEST((tp)->task_trace, type, max, masks, TR_DETAIL_SEND)
#define	TRACE_DETAIL_TP(tp, type, max, masks)		TRACE_PACKET_TEST((tp)->task_trace, type, max, masks, TR_DETAIL)

/*
 * Global data area
 */
extern trace *trace_global;		/* Global options */
extern char trace_buffer[];		/* Line buffer */
extern char *trace_ptr;			/* Pointer into buffer */

extern int trace_nosyslog;		/* Do not use syslog */
#define	TRACE_LOG_NORMAL	0	/* Use syslog */
#define	TRACE_LOG_NONE		1	/* Don't log at all */
#define	TRACE_LOG_TRACE		2	/* Trace to the terminal */

extern int trace_require_lock;


