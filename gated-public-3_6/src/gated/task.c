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


#define	INCLUDE_WAIT
#define	INCLUDE_TIME
#define	INCLUDE_SIGNAL
#define	INCLUDE_IOCTL
#define	INCLUDE_FILE
#define	INCLUDE_FCNTL 	 /* to get O_RDWR */
#define INCLUDE_SYS_MMAN /* for mmap() */
#define	INCLUDE_MROUTE
#define	INCLUDE_IF
#define INCLUDE_GQUEUE
#define INCLUDE_SYS_QUEUE
#define INCLUDE_INET_IP
#define	MALLOC_OK
#define	INCLUDE_ISO_VAR
#define	INCLUDE_SNPA

#include "include.h"
#ifdef	PROTO_INET
#include "inet/inet.h"
#endif	/* PROTO_INET */
#ifdef PROTO_INET6
#include "inet6/inet6.h"
#endif /* PROTO_INET6 */
#ifdef	PROTO_ISO
#include "iso/iso.h"
#endif	/* PROTO_ISO */
#include "krt/krt.h"
#ifdef	PROTO_BGP
#ifndef PROTO_BGP4MP 
#include "bgp/bgp.h"
#endif  /* PROTO_BGP4MP */
#ifdef PROTO_BGP4MP
#include "bgp4mp/bgp4mp.h"
#endif /* PROTO_BGP4MP */
#endif	/* PROTO_BGP */
#ifdef	PROTO_MPBGP
#include "mpbgp/mpbgp.h"
#endif	/* PROTO_MPBGP */
#ifdef  IP_MULTICAST_ROUTING
# include "mcore/mrt.h" 
# include "mcore/mroute.h" 
# ifdef PROTO_DVMRP_ROUTING
#  include "dvmrp_routing/dvmrp_routing.h"
# endif
# ifdef	PROTO_DVMRP
#  include "dvmrp/dvmrp.h"
# endif	/* PROTO_DVMRP */
# ifdef PROTO_PIM
#  include "pim/pim.h"
# endif /* PROTO_PIM */
# ifdef PROTO_MSDP
#  include "msdp/msdp.h"
# endif /* PROTO_MSDP */
#endif /* IP_MULTICAST_ROUTING */
#ifdef	PROTO_EGP
#include "egp/egp.h"
#endif	/* PROTO_EGP */
#ifdef	PROTO_OSPF
#include "ospf/ospf.h"
#endif	/* PROTO_OSPF */
#ifdef  PROTO_OSPF2
#include "new_ospf/new_ospf_parse.h"
#endif	/* PROTO_OSPF2 */
#ifdef  PROTO_IPX
#include "ipx_rip.h"
#include "ipx_sap.h"
#endif	/* PROTO_IPX */
#ifdef PROTO_GII
#include "gii/gii.h"
#endif	/* PROTO_GII */
#ifdef	PROTO_IDPR
#include "idrp/idpr.h"
#endif	/* PROTO_IDPR */
#ifdef	PROTO_RIP
#include "rip/rip.h"
#endif	/* PROTO_RIP */
#ifdef	PROTO_HELLO
#include "hello/hello.h"
#endif	/* PROTO_HELLO */
#ifdef	PROTO_ICMP
#include "icmp/icmp.h"
#endif	/* PROTO_ICMP */
#ifdef  IP_MULTICAST_ROUTING
#include "mcore/mroute.h"
#endif  /* IP_MULTICAST_ROUTING */
#ifdef	PROTO_ICMPV6
#ifdef  IPV6_NETINET6
#include <netinet6/icmp6.h>
#else
#ifdef IPV6_NETINET 
#include <netinet/icmp6.h>
#endif
#endif
#include "icmpv6/icmpv6.h"
#endif	/* PROTO_ICMPV6 */
#ifdef	PROTO_IGMP
#include "igmp/igmp.h"
#endif	/* PROTO_IGMP */
#ifdef	PROTO_BGMP
#include "bgmp/bgmp.h"
#endif	/* PROTO_BGMP */
#ifdef	PROTO_CMU_SNMP
#include "snmp_cmu/snmp_cmu.h"
#endif	/* PROTO_CMU_SNMP */
#ifdef PROTO_SMUX
#include "smux/smux_asn1.h"
#include "smux/smux.h"
#endif /* PROTO_SMUX */
#ifdef	PROTO_ISIS
#include "isis/isis_includes.h"
#endif	/* PROTO_ISIS */
#ifdef	PROTO_ISIS2
#include "new_isis/new_isis_parse.h"
#include "new_isis/new_isis.h"
#endif	/* PROTO_ISIS2 */
#ifdef	PROTO_SLSP
#include "slsp/slsp.h"
#endif	/* PROTO_SLSP */
#ifdef	PROTO_RDISC
#include "rdisc/rdisc.h"
#endif	/* PROTO_RDISC */
#ifdef	PROTO_RIPNG
#include "ripng/ripng.h"
#endif	/* PROTO_RIPNG */
#ifdef	PROTO_PIMV6
#include "pimv6.h"
#endif	/* PROTO_PIMV6 */
#include "parse.h"
#ifndef HAVE_SYS_SIGNAME
#include "signames.h"
#endif

#ifdef HAVE_AIX
#define WAIT_T  union wait
#define WIFCOREDUMP(statusp)  (statusp.w_coredump) 
#endif

/* nice useful global of 32 bytes of zero */
const u_int8 zeros32[32];

/* For systems that do not have FD_SET macros */

#ifndef	FD_SET
#ifndef	NBBY
#define	NBBY	8			/* number of bits in a byte */
#endif	/* NBBY */
typedef long fd_mask;

#define	NFDBITS	(sizeof(fd_mask) * NBBY)/* bits per mask */

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define	FD_ZERO(p)	bzero((char *)(p), sizeof(*(p)))
#endif	/* FD_SET */

struct gtime task_time = { { 0 } };		/* Current time of day */
struct gtime task_time_start = { { 0 } };	/* Time gated started */

static task_timer task_timer_queue_active =
{&task_timer_queue_active, &task_timer_queue_active, "activeTimers"};	/* Doubly linked list of active timers */
static task_timer task_timer_queue_inactive =
{&task_timer_queue_inactive, &task_timer_queue_inactive, "inactiveTimers"};	/* Doubly linked list of inactive timers */
static task_timer task_timer_queue_hiprio =
{&task_timer_queue_hiprio, &task_timer_queue_hiprio, "hiprioTimers"};

int task_timer_hiprio_active = 0;
utime_t *task_timer_hiprio_time;

int task_timer_active = 0;
utime_t *task_timer_active_time;

#define	TIMER_QUEUE(queue, tip, tip1) { task_timer *tip1; \
				for (tip = (queue)->task_timer_forw; tip1 = tip->task_timer_back, tip != queue; \
				     tip = (tip == tip1->task_timer_forw) ? tip->task_timer_forw : tip1->task_timer_forw)
#define TIMER_QUEUE_END(queue, tip, tip1)	}

task task_head = {	/* Root of tasks */
    &task_head,
    &task_head,
    "taskHead"
};

#define	TMQ_TP(tmq, member)	((task *) ((void_t) ((byte *) (tmq) - offsetof(task, member))))

#define	TMQ_LIST(tp, queue) \
	{ \
	     register task_method_queue *Xtmq_next = \
		((queue).tmqp_normal_priority.tmqh_queue.tmq_forw); \
	     while (Xtmq_next != &((queue).tmqp_normal_priority.tmqh_queue)) { \
		 (tp) = TMQ_TP(Xtmq_next, queue); \
		 Xtmq_next = Xtmq_next->tmq_forw;

#define	TMQ_LIST_END(tp, queue) }}

#define	TMQ_LP_LIST(tp, queue) \
	{ \
	     register task_method_queue *Xtmq_next = \
		((queue).tmqp_low_priority.tmqh_queue.tmq_forw); \
	     while (Xtmq_next != &((queue).tmqp_low_priority.tmqh_queue)) { \
		 (tp) = TMQ_TP(Xtmq_next, queue); \
		 Xtmq_next = Xtmq_next->tmq_forw;

#define	TMQ_LP_LIST_END(tp, queue) }}


#define	TMQ_INSERT(tp, queue) \
	do { \
	     if (!(tp)->queue.tmq_forw) { \
		INSQUE(&((tp)->queue), ((queue).tmqp_normal_priority.tmqh_queue.tmq_back)); \
	     } \
	 } while (0)

#define	TMQ_LP_INSERT(tp, queue) \
	do { \
	     if (!(tp)->queue.tmq_forw) { \
		INSQUE(&((tp)->queue), ((queue).tmqp_low_priority.tmqh_queue.tmq_back)); \
	     } \
	 } while (0)

#define	TMQ_REMOVE(tp, member) \
	do { \
	   if ((tp)->member.tmq_forw) { \
		if (member.tmqp_normal_priority.tmqh_lock) { \
		    member.tmqp_normal_priority.tmqh_lock = TMQ_LOCK_WASLOCKED; \
		} else { \
		    REMQUE(&(tp)->member); \
		    (tp)->member.tmq_forw = (tp)->member.tmq_back = (task_method_queue *) 0; \
		} \
	     } \
	} while (0)

#define	TMQ_LP_REMOVE(tp, member) \
	do { \
	   if ((tp)->member.tmq_forw) { \
		if (member.tmqp_low_priority.tmqh_lock) { \
		    member.tmqp_low_priority.tmqh_lock = TMQ_LOCK_WASLOCKED; \
		} else { \
		    REMQUE(&(tp)->member); \
		    (tp)->member.tmq_forw = (tp)->member.tmq_back = (task_method_queue *) 0; \
		} \
	     } \
	} while (0)

#define	TMQ_REQUEUE(tp, queue) \
    do { \
	REMQUE(&((queue).tmqp_normal_priority.tmqh_queue)); \
	INSQUE(&((queue).tmqp_normal_priority.tmqh_queue), &((tp)->queue)); \
    } while (0)

#define	TMQ_LP_REQUEUE(tp, queue) \
    do { \
	REMQUE(&((queue).tmqp_low_priority.tmqh_queue)); \
	INSQUE(&((queue).tmqp_low_priority.tmqh_queue), &((tp)->queue)); \
    } while (0)

#define	TMQ_EMPTY(queue) \
    ((queue).tmqp_normal_priority.tmqh_queue.tmq_forw \
    == &((queue).tmqp_normal_priority.tmqh_queue))

#define	TMQ_LP_EMPTY(queue) \
    ((queue).tmqp_low_priority.tmqh_queue.tmq_forw \
    == &((queue).tmqp_low_priority.tmqh_queue))

/*
 * Queue locking.  Whenever a queue is being run the associated lock word
 * is set to -1.  If it is attempted to delete a queue entry from the queue
 * while it is being run the lock word is set to 1.  After each queue run
 * the lock is examined.  If it has been set to 1 the queue is rescanned to
 * remove the offending entry.
 */
typedef struct _task_method_queue_head {
    task_method_queue tmqh_queue;
    int tmqh_lock;
} task_method_queue_head;

typedef struct _task_method_queue_priority {
    task_method_queue_head tmqp_normal_priority;
    task_method_queue_head tmqp_low_priority;
} task_method_queue_priority;

typedef struct _task_method_queue_nopriority {
    task_method_queue_head tmqp_normal_priority;
} task_method_queue_nopriority;

#define	TMQ_LOCK_NONE		0			/* no lock on queue */
#define	TMQ_LOCK_LOCKED		(TMQ_LOCK_NONE-1)	/* queue is locked */
#define	TMQ_LOCK_WASLOCKED	(TMQ_LOCK_NONE+1)	/* someone wished it wasn't */

#define	TMQ_SET_LOCK(queue) \
    ((queue).tmqp_normal_priority.tmqh_lock = TMQ_LOCK_LOCKED)
#define	TMQ_SET_LP_LOCK(queue) \
    ((queue).tmqp_low_priority.tmqh_lock = TMQ_LOCK_LOCKED)
#define	TMQ_CHECK_WASLOCKED(queue) \
    ((++((queue).tmqp_normal_priority.tmqh_lock)) != TMQ_LOCK_NONE)
#define	TMQ_CHECK_LP_WASLOCKED(queue) \
    ((++((queue).tmqp_low_priority.tmqh_lock)) != TMQ_LOCK_NONE)
#define	TMQ_CLEAR_LOCK(queue) \
    ((queue).tmqp_normal_priority.tmqh_lock = TMQ_LOCK_NONE)
#define	TMQ_CLEAR_LP_LOCK(queue) \
    ((queue).tmqp_low_priority.tmqh_lock = TMQ_LOCK_NONE)

#define	TMQ_INIT_HEAD(head)	{ { &(head).tmqh_queue, &(head).tmqh_queue }, 0 }
#define	TMQ_INIT_PRIORITY(queue) \
	{ TMQ_INIT_HEAD((queue).tmqp_normal_priority), \
	  TMQ_INIT_HEAD((queue).tmqp_low_priority) }

#define	TMQ_INIT_NOPRIORITY(queue) \
	{ TMQ_INIT_HEAD((queue).tmqp_normal_priority) }

static task_method_queue_priority task_read_queue = TMQ_INIT_PRIORITY(task_read_queue);
static task_method_queue_nopriority task_write_queue = TMQ_INIT_NOPRIORITY(task_write_queue);
static task_method_queue_nopriority task_flash_queue = TMQ_INIT_NOPRIORITY(task_flash_queue);
static task_method_queue_nopriority task_except_queue = TMQ_INIT_NOPRIORITY(task_except_queue);

/*
 * Check to see if a task in on a queue.
 */
#define	TMQ_ON_QUEUE(tp, queue) \
    ((tp)->queue.tmq_forw != (task_method_queue *) 0)
#define	TMQ_ON_ANY_QUEUE(tp) \
    (TMQ_ON_QUEUE(tp, task_read_queue) \
    || TMQ_ON_QUEUE(tp, task_write_queue) \
    || TMQ_ON_QUEUE(tp, task_except_queue) \
    || TMQ_ON_QUEUE(tp, task_flash_queue))


/*
 * Task scheduler tuning.  Normal priority reads are always done.
 * You can limit the number of writes, low priority reads, or the
 * sum of writes and low priority reads done in one loop.  You can
 * also limit the number of normal priority timers run in one loop.
 * This will most often be unnecessary, but will ensure your normal
 * priority reads get sufficient attention under periods of high load.
 */
#define	TASK_SCHED_UNLIMITED	((u_int)(-1))
u_int task_sched_reads = TASK_SCHED_UNLIMITED;
u_int task_sched_writes = TASK_SCHED_UNLIMITED;
u_int task_sched_reads_and_writes = TASK_SCHED_UNLIMITED;
u_int task_sched_timers = TASK_SCHED_UNLIMITED;

/*
 * Select bits.  We keep a count of the number of select bits set
 * in each mask so we can avoid the overhead of giving the mask
 * to select() when no bits are set.
 */
typedef struct _task_fd_set {
    fd_set tfd_bits;
    u_int tfd_n_bits;
} task_fd_set;

/*
 * Set a bit in the task_fd_set.
 */
#define	TASK_FD_SET(n, set) \
    do { \
	if (!FD_ISSET((n), &((set)->tfd_bits))) { \
	    FD_SET((n), &((set)->tfd_bits)); \
	    (set)->tfd_n_bits++; \
	} \
    } while (0)

#define	TASK_FD_CLR(n, set) \
    do { \
	if (FD_ISSET((n), &((set)->tfd_bits))) { \
	    FD_CLR((n), &((set)->tfd_bits)); \
	    (set)->tfd_n_bits--; \
	} \
    } while (0)


#define	TASK_FD_SOMESET(set)	((set)->tfd_n_bits != 0)

#define	TASK_FD_ISSET(n, set) \
    ((set)->tfd_n_bits != 0 && FD_ISSET((n), &((set)->tfd_bits)))

#define	TASK_FD_GETBITS(set)	((set)->tfd_bits)

static task_fd_set task_select_readbits;
static task_fd_set task_select_writebits;
static task_fd_set task_select_exceptbits;
static int task_max_socket = -1;
static int task_n_tasks = 0;		/* Number of tasks */
char *task_path_start = 0;		/* Directory where we were started */
char *task_path_now = 0;		/* Directory where we are now */
char *task_config_file = 0;		/* Config file we read (and reread) */

static task task_task = {		/* Dummy task for the scheduler */
    (task *) 0,
    (task *) 0,
    "Scheduler"
};
task *task_active = &task_task;		/* Task pointer to the active task */

/*
 *	Signals
 */

static volatile int task_signal_pending;		/* Indicate a signal is pending */
static volatile int task_signal_unknown;		/* The last unknown signal */

struct task_signal {
    int sig_sig;			/* The signal */
    const char *sig_name;		/* A text name */
    volatile int sig_pending;		/* A signal is pending */
    int sig_process;			/* We need to process this */
};

static struct task_signal task_signals[] = {
    { SIGTERM,	"Terminate" },
    { SIGUSR1,	"Toggle Tracing" },
    { SIGUSR2,	"Interface Check" },
    { SIGINT,	"Status Dump" },
    { SIGHUP,	"Reconfigure" },
    { SIGCHLD,	"Reap Children" },
    { 0 }
};

#define	SIGNAL_LIST(ip)	{ struct task_signal *ip; for (ip = task_signals; ip->sig_sig; ip++)
#define	SIGNAL_LIST_END(ip) }

#ifdef	SYS_SIGNAME
extern SYS_SIGNAME;
#endif	/* SYS_SIGNAME */

/*
 * Miscellaneous variables.
 */
char *task_progname = 0;			/* name we were invoked as */
char *task_hostname = 0;			/* Hostname of this system */
int task_pid = 0;				/* my process ID */
int task_mpid = 0;				/* process ID of main process */
char task_pid_str[6] = { 0 };			/* Printable version of PID */
flag_t task_state = TASKS_INIT;			/* Current state */
size_t task_pagesize = 0;			/* System page size */
size_t task_maxpacket = 0;			/* Maximum packet size the kernel supports */
block_t task_block_index = 0;			/* Block allocation index for task structures */

/*
 *	I/O structures - visible
 */

/* Receive buffer and length */
void_t task_recv_buffer = 0;
size_t task_recv_buffer_len = 0;

/* Send buffer and length */
void_t task_send_buffer = 0;
size_t task_send_buffer_len = 0;

sockaddr_un *task_recv_srcaddr = 0;	/* Source address of this packet */
sockaddr_un *task_recv_dstaddr = 0;	/* Destination address of this packet */

/* index of receiveing interface or 0 if not known */
u_int task_recv_if_index = 0;

#ifdef PROTO_INET6
if_addr *task_recv_interface = 0;
u_char task_recv_hoplimit = 255;
#endif /* PROTO_INET6 */


static const bits task_state_bits[] =
{
    {TASKS_INIT,	"Init" },
    {TASKS_TEST,	"Test" },
    {TASKS_RECONFIG,	"ReConfig" },
    {TASKS_TERMINATE,	"Terminate" },
    {TASKS_NORECONFIG,	"NoReConfig" },
    {TASKS_NOSEND,	"NoSend" },
    {TASKS_FLASH,	"FlashUpdate" },
    {TASKS_NEWPOLICY,	"NewPolicy" },
    {TASKS_NODAEMON, 	"Foreground" },
    {TASKS_STRICTIFS,	"StrictIfs" },
    {TASKS_NODUMP,	"NoDump" },
    {TASKS_NORESOLV,	"NoResolv" },
    {TASKS_NODETACH,	"NoDetach" },
    {0}
} ;

const bits task_flag_bits[] =
{
    {TASKF_ACCEPT,	"Accept"},
    {TASKF_CONNECT,	"Connect"},
    {TASKF_DELETE,	"Delete"},
    {TASKF_LOWPRIO,	"LowPrio"},
    {0}
};

static const bits task_socket_options[] =
{
    {TASKOPTION_RECVBUF, "RecvBuffer"},
    {TASKOPTION_SENDBUF, "SendBuffer"},
    {TASKOPTION_LINGER, "Linger"},
    {TASKOPTION_REUSEADDR, "ReUseAddress"},
    {TASKOPTION_BROADCAST, "Broadcast"},
    {TASKOPTION_DONTROUTE, "DontRoute"},
    {TASKOPTION_KEEPALIVE, "KeepAlive"},
    {TASKOPTION_DEBUG, "Debug"},
    {TASKOPTION_NONBLOCKING, "NonBlocking"},
    {TASKOPTION_USELOOPBACK, "UseLoopback"},
    {TASKOPTION_GROUP_ADD, "GroupAdd"},
    {TASKOPTION_GROUP_DROP, "GroupDrop"},
    {TASKOPTION_MULTI_IF, "MulticastInterface"},
    {TASKOPTION_MULTI_LOOP, "MulticastLoop"},
    {TASKOPTION_MULTI_TTL, "MulticastTTL"},
    {TASKOPTION_MULTI_ROUTE, "MulticastRouting"},
    {TASKOPTION_TTL,	"TTL"},
    {TASKOPTION_TOS,	"TOS"},
    {TASKOPTION_RCVDSTADDR,	"RcvDstAddr"},
    {TASKOPTION_RCVIF,	"RcvIF"},
    {TASKOPTION_IPHEADER_INC,	"IncludeIpHeader"},
    {TASKOPTION_ADD_VIF, "MulticastAddVif"},
    {TASKOPTION_DEL_VIF, "MulticastDelVif"},
    {TASKOPTION_ADD_MFC, "MulticastAddMFC"},
    {TASKOPTION_DEL_MFC, "MulticastDelMFC"},
#ifdef  TASKOPTION_ASSERT
    {TASKOPTION_ASSERT, "MulticastAssert"},
#else
    {24, "???"},    /* That's gross. BUt what else can we do? */
#endif        /* TASKOPTION_ASSERT */
#ifdef IPSEC
    {TASKOPTION_IPSEC_ENCRYPTED, "IPEncrypted"},
#endif

#if defined(PROTO_INET6)
    {TASKOPTION_RCVIF, "RcvInterface"},
    {TASKOPTION_RCVHOPLIM, "RcvHopLim"},
    {TASKOPTION_PKTOPTIONS, "PktOptions"},
    {TASKOPTION_SENDIF, "SendIf"},
    {TASKOPTION_CHECKSUM, "CheckSum"},
#endif
    {0, NULL}
};

static const bits task_msg_bits[] =
{
    {MSG_OOB, "MSG_OOB"},
    {MSG_PEEK, "MSG_PEEK"},
    {MSG_DONTROUTE, "MSG_DONTROUTE"},
#ifdef	MSG_EOR
    {MSG_EOR, "MSG_EOR"},
#endif	/* MSG_EOR */
#ifdef	MSG_TRUNC
    {MSG_TRUNC, "MSG_TRUNC"},
#endif	/* MSG_TRUNC */
#ifdef	MSG_CTRUNC
    {MSG_CTRUNC, "MSG_CTRUNC"},
#endif	/* MSG_CTRUNC */
#ifdef	MSG_WAITALL
    {MSG_WAITALL, "MSG_WAITALL"},
#endif	/* MSG_WAITALL */
    {0, NULL}
};


/*
 *	Free a deleted task
 */
static void
task_collect_job(task_job *jp)
{
    register task *delete_tp = (task *) jp->task_job_data;

    assert(BIT_TEST(delete_tp->task_flags, TASKF_DELETE));

    if (TRACE_TP(jp->task_job_task, TR_TASK)) {
	trace_only_tp(jp->task_job_task,
		      0,
		      ("task_collect_job: freeing task %s",
		       task_name(delete_tp)));
    }
    
    REMQUE(delete_tp);
    assert(!TMQ_ON_ANY_QUEUE(delete_tp) && !(delete_tp->task_timers));

    /* Free the tracing info */
    trace_freeup(delete_tp->task_trace);
    task_block_free(task_block_index, (void_t) delete_tp);
}


/**/

/* Timer stuff */

const bits task_timer_flag_bits[] =
{
    {TIMERF_DELETE,	"Delete"},
    {TIMERF_HIPRIO,	"HiPrio"},
    {TIMERF_ONESHOT,	"OneShot"},
    {TIMERF_SET, 	"Set"},
    {TIMERF_PROCESSING, "Processing"},
    {TIMERF_INACTIVE, 	"Inactive"},
    {TIMERF_RESET, 	"Reset"},
	{TIMERF_SHOTNOW, "ShotNow"},
    {0}
};

block_t task_timer_block_index = 0;		/* Allocation index for timer structures */

#define	TIMER_NORMALIZE(tvp) \
    do { \
	if ((tvp)->ut_usec >= 1000000) { \
	    (tvp)->ut_usec -= 1000000; \
	    (tvp)->ut_sec += 1; \
	} \
    } while (0)

#define	TIMER_ADD(to, from) \
    do { \
	(to)->ut_sec += (from)->ut_sec; \
	(to)->ut_usec += (from)->ut_usec; \
	TIMER_NORMALIZE((to)); \
    } while (0)

#define	TIMER_ENQUEUE_IDLE(tip) \
    do { \
	register task_timer *Xtip = (tip); \
	BIT_SET(Xtip->task_timer_flags, TIMERF_INACTIVE); \
	INSQUE(Xtip, &task_timer_queue_inactive); \
    } while (0)

#define	TIMER_ENQUEUE(tip) \
    do { \
	register task_timer *Xtipq, *Xtiptmp; \
	register task_timer *Xtip = (tip); \
	if (BIT_TEST(tip->task_timer_flags, TIMERF_HIPRIO)) { \
	    Xtipq = &task_timer_queue_hiprio; \
	    task_timer_hiprio_active++; \
	} else { \
	    Xtipq = &task_timer_queue_active; \
	    task_timer_active++; \
	} \
	for (Xtiptmp = Xtipq->task_timer_back; Xtiptmp != Xtipq; Xtiptmp = Xtiptmp->task_timer_back) { \
	    if (Xtip->task_timer_next_time > Xtiptmp->task_timer_next_time \
	      || (Xtip->task_timer_next_time == Xtiptmp->task_timer_next_time \
		&& Xtip->task_timer_next_utime.ut_usec >= Xtiptmp->task_timer_next_utime.ut_usec)) { \
		break; \
	    } \
	} \
	INSQUE(Xtip, Xtiptmp); \
	if (BIT_TEST(Xtip->task_timer_flags, TIMERF_HIPRIO)) { \
	    task_timer_hiprio_time = &(task_timer_queue_hiprio.task_timer_forw->task_timer_next_utime); \
	} else { \
	    task_timer_active_time = &(task_timer_queue_active.task_timer_forw->task_timer_next_utime); \
	} \
    } while (0)

#define	TIMER_DEQUEUE(tip) \
    do { \
	register task_timer *Xtip = (tip); \
	REMQUE(Xtip); \
	if (BIT_TEST(Xtip->task_timer_flags, TIMERF_INACTIVE)) { \
	    BIT_RESET(Xtip->task_timer_flags, TIMERF_INACTIVE); \
	} else if (BIT_TEST(Xtip->task_timer_flags, TIMERF_HIPRIO)) { \
	    task_timer_hiprio_active--; \
	    task_timer_hiprio_time = &(task_timer_queue_hiprio.task_timer_forw->task_timer_next_utime); \
	} else { \
	    task_timer_active--; \
	    task_timer_active_time = &(task_timer_queue_active.task_timer_forw->task_timer_next_utime); \
	} \
    } while (0)


/*
 * Update the timer strings.  Called when they're needed but
 * may be out-of-date.
 */
static void
task_timer_str_update(void)
{
    time_t newtime;

    task_time.gt_up_to_date = 1;
    newtime = time_boot + time_sec;
    if ((utime_boot.ut_usec + utime_current.ut_usec) >= 1000000) {
	newtime++;
    }

    if (task_time.gt_str_time != newtime) {
	task_time.gt_str_time = newtime;

	(void) strcpy(task_time.gt_ctime, (char *) ctime(&newtime));
	(void) strncpy(task_time.gt_str, &time_full[4], 15);
	task_time.gt_str[15] = (char) 0;
    }
}


/*
 * task_timer_get_str() - update the timer strings, return the brief one
 */
char *
task_timer_get_str(void)
{
    task_timer_str_update();
    return (task_time.gt_str);
}


/*
 * task_timer_get_ctime() - update the timer strings, return the ctime
 */
char *
task_timer_get_ctime(void)
{
    task_timer_str_update();
    return (task_time.gt_ctime);
}


/*
 * task_timer_peek() - update the current time-of-day
 */
void
task_timer_peek(void)
{
    TIMER_PEEK();
}


/*
 *	Return a pointer to a string containing the timer name
 */
char *
task_timer_name(task_timer *tip)
{
    static char name[MAXHOSTNAMELENGTH];

    if (tip->task_timer_task) {
	(void) sprintf(name, "%s_%s",
		       task_name(tip->task_timer_task),
		       tip->task_timer_name);
    } else {
	(void) strcpy(name, tip->task_timer_name);
    }
    return name;
}


/*
 *	Create a timer - returns pointer to timer structure
 *
 * Here's how this works.  interval, offset and jitter are utime pointers,
 * may be specified as NULL.  If an offset is specified, the first timer expiry
 * will be offset (seconds.microseconds) from now, otherwise the first timer
 * expiry will be interval (seconds.microseconds) from now.  If an interval
 * is specified the timer will refire every interval (seconds.microseconds),
 * otherwise (if you only give an offset) it will fire once and then go idle.
 *
 * If you want the timer to fire immediately after creation, provide an offset
 * whose value is 0.  An offset of NULL won't do this.
 *
 * The TIMERF_ABSOLUTE flag is gone, there are only two ways timers work.  If
 * you specify a NULL jitter the timer will attempt to fire every interval
 * seconds without drift (i.e. the next expiry time will be equal to the
 * interval plus the time at which the timer *should* *have* fired last time).
 * If you specify a jitter, however, the next expiry will be set to the time
 * the timer actually fired previously, plus the interval, +/- something less
 * than jitter (seconds.microseconds).
 *
 * If you want a timer whose next expiry time will be readjusted at every
 * firing, the best thing to do is to *not* specify an interval, instead
 * specifying an offset when the timer is created and resetting the offset
 * using task_timer_uset() every time the timer fires.  Also note that if timer
 * processing is delayed beyond a timer's interval, non-drifting timers will
 * only be fired once.
 */
task_timer *
task_timer_ucreate(task *tp, const char *name, flag_t flags, utime_t *interval,
    utime_t *offset, utime_t *jitter, task_timer_func_t tjob, void_t data)
{
    task_timer *tip;

    tip = (task_timer *) task_block_alloc(task_timer_block_index);
    tip->task_timer_name = name;
    tip->task_timer_task = tp;
    tip->task_timer_flags = flags & TIMERF_USER_CAN_SET;
    if (interval && !BIT_TEST(flags, TIMERF_DELETE)) {
	tip->task_timer_uinterval = *interval;		/* struct copy */
    } else {
	tip->task_timer_uinterval.ut_sec = tip->task_timer_uinterval.ut_usec = 0;
	BIT_SET(tip->task_timer_flags, TIMERF_ONESHOT);
    }
    tip->task_timer_job = tjob;
    tip->task_timer_data = data;

    /* Link timer to task */
    if (!tp) {
	/* Use global task */
	tp = &task_head;
    }
    tip->task_timer_next = tp->task_timers;
    tp->task_timers = tip;

    /* If this timer is active, set the intervals */
    if (interval || offset) {
	tip->task_timer_next_utime = utime_current; 			/* struct copy */
	if (offset) {
	    TIMER_ADD(&tip->task_timer_next_utime, offset);
	    tip->task_timer_last_utime = tip->task_timer_next_utime;	/* struct copy */
	} else {
	    tip->task_timer_last_utime = utime_current;		/* struct copy */
	    TIMER_ADD(&tip->task_timer_next_utime, interval);
	}
    }

    /* Allow jitter to be no bigger than half the interval */
    if (jitter && !BIT_TEST(tip->task_timer_flags, TIMERF_ONESHOT)) {
	if (jitter->ut_sec >= TIMER_MAX_JITTER) {
	    tip->task_timer_jitter = (TIMER_MAX_JITTER * 2000000);
	} else {
	    tip->task_timer_jitter = (jitter->ut_sec * 2000000) + (jitter->ut_usec << 1);
	}

	if (tip->task_timer_uinterval.ut_sec <= (TIMER_MAX_JITTER * 2)) {
	    time_t intvl = tip->task_timer_uinterval.ut_sec * 100000
			 + tip->task_timer_uinterval.ut_usec;
	    if (intvl < tip->task_timer_jitter) {
		tip->task_timer_jitter = intvl;
	    }
	}
    }

    if (interval == NULL && offset == NULL) {
	/*
	 * Idle timer.  Queue it on the inactive queue.
	 */
	TIMER_ENQUEUE_IDLE(tip);
    } else {
	TIMER_ENQUEUE(tip);
    }

    if (TRACE_TP(tp, TR_TIMER)) {
	utime_t tv;

	tv.ut_sec = 0;
	tv.ut_usec = tip->task_timer_jitter;
	trace_only_tp(tp,
		      TR_TIMER,
		      ("task_timer_ucreate: created timer %s  flags <%s>  interval %#t jitter %#t at %t",
		       task_timer_name(tip),
		       trace_bits(task_timer_flag_bits, tip->task_timer_flags),
		       &tip->task_timer_uinterval,
		       &tv,
		       &tip->task_timer_next_utime));
    }

    return tip;
}

/*
 *	Backward compatability
 */
task_timer *
task_timer_create(task *tp, const char *name, flag_t flags, time_t interval,
    time_t offset, task_timer_func_t tjob, void_t data)
{
    utime_t itv, otv;
    utime_t *itvp, *otvp;

    if (interval > 0) {
	itvp = &itv;
	itv.ut_sec = (long) interval;
	itv.ut_usec = 0;
    } else {
	itvp = (utime_t *) 0;
    }

    if (offset > 0) {
	otvp = &otv;
	otv.ut_sec = (long) offset;
	otv.ut_usec = 0;
	} else if (BIT_TEST(flags, TIMERF_SHOTNOW)) {
			otvp = &otv;
			otv.ut_sec = (long) 0;
			otv.ut_usec = 0;
    } else {
	otvp = (utime_t *) 0;
    }

    return task_timer_ucreate(tp,
			      name,
			      flags,
			      itvp,
			      otvp,
			      (utime_t *) 0,
			      tjob,
			      data);
}


/*
 *	Delete a timer
 */
void
task_timer_delete(task_timer *tip)
{
    task *tp = tip->task_timer_task ? tip->task_timer_task : &task_head;

    trace_tp(tp,
	     TR_TIMER,
	     0,
	     ("task_timer_delete: %s <%s>",
	      task_timer_name(tip),
	      trace_bits(task_timer_flag_bits, tip->task_timer_flags)));

    if (BIT_TEST(tip->task_timer_flags, TIMERF_PROCESSING)) {
	BIT_SET(tip->task_timer_flags, TIMERF_DELETE);
    } else {
	/* Unlink it from it's task */
	if (tp->task_timers == tip) {
	    tp->task_timers = tip->task_timer_next;
	} else {
	    register task_timer *tip2;

	    for (tip2 = tp->task_timers; tip2->task_timer_next; tip2 = tip2->task_timer_next) {
		if (tip2->task_timer_next == tip) {
		    tip2->task_timer_next = tip->task_timer_next;
		    break;
		}
	    }
	}

	/* Unlink this timer from it's task */
	tip->task_timer_task = (task *) 0;

	/* Delete it */
	TIMER_DEQUEUE(tip);
	task_block_free(task_timer_block_index, (void_t) tip);
    }
}


/*
 *	Reset a timer - move it to the inactive queue
 */
void
task_timer_reset(task_timer *tip)
{
    task *tp = tip->task_timer_task ? tip->task_timer_task : &task_head;

    if (!BIT_TEST(tip->task_timer_flags, TIMERF_INACTIVE|TIMERF_RESET)) {
	tip->task_timer_jitter = 0;
	tip->task_timer_uinterval.ut_sec = tip->task_timer_uinterval.ut_usec = 0;
	if (BIT_TEST(tip->task_timer_flags, TIMERF_PROCESSING)) {
	    BIT_RESET(tip->task_timer_flags, TIMERF_SET);
	    BIT_SET(tip->task_timer_flags, TIMERF_RESET);
	} else {
	    TIMER_DEQUEUE(tip);
	    TIMER_ENQUEUE_IDLE(tip);
	}

	trace_tp(tp,
		 TR_TIMER,
		 0,
		 ("task_timer_reset: reset %s",
		  task_timer_name(tip)));
    }
}

/*
 *	Set (and possibly create) a timer
 */
void
task_timer_urestart(task_timer **ttpp, task *tp, const char *description,
    utime_t *interval, utime_t *offset, utime_t *jitter, task_timer_func_t fcn,
    void_t data)
{
	/* if no timer running, create one */
	if (!*ttpp) {
		*ttpp = task_timer_ucreate(tp, description, 
		    0, interval, offset, jitter, fcn, data);
	} else {
		/* set existing timer to new time */
		(*ttpp)->task_timer_data = data;
		task_timer_uset(*ttpp, offset, interval, jitter);
	}
}

/*
 *	Set (and possibly create) a timer
 */
void
task_timer_restart(task_timer **ttpp, task *tp, const char *description,
    time_t period, int offset, task_timer_func_t fcn, void_t data)
{
	/* if no timer running, create one */
	if (!*ttpp) {
		*ttpp = task_timer_create(tp, description, 
		    0, period, offset, fcn, data);
	} else {
		/* set existing timer to new time */
		(*ttpp)->task_timer_data = data;
		task_timer_set(*ttpp, period, offset);
	}
}

/*
 *	Set a timer to fire in offset/interval seconds from now
 */
void
task_timer_uset(task_timer *tip, utime_t *offset, utime_t *interval,
    utime_t *jitter)
{
    task *tp = tip->task_timer_task ? tip->task_timer_task : &task_head;

    if (interval) {
	tip->task_timer_uinterval = *interval;		/* struct copy */
	BIT_RESET(tip->task_timer_flags, TIMERF_ONESHOT);
    } else {
	tip->task_timer_uinterval.ut_sec = tip->task_timer_uinterval.ut_usec = 0;
	tip->task_timer_jitter = 0;
	if (offset) {
	    BIT_SET(tip->task_timer_flags, TIMERF_ONESHOT);
	} else {
	    trace_tp(tp,
		     TR_TIMER,
		     0,
		     ("task_timer_uset: resetting %s",
		      task_timer_name(tip)));
	    task_timer_reset(tip);
	    return;
	}
    }

    /* Allow jitter to be no bigger than half the interval */
    if (jitter && !BIT_TEST(tip->task_timer_flags, TIMERF_ONESHOT)) {
	if (jitter->ut_sec >= TIMER_MAX_JITTER) {
	    tip->task_timer_jitter = (TIMER_MAX_JITTER * 2000000);
	} else {
	    tip->task_timer_jitter = (jitter->ut_sec * 2000000) + (jitter->ut_usec << 1);
	}

	if (tip->task_timer_uinterval.ut_sec <= (TIMER_MAX_JITTER * 2)) {
	    time_t intvl = tip->task_timer_uinterval.ut_sec * 100000
			 + tip->task_timer_uinterval.ut_usec;
	    if (intvl < tip->task_timer_jitter) {
		tip->task_timer_jitter = intvl;
	    }
	}
    } else {
	tip->task_timer_jitter = 0;
    }

    if (BIT_TEST(tip->task_timer_flags, TIMERF_PROCESSING)) {
	BIT_RESET(tip->task_timer_flags, TIMERF_RESET);
	/* Timer being processed, only compute timeout */
	tip->task_timer_last_utime = utime_current;		/* struct copy */
	if (offset) {
	    tip->task_timer_next_utime = utime_current;	/* struct copy */
	    TIMER_ADD(&tip->task_timer_next_utime, offset);
	    BIT_SET(tip->task_timer_flags, TIMERF_SET);
	} else {
	    BIT_RESET(tip->task_timer_flags, TIMERF_SET);
	}
    } else {
	/* If this timer is on queue, set the intervals and requeue */
	tip->task_timer_next_utime = utime_current; 		/* struct copy */
	if (offset) {
	    TIMER_ADD(&tip->task_timer_next_utime, offset);
	    tip->task_timer_last_utime = tip->task_timer_next_utime;	/* struct copy */
	} else {
	    tip->task_timer_last_utime = utime_current;	/* struct copy */
	    TIMER_ADD(&tip->task_timer_next_utime, interval);
	}
	TIMER_DEQUEUE(tip);
	TIMER_ENQUEUE(tip);
    }

    if (TRACE_TP(tp, TR_TIMER)) {
	tracef("task_timer_uset: timer %s <%s> set to",
		       task_timer_name(tip),
		       trace_bits(task_timer_flag_bits, tip->task_timer_flags));
	if (tip->task_timer_uinterval.ut_sec || tip->task_timer_uinterval.ut_usec) {
	    tracef(" interval %#t",
		   &tip->task_timer_uinterval);
	}
	if (offset) {
	    tracef(" offset %#t",
		   offset);
	}
	if (tip->task_timer_jitter) {
	    utime_t tv;

	    tv.ut_sec = 0;
	    tv.ut_usec = tip->task_timer_jitter;
	    tracef(" jitter %#t",
		   &tv);
	}
	trace_only_tp(tp,
		      TR_TIMER,
		      (" at %t",
		       &tip->task_timer_next_utime));
    }
}

/*
 * Backward compatability routine
 */
void
task_timer_set(task_timer *tip, time_t interval, time_t offset)
{
	utime_t itv, otv;
	utime_t *itvp = &itv;
	utime_t *otvp = &otv;

	if (offset == 0 && !BIT_TEST(tip->task_timer_flags, TIMERF_SHOTNOW)) {
		otvp = (utime_t *) 0;
	} else {
		otv.ut_sec = offset;
		otv.ut_usec = 0;
	}

	if (interval == 0) {
		itvp = (utime_t *)0;
	} else {
		itv.ut_sec = interval;
		itv.ut_usec = 0;
	}

	task_timer_uset(tip, otvp, itvp, (utime_t *) 0);
}

/*
 *	Set a timer to fire in interval seconds from the last time it fired
 */
void
task_timer_set_uinterval(task_timer *tip, utime_t *interval)
{
    task *tp = tip->task_timer_task ? tip->task_timer_task : &task_head;
    int requeue = 0;

    if (BIT_TEST(tip->task_timer_flags, TIMERF_ONESHOT|TIMERF_INACTIVE)) {
	if (interval) {
	    BIT_RESET(tip->task_timer_flags, TIMERF_ONESHOT);
	    tip->task_timer_uinterval = *interval;			/* struct copy */
	    if (BIT_TEST(tip->task_timer_flags, TIMERF_INACTIVE)) {
		tip->task_timer_last_utime = utime_current;		/* struct copy */
		tip->task_timer_next_utime = utime_current;		/* struct copy */
		requeue = 1;
	    }
	} else {
	    trace_tp(tp,
		     TR_TIMER,
		     0,
		     ("task_timer_uinterval: no interval set on %s",
		      task_timer_name(tip)));
	    return;
	}
    } else {
	if (interval) {
	    tip->task_timer_uinterval = *interval;			/* struct copy */
	    if (!BIT_TEST(tip->task_timer_flags, TIMERF_PROCESSING)) {
		tip->task_timer_next_utime = tip->task_timer_last_utime;
		requeue = 1;
	    }
	    /* Allow jitter to be no bigger than half the interval */
	    if (tip->task_timer_jitter != 0) {
		if (interval->ut_sec <= (TIMER_MAX_JITTER * 2)) {
		    time_t intvl = tip->task_timer_uinterval.ut_sec * 100000
				 + tip->task_timer_uinterval.ut_usec;
		    if (intvl < tip->task_timer_jitter) {
		        tip->task_timer_jitter = intvl;
		    }
		}
	    }
	} else {
	    trace_tp(tp,
		     TR_TIMER,
		     0,
		     ("task_timer_uinterval: resetting %s",
		      task_timer_name(tip)));
	    task_timer_reset(tip);
	    return;
	}
    }

    if (requeue) {
	TIMER_ADD(&(tip->task_timer_next_utime), interval);
	TIMER_DEQUEUE(tip);
	TIMER_ENQUEUE(tip);
    }

    trace_tp(tp,
	     TR_TIMER,
	      0,
	      ("task_timer_uinterval: timer %s interval set to %#t at %t",
	       task_timer_name(tip),
	       &(tip->task_timer_uinterval),
	       &(tip->task_timer_next_time)));
}

/*
 * For backwards compatability
 */
void
task_timer_set_interval(task_timer *tip, time_t interval)
{
    utime_t ut;

    if (interval > 0) {
	ut.ut_sec = interval;
	ut.ut_usec = 0;
	task_timer_set_uinterval(tip, &ut);
    } else {
	task_timer_set_uinterval(tip, (utime_t *) 0);
    }
}


/*
 *	Dump the specified timer
 */
static void
task_timer_dump(FILE *fd, task_timer *tip)
{
    (void) fprintf(fd, "\t\t%s",
		   task_timer_name(tip));
    if (tip->task_timer_flags) {
	(void) fprintf(fd, "\t<%s>",
		       trace_bits(task_timer_flag_bits, tip->task_timer_flags));
    }
    if (!BIT_TEST(tip->task_timer_flags, TIMERF_INACTIVE)) {
	(void) fprintf(fd, "\n\t\t\tlast: %.3t\tnext: %.3t",
		       &tip->task_timer_last_utime,
		       &tip->task_timer_next_utime);
	if (tip->task_timer_uinterval.ut_sec || tip->task_timer_uinterval.ut_usec) {
	    (void) fprintf(fd, "\tinterval: %#t",
		       &tip->task_timer_uinterval);
	}
	if (tip->task_timer_jitter) {
	    (void) fprintf(fd, "\tjitter: %u",
		       tip->task_timer_jitter);
	}
	(void) fprintf(fd, "\n");
    } else {
	(void) fprintf(fd, "\n");
    }
}


/*
 * task_timer_dispatch() is called to run one of the timer queues
 */
static int
task_timer_dispatch(task_timer *queue, int hiprio, u_int n)
{
    int processed = 0;
    register task_timer *tip;

    assert(n);
    /*
     * Run the queue, running all expired entries and reevaluating
     * their next expiry time.
     */
    tip = queue->task_timer_forw;
    if (tip == queue) {
	trace_tf(trace_global,
		 TR_TIMER,
		 0,
		 ("task_timer_dispatch: no timers queued on %s queue!",
		  (hiprio ? "high priority" : "normal priority")));
	return 0;
    }

    do {
	register task *task_save = (task *) 0;
	trace *trp = tip->task_timer_task ? tip->task_timer_task->task_trace : trace_global;

	/* If this guy's time hasn't come, we're done */
	if (tip->task_timer_next_time > time_sec
	    || (tip->task_timer_next_time == time_sec
		&& tip->task_timer_next_utime.ut_usec > utime_current.ut_usec)) {
	    break;
	}

	/* Log this if we're doing that */
	if (TRACE_TF(trp, TR_TIMER)) {
	    utime_t tv;

	    tv = utime_current;			/* struct copy */
	    if (tv.ut_usec < tip->task_timer_next_utime.ut_usec) {
		tv.ut_usec += 1000000;
		tv.ut_sec--;
	    }
	    tv.ut_sec -= tip->task_timer_next_utime.ut_sec;
	    tv.ut_usec -= tip->task_timer_next_utime.ut_usec;

	    trace_only_tf(trp,
			  0,
			  ("task_timer_dispatch: calling %s, late by %#.3t",
			   task_timer_name(tip),
			   &tv));
	}

	/* Change the active task pointer to point at the timer's task */
	if (tip->task_timer_task) {
	    task_save = task_active;
	    task_active = tip->task_timer_task;
	}

	/* Run the timer routine */
	BIT_SET(tip->task_timer_flags, TIMERF_PROCESSING);
	tip->task_timer_job(tip, tip->task_timer_uinterval.ut_sec);
	BIT_RESET(tip->task_timer_flags, TIMERF_PROCESSING);
	processed++;

	if (!hiprio) {
	    TIMER_UPDATE();
	}

	/*
	 * Reset the trace pointer, it may have changed
	 */
	trp = tip->task_timer_task ? tip->task_timer_task->task_trace : trace_global;

	/* Put the active task pointer back the way it was */
	if (task_save) {
	    task_active = task_save;
	    task_save = (task *) 0;
	}

	/* Figure out what to do with the task_timer */
	if (BIT_TEST(tip->task_timer_flags, TIMERF_DELETE)) {
	    /* Timer got deleted */

	    trace_tf(trp,
		     TR_TIMER,
		     0,
		     ("task_timer_dispatch: returned from %s, deletion requested",
		      task_timer_name(tip)));
	    task_timer_delete(tip);
	    continue;
	}
	if (BIT_TEST(tip->task_timer_flags, TIMERF_RESET)
	    || BIT_COMPARE(tip->task_timer_flags, TIMERF_ONESHOT|TIMERF_SET, TIMERF_ONESHOT)) {
	    /* Timer going idle */
	    BIT_RESET(tip->task_timer_flags, TIMERF_RESET);
	    tip->task_timer_last_utime = utime_current;		/* struct copy */
	    TIMER_DEQUEUE(tip);
	    TIMER_ENQUEUE_IDLE(tip);
	    trace_tf(trp,
		     TR_TIMER,
		     0,
		     ("task_timer_dispatch: returned from %s, timer now inactive",
		      task_timer_name(tip)));
	    continue;
	}

	if (BIT_TEST(tip->task_timer_flags, TIMERF_SET)) {
	    BIT_RESET(tip->task_timer_flags, TIMERF_SET);
	} else if (tip->task_timer_jitter != 0) {
	    u_int32 jitter = grand((u_int32) tip->task_timer_jitter);
	    u_int32 jitter_sec = 0;

	    if (jitter >= 2000000) {
		if (jitter >= 4000000) {
		    jitter_sec = jitter / 2000000;
		    jitter %= 2000000;
		} else {
		    jitter_sec = 1;
		    jitter -= 2000000;
		}
	    }

	    tip->task_timer_next_utime = tip->task_timer_last_utime = utime_current;	/* struct copy */
	    TIMER_ADD(&(tip->task_timer_next_utime), &(tip->task_timer_uinterval));
	    if (BIT_TEST(tip->task_timer_flags, TIMERF_SUBJITTER) || (jitter & 0x01)) {
		/*
		 * Subtract jitter off
		 */
		jitter >>= 1;
		if ((u_int32)tip->task_timer_next_utime.ut_usec < jitter) {
		    tip->task_timer_next_utime.ut_sec -= 1;
		    tip->task_timer_next_utime.ut_usec += 1000000;
		}
		tip->task_timer_next_utime.ut_usec -= jitter;
		tip->task_timer_next_utime.ut_sec -= jitter_sec;
	    } else {
		/*
		 * Add jitter in
		 */
		jitter >>= 1;
		tip->task_timer_next_utime.ut_sec += jitter_sec;
		tip->task_timer_next_utime.ut_usec += jitter;
		if (tip->task_timer_next_utime.ut_usec >= 1000000) {
		    tip->task_timer_next_utime.ut_usec -= 1000000;
		    tip->task_timer_next_utime.ut_sec += 1;
		}
	    }
	} else {
	    /* Normal interval, add it to last but don't run timer twice */
	    tip->task_timer_last_utime = tip->task_timer_next_utime;			/* struct copy */
	    do {
		TIMER_ADD(&(tip->task_timer_next_utime), &(tip->task_timer_uinterval));
	    } while (tip->task_timer_next_utime.ut_sec < utime_current.ut_sec
	      || (tip->task_timer_next_utime.ut_sec == utime_current.ut_sec
	        && tip->task_timer_next_utime.ut_usec <= utime_current.ut_usec));
	}

	if (TRACE_TF(trp, TR_TIMER)) {
	    utime_t tv;

	    tv = tip->task_timer_next_utime;			/* struct copy */
	    tv.ut_sec -= utime_current.ut_sec;
	    if (tv.ut_usec < utime_current.ut_usec) {
		tv.ut_usec += 1000000;
		tv.ut_sec -= 1;
	    }
	    tv.ut_usec -= utime_current.ut_usec;

	    trace_only_tf(trp,
			  0,
			  ("task_timer_dispatch: returned from %s, rescheduled in %#.3t",
			   task_timer_name(tip),
			   &tv));
	}

	/* Requeue the timer if necessary */
	if (tip->task_timer_forw == queue) {
	    break;
	} else {
	    register task_timer *tip_next = tip->task_timer_forw;

	    if (tip->task_timer_next_utime.ut_sec < tip_next->task_timer_next_utime.ut_sec
	      || (tip->task_timer_next_utime.ut_sec == tip_next->task_timer_next_utime.ut_sec
	      && tip->task_timer_next_utime.ut_usec <= tip_next->task_timer_next_utime.ut_usec)) {
		break;
	    } else {
		tip->task_timer_back->task_timer_forw = tip->task_timer_forw;
		tip->task_timer_forw->task_timer_back = tip->task_timer_back;
		for (tip_next = tip_next->task_timer_forw;
		     tip_next != queue;
		     tip_next = tip_next->task_timer_forw) {
		    if (tip->task_timer_next_utime.ut_sec < tip_next->task_timer_next_utime.ut_sec
			|| (tip->task_timer_next_utime.ut_sec == tip_next->task_timer_next_utime.ut_sec
			    && tip->task_timer_next_utime.ut_usec <= tip_next->task_timer_next_utime.ut_usec)) {
			break;
		    }
		}

		/* Insert timer before tip_next */
		tip->task_timer_forw = tip_next;
		tip->task_timer_back = tip_next->task_timer_back;
		tip->task_timer_back->task_timer_forw = tip;
		tip_next->task_timer_back = tip;
	    }
	}

	/* Check for count out */
	if ((--n) == 0) {
	    break;
	}
    } while ((tip = queue->task_timer_forw) != queue);

    /* Bookkeeping.  Remember the last time we ran this */
    queue->task_timer_last_utime = utime_current;		/* struct copy */

    return processed;
}


/*
 * task_timer_hiprio_dispatch() is called to dispatch the high priority timer queue
 */
void
task_timer_hiprio_dispatch(void)
{
    int processed;

    if (task_timer_hiprio_active == 0) {
	trace_tf(trace_global,
		 TR_TIMER,
		 LOG_WARNING,
		 ("task_timer_hiprio_dispatch: high priority timer misfire!"));
	return;
    }

    trace_tf(trace_global,
	     TR_TIMER,
	     0,
	     ("task_timer_hiprio_dispatch: running high priority timer queue"));

    processed = task_timer_dispatch(&task_timer_queue_hiprio,
				    TRUE,
				    TASK_SCHED_UNLIMITED);

    trace_tf(trace_global,
	     TR_TIMER,
	     0,
	     ("task_timer_hiprio_dispatch: ran %d timer%s",
	      processed,
	      ((processed == 1) ? "" : "s")));

    if (task_timer_hiprio_active > 0) {
	task_timer_hiprio_time = &(task_timer_queue_hiprio.task_timer_forw->task_timer_next_utime);
    } else {
	task_timer_hiprio_time = (utime_t *) 0;
    }
}


/*
 * task_time_bad() - called when gettimeofday()/getsystimes() fails.
 *			 Should never happen.
 */
void
task_time_bad(void)
{
#ifdef	HAVE_GETSYSTIMES
    trace_tf(trace_global,
	     TR_ALL,
	     LOG_ERR,
	     ("task_time_screwed: getsystimes() failed: %m"));
#else	/* HAVE_GETSYSTIMES */
    trace_tf(trace_global,
	     TR_ALL,
	     LOG_ERR,
	     ("task_time_screwed: gettimeofday() failed: %m"));
#endif	/* HAVE_GETSYSTIMES */
    assert(FALSE);
}


#ifndef	HAVE_GETSYSTIMES
/*
 * task_time_fix - recover after time-of-day change
 */
void
task_time_fix(time_t oldtime, utime_t *intervalp)
{
    register time_t t1, t2, oldboot;

    /*
     * This is really grotty, but hopefully will hold us through those
     * (rare) occasions when the clock is changed.  This is called
     * when we detect that the time has either gone backwards or
     * has gone forwards by more than TIMER_MAX_TIME seconds.  What
     * we do is rewrite our notion of the boot time to make it appear
     * that TIMER_FUDGE_TIME seconds have passed.
     */
    t1 = time_sec + time_boot;		/* original time-of-day */
    t2 = oldtime + TIMER_FUDGE_TIME;
    if (intervalp) {
	t2 += intervalp->ut_sec;
	if (intervalp->ut_usec >= 500000) {
	    t2++;
	}
    }

    oldboot = time_boot;
    time_boot = t1 - t2;
    time_sec = t2;
    if (task_mpid == task_pid) {
	/* Don't bitch in a child */
	
	trace_tf(trace_global,
		 TR_ALL,
		 LOG_WARNING,
		 ("task_time_fix: detected time change %s by %d seconds, fixed",
		  ((oldboot < time_boot) ? "forward" : "backward"),
		  ((oldboot > time_boot) ? (oldboot - time_boot) : (time_boot - oldboot))));
    }
}
#endif	/* HAVE_GETSYSTIMES */


/*
 * task_time_init - initialize the current notion of the system time
 */
static void
task_time_init(void)
{
    struct timeval cur;
    
    /* Fetch the current time */
#ifdef	HAVE_GETSYSTIMES
    struct timeval boot;
    
    if (getsystimes(&cur, &boot) != 0) {
	task_time_bad();
    }

    utime_boot.ut_sec = boot.tv_sec;
    utime_boot.ut_usec = boot.tv_usec;
    utime_current.ut_sec = cur.tv_sec;
    utime_current.ut_usec = cur.tv_usec;
#else	/* HAVE_GETSYSTIMES */

    if (gettimeofday(&cur, (struct timezone *) 0) != 0) {
	task_time_bad();
    }
    utime_current.ut_usec = cur.tv_usec;
    utime_boot.ut_sec = cur.tv_sec - 1;
    utime_boot.ut_usec = 0;
    utime_current.ut_sec = 1;
#endif	/* HAVE_GETSYSTIMES */

    task_time.gt_str_time = 0;
    task_timer_str_update();

    /* Save the gated start time */
    task_time_start = task_time;	/* struct copy */
}


/*  */

/* Job support */

#define	TR_JOB	TR_TASK

static task_job task_job_fg_queue = 
  { &task_job_fg_queue, &task_job_fg_queue, "Job Foreground Queue", (task *)0, 0 };
static int task_job_fg_queued = 0;		/* non-zero when jobs queued */

static task_job task_job_bg_queue = 
  { &task_job_bg_queue, &task_job_bg_queue, "Job Background Queue", (task *)0, TASK_JOB_FG };
static int task_job_bg_queued = 0;		/* non-zero when jobs queued */
static task_job *task_job_bg_prio[TASK_JOB_N_PRIO] = { 0 };	/* points at end of priority list */

static block_t task_job_block_index;		/* Block index for fetching new jobs */

#define	TASK_JOB_NAME(jp)	(((jp)->task_job_name) ? (jp)->task_job_name : "UNNAMED")


/*
 * task_job_create - create a job and queue it on the appropriate queue
 */
task_job *
task_job_create(task *tp, int priority, const char *name,
    task_job_func_t task_job_rtn, void_t data)
{
    register task_job *jp = (task_job *) task_block_alloc(task_job_block_index);
    register task_job *jtmp;

    jp->task_job_name = name;
    jp->task_job_task = tp;
    jp->task_job_job = task_job_rtn;
    jp->task_job_data = data;

    if (priority <= TASK_JOB_PRIO_WORST && priority >= TASK_JOB_PRIO_BEST) {
	/*
	 * This is a background job.  Find where to queue it and add it in.
	 */
	for (jtmp = task_job_bg_queue.task_job_back;
	     jtmp != &task_job_bg_queue;
	     jtmp = jtmp->task_job_back) {
	    if (jtmp->task_job_priority <= (byte) priority) {
		break;
	    }
	}
	INSQUE(jp, jtmp);
	task_job_bg_prio[priority] = jp;
	jp->task_job_priority = priority;
	task_job_bg_queued++;
    } else {
	/*
	 * Foreground job, just stick it at the end of the list.
	 */
	INSQUE(jp, task_job_fg_queue.task_job_back);
	jp->task_job_priority = TASK_JOB_FG;
	task_job_fg_queued++;
    }

    /* Done! */
    trace_tp(tp,
	     TR_JOB,
	     0,
	     ("task_job_create: create %s job %s for task %s",
	      ((jp->task_job_priority == TASK_JOB_FG) ? "foreground" : "background"),
	      TASK_JOB_NAME(jp),
	      task_name(tp)));
    return jp;
}


/*
 * task_job_delete - delete a job from one of the queues
 */
void
task_job_delete(task_job *jp)
{
    /*
     * If it is already deleted, don't do anything.  Otherwise pull
     * it from the queue and either mark it deleted or free the structure.
     */
    if (jp->task_job_forw != NULL) {
	trace_tp(jp->task_job_task,
		 TR_JOB,
		 0,
		 ("task_job_delete: delete %s job %s for task %s",
		  ((jp->task_job_priority == TASK_JOB_FG) ? "foreground" : "background"),
		   TASK_JOB_NAME(jp),
		   task_name(jp->task_job_task)));
	if (jp->task_job_priority != TASK_JOB_FG) {
	    /*
	     * Background job, extra bookkeeping.
	     */
	    if (task_job_bg_prio[jp->task_job_priority] == jp) {
		if (jp->task_job_back->task_job_priority == jp->task_job_priority) {
		    task_job_bg_prio[jp->task_job_priority] = jp->task_job_back;
		} else {
		    task_job_bg_prio[jp->task_job_priority] = NULL;
		}
	    }
	    task_job_bg_queued--;
	} else {
	    task_job_fg_queued--;
	}
	REMQUE(jp);
	if (jp->task_job_isactive) {
	    jp->task_job_forw = NULL;
	} else {
	    task_block_free(task_job_block_index, (void_t)jp);
	}
    } else {
	trace_tp(jp->task_job_task,
		 TR_JOB,
		 0,
		 ("task_job_delete: job %s for task %s already deleted",
		  ((jp->task_job_priority == TASK_JOB_FG) ? "foreground" : "background"),
		   TASK_JOB_NAME(jp),
		   task_name(jp->task_job_task)));
    }
}


/*
 * task_job_delete_task - delete all jobs from a given task, part of task cleanup
 */
static void
task_job_delete_task(task *tp)
{
    task_job *jp, *jpnext;
    int nbg = 0;
    int nfg = 0;

    trace_tp(tp,
	     TR_JOB,
	     0,
	     ("task_job_delete_task: deleting all jobs for task %s",
	       task_name(tp)));

    for (jp = task_job_bg_queue.task_job_forw; jp != &task_job_bg_queue; jp = jpnext) {
	jpnext = jp->task_job_forw;
	if (jp->task_job_task == tp) {
	    task_job_delete(jp);
	    nbg++;
	}
    }

    for (jp = task_job_fg_queue.task_job_forw; jp != &task_job_fg_queue; jp = jpnext) {
	jpnext = jp->task_job_forw;
	if (jp->task_job_task == tp) {
	    task_job_delete(jp);
	    nfg++;
	}
    }

    if (nfg == 0 && nbg == 0) {
	trace_tp(tp,
		 TR_JOB,
		 0,
		 ("task_job_deleted_task: no jobs found for task %s",
		  task_name(tp)));
    } else {
	trace_tp(tp,
		 TR_JOB,
		 0,
		 ("task_job_delete_task: deleted %d/%d jobs for task %s",
		  nfg,
		  nbg,
		  task_name(tp)));
    }
}


/*
 * task_job_fg_dispatch - run all foreground jobs on the queue
 */
static void
task_job_fg_dispatch(void)
{
    task_job *jp;

    for (jp = task_job_fg_queue.task_job_forw;
	 jp != &task_job_fg_queue;
	 jp = task_job_fg_queue.task_job_forw) {

	REMQUE(jp);
	jp->task_job_forw = NULL;
	task_job_fg_queued--;

	trace_tp(jp->task_job_task,
		 TR_JOB,
		 0,
		 ("task_job_fg_dispatch: running foreground job %s for task %s",
		  TASK_JOB_NAME(jp),
		  task_name(jp->task_job_task)));

	jp->task_job_isactive = 1;
	jp->task_job_job(jp);

	trace_tp(jp->task_job_task,
		 TR_JOB,
		 0,
		 ("task_job_fg_dispatch: completed foreground job %s for task %s",
		  TASK_JOB_NAME(jp),
		  task_name(jp->task_job_task)));

	task_block_free(task_job_block_index, (void_t)jp);
    }

    assert(task_job_fg_queued == 0);
}


/*
 * task_job_bg_dispatch - run the top background job on the queue
 */
static void
task_job_bg_dispatch(void)
{
    task_job *jp;

    jp = task_job_bg_queue.task_job_forw;
    if (jp == &task_job_bg_queue) {
	assert(task_job_bg_queued == 0);
	return;
    }

    /*
     * Got one, run it first and see if it deletes itself.
     */
    trace_tp(jp->task_job_task,
	     TR_JOB,
	     0,
	     ("task_job_bg_dispatch: running background job %s for task %s",
	      TASK_JOB_NAME(jp),
	      task_name(jp->task_job_task)));

    jp->task_job_isactive = 1;
    jp->task_job_job(jp);

    trace_tp(jp->task_job_task,
	     TR_JOB,
	     0,
	     ("task_job_bg_dispatch: background job %s for task %s %s",
	      TASK_JOB_NAME(jp),
	      task_name(jp->task_job_task),
	      ((jp->task_job_forw == NULL) ? "completed" : "returned")));

    if (jp->task_job_forw == NULL) {
	/*
	 * Gone, get rid of structure.
	 */
	task_block_free(task_job_block_index, (void_t)jp);
    } else {
	/*
	 * Still here, drop below tasks at same priority.
	 */
	if (task_job_bg_prio[jp->task_job_priority] != jp) {
	    REMQUE(jp);
	    INSQUE(jp, task_job_bg_prio[jp->task_job_priority]);
	    task_job_bg_prio[jp->task_job_priority] = jp;
	}
	jp->task_job_isactive = 0;
    }
}


/*
 * task_job_run - force a particular job to run, used when a job can no
 *	     longer be deferred
 */
void
task_job_run(task_job *jp)
{
    assert(!(jp->task_job_isactive));

    /*
     * If it is a foreground job, remove it from the queue now
     */
    if (jp->task_job_priority == TASK_JOB_FG) {
	REMQUE(jp);
	jp->task_job_forw = NULL;
	task_job_fg_queued--;
    }

    trace_tp(jp->task_job_task,
	     TR_JOB,
	     0,
	     ("task_job_run: forcing %s job %s to run for task %s",
	      ((jp->task_job_priority == TASK_JOB_FG) ? "foreground" : "background"),
	      TASK_JOB_NAME(jp),
	      task_name(jp->task_job_task)));

    jp->task_job_isactive = 1;
    jp->task_job_job(jp);

    trace_tp(jp->task_job_task,
	     TR_JOB,
	     0,
	     ("task_job_run: %s job %s for task %s %s",
	      ((jp->task_job_priority == TASK_JOB_FG) ? "foreground" : "background"),
	      TASK_JOB_NAME(jp),
	      task_name(jp->task_job_task),
	      ((jp->task_job_forw == NULL) ? "completed" : "returned")));

    if (jp->task_job_forw == NULL) {
	/*
	 * Gone, get rid of structure.
	 */
	task_block_free(task_job_block_index, (void_t)jp);
    } else {
	/*
	 * Still here, drop below tasks at same priority.
	 */
	if (task_job_bg_prio[jp->task_job_priority] != jp) {
	    REMQUE(jp);
	    INSQUE(jp, task_job_bg_prio[jp->task_job_priority]);
	    task_job_bg_prio[jp->task_job_priority] = jp;
	}
	jp->task_job_isactive = 0;
    }
}


static void
task_job_dump(FILE *fd, task_job *jp)
{
    task *tp = jp->task_job_task;

    if (jp->task_job_priority == TASK_JOB_FG) {
	(void) fprintf(fd, "\t\t%s_%s\n",
		       task_name(tp),
		       TASK_JOB_NAME(jp));
    } else {
	(void) fprintf(fd, "\t\t%s_%s priority %u\n",
		       task_name(tp),
		       TASK_JOB_NAME(jp),
		       jp->task_job_priority);
    }
}
/*  */

#define	TASK_SAVE(tp, s)		{ task *task_save = task_active; task_active = tp; s; task_active = task_save; }


const bits task_socket_types[] =
{
#ifdef	SOCK_STREAM
    {SOCK_STREAM, "STREAM"},
#endif	/* SOCK_STREAM */
#ifdef	SOCK_DGRAM
    {SOCK_DGRAM, "DGRAM"},
#endif	/* SOCK_DGRAM */
#ifdef	SOCK_RAW
    {SOCK_RAW, "RAW"},
#endif	/* SOCK_RAW */
#ifdef	SOCK_RDM
    {SOCK_RDM, "RDM"},
#endif	/* SOCK_RDB */
#ifdef	SOCK_SEQPACKET
    {SOCK_SEQPACKET, "SEQPACKET"},
#endif	/* SOCK_SEQPACKET */
    { 0, NULL }
};


const bits task_domain_bits[] =
{
#ifdef	AF_UNSPEC
    {AF_UNSPEC, "UNSPEC"},
#endif	/* AF_UNSPEC */
#ifdef	AF_UNIX
    {AF_UNIX, "UNIX"},
#endif	/* AF_UNIX */
#ifdef	AF_INET
    {AF_INET, "INET"},
#endif	/* AF_INET */
#ifdef	AF_ISO
    {AF_ISO, "ISO"},
#endif	/* AF_ISO */
#ifdef	AF_ROUTE
    {AF_ROUTE, "Route"},
#endif	/* AF_ROUTE */
#ifdef	AF_LINK
    {AF_LINK, "LINK"},
#endif	/* AF_LINK */
#ifdef	AF_NIT
    {AF_NIT, "NIT"},
#endif	/* AF_NIT */
#ifdef  AF_IPX
  {AF_IPX, "IPX"},
#endif
#ifdef  AF_IPXSERV
  {AF_IPXSERV, "IPXSERV"},
#endif
#ifdef	AF_INET6
    {AF_INET6, "INET6"},
#endif
    { 0, NULL }
};

/**/

static int task_pid_fd = -1;

/* Write and lock PID file */
void
task_pid_open(void)
{
    char path_pid[MAXPATHLEN];

    /* Open, lock and update the PID file */

    /* Try to open it */
#ifndef	O_SYNC
#define	O_SYNC	0
#endif	/* O_SYNC */
    (void) sprintf(path_pid, _PATH_PID, task_progname);
    task_pid_fd = task_floating_socket((task *) 0,
				       open(path_pid, O_RDWR | O_CREAT | O_SYNC, 0644),
				       path_pid);
    if (task_pid_fd < 0) {
	int error = errno;

	trace_log_tf(trace_global,
		     0,
		     LOG_ERR,
		     ("Could not open %s: %m",
		      path_pid));

	task_quit(error);
    } else {
	size_t len;
	char buf[LINE_MAX];
	
	/* Try to lock it */
	if (flock(task_pid_fd, LOCK_EX|LOCK_NB) < 0) {
	    int error = errno;
	    int pid;

	    switch (error) {
	    case EWOULDBLOCK:
#if	defined(EAGAIN) && EAGAIN != EWOULDBLOCK
	    case EAGAIN:		/* System V style */
#endif	/* EAGAIN */
		len = read(task_pid_fd, buf, sizeof buf);
		if (len > 0 &&
		    (pid = atoi(buf))) {

		    /* Announce PID of gated already running */

		    trace_log_tf(trace_global,
				 0,
				 LOG_ERR,
				 ("Could not obtain a lock on %s, %s[%d] is still running!",
				  path_pid,
				  task_progname,
				  pid));
		} else {
		    trace_log_tf(trace_global,
				 0,
				 LOG_ERR,
				 ("Could not obtain a lock on %s, is another copy of gated running!",
				  path_pid));
		}
		break;

	    default:
		trace_log_tf(trace_global,
			     0,
			     LOG_ERR,
			     ("flock(%s, LOCK_EX): %m",
			      path_pid));
	    }
	    (void) close(task_pid_fd);
	    task_pid_fd = -1;
	    task_quit(error);
	}

	len = sprintf(buf, "%d\n",
		      task_pid);

#ifndef	SEEK_SET
#define	SEEK_SET	L_SET
#endif	/* SEEK_SET */
	/* Back up to the beginning and truncate the file */
	if (lseek(task_pid_fd, (off_t) 0, SEEK_SET) < 0
	    || ftruncate(task_pid_fd, (off_t) 0) < 0
	    || (size_t)write(task_pid_fd, buf, len) != len) {
	    int error = errno;

	    trace_log_tf(trace_global,
			 0,
			 LOG_ERR,
			 ("Could not write %s: %m",
			  path_pid));

	    task_quit(error);
	}

	/* Leave the file open to retain the lock */
    }

    {
	FILE *fp;
	
	/* Write version file */
	(void) sprintf(path_pid, _PATH_VERSION, task_progname);
	fp = fopen(path_pid, "w");
	if (fp) {
	    (void) fprintf(fp, "%s version %s built %s\n\tpid %d, started %s",
			   task_progname,
			   gated_version,
			   build_date,
			   task_pid,
			   time_full);
	    (void) fclose(fp);
	}
    }
}

/* Close the PID file */
static void
task_pid_close(void)
{
    char path_pid[MAXPATHLEN];

    (void) sprintf(path_pid, _PATH_PID, task_progname);
    if (task_pid_fd > -1) {
	if (close(task_pid_fd) == -1
	    || unlink(path_pid) == -1) {
	    trace_log_tf(trace_global,
			 0,
			 LOG_ERR,
			 ("Could not close and remove %s: %m",
			  path_pid));
	}
	task_pid_fd = -1;
    }
}


/**/
/* Exit gated */

void
task_quit(int code)
{
    /* Figure out what time it is */
    task_timer_peek();

    /* If the main process -- remove the PID file */
    if (task_pid == task_mpid)
	task_pid_close();
    
    trace_only_tf(trace_global,
		  0,
		  (NULL));

    switch (code) {
    case 0:
    case EDESTADDRREQ:
    case ENOENT:
        tracef("Exit %s:\n\t\tVersion %s built %s\n\t\tPid %d, started %s",
               task_progname,
                   gated_version,
                   build_date,
                   task_pid,
                   time_full);
	if (code) {
	    errno = code;
	    tracef(": %m");
	}	
	trace_log_tf(trace_global,
		     TRC_NL_AFTER,
		     LOG_NOTICE,
		     (NULL));
	trace_close_all();
	break;

    default:
	errno = code;
	trace_log_tf(trace_global,
		     TRC_NL_AFTER,
		     LOG_NOTICE,
				 ("Abort %s:\n\t\tVersion %s built %s\n\t\tPid %d, started %s",
				  task_progname,
				  gated_version,
				  build_date,
				  task_pid,
				  time_full));
	trace_close_all();
	abort();
	break;
    };

    exit(code);
}


void
task_assert(const char *file, const int line, const char *test)
{
    /* Figure out what time it is */
    task_timer_peek();

    /* Let them know what happened */
    trace_log_tf(trace_global,
		 TRC_NL_BEFORE|TRC_NL_AFTER,
		 LOG_ERR,
		 ("Assertion failed %s[%d]: file \"%s\", line %d: \"%s\"",
		  task_progname,
		  task_pid,
		  file,
		  line,
		  test));

    /* Exit with a core dump */
    task_quit(EINVAL);
}


/* Change state */
void
task_newstate(flag_t set, flag_t reset)
{
    flag_t state = (task_state & ~reset) | set;
    
    tracef("task_newstate: State change from <%s>",
	   trace_bits(task_state_bits, task_state));
    trace_tf(trace_global,
	     TR_TASK,
	     0,
	     (" to <%s>",
	      trace_bits(task_state_bits, state)));

    task_state = state;
}


/*
 *	Call the reinit routine for each task
 */
static void
task_reinit(void)
{
    task *tp;
    
    trace_tf(trace_global,
	     TR_TASK,
	     0,
	     (NULL));
    TASK_TABLE(tp) {
	if (tp->task_reinit_method) {
	    trace_tf(trace_global,
		     TR_TASK,
		     0,
		     ("task_reinit: Starting reinit for task %s",
		      task_name(tp)));
	    TASK_SAVE(tp, tp->task_reinit_method(tp));
	    TIMER_UPDATE();
	    trace_tf(trace_global,
		     TR_TASK,
		     0,
		     ("task_reinit: Finished reinit for task %s",
		      task_name(tp)));
	}
    } TASK_TABLE_END(tp);
}

/*
 *	Call the reinit_finalize routine for each task
 */
static void
task_reinit_finalize (void)
{
    task *tp;
    
    trace_tf(trace_global,
	     TR_TASK,
	     0,
	     (NULL));
    TASK_TABLE(tp) {
	if (tp->task_reinit_finalize_method) {
	    trace_tf(trace_global,
		     TR_TASK,
		     0,
		     ("task_reinit_finalize: Starting reinit for task %s",
		      task_name(tp)));
	    TASK_SAVE(tp, tp->task_reinit_finalize_method(tp));
	    TIMER_UPDATE();
	    trace_tf(trace_global,
		     TR_TASK,
		     0,
		     ("task_reinit_finalize: Finished reinit for task %s",
		      task_name(tp)));
	}
    } TASK_TABLE_END(tp);
}


/*
 *	Return a pointer to a string containing the task name
 */
char *
task_name(task *tp)
{
    static char name[MAXHOSTNAMELENGTH];

    if (!tp) {
	(void) strcpy(name, "(null task)");
    } else if (BIT_TEST(tp->task_flags, TASKF_DELETE)) {
	(void) sprintf(name, "%s (DELETED)",
		       tp->task_name);
    } else {
	if (tp->task_addr) {
	    (void) sprintf(name, "%s.%#A",
			   tp->task_name,
			   tp->task_addr);
	} else {
	    (void) strcpy(name, tp->task_name);
	}
	
	if (tp->task_pid > 0) {
	    (void) sprintf(&name[strlen(name)], "[%d]",
			   tp->task_pid);
	}
    }
    
    return name;
}


/*
 *	Locate a task with the given address
 */
task *
task_locate(const char *name, sockaddr_un *addr)
{
    task *tp;

    TASK_TABLE(tp) {
	if (!strcmp(name, tp->task_name)
	    && (!tp->task_addr
		|| sockaddrcmp(addr, tp->task_addr))) {
	    /* Found it */

	    return tp;
	}
    } TASK_TABLE_END(tp) ;

    return (task *) 0;
}


/*
 *	Receive packet and check for errors
 */
int
task_receive_packet(task *tp, size_t *count)
{
    register int rc;
    byte buf[BUFSIZ];
#ifdef	USE_MSGHDR_CONTROLFIELDS
    caddr_t bp = (caddr_t) buf;
    static struct iovec iovec;
    static struct msghdr msghdr = {
						0, 0,		/* Address and length of received address */
						&iovec, 1,	/* Address and length of buffer runtime */
						NULL, 0		/* Address and length of access rights */
    };
#define	name	(struct sockaddr *) (void_t) msghdr.msg_name
#define	namelen	msghdr.msg_namelen

#else	/* USE_MSGHDR_CONTROLFIELDS */
    int buflen = BUFSIZ;
#define	name	(struct sockaddr *) (void_t) buf
#define	namelen	buflen

#endif	/* USE_MSGHDR_CONTROLFIELDS */

    if (task_recv_srcaddr) {
			sockfree(task_recv_srcaddr);
			task_recv_srcaddr = (sockaddr_un *) 0;
    }

    /* indicate we don't know the index yet */
    task_recv_if_index = 0;

#ifdef	USE_MSGHDR_CONTROLFIELDS
    iovec.iov_base = task_recv_buffer;
    iovec.iov_len = task_recv_buffer_len;

    /* Setup to receive address */
    msghdr.msg_name = bp;		/* Set pointer to address */
    msghdr.msg_namelen = 128;		/* Set max size */
    bp += msghdr.msg_namelen;
    bzero(msghdr.msg_name, msghdr.msg_namelen);	/* Clean address buffer */
    /* Setup to receive control information */
    msghdr.msg_control = bp;			/* Set max size */
    msghdr.msg_controllen = sizeof buf - (bp - (caddr_t) buf);	/* Set pointer to buffer */
    bzero(msghdr.msg_control, msghdr.msg_controllen);
    while ((rc = recvmsg(tp->task_socket, &msghdr, 0)) < 0) {
#else	/* USE_MSGHDR_CONTROLFIELDS */
    bzero(buf, (size_t) buflen);		/* Clean address buffer */

    while ((rc = recvfrom(tp->task_socket,
			  task_recv_buffer,
			  task_recv_buffer_len,
			  0,
			  name,
			  (void_t) &namelen)) < 0) {
#endif	/* USE_MSGHDR_CONTROLFIELDS */
	switch (errno) {
	case EINTR:
	    /* The call was interrupted, probably by a signal, */
	    /* silently retry it. */
	    break;
		
	case EHOSTUNREACH:
	case ENETUNREACH:
	    /* These errors are just an indication that an */
	    /* unreachable was received.  When an operation is */
	    /* attempted on a socket with an error pending */
	    /* it does not complete.  So we need to retry. */
	    trace_only_tp(tp,
			  0,
			  ("task_receive_packet: %s recvfrom/recvmsg: %m",
			   task_name(tp)));
	    break;
		
	default:
	    trace_log_tp(tp,
			 0,
			 LOG_ERR,
			 ("task_receive_packet: %s recvfrom/recvmsg: %m",
			  task_name(tp)));
	    /* Fall through */
	    
	case EWOULDBLOCK:
#if	defined(EAGAIN) && EAGAIN != EWOULDBLOCK
	case EAGAIN:		/* System V style */
#endif	/* EAGAIN */
	    /* Nothing to read */
	    *count = rc;
	    return errno;
	}
    }

    if (!rc) {
	return TASKRC_EOF;
    }

    if (namelen) {
	register sockaddr_un *addr = sock2gated(name, (size_t) namelen);
	
	task_recv_srcaddr = sockdup(addr);
    }

    *count = rc;
    
    if (task_recv_dstaddr) {
	sockfree(task_recv_dstaddr);
	task_recv_dstaddr = (sockaddr_un *) 0;
    }
    
#ifdef	USE_MSGHDR_CONTROLFIELDS
#define	ENOUGH_CMSG(cmsg, size)	((cmsg)->cmsg_len >= ((size) + sizeof(struct cmsghdr)))
    /* Look at the control information */
    if (msghdr.msg_controllen >= sizeof (struct cmsghdr)
	&& !BIT_TEST(msghdr.msg_flags, MSG_CTRUNC)) {
	struct cmsghdr *cmsg;
	
	for (cmsg = CMSG_FIRSTHDR(&msghdr);
	     cmsg && cmsg->cmsg_len >= sizeof (struct cmsghdr);
	     cmsg = CMSG_NXTHDR(&msghdr, cmsg)) {
	    switch (cmsg->cmsg_level) {
#ifdef	PROTO_INET
	    case IPPROTO_IP:
		switch (cmsg->cmsg_type) {
#ifdef IP_RECVDSTADDR
		case IP_RECVDSTADDR:
		    /* Destination address of the packet */

		    if (!ENOUGH_CMSG(cmsg, sizeof(struct in_addr))) {
			trace_log_tp(tp,
				     0,
				     LOG_ERR,
				     ("task_receive_packet: %s dest address from %#A truncated",
				      task_name(tp),
				      task_recv_srcaddr));
		    } else if (!task_recv_dstaddr) {
			task_recv_dstaddr = sockdup(sockbuild_in((u_short) 0,
								 ((struct in_addr *) CMSG_DATA(cmsg))->s_addr));
		    }
		    break;
#endif /* IP_RECVDSTADDR */
#ifdef  IP_RECVIF
    case IP_RECVIF:
        /* get the interface index */
        if (!ENOUGH_CMSG(cmsg, (offsetof(struct sockaddr_dl, sdl_index)
        + sizeof(u_int16)))) {
      trace_log_tp(tp,
             0,
             LOG_ERR,
             ("task_receive_packet: %s interface index from %#A truncated",
              task_name(tp),
              task_recv_srcaddr));
        } else
						task_recv_if_index =
								((struct sockaddr_dl *)CMSG_DATA(cmsg))->sdl_index;
        break;
#endif  /* IP_RECVIF */
		}
		break;
#endif	/* PROTO_INET */
#ifdef PROTO_INET6
		case IPPROTO_IPV6:
		    switch (cmsg->cmsg_type) {
#ifdef IPV6_PKTINFO
		    case IPV6_PKTINFO:
		        if (!ENOUGH_CMSG(cmsg, sizeof(struct in6_pktinfo))) {
			trace_log_tp(tp,
				     0,
				     LOG_ERR,
					 ("task_receive_packet: %s dest address from %#A truncated",
				      task_name(tp),
				      task_recv_srcaddr));
			} else {
			    task_recv_dstaddr =
			      sockdup(sockbuild_in6((u_short) 0,
						    ((byte *) &((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_addr)));
			    if (inet6_scope_of(task_recv_srcaddr) == INET6_SCOPE_LINKLOCAL) {
				task_recv_if_index = ((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_ifindex;
				task_recv_interface =
				  if_withindex(task_recv_if_index, INET6_SCOPE_LINKLOCAL);
			    } else {
			        task_recv_interface =
				  if_withlcladdr(sockbuild_in6((u_short) 0,
							       ((byte *)CMSG_DATA(cmsg))),
						 FALSE);
			    }
			}
		    break;
#else  /* !IPV6_PKTINFO */
#ifdef IPV6_RECVDSTADDR
		    case IPV6_RECVDSTADDR:
		        /* Destination address of the packet */
		        if (!ENOUGH_CMSG(cmsg, sizeof(struct in6_addr))) {
			    trace_log_tp(tp,
					 0,
					 LOG_ERR,
					 ("task_receive_packet: %s dest address from %#A truncated",
					  task_name(tp),
					  task_recv_srcaddr));
			} else {
			    task_recv_dstaddr = 
			      sockdup(sockbuild_in6((u_short) 0,
						    ((byte *) CMSG_DATA(cmsg))));
		}
		break;
#endif /* IPV6_RECVDSTADDR */
#ifdef IPV6_RECVIF
		    case IPV6_RECVIF:
		        /* received interface of the packet */
		        if (!ENOUGH_CMSG(cmsg, sizeof(struct in6_addr))) {
			    trace_log_tp(tp,
					 0,
					 LOG_ERR,
					 ("task_receive_packet: %s dest address from %#A truncated",
					  task_name(tp),
					  task_recv_srcaddr));
			} else {
			    task_recv_interface =
			      if_withlcladdr(sockbuild_in6((u_short) 0,
							   ((byte *)CMSG_DATA(cmsg))),
					     FALSE);
			}
			break;
#endif /* IPV6_RECVIF */
#endif /* IPV6_PKTINFO */
		    }
#endif /* PROTO_INET6 */
	    }
	}
#undef	ENOUGH_CMSG

    }
    if (BIT_TEST(msghdr.msg_flags, MSG_TRUNC)) {
	/* Packet truncated */
	    
	trace_log_tp(tp,
		     0,
		     LOG_ERR,
		     ("task_receive_packet: %s packet from %#A socket %d truncated",
		      task_name(tp),
		      task_recv_srcaddr,
		      tp->task_socket));
	return TASKRC_TRUNC;
    }
#endif	/* USE_MSGHDR_CONTROLFIELDS */

    if (TRACE_TP(tp, TR_TASK)) {
	tracef("task_receive_packet: task %s ",
	       task_name(tp));

	if (task_recv_srcaddr) {
	    tracef("from %#A ",
		   task_recv_srcaddr);
	}

	if (task_recv_dstaddr) {
	    tracef("to %A ",
		   task_recv_dstaddr);
	}
	
	trace_tp(tp,
		 TR_TASK,
		 0,
		 ("socket %d length %d",
		  tp->task_socket,
		  rc));
    }

    return TASKRC_OK;

#undef	name
#undef	namelen
}

/*
 * number of times to retry sending
 */
#define	SEND_RETRIES	5


#ifdef HAVE_SENDMSG
/*
 * Send a packet, returns number of bytes sent.
 */
int
task_send_packet_iov(task *tp, struct iovec *iovp, int niov, flag_t flags,
    sockaddr_un *addr)
{
	int err;

	return(task_send_packet_iov_err(tp, iovp, niov, flags, addr, &err));
}

/*
 * Send a packet, returns number of bytes sent. as well as error code!
 */
int
task_send_packet_iov_err(task *tp, struct iovec *iovp, int niov, flag_t flags,
    sockaddr_un *addr, int *err)
{
	struct msghdr mhdr;
	int rc, pri, value, retry, i;
	const char *errmsg;
	flag_t log;
	size_t len;

	pri = value = rc = 0;
	retry = SEND_RETRIES;
	log = TR_TASK;
	errmsg = NULL;

	*err = 0;

	/* calculate the length */
	len = 0;
	for (i = 0; i < niov; i++)
		len += iovp[i].iov_len;

	if (BIT_TEST(task_state, TASKS_NOSEND)) {
		log = TR_ALL;
		errmsg = ": packet transmission disabled";
		*err = errno;
		rc = len;

		goto Log;
	}

	/* zero the msghdr, nice so we don't need ifdefs */
	memset(&mhdr, 0, sizeof(mhdr));
	mhdr.msg_iov = iovp;
	mhdr.msg_iovlen = niov;

	if (addr) {
#if defined(SOCKADDR_DL) && defined(USE_SOCKLEN)
		/* don't copy these they are the same */
		if (addr->a.ga_family == AF_LINK) {
			mhdr.msg_name = (void *)addr;
			mhdr.msg_namelen = addr->a.ga_len;
		} else
#endif
		{
			int nlen;
			mhdr.msg_name = (void *)sock2unix(addr, &nlen);
			mhdr.msg_namelen = nlen;
		}
	} else {
		mhdr.msg_name = 0;
		mhdr.msg_namelen = 0;
	}

	while ((rc = sendmsg(tp->task_socket, &mhdr, flags)) < 0) {
		*err = errno;

		switch (errno) {
		case EHOSTUNREACH:
		case ENETUNREACH:
			/*
			 * These errors may be just an indication that an
			 * unreachable was received.  When an operation is
			 * attempted on a socket with an error pending
			 * it does not complete.  So we need to retry.
			 */
			if (retry--) {
				/* Retry the send a few times */
				break;
			}
			/* Too many retries - give up */
			log = TR_ALL;
			value = SEND_RETRIES;
			errmsg = ": (%d retries) %m";
			goto Log;
		    
		case EINTR:
			/*
			 * The system call was interrupted, probably by
			 * a signal.  Silently retry
			 */
			break;

		case ENETDOWN:
#ifdef	EHOSTDOWN
		case EHOSTDOWN:
#endif	/* EHOSTDOWN */
			krt_ifcheck();

			/* FALLTHROUGH */
		default:
			/* Fatal error */
			log = TR_ALL;
			pri = LOG_ERR;
			errmsg = ": %m";
			goto Log;

		case EWOULDBLOCK:
#if	defined(EAGAIN) && EAGAIN != EWOULDBLOCK
		case EAGAIN:		/* System V style */
#endif	/* EAGAIN */
			goto Return;
		}
	}

	if ((size_t)rc != len) {
		value = len - rc;
		log = TR_ALL;
		pri = LOG_ERR;
		errmsg = ": %d bytes not accepted";
	}

Log:
	if (TRACE_TP(tp, log)) {
		tracef("task_send_packet: task %s socket %d length %d",
		    task_name(tp), tp->task_socket, len);
		if (flags) {
			tracef(" flags %s(%X)",
			    trace_bits(task_msg_bits, flags), flags);
		}
		if (addr) {
			tracef(" to %#A", addr);
		}
		trace_log_tp(tp, 0, pri, (errmsg, value));
	}

Return:
	return (rc);
}
#endif /* HAVE_SENDMSG */


/*
 * Send a packet, returns number of bytes sent.
 */
int
task_send_packet(task *tp, void_t msg, size_t len, flag_t flags,
    sockaddr_un *addr)
{
	int err;

	return(task_send_packet_err(tp, msg, len, flags, addr, &err));
}


/*
 * Send a packet, returns number of bytes sent. as well as error code!
 */
int
task_send_packet_err(task *tp, void_t msg, size_t len, flag_t flags,
    sockaddr_un *addr, int *err)
{
    int rc = 0;
    flag_t log = TR_TASK;
    int pri = 0;
    int value = 0;
    int retry = SEND_RETRIES;
    const char *errmsg = NULL;
    struct sockaddr *name;
    int namelen;
 
  *err = 0;
 
    if (BIT_TEST(task_state, TASKS_NOSEND)) {
  log = TR_ALL;
  errmsg = ": packet transmission disabled";
    *err = errno;
  rc = len;
  goto Log;
    }
 
    if (addr) {
#if defined(SOCKADDR_DL) && defined(USE_SOCKLEN)
  /* don't copy these they are the same */
  if (addr->a.ga_family == AF_LINK) {
      name = (struct sockaddr *)addr;
      namelen = addr->a.ga_len;
  } else
#endif
  name = sock2unix(addr, &namelen);
    } else {
  name = (struct sockaddr *) 0;
  namelen = 0;
    }
 
    while ((rc = sendto(tp->task_socket,
      msg,
      len,
      (int) flags,
      name,
      namelen)) < 0) {
    *err = errno;
  switch (errno) {
  case EHOSTUNREACH:
  case ENETUNREACH:
      /* These errors may be just an indication that an */
      /* unreachable was received.  When an operation is */
      /* attempted on a socket with an error pending */
      /* it does not complete.  So we need to retry. */
      if (retry--) {
    /* Retry the send a few times */
    break;
      }
      /* Too many retries - give up */
      log = TR_ALL;
      value = SEND_RETRIES;
      errmsg = ": (%d retries) %m";
      goto Log;
 
  case EINTR:
      /* The system call was interrupted, probably by */
      /* a signal.  Silently retry */
      break;
 
  case ENETDOWN:
#ifdef  EHOSTDOWN
  case EHOSTDOWN:
#endif  /* EHOSTDOWN */
      krt_ifcheck();
      /* Fall through */
 
  default:
      /* Fatal error */
      log = TR_ALL;
      pri = LOG_ERR;
      errmsg = ": %m";
      goto Log;
 
  case EWOULDBLOCK:
#if defined(EAGAIN) && EAGAIN != EWOULDBLOCK
  case EAGAIN:    /* System V style */
#endif  /* EAGAIN */
      goto Return;
  }
    }
 
    if ((size_t)rc != len) {
  value = len - rc;
  log = TR_ALL;
  pri = LOG_ERR;
  errmsg = ": %d bytes not accepted";
    }
 
 Log:
    if (TRACE_TP(tp, log)) {
  tracef("task_send_packet: task %s socket %d length %d",
         task_name(tp),
         tp->task_socket,
         len);
  if (flags) {
      tracef(" flags %s(%X)",
       trace_bits(task_msg_bits, flags),
       flags);
  }
  if (addr) {
      tracef(" to %#A",
       addr);
  }
  trace_log_tp(tp,
         0,
         pri,
         (errmsg,
          value));
    }
 
 Return:
    return rc;
}


#if defined(PROTO_INET6) && defined(IPV6_PKTINFO)
/*
 *	Send a message
 */
int
task_send_message (task *tp, void_t msg, size_t len, flag_t flags, 
    sockaddr_un *addr, if_addr *ifap)
{
    int rc = 0;
    flag_t log = TR_TASK;
    int pri = 0;
    int value = 0;
#define	SEND_RETRIES	5
    int retry = SEND_RETRIES;
    const char *errmsg = NULL;
    struct sockaddr *name;
    struct msghdr mh;
    struct cmsghdr *cmh;
    struct iovec iov[2];
    byte cmsgbuf[256];
    struct in6_pktinfo *pi;
    u_int ifindex = 0;
    int namelen;

    if (socktype(addr) != AF_INET6) {
	log = TR_ALL;
	errmsg = ": don't support AF";
	rc = len;
	goto Log;
    }

    if (!ifap) {
        log = TR_ALL;
	errmsg = ": no specified if_addr";
	rc = len;
	goto Log;
    }

    if (BIT_TEST(task_state, TASKS_NOSEND)) {
	log = TR_ALL;
	errmsg = ": packet transmission disabled";
	rc = len;
	goto Log;
    }

    iov[0].iov_base = (caddr_t)msg;
    iov[0].iov_len = len;
    mh.msg_iov = iov;
    mh.msg_iovlen = 1;

    if (addr) {
	name = sock2unix(addr, &namelen);
    } else {
	name = (struct sockaddr *) 0;
	namelen = 0;
    }
    mh.msg_name = (void *) name;
    mh.msg_namelen = namelen;

    mh.msg_flags  = 0;
    ifindex = ifap->ifa_link->ifl_index;

    if (!ifindex) {
        mh.msg_control = NULL;
	mh.msg_controllen = 0;
    } else {
        bzero((caddr_t *) cmsgbuf, sizeof (cmsgbuf));
	cmh = (struct cmsghdr *) cmsgbuf;
	mh.msg_control = (caddr_t) cmh;

	mh.msg_controllen = CMSG_SPACE(sizeof (struct in6_pktinfo));
	cmh->cmsg_len = CMSG_LEN(sizeof (struct in6_pktinfo));


	cmh->cmsg_level = IPPROTO_IPV6;
	cmh->cmsg_type = IPV6_PKTINFO;
	pi = (struct in6_pktinfo *) CMSG_DATA(cmh);
#ifdef HAVE_BCOPY
	bcopy((caddr_t *)&ifap->ifa_addr_local->in6.gin6_addr, (caddr_t *)&pi->ipi6_addr, sizeof (pi->ipi6_addr));
#else  /* HAVE_BCOPY */
	bzero((caddr_t *)&pi->ipi6_addr, sizeof (pi->ipi6_addr));
#endif
		pi->ipi6_ifindex = ifindex;
    }

    while ((rc = sendmsg(tp->task_socket,
			&mh,
			(int) flags)) < 0) {
	switch (errno) {
	case EHOSTUNREACH:
	case ENETUNREACH:
	    /* These errors may be just an indication that an */
	    /* unreachable was received.  When an operation is */
	    /* attempted on a socket with an error pending */
	    /* it does not complete.  So we need to retry. */
	    if (retry--) {
		/* Retry the send a few times */
		break;
	    }
	    /* Too many retries - give up */
	    log = TR_ALL;
	    value = SEND_RETRIES;
	    errmsg = ": (%d retries) %m";
	    goto Log;
	    
	case EINTR:
	    /* The system call was interrupted, probably by */
	    /* a signal.  Silently retry */
	    break;

	case ENETDOWN:
#ifdef  ENXIO
	case ENXIO:
#endif /* ENXIO */
#ifdef	EHOSTDOWN
	case EHOSTDOWN:
#endif	/* EHOSTDOWN */
	    krt_ifcheck();
	    /* Fall through */

	default:
	    /* Fatal error */
	    log = TR_ALL;
	    pri = LOG_ERR;
	    errmsg = ": %m";
	    goto Log;

	case EWOULDBLOCK:
#if	defined(EAGAIN) && EAGAIN != EWOULDBLOCK
	case EAGAIN:		/* System V style */
#endif	/* EAGAIN */
	    goto Return;
	}
    }

    if (rc != len) {
	value = len - rc;
	log = TR_ALL;
	pri = LOG_ERR;
	errmsg = ": %d bytes not accepted";
    }

 Log:
    if (TRACE_TP(tp, log)) {
	tracef("task_send_message: task %s socket %d length %d",
	       task_name(tp),
	       tp->task_socket,
	       len);
	if (flags) {
	    tracef(" flags %s(%X)",
		   trace_bits(task_msg_bits, flags),
		   flags);
	}
	if (addr) {
	    tracef(" to %#A if_index %d",
		   addr, ifindex);
	}
	trace_log_tp(tp,
		     0,
		     pri,
		     (errmsg,
		      value));
    }

 Return:
    return rc;
}
#endif /* PROTO_INET6 */

/**/

time_t task_mark_interval;
static task_timer *task_mark_timer;

/*ARGSUSED*/
static void
task_mark(task_timer *tip, time_t interval)
{
    trace_only_tf(trace_global,
		  TRC_NOSTAMP,
		  ("%s MARK",
		   time_string));
}


static void
task_mark_init(void)
{
    if (task_mark_interval) {
	if (!task_mark_timer) {
	    /* Create task_timer */
	
	    task_mark_timer = task_timer_create((task *) 0,
						"Time.Mark",
						0,
						task_mark_interval,
						(time_t) 0,
						task_mark,
						(void_t) 0);
	} else if (task_mark_timer->task_timer_interval != task_mark_interval) {
	    /* Set to new interval */
	    
	    task_timer_set_interval(task_mark_timer, task_mark_interval);
	}
    } else if (task_mark_timer) {
	/* Delete it */

	task_timer_delete(task_mark_timer);
	task_mark_timer = (task_timer *) 0;
    }

}


/**/
/*
 *	Call all configured protocols init routines
 */
struct protos {
    void (*init)(void);
    void (*var_init)(void);
    const char *proto;
};

static struct protos proto_inits[] = {
#ifdef	PROTO_INET
    { inet_init,	inet_var_init,		"INET" },
#endif	/* PROTO_INET */
#ifdef PROTO_INET6
    { inet6_init,	inet6_var_init,		"INET6" },
#endif /* PROTO_INET6 */
#ifdef	PROTO_ISO
    { iso_init,		0,			"ISO" },
#endif	/* PROTO_ISO */
#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
    { aspath_init,	0,			"ASPath" },
#endif	/* PROTO_ASPATHS */
    { krt_init,		krt_var_init,		"KRT" },
    { if_init,		0,			"IF" },
#ifdef	PROTO_ICMP
    { icmp_init,	icmp_var_init,		"ICMP" },
#endif	/* PROTO_ICMP */
#ifdef	PROTO_ICMPV6
    { icmpv6_init,	icmpv6_var_init,	"ICMPv6" },
#endif	/* PROTO_ICMPV6 */
#if	defined(PROTO_ICMP) || defined(PROTO_ICMPV6) || defined(KRT_RT_SOCK)
    { 0,		redirect_var_init,	"Redirects" },
#endif	/* defined(PROTO_ICMP) || defined(KRT_RT_SOCK) */
#ifdef	IP_MULTICAST_ROUTING
    { mroute_init,	mroute_var_init,	"MRouting" },
#endif	/* IP_MULTICAST_ROUTING */
#ifdef	PROTO_IGMP
    { igmp_init,	igmp_var_init,		"IGMP" },
#endif	/* PROTO_IGMP */
#ifdef	PROTO_EGP
    { egp_init,		egp_var_init,		"EGP" },
#endif	/* PROTO_EGP */
#ifdef	PROTO_BGP
    { bgp_init,		bgp_var_init,		"BGP" },
#ifdef PROTO_BGP4MP
	{ bgp4mp_init,	bgp4mp_var_init,	"BGP4+" },
#endif /* PROTO_BGP4MP */
#endif	/* PROTO_BGP */
#ifdef	PROTO_MPBGP
    { bgp_init,		bgp_var_init,		"MPBGP" },
#endif	/* PROTO_MPBGP */
#ifdef	PROTO_DVMRP_ROUTING
    { dvmrp_routing_init, dvmrp_routing_var_init, "DVMRP_ROUTING"},
#endif	/* PROTO_DVMRP_ROUTING */
#ifdef	PROTO_DVMRP
    { dvmrp_init,	dvmrp_var_init,		"DVMRP" },
#endif	/* PROTO_DVMRP */
#ifdef  PROTO_PIM
	{pim_init, 	pim_var_init,		"PIMSM/DM" },
#endif
#ifdef	PROTO_OSPF
    { ospf_init,	ospf_var_init,		"OSPF" },
#endif	/* PROTO_OSPF */
#ifdef  PROTO_IPX
	{ipxrip_init, 	ipxrip_var_init, 	"IPXRIP" },
	{ipxsap_init, 	ipxsap_var_init, 	"IPXSAP" },
#endif  /* PROTO_IPX */
#ifdef  PROTO_OSPF2
	{nospf_init, 	nospf_var_init, 		"OSPF" },
#endif  /* PROTO_OSPF2 */
#ifdef	PROTO_IGRP
    { igrp_init, 	igrp_var_init,		"IGRP" },
#endif	/* PROTO_IGRP */
#ifdef	PROTO_RIP
    { rip_init,		rip_var_init,		"RIP" },
#endif	/* PROTO_RIP */
#ifdef	PROTO_HELLO
    { hello_init,	hello_var_init,		"HELLO" },
#endif	/* PROTO_HELLO */
#ifdef	PROTO_IDPR
	{idpr_init, 	idpr_var_init, 		"IDPR" },
#endif	/* PROTO_IDPR */
#ifdef	PROTO_ISIS
    { isis_init,	isis_var_init,		"ISIS" },
#endif	/* PROTO_ISIS */
#ifdef	PROTO_ISIS2
    { isis_proto_init,	isis_proto_var_init,	"ISIS" },
#endif	/* PROTO_ISIS2 */
#ifdef	PROTO_SLSP
    { slsp_init,	slsp_var_init,		"SLSP" },
#endif	/* PROTO_SLSP */
#ifdef	PROTO_RDISC
    { rdisc_init,	rdisc_var_init,		"RDISC" },
#endif	/* PROTO_RDISC */
#ifdef PROTO_GII
       {gii_init,   gii_var_init,     "GII" },
#endif  /* PROTO_GII */
#ifdef PROTO_SMUX
  {smux_init,   smux_var_init,    "SMUX" },
#endif /* PROTO_SMUX */
#ifdef  PROTO_CMU_SNMP
  {snmp_init,   snmp_var_init,    "SNMP" },
#endif  /* PROTO_CMU_SNMP */
#ifdef  PROTO_BGMP
    { bgmp_init,  bgmp_var_init,    "BGMP" },
#endif  /* PROTO_BGMP */
#ifdef PROTO_MSDP
    { msdp_init,  msdp_var_init,    "MSDP" },
#endif  /* PROTO_MSDP */
#ifdef	PROTO_RIPNG
    { ripng_init,	ripng_var_init,		"RIPng" },
#endif	/* PROTO_RIPNG */
#ifdef	PROTO_PIMV6
    { pimv6_init,	pimv6_var_init,		"PIMV6" },
#endif	/* PROTO_PIMV6 */
        {0}
    };

void
task_proto_inits(void)
{
    struct protos *proto;

    for (proto = proto_inits; proto->proto; proto++) {
	if (proto->init) {
	    trace_tf(trace_global,
		     TR_TASK,
		     TRC_NL_BEFORE,
		     ("task_proto_inits: initializing %s",
		      proto->proto));
	    (proto->init)();
	}
	task_active = &task_task;
    }
}


void
task_proto_var_inits(void)
{
    struct protos *proto;

    for (proto = proto_inits; proto->proto; proto++) {
	if (proto->var_init) {
	    trace_tf(trace_global,
		     TR_TASK,
		     TRC_NL_BEFORE,
		     ("task_proto_var_inits: initializing %s",
		      proto->proto));
	    (proto->var_init)();
	}
	task_active = &task_task;
    }
}


/**/
/*
 *	Call all task that have posted a reinit routine
 */
static void
task_reconfigure(void)
{
    int i;
    task *tp;

    trace_log_tf(trace_global,
		 TRC_NL_BEFORE|TRC_NL_AFTER,
		 LOG_INFO,
		 ("task_reconfigure re-initializing from %s",
		  task_config_file));

    i = adv_n_allocated;

    task_newstate(TASKS_RECONFIG, 0);

    /* Call all tasks that have posted a cleanup routine */
    trace_tf(trace_global,
	     TR_TASK,
	     0,
	     (NULL));
    TASK_TABLE(tp) {
	if (tp->task_cleanup_method) {
	    trace_tf(trace_global,
		     TR_TASK,
		     0,
		     ("task_reconfigure Starting cleanup for task %s",
		      task_name(tp)));
	    TASK_SAVE(tp, tp->task_cleanup_method(tp));
	    TIMER_UPDATE();
	    trace_tf(trace_global,
		     TR_TASK,
		     0,
		     ("task_reconfigure Finished cleanup for task %s",
		      task_name(tp)));
	}
    } TASK_TABLE_END(tp);

    if (adv_n_allocated) {
	trace_log_tf(trace_global,
		     TRC_NL_BEFORE|TRC_NL_AFTER,
		     LOG_ERR,
		     ("task_reconfigure %d of %d adv_entry elements not freed",
		      adv_n_allocated, i));
    }

    /* Cleanup tracing */
    trace_freeup(task_task.task_trace);
    trace_cleanup();

    /* Reset all protocol configurations */
    task_proto_var_inits();
    
    if (parse_parse(task_config_file)) {
	task_quit(0);
    }
    TIMER_UPDATE();

    task_proto_inits();

    /* Reinit tracing */
    trace_reinit();
    task_task.task_trace = trace_set_global((bits *) 0, (flag_t) 0);

    /* Cause tasks to reinit */
    task_reinit();

    /* Remind the protocols about the interfaces */
    if_notify();

    /* finalize the reinit */
    task_reinit_finalize();

    /* Update the kernel with changes so far and have protocols re-evaluate policy */
    rt_new_policy();

    /* Update the mark timer */
    task_mark_init();

    task_newstate(0, TASKS_RECONFIG);

    trace_log_tf(trace_global,
		 TRC_NL_BEFORE|TRC_NL_AFTER,
		 LOG_INFO,
		 ("task_reconfigure reinitializing done"));
}


/*
 *	Call all tasks that have posted an ifchange routine
 */
void
task_ifachange(if_addr *ifap)
{
    task *tp;

    trace_tf(trace_global,
	     TR_TASK,
	     0,
	     (NULL));
    TASK_TABLE(tp) {
	if (tp->task_ifachange_method) {
	    trace_tf(trace_global,
		     TR_TASK,
		     0,
		     ("task_ifachange: Starting ifachange of %A(%s) for task %s",
		      IFA_UNIQUE_ADDR(ifap),
		      ifap->ifa_link->ifl_name,
		      task_name(tp)));
	    TASK_SAVE(tp, tp->task_ifachange_method(tp, ifap));
	    TIMER_UPDATE();
	    trace_tf(trace_global,
		     TR_TASK,
		     0,
		     ("task_ifachange: Finished ifachange of %A(%s) for task %s",
		      IFA_UNIQUE_ADDR(ifap),
		      ifap->ifa_link->ifl_name,
		      task_name(tp)));
	}
    } TASK_TABLE_END(tp);
}


/*
 *	Call all tasks that have posted an ifchange routine
 */
void
task_iflchange(if_link *ifl)
{
    task *tp;

    trace_tf(trace_global,
	     TR_TASK,
	     0,
	     (NULL));
    TASK_TABLE(tp) {
	if (tp->task_iflchange_method) {
	    trace_tf(trace_global,
		     TR_TASK,
		     0,
		     ("task_iflchange: Starting iflchange of %s for task %s",
		      ifl->ifl_name,
		      task_name(tp)));
	    TASK_SAVE(tp, tp->task_iflchange_method(tp, ifl));
	    TIMER_UPDATE();
	    trace_tf(trace_global,
		     TR_TASK,
		     0,
		     ("task_iflchange: Finished iflchange of %s for task %s",
		      ifl->ifl_name,
		      task_name(tp)));
	}
    } TASK_TABLE_END(tp);
}


static const char *term_names[] = {
    "first",
    "second",
    "third",
    "fourth"
    };

/*
 *	Shutdown last tasks
 */
static void
task_terminate_job(task_job *jp)
{
    task *tp;
    
    TASK_TABLE(tp) {
	if (tp->task_shutdown_method) {
	    trace_tf(trace_global,
		     TR_TASK,
		     0,
		     ("task_terminate_job: shutting down task %s",
		      task_name(tp)));
	    TASK_SAVE(tp, tp->task_shutdown_method(tp));
	    TIMER_UPDATE();
	    trace_tf(trace_global,
		     TR_TASK,
		     0,
		     (NULL));
	} 
    } TASK_TABLE_END(tp);
}


static void
task_terminate(void)
{
    register task *tp;
    static int terminate = 0;

    trace_log_tf(trace_global,
		 0,
		 LOG_NOTICE,
		 ("task_terminate: %s terminate signal received",
		  term_names[terminate]));

    /* Subprocesses terminate immediately for now */
    if (task_pid != task_mpid) {
	exit(0);
    }
    if (++terminate > 2) {
	task_quit(0);
    }
    task_newstate(TASKS_TERMINATE, 0);

    TASK_TABLE(tp) {
	if (tp->task_terminate_method) {

	    trace_tf(trace_global,
		     TR_TASK,
		     TRC_NL_AFTER,
		     ("task_terminate: terminating task %s",
		      task_name(tp)));
	    TASK_SAVE(tp, tp->task_terminate_method(tp));
	    TIMER_UPDATE();
	}
    } TASK_TABLE_END(tp);

    trace_tf(trace_global,
	     TR_TASK,
	     0,
	     ("task_terminate: Exiting and waiting for completion"));
}


static INLINE const char *
task_signame(int sig)
{
#ifndef INRIA_DEFINES
#ifndef	SIGMAX
#ifdef	NSIG
#define	SIGMAX	NSIG
#else	/* NSIG */
#ifdef	_NSIG
#define	SIGMAX	_NSIG
#endif	/* _NSIG */
#endif	/* NSIG */
#endif	/* SIGMAX */
#endif

#ifdef	SIGMAX
    static char line[LINE_MAX];

    if (sig > SIGMAX) {
	sprintf(line, "?%d?", sig);
	return line;
    }
#endif	/* SIGMAX */

    return gd_upper(sys_signame[sig]);
}


static void
task_child(void)
{
    int pid;
    WAIT_T statusp;

    while ((pid = waitpid(-1, &statusp, WNOHANG|WUNTRACED))) {
	if (pid < 0) {
	    /* Error */
	    switch (errno) {
	    case EINTR:
		/* Interrupted, try again */
		continue;

	    case ECHILD:
		/* No Children to wait for */
		return;
		    
	    default:
		trace_log_tf(trace_global,
			     0,
			     LOG_ERR,
			     ("task_child: waitpid() error: %m"));
	    }
	} else {
	    task *tp;

	    TASK_TABLE(tp) {
		if (pid == tp->task_pid) {
		    /* Assume my pid */
		    int done = TRUE;
			    
		    if (WIFSTOPPED(statusp)) {
			/* Stopped by a signal */
		    
			trace_log_tf(trace_global,
				     0,
				     LOG_ERR,
				     ("task_child: %s stopped by SIG%s",
				      task_name(tp),
				      task_signame(WSTOPSIG(statusp))));
			done = FALSE;
		    } else if (WIFSIGNALED(statusp)) {
			/* Terminated by a signal */
				
			trace_log_tf(trace_global,
				     0,
				     LOG_ERR,
				     ("task_child: %s terminated abnormally by SIG%s%s",
				      task_name(tp),
				      task_signame(WTERMSIG(statusp)),
				      WIFCOREDUMP(statusp) ? " with core" : ""));
		    } else if (WEXITSTATUS(statusp)) {
			/* Non-zero exit status */
			
			trace_log_tf(trace_global,
				     0,
				     LOG_ERR,
				     ("task_child: %s terminated abnormally with retcode %d",
				      task_name(tp),
				      WEXITSTATUS(statusp)));
		    } else {
			/* Normal termination */
			
			trace_tf(trace_global,
				 TR_TASK,
				 0,
				 ("task_child: %s terminated normally",
				  task_name(tp)));
		    }
		    
		    if (done && tp->task_child_method) {
			TASK_SAVE(tp, tp->task_child_method(tp));
			TIMER_UPDATE();
		    }

		    break;
		}
	    } TASK_TABLE_END(tp) ;
	}
    }

}


static SIGTYPE
task_receive_signal(int sig)
{
    /* Check to see if is valid */
    SIGNAL_LIST(ip) {
	if (sig == ip->sig_sig) {
	    /* Indicate it is pending */

	    ip->sig_pending = TRUE;

	    /* Re-arm the signal handler */
#ifdef	SYSV_SIGNALS
	    sigset(ip->sig_sig, task_receive_signal);
#endif	/* SYSV_SIGNALS */
	    goto Return;
	}
    } SIGNAL_LIST_END(ip);

    task_signal_unknown = sig;

 Return:
    task_signal_pending = TRUE;
    SIGRETURN;
}


/*
 *	close a task's socket and terminate
 */
void
task_close(task *close_tp)
{
    int rc;
    int s = close_tp->task_socket;
    
    trace_tp(close_tp,
	     TR_TASK,
	     0,
	     ("task_close: close socket %d task %s",
	      close_tp->task_socket,
	      task_name(close_tp)));

    task_reset_socket(close_tp);
    NON_INTR(rc, close(s));
    if (rc < 0) {
	trace_log_tp(close_tp,
		     0,
		     LOG_ERR,
		     ("task_close: close %s.%d: %m",
		      task_name(close_tp),
		      s));
    }
}


/*
 *  Delete a task block and free allocated storage.  When the last task has been deleted, exit.
 */
void
task_delete(task *tp)
{
    trace_tp(tp,
	     TR_TASK,
	     0,
	     ("task_delete: deleting task %s",
	      task_name(tp)));

    /* Close the socket if present */
    if (tp->task_socket != -1) {
	task_close(tp);
    }

    /* Remove the entry from the flash list */
    TMQ_REMOVE(tp, task_flash_queue);

    /* Delete timers for this task */
    if (tp->task_timers) {
	task_timer *tip_next = tp->task_timers;
	tip_next = tp->task_timers;
	do {
	    task_timer *tip = tip_next;
	    tip_next = tip->task_timer_next;
	    task_timer_delete(tip);
	} while (tip_next);
    }

    /* Delete any jobs */
    task_job_delete_task(tp);

    /* Remove this task from the count and delete it's address */
    task_n_tasks--;
    if (tp->task_addr) {
	sockfree(tp->task_addr);
	tp->task_addr = (sockaddr_un *) 0;
    }

    if (tp->task_forw || TMQ_ON_ANY_QUEUE(tp) || tp->task_timers) {
	/* If we are active on some list, a deletion now would mangle some */
	/* list pointers, so defer the deletion for later */
	BIT_SET(tp->task_flags, TASKF_DELETE);
	(void) task_job_create(&task_task,
			       TASK_JOB_FG,
			       "task_collect",
			       task_collect_job,
			       (void_t) tp);
    } else {
	/* Delete this task now */

	/* Free the tracing info */
	trace_freeup(tp->task_trace);
	task_block_free(task_block_index, (void_t) tp);
	return;
    }

    if (!task_n_tasks) {
	/* The only foreground jobs that should be present are task */
	/* deletions, do them now */
	if (task_job_fg_queued) {
	    task_job_fg_dispatch();
	}
	trace_tf(trace_global,
		 TR_TASK,
		 0,
		 ("task_delete: Removed last task, exiting"));

	/* Free up tracing */
	trace_freeup(task_task.task_trace);
	
	/* And we are out of here */
	task_quit(0);
    } else {
	int last_count = 0;
	static task_job *term_job;

	if (!term_job) {
	    
	    TASK_TABLE(tp) {
		if (tp->task_shutdown_method) {
		    last_count++;
		}
	    } TASK_TABLE_END(tp) ;

	    if (last_count == task_n_tasks) {
		term_job = task_job_create(&task_task,
					   TASK_JOB_FG,
					   "task_terminate_job",
					   task_terminate_job,
					   (void_t) 0);
	    }
	}
    }
}


/**/

/* Main signal, timer and input packet processing */

/*
 *	Process signals
 */
static void
task_process_signals(void)
{
    int unknown;

    /* Capture the list of pending signals */
    task_signal_pending = FALSE;

    SIGNAL_LIST(ip) {
	if (ip->sig_pending) {
	    ip->sig_pending = FALSE;
	    ip->sig_process = TRUE;
	}
    } SIGNAL_LIST_END(ip) ;

    if ((unknown = task_signal_unknown)) {
	/* Bitch about an unknown signal */

	task_signal_unknown = 0;

	trace_log_tf(trace_global,
		     0,
		     LOG_WARNING,
		     ("task_process_signals: Ignoring unknown signal SIG%s(%d)",
		      task_signame(unknown),
		      unknown));
    }


    /* Process signals */
    SIGNAL_LIST(ip) {

	if (ip->sig_process) {
	    /* This signal was pending */

	    /* Reset pending indication */
	    ip->sig_process = FALSE;

	    trace_tf(trace_global,
		     TR_TASK,
		     0,
		     ("task_process_signals: processing SIG%s(%d): %s",
		      task_signame(ip->sig_sig),
		      ip->sig_sig,
		      ip->sig_name));

	    switch (ip->sig_sig) {
	    case SIGTERM:
		task_terminate();
		break;

	    case SIGHUP:
		if (BIT_TEST(task_state, TASKS_NORECONFIG)) {
		    trace_log_tf(trace_global,
				 0,
				 LOG_ERR,
				 ("task_process_signals: reinitialization not possible"));
		} else {
		    task_reconfigure();
		}
		break;

#ifdef	SIGPIPE
	    case SIGPIPE:
		break;
#endif	/* SIGPIPE */
	
	    case SIGINT:
		trace_dump(FALSE);
		break;

	    case SIGUSR1:
		trace_toggle();
		break;

	    case SIGUSR2:
		krt_ifcheck();
		break;

	    case SIGCHLD:
		task_child();
		break;

	    default:
		assert(FALSE);
	    }

	    trace_tf(trace_global,
		     TR_TASK,
		     0,
		     (NULL));
	}
    } SIGNAL_LIST_END(ip);
}


/*
 *	Process sockets
 */
static void
task_process_sockets(int numset, fd_set *read_bits, fd_set *write_bits,
    fd_set *except_bits)
{
    task *tp;
    const char *name = (char *) 0;
    static int do_writes_first = 0;
    int dont_check = FALSE;
    int did_once;
    u_int limit_reads_or_writes;
    u_int limit_reads_and_writes;
    u_int *limit;
    u_int n;
    void (*method)(task *);

    n = numset;
    if (n == 0) {
	return;
    }

	/* Process normal priority reads first */
	if (read_bits) {
		TMQ_SET_LOCK(task_read_queue);
		TMQ_LIST(tp, task_read_queue) {
			if (tp->task_socket == (-1)
			       || !FD_ISSET(tp->task_socket, read_bits)) {
				continue;
			}

			/* Read read here, reset bit */
			FD_CLR(tp->task_socket, read_bits);

			/* Which routine */
			if (BIT_TEST(tp->task_flags, TASKF_ACCEPT)) {
				name = "accept";
				method = tp->task_accept_method;
			} else {
				name = "recv";
				method = tp->task_recv_method;
			}

			/* Run it */
			trace_tp(tp,
			         TR_TASK,
			         0,
			         ("task_process_sockets: %s ready for %s",
			         name,
			         task_name(tp)));
			TASK_SAVE(tp, method(tp));

			/* Update the timer */
			TIMER_UPDATE();

			/* If no more bits, stop.  Requeue for fun */
			if ((--n) == 0) {
				TMQ_REQUEUE(tp, task_read_queue);
				break;
			}
		} TMQ_LIST_END(tp, task_read_queue) ;

		/* See if someone found the queue locked.  If so, blow them off */
		if (TMQ_CHECK_WASLOCKED(task_read_queue)) {
			TMQ_CLEAR_LOCK(task_read_queue);
			dont_check = TRUE;
			TMQ_LIST(tp, task_read_queue) {
				if (tp->task_socket == (-1)
				        || !(tp->task_accept_method || tp->task_recv_method)) {
					TMQ_REMOVE(tp, task_read_queue);
				}
			} TMQ_LIST_END(tp, task_read_queue);
		}

		if (n == 0) {
			return;
		}
	}

	/* If we have exceptions (we usually don't) do them now */
	if (except_bits) {
		TMQ_SET_LOCK(task_except_queue);

		TMQ_LIST(tp, task_except_queue) {
			/* If no socket here, don't bother */
			if (tp->task_socket == (-1)
			      || !FD_ISSET(tp->task_socket, except_bits)) {
				continue;
			}

			/* Got one, reset bit and update the count */
			FD_CLR(tp->task_socket, except_bits);

			/* Run it */
			trace_tp(tp,
			         TR_TASK,
			         0,
			         ("task_process_sockets: exception ready for %s",
			         task_name(tp)));
			TASK_SAVE(tp, (tp->task_except_method)(tp));

			/* Update the timer */
			TIMER_UPDATE();

			/* If no more bits, stop.  Requeue for fun */
			if ((--n) == 0) {
				TMQ_REQUEUE(tp, task_except_queue);
				break;
			}

		} TMQ_LIST_END(tp, task_except_queue);

		if (TMQ_CHECK_WASLOCKED(task_except_queue)) {
			TMQ_CLEAR_LOCK(task_except_queue);
			dont_check = TRUE;

			TMQ_LIST(tp, task_except_queue) {
				if (tp->task_socket == (-1) || !(tp->task_except_method)) {
					TMQ_REMOVE(tp, task_except_queue);
				}
			} TMQ_LIST_END(tp, task_except_queue);
		}

		if (n == 0) {
			return;
		}
	}

	/* Now do writes and low priority reads while there seem to be some */
	limit_reads_and_writes = task_sched_reads_and_writes;
	for (did_once = 0; did_once <= 1; did_once++) {
		/*
		 * Do reads if did_once == 0 and do_writes_first == 0,
		 * or if did_once == 1 and do_writes_first == 1
		 */
		if ((do_writes_first != 0) ^ (did_once == 0)) {
			if (!read_bits) {
				continue;
			}
			if (n <= task_sched_reads) {
				if (n <= limit_reads_and_writes) {
					limit = &n;
				} else {
					limit = &limit_reads_and_writes;
				}
			} else if (task_sched_reads <= limit_reads_and_writes) {
				limit_reads_or_writes = task_sched_reads;
				limit = &limit_reads_or_writes;
			} else {
				limit = &limit_reads_and_writes;
	    }

			TMQ_SET_LP_LOCK(task_read_queue);
			TMQ_LP_LIST(tp, task_read_queue) {

				if (tp->task_socket == (-1)
				       || !(tp->task_accept_method || tp->task_recv_method)
				       || !FD_ISSET(tp->task_socket, read_bits)) {
					continue;
				}

				/* Read read here, reset bit */
				FD_CLR(tp->task_socket, read_bits);

				/* Which routine */
				if (BIT_TEST(tp->task_flags, TASKF_ACCEPT)) {
					name = "accept";
					method = tp->task_accept_method;
				} else {
					name = "recv";
					method = tp->task_recv_method;
				}

				/* Run it */
				trace_tp(tp,
				         TR_TASK,
				         0,
				         ("task_process_sockets: low priority %s ready for %s",
				          name,
				          task_name(tp)));
				TASK_SAVE(tp, method(tp));
	
				/* Update the timer */
				TIMER_UPDATE();

				/* If no more, don't bother.  Requeue so next guy is first */
				if ((--(*limit)) == 0) {
					TMQ_LP_REQUEUE(tp, task_read_queue);
					break;
				}
			} TMQ_LP_LIST_END(tp, task_read_queue) ;

	    /* See if someone found the queue locked.  If so, blow them off */
	    if (TMQ_CHECK_LP_WASLOCKED(task_read_queue)) {
				TMQ_CLEAR_LP_LOCK(task_read_queue);
				dont_check = TRUE;
				TMQ_LP_LIST(tp, task_read_queue) {
					if (tp->task_socket == (-1)
					     || !(tp->task_accept_method || tp->task_recv_method)) {
						TMQ_LP_REMOVE(tp, task_read_queue);
					}
				} TMQ_LP_LIST_END(tp, task_read_queue);
			}

			/* If we reached some limit, do the right thing */
			if ((*limit) == 0) {
				if (limit == &n) {
					do_writes_first = 0;
					return;		/* All done */
				}
				if (limit == &limit_reads_and_writes) {
					/*
					 * If we did write already, do reads first next,
					 * otherwise do writes
					 */
					if (did_once) {
						do_writes_first = 0;
					} else {
						do_writes_first = 1;
					}
					return;
				}
				dont_check = 1;
			}
		} else {
			/*
			 * Do writes here.  More of the same
			 */
			if (!write_bits) {
				continue;
			}
			if (n <= task_sched_writes) {
				if (n <= limit_reads_and_writes) {
					limit = &n;
				} else {
					limit = &limit_reads_and_writes;
				}
			} else if (task_sched_writes <= limit_reads_and_writes) {
				limit_reads_or_writes = task_sched_writes;
				limit = &limit_reads_or_writes;
			} else {
				limit = &limit_reads_and_writes;
			}

			TMQ_SET_LOCK(task_write_queue);
			TMQ_LIST(tp, task_write_queue) {

				if (tp->task_socket == (-1)
				          || !FD_ISSET(tp->task_socket, write_bits)
				          || !(tp->task_write_method || tp->task_connect_method)) {
					continue;
				}

				/* Got a live one, reset bit */
				FD_CLR(tp->task_socket, write_bits);

				/* Which routine */
				if (BIT_TEST(tp->task_flags, TASKF_CONNECT)) {
					name = "connect";
					method = tp->task_connect_method;
				} else {
					name = "write";
					method = tp->task_write_method;
				}

				/* Run it */
				trace_tp(tp,
				         TR_TASK,
				         0,
				         ("task_process_sockets: %s ready for %s",
				         name,
				         task_name(tp)));
				TASK_SAVE(tp, method(tp));
	
				/* Update the timer */
				TIMER_UPDATE();

				/* If no more, stop.  Requeue so we start from here next */
				if ((--(*limit)) == 0) {
					TMQ_REQUEUE(tp, task_write_queue);
					break;
				}
			} TMQ_LIST_END(tp, task_write_queue) ;

			/* See if someone found the queue locked.  If so, blow them off */
			if (TMQ_CHECK_WASLOCKED(task_write_queue)) {
				TMQ_CLEAR_LOCK(task_write_queue);
				dont_check = TRUE;

				TMQ_LIST(tp, task_write_queue) {
					if (tp->task_socket == (-1)
						|| !(tp->task_write_method || tp->task_connect_method)) {
						TMQ_REMOVE(tp, task_write_queue);
					}
				} TMQ_LIST_END(tp, task_write_queue);
			}

			/* If we reached some limit, do the right thing */
			if ((*limit) == 0) {
				if (limit == &n) {
					do_writes_first = 0;
					return;		/* All done */
				}
				if (limit == &limit_reads_and_writes) {
					/*
					 * If we did read already, do writes first next,
					 * otherwise do reads
					 */
					if (did_once) {
						do_writes_first = 1;
					} else {
						do_writes_first = 0;
					}
					return;
				}
				dont_check = 1;
			}
		}
	}


	/*
	 * Here everything completed normally but we still have some bits
	 * set.  If we were told not to check (presumably because this
	 * could normally happen), return right away.
	 */
	do_writes_first = 0;
	if (dont_check) {
		return;
	}

	/*
	 * This could be a program error.  Scan the entire task table
	 * looking for some guy with his bit set but with no processing
	 * routine set up.  If found, reset his select bit.
	 */
	TASK_TABLE(tp) {

		if (tp->task_socket == (-1)) {
			continue;
		}

		/* Check for a mis-set read bit */
		if (read_bits && FD_ISSET(tp->task_socket, read_bits)) {
			if (!(tp->task_recv_method || tp->task_accept_method)
			       || (tp->task_read_queue.tmq_forw == (task_method_queue *) 0)) {
				trace_log_tp(tp,
				             0,
				             LOG_ERR,
				             ("task_process_sockets: no read/accept method for %s socket %d",
				             task_name(tp),
				             tp->task_socket));
				TASK_FD_CLR(tp->task_socket, &task_select_readbits);
			}
		}

		/* Check for a mis-set write bit */
		if (write_bits && FD_ISSET(tp->task_socket, write_bits)) {
			if (!(tp->task_connect_method || tp->task_write_method)
			    || (tp->task_write_queue.tmq_forw == (task_method_queue *) 0)) {
				trace_log_tp(tp,
				             0,
				             LOG_ERR,
				             ("task_process_sockets: no write/connect method for %s socket %d",
				             task_name(tp),
				             tp->task_socket));
				TASK_FD_CLR(tp->task_socket, &task_select_writebits);
			}
		}

		/* Check for exception on socket */
		if (except_bits && FD_ISSET(tp->task_socket, except_bits)) {
			if (!(tp->task_except_method)
			    || (tp->task_except_queue.tmq_forw == (task_method_queue *) 0)) {
				trace_log_tp(tp,
				             0,
				             LOG_ERR,
				             ("task_process_sockets: no exception method for %s socket %d",
				             task_name(tp),
				             tp->task_socket));
				TASK_FD_CLR(tp->task_socket, &task_select_exceptbits);
			}
		}
	} TASK_TABLE_END(tp) ;
}

/**/

/* Deal with flash updates */

void
task_set_flash(task *tp, task_flash_func_t flash)
{
	tp->task_flash_method = flash;
	if (flash) {
		TMQ_INSERT(tp, task_flash_queue);
	} else {
		TMQ_REMOVE(tp, task_flash_queue);
	}
}


void
task_flash(rt_list *change_list)
{
	task *tp;

	/* Change state */
	task_newstate(TASKS_FLASH, 0);

	/* Lock the queue before starting */
	TMQ_SET_LOCK(task_flash_queue);
	TMQ_LIST(tp, task_flash_queue) {
		if (!(tp->task_flash_method)) {
			continue;
		}
		trace_tf(trace_global,
		         TR_TASK,
		         0,
		         ("task_flash: calling flash update routine for %s",
		         task_name(tp)));
		TASK_SAVE(tp, tp->task_flash_method(tp, change_list));
		TIMER_UPDATE();
		trace_tf(trace_global,
		         TR_TASK,
		         0,
		         ("task_flash: return from flash update routine for %s",
		         task_name(tp)));
	} TMQ_LIST_END(tp, task_flash_queue) ;

	/* See if someone found the queue locked.  If so, blow them off */
	if (TMQ_CHECK_WASLOCKED(task_flash_queue)) {
		TMQ_CLEAR_LOCK(task_flash_queue);
		TMQ_LIST(tp, task_flash_queue) {
			if (!(tp->task_flash_method)) {
				TMQ_REMOVE(tp, task_flash_queue);
			}
		} TMQ_LIST_END(tp, task_flash_queue);
	}

	/* Reset state */
	task_newstate(0, TASKS_FLASH);
}


void
task_newpolicy(rt_list *change_list)
{
	task *tp;
 
	/* Change state */
	task_newstate(TASKS_NEWPOLICY, 0);

	TASK_TABLE(tp) {
		if (tp->task_newpolicy_method) {
			trace_tf(trace_global,
			         TR_TASK,
			         0,
			         ("task_flash: calling new policy routine for %s",
			         task_name(tp)));
			         TASK_SAVE(tp, tp->task_newpolicy_method(tp, change_list));
			TIMER_UPDATE();
			trace_tf(trace_global,
			         TR_TASK,
			         0,
			         ("task_flash: return from new policy routine for %s",
			         task_name(tp)));
		}
	} TASK_TABLE_END(tp);

	/* Reset state */
	task_newstate(0, TASKS_NEWPOLICY);
}


/*
 *	Allocate a task block with the specified name
 */
task *
task_alloc(const char *name, int priority, trace *trp)
{
    task *tp;

    tp = (task *) task_block_alloc(task_block_index);
    tp->task_name = name;
    task_set_terminate(tp, task_delete);
    tp->task_socket = -1;
    tp->task_priority = priority;
    tp->task_trace = trace_alloc(trp);

    trace_tp(tp,
	     TR_TASK,
	     0,
	     ("task_alloc: allocated task block for %s priority %d",
	      tp->task_name,
	      tp->task_priority));
    return tp;
}


/*
 *	Allocate an output buffer
 */
void
task_alloc_send(task *tp, size_t maxsize)
{
    if (maxsize > task_send_buffer_len) {
	/* This request is larger than previous requests */

	/* Round it up to a page size */
	maxsize = ROUNDUP(maxsize, task_pagesize);

	if (task_send_buffer) {
	    /* Free the old buffer */
	    task_block_reclaim(task_send_buffer_len, task_send_buffer);
	}

	/* Allocate send buffer */
	task_send_buffer = (void_t) task_block_malloc(maxsize);

	trace_tp(tp,
		 TR_TASK,
		 0,
		 ("task_alloc_send: send buffer size increased to %d from %d by %s",
		  maxsize,
		  task_send_buffer_len,
		  task_name(tp)));
	task_send_buffer_len = maxsize;
    }
}


/*
 *	Allocate an input buffer
 */
void
task_alloc_recv(task *tp, size_t maxsize)
{
    if (maxsize > task_recv_buffer_len) {
	/* This request is larger than previous requests */

	/* Round it up to a page size */
	maxsize = ROUNDUP(maxsize, task_pagesize);

	if (task_recv_buffer) {
	    /* Free the old buffer */
	    task_block_reclaim(task_recv_buffer_len, task_recv_buffer);
	}

	/* Allocate recv buffer */
	task_recv_buffer = (void_t) task_block_malloc(maxsize);

	trace_tp(tp,
		 TR_TASK,
		 0,
		 ("task_alloc_recv: recv buffer size increased to %d from %d by %s",
		  maxsize,
		  task_recv_buffer_len,
		  task_name(tp)));
	task_recv_buffer_len = maxsize;
    }
}


/*
 *	Build a task block and add to the linked list
 */
int
task_create(task *tp)
{

    if (tp->task_socket != -1) {
	task_set_socket(tp, tp->task_socket);
    }

    if (task_head.task_forw == &task_head ||
	tp->task_priority < task_head.task_forw->task_priority) {
	/* This is the only task or a lower priority than the first one */
	INSQUE(tp, &task_head);
    } else if (tp->task_priority > task_head.task_back->task_priority) {
	/* Highest priority */
	INSQUE(tp, task_head.task_back);
    } else {
	task *tp2 = task_head.task_forw;

	while (tp->task_priority > tp2->task_priority) {
	    tp2 = tp2->task_forw;
	}

	/* Insert before this element */
	INSQUE(tp, tp2->task_back);
    }
	
    task_n_tasks++;

    tracef("task_create: %s",
	   task_name(tp));

    if (tp->task_proto) {
	tracef("  proto %d",
	       tp->task_proto);
    }
#if	defined(PROTO_INET) || defined(PROTO_INET6)
    if (tp->task_addr && sock2port(tp->task_addr)) {
	tracef("  port %d",
	       ntohs(sock2port(tp->task_addr)));
    }
#endif	/* PROTO_INET */
    if (tp->task_socket != -1) {
	tracef("  socket %d",
	       tp->task_socket);
    }
    if (tp->task_rtproto) {
	tracef("  rt_proto <%s>",
	       trace_state(rt_proto_bits, tp->task_rtproto));
    }
    trace_tp(tp,
	     TR_TASK,
	     0,
	     (NULL));

    return 1;
}


/*
 * Terminate a subprocess
 */
static void
task_kill(task *tp)
{
    kill(tp->task_pid, SIGTERM);
}


/*
 * Spawn a process and create a task for it.
 */
int
task_fork(task *tp)
{
    int rc = 0;

    switch (tp->task_pid = fork()) {
    case 0:
	/* Child */
	tp->task_pid = task_pid = getpid();
	(void) sprintf(task_pid_str, "%d", task_pid);

	trace_tp(tp,
		 TR_TASK,
		 0,
		 ("task_fork: %s forked",
		  task_name(tp)));

	if (tp->task_process_method) {
	    TASK_SAVE(tp, tp->task_process_method(tp));
	}

	task_timer_peek();
	
	trace_tp(tp,
		 TR_TASK,
		 0,
		 ("task_fork: %s exiting",
		  task_name(tp)));
	_exit(0);

    case -1:
	/* Error */
	trace_log_tp(tp,
		     0,
		     LOG_ERR,
		     ("task_fork: could not fork %s: %m",
		      task_name(tp)));
	task_delete(tp);
	break;
	
    default:
	/* Parent */
	task_set_terminate(tp, task_kill);
	rc = task_create(tp);
    }

    return rc;
}


/*  */

int
task_ioctl(int fd, u_long cmd, void_t data, int len)
{
    int rc;
    
#ifdef	USE_STREAMIO
    struct strioctl si;
 
    si.ic_cmd = cmd;
    si.ic_timout = 0;
    si.ic_len = len;
    si.ic_dp = (caddr_t) data;
    
    NON_INTR(rc, ioctl(fd, I_STR, &si));
#else	/* USE_STREAMIO */
    NON_INTR(rc, ioctl(fd, cmd, data));
#endif	/* USE_STREAMIO */

    return rc;
}
/*  */

#ifdef	STDIO_HACK
/*
 *  A hack to catch stdio and stderr output when gated is running as a daemon.
 */

static void
task_stdio_read(tp)
	task * tp;
{
    register char *cp, *ep;
    register char *sp = task_get_recv_buffer(char *);
    size_t len = task_recv_buffer_len;

    while (TRUE) {
	/* Read until there is not more to read */
	if ((int) (len = read(tp->task_socket,
			      sp,
			      len)) < 0) {
	    switch (errno) {
	    case EWOULDBLOCK:
#if	defined(EAGAIN) && EAGAIN != EWOULDBLOCK
	    case EAGAIN:		/* System V style */
#endif	/* EAGAIN */
		break;

	    case EINTR:
		/* The system call was interrupted, probably by */
		/* a signal.  Silently retry */
		continue;
		
	    default:
		trace_log_tp(tp,
			     0,
			     LOG_INFO,
			     ("task_stdio_read: read: %m"));
	    }
	    return;
	}

	assert(len);
	
	if (len < task_recv_buffer_len) {
	    sp[len] = (char) 0;
	}
	ep = (cp = sp) + len;

	/* Print each line seperately */
	while (cp < ep) {
	    switch (*cp) {
	    case '\n':
		trace_only_tp(tp,
			      0,
			      ("stdio: %.*s",
			       cp - sp,
			       sp));
		sp = ++cp;
		break;
		
	    default:
		cp++;
	    }
	}

	/* Print any remaining */
	if (cp > sp) {
	    trace_only_tp(tp,
			  0,
			  ("stdio: %.*s",
			   cp - sp,
			   sp));
	}
    }
}
	

static void
task_stdio_cleanup(tp)
	task * tp;
{
    trace_freeup(tp->task_trace);
}


static void
task_stdio_reinit(tp)
	task * tp;
{
    trace_freeup(tp->task_trace);
    tp->task_trace = trace_set_global((bits *) 0, (flag_t) 0);
}


static void
task_stdio_family_init()
{
    int fd[2];
    task *tp;

    tp = task_alloc("stdio",
		    0,
		    trace_set_global((bits *) 0, (flag_t) 0));

    if (pipe(fd) < 0) {
	trace_log_tp(tp,
		     0,
		     LOG_WARNING,
		     ("task_stdio: pipe: %m"));
	return;
    }

    tp->task_socket = fd[0];
    task_set_recv(tp, task_stdio_read);
    task_set_reinit(tp, task_stdio_reinit);
    task_set_cleanup(tp, task_stdio_cleanup);
    if (!task_create(tp)) {
    close_up:
	(void) close(fd[0]);
	(void) close(fd[1]);
	return;
    }

    if (task_set_option(tp,
			TASKOPTION_NONBLOCKING,
			TRUE) < 0) {
	goto close_up;
    }
    
    if (fd[1] != fileno(stdout)
	&& dup2(fd[1], fileno(stdout)) < 0) {
	trace_log_tp(tp,
		     0,
		     LOG_INFO,
		     ("task_stdio_family_init: dup2(%d, stdout): %m",
		      fd[1]));
	goto close_up;
    }
    (void) task_floating_socket(tp,
				fileno(stdout),
				"stdout capture");
    
    if (fd[1] != fileno(stderr)
	&& dup2(fd[1], fileno(stderr)) < 0) {
	trace_log_tp(tp,
		     0,
		     LOG_INFO,
		     ("task_stdio_init: dup2(%d, stderr): %m",
		      fd[1]));
	goto close_up;
    }
    (void) task_floating_socket(tp,
				fileno(stderr),
				"stderr capture");

    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);

    task_alloc_recv(tp, BUFSIZ);

}
#endif	/* STDIO_HACK */


/**/


#ifdef	notyet
void
task_set_recv(tp, method)
task *tp;
void (*method)(task *);
{
    tp->task_recv_method = method;
    if (!BIT_TEST(tp->task_flags, TASKF_ACCEPT)) {
	if (method) {
	    TASK_FD_SET(tp->task_socket, &task_select_readbits);
	    TMQ_INSERT(tp, task_read_queue);
	} else {
	    TASK_FD_CLR(tp->task_socket, &task_select_readbits);
	    TMQ_REMOVE(tp, task_read_queue);
	}
    }
}


void
task_set_accept(tp, method)
task *tp;
void (*method)(task *);
{
    tp->task_accept_method = method;
    if (method) {
	BIT_SET(tp->task_flags, TASKF_ACCEPT);
	TASK_FD_SET(tp->task_socket, &task_select_readbits);
	TMQ_INSERT(tp, task_read_queue);
    } else {
	BIT_RESET(tp->task_flags, TASKF_ACCEPT);
	if (!tp->task_recv_method) {
	    TASK_FD_CLR(tp->task_socket, &task_select_readbits);
	    TMQ_REMOVE(tp, task_read_queue);
	}
    }
}


void
task_set_write(tp, method)
task *tp;
void (*method)(task *);
{
    tp->task_write_method = method;
    if (!BIT_TEST(tp->task_flags, TASKF_ACCEPT)) {
	if (method) {
	    TASK_FD_SET(tp->task_socket, &task_select_writebitsbits);
	    TMQ_INSERT(tp, task_write_queue);
	} else {
	    TASK_FD_CLR(tp->task_socket, &task_select_writebits);
	    TMQ_REMOVE(tp, task_write_queue);
	}
    }
}


void
task_set_connect(tp, method)
task *tp;
void (*method)(task *);
{
    tp->task_connect_method = method;
    if (method) {
	BIT_SET(tp->task_flags, TASKF_CONNECT);
	TASK_FD_SET(tp->task_socket, &task_select_writebits);
	TMQ_INSERT(tp, task_write_queue);
    } else {
	BIT_RESET(tp->task_flags, TASKF_CONNECT);
	if (!tp->task_recv_method) {
	    TASK_FD_CLR(tp->task_socket, &task_select_writebits);
	    TMQ_REMOVE(tp, task_write_queue);
	}
    }
}


void
task_set_except(tp, method)
task *tp;
void (*method)(task *);
{
    tp->task_except_method = method;
    if (method)
	TASK_FD_SET(tp->task_socket, &task_select_exceptbits);
    } else {
	TASK_FD_CLR(tp->task_socket, &task_select_exceptbits);
    }
}


void
task_set_socket (tp, s)
	task * tp;
	int s;
{
    tp->task_socket = s;

    trace_tp(tp,
	     TR_TASK,
	     0,
	     ("task_set_socket: task %s socket %d",
	      task_name(tp),
	      tp->task_socket));

    if (tp->task_socket > task_max_socket) {
	task_max_socket = tp->task_socket;
    }

    if (BIT_TEST(tp->task_flags, TASKF_ACCEPT)) {
	task_set_accept(tp, tp->task_accept_method);
    } else {
	task_set_recv(tp, tp->task_recv_method);
    }

    if (BIT_TEST(tp->task_flags, TASKF_CONNECT)) {
	task_set_connect(tp, tp->task_connect_method);
    } else {
	task_set_write(tp, tp->task_connect_method);
    }

    task_set_except(tp, tp->task_except_method);
}


void
task_reset_socket (tp)
	task * tp;
{

    trace_tp(tp,
	     TR_TASK,
	     0,
	     ("task_reset_socket: task %s socket %d",
	      task_name(tp),
	      tp->task_socket));

    TASK_FD_CLR(tp->task_socket, &task_select_readbits);
    TASK_FD_CLR(tp->task_socket, &task_select_writebits);
    TASK_FD_CLR(tp->task_socket, &task_select_exceptbits);

    BIT_RESET(tp->task_flags, TASKF_CONNECT | TASKF_ACCEPT);
    tp->task_accept_method = 0;
    TMQ_REMOVE(tp, task_read_queue);
    tp->task_connect_method = 0;
    TMQ_REMOVE(tp, task_write_queue);

    tp->task_socket = -1;
}
#endif	/* notdef */

/**/

void
task_set_socket(task *tp, int s)
{
    tp->task_socket = s;

    trace_tp(tp,
	     TR_TASK,
	     0,
	     ("task_set_socket: task %s socket %d",
	      task_name(tp),
	      tp->task_socket));

    if (tp->task_socket > task_max_socket) {
	task_max_socket = tp->task_socket;
    }

    if (tp->task_recv_method || tp->task_accept_method) {
	TASK_FD_SET(tp->task_socket, &task_select_readbits);
	if (BIT_TEST(tp->task_flags, TASKF_LOWPRIO)) {
	    TMQ_LP_INSERT(tp, task_read_queue);
	} else {
	    TMQ_INSERT(tp, task_read_queue);
	}
    } else {
	TASK_FD_CLR(tp->task_socket, &task_select_readbits);
	if (BIT_TEST(tp->task_flags, TASKF_LOWPRIO)) {
	    TMQ_LP_REMOVE(tp, task_read_queue);
	} else {
	    TMQ_REMOVE(tp, task_read_queue);
	}
    }

    if (tp->task_write_method || tp->task_connect_method) {
	TASK_FD_SET(tp->task_socket, &task_select_writebits);
	TMQ_INSERT(tp, task_write_queue);
    } else {
	TASK_FD_CLR(tp->task_socket, &task_select_writebits);
	TMQ_REMOVE(tp, task_write_queue);
    }

    if (tp->task_except_method) {
	TASK_FD_SET(tp->task_socket, &task_select_exceptbits);
	TMQ_INSERT(tp, task_except_queue);
    } else {
	TASK_FD_CLR(tp->task_socket, &task_select_exceptbits);
	TMQ_REMOVE(tp, task_except_queue);
    }
}


void
task_reset_socket(task *tp)
{

    trace_tp(tp,
	     TR_TASK,
	     0,
	     ("task_reset_socket: task %s socket %d",
	      task_name(tp),
	      tp->task_socket));

    TASK_FD_CLR(tp->task_socket, &task_select_readbits);
    TASK_FD_CLR(tp->task_socket, &task_select_writebits);
    TASK_FD_CLR(tp->task_socket, &task_select_exceptbits);

    /* See if we can reduce task_max_socket */
    if (tp->task_socket == task_max_socket) {
	do {
	    task_max_socket--;
	} while (task_max_socket >= 0
	      && !TASK_FD_ISSET(task_max_socket, &task_select_readbits)
	      && !TASK_FD_ISSET(task_max_socket, &task_select_writebits)
	      && !TASK_FD_ISSET(task_max_socket, &task_select_exceptbits));
    }

    /* Delete from socket to task table if no routines present */

    tp->task_socket = -1;
    BIT_RESET(tp->task_flags, TASKF_CONNECT | TASKF_ACCEPT);
    tp->task_recv_method = 0;
    tp->task_accept_method = 0;
    if (BIT_TEST(tp->task_flags, TASKF_LOWPRIO)) {
	TMQ_LP_REMOVE(tp, task_read_queue);
    } else {
	TMQ_REMOVE(tp, task_read_queue);
    }
    tp->task_write_method = 0;
    tp->task_connect_method = 0;
    TMQ_REMOVE(tp, task_write_queue);
    tp->task_except_method = 0;
    TMQ_REMOVE(tp, task_except_queue);
}


/*
 *	task_addr_local - Set local socket address (bind())
 */
int
task_addr_local(task *tp, sockaddr_un *ap)
{
    int rc = 0;
    int len;
    struct sockaddr *addr = sock2unix(ap, &len);
    
    tracef("task_addr_local: task %s address %#A",
	   task_name(tp),
	   ap);

    if (!BIT_TEST(task_state, TASKS_TEST) &&
	(bind(tp->task_socket, addr, len) < 0)) {
	rc = errno;
	trace_log_tp(tp,
		     0,
		     LOG_ERR,
		     (": %m"));
    } else {
	trace_tp(tp,
		 TR_TASK,
		 0,
		 (NULL));
    }

    return errno = rc;	/* Reset errno */
}


/*
 *	task_connect - Set remote socket address (connect())
 */
int
task_connect(task *tp, if_addr *ifap)
{
    int rc = 0;
    int len;
    struct sockaddr *addr = sock2unix(tp->task_addr, &len);
    
    tracef("task_connect: task %s addr %#A",
	   task_name(tp),
	   tp->task_addr);

#ifdef PROTO_INET6
    if (ifap) {
        task_set_option(tp, TASKOPTION_SENDIF, ifap);
    }
#endif /* PROTO_INET6 */

    if (!BIT_TEST(task_state, TASKS_TEST) &&
	(connect(tp->task_socket, addr, len) < 0)) {
	rc = errno;
	trace_tp(tp,
		 TR_TASK,
		 0,
		 (": %m"));
    } else {
	trace_tp(tp,
		 TR_TASK,
		 0,
		 (NULL));
    }

    return errno = rc;	/* Reset errno */
}


/*
 *  task_socket_options - Sets socket options.
 *  Isolates protocols from system layer.
 */
int
task_set_option(task *tp, int option, ...)
{
#if defined(PROTO_INET6) || defined (IP_MULTICAST)
	if_addr *ifap;
#endif	/* PROTO_INET6 || IP_MULTICAST */
#if defined(PROTO_INET6) && defined(IPV6_PKTOPTIONS)
	byte cmsgbuf[256];
	struct cmsghdr *cmsgp;
	struct in6_pktinfo *pi;
	int cmsglen;
#endif	/* PROTO_INET6 && IPV6_PKTOPTIONS */
#if defined(IP_MULTICAST)
	struct ip_mreq mreq;
#endif	/* IP_MULTICAST */
#if defined(PROTO_INET6)
	struct ipv6_mreq mreq6;
	int is_v6;
#endif 	/* PROTO_INET6 */
#ifndef LINGER_NO_PARAM
	struct linger linger;
#endif  /* LINGER_NO_PARAM */
#ifdef  IP_MULTICAST
	byte value_uchar;
#endif  /* IP_MULTICAST */
	int len, level, opt, rc, s, value_int;
	void_t ptr;
	va_list ap;

	rc = 0;
	opt = -1;		/* quiet gcc in semi-safe way */
	len = sizeof(value_int);
	ptr = (void_t) &value_int;
	level = SOL_SOCKET;

	va_start(ap, option);

	tracef("task_set_option: task %s socket %d option %s(%d)",
	    task_name(tp), tp->task_socket,
	    trace_state(task_socket_options, option), option);

	switch (option) {
	case TASKOPTION_REUSEADDR:
		opt = SO_REUSEADDR;
		goto int_value;
	case TASKOPTION_DONTROUTE:
		opt = SO_DONTROUTE;
		goto int_value;
	case TASKOPTION_KEEPALIVE:
		opt = SO_KEEPALIVE;
		goto int_value;
	case TASKOPTION_DEBUG:
		opt = SO_DEBUG;
		goto int_value;
	case TASKOPTION_LINGER:
		opt = SO_LINGER;
#if			defined(LINGER_NO_PARAM)
		ptr = 0;
		len = 0;
#else			/* LINGER_NO_PARAM */
		linger.l_linger = va_arg(ap, int);
		linger.l_onoff = linger.l_linger ? TRUE : FALSE;
		ptr = (void_t) &linger;
		len = sizeof(struct linger);
		tracef(" value { %d, %d }", linger.l_linger, linger.l_onoff);
#endif			/* LINGER_NO_PARAM */
		goto setsocketopt;

	case TASKOPTION_RECVBUF:
#if			defined(SO_RCVBUF)
		opt = SO_RCVBUF;
		goto int_value;
#endif  		/* SO_RCVBUF */
		break;

	case TASKOPTION_SENDBUF:
#if			defined(SO_SNDBUF)
		opt = SO_SNDBUF;
		goto int_value;
#endif			/* SO_SNDBUF */
		break;

	case TASKOPTION_BROADCAST:
#if			defined(SO_BROADCAST)
		opt = SO_BROADCAST;
		goto int_value;
#endif			/* SO_BROADCAST */
		break;

	case TASKOPTION_USELOOPBACK:
#if			defined(SO_USELOOPBACK)
		opt = SO_USELOOPBACK;
		goto int_value;
#endif  		/* SO_USELOOPBACK */
		break;

	case TASKOPTION_IPSEC_ENCRYPTED:
#if			defined(IPSEC)
		level = IPPROTO_IP;
		opt = IP_ENCRYPTED;
		goto int_value;
#endif			/* IPSEC */
		goto not_supported;

	case TASKOPTION_TOS:
#if			defined(IP_TOS)
		opt = IP_TOS;
		level = IPPROTO_IP;
		goto int_value;
#endif  		/* IP_TOS */
		goto not_supported;

	case TASKOPTION_RCVIF:
#if			defined(IP_RECVIF)
		opt = IP_RECVIF;
		level = IPPROTO_IP;
		goto int_value;
#endif			/* IP_RECVIF */
		goto not_supported;

	case TASKOPTION_TTL:
#ifdef PROTO_INET6
		if(tp->task_rtfamily == AF_INET6) {
			opt = IPV6_UNICAST_HOPS;
			level = IPPROTO_IPV6;
			value_uchar = va_arg(ap, int);
			ptr = (void_t) &value_uchar;
			len = sizeof (value_uchar);
			goto setsocketopt;
		}
#endif /* PROTO_INET6 */

#ifdef  IP_TTL
		opt = IP_TTL;
		level = IPPROTO_IP;
		goto int_value;
#endif  /* IP_TTL */
		goto not_supported;

	case TASKOPTION_RCVDSTADDR:
#ifdef IP_RECVDSTADDR
#if defined(PROTO_INET6) && defined(IPV6_PKTINFO)
		switch (tp->task_rtfamily) {
		default:
			level = IPPROTO_IP;
			opt = IP_RECVDSTADDR;
			break;
		case AF_INET6:
			level = IPPROTO_IPV6;
			opt = IPV6_PKTINFO;
			break;
		}
#else  /* PROTO_INET6 */
		opt = IP_RECVDSTADDR;
		level = IPPROTO_IP;
#endif /* !PROTO_INET6 */
		goto int_value;
#else /* IP_RECVDSTADDR */
		goto not_supported;
#endif  /* IP_RECVDSTADDR */

	case TASKOPTION_PKTOPTIONS:
#if defined(PROTO_INET6) && defined(IPV6_PKTOPTIONS)
	{
		cmsgp = va_arg(ap, struct cmsghdr *);
		cmsglen = va_arg(ap, int);
		opt = IPV6_PKTOPTIONS;
		level = IPPROTO_IPV6;
		ptr = (void_t) cmsgp;
		len = cmsglen;
		goto setsocketopt;
	}
#else  /* !IPV6_PKTOPTIONS */
		goto not_supported;
#endif /* IPV6_PKTOPTIONS */

#ifdef PROTO_INET6
	case TASKOPTION_RCVIF6:
	/*
	 * XXX is this the same as IP_RECVIF for systems that don't support
	 * IP_RECVIF?
	 */
#ifdef  IPV6_RECVIF
		opt = IPV6_RECVIF;
		level = IPPROTO_IPV6;
		goto int_value;
#else /* IPV6_RECVIF */
		goto not_supported;
#endif  /* IPV6_RECVIF */

    case TASKOPTION_RCVHOPLIM:
#ifdef  IPV6_RECVHOPLIM
		opt = IPV6_RECVHOPLIM;
		level = IPPROTO_IPV6;
		goto int_value;
#else /* IPV6_RECVHOPLIM */
# ifdef IPV6_HOPLIMIT
		opt = IPV6_HOPLIMIT;
		level = IPPROTO_IPV6;
		goto int_value;
# else /* IPV6_HOPLIMIT */
		goto not_supported;
# endif /* IPV6_HOPLIMIMIT */
#endif  /* IPV6_RECVHOPLIM */
#endif /* PROTO_INET6 */

	case TASKOPTION_IPHEADER_INC:
#ifdef IP_HDRINCL
		opt = IP_HDRINCL;
		level = IPPROTO_IP;
		goto int_value;
#else /* IP_HDRINCL */
		goto not_supported;
#endif  /* IP_HDRINCL */

	case TASKOPTION_SENDIF: /* UDP/TCP set/get Ancillary Data */
#if defined(PROTO_INET6) && defined(IPV6_PKTOPTIONS)
		ifap = va_arg(ap, if_addr *);
		bzero((caddr_t *) cmsgbuf, sizeof(cmsgbuf));
		cmsgp = (struct cmsghdr *) cmsgbuf;
		opt = IPV6_PKTOPTIONS;
		level = IPPROTO_IPV6;
		cmsgp->cmsg_len   = CMSG_LEN(sizeof(struct in6_pktinfo));
		cmsgp->cmsg_level = IPPROTO_IPV6;
		cmsgp->cmsg_type  = IPV6_PKTINFO;
		pi = (struct in6_pktinfo *) CMSG_DATA(cmsgp);
		if (ifap) {
			bzero((caddr_t *)&pi->ipi6_addr, sizeof(pi->ipi6_addr));
			pi->ipi6_ifindex = ifap->ifa_link->ifl_index;
		}
		ptr = (void_t) cmsgp;
		len = CMSG_SPACE(sizeof(struct in6_pktinfo));
		goto setsocketopt;
#else  /* !IPV6_PKTOPTIONS */
		goto not_supported;
#endif /* IPV6_PKTOPTIONS */

	case TASKOPTION_CHECKSUM:
#if defined(PROTO_INET6) && defined(IPV6_CHECKSUM)
		opt = IPV6_CHECKSUM;
		level = IPPROTO_IPV6;
		goto int_value;
#else
		goto not_supported;
#endif  /* IPV6_CHECKSUM */



#if	!defined(IP_MULTICAST) && !defined(PROTO_INET6)

	case TASKOPTION_GROUP_ADD:
	case TASKOPTION_GROUP_DROP:
	case TASKOPTION_MULTI_IF:
	case TASKOPTION_MULTI_LOOP:
	case TASKOPTION_MULTI_TTL:
	case TASKOPTION_MULTI_ROUTE:
		goto not_supported;

#else	/* IP_MULTICAST || PROTO_INET6 */

	case TASKOPTION_GROUP_ADD:
#ifdef PROTO_INET6
		if (tp->task_rtfamily == AF_INET6) {
			level = IPPROTO_IPV6;
#ifdef  IPV6_JOIN_GROUP
			opt = IPV6_JOIN_GROUP;
#else
#ifdef  IPV6_JOIN_MEMBERSHIP
			opt = IPV6_JOIN_MEMBERSHIP;
#else
			opt = IPV6_ADD_MEMBERSHIP;
#endif  /* IPV6_JOIN_MEMBERSHIP  */
#endif  /* IPV6_JOIN_GROUP  */
		} else {
			level = IPPROTO_IP;
			opt = IP_ADD_MEMBERSHIP;
		} /* if rtfamily == AF_INET6  */
#else  /* !PROTO_INET6 */
		level = IPPROTO_IP;
		opt = IP_ADD_MEMBERSHIP;
#endif /* PROTO_INET6 */
		goto ip_mreq_value;

	case TASKOPTION_GROUP_DROP:
#ifdef PROTO_INET6
		if (tp->task_rtfamily == AF_INET6) {
			level = IPPROTO_IPV6;
#ifdef  IPV6_LEAVE_GROUP
			opt = IPV6_LEAVE_GROUP;
#else
#ifdef  IPV6_LEAVE_MEMBERSHIP
			opt = IPV6_LEAVE_MEMBERSHIP;
#else
			opt = IPV6_DROP_MEMBERSHIP;
#endif /* IPV6_LEAVE_MEMBERSHIP  */
#endif /* IPV6_LEAVE_GROUP  */
		} else {
			level = IPPROTO_IP;
			opt = IP_DROP_MEMBERSHIP;
		}  /* if rtfamily == AF_INET6  */
#else  /* !PROTO_INET6 */
		level = IPPROTO_IP;
		opt = IP_DROP_MEMBERSHIP;
#endif /* PROTO_INET6 */

	ip_mreq_value: {
#ifdef PROTO_INET6
		is_v6 = 0;
#endif /* PROTO_INET6 */

		ifap = va_arg(ap, if_addr *);
		if (ifap) {
			tracef(" interface %A(%s)", ifap->ifa_addr_local,
			ifap->ifa_link->ifl_name);
			if (!BIT_TEST(ifap->ifa_state, IFS_MULTICAST)) {
				tracef(": multicast not supported on this"
				    " interface");
				break;
			}

			switch(socktype(ifap->ifa_addr_local)) {
			case AF_INET:
				mreq.imr_interface =
				    sock2in(ifap->ifa_addr_local);
				mreq.imr_multiaddr =
				    sock2in(va_arg(ap, sockaddr_un *));
				break;
#ifdef PROTO_INET6
			case AF_INET6:
				mreq6.ipv6mr_multiaddr =
				    sock2in6(va_arg(ap, sockaddr_un *));
#ifdef MREQ_INTF_IN6
				mreq6.ipv6mr_interface =
				    sock2in6(va_arg(ap, sockaddr_un *));
#else
				mreq6.ipv6mr_interface =
				     ifap->ifa_link->ifl_index;
#endif /* MREQ_INTF_IN6 */
				is_v6 = TRUE;
				break;
#endif /* PROTO_INET6  */
			}   /* end switch */
		} else {    /* no ifap  */
			sockaddr_un *multiaddr = va_arg(ap, sockaddr_un *);
			sockaddr_un *interface_addr = va_arg(ap, sockaddr_un *);
			switch (socktype(multiaddr)) {
			case AF_INET:
				mreq.imr_interface = sock2in(inet_addr_default);
				mreq.imr_multiaddr = sock2in(multiaddr);
				break;
#ifdef PROTO_INET6
			case AF_INET6:
			mreq6.ipv6mr_multiaddr = sock2in6(multiaddr);
#ifdef MREQ_INTF_IN6
			mreq6.ipv6mr_interface = sock2in6(interface_addr);
#else
			mreq6.ipv6mr_interface = 0; /* will cause ERROR */
#endif /* MREQ_INTF_IN6 */
			is_v6 = TRUE;
			break;
#endif /* PROTO_INET6 */
			}  /* switch */
		}   /* if ifap */

#ifdef PROTO_INET6
		if (is_v6) {
			tracef(" group %A",
			    sockbuild_in6(0, (byte *)&mreq6.ipv6mr_multiaddr));
			ptr = (void_t) &mreq6;
			len = sizeof (mreq6);
		} else
#endif /* PROTO_INET6 */
		{
		tracef(" group %A", sockbuild_in(0, mreq.imr_multiaddr.s_addr));
		ptr = (void_t) &mreq;
		len = sizeof (mreq);
		}
		goto setsocketopt;
	}  /* end code block for ip_mreq_value:   */

	case TASKOPTION_MULTI_IF:
		ifap = va_arg(ap, if_addr *);
#ifdef PROTO_INET6
		switch (socktype(ifap->ifa_addr_local)) {
		case AF_INET:
#endif
			level = IPPROTO_IP;
			opt = IP_MULTICAST_IF;
			ptr = (void_t) &sock2in(ifap->ifa_addr_local);
			len = sizeof (sock2in(ifap->ifa_addr_local));
#ifdef PROTO_INET6
			break;
		case AF_INET6:
			level = IPPROTO_IPV6;
			opt = IPV6_MULTICAST_IF;
			ptr = (void_t) &ifap->ifa_link->ifl_index; /* XXX */
			len = sizeof (unsigned int);
			break;
		}
#endif /* PROTO_INET6 */
		tracef(" interface %A(%s)", ifap->ifa_addr_local,
		    ifap->ifa_link->ifl_name);
		goto setsocketopt;
	case TASKOPTION_MULTI_LOOP:
		switch (tp->task_rtfamily) {
#ifdef PROTO_INET6 
		case AF_INET6:
			level = IPPROTO_IPV6;
			opt = IPV6_MULTICAST_LOOP;
			value_int = va_arg(ap, int);
			ptr = (void_t) &value_int;
			len = sizeof (value_int);
			tracef(" loop %d", value_int);
#endif /* PROTO_INET6 */
		default: /* INET */
			level = IPPROTO_IP;
			opt = IP_MULTICAST_LOOP;
			value_uchar = va_arg(ap, int);
			ptr = (void_t) &value_uchar;
			len = sizeof (value_uchar);
			tracef(" loop %d", value_uchar);
			break;
		}
		goto setsocketopt;

	case TASKOPTION_MULTI_TTL:
		switch (tp->task_rtfamily) {
		default: /* INET */
			level = IPPROTO_IP;
			opt = IP_MULTICAST_TTL;
			value_uchar = va_arg(ap, int);
			ptr = (void_t) &value_uchar;
			len = sizeof (value_uchar);
			tracef(" ttl %d", value_uchar);
			break;
#ifdef PROTO_INET6
		case AF_INET6:
			level = IPPROTO_IPV6;
			opt = IPV6_MULTICAST_HOPS;
			value_int = va_arg(ap, int);
			ptr = (void_t) &value_int;
			len = sizeof (value_int);
			tracef(" hops %d", value_int);
		break;
#endif   /* !PROTO_INET6 */
		}
		goto setsocketopt;

	case TASKOPTION_MULTI_ROUTE:
#ifdef  IP_MULTICAST_ROUTING
#ifndef MRT_INIT
#define MRT_INIT        DVMRP_INIT
#define MRT_DONE        DVMRP_DONE
#endif        /* MRT_INIT */

		level = IPPROTO_IP;
		value_int = va_arg(ap, int);
		opt = value_int ? MRT_INIT : MRT_DONE;
		tracef(" %s", value_int ? "On" : "Off");
		goto setsocketopt;
#else /* IP_MULTICAST_ROUTING */
		goto not_supported;
#endif  /* IP_MULTICAST_ROUTING */

#ifdef  KRT_IPMULTI_TTL0
	case TASKOPTION_ADD_VIF:
#ifdef  IP_MULTICAST_ROUTING
#ifndef MRT_ADD_VIF
#define MRT_ADD_VIF DVMRP_ADD_VIF
#endif  /* MRT_ADD_VIF */
	{
		struct vifctl  *vc;

		level = IPPROTO_IP;
		opt = MRT_ADD_VIF;
		vc = va_arg(ap, struct vifctl *);
		ptr = (void_t) vc;
		len = sizeof(struct vifctl);
		tracef(" interface %A",
		    sockbuild_in(0, vc->vifc_lcl_addr.s_addr));
		goto setsocketopt;
	}
#else /* IP_MULTICAST_ROUTING */
		goto not_supported;
#endif  /* IP_MULTICAST_ROUTING */

	case TASKOPTION_DEL_VIF:
#ifdef  IP_MULTICAST_ROUTING
#ifndef MRT_DEL_VIF
#define MRT_DEL_VIF DVMRP_DEL_VIF
#endif  /* MRT_DEL_VIF */
		level = IPPROTO_IP;
		opt = MRT_DEL_VIF;
		ifap = va_arg(ap, if_addr *);
		ptr = (void_t) & ifap->ifa_vif;
		len = sizeof(vifi_t);
		tracef(" interface %A(%s)", IFA_UNIQUE_ADDR(ifap),
		    ifap->ifa_link->ifl_name);
		goto setsocketopt;
#else /* IP_MULTICAST_ROUTING */
		goto not_supported;
#endif  /* IP_MULTICAST_ROUTING */

	case TASKOPTION_ADD_MFC:
#ifdef  IP_MULTICAST_ROUTING
#ifndef MRT_ADD_MFC
#define MRT_ADD_MFC     DVMRP_ADD_MFC
#endif  /* MRT_ADD_MFC */
	{
		struct mfcctl  *mc;

		level = IPPROTO_IP;
		opt = MRT_ADD_MFC;
		mc = va_arg(ap, struct mfcctl *);
		ptr = (void_t) mc;
		len = sizeof(struct mfcctl);
		tracef(" group %A source %A",
		    sockbuild_in(0, mc->mfcc_mcastgrp.s_addr),
		    sockbuild_in(0, mc->mfcc_origin.s_addr));
		goto setsocketopt;
	}
#else /* IP_MULTICAST_ROUTING */
		goto not_supported;
#endif  /* IP_MULTICAST_ROUTING */

	case TASKOPTION_DEL_MFC:
#ifdef  IP_MULTICAST_ROUTING
#ifndef MRT_DEL_MFC
#define MRT_DEL_MFC     DVMRP_DEL_MFC
#else /* MRT_DEL_MFC */
#define delmfcctl       mfcctl
#endif  /* MRT_DEL_MFC */
	{
		struct delmfcctl *mc;

		level = IPPROTO_IP;
		opt = MRT_DEL_MFC;
		mc = va_arg(ap, struct delmfcctl *);
		ptr = (void_t) mc;
		len = sizeof(struct delmfcctl);
		tracef(" group %A source %A",
		    sockbuild_in(0, mc->mfcc_mcastgrp.s_addr),
		    sockbuild_in(0, mc->mfcc_origin.s_addr));
		goto setsocketopt;
	}
#else /* IP_MULTICAST_ROUTING */
		goto not_supported;
#endif  /* IP_MULTICAST_ROUTING */

#ifdef  TASKOPTION_ASSERT
	case TASKOPTION_ASSERT:
#ifdef  IP_MULTICAST_ROUTING
		opt = MRT_ASSERT;
		level = IPPROTO_IP;
		goto int_value;
#else /* IP_MULTICAST_ROUTING */
		goto not_supported;
#endif  /* IP_MULTICAST_ROUTING */
#endif  /* TASKOPTION_ASSERT */

#endif  /* KRT_IPMULTI_TTL0 */

#endif /* IP_MULTICAST || PROTO_INET6 */

	int_value:
		value_int = va_arg(ap, int);
		tracef(" value %d", value_int);
		goto setsocketopt;

	setsocketopt:
		if (!BIT_TEST(task_state, TASKS_TEST))
			rc = setsockopt(tp->task_socket, level, opt, ptr, len);
		break;

	case TASKOPTION_NONBLOCKING:
		value_int = va_arg(ap, int);
		tracef(" value %d", value_int);
		if (!BIT_TEST(task_state, TASKS_TEST)) {
#ifdef  FIONBIO
			rc = task_ioctl(tp->task_socket, (u_long) FIONBIO,
			    (caddr_t) &value_int, sizeof (value_int));
#else /* FIONBIO */
			NON_INTR(rc, fcntl(tp->task_socket, F_SETFL, O_NDELAY));
#endif  /* FIONBIO */
		}
		break;

	not_supported:
		tracef(": not supported");
		break;
	default:
		rc = -1;
		errno = EINVAL;
	}   /*  end switch  */

	s = errno;
	if (rc < 0) {
		trace_log_tp(tp, 0, LOG_ERR, (": %m"));
	} else {
		trace_tp(tp, TR_TASK, 0, (NULL));
	}
	errno = s;

	va_end(ap);
	return rc;
}


/*  */
/*
 *	Memory allocation
 */

void_t
task_mem_malloc(task *tp, size_t size)
{
    void_t p;

    p = (void_t) malloc(size);
    if (!p) {
	trace_log_tp(tp,
		     0,
		     LOG_ERR,
		     ("task_mem_malloc: Can not malloc(%d) for %s",
		      size,
		      task_name(tp)));
	task_quit(ENOMEM);
    }

    return p;
}


void_t
task_mem_calloc(task *tp, u_int number, size_t size)
{
    void_t p;

    p = (void_t) calloc(number, size);
    if (!p) {
	trace_log_tp(tp,
		     0,
		     LOG_ERR,
		     ("task_mem_calloc: Can not calloc(%d, %d) for %s",
		      number,
		      size,
		      task_name(tp)));
	task_quit(ENOMEM);
    }

    return p;
}


void_t
task_mem_realloc(task *tp, void_t p, size_t size)
{
    p = (void_t) realloc(p, size);
    if (!p) {
	trace_log_tp(tp,
		     0,
		     LOG_ERR,
		     ("task_mem_realloc: Can not realloc( ,%d) for %s",
		      size,
		      task_name(tp)));
	task_quit(ENOMEM);
    }

    return p;
}


char *
task_mem_strdup(task *tp, const char *str)
{
    return strcpy((char *) task_mem_malloc(tp, (size_t) (strlen(str) + 1)), str);
}


/*ARGSUSED*/
void
task_mem_free(task *tp, void_t p)
{
    if (p) {
	free((caddr_t) p);
    }
}


/**/

#ifdef	MEMORY_ALIGNMENT
#define	TASK_BLOCK_ALIGN	MEMORY_ALIGNMENT
#else	/* MEMORY_ALIGNMENT */
#define	TASK_BLOCK_ALIGN	MAX(sizeof (off_t), sizeof (off_t *))
#endif	/* MEMORY_ALIGNMENT */

/* Head of block size queue */
struct task_size_block task_block_head = {
	    &task_block_head, &task_block_head
	};

/* Pre-allocated block for size blocks */
static struct task_size_block task_block_sizes = {
    	    &task_block_sizes, &task_block_sizes,
	    {
		&task_block_sizes,
		(struct task_block *) 0,
		"task_size_block"
	    }
	};

static struct task_size_block task_block_names = {
    	    &task_block_names, &task_block_names,
	    {
		&task_block_names,
		(struct task_block *) 0,
		"task_block"
	    }
	};
static block_t task_block_name = &task_block_names.tsb_block;

static qelement task_page_list = (qelement) 0;

#define	task_page_free(vp) \
	do { \
	    register qelement Xqp = (void_t) (vp); \
	    bzero((void_t) Xqp, task_pagesize); \
	    Xqp->q_forw = task_page_list; \
	    task_page_list = Xqp; \
	} while (0)

#ifdef	TASK_BLOCK_DEBUG
#define	TASK_BLOCK_ROUNDUP(size) ROUNDUP(size + sizeof (block_t), TASK_BLOCK_ALIGN)
#else	/* TASK_BLOCK_DEBUG */
#define	TASK_BLOCK_ROUNDUP(size) ROUNDUP(size, TASK_BLOCK_ALIGN)
#endif	/* TASK_BLOCK_DEBUG */

block_t
task_block_init(register size_t size, const char *name)
{
    register struct task_size_block *tsb = task_block_head.tsb_forw;
    struct task_block *tbp;
    register int count;
    size_t runt;

    /* Round up to the minimum size */
    size = TASK_BLOCK_ROUNDUP(size);

    count = task_pagesize / size;
    if (count < 1) {
    	/* Greater than a page, allocate one at a time */
	count = 1;
    }

    /* Look for this size in current list */
    do {
	if (tsb->tsb_size == size) {
	    /* Found the size block */

	    /* Check for duplicate request */
	    for (tbp = &tsb->tsb_block; tbp; tbp = tbp->tb_next) {
		if (!strcmp(name, tbp->tb_name)) {
		    /* Already exists */

		    goto Return;
		}
	    }

	    /* Allocate a block for this caller and append it to the chain */
	    tbp = (struct task_block *) task_block_alloc(task_block_name);
	    tbp->tb_next = tsb->tsb_block.tb_next;
	    tsb->tsb_block.tb_next = tbp;
	    goto Found;
	} else if (size < tsb->tsb_size) {
	    /* Insert before this one */

	    break;
	}
    } while ((tsb = tsb->tsb_forw) != &task_block_head) ;

    tsb = tsb->tsb_back;

    /* Allocate a block before this element */
    INSQUE(task_block_alloc(&task_block_sizes.tsb_block), tsb);
    tsb = tsb->tsb_forw;

    /* Fill in the info */
    tsb->tsb_size = size;
    tsb->tsb_count = count;

    /* Allocate a block for the runt if necessary */
    runt = (task_pagesize - ((size * count) % task_pagesize)) % task_pagesize;
    if (runt > TASK_BLOCK_ALIGN) {
	tsb->tsb_runt = task_block_init(
#ifdef	TASK_BLOCK_DEBUG
					runt - sizeof (block_t),
#else	/* TASK_BLOCK_DEBUG */
					runt,
#endif	/* TASK_BLOCK_DEBUG */
					"runt");
    }

    tbp = &tsb->tsb_block;

 Found:
    /* Link the name block back to the size block */
    tbp->tb_block = tsb;

    /* Save the name (must be a constant) */
    tbp->tb_name = name;

 Return:
    /* Set init request count */
    tbp->tb_n_init++;

    return tbp;
}


static void_t
task_block_sbrk(size_t size)
{
/*
 * USE_MMAP uses MAP_ANON, which doesn't exist on some systems.
 * on these systems one should map on the file /dev/zero
 */
#if defined(HAVE_MMAP) && defined(HAVE_MAP_ANON)
    size_t my_size;
    void_t vp;

    my_size = ROUNDUP(size, task_pagesize);
    vp = mmap(0, my_size, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);

    /* mmap should always return page aligned */
    GASSERT(!((size_t)vp % task_pagesize));

    if (vp == GS2A(-1)) {
	int error = errno;
	
	trace_log_tf(trace_global,
		     0,
		     LOG_ERR,
		     ("task_block_sbrk: mmap(0, %u, ...): %m",
		      my_size));
	task_quit(error);
    }

    bzero(vp, my_size);
    return vp;
#else
    size_t my_size = ROUNDUP(size, task_pagesize);
    size_t unaligned;
    void_t vp;

#ifdef PURIFY
if(purify_is_running()) 
    vp = (void_t) memalign(task_pagesize, (int) my_size);
else
#endif /* PURIFY */
    vp = (void_t) sbrk((int) my_size);

    if (vp == GS2A(-1)) {
	int error = errno;
	
	trace_log_tf(trace_global,
		     0,
		     LOG_ERR,
		     ("task_block_sbrk: sbrk(%u): %m",
		      my_size));
	task_quit(error);
    }

    /* Verify that we are page aligned */
    unaligned = (size_t) vp % task_pagesize;
    if (unaligned) {
	void_t vp1;

#ifdef	DEBUG
	trace_only_tf(trace_global,
		      0,
		      ("task_block_sbrk: mod %u rounding to %u",
		       unaligned,
		       task_pagesize));
#endif	/* DEBUG */

#ifdef PURIFY
if(purify_is_running())
        vp1 = (void_t) memalign(task_pagesize, (task_pagesize - unaligned));
else
#endif /* PURIFY */
	vp1 = (void_t) sbrk((int) (task_pagesize - unaligned));
	if (vp1 == GS2A(-1)) {
	    int error = errno;
	
	    trace_log_tf(trace_global,
			 0,
			 LOG_ERR,
			 ("task_block_sbrk: rounding sbrk(%u): %m",
			  task_pagesize - unaligned));
	    task_quit(error);
	}

	assert((caddr_t) vp1 == (caddr_t) vp + my_size);

	/* XXX - Save the unaligned block? */
	vp = (caddr_t) vp + (task_pagesize - unaligned);
    }
    
    bzero(vp, my_size);
    return vp;
#endif /* HAVE_MMAP && HAVE_MAP_ANON */
}


static INLINE void_t
task_page_alloc(void)
{
    if (task_page_list) {
	register qelement qp = task_page_list;
	task_page_list = qp->q_forw;
	qp->q_forw = (qelement) 0;
	return (void_t) qp;
    } else {
	return task_block_sbrk(task_pagesize);
    }
}


void_t
task_block_malloc(size_t size)
{
    if (size > task_pagesize) {
	return task_block_sbrk(size);
    } else {
	return task_page_alloc();
    }
}


void
task_block_reclaim(size_t size, void_t p)
{
    int count = ROUNDUP(size, task_pagesize) / task_pagesize;

    while (count--) {
	task_page_free(p);
	p = (void_t) ( (caddr_t) p + task_pagesize);
    }
}


qelement
task_block__alloc(register block_t tbp)
{
    register qelement ap;
    register struct task_size_block *tsb = tbp->tb_block;

    /* Allocate another block of structures */
    register u_int n = tsb->tsb_count;
    register size_t size = n * tsb->tsb_size;
    register union {
	qelement qp;
	caddr_t cp;
    } np;

    if (size > task_pagesize) {
	/* Not a page sized block */

	np.cp = (caddr_t) task_block_sbrk(size);
    } else {
	/* Getting one page */

	np.cp = (caddr_t) task_page_alloc();
    }
    ap = np.qp;

    tsb->tsb_n_free += n;

    while (--n) {
	register qelement qp = np.qp;
	    
	np.cp += tsb->tsb_size;
	qp->q_forw = np.qp;
    }

    if (tsb->tsb_runt) {
	/* Find a home for the runt */

	np.cp += tsb->tsb_size;
	np.qp->q_forw = tsb->tsb_runt->tb_block->tsb_free;
	tsb->tsb_runt->tb_block->tsb_free = np.qp;
	tsb->tsb_runt->tb_block->tsb_n_free++;
    }

    return ap;
}


static void
task_block_init_all(void)
{
    size_t runt;

    /* Init the size block */
    task_block_sizes.tsb_size = TASK_BLOCK_ROUNDUP(sizeof (struct task_size_block));
    task_block_sizes.tsb_count = task_pagesize / task_block_sizes.tsb_size;

    /* Put it on the linked list */
    INSQUE(&task_block_sizes, &task_block_head);

    /* Init the names block */
    task_block_names.tsb_size = TASK_BLOCK_ROUNDUP(sizeof (struct task_block));
    task_block_names.tsb_count = task_pagesize / task_block_names.tsb_size;

    /* Put it on the linked list */
    INSQUE(&task_block_names, &task_block_head);

    /* Create run block for task_block_sizes */
    if ((runt = task_pagesize - (task_block_sizes.tsb_size * task_block_sizes.tsb_count))) {
	task_block_sizes.tsb_runt = task_block_init(runt, "runt");
    }

    /* Create run block for task_block_names */
    if ((runt = task_pagesize - (task_block_names.tsb_size * task_block_names.tsb_count))) {
	task_block_names.tsb_runt = task_block_init(runt, "runt");
    }
}


static void
task_block_dump(FILE *fp)
{
    register struct task_size_block *tsb = task_block_head.tsb_forw;

    fprintf(fp, "Task Blocks:\n\tAllocation size: %5d\n\n",
	    task_pagesize);

    do {
	struct task_block *tbp = &tsb->tsb_block;

	fprintf(fp, "\tSize: %5u\tN_free: %u\tLastAlloc: %08X\n",
		tsb->tsb_size,
		tsb->tsb_n_free,
		tsb->tsb_tmp);

	do {
	    fprintf(fp, "\t%32s\tInit: %8u  Alloc: %8u  Free: %8u  InUse: %8u\n",
		    tbp->tb_name,
		    tbp->tb_n_init,
		    tbp->tb_n_alloc,
		    tbp->tb_n_free,
		    tbp->tb_n_alloc - tbp->tb_n_free);
	} while ((tbp = tbp->tb_next)) ;

	fprintf(fp, "\n");

    } while ((tsb = tsb->tsb_forw) != &task_block_head) ;

    fprintf(fp, "\n");
}


/**/

struct task_floating_sockets {
    struct task_floating_sockets *tfs_next;
    int tfs_socket;
    task *tfs_task;
    const char *tfs_name;
};

static struct task_floating_sockets *task_floating_sockets;

int
task_floating_socket(task *tp, int s, const char *name)
{
    static block_t task_floating_block = (block_t) 0;

    if (s > -1) {
	struct task_floating_sockets *tfs;

	if (!task_floating_block) {
	    task_floating_block = task_block_init(sizeof (*tfs), "task_floating_sockets");
	}

	tfs = (struct task_floating_sockets *) task_block_alloc(task_floating_block);

	tfs->tfs_socket = s;
	tfs->tfs_task = tp;
	tfs->tfs_name = task_mem_strdup((task *) 0, name);
	tfs->tfs_next = task_floating_sockets;
	task_floating_sockets = tfs;
    }

    return s;    
}


/*
 * task_get_socket gets a socket, retries later if no buffers at present
 */

int
task_get_socket(task *tp, int domain, int type, int proto)
{
    int retry, get_socket, error;

    tracef("task_get_socket: domain AF_%s  type SOCK_%s  protocol %d",
	   trace_value(task_domain_bits, domain),
	   trace_value(task_socket_types, type),
	   proto);

    if (BIT_TEST(task_state, TASKS_TEST)) {
	if (task_max_socket) {
	    get_socket = ++task_max_socket;
	} else {
	    /* Skip first few that may be used for logging */
	    get_socket = (task_max_socket = 2);
	}
    } else {
	retry = 2;			/* if no buffers a retry might work */
	while ((get_socket = socket(domain, type, proto)) < 0 && retry--) {
	    error = errno;
	    trace_log_tp(tp,
			 0,
			 LOG_ERR,
			 (": %m"));
	    if (error == ENOBUFS) {
		(void) sleep(5);
	    } else if (error == EINTR) {
		/* The system call was interrupted, probably by */
		/* a signal.  Silently retry */
		retry++;
		continue;
	    } else {
		break;
	    }
	}
    }

    if (get_socket >= 0) {
	trace_tp(tp,
		 TR_TASK,
		 0,
		 ("  socket %d",
		  get_socket));
    } else {
	trace_clear();
    }

    return get_socket;
}


/*
 *	Who are we connected to?
 */
sockaddr_un *
task_get_addr_remote(task *tp)
{
    caddr_t name[MAXPATHLEN+2];
    size_t namelen = sizeof name;

    if (getpeername(tp->task_socket,
		    (struct sockaddr *) name,
		    (int *) &namelen) < 0) {
	switch (errno) {
	case ENOTCONN:
	    /* Ignore */
	    break;

	default:
	    trace_log_tp(tp,
			 0,
			 LOG_ERR,
			 ("task_get_addr_remote: getpeername(%s): %m",
			  task_name(tp)));
	}
	return (sockaddr_un *) 0;
    }

    return sock2gated((struct sockaddr *) name, namelen);
}


sockaddr_un *
task_get_addr_local(task *tp)
{
    caddr_t name[MAXPATHLEN+2];
    size_t namelen = sizeof name;

    if (getsockname(tp->task_socket,
		    (struct sockaddr *) name,
		    (int *) &namelen) < 0) {
	switch (errno) {
	case ENOTCONN:
	    /* Ignore */
	    break;

	default:
	    trace_log_tp(tp,
			 0,
			 LOG_ERR,
			 ("task_get_addr_remote: getsockname(%s): %m",
			  task_name(tp)));
	}
	return (sockaddr_un *) 0;
    }

    return sock2gated((struct sockaddr *) name, namelen);
}

/**/

u_short
task_get_port(trace *tf, const char *name, const char *proto,
    u_short default_port)
{
    struct servent *se = getservbyname((const char *)name, proto);
    u_short port;

    if (se) {
	port = se->s_port;
    } else {
	port = default_port;
	trace_log_tf(tf,
		     0,
		     LOG_WARNING,
		     ("task_get_port: getservbyname(\"%s\", \"%s\") failed, using port %d",
		      name,
		      proto,
		      htons(port)));
    }

    return port;
}

int
task_get_proto(trace *tf, const char *name, int default_proto)
{
    struct protoent *pe = getprotobyname(name);
    int proto;

    if (pe) {
	proto = pe->p_proto;
#ifdef	PROTO_ICMPV6
    } else if (strcasecmp(name, "icmpv6") == 0) {
	return IPPROTO_ICMPV6;
#endif	/* PROTO_ICMPV6 */
    } else {
	proto = default_proto;
	trace_log_tf(tf,
		     0,
		     LOG_WARNING,
		     ("task_get_proto: getprotobyname(\"%s\") failed, using proto %d",
		      name,
		      proto));
    }

    return proto;
}


/**/
/*
 *	Path names
 */
char *
task_getwd(void)
{
    static char path_name[MAXPATHLEN];
    
    if (!getcwd(path_name, MAXPATHLEN)) {
	trace_log_tf(trace_global,
		     0,
		     LOG_ERR,
		     ("task_getwd: getwd: %s",
		      path_name));
	/* In case of system error, pick a default */
	(void) strcpy(path_name, "/");
    }

    return path_name;
}


int
task_chdir(const char *path_name)
{
    int rc;
    
    if ((rc = chdir(path_name))) {
	trace_log_tf(trace_global,
		     0,
		     LOG_ERR,
		     ("task_cwd: chdir: %m"));
    }

    task_mem_free((task *) 0, task_path_now);
    task_path_now = task_mem_strdup((task *) 0, task_getwd());

    return rc;
}


/**/
/* IGP-EGP interaction */

/* A BGP will register an AUX connection indicating the protocol it wishes */
/* to interact with.  If a task for that IGP exists, the register routine */
/* is called.  If not, the IGP will call task_aux_lookup when it starts. */

static aux_proto aux_head = { &aux_head, &aux_head };

static block_t task_aux_index = 0;

#define	AUX_LIST(auxp)	for (auxp = aux_head.aux_forw; auxp != &aux_head; auxp = auxp->aux_forw)
#define	AUX_LIST_END(auxp)	if (auxp == &aux_head) auxp = (aux_proto *) 0

/* EGP is ready, register it's connection and make the connection if the */
/* IGP exists */    
void
task_aux_register(task *tp, u_int proto,
    void (*initiate)(task *, proto_t, u_int),
    void (*terminate)(task *),
    void (*flash)(task *, rt_list *),
    void (*newpolicy)(task *, rt_list *))
{
    register aux_proto *auxp;
    register task *atp;

    /* Duplicate check */
    AUX_LIST(auxp) {
	/* Duplicate registration */
	assert(auxp->aux_task_egp != tp && auxp->aux_proto_igp != proto);
    } AUX_LIST_END(auxp) ;

    /* Allocate, fill in and add to list */
    auxp = (aux_proto *) task_block_alloc(task_aux_index);

    auxp->aux_task_egp = tp;
    auxp->aux_proto_igp = proto;
    auxp->aux_initiate = initiate;
    auxp->aux_terminate = terminate;
    auxp->aux_flash = flash;
    auxp->aux_newpolicy = newpolicy;

    INSQUE(auxp, aux_head.aux_back);

    /* Find the task and notify */
    TASK_TABLE(atp) {
	if (atp->task_aux_proto == proto) {
	    atp->task_aux = auxp;
	    auxp->aux_task_igp = atp;
	    assert(atp->task_aux_register);
	    atp->task_aux_register(atp, auxp);
	    break;
	}
    } TASK_TABLE_END(atp) ;
}


/* EGP is going away, sever the connection */
void
task_aux_unregister(task *tp)
{
    register aux_proto *auxp;

    AUX_LIST(auxp) {
	if (auxp->aux_task_egp == tp) {
	    task *atp = auxp->aux_task_igp;
	    
	    atp->task_aux_register(atp, (aux_proto *) 0);

	    auxp->aux_task_igp = (task *) 0;
	    atp->task_aux = (aux_proto *) 0;

	    /* Remove from queue and free */
	    REMQUE(auxp);

	    task_block_free(task_aux_index, (void_t) auxp);

	    return;
	}
    } AUX_LIST_END(auxp) ;

    /* Aux not found for task */
    assert(FALSE);
}


/* IGP is operational and looking for an EGP to interact with */
void
task_aux_lookup(task *tp)
{
    register aux_proto *auxp;

    assert(tp->task_aux_register);
    
    AUX_LIST(auxp) {
	if (tp->task_aux_proto == auxp->aux_proto_igp) {
	    tp->task_aux = auxp;
	    auxp->aux_task_igp = tp;
	    tp->task_aux_register(tp, auxp);
	    break;
	}
    } AUX_LIST_END(auxp) ;
}


/* IGP is going down, notify the EGP and break the connection */
void
task_aux_terminate(task *tp)
{
    aux_proto *auxp = tp->task_aux;

    if (auxp) {
	assert(tp == auxp->aux_task_igp);
	
	auxp->aux_terminate(auxp->aux_task_egp);
	auxp->aux_task_igp = (task *) 0;
	tp->task_aux = (aux_proto *) 0;
    }
}


static void
task_aux_dump(FILE *fp)
{
    register aux_proto *auxp;

    if (aux_head.aux_forw == &aux_head) {
	return;
    }

    (void) fprintf(fp, "\t\tIGP-EGP interactions:\n\n");
    
    AUX_LIST(auxp) {
	(void) fprintf(fp, "\t\tEGP task: %s\tIGP proto: %s",
		       task_name(auxp->aux_task_egp),
		       trace_state(rt_proto_bits, auxp->aux_proto_igp));
	if (auxp->aux_task_igp) {
	    (void) fprintf(fp, "\tIGP task: %s\n",
			   task_name(auxp->aux_task_igp));
	} else {
	    (void) fprintf(fp, "\n");
	}
    } AUX_LIST_END(auxp) ;

    (void) fprintf(fp, "\n");
}


/**/


static void
task_signal_ignore(int sig)
{
#ifdef	POSIX_SIGNALS
    struct sigaction act;

    /* Setup signal processing */
    sigemptyset(&act.sa_mask);
    act.sa_handler = SIG_IGN;
    act.sa_flags = 0;

    if (sigaction(sig, &act, (struct sigaction *) 0) < 0) {
	int error = errno;

	trace_log_tf(trace_global,
		     0,
		     LOG_ERR,
		     ("task_signal_ignore: sigaction(SIG%s): %m",
		      task_signame(sig)));
	task_quit(error);
    }
#else	/* POSIX_SIGNALS */
    signal(sig, SIG_IGN);
#endif	/* POSIX_SIGNALS */
}


static void
task_signal_init(void)
{
#ifdef	BSD_SIGNALS
    struct sigvec vec, ovec;

    bzero((char *) &vec, sizeof(vec));
    vec.sv_handler = task_receive_signal;
#endif	/* BSD_SIGNALS */
#ifdef	POSIX_SIGNALS
    struct sigaction act;
#ifdef	SA_FULLDUMP
    /* Some systems (AIX) don't make a useful dump by default */
    static int dumpsigs[] = {
#ifdef	SIGQUIT
	SIGQUIT,
#endif
#ifdef	SIGILL
	SIGILL,
#endif
#ifdef	SIGTRAP
	SIGTRAP,
#endif
#ifdef	SIGIOT
	SIGIOT,
#endif
#ifdef SIGABRT
	SIGABRT,
#endif
#ifdef	SIGFPE
	SIGFPE,
#endif
#ifdef SIGBUS
	SIGBUS,
#endif
#ifdef SIGSEGV
	SIGSEGV,
#endif
#ifdef	SIGSYS
	SIGSYS,
#endif
	0 };
    register int *sp;

    sigemptyset(&act.sa_mask);
    act.sa_handler = SIG_DFL;
    act.sa_flags = SA_FULLDUMP;
 
    for (sp = dumpsigs; *sp; sp++) {
	if (sigaction(*sp, &act, (struct sigaction *) 0) < 0) {
	    int error = errno;

	    trace_log_tf(trace_global,
			 0,
			 LOG_ERR,
			 ("task_signal_ignore: sigaction(SIG%s): %m",
			  task_signame(*sp)));
	    task_quit(error);
	}
    }
#endif	/* SA_FULLDUMP */
    
    sigemptyset(&act.sa_mask);
    act.sa_handler = task_receive_signal;
    act.sa_flags = 0;
#endif	/* POSIX_SIGNALS */

#ifdef	SIGPIPE
    task_signal_ignore(SIGPIPE);
#endif	/* SIGPIPE */

    SIGNAL_LIST(ip) {
#ifdef	SYSV_SIGNALS
	sigset(ip->sig_sig, task_receive_signal);
#endif	/* SYSV_SIGNALS */
#ifdef	BSD_SIGNALS
	if (sigvec(ip->sig_sig, &vec, &ovec)) {
	    int error = errno;

	    trace_log_tf(trace_global,
			 0,
			 LOG_ERR,
			 ("task_init: sigvec(SIG%s): %m",
			  task_signame(ip->sig_sig)));
	    task_quit(error);
	}
#endif	/* BSD_SIGNALS */
#ifdef	POSIX_SIGNALS
	if (sigaction(ip->sig_sig, &act, (struct sigaction *) 0) < 0) {
	    int error = errno;

	    trace_log_tf(trace_global,
			 0,
			 LOG_ERR,
			 ("task_init: sigaction(SIG%s): %m",
			  task_signame(ip->sig_sig)));
	    task_quit(error);
	}
#endif	/* POSIX_SIGNALS */
    } SIGNAL_LIST_END(ip) ;
}


static void
task_daemonize(void)
{
    /* This code rearranged after reading "Unix Network Programming" */
    /* by W. Richard Stevens */
    int t;

    /*
     * On System V if we were started by init from /etc/inittab there
     * is no need to detach.
     * There is some ambiguity here if we were orphaned by another
     * process.
     */
    if (!BIT_TEST(task_state, TASKS_NODAEMON)) {
	/* Ignore terminal signals */
#ifdef	SIGTTOU
	task_signal_ignore(SIGTTOU);
#endif	/* SIGTTOU */
#ifdef	SIGTTIN
	task_signal_ignore(SIGTTIN);
#endif	/* SIGTTIN */
#ifdef	SIGTSTP
	task_signal_ignore(SIGTSTP);
#endif	/* SIGTSTP */

	switch (fork()) {
	case 0:
	    /* Child */
	    break;

	case -1:
	    /* Error */
	    perror("task_daemonize: fork");
	    exit(1);

	default:
	    /* Parent */
	    exit(0);
	}

	/* Remove our association with a controlling tty */
#ifdef HAVE_SETSID
	t = setsid();
	if (t < 0) {
	    perror("task_daemonize: setsid");
	    exit(1);
	}
#else
	t = setpgrp(0, getpid());
	if (t < 0) {
	    perror("task_daemonize: setpgrp");
	    exit(1);
	}
#endif

#ifndef	TIOCNOTTY
	task_signal_ignore(SIGHUP);

	/* Fork again so we are not a process group leader */
	switch (fork()) {
	case 0:
	    /* Child */
	    break;

	case -1:
	    /* Error */
	    perror("task_daemonize: fork");
	    exit(1);

	default:
	    /* Parent */
	    exit(0);
	}
#else	/* !USE_SETPGRP */
	NON_INTR(t, open(_PATH_TTY, O_RDWR, 0));
	if (t >= 0) {
	    if (ioctl(t, TIOCNOTTY, (caddr_t) 0) < 0) {
		perror("task_daemonize: ioctl(TIOCNOTTY)");
		exit(1);
	    }
	    (void) close(t);
	}
#endif	/* !USE_SETPGRP */
    }

    /* Close all open files */
    {
#ifndef	NOFILE
#ifdef	_NFILE
#define	NOFILE	_NFILE
#else	/* _NFILE */
#ifdef	OPEN_MAX
#define	NOFILE	OPEN_MAX
#else	/* OPEN_MAX */
#define	NOFILE	20
#endif	/* OPEN_MAX */
#endif	/* _NFILE */
#endif	/* NOFILE */
	int tf = -1;

	if (trace_global
	    && trace_global->tr_file
	    && trace_global->tr_file->trf_FILE) {
	    /* Tracing is enabled to a file, don't close the file. */
	    /* If tracing was enabled to stderr, TASKS_NODAEMON would */
	    /* have been set. */
	    
	    tf = fileno(trace_global->tr_file->trf_FILE);
	}

	t = NOFILE;
	do {
	    if (--t != tf) {
		(void) close(t);
	    }
	} while (t);

    }
	    
    /* Reset umask */
    umask(022);

#ifdef	STDIO_HACK
    /* Setup to catch I/O to stdout and stderr */
    task_stdio_family_init();
#endif	/* STDIO_HACK */
}


/*
 *	Dump task information to dump file
 */
void
task_dump(FILE *fd)
{
    int i;
    int first;
    task *tp;
    task_timer *tip;

    (void) fprintf(fd,
		   "Task State: <%s>\n",
		   trace_bits(task_state_bits, task_state));

    (void) fprintf(fd,
		   "\tSend buffer size %u at %X\n",
		   task_send_buffer_len,
		   task_send_buffer);

    (void) fprintf(fd,
		   "\tRecv buffer size %u at %X\n\n",
		   task_recv_buffer_len,
		   task_recv_buffer);

    /* Print out task blocks */
    (void) fprintf(fd,
		   "Tasks (%d) and Timers:\n\n",
				task_n_tasks);
    TASK_TABLE(tp) {
			(void) fprintf(fd, "\t%s\tPriority %d",
											task_name(tp),
											tp->task_priority);

			if (tp->task_proto) {
				(void) fprintf(fd, "\tProto %3d",
			  tp->task_proto);
			}

			if (tp->task_addr) {
				switch (socktype(tp->task_addr)) {
#ifdef	PROTO_INET
				case AF_INET:
					if (tp->task_addr
							&& socktype(tp->task_addr) == AF_INET
							&& ntohs(sock2port(tp->task_addr))) {
								(void) fprintf(fd, "\tPort %5u",
								ntohs(sock2port(tp->task_addr)));
					}
#endif	/* PROTO_INET */
#ifdef	PROTO_INET6
	    	case AF_INET6:
	        if (ntohs(sock2port6(tp->task_addr))) {
							(void) fprintf(fd, "\tPort %5u",
														ntohs(sock2port6(tp->task_addr)));
					}
					break;
#endif	/* PROTO_INET6 */
	    	default:
	        break;
	    	}  /* end switch  */
		} /* tp->task_addr */

		if (tp->task_socket != -1) {
	    (void) fprintf(fd, "\tSocket %2d",
			   tp->task_socket);
		}

		if (tp->task_rtproto) {
	    (void) fprintf(fd, "\tRtProto %s",
			   trace_state(rt_proto_bits, tp->task_rtproto));
		}

		if (tp->task_rtbit) {
	    (void) fprintf(fd, "\tRtBit %d",
			   tp->task_rtbit);
		}

		if (tp->task_flags) {
	    (void) fprintf(fd, "\t<%s>",
			   trace_bits(task_flag_bits, tp->task_flags));
		}

		(void) fprintf(fd, "\n");
		if (tp->task_trace) {
	    trace_task_dump(fd, tp->task_trace);
		}

		first = TRUE;
		for (tip = tp->task_timers; tip; tip = tip->task_timer_next) {
	    if (first) {
				(void) fprintf(fd, "\n");
				first = FALSE;
	    }
	    task_timer_dump(fd, tip);
		}

		(void) fprintf(fd, "\n");
	} TASK_TABLE_END(tp);

	(void) fprintf(fd, "\n");

    /* Print timers that are not associated with tasks */
    first = TRUE;
    for (tip = task_head.task_timers; tip; tip = tip->task_timer_next) {
			if (first) {
				(void) fprintf(fd, "\tTimers without tasks:\n\n");
				first = FALSE;
			}
			task_timer_dump(fd, tip);
    }

    if (!first) {
			(void) fprintf(fd, "\n");
    }

    /* Print jobs */
    if (task_job_fg_queued || task_job_bg_queued) {
			task_job *jp;

		if (task_job_fg_queued) {
	    (void) fprintf(fd, "\tForeground jobs:\n");

	    for (jp = task_job_fg_queue.task_job_forw;
						jp != &task_job_fg_queue;
						jp = jp->task_job_forw) {
				task_job_dump(fd, jp);
	    }

	    (void) fprintf(fd, "\n");
		}

		if (task_job_bg_queued) {
	    (void) fprintf(fd, "\tBackground jobs:\n");
	    
	    for (jp = task_job_fg_queue.task_job_forw;
						jp != &task_job_fg_queue;
						jp = jp->task_job_forw) {
				task_job_dump(fd, jp);
	    }

	    (void) fprintf(fd, "\n");
		}

		(void) fprintf(fd, "\n");
    }

    /* Print flash queue */
    if (!TMQ_EMPTY(task_flash_queue)) {
	(void) fprintf(fd, "\tFlash routines:\n\n");
	TMQ_LIST(tp, task_flash_queue) {
	    (void) fprintf(fd, "\t\t%s\n",
			   task_name(tp));
	} TMQ_LIST_END(tp, task_flash_queue) ;
	(void) fprintf(fd, "\n");
    }

    /* Print recv queue */
    if (!TMQ_EMPTY(task_read_queue)) {
	(void) fprintf(fd, "\tSocket read routines:\n\n");
	TMQ_LIST(tp, task_read_queue) {
	    (void) fprintf(fd, "\t\t%d\t%s%s\n",
			   tp->task_socket,
			   task_name(tp),
			   BIT_TEST(tp->task_flags, TASKF_ACCEPT)
			   ? " (accept)" : "");
	} TMQ_LIST_END(tp, task_read_queue) ;
	(void) fprintf(fd, "\n");
    }

    /* Print low priority recv queue */
    if (!TMQ_LP_EMPTY(task_read_queue)) {
	(void) fprintf(fd, "\tSocket low priority read routines:\n\n");
	TMQ_LP_LIST(tp, task_read_queue) {
	    (void) fprintf(fd, "\t\t%d\t%s%s\n",
			   tp->task_socket,
			   task_name(tp),
			   BIT_TEST(tp->task_flags, TASKF_ACCEPT)
			   ? " (accept)" : "");
	} TMQ_LP_LIST_END(tp, task_read_queue) ;
	(void) fprintf(fd, "\n");
    }

    /* Print write queue */
    if (!TMQ_EMPTY(task_write_queue)) {
	(void) fprintf(fd, "\tSocket write routines:\n\n");
	TMQ_LIST(tp, task_write_queue) {
	    (void) fprintf(fd, "\t\t%d%s%s\n",
			   tp->task_socket,
			   BIT_TEST(tp->task_flags, TASKF_CONNECT)
			   ? " (connect)" : "",
			   task_name(tp));
	} TMQ_LIST_END(tp, task_write_queue) ;
	(void) fprintf(fd, "\n");
    }

    /* File descriptors */
    (void) fprintf(fd, "\tFile Descriptors (max %d):\n",
		   task_max_socket);

    /* First the read bits */
    for (i = 0; i <= task_max_socket; i++) {
	const char *read_string = "";
	const char *write_string = "";
	const char *float_socket = (char *) 0;

	TMQ_LIST(tp, task_read_queue) {
	    if (tp->task_socket == i) {
		read_string = " rqueue";
		break;
	    }
	} TMQ_LIST_END(tp, task_read_queue) ;

	TMQ_LIST(tp, task_write_queue) {
	    if (tp->task_socket == i) {
		read_string = " wqueue";
		break;
	    }
	} TMQ_LIST_END(tp, task_write_queue) ;

	TASK_TABLE(tp) {
	    if (tp->task_socket == i) {
		break;
	    }
	} TASK_TABLE_END(tp) ;

	if (tp == &task_head) {
	    struct task_floating_sockets *tfs;

	    tp = (task *) 0;
	    
	    for (tfs = task_floating_sockets; tfs; tfs = tfs->tfs_next) {
		if (tfs->tfs_socket == i) {
		    tp = tfs->tfs_task;
		    float_socket = tfs->tfs_name;
		    break;
		}
	    }
	}

	(void) fprintf(fd, "\t\t\t%d",
		       i);
	if (tp) {
	    (void) fprintf(fd, "\tTask: %s",
			   task_name(tp));
	}
	if (float_socket) {
	    (void) fprintf(fd, "\tFile: %s",
			   float_socket);
	}
	if (TASK_FD_ISSET(i, &task_select_readbits)) {
	    (void) fprintf(fd, "\t%s%s",
			   BIT_TEST(tp->task_flags, TASKF_ACCEPT)
			       ? " accept"
			       : " read",
			   read_string);
	}
	if (TASK_FD_ISSET(i, &task_select_writebits)) {
	    (void) fprintf(fd, "\t%s%s",
			   BIT_TEST(tp->task_flags, TASKF_CONNECT)
			       ? " connect"
			       : " write",
			   write_string);
	}
	if (TASK_FD_ISSET(i, &task_select_exceptbits)) {
	    (void) fprintf(fd, "\texcept");
	}
	(void) fprintf(fd, "\n");
    }
    (void) fprintf(fd, "\n");

    /* Print memory block usage */
    task_block_dump(fd);
    
    /* Do task-specific dumps */
    TASK_TABLE(tp) {
	if (tp->task_dump_method) {
	    fprintf(fd, "Task %s:\n",
		    task_name(tp));
	    TASK_SAVE(tp, tp->task_dump_method(tp, fd));
	    fprintf(fd, "\n");
	}
    } TASK_TABLE_END(tp);

    /* Print out aux information */
    task_aux_dump(fd);
}


/*
 *	Initialization processing
 */
int
main(int argc, char **argv)
{
    char *name = argv[0];
    char hostname[MAXHOSTNAMELENGTH + 1];
    int did_something = 0;

#ifdef	CSRIMALLOC
    mal_debug(2);
#endif	/* CSRIMALLOC */
    
    /* Get our program name */
    task_progname = name;
    if ((name = (char *) rindex(task_progname, '/'))) {
	task_progname = name + 1;
    }

    /* Reset any user-specified time zones */
    tzsetwall();

#ifdef	_SC_PAGE_SIZE
    task_pagesize = sysconf(_SC_PAGE_SIZE);
#else	/* _SC_PAGE_SIZE */
    task_pagesize = getpagesize();
#endif	/* _SC_PAGE_SIZE */

    /* Init block allocation routines */
    task_block_init_all();

    /* Init tracing code */
    trace_init();

    /* Initialize the current time */
    task_time_init();

    /* Prime the random number generator */
    grand_seed((u_int32) ((time_sec+time_boot)^(utime_current.ut_usec+utime_boot.ut_usec)));

    /* Get our host name */
    if (gethostname(hostname, MAXHOSTNAMELENGTH + 1)) {
	trace_log_tf(trace_global,
		     0,
		     LOG_ERR,
		     ("main: gethostname: %m"));
	task_quit(errno);
    }
    task_hostname = task_mem_strdup((task *) 0, hostname);

    /* Remember directory we were started from */
    task_path_start = task_mem_strdup((task *) 0, task_getwd());
    task_path_now = task_mem_strdup((task *) 0, task_path_start);

    /* Init some common block sizes */
    task_block_index = task_block_init(sizeof (task), "task");
    task_timer_block_index = task_block_init(sizeof (task_timer), "task_timer");
    task_job_block_index = task_block_init(sizeof (task_job), "task_job");
    task_aux_index = task_block_init(sizeof (aux_proto), "aux_proto");

    if (getppid() == 1) {
	/* We were probably started from /etc/inittab */
	task_newstate(TASKS_NODAEMON, 0);
    }

    /* Init the socket code */
    sock_init();

    /* Parse the args */
    if (parse_args(argc, argv)) {
	task_quit(0);
    }

    /* Start tracing */
    trace_init2();

    /* open initialization file */
    if (!task_config_file) {
	char path_config[MAXPATHLEN];

	(void) sprintf(path_config, _PATH_CONFIG, task_progname);
	
	task_config_file = task_mem_strdup((task *) 0, path_config);
#ifndef	FLAT_FS
    } else  if (*task_config_file != '/') {
	/* Make config file name absolute */
	char *file = task_mem_malloc((task *) 0,
				     (size_t) (strlen(task_config_file) + strlen(task_path_start) + 2));

	(void) strcpy(file, task_path_start);
	(void) strcat(file, "/");
	(void) strcat(file, task_config_file);

	task_mem_free((task *) 0, task_config_file);
	task_config_file = file;
#endif	/* FLAT_FS */
    }

    if (!BIT_TEST(task_state, TASKS_TEST)) {

	/* Make sure we are running as root */
	if (getuid()) {
	    fprintf(stderr, "%s: must be root\n",
		    task_progname);
	    exit(2);
	}

	/* Detach from the controlling terminal and become a daemon */
	/* if (!BIT_TEST(task_state, TASKS_NODETACH)) { -- RUSTY */
	if (!BIT_TEST (task_state, TASKS_NODAEMON)) {
	    task_daemonize();
	}
    }

    /* Init syslog */
#if	defined(LOG_DAEMON)
    openlog(task_progname, LOG_OPTIONS, LOG_FACILITY);
    (void) setlogmask(LOG_UPTO(LOG_INFO));
#else	/* defined(LOG_DAEMON) */
    openlog(task_progname, LOG_PID);
#endif	/* defined(LOG_DAEMON) */

    /* Init signals */
    task_signal_init();

    /* Get our process ID */
    task_pid = task_mpid = getpid();

    if (!BIT_MATCH(task_state, TASKS_TEST|TASKS_NODUMP)) {
	trace_log_tf(trace_global,
		     TRC_NL_BEFORE|TRC_NL_AFTER,
		     LOG_INFO,
		     ("Start %s[%d] version %s built %s",
		      task_progname,
		      task_pid,
		      gated_version,
		      build_date));
    }

    /* Init our tracing */
    task_task.task_trace = trace_set_global((bits *) 0, (flag_t) 0);

    /* Initialize the policy */
    policy_family_init();

    /* Initialize routing tables */
    rt_family_init();

#if	defined(PROTO_ASPATHS) || defined(PROTO_MPASPATHS)
    /* Initialize AS paths */
    aspath_family_init();
#endif	/* PROTO_ASPATHS */

#ifdef	PROTO_INET
    /* Initialize INET constants */
    inet_family_init();
#endif	/* PROTO_INET */

#ifdef	PROTO_INET6
    /* Initialize INET6 constants */
    inet6_family_init();
#endif	/* PROTO_INET6 */

#ifdef	PROTO_ISO
    /* Initialize ISO constants */
    iso_family_init();
#endif	/* FAMILY_ISO */

    /* Initialize interface tables */
    if_family_init();

    /* Init kernel and scan the interface list */
    krt_family_init();

    trace_tf(trace_global,
	     TR_TASK,
	     0,
	     (NULL));

    /* Reset all protocol configurations */
    task_proto_var_inits();
    
    /* Read the config file */
    switch (parse_parse(task_config_file)) {
    case -1:
	/* Could not open config file */
#ifdef	PROTO_INET
	if (if_n_link.up == 1) {
	    if (!rt_locate(RTS_NETROUTE,
			   inet_addr_default,
			   inet_mask_default,
			   RTPROTO_BIT(RTPROTO_KERNEL))) {
		break;
	    }

	    trace_log_tf(trace_global,
			 TRC_NL_BEFORE|TRC_NL_AFTER,
			 LOG_NOTICE,
			 ("No config file, one interface and a default route, gated exiting"));
	    task_quit(0);
	}
#endif	/* PROTO_INET */
	task_quit(ENOENT);
	break;

    case 0:
	/* Successful */
	if (BIT_MATCH(task_state, TASKS_TEST|TASKS_NODUMP)) {
	    /* Just syntax check */
	    exit(0);
	}
	break;

    default:
	/* Errors in config file */
	if (BIT_MATCH(task_state, TASKS_TEST|TASKS_NODUMP)) {
	    /* Just syntax check */
	    exit(1);
	} else {
	    task_quit(0);
	}
    }

    if (!BIT_TEST(task_state, TASKS_TEST)) {
	/* Open the .pid file */

	task_pid_open();
    }

    /* Get current time again */
    task_timer_peek();
    task_timer_str_update();

    /* Initialize the protocols */
    task_proto_inits();

    trace_tf(trace_global,
	     TR_TASK,
	     0,
	     (NULL));

    trace_only_tf(trace_global,
		  TRC_NL_BEFORE|TRC_NL_AFTER,
		  ("***Routes are %sbeing installed in kernel",
		   BIT_TEST(krt_options, KRT_OPT_NOINSTALL) ? "not " : ""));

    /* Make dumps happen in a known place */
    (void) task_chdir(_PATH_DUMPDIR);

    if (!BIT_TEST(task_state, TASKS_TEST)) {
	trace_log_tf(trace_global,
		     TRC_NL_BEFORE,
		     LOG_NOTICE,
		     ("Commence routing updates"));
    }
    trace_only_tf(trace_global,
		  0,
		  (NULL));

    /* Allocate send and receive buffer now that we know their maximum size */
    if (task_send_buffer_len && !task_send_buffer) {
	task_send_buffer = (void_t) task_block_malloc(task_send_buffer_len);
    }
    if (task_recv_buffer_len && !task_recv_buffer) {
	task_recv_buffer = (void_t) task_block_malloc(task_recv_buffer_len);
    }

    task_newstate(0, TASKS_INIT);

    /* Reinit tracing */
    trace_reinit();

    /* Set our tracing */
    trace_freeup(task_task.task_trace);
    task_task.task_trace = trace_set_global((bits *) 0, (flag_t) 0);

    /* Cause tasks to reinit */
    task_reinit();

    /* Notify the protocols about the interfaces */
    if_notify();

    /* finalize the reinit */
    task_reinit_finalize();
    
    /* XXX - This will cause protocols to send update packets, should defer just a bit longer */
    /* XXX - How about TASKS_NOBUF to prevent bufs from being allocated and leaving TASKS_INIT on? */

    /* Update the kernel with changes so far and have protocols re-evaluate policy */
    rt_new_policy();

    if (BIT_MATCH(task_state, TASKS_TEST)) {
	/* Just testing configuration */
	if (!BIT_TEST(task_state, TASKS_NODUMP)) {
	    trace_dump(TRUE);
	}
	task_quit(0);
    }

    /* Update the mark timer */
    task_mark_init();

    trace_tf(trace_global,
	     TR_TASK,
	     0,
	     (NULL));

    /* Main dispatching loop */
    task_timer_peek();
    while (TRUE) {
	int n;
	fd_set read_bits, write_bits, except_bits;
	fd_set *read_bits_ptr, *write_bits_ptr, *except_bits_ptr;
	utime_t interval;
	struct timeval tv;

#ifdef	CSRIMALLOC
	mal_verify(1);
#endif	/* CSRIMALLOC */

	/*
	 * Run any normal priority timers which are ready
	 */
	if (task_timer_active > 0
	    && (task_timer_active_time->ut_sec < time_sec
		|| (task_timer_active_time->ut_sec == time_sec
		    && task_timer_active_time->ut_usec <= utime_current.ut_usec))) {
	    int processed;

	    /* Some timers are ready */
	    trace_tf(trace_global,
		     TR_TIMER,
		     0,
		     ("main: running normal priority timer queue"));

	    processed = task_timer_dispatch(&task_timer_queue_active,
					    FALSE,
					    task_sched_timers);
	    did_something++;
	    if (task_timer_active > 0) {
		task_timer_active_time = &(task_timer_queue_active.task_timer_forw->task_timer_next_utime);
	    } else {
		task_timer_active_time = (utime_t *) 0;
	    }

	    trace_tf(trace_global,
		     TR_TIMER,
		     0,
		     ("main: ran %d timer%s",
		      processed,
		      ((processed == 1) ? "" : "s")));
	}

	/*
	 * If we didn't do anything on this loop and we have active
	 * background jobs, run one.
	 */
	if (!did_something && task_job_bg_queued) {
	    task_job_bg_dispatch();
	    did_something++;
	}

	/*
	 * If there are foreground jobs queued, run them now
	 */
after_signal:		/* Come here after signals so select is redone */
	if (task_job_fg_queued) {
	    task_job_fg_dispatch();
	    did_something++;
	}

	/*
	 * Compute the interval to use, and the select bits.  To minimize
	 * race conditions with the signals we check for pending signals
	 * at the end of this and, if there is one, go around again after
	 * dealing with it.
	 */
	if (did_something) {
	    trace_tf(trace_global,
		     TR_TASK,
		     0,
		     (NULL));
	}
	
	if (TASK_FD_SOMESET(&task_select_readbits)) {
	    read_bits = TASK_FD_GETBITS(&task_select_readbits);
	    read_bits_ptr = &read_bits;
	} else {
	    read_bits_ptr = (fd_set *) 0;
	}
	if (TASK_FD_SOMESET(&task_select_writebits)) {
	    write_bits = TASK_FD_GETBITS(&task_select_writebits);
	    write_bits_ptr = &write_bits;
	} else {
	    write_bits_ptr = (fd_set *) 0;
	}
	if (TASK_FD_SOMESET(&task_select_exceptbits)) {
	    except_bits = TASK_FD_GETBITS(&task_select_exceptbits);
	    except_bits_ptr = &except_bits;
	} else {
	    except_bits_ptr = (fd_set *) 0;
	}

	if (task_job_bg_queued) {
	    /* Just a poll here */
	    interval.ut_sec = interval.ut_usec = 0;
	} else {
	    register utime_t *tp;

	    if (task_timer_active) {
		if (!task_timer_hiprio_active
		    || task_timer_active_time->ut_sec < task_timer_hiprio_time->ut_sec
		    || (task_timer_active_time->ut_sec == task_timer_hiprio_time->ut_sec
			&& task_timer_active_time->ut_usec <= task_timer_hiprio_time->ut_usec)) {
		    tp = task_timer_active_time;
		} else {
		    tp = task_timer_hiprio_time;
		}
	    } else if (task_timer_hiprio_active) {
		tp = task_timer_hiprio_time;
	    } else {
		tp = (utime_t *) 0;
	    }

	    if (tp) {
		interval = *tp;

		TIMER_PEEK();
		if (interval.ut_sec < utime_current.ut_sec) {
		    /* Timer already expired, do a poll */
		    interval.ut_sec = interval.ut_usec = 0;
		} else {
		    interval.ut_sec -= utime_current.ut_sec;
		    if (interval.ut_usec < utime_current.ut_usec) {
			if (interval.ut_sec == 0) {
			    /* Just a poll here too */
			    interval.ut_usec = 0;
			} else {
			    interval.ut_usec += (1000000 - utime_current.ut_usec);
			    interval.ut_sec--;
			}
		    } else {
			interval.ut_usec -= utime_current.ut_usec;
		    }

		    /* Limit sleep time */
		    if (interval.ut_sec >= TIMER_MAX_SLEEP) {
			interval.ut_sec = TIMER_MAX_SLEEP;
			interval.ut_usec = 0;
		    }
		}
	    } else {
		interval.ut_sec = TIMER_MAX_SLEEP;
		interval.ut_usec = 0;
	    }
	}

	/* Check for pending signals, just before select */
	if (task_signal_pending) {
	    task_process_signals();
	    did_something++;
	    goto after_signal;
	}

	tv.tv_sec = interval.ut_sec;
	tv.tv_usec = interval.ut_usec;
	n = select(task_max_socket + 1,
		   read_bits_ptr,
		   write_bits_ptr,
		   except_bits_ptr,
		   &tv);

	/* Check for fatal errors */
	if (n < 0 && errno != EINTR) {
	    int error = errno;
	    
	    trace_log_tf(trace_global,
			 0,
			 LOG_ERR,
			 ("main: select: %m"));

	    task_quit(error);
	}

	/* Check for high priority timer expiry */
	TIMER_TIME_CHECK(&interval);
	TIMER_HIPRIO_CHECK();

	/* Note nothing done so far */
	did_something= 0;

	/* Process any pending signals */
	if (task_signal_pending) {
	    task_process_signals();
	    did_something++;
	    goto after_signal;
	}

	if (n > 0) {
	    /* Process socket data */

	    task_process_sockets(n,
				 read_bits_ptr,
				 write_bits_ptr,
				 except_bits_ptr);
	    did_something++;
	}
    }

#if	defined(ibm032) && defined(__HIGHC__)
    /* Most compilers are smart enough to realize that a return is not necessary */
    /* on a routine that never returns... */
    return 0;
#endif	/* defined(ibm032) && defined(__HIGHC) */
}

