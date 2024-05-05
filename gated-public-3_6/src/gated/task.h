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


/* Task definitions */

typedef struct _task_method_queue {
    struct _task_method_queue *tmq_forw, *tmq_back;
} task_method_queue ;

struct _aux_proto;

typedef void (*task_timer_func_t)(task_timer *, time_t);
typedef void (*task_job_func_t)(task_job *);

typedef void (*task_recv_func_t)(task *);
typedef void (*task_accept_func_t)(task *);
typedef void (*task_write_func_t)(task *);
typedef void (*task_connect_func_t)(task *);
typedef void (*task_except_func_t)(task *);
typedef void (*task_terminate_func_t)(task *);
typedef void (*task_shutdown_func_t)(task *);
typedef void (*task_flash_func_t)(task *, rt_list *);
typedef void (*task_newpolicy_func_t)(task *, rt_list *);
typedef void (*task_ifachange_func_t)(task *, if_addr *);
typedef void (*task_iflchange_func_t)(task *, if_link *);
typedef void (*task_cleanup_func_t)(task *);
typedef void (*task_reinit_func_t)(task *);
typedef void (*task_reinit_finalize_func_t)(task *);
typedef void (*task_dump_func_t)(task *, FILE *);
typedef void (*task_aux_register_func_t)(task *, struct _aux_proto *);
typedef void (*task_process_func_t)(task *);
typedef void (*task_child_func_t)(task *);

struct _task {
    struct _task *task_forw;
    struct _task *task_back;
    const char *task_name;		/* Printable task name */
    flag_t task_flags;			/* Flags */
    int task_proto;			/* Protocol */
    int task_socket;			/* Socket (if applicable) */
    proto_t task_rtproto;		/* Routing table protocol (if applicable) */
    proto_t task_rtfamily;		/* Routing table family (if applicable) */
    u_int task_rtbit;			/* Place to save my bit number */
    int task_priority;			/* Priority of this task in relation to others */
    trace *task_trace;			/* Tracing info pointer for this task */
    const bits *task_trace_types;	/* Dscriptions of task specific flags */

				/* func to receive packets (if applicable) */
    task_recv_func_t task_recv_method;
				/* func to process accepts (if applicable) */
    task_accept_func_t task_accept_method;
    task_method_queue	task_read_queue;	/* Entry on read queue */
    
				/* func to write when socket is ready */
    task_write_func_t task_write_method;

				/* func to process connect completions */
    task_connect_func_t task_connect_method;
    task_method_queue	task_write_queue;	/* Entry on write queue */

    task_except_func_t task_except_method; 	/* func to handle exceptions */
    task_method_queue	task_except_queue;	/* Entry on except queue */

    task_terminate_func_t task_terminate_method; /* func to terminate task */

				/* Special func for terminate processing */
    task_shutdown_func_t task_shutdown_method;

    task_flash_func_t task_flash_method;	/* func to do flash updates */
    task_method_queue	task_flash_queue;	/* Entry on flash queue */

			/* Routine to re-evaluate policy after reconfig */
    task_newpolicy_func_t task_newpolicy_method;

			/* Routine to call when an address status changes */
    task_ifachange_func_t task_ifachange_method;

		/* func to call when a physical interface status changes */
    task_iflchange_func_t task_iflchange_method;

			/* func to cleanup before config file is re-read */
    task_cleanup_func_t task_cleanup_method;

			/* func to called before normal processing begins */
    task_reinit_func_t task_reinit_method;

    task_reinit_finalize_func_t task_reinit_finalize_method;

    task_dump_func_t task_dump_method;	/* func to dump state */

    sockaddr_un *task_addr;		/* Task dependent address */
    void_t task_data;			/* Task dependent pointer */

    /* Aux stuff */
    proto_t	task_aux_proto;		/* Protocol for Aux */
    struct _aux_proto *task_aux;	/* For protocol interaction */
					/* To register aux request */
    task_aux_register_func_t task_aux_register;
		
    int task_pid;			/* PID if this is a child */
					/* Routine to run after fork */
    task_process_func_t task_process_method;
				/* Routine to run after child finishes */
    task_child_func_t task_child_method;

    /* Timer list for deletion and logging */
    struct _task_timer *task_timers;	/* List of timers we own */
};

#define	TASKF_ACCEPT		0x01	/* This socket is waiting for accepts, not reads */
#define	TASKF_CONNECT		0x02	/* This socket is waiting for connects, not writes */
#define	TASKF_DELETE		0x04	/* This task has been deleted and is waiting for housekeeping */
#define	TASKF_LOWPRIO		0x08	/* Low priority reads on this socket */

#define	TASKOPTION_RECVBUF	0	/* Set receive buffer size */
#define	TASKOPTION_SENDBUF	1	/* Set send buffer size */
#define	TASKOPTION_LINGER	2	/* Set TCP linger on close */
#define	TASKOPTION_REUSEADDR	3	/* Enable/disable address reuse */
#define	TASKOPTION_BROADCAST	4	/* Enable/disable broadcast use */
#define	TASKOPTION_DONTROUTE	5	/* Enable/disable don't route */
#define	TASKOPTION_KEEPALIVE	6	/* Enable/disable keepalives */
#define	TASKOPTION_DEBUG	7	/* Enable/disable socket level debugging */
#define	TASKOPTION_NONBLOCKING	8	/* Enable/disable non-blocking I/O */
#define	TASKOPTION_USELOOPBACK	9	/* Use loopback */
#define	TASKOPTION_GROUP_ADD	10	/* Join a multicast group */
#define	TASKOPTION_GROUP_DROP	11	/* Leave a multicast group */
#define	TASKOPTION_MULTI_IF	12	/* Set multicast interface */
#define	TASKOPTION_MULTI_LOOP	13	/* Set multicast loopback */
#define	TASKOPTION_MULTI_TTL	14	/* Set multicast TTL */
#define	TASKOPTION_MULTI_ROUTE	15	/* Enable Multicast routing in kernel */
#define	TASKOPTION_TTL		16	/* Set the IP TTL */
#define	TASKOPTION_TOS		17	/* Set the IP TOS */
#define	TASKOPTION_RCVDSTADDR	18	/* Receive destination address */
#define	TASKOPTION_IPHEADER_INC	19	/* IP Header is included */
#define	TASKOPTION_ADD_VIF	20	/* Add vif in kernel */
#define	TASKOPTION_DEL_VIF	21	/* Delete vif in kernel */
#define	TASKOPTION_ADD_MFC	22	/* Add mfc in kernel */
#define TASKOPTION_DEL_MFC  23  /* Delete mfc in kernel */
#define	TASKOPTION_ASSERT	24	/* Enable/Disable Assert Support */
#define TASKOPTION_IPSEC_ENCRYPTED 25	/* Data is already encrypted */
#define	TASKOPTION_RCVIF	26	/* receive interface index */
#define TASKOPTION_RCVHOPLIM    27  /* recevied hop limit */
#define TASKOPTION_PKTOPTIONS 28  /* IPV6 PKTOPTIONS */
#define TASKOPTION_SENDIF 29  /* send interface (PKTOPTIONS) */
#define TASKOPTION_CHECKSUM 30  /* compute and verify CheckSum */
#define	TASKOPTION_RCVIF6	31	/* receive interface index v6 */

#define	TASKPRI_INTERFACE	10	/* Interface task */
#define	TASKPRI_FAMILY		15	/* Address family */
#define	TASKPRI_RT		20	/* Routing table */
#define	TASKPRI_ICMP		30	/* ICMP */
#define	TASKPRI_IGMP		35	/* IGMP */
#define	TASKPRI_PROTO		40	/* Protocol tasks */
#define	TASKPRI_MPROTO		45	/* Multicast Protocol tasks */
#define TASKPRI_EXTPROTO	50	/* External protocols */
#define	TASKPRI_REDIRECT	60	/* Redirects */
#define	TASKPRI_KERNEL		TASKPRI_REDIRECT
#define	TASKPRI_NETMGMT		70	/* SNMP et all */
#define	TASKPRI_SCRAM		TASKPRI_NETMGMT

#define	task_set_recv(tp, method)	(tp)->task_recv_method = (method)
#define	task_set_accept(tp, method)	(tp)->task_accept_method = (method)
#define	task_set_write(tp, method)	(tp)->task_write_method = (method)
#define	task_set_connect(tp, method)	(tp)->task_connect_method = (method)
#define	task_set_except(tp, method)	(tp)->task_except_method = (method)
#define	task_set_terminate(tp, method)	(tp)->task_terminate_method = (method)
#define	task_set_shutdown(tp, method)	(tp)->task_shutdown_method = (method)
#define	task_set_newpolicy(tp, method)	(tp)->task_newpolicy_method = (method)
#define	task_set_ifachange(tp, method)	(tp)->task_ifachange_method = (method)
#define	task_set_iflchange(tp, method)	(tp)->task_iflchange_method = (method)
#define	task_set_cleanup(tp, method)	(tp)->task_cleanup_method = (method)
#define	task_set_reinit(tp, method)	(tp)->task_reinit_method = (method)
#define	task_set_reinit_finalize(tp, method)	\
    (tp)->task_reinit_finalize_method = (method)
#define	task_set_dump(tp, method)	(tp)->task_dump_method = (method)
#define	task_set_process(tp, method)	(tp)->task_process_method = (method)
#define	task_set_child(tp, method)	(tp)->task_child_method = (method)

extern task *task_active;		/* Pointer to the active task */
extern char *task_progname;		/* name we were invoked as */
extern int task_pid;			/* my process ID */
extern int task_mpid;			/* process ID of main process */
extern char task_pid_str[];		/* Printable process ID */
extern char *task_hostname;
extern flag_t task_state;		/* State of things to come */
extern size_t task_pagesize;		/* System page size */
extern size_t task_maxpacket;		/* Maximum packet size the kernel supports (set by KRT) */
extern char *task_path_start;		/* Directory where we were started */
extern char *task_path_now;		/* Directory where we are now */
extern char *task_config_file;		/* Configuration file to read */
extern task task_head;                  /* List of active tasks. */
extern const bits task_flag_bits[];
extern const bits task_timer_flag_bits[];
extern struct task_size_block task_block_head;

extern const bits task_domain_bits[];
extern const bits task_socket_types[]; 

/* nice useful global of 32 bytes of zero */
extern const u_int8 zeros32[32];

#define	TASKS_INIT		BIT(0x01)		/* Initializing */
#define	TASKS_TEST		BIT(0x02)		/* In configuration test mode */
#define	TASKS_RECONFIG		BIT(0x04)		/* Reconfiguration active */
#define	TASKS_TERMINATE		BIT(0x08)		/* Terminating */
#define	TASKS_NORECONFIG	BIT(0x10)		/* Reinits disabled */
#define	TASKS_NOSEND		BIT(0x20)		/* Packet transmission disabled */
#define	TASKS_FLASH		BIT(0x40)		/* Flash update in progress */
#define	TASKS_NEWPOLICY		BIT(0x80)		/* New Policy in progress */
#define	TASKS_NODAEMON		BIT(0x0100)		/* Do not daemonize */
#define	TASKS_STRICTIFS		BIT(0x0200)		/* Allow references to interfaces that do not (yet) exist */
#define	TASKS_NODUMP		BIT(0x0400)		/* Do not create gated_dump in test mode */
#define	TASKS_NORESOLV		BIT(0x0800)		/* Do not use gethostbyname() or getnetbyname() */
#define	TASKS_NODETACH		BIT(0x1000)		/* Tracing to stdout is active */

#define	TASK_PACKET_LIMIT	10	/* Max number of packets to read at one time */


/* Return codes from task_receive_packet - positive values are errno */
#define	TASKRC_OK		0		/* Read OK */
#define	TASKRC_EOF		-1		/* End-of-file */
#define	TASKRC_TRUNC		-2		/* Truncated */

#define TASK_ERR		ELAST

/*
 *	I/O structures
 */

#ifdef	IP_HL_MASK
#define	task_parse_ip_hl(ip)	(((ip)->ip_hl_v & IP_HL_MASK) << 2)
#else	/* IP_HL_MASK */
#define	task_parse_ip_hl(ip)	((ip)->ip_hl << 2)
#endif	/* IP_HL_MASK */

#define	task_parse_ip(ip, dp, type) \
{ \
    ip = task_get_recv_buffer(struct ip *); \
    dp = (type) ((void_t) ((caddr_t) ip + task_parse_ip_hl(ip))); \
}

#define	task_parse_ip_opt(ip, op, dp, type) { \
    task_parse_ip(ip, dp, type); \
    op = ((caddr_t) dp > (caddr_t) ip + sizeof (struct ip)) ? (byte *) ip + sizeof (struct ip) : (byte *) 0; \
}

/* Receive buffer and length */
extern void_t task_recv_buffer;
extern size_t task_recv_buffer_len;


#if defined(SUNOS5_0) || !defined(HAVE_CMSG_SPACE) 
#ifndef CMSG_ALIGN
#define CMSG_ALIGN(n)   (((n) + 3) & ~3)
#define CMSG_SPACE(l)   (CMSG_ALIGN(sizeof(struct cmsghdr)) + CMSG_ALIGN(l))
#define CMSG_LEN(l)   (CMSG_ALIGN(sizeof(struct cmsghdr)) + (l))
#endif 
#endif

#define	task_get_recv_buffer(type)	(type) task_recv_buffer

/* Send buffer and length */
extern void_t task_send_buffer;
extern size_t task_send_buffer_len;

#define	task_get_send_buffer(type)	(type) task_send_buffer

extern sockaddr_un *task_recv_srcaddr;	/* Source address of received packet */
extern sockaddr_un *task_recv_dstaddr;	/* Destination address of received packet */
extern u_int task_recv_if_index;   /* Index of incoming interface of received packet */
#ifdef PROTO_INET6
extern if_addr *task_recv_interface;  /* Incoming interface of received packet */
extern u_char task_recv_hoplimit; /* Hop count on incoming packet */
#endif /* PROTO_INET6 */

void task_pid_open(void);
void task_quit(int);
void task_assert(const char *, const int, const char *);
void task_newstate(flag_t, flag_t);
task * task_alloc(const char *, int, trace *);
int task_create(task *);
void task_alloc_send(task *, size_t);
void task_alloc_recv(task *, size_t);
int task_fork(task *);
int task_ioctl(int, u_long, void_t, int);
void task_delete(task *);
void task_close(task *);
void task_flash(rt_list *);
void task_set_flash(task *, task_flash_func_t);
void task_newpolicy(rt_list *);
void task_ifachange(if_addr *);
void task_iflchange(if_link *);
extern int task_set_option(task *, int, ...);
int task_floating_socket(task *, int, const char *);
int task_get_socket(task *, int, int, int);
void task_set_socket(task *, int);
int task_addr_local(task *, sockaddr_un *);
int task_connect(task *, if_addr *);
sockaddr_un *task_get_addr_local(task *);
sockaddr_un *task_get_addr_remote(task *);
u_short task_get_port(trace *, const char *, const char *, u_short);
int task_get_proto(trace *, const char *, int);
void task_reset_socket(task *);
task * task_locate(const char *, sockaddr_un *);
char * task_name(task *);
void task_dump(FILE *);
#ifdef	HAVE_SENDMSG
int task_send_packet_iov(task * tp, struct iovec *, int, flag_t, sockaddr_un *);
int task_send_packet_iov_err(task * tp, struct iovec *, int, flag_t,
    sockaddr_un *, int *);
#endif
#if defined(PROTO_INET6) && defined(IPV6_PKTINFO)
int task_send_message(task *, void_t, size_t, flag_t, sockaddr_un *, if_addr *);
#endif /* PROTO_INET6 && IPV6_PKTINFO */
int task_receive_packet(task * tp, size_t *);
int task_send_packet(task * tp, void_t, size_t, flag_t, sockaddr_un *);
int task_send_packet_err(task * tp, void_t, size_t, flag_t, sockaddr_un *,
    int *);
void task_proto_inits(void);
void task_proto_var_inits(void);
void_t task_mem_malloc(task *, size_t);
void_t task_mem_calloc(task *, u_int, size_t);
void_t task_mem_realloc(task *, void_t, size_t);
char * task_mem_strdup(task *, const char *);
void task_mem_free(task *, void_t);
char * task_getwd(void);
int task_chdir(const char *);

#define	TASK_TABLE(tp) \
    for (tp = task_head.task_forw; tp != &task_head; tp = tp->task_forw) { \
	if (!BIT_TEST(tp->task_flags, TASKF_DELETE))
#define	TASK_TABLE_END(tp)	}


/**/
#define	TIME_MARK	60*10		/* Duration between marks in seconds */

extern time_t task_mark_interval;

/**/

/* Blocks */

struct task_block {
    struct task_size_block *tb_block;	/* Pointer to parent */
    struct task_block *tb_next;		/* Pointer to next in chain */

    const char *tb_name;    		/* Name for this block */

    u_int	tb_n_init;		/* Number of init requests */
    u_int	tb_n_alloc;		/* Number of alloc requests */
    u_int	tb_n_free;		/* Number of free requests */
};


struct task_size_block {
    struct task_size_block *tsb_forw;	/* Queue glue */
    struct task_size_block *tsb_back;

    struct task_block tsb_block;	/* First block using this size */

    size_t tsb_size;			/* Size of this block */
    u_int tsb_count;			/* Number per page */
    u_int tsb_n_free;			/* Number free */
    block_t tsb_runt;			/* Where to hide the runt */
    qelement tsb_free;			/* Free list */
    qelement tsb_tmp;			/* Work area for allocation macro */

};


block_t task_block_init(size_t, const char *);
qelement task_block__alloc(block_t);
void_t task_block_malloc(size_t);
void task_block_reclaim(size_t, void_t);

#ifdef	TASK_BLOCK_DEBUG
/* Free a clear block */
#define	task_block_free_clear(tbp, p) \
    do { \
	register qelement Xqp = (qelement) ((block_t *) (p) - 1); \
	register struct task_size_block *Xtsb = (tbp)->tb_block; \
	/* Put this element on the head of the list */ \
	Xqp->q_forw = Xtsb->tsb_free; \
	Xtsb->tsb_free = Xqp; \
	Xtsb->tsb_n_free++, (tbp)->tb_n_free++; \
    } while (0)

/* Clear a block and return it */
#define	task_block_free(tbp, p) \
    do { \
	register void_t Xp = (block_t *) (p) - 1; \
	assert(*((block_t *) (p)) == (tbp)); \
	bzero((caddr_t) Xp, (tbp)->tb_block->tsb_size); \
	task_block_free_clear(tbp, (block_t *) Xp + 1); \
    } while (0)

/* Allocate a block */
#define	task_block_alloc(tbp) \
    ((tbp)->tb_block->tsb_tmp = ((tbp)->tb_block->tsb_free ? (tbp)->tb_block->tsb_free : task_block__alloc(tbp)), \
     (tbp)->tb_block->tsb_free = (tbp)->tb_block->tsb_tmp->q_forw, \
     (tbp)->tb_block->tsb_tmp->q_forw = (qelement) 0, \
     (tbp)->tb_block->tsb_n_free--, (tbp)->tb_n_alloc++, \
     (tbp)->tb_block->tsb_tmp)++ = (tbp), \
     (void_t) (tbp)->tb_block->tsb_tmp)
#else	/* TASK_BLOCK_DEBUG */
/* Free a clear block */
#define	task_block_free_clear(tbp, p) \
    do { \
	register qelement Xqp = (qelement) (p); \
	register struct task_size_block *Xtsb = (tbp)->tb_block; \
	/* Put this element on the head of the list */ \
	Xqp->q_forw = Xtsb->tsb_free; \
	Xtsb->tsb_free = Xqp; \
	Xtsb->tsb_n_free++, (tbp)->tb_n_free++; \
    } while (0)

/* Clear a block and return it */
#define	task_block_free(tbp, p) \
    do { \
	register void_t Xp = (block_t *) (p); \
	bzero((caddr_t) Xp, (tbp)->tb_block->tsb_size); \
	task_block_free_clear(tbp, Xp); \
    } while (0)

/* Allocate a block */
#define	task_block_alloc(tbp) \
    ((tbp)->tb_block->tsb_tmp = ((tbp)->tb_block->tsb_free ? (tbp)->tb_block->tsb_free : task_block__alloc(tbp)), \
     (tbp)->tb_block->tsb_free = (tbp)->tb_block->tsb_tmp->q_forw, \
     (tbp)->tb_block->tsb_tmp->q_forw = (qelement) 0, \
     (tbp)->tb_block->tsb_n_free--, (tbp)->tb_n_alloc++, \
     (void_t) (tbp)->tb_block->tsb_tmp)
#endif	/* TASK_BLOCK_DEBUG */

/*  */
/* Timer definitions */

/* gated's internal notion of what precision time looks like */
typedef struct _utime_t {
    time_t ut_sec;
    time_t ut_usec;
} utime_t;

struct _task_timer {
    /* Pointers for timer queue */
    struct _task_timer *task_timer_forw;
    struct _task_timer *task_timer_back;
    const char *task_timer_name;	/* Printable name for this timer */
    flag_t task_timer_flags;		/* Flags */
    utime_t task_timer_next_utime;	/* Timer job wakeup time */
    utime_t task_timer_uinterval;	/* Time to sleep between timer jobs */
    utime_t task_timer_last_utime;	/* Last time job was called */
    time_t task_timer_jitter;		/* Timer jitter, in usec (2000 sec max) */
    void (*task_timer_job)(task_timer *,
		time_t);		/* Timer job (if applicable) */
    task *task_timer_task;		/* Task which owns this timer */
    void_t task_timer_data;		/* Timer specific data */
    /* Pointer in task timer list */
    struct _task_timer *task_timer_next;
};

/* XXX Backward compatability */

#define	task_timer_next_time	task_timer_next_utime.ut_sec
#define	task_timer_interval	task_timer_uinterval.ut_sec
#define	task_timer_last_time	task_timer_last_utime.ut_sec

/* Timer flags */

#define	TIMERF_DELETE		BIT(0x01)	/* Delete timer after it fires*/
#define	TIMERF_HIPRIO		BIT(0x02)	/* Timer is high priority */
#define	TIMERF_ONESHOT		BIT(0x04)	/* Timer has no interval */
#define	TIMERF_SET		BIT(0x08)	/* Timer set by someone */
#define	TIMERF_PROCESSING	BIT(0x10)	/* This timer being processed */
#define	TIMERF_INACTIVE		BIT(0x20)	/* This timer inactive */
#define	TIMERF_RESET		BIT(0x40)	/* This timer reset */
#define TIMERF_SHOTNOW		BIT(0x40)	/* Shot it now */
#define TIMERF_SUBJITTER	BIT(0x80)	/* only subtract jitter */

#define	TIMERF_USER_CAN_SET	(TIMERF_DELETE|TIMERF_HIPRIO)

#define	TIMER_FUZZ		2	/* How forgiving to be before bitching about the system clock */

#define	TIMER_MAX_JITTER	1000	/* Only room for 1000 seconds of jitter */

#define	TIMER_MAX_SLEEP		8	/* Sleep no more than 8 seconds */

/* Current time definition */

struct gtime {
    utime_t gt_current;
    utime_t gt_boot;
    int gt_up_to_date;		/* Set when strings are up to date */
    time_t gt_str_time;		/* Set to time corresponding to strings */
    char gt_str[16];
    char gt_ctime[26];
};

extern struct gtime task_time;
extern struct gtime task_time_start;

extern int task_timer_hiprio_active;		/* set when hi priority timer active */
extern utime_t *task_timer_hiprio_time;	/* time of hi priority expiry */

#define	TIMER_MAX_TIME		90	/* If time shifts forward by this much, assume it changed */
#define	TIMER_FUDGE_TIME	10	/* If time set forward, assume this much time has passed */

#define	time_sec	task_time.gt_current.ut_sec
#define	time_boot	task_time.gt_boot.ut_sec
#define time_string \
	(task_time.gt_up_to_date ? task_time.gt_str : task_timer_get_str())
#define	time_full \
	(task_time.gt_up_to_date ? task_time.gt_ctime : task_timer_get_ctime())

#define	utime_current	task_time.gt_current
#define	utime_boot	task_time.gt_boot

/*
 * Fetching the time/checking the hi priority timer
 *
 */

#ifdef	HAVE_GETSYSTIMES
#define	TIMER_PEEK() \
    do {  \
	struct timeval Xcur, Xboot; \
	if (getsystimes(&Xcur, &Xboot)) { \
	    task_time_bad(); \
	} \
	utime_current.ut_sec = Xcur.tv_sec; \
	utime_current.ut_usec = Xcur.tv_usec; \
	utime_boot.ut_sec = Xboot.tv_sec; \
	utime_boot.ut_usec = Xboot.tv_usec; \
	task_time.gt_up_to_date = 0; \
    } while (0)

#define	TIMER_TIME_CHECK(intervalp) 	TIMER_PEEK()

#else	/* HAVE_GETSYSTIMES */
#define	TIMER_PEEK() \
    do { \
	struct timeval Xcur; \
	time_t Xoldtime; \
	Xoldtime = time_sec; \
	if (gettimeofday(&Xcur, (struct timezone *)0) != 0) { \
	    task_time_bad(); \
	} \
	utime_current.ut_sec = Xcur.tv_sec; \
	utime_current.ut_usec = Xcur.tv_usec; \
	time_sec -= time_boot; \
	if (time_sec < Xoldtime || time_sec > (Xoldtime + TIMER_MAX_TIME)) { \
	    task_time_fix(Xoldtime, (utime_t *) 0); \
	} \
	task_time.gt_up_to_date = 0; \
    } while (0)

#define	TIMER_TIME_CHECK(intervalp) \
    do { \
	struct timeval Xcur; \
	time_t Xoldtime; \
	Xoldtime = time_sec; \
	if (gettimeofday(&Xcur, (struct timezone *)0) != 0) { \
	    task_time_bad(); \
	} \
	utime_current.ut_sec = Xcur.tv_sec; \
	utime_current.ut_usec = Xcur.tv_usec; \
	time_sec -= time_boot; \
	if (time_sec < Xoldtime \
	    || time_sec > (Xoldtime + (intervalp)->ut_sec + TIMER_MAX_TIME)) { \
	    task_time_fix(Xoldtime, (intervalp)); \
	} \
	task_time.gt_up_to_date = 0; \
    } while (0)

#endif	/* HAVE_GETSYSTIMES */

#define	TIMER_HIPRIO_CHECK() \
    do { \
	if (task_timer_hiprio_active && (time_sec > task_timer_hiprio_time->ut_sec \
	  || (time_sec == task_timer_hiprio_time->ut_sec \
	    && utime_current.ut_usec >= task_timer_hiprio_time->ut_usec))) { \
	    task_timer_hiprio_dispatch(); \
	} \
    } while (0)

#define	TIMER_UPDATE() \
    do { \
	TIMER_PEEK(); \
	TIMER_HIPRIO_CHECK(); \
    } while (0)

#define TIMER_IS_INACTIVE(tip)	\
	(BIT_TEST((tip)->task_timer_flags, TIMERF_INACTIVE))

char *task_timer_name(task_timer *);
task_timer *task_timer_ucreate(task *, const char *, flag_t, utime_t *,
    utime_t *, utime_t *, task_timer_func_t, void_t data);
task_timer *task_timer_create(task *, const char *, flag_t, time_t, time_t,
    task_timer_func_t, void_t data);
void task_timer_peek(void);
void task_timer_delete(task_timer *);
void task_timer_uset(task_timer *, utime_t *, utime_t *, utime_t *);
void task_timer_set(task_timer *, time_t, time_t);
void task_timer_reset(task_timer *);
void task_timer_set_uinterval(task_timer *, utime_t *);
void task_timer_restart(task_timer **, task *, const char *, time_t, int,
  task_timer_func_t, void_t);
void task_timer_urestart(task_timer **, task *, const char *, utime_t *,
    utime_t *, utime_t *, task_timer_func_t, void_t);
void task_timer_set_interval(task_timer *, time_t);
char *task_timer_get_str(void);
char *task_timer_get_ctime(void);
void task_time_bad(void);
void task_time_fix(time_t, utime_t *);
void task_timer_hiprio_dispatch(void);

/**/

/* Job support */

/*
 * Jobs can be scheduled by tasks to run at some point in the future.
 * There are two types of jobs.  Foreground jobs are run in the near
 * future, at a point when it is safe to modify the routing table and
 * where time constraints are moderate.  Foreground jobs are
 * particularly useful when scheduled from high priority timer
 * handlers (which aren't allowed to modify the routing table, or
 * do anything which takes a long time) or from flash update handlers,
 * much can't modify the routing table.  The foreground job queue is
 * collected during the processing loop, and run to completion before
 * I/O is rechecked.
 *
 * Background jobs are either long running jobs, or jobs which can
 * be deferred if gated is busy with other things.  Background jobs
 * can have a priority between 0-7 inclusive, and are queued in
 * priority order.  Background jobs are only run when there is no
 * pending I/O or timer processing to do.  When this is the case
 * the top background job on the queue is run, and then the I/O and
 * timer processing are rechecked when the job returns.  Background
 * jobs remain on the queue until they are deleted by the task.
 * Background jobs on the queue with the same priority will be
 * processed in round robin fashion.
 */

struct _task_job {
    struct _task_job *task_job_forw;
    struct _task_job *task_job_back;
    const char *task_job_name;		/* Printable name for job */
    task *task_job_task;		/* Task responsible for job */
    byte task_job_priority;		/* Priority job is run with */
    byte task_job_isactive;		/* Set when job is active */
    void (*task_job_job)(struct _task_job *);	/* Job to run */
    void_t task_job_data;		/* Argument to run job with */
};

/* Job Priorities */

#define	TASK_JOB_PRIO_0	0
#define	TASK_JOB_PRIO_1	1
#define	TASK_JOB_PRIO_2	2
#define	TASK_JOB_PRIO_3	3
#define	TASK_JOB_PRIO_4	4
#define	TASK_JOB_PRIO_5	5
#define	TASK_JOB_PRIO_6	6
#define	TASK_JOB_PRIO_7	7

#define	TASK_JOB_PRIO_BEST	TASK_JOB_PRIO_0
#define	TASK_JOB_PRIO_WORST	TASK_JOB_PRIO_7
#define	TASK_JOB_N_PRIO		(TASK_JOB_PRIO_WORST + 1)

#define	TASK_JOB_FG		128		/* A foreground job */

#define	TASK_JOB_PRIO_FLASH	TASK_JOB_PRIO_5	/* Priority for flash routine exec */
#define	TASK_JOB_PRIO_SPF	TASK_JOB_PRIO_2	/* Priority to run SPF computation */

/* Job creation and deletion */

task_job *task_job_create(task *,			/* Task starting job */
	   int,				/* Job priority */
	   const char *,		/* Name of job */
	   void (*task_job_job)(task_job *),	/* Job to run */
	   void_t);			/* Argument for job */
void task_job_delete(task_job *);		/* Delete a job */
void task_job_run(task_job *);		/* Force a job to run */

/**/

/* IGP-EGP interaction */

/*
 * Auxiliary routing protocol structure.  An auxiliary routing protocol
 * is one which operates in parallel with, or as a part of, an IGP to carry
 * additional routing information which the IGP cannot manage itself.
 * Examples of an auxiliary routing protocol are internal BGP and
 * internal IDRP, when run with an IGP such as OSPF or IS-IS.
 */
typedef struct _aux_proto {
    struct _aux_proto	*aux_forw;
    struct _aux_proto	*aux_back;
    proto_t aux_proto_igp;	/* protocol of aux protocol */
    task *aux_task_egp;		/* pointer to aux task */
    task *aux_task_igp;		/* pointer to other task */
    void (*aux_initiate)(task *,
		proto_t,
		u_int);	/* Initiate interaction */
    void (*aux_flash)(task *,
		rt_list *);	/* Flash update done */
    void (*aux_newpolicy)(task *,
		rt_list *);	/* New policy done */
    void (*aux_terminate)(task *);	/* Terminate interaction */
} aux_proto;


#define	task_aux_flash(aux, rtl)	(auxp)->aux_flash((auxp)->aux_task_egp, rtl)
#define	task_aux_newpolicy(auxp, rtl)	(auxp)->aux_newpolicy((auxp)->aux_task_egp, rtl)
#define	task_aux_initiate(auxp, rtbit)	(auxp)->aux_initiate((auxp)->aux_task_egp, (auxp)->aux_proto_igp, rtbit)

void task_aux_register(task *, u_int,
	void (*aux_initiate)(task *, proto_t, u_int),
	void (*aux_terminate)(task *),
	void (*aux_flash)(task *, rt_list *),
	void (*aux_newpolicy)(task *, rt_list *));
void task_aux_unregister(task *);
void task_aux_lookup(task *);
void task_aux_terminate(task *);
