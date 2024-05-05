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


#include "include.h"

#if defined(PROTO_SMUX)
#include "inet/inet.h"
#include "smux_asn1.h"
#include "smux.h"
#include "smux_snmp.h"

/* protocol initialization routines */
#if defined(PROTO_BGP) && defined(GATED_MEMBER)
extern void init_bgp_vars(void);
#endif /* PROTO_BGP && GATED_MEMBER */
#ifdef PROTO_EGP
extern void init_egp_vars();
#endif /* PROTO_EGP */
#ifdef PROTO_OSPF
extern void init_ospf_vars();
#endif /* PROTO_OSPF */
#ifdef PROTO_OSPF2
extern void init_nospf_vars();
#endif /* PROTO_OSPF2 */
#ifdef PROTO_RIP
extern void init_rip_vars();
#endif /* PROTO_RIP */
#ifdef IP_MULTICAST_ROUTING
extern void init_ipMRoute_vars();
#endif /* IP_MULTICAST_ROUTING */
#ifdef PROTO_IGMP
extern void init_igmp_vars();
#endif /* PROTO_IGMP */
#ifdef PROTO_DVMRP
extern void init_dvmrp_vars();
#endif /* PROTO_DVMRP */
#if defined(PROTO_PIMSM) || defined(PROTO_PIM)
extern void init_pim_vars();
#endif /* PROTO_PIMSM || PROTO_PIM */
#ifdef  PROTO_SLSP
#ifdef not_used
/* XXX slsp MIB not converted to SMUX */
extern void init_slsp_vars();
#endif /* not_used */
#endif /* PROTO_SLSP */
#ifdef PROTO_ISIS
extern void init_isis_vars();
#endif /* PROTO_ISIS */
#ifdef PROTO_MSDP
extern void init_msdp_vars();
#endif /* PROTO_MSDP */

static void smux_tree_reset(void);
static void smux_terminate(task *);
static int smux_register(task *, int);
static void smux_recv(task *);
static void smux_startup(task *);
static int smux_connect(task *);
static void smux_job(task_timer *, time_t);
static void smux_cleanup(task *);
static void smux_dump(task *, FILE *);
static int smux_pdu_response(task *, u_char *, int *, oid **, int *, int, int);
static void smux_restart(task *, int);
static char *tree_str(oid *, int);
static void add_smux_subtrees(void);
static int smux_register_subtree(oid *, int, int, int, task *);
static u_char *smux_get_data(oid *, int *, u_char *, int *, int, int*);
static int smux_write(task *, u_char *, int);
static int smux_close(task *, u_char);
static int smux_simple_open(task *);

static int snmp_tree_next = -1;
static char my_desc[SMUX_MAX_STR_LEN];
static int tc;

task *smux_task;
pref_t smux_preference;
extern int strees_alloc, strees_used;
extern struct subtree *strees;
task_timer *smux_timer_startup = NULL;
int32 smux_reqid = 0;
int snmp_quantum = 0;

static u_char *smux_recv_buf;
static u_char *smux_send_buf;
static block_t smux_buf_idx;

/*
 *	NOTES:
 *		general startup flow....
 *		initialize smux tcp port.  When the socket is
 *		ready for writing, kick off the registration
 *		process.  
 */

const bits smux_trace_types[] = {
        { TR_SMUX_RECV,          "receive" },
        { TR_SMUX_SEND,          "send" },
        { TR_SMUX_PACKETS,       "packets" },
        { 0, NULL }
};

static void
smux_tree_reset(void)
{
	int i;

	for (i = 0; i < strees_used; i++)
		strees[i].st_flags = SMUX_TREE_REGISTER;
    
	snmp_tree_next = -1;
}

/* 
 * Terminate the SMUX task and free the trace options.
 */
static void
smux_terminate(task *tp)
{
	if (tp->task_socket >= 0) {
		/* try to send a close */
		(void)smux_close(tp, (u_char)SMUX_CLOSE_GOINGDOWN);
		close(tp->task_socket);
		task_reset_socket(tp);
	}

	if (smux_timer_startup) {
		task_timer_delete(smux_timer_startup);
		smux_timer_startup = (task_timer *) 0;
	}
	task_delete(tp);
	smux_task = (task *) 0;

	task_mem_free((task *)NULL, strees);
	strees_used = strees_alloc = 0;

	if (BIT_TEST(task_state, TASKS_TERMINATE)) {
		trace_freeup(smux_trace_options);
	}
}

static int
smux_pdu_response(task *tp, u_char *buf, int *buflen, oid **names,
    int *namelens, int n, int exact)
{

	int eidx, error, nso, i, len, vlens[SMUX_MAX_NAME];
	u_char type, types[SMUX_MAX_NAME], *vptr[SMUX_MAX_NAME];

	for (i = 0; i < n; i++) {
		vptr[i] = smux_get_data(names[i], &namelens[i], &type,
		    &len, exact, &nso);
		if (vptr[i] == NULL) {
			if (nso)
				error = SMUX_NOSUCHOBJECT;
			else
				error = SMUX_NOSUCHINSTANCE;
			eidx = i;
			goto badpkt;
		}
		vlens[i] = len;
		types[i] = type;
	}

	if (smux_build_getrsp(buf, buflen, names, namelens,
	    vptr, vlens, types, n, 0, 0)) {
		/* XXX we have no way of telling if it is TooBig */
		return 1;
	} else {
		return (smux_write(tp, buf, (SMUX_MAX_SIZE - *buflen)));
	}
badpkt:
	if (smux_build_getrsp(buf, buflen, names, namelens, NULL, 
	    NULL, NULL, n, error, eidx)) {
		return 1;
	} else {
		return (smux_write(tp, buf, (SMUX_MAX_SIZE - *buflen)));
	}

	/* free the OIDs... */
	for (i = 0; i < n; i++) {
		task_block_free(asn1_oid_block_index, (void_t)names[i]);
	}
}

/* 
 * Modified getStatPtr that handles SNMPv1 only.
 */
static u_char *
smux_get_data(oid *name, int *namelen, u_char *type, int *len,
    int exact, int *noSuchObject)
{
	u_char *access;
	struct subtree *tp;
	struct variable *vp;
	int found, res, savelen, sn, suffixlen;
	int tres, var_num;
	oid save[MAX_NAME_LEN], *suffix;

	access = NULL;
	found = FALSE;

	if (!exact){
		bcopy((char*)name, (char*)save, *namelen * sizeof(oid));
		savelen = *namelen;
	}
	for (sn = 0, tp = strees; sn < strees_used;
	    sn++, tp++) {

		tres = compare_partial(name, *namelen,
		    tp->st_name, tp->st_namelen);

	    	/* if exact and tres == 0
	       	 * if next  and tres <= 0 
		 */
		if (tres == 0 || (!exact && tres < 0)) {
			res = tres;
			suffixlen = *namelen - tp->st_namelen;
			suffix = name + tp->st_namelen;
			for (var_num = 0; var_num < tp->st_n_vars;
			    var_num++) {
				/* if exact and ALWAYS
			 	 * if next  and res >= 0 
				 */
				vp = &(tp->st_vars[var_num]);
				if (exact || res >= 0) {
					res = compare_partial(suffix,
					    suffixlen, vp->suf_name,
					    vp->suf_namelen);
				}
	            		/* if exact and res == 0
	             		 *  if next  and res <= 0 
		     		 */
				if ((!exact && (res <= 0)) ||
				    (exact && (res == 0))) {

			    		access = (*(vp->findVar))(vp, name,
					    namelen, exact, len, NULL);

	              	       		/* $$$ this code is incorrect if there is
	               	 		 * a view configuration that exludes a
					 * particular instance of a variable.
					 * It would return noSuchObject,
	                 		 * which would be an error 
					 */

	                		if (access != NULL)
	                    			break;
	            		}

				/* if exact and res <= 0 */
				if (exact && (res <= 0)) {
					*type = vp->type;

	               	 	if (found)
	                 		*noSuchObject = FALSE;
	                	else
	                    		*noSuchObject = TRUE;

	                	return NULL;
	      			}
	        	}
		if (access != NULL)
			break;
		}
	}

	if (sn == strees_used) {
		if (!access && !exact){
			bcopy((char*)save, (char*)name, savelen * sizeof(oid));
			*namelen = savelen;
		}
		if (found)
			*noSuchObject = FALSE;
		else
			*noSuchObject = TRUE;
		return NULL;
	}
	/* vp now points to the approprate struct */
	*type = vp->type;

	return access;
}

/*
 *	Send a smux register request.
 *	returns:
 *		OK 	== a register request was sent
 *		NOTOK	== nothing left to register, <or>
 *			problems sending the request.
 *			Check smux_state to know which failed.
 *			smux_state & SMUX_CONNECTED == nothing to register
 */
static int
smux_register(task *tp, int failure)
{
	const char *cmode;
	int mode, sn;

	/* Find something that needs to be registered */
	if (snmp_tree_next >= 0) {
		if (failure) {
			/* Registration failed, don't try again */
			BIT_SET(strees[snmp_tree_next].st_flags,
			    SMUX_TREE_REG_FAILED);
			snmp_tree_next++;
		} else
			BIT_FLIP(strees[snmp_tree_next].st_flags,
			    SMUX_TREE_REGISTERED);
	} else {
		snmp_tree_next = 0;
	}

	/* Find some work to do */
	for (sn = snmp_tree_next; sn < strees_used; 
	    sn++) {
		if ((BIT_MATCH(strees[sn].st_flags, SMUX_TREE_REGISTER)
		    != BIT_MATCH(strees[sn].st_flags, SMUX_TREE_REGISTERED)) &&
		    !BIT_TEST(strees[sn].st_flags, SMUX_TREE_REG_FAILED))
			break;
	}
    
	if (sn == strees_used) {
		/* No more work to do */
		snmp_tree_next = -1;
		trace_tp(tp, TR_SMUX_SEND, 0,
		    ("smux_register: registered %d subtrees", tc));
		return OK;
	}

	/* see if we're registering or un-registering */
	if (BIT_TEST(strees[sn].st_flags, SMUX_TREE_REGISTERED)) {
		/* Unregistering */
		trace_tp(tp, TR_SMUX_SEND, 0,
		    ("Building RREQ-delete for tree %s",
		    tree_str(strees[sn].st_name, strees[sn].st_namelen)));
		mode = 0;
    	} else {
		/* Registering */
		trace_tp(tp, TR_SMUX_SEND, 0,
		    ("Sending REGISTER (read only) for tree %s",
		    tree_str(strees[sn].st_name, strees[sn].st_namelen)));
		mode = RONLY;
    	}

	snmp_tree_next = sn; 

	if (smux_register_subtree(strees[snmp_tree_next].st_name,
	    strees[snmp_tree_next].st_namelen, -1, mode, tp) == NOTOK) {
		smux_restart(tp, 1);
		return NOTOK;
	}

	return OK;
}

/*
 * Main recv() routine, called from task.c.
 */
static void
smux_recv(task *tp)
{
	u_char *ptr, type;
	int i, j, len, mlen, n, odlen;
	int32 status;
	oid *names[SMUX_MAX_NAME];
	int namelens[SMUX_MAX_NAME];
	char lstr[50], tstr[4];

	odlen = SMUX_MAX_SIZE;
	status = 0;

	if ((len = recv(tp->task_socket, smux_recv_buf, SMUX_MAX_SIZE, 0)) <= 0) {
		trace_tp(tp, TR_ALL, 0,
		    ("smux_recv: receive failed, errno %d.  Restarting.", errno));
		smux_restart(tp, 1);
		return;
	}

	ptr = smux_recv_buf;

	/* trace the packet if necessary */
	if (TRACE_TP(tp, TR_SMUX_PACKETS)) {
		trace_tp(tp, TR_SMUX_PACKETS, 0, (""));
		trace_tp(tp, TR_SMUX_PACKETS, 0,
		    ("SMUX RECEIVED %d BYTES", len));
		mlen = len % 8;
		for (i = 0; i < len - mlen; i += 8) {
			sprintf(lstr,
			    "PKT: %02X %02X %02X %02X %02X %02X %02X %02X",
			    ptr[i], ptr[i+1], ptr[i+2], ptr[i+3],
			    ptr[i+4], ptr[i+5], ptr[i+6], ptr[i+7]);
			trace_tp(tp, TR_SMUX_PACKETS, 0, (lstr));
		}
		if (mlen) {
			sprintf(lstr, "PKT: ");
			for (i = len - mlen; i < len; i++) {
				sprintf(tstr, "%02X ", ptr[i]);
				strcat(lstr, tstr);
			}
			trace_tp(tp, TR_SMUX_PACKETS, 0, (lstr));
		}
		trace_tp(tp, TR_SMUX_PACKETS, 0, (""));
	}

	switch (type = *ptr) {
	case SMUX_RRSP:
		if (smux_parse_rrsp(ptr, &len, &status)) {
			trace_tp(tp, TR_ALL, 0,
			    ("SMUX RRSP: invalid packet, restarting connection"));
			(void)smux_close(tp, (u_char)SMUX_CLOSE_PACKETFORMAT);
			smux_restart(tp, 1);
		}
		if (snmp_tree_next == -1) {
			/* error, we have not sent a REGISTER yet */
			trace_tp(tp, TR_ALL, 0, 
			    ("SMUX RRSP: got RRSP without sending RREQ?! (restarting)"));
			(void)smux_close(tp, (u_char)SMUX_CLOSE_PROTOCOLERROR);
			smux_restart(tp, 1);
			return;
		}
		if (status < 0) {
			trace_tp(tp, TR_ALL, 0, ("SMUX RRSP: failure for tree %s",
			    tree_str(strees[snmp_tree_next].st_name,
			    strees[snmp_tree_next].st_namelen)));
		}
		trace_tp(tp, TR_SMUX_RECV, 0,
		    ("smux_recv:  received RRSP length %d status %d", len, status));
		/* at least one broken implementation sets "failure" to 0
		 * if the registration succeeds.  Tolerate this for now.
		 */
		tc++;
		smux_register(tp, 0);
		break;
	case SMUX_GET:
		trace_tp(tp, TR_SMUX_RECV, 0,
		    ("smux_recv:  received GET length %d", len));
		if (smux_parse_get(ptr, &len, names, namelens, &n)) {
			trace_tp(tp, TR_ALL, 0, ("SMUX GET: invalid packet, restarting connection"));
			(void)smux_close(tp, (u_char)SMUX_CLOSE_PACKETFORMAT);
			smux_restart(tp, 1);
			return;
		}
		len = SMUX_MAX_SIZE;
		if (smux_pdu_response(tp, smux_send_buf,
		    &len, names, namelens, n, TRUE)) {
			trace_tp(tp, TR_ALL, 0,
			    ("SMUX GET: could not build response, restarting connection"));
			(void)smux_close(tp, (u_char)SMUX_CLOSE_INTERNALERROR); /* ? */
			smux_restart(tp, 1);
			return;
		}
		break;
	case SMUX_GETNEXT:
		trace_tp(tp, TR_SMUX_RECV, 0,
		    ("smux_recv:  received GETNEXT length %d", len));
		if (smux_parse_get(ptr, &len, names, namelens, &n)) {
			trace_tp(tp, TR_ALL, 0, ("SMUX GET: invalid packet, restarting connection"));
			(void)smux_close(tp, (u_char)SMUX_CLOSE_PACKETFORMAT);
			smux_restart(tp, 1);
			return;
		}
		len = SMUX_MAX_SIZE;
		if (smux_pdu_response(tp, smux_send_buf, &len, names, namelens, n, FALSE)) {
			trace_tp(tp, TR_ALL, 0,
			    ("SMUX GET: could not build response, restarting connection"));
			(void)smux_close(tp, (u_char)SMUX_CLOSE_INTERNALERROR); /* ? */
			smux_restart(tp, 1);
			return;
		}
		break;

    case SMUX_CLOSE:
		if (smux_parse_close(ptr, &len, &status)) {
			trace_tp(tp, TR_ALL, 0,
			    ("SMUX CLOSE: invalid packet, restarting connection"));
			(void)smux_close(tp, (u_char)SMUX_CLOSE_PACKETFORMAT);
			smux_restart(tp, 1);
		}
		trace_tp(tp, TR_SMUX_RECV, 0,
		    ("smux_recv:  received CLOSE length %d reason %d", len, status));
		smux_restart(tp, 0);
		break;
	case SMUX_OPEN:
	case SMUX_RREQ:
	case SMUX_SOUT:
	case SMUX_GETRSP:
	default:
		trace_tp(tp, TR_SMUX_RECV, 0,
		    ("smux_recv: received unexpected operation: %d", type));
		(void)smux_close(tp, (u_char)SMUX_CLOSE_PROTOCOLERROR);
		smux_restart(tp, 1);
		break;
    	}
}

/*
 * Startup the registration process, stop paying attention to
 * writes on the socket.
 */
static void
smux_startup(task *tp)
{
	trace_tp(tp, TR_ALL, 0,
	    ("smux_startup: CONNECTED to master agent on port %d",
	    htons(smux_port)));

	if (smux_simple_open(tp) == NOTOK) {
		smux_restart(tp, 1);
		return;
	}

	if (smux_register(tp, FALSE) == NOTOK) {
		smux_restart(tp, 1);
		return;
	}
    
	BIT_RESET(tp->task_flags, TASKF_CONNECT);
	task_set_connect(tp, (void (*) ()) 0);
	task_set_socket(tp, tp->task_socket);
}

/* 
 * Connect to the SMUX tcp port.
 * task_get_socket()
 */
static int
smux_connect(task *tp)
{
	tracef("smux_connect: attempting connect %s",
		smux_debug ? " (debugging)" : "(debugging not configured)");

	if (BIT_TEST(task_state, TASKS_TEST)) {
		tp->task_socket = task_get_socket(tp, PF_INET, SOCK_STREAM, 0);
		assert(tp->task_socket >= 0);
    	} else {
		if ((tp->task_socket = task_get_socket(tp, PF_INET, SOCK_STREAM, 0)) < 0) {
			trace_log_tp(tp, 0, LOG_WARNING, 
		    	    (": smux_connect: couldn't get TCP socket!"));
		    	task_quit(errno);
		}
		task_set_recv(tp, smux_recv);
		task_set_connect(tp, smux_startup);
		BIT_SET(tp->task_flags, TASKF_CONNECT);

		trace_tp(tp, TR_STATE, 0, (NULL));
    		task_set_socket(tp, tp->task_socket);

		if (task_connect(tp, (if_addr *) 0)) {
			trace_tp(tp, TR_ALL, 0,
			    ("smux_connect: connect failed, restarting"));
			return NOTOK;
		}
    	}
	return OK;
}

/* 
 * Called when 60 sec. connection timer fires.
 */
static void
smux_job(task_timer *tip, time_t interval)
{
	if (smux_connect(tip->task_timer_task) == NOTOK) {
		smux_restart(tip->task_timer_task, 1);
	} else {
		/* connection succeeded */
		task_timer_delete(tip);
		smux_timer_startup = (task_timer *) 0;
	}
}

/*
 * Cleanup routine.
 */
static void
smux_cleanup(task *tp)
{
	trace_freeup(tp->task_trace);
	trace_freeup(smux_trace_options);
}

/* 
 * Restart SMUX.  Close the socket and reset the timer,
 */
static void
smux_restart(task *tp, int doclose)
{

	trace_tp(tp, TR_ALL, 0,
	    ("smux_restart: restart of SMUX requested, retry in 60 seconds"));

	/* Reset things */
	if (tp->task_socket != -1) {
		if (!BIT_TEST(tp->task_flags, TASKF_CONNECT)) {
			/* the socket is connected, try to send a close
			 * if requested
			 */
			if (doclose)
				(void)smux_close(tp,
				    (u_char)SMUX_CLOSE_GOINGDOWN);
		}
		close(tp->task_socket);
		task_reset_socket(tp);
    	}
	task_set_recv(tp, (void (*) ()) 0);
	task_set_connect(tp, (void (*) ()) 0);
	BIT_RESET(tp->task_flags, TASKF_CONNECT);
	smux_tree_reset();

	/* reset tree counter */
	tc = 0;

	/* a constant 60sec timer, to try to startup smux again */
	if (smux_timer_startup) {
		task_timer_set(smux_timer_startup,
		    (time_t) 60,
		    (time_t) 0);
	} else {
		smux_timer_startup = task_timer_create(tp, "Startup",
		    (flag_t) 0, (time_t) 60, (time_t) 0, smux_job, (void_t) 0);
	}
}

/*
 * Dump.
 */
static void
smux_dump(task *tp, FILE *fp)
{
	return;
}

/*
 * Initialize SMUX variables before parsing.
 */
void
smux_var_init(void)
{
	doing_smux = TRUE;
	smux_preference = RTPREF_SNMP;
	smux_debug = FALSE;
	smux_port = 0;
	smux_passwd[0] = '\0';
}

/*
 * From-the-top initialization of the SMUX task.
 */
void
smux_init(void)
{
	/* 
	 * smux_init() must always be called before snmp_init()
	 */
	if (!doing_smux
#ifdef	PROTO_CMU_SNMP
	    || doing_snmp
#endif /* PROTO_CMU_SNMP */
	) {
		/* turned off */
		if (smux_task)
			smux_terminate(smux_task);
		if (smux_send_buf) {
			task_block_free(smux_buf_idx, (void_t)smux_send_buf);
			smux_send_buf = NULL;
		}
		if (smux_recv_buf) {
			task_block_free(smux_buf_idx, (void_t)smux_recv_buf);
			smux_recv_buf = NULL;
		}
		return;
	} else if (smux_task) {
		/* reconfig */
		trace_inherit_global(smux_trace_options,
		    smux_trace_types, (flag_t) 0);
		smux_task->task_trace = trace_alloc(smux_trace_options);
		smux_restart(smux_task, 1); 
		return;
	}

	/* reset tree counter */
	tc = 0;

	/* init bufs idx */
	smux_buf_idx = task_block_init(SMUX_MAX_SIZE, "smux_buffers");

	/* Set tracing */
	trace_inherit_global(smux_trace_options, smux_trace_types, (flag_t) 0);

	/* add only the GateD-implemented subtrees */
	add_smux_subtrees();
	
	/* init the ASN.1 parsing routines */
	asn_init();

	/* copy the full name to the variables */
	finalize_tree();
   
	/* set the REGISTER bit on all subtrees */
	smux_tree_reset();
 
	sprintf(my_desc, "SMUX GateD version %s, built %s",
	    gated_version, build_date);

	/* setup a task to handle smux */
	smux_task = task_alloc("SMUX", TASKPRI_NETMGMT, smux_trace_options);

	/* alloc send and recv buffers */
	smux_send_buf = (u_char *)task_block_alloc(smux_buf_idx);
	smux_recv_buf = (u_char *)task_block_alloc(smux_buf_idx);

	/* make the remote address the loopback address */
	smux_task->task_addr = sockdup(inet_addr_loopback);

	if (!smux_port) {
		smux_port = task_get_port(smux_trace_options,
		"smux", "tcp", htons(SMUX_PORT));
	}

	sock2port(smux_task->task_addr) = smux_port;
	task_set_terminate(smux_task, smux_terminate);
	task_set_dump(smux_task, smux_dump);
	task_set_cleanup(smux_task, smux_cleanup);
	smux_task->task_rtproto = RTPROTO_SMUX;
	BIT_SET(smux_task->task_flags, TASKF_LOWPRIO);

	if (!task_create(smux_task)) {
		task_quit(errno);
	}

	if (smux_connect(smux_task) == NOTOK)
		smux_restart(smux_task, 1);
}

/*
 * Initialize only the subtrees that we plan to register
 * via SMUX.
 */
static void
add_smux_subtrees(void) {
#if defined(PROTO_BGP) && defined(GATED_MEMBER)
	init_bgp_vars();
#endif /* PROTO_BGP && GATED_MEMBER */
#ifdef PROTO_EGP
	init_egp_vars();
#endif /* PROTO_EGP */
#ifdef	PROTO_OSPF
        init_ospf_vars();
#endif /* PROTO_OSPF */
#ifdef	PROTO_OSPF2
	init_nospf_vars();
#endif	/* PROTO_OSPF2 */
#ifdef	PROTO_RIP
        init_rip_vars();
#endif /* PROTO_RIP */
#ifdef IP_MULTICAST_ROUTING
        init_ipMRoute_vars();
#endif /* IP_MULTICAST_ROUTING */
#ifdef	PROTO_IGMP
        init_igmp_vars();
#endif /* PROTO_IGMP */
#ifdef	PROTO_DVMRP
        init_dvmrp_vars();
#endif /* PROTO_DVMRP */
#if defined(PROTO_PIMSM) || defined(PROTO_PIM)
        init_pim_vars();
#endif /* PROTO_PIMSM || PROTO_PIM */
#ifdef	PROTO_SLSP
#ifdef not_used
	/* slsp MIB not converted to Merit SMUX */
        init_slsp_vars();
#endif /* not_used */
#endif /* PROTO_SLSP */
#ifdef	PROTO_ISIS
        init_isis_vars();
#endif /* PROTO_ISIS */
#ifdef PROTO_MSDP
        init_msdp_vars();
#endif
}

/*
 * Register a single OID.
 */
static int
smux_register_subtree(oid *tname, int tlen, int tpri, int tmode, task *tp)
{
	int len;
	u_char *ptr;
	
	len = SMUX_MAX_SIZE;
	ptr = smux_send_buf;

	if (smux_build_rreq(ptr, &len, tname, tlen, tpri, tmode)) {
		trace_tp(tp, TR_ALL, 0,
		    ("smux_register: build of RREQ failed, restarting."));
		return 1;
	}

    	return(smux_write(tp, ptr, (SMUX_MAX_SIZE - len)));
}

/* 
 * Send a SimpleOpen PDU
 */
static int
smux_simple_open(task *tp)
{
	u_char *ptr;
	oid identity[10] = { 1, 3, 6, 1, 4, 1, 4, 3, 1, 4 };
	int idlen, len;
	int32 version;
	char descr[100];

	len = SMUX_MAX_SIZE;
	idlen = 10;
	ptr = smux_send_buf;

	sprintf(descr, "SMUX GateD version %s built %s", gated_version, build_date);

	trace_tp(tp, TR_SMUX_SEND, 0, 
	    ("smux_simple_open: Sending OpenPDU"));

	if (smux_build_open(ptr, &len, identity, idlen, descr, smux_passwd)) {
		trace_tp(tp, TR_ALL, 0, ("smux_register: build of OPEN failed"));
		return 1;
	}

   	return(smux_write(tp, ptr, SMUX_MAX_SIZE - len));
}

/*
 * Send a packet to the master agent.
 */
static int
smux_write(task *tp, u_char *data, int len)
{
	int i, mlen;
	char lstr[30], tstr[4];

    	if (send(tp->task_socket, data, len, 0) < 0) {
		trace_tp(tp, LOG_ERR, 0,
		    ("smux_write: write of length %d failed, errno %d",
		    len, errno));
		return NOTOK;
    	}

	/* trace the packet if necessary */
	if (TRACE_TP(tp, TR_SMUX_PACKETS)) {
		trace_tp(tp, TR_SMUX_PACKETS, 0, (""));
		trace_tp(tp, TR_SMUX_PACKETS, 0,
		    ("SMUX SENT %d BYTES", len));
		trace_tp(tp, TR_SMUX_PACKETS, 0, (""));
		mlen = len % 8;
		for (i = 0; i < (len - mlen); i += 8) {
			sprintf(lstr,
			    "PKT: %02X %02X %02X %02X %02X %02X %02X %02X",
			    data[i], data[i+1], data[i+2], data[i+3],
			    data[i+4], data[i+5], data[i+6], data[i+7]);
			trace_tp(tp, TR_SMUX_PACKETS, 0, (lstr));
		}
		if (mlen) {
			sprintf(lstr, "PKT: ");
			for (i = len - mlen; i < len; i++) {
				sprintf(tstr, "%02X ", data[i]);
				strcat(lstr, tstr);
			}
			trace_tp(tp, TR_SMUX_PACKETS, 0, (lstr));
		}
		trace_tp(tp, TR_SMUX_PACKETS, 0, (""));
	}
	return 0;
}

/*
 * Convert an OID to a string.
 */
static char *
tree_str(oid *tree, int len)
{
	static char *ptr, tstr[100];
	int i;
   
	ptr = tstr;

	if (tree == NULL) {
		tstr[0] = '\0';
		return tstr;
	}

	for (i = 0; i < len; i++, ptr += 2)
		sprintf(ptr, "%d.", tree[i]);

	*ptr = '\0';

	return tstr;
}

static int
smux_close(task *tp, u_char reason)
{
	u_char *ptr;
	int len;

	ptr = smux_send_buf;
	len = SMUX_MAX_SIZE;

	trace_tp(tp, TR_SMUX_SEND, 0,
	    ("smux_close: sending ClosePDU reason %d", (int)reason));

	if (smux_build_close(ptr, &len, reason))
		return 1;

	return (smux_write(tp, ptr, (SMUX_MAX_SIZE - len)));
}
#endif /* defined(PROTO_SMUX) */
