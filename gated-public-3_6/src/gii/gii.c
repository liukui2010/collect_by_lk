/*
 * Consortium Release 4
 * 
 * $Id: gii.c,v 1.8 2000/03/03 06:38:01 bobsills Exp $
 */
/*
 * Copyright (c) 1996 The Regents of the University of Michigan
 * All Rights Reserved
 * 
 * License to use, copy, modify, and distribute this software and its
 * documentation can be obtained from Merit at the University of Michigan.
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
 */
#define INCLUDE_IF
#define INCLUDE_RT_VAR

#include "include.h"
#include "gii.h"
#include "inet/inet.h"
#include <pwd.h>
#ifdef	SHADOWPW
#include <shadow.h>
#endif	/* SHADOWPW */
#include <arpa/telnet.h>
#include "list.h"
#include "krt/krt.h"
#include "krt/krt_var.h"
#ifdef IP_MULTICAST_ROUTING
#include "inet_multi.h"
#endif
#ifdef PROTO_BGP
#include "bgp/bgp_proto.h"
#include "bgp/bgp.h"
#include "bgp/bgp_var.h"
#endif
#ifdef PROTO_RIP
#include "rip/rip.h"
#endif
#define expressionMatch(a) a


extern const bits kernel_support_bits[];
extern const bits kernel_option_bits[];

giimenu_cmd_t giicmd_route[] = {
	{ "route",	NULL,		gii_showrtipall,gii_showrtip,
				" [x.x.x/len]: Show info about IP routes" },
	{ "walkup",	NULL,		gii_help,	gii_showipup,
				" x.x.x/len: Show less specific routes" },
	{ "walkdown",	NULL,		gii_help,	gii_showipdown,
				" x.x.x/len: Show more specific routes" },
	{ NULL, NULL, NULL, NULL, NULL }
};

giimenu_cmd_t giicmd_bgp[] = {
        { "aspath",	NULL,   NULL,	gii_showbgpaspath,
                                " [AS path regexp]: Show BGP aspath info" },
        { "cidr-only",  NULL,   NULL,   gii_showbgpcidronly,
                                ": Show routes with CIDR network masks" },
	{ "expression", NULL,   NULL,   gii_showbgpexpression,
                                " [expression]: Show routes that match the expression" },
        { "inconsistent-as",  NULL,   NULL,   gii_showbgpinconsistent,
                                ": Show routes with inconsistent AS" },
	{ "peeras",     NULL,   NULL,   gii_showbgppeeras,
                                " [AS number]: Show BGP peer info" },
        { "peer-group", NULL,   NULL,   gii_showbgppeergroup,
                                " [tag]: Show information about BGP peer groups" },
	{ "routes",     NULL,   NULL,   gii_showbgproutes,
                                " [network][/network-mask]: Show entries in the BGP routing table" },
	{ "summary",    NULL,   NULL,   gii_showbgpsum,
                                ": Show BGP summary" },
        { NULL, NULL, NULL, NULL, NULL }
};

giimenu_cmd_t giicmd_rip[] = {
	{ "routes",	NULL,	NULL,	gii_showriproutes,
				" [network][/network-mask]: Show routes learned via RIP" },
	{ "summary",	NULL,	NULL,	gii_showripsummary,
				" : Show RIP summary" },
	{ "tag",	NULL,	NULL,	gii_showriptag,
				" [tag]: Show routes that match a tag (v2 only)"}, 
	{ NULL, NULL, NULL, NULL, NULL }
	};

giimenu_cmd_t giicmd_show[] = {
	{ "version", 	NULL, 		NULL,		gii_showversion,
					": Show the current GateD version" },
	{ "kernel", 	NULL,		NULL,		gii_showkernel,
					": Show the Kernel support" },
	{ "interface",	NULL, 		gii_showallif,	gii_showif,
					" [name|index]: Show interface status"},
	{ "memory",	NULL,		NULL,		gii_showmem,
					": Show the memory allocation" },
	{ "ip",		giicmd_route,	gii_help,	gii_help,
					": Show info about IP protocol" },
	{ "task",	NULL,		gii_showalltask,gii_showalltask,
					": Show list of active tasks" },
	{ "timer",	NULL,		gii_showalltimer,gii_showalltimer,
					": Show list of timers" },
	{ "bgp",	giicmd_bgp,	gii_help,	gii_help,
					": Show info about BGP protocol" },
	{ "rip",	giicmd_rip,	gii_help,	gii_help,
					": Show info about RIP protocol" },
	{ NULL, NULL, NULL, NULL, NULL }
};

giimenu_cmd_t giicmd_top[] = {
	{ "help",	NULL, 		NULL, 		gii_help,
					": Print help messages" },
	{ "show",	giicmd_show,	gii_help, 	gii_help,
					": Show internal values" },
	{ "quit",	NULL,		NULL, 		gii_quit,
					": Close the session" },
	{ NULL, NULL, NULL, NULL, NULL }
};
/* YYYYUK!
 */
giimenu_cmd_t *gii_helpcmd = &giicmd_top[0];

/* List of state names
 */
const char *gii_statenames[] = {
	"GIIS_OPEN",		/* GIIS_OPEN */
	"GIIS_SESSION",		/* GIIS_SESSION */
	"GIIS_JOB",		/* A job is running */
};

trace *gii_trace_options;
const bits gii_trace_types[] = {
	{ TR_DETAIL,        "detail packets" },
    	{ TR_DETAIL_SEND,   "detail send packets" },
    	{ TR_DETAIL_RECV,   "detail recv packets" },
	{ 0, NULL }
};

task *gii_task_listen = NULL;
u_short gii_port = 0;
flag_t gii_flags = GIIF_ON;
gii_ctl_t *gii_ctl_list = NULL;
block_t gii_ctl_alloc = NULL;
char cmd_errmsg[BUFSIZ];

/* Initialisation of the Gated Interactive Interface
 */
void
gii_init ()
{
	int s;

	/* If GII is not used, clean up!
	 */
	if (!BIT_TEST(gii_flags, GIIF_ON)) {
		gii_cleanup();
		return;
	}

	/* If we use a "-c" on gated run command
	 * none of the socket call are worth having
	 * as they give garbage due to the the TASKS_TEST
         * bit being set in the task_state.
	 *   GII wont run in "-c" because it absolutely work because 
	 *   it's a server function which requires a socket,
	 * 	a bind and a listen.
	 *
	 *  So, if we exit here.  
	 */  

	if (BIT_TEST(task_state,TASKS_TEST)) { 
		gii_cleanup();
		return;
	}

	/* Get the trace options from the global trace
	 */
	trace_inherit_global(gii_trace_options, gii_trace_types, (flag_t) 0);

	/* Do we need to create a task for listening?
	 */
	if (!gii_task_listen) {

		/* Get one...
		 */
		gii_task_listen = task_alloc("GII_LISTEN", TASKPRI_NETMGMT,
			gii_trace_options);

		/* Get the port number to listen from
		 */
		if (!gii_port)
			gii_port = task_get_port(gii_trace_options,
				"gii", "tcp", htons(GII_PORT));

		/* Some method initilaisation...
		 */
		/*task_set_recv(gii_task_listen, gii_recv); */
		/*task_set_cleanup(gii_task_listen, gii_cleanup);*/
		/*task_set_reinit(gii_task_listen, gii_reinit);*/
		gii_task_listen->task_flags |= TASKF_ACCEPT;
		task_set_dump(gii_task_listen, gii_dump);
		task_set_terminate(gii_task_listen, gii_terminate);
		task_set_accept(gii_task_listen, gii_accept);

		/* And the socket...
		 */
		if ((s = task_get_socket(gii_task_listen, AF_INET,
				SOCK_STREAM, 0)) < 0) {
			s = errno;
			trace_log_tp(gii_task_listen, 0, LOG_ERR,
				("gii_init: cannot get socket"));
			task_quit(s);
		}
		task_set_socket(gii_task_listen, s);

		/* We want to reuse the address.
		 */
		if (task_set_option(gii_task_listen, TASKOPTION_REUSEADDR,
				TRUE) < 0)
			task_quit(errno);

		/* The bind() call
		 */
		gii_task_listen->task_addr = sockdup(inet_addr_any);
		sock2port(gii_task_listen->task_addr) = gii_port;
		if (task_addr_local(gii_task_listen,gii_task_listen->task_addr))
			task_quit(errno);

		/* Now listen to the socket. No task_xxx function to do that!
		 */
		if (listen(s, 5) < 0) {
			trace_log_tp(gii_task_listen, 0, LOG_ERR,
				("gii_init: cannot listen: %m"));
			task_quit(errno);
		}

		/* Start the task
		 */
		task_create(gii_task_listen);
	}

	/* Memory initialisation
	 */
	if (!gii_ctl_alloc)
		gii_ctl_alloc = task_block_init(sizeof(gii_ctl_t), "gii_ctl_t");
}

void
gii_var_init ()
{
}

/* Accept an incoming connection
 */
void
gii_accept (task * listen_tp)
{
	int s, inaddrlen;
	struct sockaddr_in inaddr;
	sockaddr_un *paddr;
	task *tp;
	gii_ctl_t *gii_ctl;

	/* Accept the connection
	 */
	inaddrlen = sizeof(inaddr);
	if ((s = accept(listen_tp->task_socket, (struct sockaddr *) &inaddr,
			(int *) &inaddrlen)) < 0) {
		trace_log_tp(listen_tp, 0, LOG_ERR,
			("gii_accept: accept: accept(%d): %m",
				listen_tp->task_socket));
		return;
	}

	/* Make a copy of the address for later use
	 */
	paddr = sockdup(sock2gated((struct sockaddr *) &inaddr, inaddrlen));

#ifdef TCPWRAPPER
	/* Do we want the guy?
	 */
	if (!hosts_ctl("gii", "", inet_ntoa((struct sockaddr_in *)&inaddr,
			"")) {
		trace_tp(listen_tp, TR_NORMAL, 0,
			("gii_accept: connection refused for %#A", paddr));

		/* Get rid of him!
		 */
		(void)close(s);
		return;
	}
#endif	/* TCPWRAPPER */

	trace_tp(listen_tp, TR_NORMAL, 0, ("gii_accept: connection from %#A",
		paddr));

	/* Now we create a task to take care of that connection
         */
        tp = task_alloc("GII_SESSION", TASKPRI_NETMGMT, gii_trace_options);
        task_set_socket(tp, s);
        tp->task_addr = paddr;
        if (task_set_option(tp, TASKOPTION_REUSEADDR, TRUE) < 0)
                task_quit(errno);

	/* Set all the methods
	 */
	task_set_dump(tp, gii_dump);
	task_set_terminate(tp, gii_terminate);
	task_set_recv(tp, gii_recv);

	/* Create a local structure to keep the state of the connection
	 */
	gii_ctl = (gii_ctl_t *)task_block_alloc(gii_ctl_alloc);
	gii_ctl->g_state = GIIS_OPEN;
	gii_ctl->g_iden_tries = 0;
	gii_ctl->g_task = tp;
	gii_ctl->g_cmdmenu = giicmd_top;
	gii_ctl->g_cmd = NULL;
	gii_ctl->g_cmdStr[0] = '\0';
	gii_ctl->g_bufflen = 0;
	gii_ctl->g_buffLeft = 2*GIIMAXLINELEN;
	LIST_ADD(gii_ctl_list, gii_ctl);

	tp->task_data = (caddr_t)gii_ctl;
	task_create(tp);

	/* Identify the user
	 */
	(void) gii_iden(gii_ctl);
}

/* Identify an user. In fact, just ask for the password
 */
int
gii_iden (gii_ctl_t * gii_ctl)
{
	/* If we have tries too many time, give up!
	 */
	if (++gii_ctl->g_iden_tries > GII_MAXTRIES) {
		trace_tp(gii_ctl->g_task, TR_NORMAL, 0,
			("gii_iden: logging failed from %#A",
			gii_ctl->g_task->task_addr));
		gii_terminate(gii_ctl->g_task);
		return(1);
	}

	/* Turn off echo on a telnet connection
	 */
	telnet_echooff(gii_ctl);

	/* Ask for a password.
	 */
	return(gii_write(gii_ctl, GW_NONE, "Password? "));
}

/* what to do when receiving a packet
 */
void
gii_recv (task * tp)
{
	int err, lnSize;
	gii_ctl_t *gii_ctl;
	char *ln, *cr;

	/* Our control structure
	 */
	gii_ctl = (gii_ctl_t *)tp->task_data;

	/* read the data and copy it into our internal bugger
	 */
	err = read(tp->task_socket, gii_ctl->g_buff + gii_ctl->g_bufflen,
		gii_ctl->g_buffLeft);
	if (err < 0) {
		switch(errno) {
		case EWOULDBLOCK:
#if     defined(EAGAIN) && EAGAIN != EWOULDBLOCK
		case EAGAIN:
#endif  /* EAGAIN */
		case EINTR:
			/* Well, nothing to do, just return.
			 */
			return;
		default:
			/* Get rid of the peer
			 */
			trace_tp(tp, 0, LOG_ERR,
				("gii_recv: read from peer %#A failed: %m",
				tp->task_addr));
			gii_terminate(tp);
			return;
		}
	}

	if (err == 0) {
		/* End of file. Terminate.
		 */
		trace_tp(tp, TR_NORMAL, 0,
			("gii_recv: end of session from %#A", tp->task_addr));
		gii_terminate(tp);
		return;
	}

	gii_ctl->g_bufflen += err;
	gii_ctl->g_buffLeft -= err;
	telnet_strip(gii_ctl->g_buff, &gii_ctl->g_bufflen);

	/* Get as much "line" as possible, freeing the buffer
	 */
	while(gii_ctl->g_bufflen &&
			(cr = (char *)index(gii_ctl->g_buff, '\n'))) {
		*cr = '\0';
		ln = gii_ctl->g_buff;
		STRIP(ln);
		if (gii_process(gii_ctl, ln))
			return;

		lnSize = GA2S(cr) - GA2S(gii_ctl->g_buff) + 1;
		gii_ctl->g_bufflen -= lnSize;
		gii_ctl->g_buffLeft += lnSize;
		(void)bcopy(cr, gii_ctl->g_buff, lnSize);
	}
}

/* Process the line. Just a parser for the interpreter.
 * Return 1 if the task has terminated.
 */
int
gii_process (gii_ctl_t * gii_ctl, char * ln)
{
#ifdef SHADOWPW
	struct spwd *pw;
#else
	struct passwd *pw;
#endif	/* SHADOWPW */

	switch(gii_ctl->g_state) {
	case GIIS_OPEN:
		/* Echo is turned off, so echo only the last '\n'
		 */
		if (gii_write(gii_ctl, GW_NONE, "\r\n"))
			return(1);

		/* If the state is GIIS_OPEN we need to read the 
	 	 * password. But first get the crypted password.
	 	 */
#ifdef SHADOWPW
		pw = getspnam(GII_USER);
		if (!pw || !pw->sp_pwdp) {
#else
		pw = getpwnam(GII_USER);
		if (!pw || !pw->pw_passwd) {
#endif	/* SHADOWPW */
			trace_tp(gii_ctl->g_task, 0, LOG_ERR,
				("gii_process: no password or user %s",
					GII_USER));
			if (gii_write(gii_ctl, GW_ERR,
					"Configuration error. Disconnecting!"))
				return(1);
			gii_terminate(gii_ctl->g_task);
			return(1);
		}

		/* Check the password we got
		 */
#ifdef SHADOWPW
		if (strcmp(pw->sp_pwdp, (char *)crypt(ln, pw->sp_pwdp)))
#else
		if (strcmp(pw->pw_passwd, (char *)crypt(ln, pw->pw_passwd)))
#endif	/* SHADOWPW */
			return(gii_iden(gii_ctl));

		/* Authentication succeeded. Go to state GIIS_SESSION.
		 * Also turn on the echo back.
		 */
		telnet_echoon(gii_ctl);
		if (gii_write(gii_ctl, GW_INFO,
				"Gated Interactive Interface. Version %s",
				gated_version))
			return(1);
		gii_ctl->g_state = GIIS_SESSION;
		return(gii_prompt(gii_ctl));

	case GIIS_SESSION:
		/* Parse the command.
		 */
		if (gii_parse_cmd(gii_ctl, ln))
			return(1);
		return(gii_prompt(gii_ctl));
	case GIIS_JOB:
		/* If we get a ^C or ^D or ^Z then we stop the job.
		 */
		if (index(ln, '\013') || index(ln, '\014') ||
				index(ln, '\032')) {
			GASSERT(gii_ctl->g_job && gii_ctl->g_walk);
			gii_ctl->g_walk = rt_walk_free(gii_ctl->g_walk);
			task_job_delete(gii_ctl->g_job);
			gii_ctl->g_job = NULL;
			GII_WRITE((gii_ctl, GW_INFO,
				"Current job killed"));
			return(gii_prompt(gii_ctl));
		}
		return(0);
	}
	GASSERT(0);
	return(0);
}

/* Write a message to the peer. Return 1 if the task has been terminated.
 */
int
#ifdef  STDARG
gii_write(gii_ctl_t *gii_ctl, int code, const char *msg, ...)
#else   /* STDARG */
gii_write(va_alist)
	va_dcl
#endif  /* STDARG */
{
	va_list ap;
	char buf[GIIMAXLINELEN];
	char buf2[GIIMAXLINELEN];
	int err, len, try;
	
#ifdef  STDARG
	va_start(ap, msg);
#else   /* STDARG */
	gii_ctl_t *gii_ctl;
	int code;
	const char *msg;
	int pri;
	
	va_start(ap);
	gii_ctl = va_arg(ap, gii_ctl_t *);
	code = va_arg(ap, int);
 	msg = va_arg(ap, const char *);
#endif  /* STDARG */

	(void) vsprintf(buf, msg, ap);
	if (code != GW_NONE)
		(void) sprintf(buf2, "%1d00 %s\n", code, buf);
	else
		(void) strcpy(buf2, buf);
	len = strlen(buf2);

	/* write the buffer to the socket and check for errors.
	 */
#define MAXWRITETRIES 3
	try = 0;
	do {
		err = write(gii_ctl->g_task->task_socket, buf2, len);
		if (err < 0) {
			switch(errno) {
			case EWOULDBLOCK:
				/* The buffer are full, that's bad. Let's
				 * give up too
			 	 */
			case EHOSTUNREACH:
			case ENETUNREACH:
			default:
				/* give up
			 	 */
				trace_tp(gii_ctl->g_task, 0, LOG_ERR,
				("gii_write: write from peer %#A failed: %m",
					gii_ctl->g_task->task_addr));
				gii_terminate(gii_ctl->g_task);
				return(1);

#if defined(EAGAIN) && EAGAIN != EWOULDBLOCK
               		case EAGAIN:
#endif  /* EAGAIN */
               		case EINTR:
				/* Let's try again?
			 	*/
				try++;
				continue;
			}
		}
		else if (err == 0) {
			/* Connection closed?
			 */
			trace_tp(gii_ctl->g_task, 0, LOG_ERR,
			("gii_write: write: connection closed from peer %#A",
				gii_ctl->g_task->task_addr));
			gii_terminate(gii_ctl->g_task);
			return(1);
		}
		else if (err < len) {
			/* We didn't write every thing. that's bad. Let's
			 * close the connection.
			 */
			trace_tp(gii_ctl->g_task, 0, LOG_ERR,
			("gii_write: write: congestion from peer %#A",
				gii_ctl->g_task->task_addr));
			gii_terminate(gii_ctl->g_task);
			return(1);
		}

		/* We are happy, everything has been written
		 */
		return(0);

	} while(try < MAXWRITETRIES);

	/* something was wrong. Let's give up.
	 */
	trace_tp(gii_ctl->g_task, 0, LOG_ERR,
		("gii_write: write: too many tryes (%d) from peer %#A: %m", 
		MAXWRITETRIES, gii_ctl->g_task->task_addr));
	gii_terminate(gii_ctl->g_task);
	return(1);
}

/* Terminate a session.
 */
void
gii_terminate (task * tp)
{
	gii_ctl_t *gii_ctl;

	/* Is it a session task? If so, free the control block.
	 */
	if ((gii_ctl = (gii_ctl_t *)tp->task_data)) {
		if (gii_ctl->g_walk)
	                gii_ctl->g_walk = rt_walk_free(gii_ctl->g_walk);
		if (gii_ctl->g_job)
                	task_job_delete(gii_ctl->g_job);
                gii_ctl->g_job = NULL;
#ifdef PROTO_OSPF2
		if (gii_ctl->g_ospfwalk)
			gii_ctl->g_ospfwalk =
				ospf_pt_walkdel(gii_ctl->g_ospfwalk);
#endif

		LIST_REM(gii_ctl_list, gii_ctl);
		task_block_free(gii_ctl_alloc, (void_t)gii_ctl);
	}

	/* close the socket and free the task.
	 */
	task_delete(tp);
}

/* clean up. I.e. get read of all connections, and the listening task.
 */
void
gii_cleanup ()
{
	gii_ctl_t *gii_ctl, *next;

	/* Get all gii_ctl. Delete all tasks.
	 */
	for(gii_ctl = gii_ctl_list; gii_ctl;) {
		task_delete(gii_ctl->g_task);
		next = gii_ctl->g_next;
		task_block_free(gii_ctl_alloc, (void_t)gii_ctl);
		gii_ctl = next;
	}
	gii_ctl_list = (gii_ctl_t *)NULL;

	/* Delete the listen task
	 */
	if (gii_task_listen)
		task_delete(gii_task_listen);
}

/* Dump a task.
 */
void
gii_dump (task * tp, FILE * fd)
{
	gii_ctl_t *gii_ctl;

	gii_ctl = (gii_ctl_t *)tp->task_data;

	if (!gii_ctl) {
		/* This is the listen task
		 */
		(void) fprintf(fd, "\tGII LISTEN on port %d\n",
			ntohs(gii_port));
		return;
	}

	/* This is a session task
	 */
	(void) fprintf(fd, "\tPeer %#A\tState %s\n",
		tp->task_addr, GIISTATESTR(gii_ctl->g_state));
}

/* Parse a command from the peer
 */
int
gii_parse_cmd (gii_ctl_t * gii_ctl, char * ln)
{
	int nbTok, tok;
	char tokens[GIITOKENLEN][GIINBMAXTOKENS];
	giimenu_cmd_t *cmd_table, *cmd;

	/* Separate all the tokens
	 */
	nbTok = split(ln, tokens);

	/* No token means an empty line.
	 */
	if (!nbTok)
		return(0);

	/* Find out what command   to execute
	 */
	cmd_table = giicmd_top;
	gii_ctl->g_cmdStr[0] = '\0';

	for(tok = 0; tok < nbTok; tok++) {

		/* look up the command name.
		 */
		if (!(gii_ctl->g_cmd = cmd = cmd_find(cmd_table, tokens[tok])))
			return(gii_cmd_error(gii_ctl));

		(void)strcat(gii_ctl->g_cmdStr, " ");
		(void)strcat(gii_ctl->g_cmdStr, cmd->cmd_name);

		/* If no more token, execute the 'last token' method
		 */
		if (tok == nbTok - 1) {
			trace_tp(gii_ctl->g_task, TR_NORMAL, 0,
				("Executing \"%s\"", gii_ctl->g_cmdStr));
			if (cmd->cmd_lasttok) {
				return(cmd->cmd_lasttok(gii_ctl));
			}
			else if (!cmd->cmd_nextCmdTable) {
				GASSERT(cmd->cmd_exec);
				return(cmd->cmd_exec(gii_ctl, tokens + tok, 0));
			}
			else {
				(void)sprintf(cmd_errmsg,
					"Insufficiant command \"%s\"",
					gii_ctl->g_cmdStr);
				return(gii_cmd_error(gii_ctl));
			}
		}

		/* Get the next command table. If this is the last
		 * one, excetute the command method
		 */
		if (!cmd->cmd_nextCmdTable) {
			GASSERT(cmd->cmd_exec);
			trace_tp(gii_ctl->g_task, TR_NORMAL, 0,
				("Executing \"%s\"", gii_ctl->g_cmdStr));
			return(cmd->cmd_exec(gii_ctl, tokens + tok + 1,
				nbTok - tok - 1));
		}

		gii_ctl->g_cmdmenu = cmd_table = cmd->cmd_nextCmdTable;
	}
	/* By now we should have executed something
	 */
	GASSERT(0);
	return(0);
}

int
gii_cmd_error(gii_ctl)
	gii_ctl_t *gii_ctl;
{
	return(gii_write(gii_ctl, GW_ERR, cmd_errmsg));
}

int
split(str, tokens)
	char *str;
	char tokens[GIITOKENLEN][GIINBMAXTOKENS];
{
	int tok;
	char *strTok;

	for(tok = 0, strTok = (char *)strtok(str, "\t\n ");
			strTok && tok < GIINBMAXTOKENS; tok++,
			strTok = (char *)strtok(NULL, "\t\n "))
		(void)strncpy(tokens[tok], strTok, GIITOKENLEN);
	return(tok);
}

/* Given the name of a command, find out the giimenu_cmd_t entry in
 * cmd_table which describe this command
 */
giimenu_cmd_t *
cmd_find(cmd_table, cmdStr)
	giimenu_cmd_t cmd_table[];
	char *cmdStr;
{
	char match[GIITOKENLEN];
	int nbMatch;
	giimenu_cmd_t *cmd, *rtnCmd=NULL;

	/* Go through all the entries in cmd_table
	 */
	match[0] = '\0';
	nbMatch = 0;
	for(cmd = &cmd_table[0]; cmd->cmd_name; cmd++) {

		if (strncmp(cmdStr, cmd->cmd_name, strlen(cmdStr)))
			continue;

		/* If we get an exact match, take it!
		 */
		if (strlen(cmdStr) == strlen(cmd->cmd_name)) {
			nbMatch = 1;
			rtnCmd = cmd;
			(void)strcat(match, " ");
			(void)strcat(match, cmd->cmd_name);
			break;
		}

		nbMatch++;
		rtnCmd = cmd;
		(void)strcat(match, " "); (void)strcat(match, cmd->cmd_name);
	}

	/* If we got more than one match, print an error and return NULL
	 */
	if (nbMatch > 1) {
		(void)sprintf(cmd_errmsg,
			"Unbiguous keywork \"%s\". Possible values are\"%s\"",
			cmdStr, match);
		return(NULL);
	}
	else if (!nbMatch) {
		(void)sprintf(cmd_errmsg, "Unknown command \"%s\"", cmdStr);
		return(NULL);
	}
	return(rtnCmd);
}
	
/* close the session
 */
int
gii_quit(gii_ctl)
	gii_ctl_t *gii_ctl;
{
	gii_terminate(gii_ctl->g_task);
	return(1);
}

/* Print the version
 */
int
gii_showversion(gii_ctl)
        gii_ctl_t *gii_ctl;
{
        return(gii_write(gii_ctl, GW_INFO, "Version %s (%s)", gated_version,
		build_date));
}



/* Show the bgp stuff */
#ifdef BILLBILL
int gii_showbgp(gii_ctl_t *gii_ctl)
{
  return(0);
}
#endif


/* Print some help messages
 */
int
gii_help(gii_ctl)
        gii_ctl_t *gii_ctl;
{
	giimenu_cmd_t *cmd;
	const char *sub = "";

	GASSERT(gii_ctl->g_cmdmenu);

	/* Top level help command
	 */
	if (gii_ctl->g_cmd == gii_helpcmd) {
		/* Default are ok.
		 */
	}
	/* Is there any sub command for that one?
	 */
	else if (gii_ctl->g_cmd && gii_ctl->g_cmd->cmd_nextCmdTable) {
		sub = "sub";
		gii_ctl->g_cmdmenu = gii_ctl->g_cmd->cmd_nextCmdTable;
	}

        if (gii_write(gii_ctl, GW_INFO, "HELP: The possible %scommands are:",
			sub))
		return(1);

	for(cmd = gii_ctl->g_cmdmenu; cmd->cmd_name; cmd++) {
		if (gii_write(gii_ctl, GW_INFO, "\t%s%s",
			cmd->cmd_name,cmd->cmd_helpMsg))
			return(1);
	}
	return(0);
}


/* Print BGP aspath information */
int gii_showbgpaspath(gii_ctl, tokens, nbTok)
       gii_ctl_t *gii_ctl;
       char tokens[GIITOKENLEN][GIINBMAXTOKENS] UNUSED;
        int nbTok UNUSED;
 {
#ifndef PROTO_BGP
  return(GII_NOAVAILABLE);
#else
  as_path *asp;

   GII_WRITE((gii_ctl,
          GW_INFO,
         "%-5s %s",
          "Ref",
          "Path"));
   gii_ctl->g_pathwalk = (pathwalk_t *)NULL;

   ASPATH_LIST(asp) {
	if (expressionMatch(asp))
		GII_WRITE((gii_ctl, GW_INFO, "%-5d %s", 0, aspath_str(asp)));
   } ASPATH_LIST_END(asp);

  return(0);
#endif
 }
 
/* Print BGP summary information
 */
int
gii_showbgpsum(gii_ctl, tokens, nbTok)
        gii_ctl_t *gii_ctl;
        char tokens[GIITOKENLEN][GIINBMAXTOKENS] UNUSED;
        int nbTok UNUSED;
{
#ifndef PROTO_BGP
  return(GII_NOAVAILABLE);
#else
  register bgpPeerGroup *bgp;
  register bgpPeer *bnp;
  register int group_count = 0;
  register int peer_count = 0;

  GII_WRITE((gii_ctl,
         GW_INFO,
         "%-15s %1s %5s %7s %7s %s",
         "Neighbor",
         "V",
         "AS",
         "MsgRcvd",
         "MsgSent",
         "State"));
  BGP_GROUP_LIST(bgp) {
    group_count++;
    BGP_PEER_LIST(bgp, bnp) {
      GII_WRITE((gii_ctl,
             GW_INFO,
             "%-15A %1d %5d %7lu %7lu %s",
             bnp->bgp_addr,
             bnp->bgp_version ? bnp->bgp_version : bnp->bgp_conf_version,
             bnp->bgp_peer_as,
             bnp->bgp_in_updates + bnp->bgp_in_notupdates,
             bnp->bgp_out_updates + bnp->bgp_out_notupdates,
             trace_state(bgp_state_bits, bnp->bgp_state)));
      peer_count++;
    } BGP_PEER_LIST_END(bgp, bnp);
  } BGP_GROUP_LIST_END(bgp);
  return(gii_write(gii_ctl,
               GW_INFO,
               "BGP summary, %d %s, %d %s.",
               group_count, (group_count > 1)?"groups":"group",
               peer_count, (peer_count > 1)?"peers":"peer"));
#endif
}


 /* Print BGP peer information
 */
int
gii_showbgppeeras(gii_ctl, tokens, nbTok)
        gii_ctl_t *gii_ctl;
        char tokens[GIITOKENLEN][GIINBMAXTOKENS];
        int nbTok;
{
#ifndef PROTO_BGP
  return(GII_NOAVAILABLE);
#else
  register bgpPeerGroup *bgp;
  register bgpPeer *bnp;
  as_t peer_as;

  /* Parse the argument, which should be the peer autonomous system
   * number that we want to view.
   */
  if (nbTok != 1 || !(peer_as = atoi(tokens[0]))) {
    return(gii_write(gii_ctl, GW_ERR,
                 "Syntax error: show bgp peeras 1..65535"));
  }

  BGP_GROUP_LIST(bgp) {
    if (bgp->bgpg_peer_as == peer_as) {
      GII_WRITE((gii_ctl,
             GW_INFO,
             "%s flags <%s>",
             bgp->bgpg_name,
             trace_bits(bgp_group_flag_bits, bgp->bgpg_flags)));
      BGP_PEER_LIST(bgp, bnp) {
    GII_WRITE((gii_ctl,
              GW_INFO,
               " peer %A version %1d lcladdr %A gateway %A",
               bnp->bgp_addr,
               bnp->bgp_version ? bnp->bgp_version : bnp->bgp_conf_version,
               bnp->bgp_lcladdr,
               bnp->bgp_gateway));
    GII_WRITE((gii_ctl,
               GW_INFO,
               "  flags 0x%x",
               bnp->bgp_flags));
    GII_WRITE((gii_ctl,
               GW_INFO,
               "  state 0x%x <%s>",
               bnp->bgp_state,
               trace_state(bgp_state_bits, bnp->bgp_state)));
    GII_WRITE((gii_ctl,
                GW_INFO,
                "  options 0x%x <%s>",
                bnp->bgp_options,
                trace_bits(bgp_option_bits, bnp->bgp_options)));
 GII_WRITE((gii_ctl,
                GW_INFO,
                "  metric_out %d",
                bnp->bgp_metric_out));
     GII_WRITE((gii_ctl,
                GW_INFO,
                "  preference %d",
                bnp->bgp_preference));
     GII_WRITE((gii_ctl,
                GW_INFO,
                "  preference2 %d",
                bnp->bgp_preference2));
     GII_WRITE((gii_ctl,
                GW_INFO,
                "  recv buffer size %d",
                bnp->bgp_recv_bufsize));
     GII_WRITE((gii_ctl,
                GW_INFO,
                "  send buffer size %d",
                bnp->bgp_send_bufsize));
     GII_WRITE((gii_ctl,
                GW_INFO,
                "  messages in %lu (updates %lu, not updates %lu) %lu octets",
                bnp->bgp_in_updates + bnp->bgp_in_notupdates,
                bnp->bgp_in_updates,
                bnp->bgp_in_notupdates,
                bnp->bgp_in_octets));
     GII_WRITE((gii_ctl,
                GW_INFO,
                "  messages out %lu (updates %lu, not updates %lu) %lu octets",
                bnp->bgp_out_updates + bnp->bgp_out_notupdates,
                bnp->bgp_out_updates,
                bnp->bgp_out_notupdates,
                bnp->bgp_out_octets));
       } BGP_PEER_LIST_END(bgp, bnp);
     }
   } BGP_GROUP_LIST_END(bgp);
   return(0);
#endif
}





/* Reset all command processing and print a prompt. If a job is running,
 * we do not print anything.
 */
int
gii_prompt(gii_ctl)
	gii_ctl_t *gii_ctl;
{
	gii_ctl->g_cmdmenu = giicmd_top;
	gii_ctl->g_cmd = NULL;

	if (gii_ctl->g_state == GIIS_SESSION)
		return(gii_write(gii_ctl, GW_NONE, GIIPROMPT, task_hostname));

	return(0);
}

/* Get rid of all telnet out of band comand. Also get rid of any '0' which
 * may screw up the processing of the strings later on.
 */
void
telnet_strip(ln, len)
	char *ln;
	int *len;
{
	char *c;
	int left;

	for(c = ln, left = *len; left; c++, left--) {
		switch((unsigned char)*c) {
		case IAC:
			/* Get rid of the telnet option
			 */
			if (left < 3)
				break;
			(void)bcopy(c + 3, c, left - 3);
			c--;
			left -= 2;
			*len -= 3;
			break;
		case '\0':
			/* Get rid of it
			 */
			(void)bcopy(c + 1, c, left - 1);
			c--;
			*len -= 1;
			break;
		default:
			break;
		}
	}
}

/* Turn off/on telnet echo at the other end
 */
int
telnet_echooff(gii_ctl)
	gii_ctl_t *gii_ctl;
{
	static u_char buff[] = { IAC, WILL, TELOPT_ECHO, '\0' };

	return(gii_write(gii_ctl, GW_NONE, (char *) buff));
}

int
telnet_echoon(gii_ctl)
        gii_ctl_t *gii_ctl;
{
        static u_char buff[] = { IAC, WONT, TELOPT_ECHO, '\0' };

        return(gii_write(gii_ctl, GW_NONE, (char *) buff));
}

int
gii_showkernel(gii_ctl)
        gii_ctl_t *gii_ctl;
{
	
	if (gii_write(gii_ctl, GW_INFO, "Kernel options: <%s> Support: <%s>",
			trace_bits(kernel_option_bits, krt_options),
			trace_bits(kernel_support_bits, krt_rt_support)))
		return(1);
	if (gii_write(gii_ctl, GW_INFO, "IP forwarding: %d UDP checksums %d",
			inet_ipforwarding, inet_udpcksum))
		return(1);
	if (gii_write(gii_ctl, GW_INFO, "The time is %T", time_sec))
                return(1);
	return(0);
}

/* Print interface info. First parameter is the interface name or index
 */
int
gii_showif(gii_ctl, tokens, nbTok)
	gii_ctl_t *gii_ctl;
	char tokens[GIITOKENLEN][GIINBMAXTOKENS];
	int nbTok;
{
	if_link *ifl;
	if_addr *ifap;
	int proto;

	assert(nbTok);

	/* We care about the first interface name
	 */
	if (nbTok > 1)
		return(gii_write(gii_ctl, GW_ERR,
		"Syntax error (Syntax: show interface [name|index])"));

	/* Try with the name first...
	 */
	if (!(ifl = ifl_locate_name(tokens[0], strlen(tokens[0]))) &&
			!(ifl = ifl_locate_index(atoi(tokens[0]))))
		return(gii_write(gii_ctl, GW_ERR, "%s: No such interface",
			tokens[0]));

	/* Print the full dump of an interface. All from if_dump().
	 */
	GII_WRITE((gii_ctl, GW_INFO, "%s\tIndex %u%s%A",
		ifl->ifl_name, ifl->ifl_index,
		ifl->ifl_addr ? " Address ":" ",
		ifl->ifl_addr ? ifl->ifl_addr : sockbuild_str("")));
	GII_WRITE((gii_ctl, GW_INFO, "\tChange: <%s>\tState: <%s>",
		trace_bits(if_change_bits, ifl->ifl_change),
		trace_bits(if_state_bits, ifl->ifl_state)));
	GII_WRITE((gii_ctl, GW_INFO, "\tRefcount: %d\tUp-down transitions: %u",
		ifl->ifl_refcount, ifl->ifl_transitions));

	IF_ADDR(ifap) {
		if (ifap->ifa_link != ifl)
			continue;

		GII_WRITE((gii_ctl, GW_INFO,
			"\t%s %A\tMetric: %d\tMTU: %d",
			trace_value(task_domain_bits, socktype(IFA_UNIQUE_ADDR(ifap))),
			IFA_UNIQUE_ADDR(ifap), ifap->ifa_metric,
			ifap->ifa_mtu));
		GII_WRITE((gii_ctl, GW_INFO,
			"\t\tRefcount: %d\tPreference: %d\tDown: %d",
			ifap->ifa_refcount, ifap->ifa_preference,
			ifap->ifa_preference_down));
		GII_WRITE((gii_ctl, GW_INFO,
			"\t\tChange: <%s>\tState: <%s>",
			trace_bits(if_change_bits, ifap->ifa_change),
			trace_bits(if_state_bits, ifap->ifa_state)));
		GII_WRITE((gii_ctl, GW_INFO,
			"\t\tBroadcast Address: %A\tLocal %A",
			ifap->ifa_addr_broadcast? ifap->ifa_addr_broadcast:
				sockbuild_str(""),
			ifap->ifa_addr_local? ifap->ifa_addr_local:
				sockbuild_str("")));
		GII_WRITE((gii_ctl, GW_INFO,
			"\t\tSubnet Number: %A\tSubnet Mask: %A",
			ifap->ifa_addr_remote? ifap->ifa_addr_remote: sockbuild_str(""),
			ifap->ifa_netmask?ifap->ifa_netmask:sockbuild_str("")));
		GII_WRITE((gii_ctl, GW_INFO,
			"\t\tRoute %A - %A",
			ifap->ifa_rt? ifap->ifa_rt->rt_dest:
				sockbuild_str("<NONE>"),
			ifap->ifa_rt? ifap->ifa_rt->rt_dest_mask:
				sockbuild_str("<NONE>")));

#ifdef  PROTO_ASPATHS
		GII_WRITE((gii_ctl, GW_INFO, "\t\tAutonomous System: %u",
			ifap->ifa_as));
#endif  /* PROTO_ASPATHS */

		GII_WRITE((gii_ctl, GW_INFO,
			"\t\tRouting protocols active: %s",
			trace_state_all(ifap->ifa_rtactive)));

		for (proto = 0; proto < RTPROTO_MAX; proto++) {
			struct ifa_ps *ips = &ifap->ifa_ps[proto];

			if (!BIT_TEST(ifap->ifa_rtactive, RTPROTO_BIT(proto)))
				continue;
			GII_WRITE((gii_ctl, GW_INFO,
		"\t\tproto: %-6.6s Metricin: %-3u Metricout: %-3u State: <%s>",
				trace_state(rt_proto_bits, proto),
				ips->ips_metric_in, ips->ips_metric_out,
				trace_bits2(if_proto_bits, int_ps_bits[proto],
					ips->ips_state)));
		}
	} IF_ADDR_END(ifap);

	return(0);
}

char *
trace_state_all(proto)
	flag_t proto;
{
	int i = RTPROTO_MAX;
	static char lbuff[BUFSIZ] = { '\0' };

        while (i--)
                if (BIT_TEST(proto, RTPROTO_BIT(i))) {
			(void)strcat(lbuff, " ");
			(void)strcat(lbuff, trace_state(rt_proto_bits, i));
		};
	return(lbuff);
}

/* Print a list of all available interfaces.
 */
int
gii_showallif(gii_ctl)
        gii_ctl_t *gii_ctl;
{
	if_link *ifl;
	if_addr *ifap;

	GII_WRITE((gii_ctl, GW_INFO,
		"#ind name     address         mtu       flags"));

	IF_LINK(ifl) {

		IF_ADDR(ifap) {

			if (ifap->ifa_link != ifl)
				continue;

			GII_WRITE((gii_ctl, GW_INFO,
				"#%-3u %-8s %-15A %4d/%-4d %s",
				ifl->ifl_index, ifl->ifl_name,
				IFA_UNIQUE_ADDR(ifap),
				ifl->ifl_mtu, ifap->ifa_mtu,
				trace_bits(if_state_bits, ifl->ifl_state)));

		} IF_ADDR_END(ifap);

	} IF_LINK_END(ifl);

	return(0);
}


/* Show memory allocation.
 */
int
gii_showmem(gii_ctl)
        gii_ctl_t *gii_ctl;
{
	int freemem = 0, used = 0;
	struct task_size_block *tsb = task_block_head.tsb_forw;

	GII_WRITE((gii_ctl, GW_INFO, "Allocation size: %5d",
		task_pagesize));

	GII_WRITE((gii_ctl, GW_INFO,
   "Bck Size Free   Block Name        Init   Alloc  Free   InUse  (bytes)"));
/*0    12345 123456 1234567890123456  123456 123456 123456 123456 ()*/

	do {
		struct task_block *tbp = &tsb->tsb_block;

		freemem += tsb->tsb_size * tsb->tsb_n_free;

		do {
			GII_WRITE((gii_ctl, GW_INFO,
			"   %-5u %-6u %-16.16s  %-6u %-6u %-6u %-6u (%d)",
				tsb->tsb_size, tsb->tsb_n_free,
				tbp->tb_name, tbp->tb_n_init,
				tbp->tb_n_alloc, tbp->tb_n_free,
				tbp->tb_n_alloc - tbp->tb_n_free,
				(tbp->tb_n_alloc - tbp->tb_n_free)
					* tsb->tsb_size));
			/*freemem += tbp->tb_n_free * tsb->tsb_size;*/
			used += (tbp->tb_n_alloc - tbp->tb_n_free)
				* tsb->tsb_size;
		} while ((tbp = tbp->tb_next));
	} while ((tsb = tsb->tsb_forw) != &task_block_head);

	GII_WRITE((gii_ctl, GW_INFO,
		"Total Memory: %-9d Total Free: %-9d Total Allocated: %-9d",
		freemem + used, freemem, used));

	return(0);
}

int
gii_showrtip(gii_ctl, tokens, nbTok)
        gii_ctl_t *gii_ctl;
        char tokens[GIITOKENLEN][GIINBMAXTOKENS];
        int nbTok;
{
	int i, nbHop, count;
	rt_head *rth;
	rt_entry *rt;
	sockaddr_un *addr, *mask;
	char active, lbuff[BUFSIZ];
	char lbuff2[BUFSIZ];
	
	/* The only argument should be an ip address in the format
	 * X.X.X.X/len
	 */
	if (nbTok != 1 || (sockstr(tokens[0], &addr, &mask)))
		return(gii_write(gii_ctl, GW_ERR,
			"Syntax error: show route ip [x.x.x.x/len]"));

	/* find and print the route
	 */
	if (!(rth = rt_table_locate(addr, mask)))
		return(gii_write(gii_ctl, GW_ERR,
			"No IP route %A mask %A", addr, mask));

	GII_WRITE((gii_ctl, GW_INFO,
		"Route %A - %A entries %d Announced %d Depth %d <%s>",
		rth->rth_dest, rth->rth_dest_mask, rth->rth_entries,
		rth->rth_n_announce, rth->rth_aggregate_depth,
		trace_bits(rt_state_bits, rth->rth_state)));

	GII_WRITE((gii_ctl, GW_INFO,
  "  Proto Next Hop        Source Gwt      Preference/2 Metric/2 etc..."));
/*"* OSPF 192.168.10.100  192.168.10.100  1/0     0        17:15:22 IGP (Id 1) <Int Active Gateway> */

	/* Print all sources,
	 */
	RT_ALLRT(rt, rth) {
		if (rt == rth->rth_rib_active[RIB_UNICAST] && rt == rth->rth_rib_last_active[RIB_UNICAST])
			active = '*';
		else if (rt == rth->rth_rib_active[RIB_UNICAST])
			active = '+';
		else if (rt == rth->rth_rib_last_active[RIB_UNICAST])
			active = '-';
		else
			active = ' ';

		/* by next hop... We force at least 'one' next hop.
		 */
		nbHop = rt->rt_n_gw? rt->rt_n_gw: 1;
		count = 0;
		for (i = 0; i < nbHop; i++) {
			/* ... and protocol. We force at least 'one' proto.
			 */
			(void)sprintf(lbuff2, "%d/%d", rt->rt_preference,
				rt->rt_preference2);
			(void)sprintf(lbuff, "%d/%d", rt->rt_metric,
				rt->rt_metric2);

			GII_WRITE((gii_ctl, GW_INFO,
			"%c %-5.5s %-15A %-15A %-7s %-13s %-8X %8T %s <%s>",
				(!count++)? active: '|',
				(rt->rt_gwp)? trace_state(rt_proto_bits,
					rt->rt_gwp->gw_proto): "---",
/*
		(!rt->rt_n_bitsset)? "---":
		task_name(rtbit_map[proto-1].rtb_task),
 */
				(rt->rt_routers[i])? rt->rt_routers[i]:
					sockbuild_str("---"),
				(rt->rt_gwp && rt->rt_gwp->gw_addr)?
					rt->rt_gwp->gw_addr:
						 sockbuild_str("---"),
				lbuff2, lbuff,
				rt->rt_tag,
				rt_age(rt),
				aspath_str(rt->rt_aspath),
				trace_bits(rt_state_bits, rt->rt_state)
				));
					
/** STA 12.67.01.34 23.57.01.35 13/57 00 12:45:67 AS34 AS1800 IGP <Retain>*/


		}
	} RT_ALLRT_END(rt, rth);

	return(0);
}

/* display info about the IP route radix tree
 */
int
gii_showrtipall(gii_ctl)
        gii_ctl_t *gii_ctl;
{
	GII_WRITE((gii_ctl, GW_INFO,
		"IP radix tree: %d nodes, %d routes",
		rt_table_nodes(AF_INET), rt_table_routes(AF_INET)));
		
	return(0);
}

int
gii_showalltask(gii_ctl)
        gii_ctl_t *gii_ctl;
{
	task *tp;

	TASK_TABLE(tp) {

		GII_WRITE((gii_ctl, GW_INFO,
			"%-10.10s %-3d %-3d %-15A %-4d %2d <%s - %s>",
			tp->task_name, tp->task_proto, 
			tp->task_priority, 
			(tp->task_addr)? tp->task_addr: sockbuild_str("---"),
			(tp->task_addr)? ntohs(sock2port(tp->task_addr)): -1,
			tp->task_socket,
			trace_state(rt_proto_bits, tp->task_rtproto),
			trace_bits(task_flag_bits, tp->task_flags)));

	} TASK_TABLE_END(tp);

	return(0);
}

#define GII_TIMER_DUMP(tip, tpname) do { \
	GII_WRITE((gii_ctl, GW_INFO, \
	"%-20.20s %-8.8s %02d:%02ds %02d:%02ds %02d:%02ds %02d:%02ds <%s>", \
		(tip)->task_timer_name, tpname, \
		BIT_TEST(tip->task_timer_flags, TIMERF_ONESHOT)? 0: \
			(time_sec - tip->task_timer_last_time) / 60, \
		BIT_TEST(tip->task_timer_flags, TIMERF_ONESHOT)? 0: \
			(time_sec - tip->task_timer_last_time) % 60, \
		BIT_TEST(tip->task_timer_flags, TIMERF_INACTIVE)? 0: \
			(tip->task_timer_next_time - time_sec) / 60, \
		BIT_TEST(tip->task_timer_flags, TIMERF_INACTIVE)? 0: \
			(tip->task_timer_next_time - time_sec) % 60, \
		tip->task_timer_interval /60, tip->task_timer_interval % 60, \
		tip->task_timer_jitter /60, tip->task_timer_jitter % 60, \
		trace_bits(task_timer_flag_bits, tip->task_timer_flags))); \
} while(0)

/* Show all timers defined in gated.
 */
int
gii_showalltimer(gii_ctl)
        gii_ctl_t *gii_ctl;
{
	task *tp;
	task_timer *tip;

	GII_WRITE((gii_ctl, GW_INFO,
"Name                           Task     Last   Next   Intrvl Jitter flags"));

	/* Timer are listed per task.
	 */
	TASK_TABLE(tp) {
		for (tip = tp->task_timers; tip; tip = tip->task_timer_next)
			GII_TIMER_DUMP(tip, tp->task_name);

	} TASK_TABLE_END(tp);

	/* and are also global!
	 */
	for (tip = task_head.task_timers; tip; tip = tip->task_timer_next)
		GII_TIMER_DUMP(tip, "GLOBAL");

	return(0);
}

int
gii_showipup(gii_ctl, tokens, nbTok)
        gii_ctl_t *gii_ctl;
        char tokens[GIITOKENLEN][GIINBMAXTOKENS];
        int nbTok;
{
	sockaddr_un *addr, *mask;
	rt_head *rth;

	/* The only argument should be an ip address in the format
	 * X.X.X.X/len
	 */
	if (nbTok != 1 || (sockstr(tokens[0], &addr, &mask)))
                return(gii_write(gii_ctl, GW_ERR,
                        "Syntax error: show route ip [x.x.x.x/len]"));

	/* find and print the route
         */
	if (!(rth = rt_walk_start(addr, mask, RTW_UP)))
		return(gii_write(gii_ctl, GW_ERR,
			"No less specific IP route %A mask %A", addr, mask));

	/* No we create a job to walk up the tree. Everytime the job
	 * is dispatched, one route is printed.
	 */
	gii_ctl->g_walk = rt_walk_alloc();
	gii_ctl->g_walk->rw_rth = rth;
	gii_ctl->g_walk->rw_way = RTW_UP;
	gii_ctl->g_walk->rw_len = mask_bits(mask);
	assert(!gii_ctl->g_job);
	gii_ctl->g_job = task_job_create(gii_ctl->g_task, TASK_JOB_PRIO_WORST,
		"GII_WALKUP", gii_job_walk, (void_t)gii_ctl);
	gii_ctl->g_state = GIIS_JOB;
	return(0);
}

/* Print all more specific routes.
 */
int
gii_showipdown(gii_ctl, tokens, nbTok)
        gii_ctl_t *gii_ctl;
        char tokens[GIITOKENLEN][GIINBMAXTOKENS];
        int nbTok;
{
        sockaddr_un *addr, *mask;
        rt_head *rth;

        /* The only argument should be an ip address in the format
         * X.X.X.X/len
         */
        if (nbTok != 1 || (sockstr(tokens[0], &addr, &mask)))
                return(gii_write(gii_ctl, GW_ERR,
                        "Syntax error: show route ip [x.x.x.x/len]"));

        /* find and print the route
         */
        if (!(rth = rt_walk_start(addr, mask, RTW_DOWN)))
                return(gii_write(gii_ctl, GW_ERR,
                        "No more specific IP route %A mask %A", addr, mask));

        /* No we create a job to walk up the tree. Everytime the job
         * is dispatched, one route is printed.
         */
        gii_ctl->g_walk = rt_walk_alloc();
        gii_ctl->g_walk->rw_rth = rth;
        gii_ctl->g_walk->rw_way = RTW_DOWN;
        gii_ctl->g_walk->rw_len = mask_bits(mask);
        assert(!gii_ctl->g_job);
        gii_ctl->g_job = task_job_create(gii_ctl->g_task, TASK_JOB_PRIO_WORST,
                "GII_WALKDOWN", gii_job_walk, (void_t)gii_ctl);
        gii_ctl->g_state = GIIS_JOB;
        return(0);
}

#define RTWALK_BULK	10
void
gii_job_walk (task_job * tjp)
{
	gii_ctl_t *gii_ctl;
	rt_head *rth;
	int ind;

	gii_ctl = (gii_ctl_t *)tjp->task_job_data;

	/* We print a bulk of routes, then exit.
	 */
	for(ind = 0; ind < RTWALK_BULK; ind++) {
		/* Are we at the end of the tree? Then delete the job & data.
	 	 */
		if (!(rth = gii_ctl->g_walk->rw_rth)) {
			gii_ctl->g_walk = rt_walk_free(gii_ctl->g_walk);
			task_job_delete(gii_ctl->g_job);
			gii_ctl->g_job = NULL;
			gii_ctl->g_state = GIIS_SESSION;
			gii_prompt(gii_ctl);
			return;
		}

		/* Print the route
	 	 */
		if (gii_write(gii_ctl, GW_INFO,
			"%-3.3s %15A/%-2d %-15A %s",
			(rth->rth_rib_active[RIB_UNICAST] && rth->rth_rib_active[RIB_UNICAST]->rt_gwp)?
				trace_state(rt_proto_bits,
					rth->rth_rib_active[RIB_UNICAST]->rt_gwp->gw_proto):
				"---",
			rth->rth_dest,
			mask_bits(rth->rth_dest_mask),
			(rth->rth_rib_active[RIB_UNICAST] && rth->rth_rib_active[RIB_UNICAST]->rt_routers[0])?
				rth->rth_rib_active[RIB_UNICAST]->rt_routers[0]:
				sockbuild_str("---"),
				(rth->rth_rib_active[RIB_UNICAST] && rth->rth_rib_active[RIB_UNICAST]->rt_aspath)?
				aspath_str(rth->rth_rib_active[RIB_UNICAST]->rt_aspath): "")) {
			gii_terminate(gii_ctl->g_task);
			return;
		}
	
		/* Get the next one...
	 	 */
		gii_ctl->g_walk->rw_rth = rt_walk(gii_ctl->g_walk);
	}
}

int  gii_showbgpcidronly(gii_ctl, tokens, nbTok)
       gii_ctl_t *gii_ctl;
       char tokens[GIITOKENLEN][GIINBMAXTOKENS] UNUSED;
        int nbTok UNUSED;
{
#ifndef PROTO_BGP
  return(GII_NOAVAILABLE);
#else

	sockaddr_un *addr, *mask;
        rt_head *rth_top;

	sockstr("default", &addr, &mask);

	GII_WRITE((gii_ctl,
        GW_INFO,
        "%-11s %-10s %-15s %-5s %-20s %-10s",
        "Proto",
        "Route/Mask",
        "NextHop",
	"MED",
        "ASPath",
	"Communities"));

        /* find and print the route
         */
        if (!(rth_top = rt_walk_start(addr, mask, RTW_DOWN)))
                return(gii_write(gii_ctl, GW_ERR,
                        "No more specific IP route %A mask %A", addr, mask));

        gii_ctl->g_walk = rt_walk_alloc();
        gii_ctl->g_walk->rw_rth = rth_top;
	gii_ctl->g_walk->rw_way = RTW_DOWN;
        gii_ctl->g_walk->rw_len = mask_bits(mask);

	gii_ctl->g_job = task_job_create(gii_ctl->g_task, 
                             TASK_JOB_PRIO_WORST,
                             "GII_WALK_BGP",
                              gii_job_walk_bgp_cidr,
                             (void_t)gii_ctl);

	gii_ctl->g_state = GIIS_JOB;
	return(0);
#endif
}

int gii_showbgpexpression(gii_ctl, tokens, nbTok)
       gii_ctl_t *gii_ctl;
       char tokens[GIITOKENLEN][GIINBMAXTOKENS] UNUSED;
        int nbTok UNUSED;
{
	return(0);
}

 
int gii_showbgpinconsistent(gii_ctl, tokens, nbTok)
       gii_ctl_t *gii_ctl;
       char tokens[GIITOKENLEN][GIINBMAXTOKENS] UNUSED;
        int nbTok UNUSED;

{
	  return(0);
}


int  gii_showbgppeergroup(gii_ctl, tokens, nbTok)
       gii_ctl_t *gii_ctl;
       char tokens[GIITOKENLEN][GIINBMAXTOKENS] UNUSED;
        int nbTok UNUSED;

{
#ifndef PROTO_BGP
  return(GII_NOAVAILABLE);
#else
  register bgpPeerGroup *bgp;
  register bgpPeer *bnp;
  register int peer_count = 0;

	if( ( nbTok != 1 ) ) {
		 return(gii_write(gii_ctl, GW_ERR,
				"Syntax error: show bgp peer-group [internal|external|internal_igp|routing|test]"));
	}
	
  GII_WRITE((gii_ctl,
         GW_INFO,
         "%-8s %-15s %1s %5s %7s %7s %s",
         "Group",
         "Neighbor",
         "V",
         "AS",
         "MsgRcvd",
         "MsgSent",
         "State"));
  BGP_GROUP_LIST(bgp) {
	if( ((u_int)(GII_STR2GROUP(tokens[0]))) == bgp->bgpg_type ) {
		BGP_PEER_LIST(bgp, bnp) {
			GII_WRITE((gii_ctl,
		        GW_INFO,
             		"%s %-15A %1d %5d %7lu %7lu %s",
		 	GII_GROUP2STR(bgp->bgpg_type),	
             		bnp->bgp_addr,
             		bnp->bgp_version ? bnp->bgp_version : bnp->bgp_conf_version,
             		bnp->bgp_peer_as,
             		bnp->bgp_in_updates + bnp->bgp_in_notupdates,
             		bnp->bgp_out_updates + bnp->bgp_out_notupdates,
             		trace_state(bgp_state_bits, bnp->bgp_state)));
      			peer_count++;
    		} BGP_PEER_LIST_END(bgp, bnp);
	}
  } BGP_GROUP_LIST_END(bgp);
  return(gii_write(gii_ctl,
               GW_INFO,
               "BGP summary, %d peers in group type \"%s\"",
               peer_count, tokens[0]));
#endif

}


int  gii_showbgproutes(gii_ctl, tokens, nbTok)
       gii_ctl_t *gii_ctl;
       char tokens[GIITOKENLEN][GIINBMAXTOKENS] UNUSED;
        int nbTok UNUSED;
{

#ifndef PROTO_BGP
  return(GII_NOAVAILABLE);
#else

	sockaddr_un *addr, *mask;
        rt_head *rth_top;

	if (nbTok == 0) {
		sockstr("default", &addr, &mask);
	}
	else {  
     	   if (nbTok != 1 || (sockstr(tokens[0], &addr, &mask)))
                return(gii_write(gii_ctl, GW_ERR,
                        "Syntax error: show bgp route [network | network-mask]"));
	}

	GII_WRITE((gii_ctl,
        GW_INFO,
        "%-11s %-10s %-15s %-5s %-20s",
        "Proto",
        "Route/Mask",
        "NextHop",
	"MED",
        "ASPath"));

        /* find and print the route
         */
        if (!(rth_top = rt_walk_start(addr, mask, RTW_DOWN)))
                return(gii_write(gii_ctl, GW_ERR,
                        "No more specific IP route %A mask %A", addr, mask));

        gii_ctl->g_walk = rt_walk_alloc();
        gii_ctl->g_walk->rw_rth = rth_top;
	gii_ctl->g_walk->rw_way = RTW_DOWN;
        gii_ctl->g_walk->rw_len = mask_bits(mask);

	gii_ctl->g_job = task_job_create(gii_ctl->g_task, 
                             TASK_JOB_PRIO_WORST,
                             "GII_WALK_BGP",
                              gii_job_walk_bgp,
                             (void_t)gii_ctl);

	gii_ctl->g_state = GIIS_JOB;
	return(0);
#endif
}


void
gii_job_walk_bgp (task_job * tjp)
{
	gii_ctl_t *gii_ctl;
	rt_head *rth;
	int ind;

	gii_ctl = (gii_ctl_t *)tjp->task_job_data;
	/*
	 *  Print RTWALK_BULK of routes that we've learned
	 *  via BGP.
	 */

        for(ind = 0; ind < RTWALK_BULK; ind++) {
                /* Are we at the end of the tree? Then delete the job & data.
                 */
                if (!(rth = gii_ctl->g_walk->rw_rth)) {
                        gii_ctl->g_walk = rt_walk_free(gii_ctl->g_walk);
                        task_job_delete(gii_ctl->g_job);
                        gii_ctl->g_job = NULL;
                        gii_ctl->g_state = GIIS_SESSION;
                        gii_prompt(gii_ctl);
                        return;
                }
		/* naamato XXX may be too paranoid here
		 * RIPv1 routes don't set rth->rth_rib_active[RIB_UNICAST]
		 */
		if( (rth->rth_rib_active[RIB_UNICAST]) && (rth->rth_rib_active[RIB_UNICAST]->rt_gwp) && (rth->rth_rib_active[RIB_UNICAST]->rt_gwp->gw_proto == RTPROTO_BGP)) {
                	if (gii_write(gii_ctl, GW_INFO,
                       		"%-3.3s %15A/%-2d %-15A %-5d %s",
                        	(rth->rth_rib_active[RIB_UNICAST] && rth->rth_rib_active[RIB_UNICAST]->rt_gwp)?
                                trace_state(rt_proto_bits,
                                        rth->rth_rib_active[RIB_UNICAST]->rt_gwp->gw_proto):
                                "---",
                        	rth->rth_dest,
                        	mask_bits(rth->rth_dest_mask),
                        	(rth->rth_rib_active[RIB_UNICAST] && rth->rth_rib_active[RIB_UNICAST]->rt_routers[0])?
                                rth->rth_rib_active[RIB_UNICAST]->rt_routers[0]:
                                sockbuild_str("---"),
				rth->rth_rib_active[RIB_UNICAST]->rt_metric,
                                (rth->rth_rib_active[RIB_UNICAST] && rth->rth_rib_active[RIB_UNICAST]->rt_aspath)?
                                (aspath_str(rth->rth_rib_active[RIB_UNICAST]->rt_aspath)):"")) {
                        		gii_terminate(gii_ctl->g_task);
                        		return;
                	}
		}
                /* Get the next one...
                 */
                gii_ctl->g_walk->rw_rth = rt_walk(gii_ctl->g_walk);
        }
}



void
gii_job_walk_bgp_cidr (task_job * tjp)
{
	gii_ctl_t *gii_ctl;
	rt_head *rth;
	int ind;

	gii_ctl = (gii_ctl_t *)tjp->task_job_data;
	/*
	 *  Print RTWALK_BULK of routes that we've learned
	 *  via BGP that have non byte-aligned masks (CIDR).
	 */

        for(ind = 0; ind < RTWALK_BULK; ind++) {
                /* Are we at the end of the tree? Then delete the job & data.
                 */
                if (!(rth = gii_ctl->g_walk->rw_rth)) {
                        gii_ctl->g_walk = rt_walk_free(gii_ctl->g_walk);
                        task_job_delete(gii_ctl->g_job);
                        gii_ctl->g_job = NULL;
                        gii_ctl->g_state = GIIS_SESSION;
                        gii_prompt(gii_ctl);
                        return;
                }
		/* naamato XXX may be too paranoid here
		 * RIPv1 routes don't set rth->rth_rib_active[RIB_UNICAST]
		 */
		if( (rth->rth_rib_active[RIB_UNICAST]) && (rth->rth_rib_active[RIB_UNICAST]->rt_gwp) && (rth->rth_rib_active[RIB_UNICAST]->rt_gwp->gw_proto == RTPROTO_BGP) && (GII_ISCIDR(rth->rth_dest_mask))) {
                	if (gii_write(gii_ctl, GW_INFO,
                       		"%-3.3s %15A/%-2d %-15A %-5d %s %s",
                        	(rth->rth_rib_active[RIB_UNICAST] && rth->rth_rib_active[RIB_UNICAST]->rt_gwp)?
                                trace_state(rt_proto_bits,
                                        rth->rth_rib_active[RIB_UNICAST]->rt_gwp->gw_proto):
                                "---",
                        	rth->rth_dest,
                        	mask_bits(rth->rth_dest_mask),
                        	(rth->rth_rib_active[RIB_UNICAST] && rth->rth_rib_active[RIB_UNICAST]->rt_routers[0])?
                                rth->rth_rib_active[RIB_UNICAST]->rt_routers[0]:
                                sockbuild_str("---"),
				rth->rth_rib_active[RIB_UNICAST]->rt_metric,
                                (rth->rth_rib_active[RIB_UNICAST] && rth->rth_rib_active[RIB_UNICAST]->rt_aspath)?
                                (aspath_str(rth->rth_rib_active[RIB_UNICAST]->rt_aspath)):"")) {
                        		gii_terminate(gii_ctl->g_task);
                        		return;
                	}
		}
                /* Get the next one...
                 */
                gii_ctl->g_walk->rw_rth = rt_walk(gii_ctl->g_walk);
        }
}

int
gii_showriproutes(gii_ctl, tokens, nbTok)
       gii_ctl_t *gii_ctl;
       char tokens[GIITOKENLEN][GIINBMAXTOKENS] UNUSED;
       int nbTok UNUSED;
{

#ifndef PROTO_RIP
	return(GII_NOAVAILABLE);
#else
	sockaddr_un *addr, *mask;
	rt_head *rth_top;

	if (nbTok == 0) {
	  sockstr("default", &addr, &mask);
	}

	else {
	if (nbTok != 1 || (sockstr(tokens[0], &addr, &mask)))
		return(gii_write(gii_ctl, GW_ERR,
		"Syntax error: show bgp route [network | network-mask]"));
	}

	GII_WRITE((gii_ctl,
        GW_INFO,
        "%-11s %-10s %-15s %-4s",
        "Proto",
        "Route/Mask",
        "NextHop",
	"Tag"));

	if (!(rth_top = rt_walk_start(addr, mask, RTW_DOWN)))
		return(gii_write(gii_ctl, GW_ERR,
		"No more specific IP route %A mask %A", addr, mask));

	gii_ctl->g_walk = rt_walk_alloc();
	gii_ctl->g_walk->rw_rth = rth_top;
	gii_ctl->g_walk->rw_way = RTW_DOWN;
	gii_ctl->g_walk->rw_len = mask_bits(mask);

	/* create a job to walk the radix tree and print 
	 * routes learned via RIP.
	 */
        gii_ctl->g_job = task_job_create(gii_ctl->g_task,
                             TASK_JOB_PRIO_WORST,
                             "GII_WALK_BGP",
                              gii_job_walk_rip,
                             (void_t)gii_ctl);
        gii_ctl->g_state = GIIS_JOB;
        return(0);
#endif
}

void
gii_job_walk_rip (task_job * tjp)
{
	gii_ctl_t *gii_ctl;
	rt_head *rth;
	int ind;

	gii_ctl = (gii_ctl_t *)tjp->task_job_data;

	/*
	 *  Print RTWALK_BULK of routes that we've learned
	 *  via RIP.
	 */

        for(ind = 0; ind < RTWALK_BULK; ind++) {

                /* Are we at the end of the tree? Then delete the job & data.
                 */
                if (!(rth = gii_ctl->g_walk->rw_rth)) {
                        gii_ctl->g_walk = rt_walk_free(gii_ctl->g_walk);
                        task_job_delete(gii_ctl->g_job);
                        gii_ctl->g_job = NULL;
                        gii_ctl->g_state = GIIS_SESSION;
                        gii_prompt(gii_ctl);
                        return;
                }


		if( !(rth->rth_rib_active[RIB_UNICAST]) || (rth->rth_rib_active[RIB_UNICAST]->rt_gwp->gw_proto == RTPROTO_RIP)) {
                	if (gii_write(gii_ctl, GW_INFO,
                       		"%-3.3s %15A/%-2d %-15A %3d",
                        	(rth->rth_rib_active[RIB_UNICAST] && rth->rth_rib_active[RIB_UNICAST]->rt_gwp)?
                                trace_state(rt_proto_bits,
                                        rth->rth_rib_active[RIB_UNICAST]->rt_gwp->gw_proto):
                                "RIP",
                        	rth->rth_dest,
                        	mask_bits(rth->rth_dest_mask),
                        	(rth->rth_rib_active[RIB_UNICAST] && rth->rth_rib_active[RIB_UNICAST]->rt_routers[0])?
                                rth->rth_rib_active[RIB_UNICAST]->rt_routers[0]:
				sockbuild_str("---"), 
				(rth->rth_rib_active[RIB_UNICAST])?
				rth->rth_rib_active[RIB_UNICAST]->rt_tag:0)) {
                        		gii_terminate(gii_ctl->g_task);
                        		return;
                	}
		}
                /* Get the next one...
                 */
                gii_ctl->g_walk->rw_rth = rt_walk(gii_ctl->g_walk);
        }
}

int
gii_showripsummary(gii_ctl, tokens, nbTok)
	gii_ctl_t *gii_ctl;
	char tokens[GIITOKENLEN][GIINBMAXTOKENS] UNUSED;
	int nbTok UNUSED;
{
#ifndef PROTO_RIP
	return(GII_NOAVAILABLE);
#else
	gw_entry *gwp;
	int gw_count = 0;

	GII_WRITE((gii_ctl, GW_INFO, "Gateway      LastHeard     Flags"));

	GW_LIST(rip_gw_list, gwp)
	{
		gw_count++;
		GII_WRITE((gii_ctl, GW_INFO,
			"%-15A %6d      %s%s%s%s%s%s",
			gwp->gw_addr,
			gwp->gw_time,
			(BIT_TEST(gwp->gw_flags, GWF_SOURCE))?"S":" ",
			(BIT_TEST(gwp->gw_flags, GWF_TRUSTED))?"T":" ",
			(BIT_TEST(gwp->gw_flags, GWF_ACCEPT))?"A":" ",
			(BIT_TEST(gwp->gw_flags, GWF_REJECT))?"R":" ",
			(BIT_TEST(gwp->gw_flags, GWF_QUERY))?"Q":" ",
			(BIT_TEST(gwp->gw_flags, GWF_AUTHFAIL))?"F":" "));

	}
	GII_WRITE((gii_ctl, GW_INFO,
		"RIP summary, %d %s",
		gw_count, (gw_count > 1)?"gateways.":"gateway."));

	GII_WRITE((gii_ctl, GW_INFO, "Flags:"));
	GII_WRITE((gii_ctl, GW_INFO, "S\tThis is a source gateway"));
	GII_WRITE((gii_ctl, GW_INFO, "T\tThis is a trusted gateway"));
	GII_WRITE((gii_ctl, GW_INFO, "A\tWe have accepted a packet from this gateway"));
	GII_WRITE((gii_ctl, GW_INFO, "R\tWe have rejected a packet from this gateway"));
	GII_WRITE((gii_ctl, GW_INFO, "Q\tWe have received a RIP query packet from this gateway"));
	GII_WRITE((gii_ctl, GW_INFO, "F\tThis gateway failed authentication"));

	return 0;
#endif
}


int
gii_showriptag(gii_ctl, tokens, nbTok)
	gii_ctl_t *gii_ctl;
	char tokens[GIITOKENLEN][GIINBMAXTOKENS] UNUSED;
	int nbTok UNUSED;
{
#ifndef PROTO_RIP
	return(GII_NOAVAILABLE);
#else
	metric_t gtag = 0;
	rt_head *rth_top;
	sockaddr_un *addr, *mask;

        sockstr("default", &addr, &mask);

	if( nbTok >= 1 ) {
		gtag = (metric_t) atol(tokens[0]);
	}

	GII_WRITE((gii_ctl,
        GW_INFO,
        "%-11s %-10s %-15s %-4s",
        "Proto",
        "Route/Mask",
        "NextHop",
	"Tag"));

	if (!(rth_top = rt_walk_start(addr, mask, RTW_DOWN)))
		return 0;

	gii_ctl->g_walk = rt_walk_alloc();
	gii_ctl->g_walk->rw_rth = rth_top;
	gii_ctl->g_walk->rw_way = RTW_DOWN;
	gii_ctl->g_walk->rw_len = mask_bits(mask);

	if( nbTok >= 1 ) {
		gii_ctl->g_tag = (metric_t) atol(tokens[0]);
        	gii_ctl->g_job = task_job_create(gii_ctl->g_task,
                             TASK_JOB_PRIO_WORST,
                             "GII_WALK_BGP",
                              gii_job_walk_rip_tag,
                             (void_t)gii_ctl);
        	gii_ctl->g_state = GIIS_JOB;
        	return(0);
	}

	/* just print routes, no argument given */
        gii_ctl->g_job = task_job_create(gii_ctl->g_task,
                            TASK_JOB_PRIO_WORST,
                            "GII_WALK_BGP",
                             gii_job_walk_rip,
                            (void_t)gii_ctl);
       	gii_ctl->g_state = GIIS_JOB;
#endif
	return(0);
}


#ifdef PROTO_RIP
void
gii_job_walk_rip_tag (task_job * tjp)
{
	gii_ctl_t *gii_ctl;
	rt_head *rth;
	metric_t tag = 0;
	int ind;

	gii_ctl = (gii_ctl_t *)tjp->task_job_data;
	tag = gii_ctl->g_tag;

	/*
	 *  Print RTWALK_BULK of routes that we've learned
	 *  via RIP.
	 */

        for(ind = 0; ind < RTWALK_BULK; ind++) {

                /* Are we at the end of the tree? Then delete the job & data.
                 */
                if (!(rth = gii_ctl->g_walk->rw_rth)) {
                        gii_ctl->g_walk = rt_walk_free(gii_ctl->g_walk);
                        task_job_delete(gii_ctl->g_job);
                        gii_ctl->g_job = NULL;
                        gii_ctl->g_state = GIIS_SESSION;
                        gii_prompt(gii_ctl);
                        return;
                }

		if( (!(rth->rth_rib_active[RIB_UNICAST]) || (rth->rth_rib_active[RIB_UNICAST]->rt_gwp->gw_proto == RTPROTO_RIP)) && (rth->rth_rib_active[RIB_UNICAST] && (rth->rth_rib_active[RIB_UNICAST]->rt_tag == tag))) {
                	if (gii_write(gii_ctl, GW_INFO,
                       		"%-3.3s %15A/%-2d %-15A %3d",
                        	(rth->rth_rib_active[RIB_UNICAST] && rth->rth_rib_active[RIB_UNICAST]->rt_gwp)?
                                trace_state(rt_proto_bits,
                                        rth->rth_rib_active[RIB_UNICAST]->rt_gwp->gw_proto):
                                "RIP",
                        	rth->rth_dest,
                        	mask_bits(rth->rth_dest_mask),
                        	(rth->rth_rib_active[RIB_UNICAST] && rth->rth_rib_active[RIB_UNICAST]->rt_routers[0])?
                                rth->rth_rib_active[RIB_UNICAST]->rt_routers[0]:
				sockbuild_str("---"), 
				(rth->rth_rib_active[RIB_UNICAST])?
				rth->rth_rib_active[RIB_UNICAST]->rt_tag:0)) {
                        		gii_terminate(gii_ctl->g_task);
                        		return;
                	}
		}
                /* Get the next one...
                 */
                gii_ctl->g_walk->rw_rth = rt_walk(gii_ctl->g_walk);
        }
}
#endif
