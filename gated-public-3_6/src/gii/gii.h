/*
 * Consortium Release 4
 * 
 * $Id: gii.h,v 1.3 2000/03/17 19:53:30 mrr Exp $
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

#define GIIMAXCMDLEN	BUFSIZ
#define GIIMAXLINELEN	GIIMAXCMDLEN
#define GIINBMAXTOKENS	30
#define GIITOKENLEN	80
#define GII_MAXTRIES	3

/* Some global flags
 */
#define GIIF_ON		1		/* GII is ON */

/* The structure to store the command names and the associated command
 * to execute.
 */
typedef struct _giimenu_cmd_t {
	const char *cmd_name;			/* Name of the command */
	struct _giimenu_cmd_t *cmd_nextCmdTable;	/* The subcommands */
	int (*cmd_lasttok)();		/* What to execute if there is no more
					 * token to read but the command
					 * need a subcommand (error) */
	int (*cmd_exec)();		/* What to execute if there is no
					 * subcommands */
	const char *cmd_helpMsg;	/* An explanation of the command */
} giimenu_cmd_t;


/* Internal state of a GII session
 */
typedef struct _gii_ctl_t {
	struct _gii_ctl_t *g_prev, *g_next;	/* Linked list */
	int g_state;			/* The state. C.f. GIIS_XXX */
	task *g_task;			/* Gated task for that session */
	giimenu_cmd_t *g_cmdmenu;	/* Current command menu */
	giimenu_cmd_t *g_cmd;		/* Current command in that menu */
	char g_cmdStr[GIIMAXCMDLEN];	/* The current parsed command */
	char g_buff[2*GIIMAXLINELEN];	/* Line buffer */
	int g_bufflen;			/* what is the buffer */
	int g_buffLeft;			/* what is left free */
	int g_iden_tries;		/* Number of identication tries */
	rtwalk_t *g_walk;		/* Used when walking the routing tabl */
	pathwalk_t *g_pathwalk;		/* used when walking aspaths */
	task_job *g_job;		/* Any pending job */
#ifdef PROTO_RIP
	metric_t g_tag;			/* for matching RIP tags */
#endif
#ifdef PROTO_BGP
	metric_t g_comm;		/* for matching BGP communities */
#endif
} gii_ctl_t;

/* State of a session
 */
#define GIIS_OPEN	0		/* Before authentication */
#define GIIS_SESSION	1		/* After auth. */
#define GIIS_JOB	2		/* A job is running... */
#define GII_LASTSTATE	2		/* The last one */

/* Default user name when authenticating
 */
#define GII_USER	"gii"
#define GIIPROMPT	"GateD-%s> "
#define GII_PORT	616

#define GIISTATESTR(state)	(((state) > GII_LASTSTATE)? "???": \
		gii_statenames[(state)])

/* Codes when printing messages
 */
#define GW_NONE		0		/* No code */
#define GW_ERR		5		/* An error message */
#define GW_INFO		1		/* An information message */

/* Strip any whierd character at the begining of a string
 */
#define STRIP(ln)	{ \
	char *c = ln + strlen(ln) - 1; \
	while(*(ln) == '\n' || *(ln) == '\r') (ln)++; \
	while(*c == '\n' || *c == '\r') *(c--) = '\0'; \
}

#ifdef PROTO_BGP

/* macros for bgp groups and cidr-only
 */

#define GII_GROUP2STR(a)     (a == BGPG_EXTERNAL)?\
                         ("external"):(a == BGPG_INTERNAL)?\
                         ("internal"):(a == BGPG_INTERNAL_IGP)?\
                         ("internal_igp"):(a == BGPG_INTERNAL_RT)?\
                         ("routing"):(a == BGPG_TEST)?\
                         ("test"):("??")

#define GII_STR2GROUP(a)    (!strcmp(a, "external"))?\
                        (BGPG_EXTERNAL):(!strcmp(a, "internal"))?\
                        (BGPG_INTERNAL):(!strcmp(a, "internal_igp"))?\
                        (BGPG_INTERNAL_IGP):(!strcmp(a, "routing"))?\
                        (BGPG_INTERNAL_RT):(!strcmp(a, "test"))?\
                        (BGPG_TEST):(-1)

#define GII_ISCIDR(a) ( ! ((inet_prefix_mask(a) == 32) || \
                    (inet_prefix_mask(a) == 24) || \
                    (inet_prefix_mask(a) == 16) || \
                    (inet_prefix_mask(a) == 8)  || \
                    (inet_prefix_mask(a) == 0))  )
#endif

#define GII_WRITE(u)	do { if (gii_write u) return(1); } while(0)
#define GII_NOAVAILABLE	gii_write(gii_ctl, GW_ERR, "function not available")

void		gii_init (void);
void		gii_var_init (void);
void		gii_accept (task *);
int		gii_iden (gii_ctl_t *);
void		gii_recv (task *);
int		gii_process (gii_ctl_t *, char *);
int		gii_write (gii_ctl_t *, int, const char *, ...);
void		gii_terminate (task *);
void		gii_cleanup (void);
void		gii_dump (task *, FILE *);
int 		gii_parse_cmd (gii_ctl_t *, char *);
int 		gii_cmd_error (gii_ctl_t *);
int		split (char *, char[GIITOKENLEN][GIINBMAXTOKENS]);
giimenu_cmd_t *	cmd_find (giimenu_cmd_t [], char *);
int		gii_quit (gii_ctl_t *);
int		gii_showversion (gii_ctl_t *);
int             gii_showbgp (gii_ctl_t *);
int		gii_showkernel (gii_ctl_t *);
int		gii_help (gii_ctl_t *);
int		gii_prompt (gii_ctl_t *);
void		telnet_strip (char *, int *);
int		telnet_echooff (gii_ctl_t *);
int		telnet_echoon (gii_ctl_t *);
char *		trace_state_all (flag_t);
int		gii_showif (gii_ctl_t *, char [GIITOKENLEN][GIINBMAXTOKENS], int);
int		gii_showallif (gii_ctl_t *);
int		gii_showmem (gii_ctl_t *);
int		gii_showrtipall (gii_ctl_t *);
int		gii_showrtip (gii_ctl_t *, char [GIITOKENLEN][GIINBMAXTOKENS], int);
int		gii_showalltask (gii_ctl_t *);
int		gii_showalltimer (gii_ctl_t *);
int		gii_showipup (gii_ctl_t *, char [GIITOKENLEN][GIINBMAXTOKENS], int);
int		gii_showipdown (gii_ctl_t *, char [GIITOKENLEN][GIINBMAXTOKENS], int);
void		gii_job_walk (task_job *);
int		gii_dvmrp_mfcall (gii_ctl_t *);
int		gii_dvmrp_mfc (gii_ctl_t *, char [GIITOKENLEN][GIINBMAXTOKENS], int);
int		gii_dvmrp_targets (gii_ctl_t *);
int		gii_showbgpaspat (gii_ctl_t *, char [GIITOKENLEN][GIINBMAXTOKENS], int);
int             gii_showbgpsum (gii_ctl_t *, char [GIITOKENLEN][GIINBMAXTOKENS], int);
int             gii_showbgppeeras (gii_ctl_t *, char [GIITOKENLEN][GIINBMAXTOKENS], int);
int             gii_showbgpaspath (gii_ctl_t *, char [GIITOKENLEN][GIINBMAXTOKENS], int);
int		gii_showbgpcidronly (gii_ctl_t *, char [][], int);
int		gii_showbgpexpression (gii_ctl_t *, char [][], int);
int		gii_showbgpfilter (gii_ctl_t *, char [][], int);
int		gii_showbgpinconsistent (gii_ctl_t *, char [][], int);
int		gii_showbgpneighbors (gii_ctl_t *, char [][], int);
int		gii_showbgppaths (gii_ctl_t *, char [][], int);
int		gii_showbgppeergroup (gii_ctl_t *, char [][], int);
int		gii_showbgproutes (gii_ctl_t *, char [][], int);
int		gii_showriproutes (gii_ctl_t *, char [][], int);
void		gii_job_pathwalk (task_job *);
void		gii_job_walk_bgp (task_job *);
void		gii_job_walk_rip (task_job*);
void		gii_job_walk_bgp_comm (task_job*);
void		gii_job_walk_bgp_cidr (task_job*);
int		gii_showripsummary (gii_ctl_t *, char [][], int);
int		gii_showriptag (gii_ctl_t *, char [][], int);
void		gii_job_walk_rip_tag (task_job*);
