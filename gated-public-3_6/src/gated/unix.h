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


/* system function type declarations */

#ifdef	MALLOC_OK
extern void free(caddr_t);
#endif	/* MALLOC_OK */
extern int send(int s, caddr_t, int, int);
extern int getpeername(int, struct sockaddr *, int *);
extern int fcntl(int, int, int);
extern int setsockopt(int, int, int, caddr_t, int);
extern int close(int);
extern int connect(int, struct sockaddr *, int);
extern int accept(int, struct sockaddr *, int *);
extern int bind(int, struct sockaddr *, int);
extern int listen(int, int);
extern int recv(int, caddr_t, int, int);
extern void qsort(caddr_t, u_int, int, int compare(const VOID_T, const VOID_T));
#ifdef	INCLUDE_TIME
extern int gettimeofday(struct timeval *, struct timezone *);
#endif
extern int sendto(int, caddr_t, int, int, struct sockaddr *, int);
extern int ioctl(int, unsigned long, caddr_t);
#ifdef	INCLUDE_NLIST
extern int nlist(const char *, NLIST_T *);
#endif
extern int open(const char *, int, ...);
extern int read(int, caddr_t, int);
extern off_t lseek(int, off_t, int);
extern int gethostname(char *, int);
extern int fork(void);
extern void exit(int);
extern int getdtablesize(void);
extern int getpid(void);
extern void openlog(const char *, int, int);
extern void setlogmask(int);
extern void srandom(int);
extern long random(void);
extern int chdir(const char *);
extern void abort(void);
extern int fputs(const char *, FILE *);
extern int kill(int, int);
#ifdef	INCLUDE_TIME
extern int setitimer(int, struct itimerval *, struct itimerval *);
#endif
extern int recvmsg(int, struct msghdr *, int);
#ifdef	INCLUDE_TIME
extern int select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
#endif
extern int sigblock(int);
extern int sigsetmask(int);
#ifdef	INCLUDE_WAIT
extern int wait3(union wait *, int, caddr_t /* XXX */);
#endif
extern int sigvec(int, struct sigvec *, struct sigvec *);
extern int socket(int, int, int);
extern void sleep(unsigned);
extern int fclose(FILE *);
#ifdef	INCLUDE_STAT
extern int stat(const char *, struct stat *);
#endif
extern int setlinebuf(FILE *);
extern void setbuf(FILE *, caddr_t);
extern int setvbuf(FILE *, caddr_t, int, size_t);
extern int fflush(FILE *);
extern int fputc(char c, FILE *);
extern int syslog(int, const char *, ...);
#ifdef	MALLOC_OK
extern caddr_t calloc(unsigned, size_t);
extern caddr_t malloc(size_t);
#endif	/* MALLOC_OK */
#ifdef	notdef 
extern caddr_t alloca(int);
#endif
extern int atoi(const char *);
#ifdef	notdef
extern char *index(char *, char);
extern char *rindex(char *, char);
#endif
extern char *getcwd(char *);
extern sethostent(int);
extern endhostent(void);
extern endnetent(void);
extern setnetent(int);
extern char *getenv(const char *);
