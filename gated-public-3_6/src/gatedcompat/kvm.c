
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
 *  kvm.c,v 1.12.2.1 1995/01/23 12:42:57 jch Exp
 */

#define	INCLUDE_NLIST
#define	INCLUDE_FILE

#include "gated/include.h"

#ifndef HAVE_KVM_OPEN

#ifndef vax11c
#include <sys/file.h>
#endif				/* vax11c */

/*
 *	Emulation of kvm library for systems that do not have it
 */

struct __kvm {
    int	kvm_fd;
    const char *kvm_nl;
    const char *kvm_core;
    const char *kvm_swap;
    char kvm_errmsg[BUFSIZ];
};
typedef struct __kvm kvm_t;

#if	__GNUC__ > 1
/* To prevent a warning about missing prototypes */

kvm_t * kvm_openfiles (char *, char *, char *, int , char *);
int kvm_close (kvm_t *);
/* This define causes problems with linux of gcc 2.91.66 */
/* int kvm_nlist(kvm_t *, NLIST_T *, size_t); */
int kvm_read(kvm_t *, u_long, void_t, size_t);
int kvm_write(kvm_t *, u_long, void_t, size_t);
char * kvm_geterr(kvm_t *);
#endif

kvm_t *
kvm_openfiles (char *nl, char *core, char *swap, int flags, char *errbuf)
{
#ifndef	vax11c
    int fd;
    kvm_t *kd = (kvm_t *) 0;
    const char *corefile = core ? core : _PATH_KMEM;

    fd = task_floating_socket((task *) 0,
			      open(corefile, flags, 0),
			      corefile);
    if (fd < 0) {
	sprintf(errbuf, "kvm_openfiles: %m");
    } else {
	kd = (kvm_t *) task_mem_calloc((task *) 0, 1, sizeof (kvm_t));

	kd->kvm_fd = fd;
	kd->kvm_nl = nl ? nl : _PATH_UNIX;
	kd->kvm_core = corefile;
	kd->kvm_swap = NULL;
	*kd->kvm_errmsg = (char) 0;
    }

    return kd;
#else	/* vax11c */
    return (kvm_t *) TRUE;
#endif	/* vax11c */
}


int
kvm_close (kvm_t *kd)
{
#ifndef	vax11c
    int rc = 0;

    if (kd->kvm_fd >= 0) {
	rc = close(kd->kvm_fd);
	if (rc != 0) {
	    sprintf(kd->kvm_errmsg, "kvm_close: %m");
	}
    }

    (void) task_mem_free((task *) 0, (void_t) kd);

#endif	/* vax11c */

    return 0;
}

int
kvm_nlist (kvm_t *kd, NLIST_T *nl, size_t sz)
{
#ifdef	vax11c
    extern char *Network_Image_File;

    return multinet_kernel_nlist(Network_Image_File, nl);
#else	/* vax11c */
    return NLIST(kd->kvm_nl, nl, sz);
#endif	/* vax11c */
}


int
kvm_read (kvm_t *kd, u_long addr, void_t buf, size_t nbytes)
{
    off_t rc;
#ifdef	vax11c
    rc = klseek(offset);
    if (rc == (off_t) -1) {
	sprintf(kd->kvm_errmsg, "kvm_read: klseek: %m");
    } else {
	rc = klread(buf, nbytes);
	if (rc == (off_t) -1) {
	    sprintf(kd->kvm_errmsg, "kvm_read: klread: %m");
	}
    }
#else	/* vax11c */

    rc = lseek(kd->kvm_fd, (off_t) addr, 0);
    if (rc == (off_t) -1) {
	sprintf(kd->kvm_errmsg, "kvm_read: lseek: %m");
    } else {
	rc = read(kd->kvm_fd, buf, nbytes);
	if (rc == (off_t) -1) {
	    sprintf(kd->kvm_errmsg, "kvm_read: read: %m");
	}
    }
#endif	/* vax11c */

    return rc;
}

int
kvm_write (kvm_t *kd, u_long addr, void_t buf, size_t nbytes)
{
    off_t rc;
#ifdef	vax11c
    rc = klseek(offset);
    if (rc == (off_t) -1) {
	sprintf(kvm_errmsg, "kvm_write: klseek: %m");
    } else {
	rc = klwrite(buf, nbytes);
	if (rc == (off_t) -1) {
	    sprintf(kvm_errmsg, "kvm_write: klwrite: %m");
	}
    }
#else	/* vax11c */

    rc = lseek(kd->kvm_fd, (off_t) addr, 0);
    if (rc == (off_t) -1) {
	sprintf(kd->kvm_errmsg, "kvm_write: lseek: %m");
    } else {
	rc = write(kd->kvm_fd, buf, nbytes);
	if (rc == (off_t) -1) {
	    sprintf(kd->kvm_errmsg, "kvm_write: write: %m");
	}
    }
#endif	/* vax11c */

    return rc;
}


char *
kvm_geterr (kvm_t *kd)
{
    return kd->kvm_errmsg;
}

#endif
