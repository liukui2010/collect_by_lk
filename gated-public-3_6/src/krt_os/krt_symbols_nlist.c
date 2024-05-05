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


#define	INCLUDE_FILE
#define	INCLUDE_NLIST
#define	INCLUDE_KVM
#include "include.h"

/* #ifdef KRT_SYMBOLS_NLIST */

#ifdef	PROTO_INET
#include "inet/inet.h"
#endif	/* PROTO_INET */
#include "krt/krt.h"
#include "krt/krt_var.h"


#ifdef	PROTO_INET
static unsigned long krt_ipforwarding;
static unsigned long krt_udpcksum;
#endif	/* PROTO_INET */

static u_long krt_version;

typedef struct _krt_syms {
    const char *ks_name;
    u_long *ks_value;
    NLIST_T *ks_nlp;
} krt_syms;

static krt_syms krt_symbol_names[] = {
#ifdef	KRT_RTREAD_KMEM
    {KSYM_RTHOST,		&krt_rthash[KRT_RTHOST]},
    {KSYM_RTNET,		&krt_rthash[KRT_RTNET]},
    {KSYM_RTHASHSIZE,		&krt_rthashsize},
#endif	/* KRT_RTREAD_KMEM */
#ifdef	KRT_RTREAD_RADIX
    {KSYM_RADIXHEAD,		&krt_radix_head},
#endif	/* KRT_RTREAD_RADIX */
#ifdef	KRT_LLADDR_KMEM
    {KSYM_IFNET,		&krt_ifnet},
#endif	/* KRT_LLADDR_KMEM */
#ifdef	PROTO_INET
    {KSYM_IPFORWARDING,		&krt_ipforwarding},
    {KSYM_UDPCKSUM,		&krt_udpcksum},
#endif	/* PROTO_INET */
    {KSYM_VERSION,		&krt_version},
    {NULL, NULL}
};

#ifdef	_AUX_SOURCE
#define	n_name	n_nptr
#endif	/* _AUX_SOURCE */

int
krt_symbols (task *tp)
{
#ifdef HPSTREAMS
    int value, value_char;
    FILE *pfile;

    system("unset UNIX95; PRE_U95=true; export PRE_U95");
    pfile = popen ("ndd -get /dev/ip ip_forwarding", "r");
    value_char = getc(pfile);
    value = value_char - '0';
    inet_ipforwarding = value > 0; 
    trace_tp(tp,
             TR_KRT_SYMBOLS,
             0,
             ("krt_symbols: IP forwarding %u using %u",
               value,
               inet_ipforwarding));
    pclose(pfile);

    pfile = popen ("ndd -get /dev/udp udp_do_checksum", "r");
    value_char = getc(pfile);
    value = value_char - '0';
    inet_udpcksum = value != 0;
    trace_tp(tp,
             TR_KRT_SYMBOLS,
             0,
             ("krt_symbols: UDP checksum %u using %u",
               value,
               inet_udpcksum));
    pclose(pfile);
 
#else  /* HPSTREAMS */
    register NLIST_T *nl, *nlp, *nle;
    register krt_syms *ksp;
    
    if (!kd) {
	return EBADF;
    }

    if (!task_send_buffer) {
	/* We need a send buffer */

	task_alloc_send(tp, task_pagesize);
    }
    nl = (NLIST_T *) task_send_buffer;

    for (ksp = krt_symbol_names, nlp = nl; ksp->ks_name; ksp++) {

	/* Skip entries with no names */
	if (ksp->ks_name && *ksp->ks_name) {

	    /* Bcopy the pointers to avoid warning about const char */
	    bcopy((caddr_t) &ksp->ks_name, (caddr_t) &nlp->n_name,
sizeof(char *));
#ifdef	NLIST_NOUNDER
	    if (*nlp->n_name == '_') {
		nlp->n_name++;
	    }
#endif	/* NLIST_NOUNDER */

	    /* Remember this entry */
	    ksp->ks_nlp = nlp++;
	}
    }

    /* Remember the end */
    nle = nlp;

    if (nle > nl
	&& KVM_NLIST(kd, nl, nle - nl) < 0) {
	trace_log_tp(tp,
		     0,
		     LOG_ERR,
		     ("krt_symbols: %s",
		      KVM_GETERR(kd, "kvm_nlist error")));

	return EINVAL;
    }

#ifdef	_AUX_SOURCE
    /*  There is a bug in the Apple A/UX 2.01 nlist function.  It will	*/
    /*  return a value of zero for any symbol that is in the bss region.*/
    /*  It does work correctly for symbols which are in the data region.*/
    /*  This function opens a pipe to the nm(1) command, which works	*/
    /*  correctly, although more slowly, for symbols in the bss region.	*/
    /*  Herb Weiner <herbw@wiskit.rain.com>				*/

    for (nlp = nl; nlp < nle; nlp++) {	
	if (nlp->n_type && !nlp->n_value) {
	    char command [256];
	    char buffer [256];
	    char *bufp;
	    FILE *symbol_pipe;
 
	    sprintf (command, "/bin/nm -d %s | /bin/grep %s",
		     UNIX_NAME,
		     nlp->nl_name);
	    NON_INTR(symbol_pipe, pope (command, "r"));
 
	    fgets (buffer, sizeof (buffer), symbol_pipe);
	    bufp = strchr (buffer, '|');
	    if (bufp) {
		sscanf (bufp, "|%ld|", &nlp->nl_value);
	    }
    
	    pclose (symbol_pipe);
	}
    }
#endif	/* _AUX_SOURCE */

    /* Copy the values back */
    for (ksp = krt_symbol_names; ksp->ks_name; ksp++) {
	if (ksp->ks_nlp) {
	    *ksp->ks_value = ksp->ks_nlp->n_value;
	    trace_tp(tp,
		     TR_KRT_SYMBOLS,
		     0,
		     ("krt_symbols: %s = %x",
		      ksp->ks_nlp->n_name,
		      ksp->ks_nlp->n_value));
	}
    }
    
    if (krt_version) {
	char *p;

	krt_version_kernel = (char *) task_block_malloc(task_pagesize);
	if (KVM_READ(kd,
		     krt_version,
		     krt_version_kernel,
		     task_pagesize - 1) < 0) {
	    trace_log_tp(tp,
			 0,
			 LOG_ERR,
			 ("krt_symbols: reading kernel version: %s",
			  KVM_GETERR(kd, "kvm_read error")));
	    return EINVAL;
	}
	if ((p = (char *) index(krt_version_kernel, '\n'))) {
	    *p = (char) 0;
	}
	p = task_mem_strdup(tp, krt_version_kernel);
	task_block_reclaim(task_pagesize, krt_version_kernel);
	krt_version_kernel = p;
	trace_only_tp(tp,
		      TRC_NL_BEFORE,
		      ("krt_symbols: kernel_version = %s",
		       krt_version_kernel));
    }

#ifdef	PROTO_INET
    if (krt_ipforwarding) {
	int value;
	
	if (KVM_READ(kd,
		     krt_ipforwarding,
		     &value,
		     sizeof(value)) < 0) {
	    trace_log_tp(tp,
			 0,
			 LOG_INFO,
			 ("krt_symbols: reading IP forwarding enable flag: %s",
			  KVM_GETERR(kd, "kvm_read error")));
	} else {
	    inet_ipforwarding = value > 0;
	    trace_tp(tp,
		     TR_KRT_SYMBOLS,
		     0,
		     ("krt_symbols: IP forwarding %u using %u",
		      value,
		      inet_ipforwarding));
	}
    }
    if (krt_udpcksum) {
	int value;
	
	if (KVM_READ(kd,
		     krt_udpcksum,
		     &value,
		     sizeof(value)) < 0) {
	    trace_log_tp(tp,
			 0,
			 LOG_INFO,
			 ("krt_symbols: reading UDP checksum enable flag: %s",
			  KVM_GETERR(kd, "kvm_read error")));
	} else {
	    inet_udpcksum = value != 0;
	    trace_tp(tp,
		     TR_KRT_SYMBOLS,
		     0,
		     ("krt_symbols: UDP checksums %u using %u",
		      value,
		      inet_udpcksum));
	}
    }
#endif	/* PROTO_INET */

#endif /* HPSTREAMS */
    return 0;
}
/* #endif */
