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
#ifdef PROTO_ISO
#include "iso.h"

static task *iso_task;

sockaddr_un *iso_masks[ISO_MAXADDRLEN * NBBY + 1];
byte iso_mask_list[SOCKADDR_ISO_LEN * (ISO_MAXADDRLEN * NBBY + 1)];

byte iso_default_prefix[ISO_MAXADDRLEN];
sockaddr_un *iso_addr_default;

static if_addr_entry iso_systemid_list = { &iso_systemid_list, &iso_systemid_list };

/*
 *	Quickly locate this ISO mask
 */
sockaddr_un *
iso_mask_locate(sockaddr_un *mask)
{
    u_int i;
    byte *cp = (byte *) mask + socksize(mask);
    byte *lp = mask->iso.giso_addr;

    /* Find the last non-zero byte */
    while (--cp > lp) {
	if (*cp) {
	    break;
	}
    }

    /* A rough guess from the size */
    i = (cp - lp) * NBBY;

    /* And a fine tune */
    i += NBBY + 1 - ffs(*cp);

    return iso_masks[i];
}


static void
iso_ifachange(task *tp, if_addr *ifap)
{
    size_t len;
    /* XXX - Make system-id an if_addr_entry ? */
    /* XXX - Deal with non-byte boundries? */

    if (socktype(IFA_UNIQUE_ADDR(ifap)) != AF_ISO) {
	/* Not for us */
	
	return;
    }

    switch (ifap->ifa_change) {
    case IFC_NOCHANGE:
    case IFC_ADD:
	/* Create address */
    Alloc:
	if (!ifap->ifa_systemid
	    && ifap->ifa_netmask
	    && (len = socksize(IFA_UNIQUE_ADDR(ifap)) - socksize(ifap->ifa_addr_remote)) > 1) {
	    sockaddr_un *system_id = sockdup(sockbuild_ll(LL_SYSTEMID,
							  (byte *) IFA_UNIQUE_ADDR(ifap) + socksize(ifap->ifa_addr_remote),
							  len - 1));

	    ifap->ifa_systemid = ifae_locate(system_id, &iso_systemid_list);
	    ifap->ifa_systemid->ifae_n_if++;
	    
	    trace_only_tp(tp,
			  0,
			  ("iso_ifachange: Interface %A (%s) %A",
			   IFA_UNIQUE_ADDR(ifap),
			   ifap->ifa_link->ifl_name,
			   ifap->ifa_systemid->ifae_addr));
	}
	break;

    case IFC_DELETE|IFC_UPDOWN:
    case IFC_DELETE:
	if (ifap->ifa_systemid) {
	    ifap->ifa_systemid->ifae_n_if--;
	    ifae_free(ifap->ifa_systemid);
	    ifap->ifa_systemid = (if_addr_entry *) 0;
	}
	break;

    default:
	/* Something has changed */

	if (BIT_TEST(ifap->ifa_change, IFC_ADDR)) {
	    /* Free old address */
	    if (ifap->ifa_systemid) {
		ifap->ifa_systemid->ifae_n_if--;
		ifae_free(ifap->ifa_systemid);
		ifap->ifa_systemid = (if_addr_entry *) 0;
	    }

	    /* Allocate new address */
	    goto Alloc;
	}
	/* UPDOWN - We don't care */
	/* METRIC - We don't care */
	/* NETMASK - We don't care */
	/* BROADCAST - We don't care */
	/* MTU - We don't care */
	break;
    }
    
}


static void
iso_dump(task *tp, FILE *fp)
{
    if_addr *ifap;
    if_addr_entry *ifae;

    (void) fprintf(fp, "\tSystem IDs:\n");

    IF_ADDR_LIST(ifae, &iso_systemid_list) {
	(void) fprintf(fp, "\t\t%A\tInterfaces: %u\n",
		       ifae->ifae_addr,
		       ifae->ifae_n_if);
    } IF_ADDR_LIST_END(ifae, &iso_systemid_list) ;

    (void) fprintf(fp, "\n\tInterfaces:\n");
    
    IF_ADDR(ifap) {
	if (ifap->ifa_systemid) {
	    (void) fprintf(fp, "\t\tInterface %A (%s)\n\t\t\t%A\n",
			   IFA_UNIQUE_ADDR(ifap),
			   ifap->ifa_link->ifl_name,
			   ifap->ifa_systemid->ifae_addr);
	}
    } IF_ADDR_END(ifap) ;

    /* Martians */
    (void) fprintf(fp, "\tMartians:\n");
    control_dmlist_dump(fp,
			2,
			SI_MARTIANS(AF_ISO),
			(adv_entry *) 0,
			(adv_entry *) 0);
    (void) fprintf(fp, "\n");
}


static void
iso_reinit(task *tp)
{
    SI_MARTIANS(AF_ISO) = adv_destmask_finish(SI_MARTIANS(AF_ISO));
}


static void
iso_cleanup(task *tp)
{
    if (SI_MARTIANS(AF_ISO)) {
	adv_free_list(SI_MARTIANS(AF_ISO));

	SI_MARTIANS(AF_ISO) = (adv_entry *) 0;
    }

    trace_freeup(tp->task_trace);
}


static void
iso_terminate(task *tp)
{
    iso_cleanup(tp);

    task_delete(tp);
}


void
iso_init(void)
{
    if_addr *ifap;

    if (iso_task) {
	iso_task->task_trace = trace_set_global((bits *) 0, (flag_t) 0);
    } else {
	iso_task = task_alloc("ISO",
			      TASKPRI_FAMILY,
			      trace_set_global((bits *) 0, (flag_t) 0));
	task_set_ifachange(iso_task, iso_ifachange);
	task_set_dump(iso_task, iso_dump);
	task_set_cleanup(iso_task, iso_cleanup);
	task_set_reinit(iso_task, iso_reinit);
	task_set_terminate(iso_task, iso_terminate);
	if (!task_create(iso_task)) {
	    task_quit(EINVAL);
	}
    }
    
    /* Fake an ifa_change for each of the interfaces to force the system ID */
    /* to be chose now so the protocols can have it when they start */

    IF_ADDR(ifap) {
	iso_ifachange(iso_task, ifap);
    } IF_ADDR_END(ifap) ;
}


/*
 *	Init all kinds of ISO structures
 */
void
iso_family_init(void)
{
    sockaddr_un *addr;
    sockaddr_un **mp = iso_masks;
    sockaddr_un *mpp = (sockaddr_un *) ((void_t) iso_mask_list);
    byte *cp, *lp;

    /* Get an address to work with */
    addr = sockbuild_iso((byte *) 0, ISO_MAXADDRLEN);

    /* Build all possible contiguous masks */
    socksize(addr) -= ISO_MAXADDRLEN;

    /* Add null mask */
    sockcopy(addr, mpp);
    mask_insert(*mp++ = mpp);
    mpp = (sockaddr_un *) ((void_t) ((byte *) mpp + SOCKADDR_ISO_LEN));

    for (cp = addr->iso.giso_addr, lp = cp + ISO_MAXADDRLEN;
	 cp < lp;
	 cp++) {
	int bit = NBBY;

	socksize(addr)++;
	*cp = (char) 0;

	while (bit--) {
	    *cp |= 1 << bit;
	    sockcopy(addr, mpp);
	    mask_insert(*mp++ = mpp);
	    mpp = (sockaddr_un *) ((void_t) ((byte *) mpp + SOCKADDR_ISO_LEN));
	}
    }

    /* Initialize index for obtaining ISO addresses */
    sock_init_family(AF_ISO,
		     (sizeof (addr->iso) - sizeof (addr->iso.giso_addr)),
		     SOCKADDR_ISO_LEN,
		     iso_mask_list,
		     sizeof iso_mask_list,
		     "sockaddr_un.iso");

    /* Make the default address */
    iso_addr_default = sockdup(sockbuild_iso(iso_default_prefix, 0));

    /* Init the routing table */
    rt_table_init_family(AF_ISO);
    rt_static_init_family(AF_ISO);
}
#endif /* PROTO_ISO */

