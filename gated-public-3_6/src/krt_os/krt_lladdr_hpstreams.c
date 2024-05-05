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

#define INCLUDE_IF
#define INCLUDE_SYS_STROPTS
#define INCLUDE_DLPI
#define INCLUDE_IOCTL
#include "include.h"
#include "krt/krt.h"
#include "krt/krt_var.h"
#ifdef KRT_LLADDR_HPSTREAMS

static dl_hp_ppa_ack_t *dl_ppa_ack = (dl_hp_ppa_ack_t *) 0;
static dl_hp_ppa_info_t *dl_ppa_info = (dl_hp_ppa_info_t *) 0;
static char ctlbuf[4000];

s_int32
krt_lladdr_info ()
{
 s_int32 fd, error, flags=0, i, j;
 dl_hp_ppa_req_t dl_ppa_req;
 struct strbuf ctlblk;
 sockaddr_un *lladdr = (sockaddr_un *) 0;

 if (dl_ppa_ack == NULL)  {
 /* first time to retrieve the dlpi info */

    if ((fd = open("/dev/dlpi", O_RDWR)) < 0) {
         trace_tp(krt_task,
                  TR_ALL,
                  0,
                  ("krt_lladdr_info (open dlpi): %m"));
         return (-1); 
    }

    dl_ppa_req.dl_primitive = DL_HP_PPA_REQ;
    ctlblk.len = sizeof(dl_hp_ppa_req_t);
    ctlblk.buf = (char *) &dl_ppa_req;
    if (putmsg (fd, &ctlblk, (char *) 0, 0) < 0) {
         trace_tp(krt_task,
                  TR_ALL,
                  0,
                  ("krt_lladdr_info (putmsg) : %m"));
         close (fd);
         return (-1); 
    }
   
    ctlblk.maxlen = sizeof(ctlbuf);
    ctlblk.buf = ctlbuf;
    if ((error = getmsg (fd, &ctlblk, (char *) 0, &flags)) != 0) {
       if (error == MORECTL) {
         trace_tp(krt_task,
                  TR_ALL,
                  0,
                  ("krt_lladdr_info (getmsg) : ctlblk is too small"));
         close (fd);
         return (-1); 
       }
       else {
         trace_tp(krt_task,
                  TR_ALL,
                  0,
                  ("krt_lladdr_info (getmsg) : %m"));
         close (fd);
         return (-1); 
       }
    }

    close(fd);

    switch (*(unsigned long *)ctlbuf) {
      case DL_HP_PPA_ACK:
           dl_ppa_ack = (dl_hp_ppa_ack_t *) ctlblk.buf;
           dl_ppa_info=(dl_hp_ppa_info_t *) (ctlblk.buf+dl_ppa_ack->dl_offset);
           return 0;
   
      case DL_ERROR_ACK:
           trace_tp(krt_task,
                    TR_ALL,
                    0,
                    ("krt_lladdr_info : DL_ERROR_ACK") );
           return (-1); 
  
       default:
           trace_tp(krt_task,
                    TR_ALL,
                    0,
                    ("krt_lladdr_info : Got unexpected message %d", 
                     *(u_long *) ctlbuf) );
           return (-1); 
    }
 } 
 else
    return 0;
}


sockaddr_un *
krt_lladdr (struct ifreq * ifr)
{
  char if_name[IFNAMSIZ+1];
  struct ifreq *ifrp;
  s_int32 i = 0, unit = 0;
  u_long mtu = 0;
  char *sp = ifr->ifr_name;
  char *cp = if_name;
  sockaddr_un  *lladdr = (sockaddr_un * ) 0;
  dl_hp_ppa_ack_t *dl_ppa_ack_p;
  dl_hp_ppa_info_t *dl_ppa_info_p;
 
  if (krt_lladdr_info () == -1) {
        return (sockaddr_un *) 0;
  }

  do {
      *cp++ = *sp ++;
  } while ( *sp && isalpha (*sp));

  /* kwy: to be deleted later */
  if (*sp == '_')  {
      *cp++ = *sp ++;
      do {
          *cp++ = *sp ++;
      } while ( *sp && isalpha (*sp));
  }
  /* kwy: end of deletion */
  
  *cp = (char) 0;

  /* get the interface name without the unit number */
  cp = strchr (ifr->ifr_name, ':');
  if (cp == NULL)  {
      cp = if_name + strlen(ifr->ifr_name);     
  }              
  do {
    unit = (unit*10) + (*sp - '0');
  } while (*++sp && sp < cp);

  dl_ppa_ack_p = dl_ppa_ack;
  dl_ppa_info_p = dl_ppa_info;

  /* retrieve the station address */
  for (i=0; i<dl_ppa_ack_p->dl_count; i++,dl_ppa_info_p++) {
       if ( (unit == dl_ppa_info_p->dl_ppa) &&
          ( !strcmp (if_name, dl_ppa_info_p->dl_module_id_1) ||
            !strcmp (if_name, dl_ppa_info_p->dl_module_id_2) ) ) {
            lladdr = sockbuild_ll (LL_8022,
                                 (byte *) dl_ppa_info_p->dl_phys_addr,
                                 dl_ppa_info_p->dl_addr_length); 
            break;
       }
  }
  return (lladdr);
}

#endif /* KRT_LLADDR_HPSTREAMS */

