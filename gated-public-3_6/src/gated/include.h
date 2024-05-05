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

#include "../config.h"

#define GASSERT(c)  do {int *__i__ = 0; if (!(c)) {\
        (void)fprintf(stderr, "assert failed file %s line %d\n", \
                 __FILE__, __LINE__); *__i__ = 1;} \
        } while(0)



#ifndef	_GATED_INCLUDE_H
#define	_GATED_INCLUDE_H
/* #include "defines.h" */

#if	defined(_IBMR2) && !defined(_BSD)
#define	_BSD	1
#endif

/* if we are using gcc, use the gcc va_list type */
#if defined (__GNUC__) && !defined(hpux) && !defined(linux)
#define _VA_LIST
#endif /* __GNUC__ */

#ifdef PROTO_INET6
#include "krt_ipv6multi/krt_ipv6multi.h"
#endif

#include <sys/param.h>			/* Was types */
#ifdef	INCLUDE_TYPES
#include <sys/types.h>
#endif	/* INCLUDE_TYPES */
#ifdef	INCLUDE_BSDTYPES
#include <sys/bsdtypes.h>
#endif	/* INCLUDE_TYPES */
#if defined(INCLUDE_STREAMIO) && defined(HAVE_SYS_STREAM_H)
#include <sys/stream.h>
#endif	/* INCLUDE_STREAMIO && HAVE_SYS_STREAMIO_H */
#include <sys/uio.h>

#if defined(hpux) || defined(__osf__)
#define _XOPEN_SOURCE_EXTENDED
#include <sys/socket.h>
#undef _XOPEN_SOURCE_EXTENDED
#else
#include <sys/socket.h>
#endif /* hpux || __osf__ */

/* We will set ISO as UNSPEC to be on the safe side,
 * Linux uses 7 as AF_BRIDGE, therfore we will not
 * arbitrarily set it to 7
 */
#if !defined(AF_ISO) && defined(linux)
#define AF_ISO	AF_UNSPEC
#endif

#if defined(PROTO_ISIS2) && ! defined(AF_ISO)
#if	defined(AF_OSINET)
#define	AF_ISO	AF_OSINET
#elif defined(AF_OSI)
#define	AF_ISO	AF_OSI
#elif defined(AF_OTS)
#define	AF_ISO	AF_OTS
#else
#error	"can't find suitable definition for AF_ISO"
#endif
#endif	/* PROTO_ISIS2 && ! AF_ISO */

#ifdef PROTO_OSPF2
#ifndef NOSPF_NSSA
#define NOSPF_NSSA	1
#endif /* NOSPF_NSSA */
#endif /* PROTO_OSPF2 */

#ifdef linux
#undef SCM_RIGHTS
#define VARIABLE_MASKS
#endif

#ifdef	UNDEF_RCVBUF
#undef	SO_RCVBUF
#endif

#include <stdio.h>
#if	!defined(NO_STDLIB_H)
#include <stdlib.h>
#endif
#if	!defined(NO_STDDEF_H)
#include <stddef.h>
#endif
#ifdef	MALLOC_OK
#ifdef	INCLUDE_MALLOC
#include <malloc.h>
#endif
#endif
#include <netdb.h>
#include <sys/errno.h>
#ifdef	SYSV
#undef ENAMETOOLONG
#undef ENOTEMPTY
#include <net/errno.h>
#endif
#ifdef	INCLUDE_STRING
#include <string.h>
#else
#include <strings.h>
#endif

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#ifdef	HAVE_SYS_MBUF_H
#include <sys/mbuf.h>
#endif	/* HAVE_SYS_MBUF_H */
#ifdef	INCLUDE_IF
#include <net/if.h>
#endif /* INCLUDE_IF */
#if defined(INCLUDE_IF_VAR) && defined(HAVE_NET_IF_VAR_H)
#include <net/if_var.h>
#endif /* INCLUDE_IF_VAR && HAVE_NET_IF_VAR_H */

#ifdef	PROTO_UNIX
#include <sys/un.h>
#endif

/*
 * Right now, we only need mman.h if we are using mmap.
 */
#ifdef INCLUDE_SYS_MMAN
#if defined(HAVE_MMAP) && defined(HAVE_MAP_ANON) && defined(HAVE_SYS_MMAN_H)
#include <sys/mman.h>
#endif /* HAVE_MMAP && HAVE_MAP_ANON && HAVE_SYS_MMAN_H */
#endif /* INCLUDE_SYS_MMAN */

#if	defined(PROTO_INET)
#include <netinet/in.h>

#ifdef HAVE_BSD_BSD_H
#include <bsd/bsd.h>
#define  __BSD_SOURCE
#endif /*HAVE_BSD_BSD_H*/

#ifdef	linux			/* this probably ought be removed */
#ifdef BREAKS_REDHAT
#include </usr/src/linux/include/linux/in_systm.h>
#endif /*BREAKS_REDHAT*/
#endif /*linux*/

#ifdef HAVE_NETLINK
#include <linux/types.h>
#include <linux/rtnetlink.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif
#ifdef HAVE_NETINET_IP_VAR_H
#ifdef __osf__
/* XXX why does digital not provide a mask for ip_vhl? */
#ifdef __STDC__
#undef __STDC__
#include <netinet/ip.h>
#define __STDC__ 1
#else
#include <netinet/ip.h>
#endif /* __STDC__ */
#include <netinet/ip_var.h>
#else
#include <netinet/ip_var.h>
#endif  /* __osf__ */
#endif /* HAVE_NETINET_IP_VAR_H */
#ifndef __osf__
#include <netinet/ip.h>       
#endif /* !__osf__ */

#if	!defined(HPUX7_X) && !defined(linux)
#include <arpa/inet.h>
#endif	/* !defined(HPUX7_X) && !defined(linux) */
#ifdef	INCLUDE_ETHER
#if	defined(AIX) && !defined(_IBMR2)
#include <sys/if_ieee802.h>
#else
#if	defined(_IBMR2) && !defined(IPPROTO_TP)	/* AIX 3.1 */
#include <netinet/in_netarp.h>
#else	/* defined(_IBMR2) && !defined(IPPROTO_TP) */
#ifdef	linux
#include <linux/if_ether.h>
#else	/* linux */
#ifdef INCLUDE_ETHER_KERNEL
#define KERNEL
#endif /* INCLUDE_ETHER_KERNEL */
#include <netinet/if_ether.h>
#ifdef INCLUDE_ETHER_KERNEL
#undef KERNEL
#endif /* INCLUDE_ETHER_KERNEL */
#endif	/* linux */
#endif	/* defined(_IBMR2) && !defined(IPPROTO_TP) */
#endif	/* defined(AIX) && !define(_IBMR2) */
#endif	/* INCLUDE_ETHER */

#ifdef	INCLUDE_UDP
#include <netinet/udp.h>
#endif

#if defined (HAVE_NETINET_UDP_VAR_H)
#ifdef	INCLUDE_UDP_VAR
#include <netinet/udp_var.h>
#endif /*INCLUDE_UDP_VAR*/
#endif /*HAVE_NETINET_UDP_VAR_H*/
#endif	/* PROTO_INET */

/* XXX this should be a check on iso_snpac */
#ifdef	INCLUDE_SNPA
#define INCLUDE_SYS_QUEUE
#endif

#ifdef INCLUDE_SYS_QUEUE
#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include "queue.h"
#endif /* HAVE_SYS_QUEUE_H */
#endif /* INCLUDE_SYS_QUEUE */


#if defined(PROTO_INET6)
# if !defined(PROTO_INET)
#  include <netinet/in.h>
#  include <netinet/in_systm.h>
# endif /* !PROTO_INET */
# if defined(IPV6_NETINET)
#  include <netinet/ip6_var.h>
#  include <arpa/inet.h>
#  include <netinet/ip6.h>
#  ifdef INCLUDE_UDP
#   include <netinet/udp6_var.h>
#  endif /* INCLUDE_UDP */
# endif /* IPV6_NETINET */

#  ifdef IPV6_NETINET6
#   include <netinet6/in6.h> 
#   include <netinet6/ip6_var.h> 
#   include <arpa/inet.h>
#   include <netinet6/in6_systm.h>  
#   include <netinet6/ip6.h>
#   ifdef INCLUDE_UDP
#    include <netinet6/udp6_var.h>
#   endif /* INCLUDE_UDP */
#  endif /* IPV6_NETINET6  */

# define ascii2addr(family, ascii, addr) inet_pton(family, ascii, addr)
# define addr2ascii(family, addr, size, ascii) inet_ntop(family, addr, ascii, (size_t)size)
#endif /* PROTO_INET6 */

#if	defined(PROTO_ISO)
#include <netiso/iso.h>
#ifdef	INCLUDE_ISO_VAR
#include <netiso/iso_var.h>
#endif	/* INCLUDE_ISO_VAR */
#ifdef	INCLUDE_CLNP
#include <netiso/clnp.h>
#endif
#ifdef	INCLUDE_ESIS
#include <netiso/esis.h>
#endif
#ifdef	INCLUDE_SNPA
#include <netiso/iso_snpac.h>
#endif
#endif	/* PROTO_ISO */

#ifdef PROTO_IPX
#include <netipx/ipx.h>
#include <netipx/ipx_var.h>
#endif /* PROTO_IPX */

#ifdef	INCLUDE_ROUTE
#include <net/route.h>
#undef	KERNEL
#endif

/* inet/ip.h requires inet/common.h */
#if defined(INCLUDE_INET_IP) && defined(HAVE_INET_IP_H)
#ifndef __osf__
#define KERNEL
#define _KERNEL
#endif /* !__osf__ */
#include <inet/common.h>
#include <inet/ip.h>
#ifndef __osf__
#undef KERNEL
#undef _KERNEL
#endif /* __!osf__ */
#endif /* INCLUDE_INET_IP && HAVE_INET_IP_H */

/* For INCLUDE_MROUTE_KERNEL, this must be done after net/route.h */
#if defined(HAVE_NETINET_IP_MROUTE_H) && defined(IFF_MULTICAST) && \
     defined(PROTO_INET) && defined(IP_MULTICAST_ROUTING) && \
     defined(INCLUDE_MROUTE)
# ifndef INCLUDE_ROUTE
#  include <net/route.h>
#  undef  KERNEL
# endif /*INCLUDE_ROUTE*/
# if defined(INCLUDE_MROUTE_KERNEL) && !defined(KERNEL)
#  define KERNEL
#  define _KERNEL	
#  include <netinet/ip_mroute.h>
#  undef KERNEL
#  undef _KERNEL
# else
#  include <netinet/ip_mroute.h>
# endif
#endif /*REMOVE*/

#ifdef HAVE_PATHS_H
#include <paths.h>
#endif

/* #ifdef	INCLUDE_PATHS */
#include "../gated/paths.h"
/* #endif */

#ifdef	INCLUDE_WAIT
#include <sys/wait.h>
#ifdef	notdef
#include <sys/resource.h>
#endif
#endif

#ifdef	HAVE_UNISTD_H
#ifdef hpux
#define _INCLUDE_AES_SOURCE
#define _INCLUDE_HPUX_SOURCE
#include <unistd.h>
#undef _INCLUDE_AES_SOURCE
#undef _INCLUDE_HPUX_SOURCE
#else
#include <unistd.h>
#endif /* hpux */
#endif /* HAVE_UNISTD_H */

#if	defined(HAVE_NET_IF_DL_H) && defined(INCLUDE_IF)
#include <net/if_dl.h>
#endif	/* defined(HAVE_NET_IF_DL_H) && defined(INCLUDE_IF) */
#if	defined(INCLUDE_IF_TYPES) && defined(SOCKADDR_DL) && !defined(IFT_ETHER)
#include <net/if_types.h>
#endif

#if	defined(AIX)
#include <sys/syslog.h>
#else				/* defined(AIX) */
#include <syslog.h>
#endif				/* defined(AIX) */

#ifdef	INCLUDE_SIGNAL
#ifdef	linux
#undef	sigmask
#endif
#include <signal.h>
#endif

#ifdef	INCLUDE_FILE
#include <sys/file.h>
#ifdef	INCLUDE_FCNTL
#include <sys/fcntl.h>
#endif
#endif

#if	!defined(NO_STAT) && defined(INCLUDE_STAT)
#ifdef hpux
#define _INCLUDE_AES_SOURCE
#include <sys/stat.h>
#undef _INCLUDE_AES_SOURCE
#else
#include <sys/stat.h>
#endif /* hpux */
#endif

#ifdef	INCLUDE_IOCTL
#ifdef	INCLUDE_SOCKIO
#ifdef linux
#include <linux/sockios.h>
#else /*linux*/
#ifdef  HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif  /* HAVE_SYS_SOCKIO_H */
#endif /*linux*/
#endif	/* INCLUDE_SOCKIO */
#ifdef	INCLUDE_SIOCTL
#include <sys/sioctl.h>
#endif	/* INCLUDE_SIOCTL */

#ifdef	HAVE_SYS_STROPTS_H
#ifdef hpux
#define _INCLUDE_HPUX_SOURCE
#define _XOPEN_SOURCE_EXTENDED
#include <sys/stropts.h>
#undef _INCLUDE_HPUX_SOURCE
#undef _XOPEN_SOURCE_EXTENDED
#else
#include <sys/stropts.h>
#endif /* hpux */
#else	/* HAVE_SYS_STROPTS_H */
#include <sys/ioctl.h>
#endif	/* HAVE_SYS_STROPTS_H */
#endif	/* INCLUDE_IOCTL */

#ifdef HAVE_NLIST_H
#ifdef	INCLUDE_NLIST
#include <nlist.h>
#endif
#endif /*HAVE_NLIST_H*/

#ifdef INCLUDE_DLPI
#ifdef HAVE_SYS_DLPI_H
#include <sys/dlpi.h>
#endif /* HAVE_SYS_DLPI_H */
#ifdef HAVE_SYS_DLPI_EXT_H
#include <sys/dlpi_ext.h>
#endif /* HAVE_SYS_DLPI_EXT_H */
#endif /* INCLUDE_DLPI */

#ifdef	INCLUDE_KINFO
#ifdef	HAVE_SYSCTL
#include <sys/sysctl.h>
#else	/* HAVE_SYSCTL */
#if	(defined(KRT_RTREAD_KINFO) \
	 || defined(KRT_IFREAD_KINFO)) \
    && !defined(KINFO_RT_DUMP)
#include <sys/kinfo.h>
#endif
#endif	/* HAVE_SYSCTL */
#endif	/* INCLUDE_KINFO */

#if	defined(INCLUDE_NETOPT_IBMR2) && defined(_IBMR2) && !defined(SIOCGNETOPT)
#include <net/netopt.h>
#endif

#ifdef	INCLUDE_CTYPE
#if defined(__osf__) && defined(__GNUC__)
#undef _VA_LIST
#include <ctype.h>
#define _VA_LIST
#else
#include <ctype.h>
#endif /* __osf__ */
#endif

#if	defined(INCLUDE_DIRENT) && defined(HAVE_DIRENT)
#include <dirent.h>
#endif

#ifdef	IPSEC
#include "rc4.h"
#include "md5.h"
#include <vpn/ipsec.h>
#endif

#ifdef	STDARG
#ifndef	va_arg
#include <stdarg.h>
#endif	/* va_arg */
#else	/* STDARG */
#include <varargs.h>
#endif	/* STDARG */

#ifndef	MALLOC_OK
#undef	malloc
#define	malloc()	assert(FALSE)
#undef	calloc
#define	calloc()	assert(FALSE)
#undef	realloc
#define	realloc()	assert(FALSE)
#undef	free
#define	free()		assert(FALSE)
#endif	/* MALLOC_OK */

#include "defs.h" 
#include "sockaddr.h"
#include "str.h"
#ifdef	INCLUDE_GQUEUE
#include "gqueue.h"
#endif
#ifdef	PROTO_MPASPATHS
#include "mpaspath/mpaspath_hash.h"
#include "mpaspath/mpaspath.h"
#include "mpaspath/mpasmatch.h"
#endif /* PROTO_MPASPATHS */
#ifdef	PROTO_ASPATHS
#ifdef	PROTO_ASPATHS_MEMBER
#include "aspath/aspath_hash.h"
#include "aspath/aspath.h"
#include "aspath/asmatch.h"
#else /* PROTO_ASPATHS_PUBLIC */
#include "aspath/aspath.h"
#include "aspath/asmatch.h"
#endif	/* PROTO_ASPATHS_MEMBER */
#endif /* PROTO_ASPATHS */
#include "policy.h"
#ifdef	INCLUDE_RT_VAR
#include "rt_var.h"
#endif
#include "rt_table.h"
#ifdef PROTO_WRD
#include "wrd/rr_suppress.h"
#endif /* PROTO_WRD */
#include "if.h"
#include "task.h"
#include "trace.h"
#ifndef	HAVE_UNISTD_H
#include "unix.h"
#endif

#if defined(INCLUDE_CMU_SNMP) && defined(PROTO_CMU_SNMP)
#include "snmpdlib/cmusnmpdlib.h"
#endif

#ifdef INCLUDE_LINUX_H
#include "linux.h"
#endif 

#endif	/* _GATED_INCLUDE_H */
