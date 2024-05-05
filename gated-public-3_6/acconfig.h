
/* What variable contains the environment */
#undef ENVIRON

/* Name of package */
#undef PACKAGE

/* Which release this source code came from */
#undef VERSION

/* Which package are we building */
#undef GATED_MEMBER
#undef GATED_PUBLIC

/* enable the developer gii debug menu */
#undef GII_DEBUG_MENU

/* Shadow passwords */
#undef SHADOWPW

/* Define if you have the bcmp function.  */
#undef HAVE_BCMP

/* Define if you have the bcopy function.  */
#undef HAVE_BCOPY

/* Define if you have the bzero function.  */
#undef HAVE_BZERO

/* Define if you have the crypt function.  */
#undef HAVE_CRYPT

/* Define if you have /dev/nit  */
#undef HAVE_DEV_NIT

/* Define if sys/dlpi.h defines DL_HP_PPA_ACK */
#undef HAVE_DL_HP_PPA_ACK

/* Define if you have the getkerninfo function.  */
#undef HAVE_GETKERNINFO

/* Define if you have the gethostbyname function. */
#undef HAVE_GETHOSTBYNAME

/* Define if h_errlist is defined in <netdb.h> */
#undef HAVE_H_ERRLIST

/* Define if ifr_mtu is a field in struct ifreq in <net/if.h> */
#undef HAVE_IFR_MTU

/* Define if <netinet/in_var.h> has struct in_multi */
#undef HAVE_IN_MULTI

/* Define if <netinet/in_var.h> has ipaddr_t */
#undef HAVE_IPADDR_T

/* Define if you have the kstat_open() function */
#undef HAVE_KSTAT_OPEN

/* Define if you have <kvm.h> */
#undef HAVE_KVM_H

/* Define if you have kvm_nlist */
#undef HAVE_KVM_NLIST

/* Define if you have kvm_open */
#undef HAVE_KVM_OPEN

/* Define if you have MAP_ANON in sys/mman.h */
#undef HAVE_MAP_ANON

/* Define if you have <bsd/bsd.h> */
#undef HAVE_BSD_BSD_H

/* Define if you have inet_ntoa() */
#undef HAVE_INET_NTOA

/* Define if we have CMSG_SPACE */
#undef HAVE_CMSG_SPACE

/* Define if we have XPG4 support */
#undef HAVE_XPG4

/* Define if we are AIX */
#undef HAVE_AIX

/* Define if we are SunOS 4X */
#undef HAVE_SUNOS4

/* Define if we AIX defines for icmpv6  */
#undef HAVE_ICMPV6_DEST_UNREACH

/* Define if we AIX nd6_redirect structure */
#undef HAVE_REDIRECT_DESTINATION

/* Define if we have getipnodebyname */
#undef HAVE_GETIPNODEBYNAME

/* Define if we have if_nametoindex  */
#undef HAVE_IFNAMETOINDEX

/* Define if we have getipnodebyname */
#undef HAVE_GETIPNODEBYNAME

/* Define if we have icmpv6 structure */
#undef HAVE_ICMPV6_STRUCTURE

/* Define if we have ifm_data field in ifa_msghdr struct */ 
#undef HAVE_IFM_DATA

/* Define if you have <nlist.h> */
#undef HAVE_NLIST_H

/* Define if you have <net/if_dl.h> */
#undef HAVE_NET_IF_DL_H

/* Define if you have the <netinet/in_var.h> header file.  */
#undef HAVE_NETINET_IN_SYSTM_H

/* Define if you have the <netinet/in_var.h> header file.  */
#undef HAVE_NETINET_IN_VAR_H

/* Define if you have <netinet/ip_var.h> */
#undef HAVE_NETINET_IP_VAR_H

/* Define if you have <netinet/ip_var.h> */
#undef HAVE_NETINET_UDP_VAR_H

/* Define if you have <netinet/ip_mroute.h> */
#undef HAVE_NETINET_IP_MROUTE_H

/* Define if ip_mroute.h requires KERNEL or _KERNEL */
#undef INCLUDE_MROUTE_KERNEL

/* Define if you have the nlist function.  */
#undef HAVE_NLIST

/* Define if you have /proc/version file */
#undef HAVE_PROC_VERSION   

/* Define if <net/route.h> has radix_node_head */
#undef HAVE_RADIX_NODE_HEAD

/* Define if <net/route.h> has rt_tables */
#undef HAVE_RT_TABLES

/* Define if you have the setsid function.  */
#undef HAVE_SETSID

/* Define if sys/socketio.h defines SIOCGIFHWADDR */
#undef HAVE_SIOCGIFHWADDR

/* Define if you have the socket function.  */
#undef HAVE_SOCKET

/* Define if you have sys/dlpi.h  */
#undef HAVE_SYS_DLPI_H

/* Define if you have sys_signame.  */
#undef HAVE_SYS_SIGNAME

/* Define if you have the sysctl function.  */
#undef HAVE_SYSCTL

/* Define if you have the sysinfo function.  */
#undef HAVE_SYSINFO

/* Define if you have the tzsetwall function.  */
#undef HAVE_TZSETWALL

/* Define if you have the waitpid function.  */
#undef HAVE_WAITPID

/* Do we have a setlinebuf func? */
#undef HAVE_SETLINEBUF

/* Do we have netlink for Linux */
#undef HAVE_NETLINK

/* HP-UX 11.0 uses HPSTREAMS */
#undef HPSTREAMS

/* Define if multicast capability exists */
#undef IP_MULTICAST

/* location of kernel */
#undef KERNEL_FNAME

/* Define the krt socket type */
#undef KRT_RT_NETLINK
#undef KRT_RT_IOCTL
#undef KRT_RT_SOCK

/* Define the krt symbols type */
#undef KRT_SYMBOLS_SUNOS5
#undef KRT_SYMBOLS_SYSCTL
#undef KRT_SYMBOLS_NLIST
#undef KRT_SYMBOLS_PROC

/* Define the args to the krt socket creation call */
#undef KRT_SOCKET_TYPE

/* Define one of the following for the krt rtread type */
#undef KRT_RTREAD_NETLINK
#undef KRT_RTREAD_PROC
#undef KRT_RTREAD_HPSTREAMS
#undef KRT_RTREAD_KINFO
#undef KRT_RTREAD_RADIX
#undef KRT_RTREAD_KMEM
#undef KRT_RTREAD_SUNOS5

/* Define one of the following to determine how to read the if list */
#undef KRT_IFREAD_NETLINK
#undef KRT_IFREAD_KINFO
#undef KRT_IFREAD_IOCTL
#undef KRT_IFREAD_COMBO

/* Kernel variables */
#undef KSYM_BOOTTIME
#undef KSYM_IFNET
#undef KSYM_IN_IFADDR
#undef KSYM_IP_MROUTER
#undef KSYM_IPFORWARDING
#undef KSYM_IPSTAT
#undef KSYM_RTHASHSIZE
#undef KSYM_RTHOST
#undef KSYM_RTNET
#undef KSYM_TCP_TTL
#undef KSYM_UDPCKSUM
#undef KSYM_VERSION
#undef KSYM_RADIXHEAD

/* KVM lookup system */
/* Define which KVM system is in use */

/* Define that SUNOS4 kvm system is used  */
#undef KVM_TYPE_SUNOS4

/* Define that 4.3BSDreno kvm system is used  */
#undef KVM_TYPE_RENO

/* Define that BSD4.4 kvm system is used  */
#undef KVM_TYPE_BSD44

/* Define that OTHER kvm system is used  */
#undef KVM_TYPE_OTHER

/* Define that NONE kvm system is used  */
#undef KVM_TYPE_NONE

/* LLADDR lookup system */
/* Define which LLADDR system is in use */

/* Define that HPSTREAMS lladdr system is used  */
#undef KRT_LLADDR_HPSTREAMS

/* Define that KMEM lladdr system is used  */
#undef KRT_LLADDR_KMEM

/* Define that LINUX lladdr system is used  */
#undef KRT_LLADDR_LINUX

/* Define that SUNOS4 lladdr system is used  */
#undef KRT_LLADDR_SUNOS4

/* Define that SUNOS5 lladdr system is used  */
#undef KRT_LLADDR_SUNOS5

/* Define that SUNOS5 lladdr system is used  */
#undef KRT_LLADDR_NONE

/* Define if ioctl() is used for communicating routes with the kernel */
#undef HAVE_RT_IOCTL

/* Define if routing sockets exist */
#undef HAVE_RT_SOCK

/* Define if the multicast addresses are on the ifnet */
#undef MULTIADDRS_ON_IFNET

/* Define if we want to use the primary address for the interface route */
#undef PRIMARY_ADDR_INTF_ROUTE

/* Define if the radix_node_head structure is useful to us */
#undef RADIX_HEAD_USABLE

/* Define if <sys/socket.h> defines AF_LINK */
#undef SOCKADDR_DL

/* Define if netinet/if_ether.h defines struct arpcom */
#undef USE_ARPCOM

/* Define if we can use 'ndd' */
#undef USE_NDD

/* Define if we can use the ia_subnetmask field in in_ifaddrs */
#undef USE_IA_SUBNETMASK

/* Define if <netinet/in_var.h> in_multi struct has inm_list field */
#undef USE_INM_LIST

/* Define if <netinet/in_var.h> has inm_next */
#undef USE_INM_NEXT

/* Define if <inet/ip.h> has IRE_DEFAULT */
#undef USE_IRE_DEFAULT

/* Define if <sys/socket.h> msghdr struct has control fields */
#undef USE_MSGHDR_CONTROLFIELDS

/* Define if <sys/socket.h> has sa_len */
#undef USE_SOCKLEN

/* Define that USE_IA_LINK_TAILQ is used  */
#undef USE_IA_LINK_TAILQ

/* Define that USE_IA_LINK is used  */
#undef USE_IA_LINK

/* Define that USE_IA_LIST_TAILQ is used  */
#undef USE_IA_LIST_TAILQ

/* Define that USE_IA_LIST is used  */
#undef USE_IA_LIST

/* Define that the tailq head of ifaddrs is addrhead */
#undef USE_IF_ADDRHEAD_TAILQ

/* Define that the tailq head of ifaddres is addrlist */
#undef USE_IF_ADDRLIST_TAILQ

/* Define that the tailq entry of ifnets is if_list */
#undef USE_IF_LIST_TAILQ

/* Define that the tailq entry of ifnets is if_link */
#undef USE_IF_LINK_TAILQ

/* Define that USE_XNAME is used  */
#undef USE_XNAME

/* Define if paths.h exists */
#undef HAVE_PATHS_H

/* Define if we're using the RIP MIB */
#undef MIB_RIP

/* Define if we allow rip on buy default */
#undef RIP_DEFAULT_OFF

/* the number of ribs to use */
#undef NUMRIBS

/* Define for if we have icmp6_mld structure instead os mld6_hdr structure */
#undef  HAVE_ICMP6_MLD

/* Define for if we have don't have u_int8_t types */
#undef  NO_UINTn_T_DEFINES

/* Define if we have /usr/include/netinet6 directory */
#undef IPV6_NETINET6
/*
 * Define all the protocol stuff
 */
#undef AUTONOMOUS_SYSTEM
#undef RUSTY
#undef FLETCHER_CHECKSUM
#undef ICMP_SEND
#undef IP_MULTICAST_ROUTING
#undef KRT_IPMULTI_TTL0
#undef KRT_RT_SOCK
#undef MD5_CHECKSUM
#undef MIB_RIP
#undef PARSE_ASLIST
#undef PARSE_LINK
#undef PARSE_PORT
#undef PARSE_UTIME
#undef PROTO_ASPATHS
#undef PROTO_ASPATHS_MEMBER
#undef PROTO_ASPATHS_PUBLIC
#undef PROTO_BGMP
#undef PROTO_BGP
#undef PROTO_BGP4MP
#undef PROTO_CMU_SNMP
#undef PROTO_DVMRP
#undef PROTO_DVMRP_ROUTING
#undef PROTO_EGP
#undef PROTO_GII
#undef PROTO_HELLO
#undef PROTO_ICMP
#undef PROTO_ICMPV6
#undef PROTO_IDPR
#undef PROTO_IGMP
#undef PROTO_INET
#undef PROTO_INET6
#undef PROTO_ISIS
#undef PROTO_ISIS2
#undef PROTO_MLD6
#undef PROTO_MPASPATHS
#undef PROTO_MPBGP
#undef PROTO_MSDP
#undef PROTO_ISO
#undef PROTO_OSPF
#undef PROTO_OSPF2
#undef PROTO_OSPF_EITHER
#undef PROTO_PIM
#undef PROTO_PIMDM
#undef PROTO_PIMSM
#undef PROTO_RDISC
#undef PROTO_RIP
#undef PROTO_RIPNG
#undef PROTO_RSD
#undef PROTO_SLSP
#undef PROTO_SMUX
#undef PROTO_SNMP
#undef PROTO_SNMP
#undef PROTO_SNMP
#undef PROTO_WRD
#undef RDISC_CLIENT
#undef RDISC_SERVER
#undef ROUTER_ID

/* Define to empty if the keyword does not work.  */
#undef UNUSED

@BOTTOM@

/* Set to 1 if you want snmpgets to block and never */
/* timeout.  Original CMU code had this hardcoded as 1. */
#define SNMPBLOCK 1

/* Define this if we are using the Solaris routing socket */
#if defined(KRT_RT_SOCK) && defined(sun)
#define KRT_RT_SOCK_SUNOS5
#endif /* KRT_RT_SOCK && sun */

/* define if sys/cdefs.h doesn't define the __P() macro */
#undef SYS_CDEFS_DEFINES___P

/* type check for in_addr_t */
#undef in_addr_t

/* debugging stuff (SNMP) */
#define DODEBUG 0

/* needed for SNMP */
#define CMU_COMPATIBLE

#ifndef SYS_CDEFS_DEFINES___P
#ifndef __P
#ifdef __STDC__
#define __P(params) params
#else
#define __P(params) ()
#endif /* __STDC__ */
#endif /* __P */
#else /* SYS_CDEFS_DEFINES___P */
#ifndef __P
#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif /* HAVE_SYS_CDEFS_H */
#endif /* __P */
#endif /* SYS_CDEFS_DEFINES___P */

#ifndef HAVE_STRCHR 
#ifdef HAVE_INDEX
# define strchr index
# define strrchr rindex
#endif
#endif
 
#ifndef HAVE_INDEX
#ifdef HAVE_STRCHR
# define index strchr
# define rindex strrchr
#endif
#endif
 
#ifndef HAVE_MEMCPY
#ifdef HAVE_BCOPY 
# define memcpy(d, s, n) bcopy ((s), (d), (n))
# define memmove(d, s, n) bcopy ((s), (d), (n))
# define memcmp bcmp
#endif
#endif
 
#ifndef HAVE_MEMMOVE
#ifdef HAVE_MEMCPY
# define memmove memcpy 
#endif 
#endif
 
#ifndef HAVE_BCOPY
#ifdef HAVE_MEMCPY
# define bcopy(s, d, n) memcpy ((d), (s), (n))
# define bzero(p,n) memset((p),(0),(n))
# define bcmp memcmp 
#endif 
#endif

#define ENV_SEPARATOR ":"
#define ENV_SEPARATOR_CHAR ':'
#define _CRTIMP
