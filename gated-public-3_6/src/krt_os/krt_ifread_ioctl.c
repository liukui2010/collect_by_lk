/*
 *  Consortium Release 4
 *
 *  $Id: krt_ifread_ioctl.c,v 1.27 2000/03/17 07:55:06 naamato Exp $
 */

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
 * __END_OF_COPYRIGHT__
 */

#define INCLUDE_IOCTL
#define INCLUDE_IF
#define INCLUDE_SOCKIO

/* #ifdef KRT_IFREAD_IOCTL  */

#ifdef  PROTO_INET
#include "inet/inet.h"
#endif  /* PROTO_INET */

#include "include.h"
#include "krt/krt.h"
#include "krt/krt_var.h"

#ifdef HAVE_RT_IOCTL
#include <sys/sockio.h>
#endif

/* per Stevens vol 1, loopback mtu is 1536 */
#define LOOPBACK_MTU  1536
#define POINTOPOINT_MTU 256
#define ETHER_MTU     1500
#define DEFAULT_MTU    256

/*
 * Prototypes
 */
static int  addr_size(struct ifreq *);
static void get_interface_address_info(task *, struct sockaddr *,
        if_info *, if_link *, char *, int);
static void get_interface_parameter_info(task *, if_info *, char *, int);
static int read_interface_list(task *, struct ifconf *, int);
static void dump_ifrp(task *, struct ifreq *);


u_long siocgifconf, siocgifaddr, siocgifdstaddr, siocgifbrdaddr,
          siocgifnetmask, siocgifflags, siocgifmtu, siocgifmetric;


/*
 * get the length of the socket
 */
static int
addr_size(ifrp)
  struct ifreq *ifrp;
{

#ifdef USE_SOCKLEN
  return (MAX(sizeof(struct sockaddr), ifrp->ifr_addr.sa_len));
#else /* !USE_SOCKLEN */
  switch (ifrp->ifr_addr.sa_family) {
#ifdef IPV6
  case AF_INET6:
    return (sizeof(struct sockaddr_in6));
    break;
#endif  /* IPV6 */
  case AF_INET:
  default:
    return (sizeof(struct sockaddr));
    break;
  }
#endif  /* !USE_SOCKLEN */
}




/* Read the interfaces installed on the system using kernel ioctl call.  */
int read_interface_list (task *task_ptr, struct ifconf *ifc_buffer, int sockfd)
{
	int multiplier, lastlen, errcode;

	lastlen = multiplier = 0;

	/*
	 *	let's read the interface info from the kernel using ioctl with SIOCGIFCONF 
	 *	request. This is a loop because not all implementations of ioctl will 
	 *	return an error if we don't allocate a large enough buffer. The trick 
	 *	around this is do the ioctl and save the length returned, then do the ioctl 
	 *	again with a larger buffer. If the lengths are the same we have all the data
	 *	else we increase the size of the buffer and try again.
	 */ 
	while(1) {

			/*	allocate a task buffer and put buffer pointer 
			 *	and length in ioctl structure. 
			 */
			task_alloc_send(task_ptr, task_pagesize << multiplier);
			ifc_buffer->ifc_len = task_send_buffer_len;
			ifc_buffer->ifc_buf = task_send_buffer;

#if defined(SUNOS5_0) || defined(HPSTREAMS)
			NON_INTR(errcode, ioctl(sockfd, siocgifconf, ifc_buffer));
#else
			errcode = task_ioctl(sockfd, (u_long) siocgifconf,
													(void_t) ifc_buffer, ifc_buffer->ifc_len); 
#endif

		if ( errcode < 0 ) {
			if ( errno != EINVAL || lastlen !=0) {
				/* 
				 * we got problems, cannot do successful ioctl call 
				 */
				return(0);
			}
		}
		else {
			if(ifc_buffer->ifc_len == lastlen ) {
				/* 
				 * length is same so last time so we got it all, 
				 * break out of loop 
				 */
				return(1);
			}
		}
			
		/* 
		 * either first time or we got a different length,
		 * or buffer must not have been big enough
		 * let's try it again with a larger buffer 
		 */
		lastlen = ifc_buffer->ifc_len;
		multiplier++;
	}
}


#ifdef PROTO_INET6
/* Read the interfaces installed on the system using kernel ioctl call.  */
int read_interface_list6 (task *task_ptr, struct lifconf *ifc_buffer, int sockfd)
{
  int multiplier, lastlen, errcode;

  lastlen = multiplier = 0;

	/*  let' read the interface info from the kernel using ioctl with SIOCGIFCONF
   *  request. This is a loop because not all implementations of ioctl will
   *  return an error if we don't allocate a large enough buffer. The trick
   *  around this is do the ioctl and save the length returned, then do the ioctl
   *  again with a larger buffer. If the lengths are the same we have all the data
   *  else we increase the size of the buffer and try again.
   */
  while(1) {

      /*  allocate a task buffer and put buffer pointer
       *  and length in ioctl structure.
       */
			task_alloc_send(task_ptr, task_pagesize << multiplier);
			ifc_buffer->lifc_len = task_send_buffer_len;
			ifc_buffer->lifc_buf =  task_send_buffer;

#if defined(SUNOS5_0) || defined(HPSTREAMS) || defined(HAVE_XPG4)
			NON_INTR(errcode, ioctl(sockfd, siocgifconf, ifc_buffer));
#else
			errcode = task_ioctl(sockfd, (u_long) siocgifconf,
													(void_t) ifc_buffer, ifc_buffer->lifc_len);
#endif

			if ( errcode < 0 ) {
				if ( errno != EINVAL || lastlen !=0) {
	        /*
 	         * we got problems, cannot do successful ioctl call
  	       */
					return(0);
				}
			}
			else {
				if(ifc_buffer->lifc_len == lastlen ) {
					/*
         	 * length is same so last time so we got it all,
         	 * break out of loop
         	 */
        	return(1);
      	}
    	}

		/*
     * either first time or we got a different length,
     * or buffer must not have been big enough
     * let's try it again with a larger buffer
     */
    lastlen = ifc_buffer->lifc_len;
		multiplier++;
	}
}
#endif  /* PROTO_INET6 */

/*
 * do ioctls to get address specific info, such as dest address,
 * broadcast address,and netmask.
 */
static void
get_interface_address_info(task *task_ptr, struct sockaddr *addr, struct _if_info *if_info_ptr,
														if_link *if_link_ptr, char *name, int sockfd)
{
	struct ifreq ifr_buffer;
	sockaddr_un *sockaddr_ptr;

	/* copy default info into structure */
	if_info_ptr->ifi_link = if_link_ptr;

	/* ignore interfaces from undesired families */
	switch ( addr->sa_family)  {
#ifdef PROTO_INET
		case AF_INET:

			if_info_ptr->ifi_addr_local = sockdup(sock2gated(addr, unix_socksize(addr, addr->sa_family))); 
			if_info_ptr->ifi_addr_remote = 0;
			if_info_ptr->ifi_addr_broadcast = 0;
			if_info_ptr->ifi_netmask = 0;

			/* copy the interface name into the ioctl buffer */
			strcpy(ifr_buffer.ifr_name, name);

#ifdef SIOCGIFDSTADDR 
    /*
     * if we are p2p, let's set the mtu and get the address
     * of the other side
     */
		if (BIT_TEST(if_info_ptr->ifi_state, IFS_POINTOPOINT)) {
			if ( if_info_ptr->ifi_mtu == DEFAULT_MTU )
				if_info_ptr->ifi_mtu = POINTOPOINT_MTU;

				if (task_ioctl(sockfd, siocgifdstaddr, 
											(caddr_t) &ifr_buffer, sizeof (ifr_buffer)) < 0) {
						trace_log_tp(task_ptr, 0, LOG_ERR,
												("krt_ifread: %s: ioctl SIOCGIFDSTADDR: %m",
												ifr_buffer.ifr_name));
				}
				else {
					sockaddr_ptr = sock2gated(&ifr_buffer.ifr_dstaddr,
																		unix_socksize(&ifr_buffer.ifr_dstaddr, addr->sa_family));
					if (sockaddr_ptr) 
						if_info_ptr->ifi_addr_remote = sockdup(sockaddr_ptr);
					else
						trace_log_tp(task_ptr, 0, LOG_ERR,
												("krt_ifread: no destination address for %A (%s)",
												if_info_ptr->ifi_addr_local, ifr_buffer.ifr_name));

				}	
			}
#endif /* SIOCGIFDSTADDR */

#ifdef SIOCGIFBRDADDR 
    /*
     * if we are a broadcast medium, set the mtu and get
     * the broadcast address
     */
		if (BIT_TEST(if_info_ptr->ifi_state, IFS_BROADCAST)) {

			if( if_info_ptr->ifi_mtu == DEFAULT_MTU)
				if_info_ptr->ifi_mtu = ETHER_MTU;

			if (task_ioctl(sockfd, siocgifbrdaddr, 
										(caddr_t) &ifr_buffer, sizeof (ifr_buffer)) < 0) {
				trace_log_tp(task_ptr, 0, LOG_ERR,
										("krt_ifread: %s: ioctl SIOCGIFBRDADDR: %m",
										ifr_buffer.ifr_name));
			}
			else {
				sockaddr_ptr = sock2gated(&ifr_buffer.ifr_broadaddr,
																unix_socksize(&ifr_buffer.ifr_broadaddr, addr->sa_family));
				if(sockaddr_ptr)
						if_info_ptr->ifi_addr_broadcast = sockdup(sockaddr_ptr);
				else   
						trace_log_tp(task_ptr, 0, LOG_ERR, 
												("krt_ifread: no broadcast address for %A (%s)",
												if_info_ptr->ifi_addr_local, ifr_buffer.ifr_name));
			}
		}
#endif /* SIOCGIFBRDADDR */

#ifdef	SIOCGIFNETMASK 
    /*
     * get the netmask address for the interface
     */
		if (task_ioctl(sockfd, siocgifnetmask, 
									(caddr_t) &ifr_buffer, sizeof (ifr_buffer)) < 0) {
			trace_log_tp(task_ptr, 0, LOG_ERR,
									("krt_ifread: %s: ioctl SIOCGIFNETMASK: %m",
									ifr_buffer.ifr_name));
		}
		else  {
			/* build a netmask from kernel info */
			sockaddr_ptr = sock2gated(&ifr_buffer.ifr_addr,
																unix_socksize(&ifr_buffer.ifr_addr, addr->sa_family));
			if (sockaddr_ptr)
				if_info_ptr->ifi_netmask = mask_locate(sockaddr_ptr);
			else
				trace_log_tp(task_ptr, 0, LOG_ERR,
										("krt_ifread: no network mask for %A (%s)",
										if_info_ptr->ifi_addr_local, ifr_buffer.ifr_name));

			}
#endif  /* SIOCGIFNETMASK */

    if (!if_info_ptr->ifi_addr_remote)
      if_info_ptr->ifi_addr_remote = sockdup(if_info_ptr->ifi_addr_local);
    /*
     * XXX what if we don't have a netmask?
     * or its wrong e.g., p2p2 bsdi
     */
    sockmask(if_info_ptr->ifi_addr_remote, if_info_ptr->ifi_netmask);
#endif  /* PROTO_INET */

	}

}



#ifdef PROTO_INET6
/*
 * do ioctls to get address specific info, such as dest address,
 * broadcast address,and netmask.
 */
static void
get_interface_address_info6(task *task_ptr, struct sockaddr_storage *addr, 
																struct _if_info *if_info_ptr,
																if_link *if_link_ptr, char *name, int sockfd)
{

  struct lifreq ifr_buffer;
  sockaddr_un *sockaddr_ptr;

  /* copy default info into structure */
  if_info_ptr->ifi_link = if_link_ptr;

  /* ignore interfaces from undesired families */
  switch ( addr->ss_family)  {
#ifdef PROTO_INET
    case AF_INET6:

      if_info_ptr->ifi_addr_local = sockdup(sock2gated(addr, unix_socksize(addr, addr->ss_family)));
      if_info_ptr->ifi_addr_remote = 0;
      if_info_ptr->ifi_addr_broadcast = 0;
      if_info_ptr->ifi_netmask = 0;

      /* copy the interface name into the ioctl buffer */
      strcpy(ifr_buffer.lifr_name, name);

#ifdef SIOCGLIFDSTADDR
    /*
     * if we are p2p, let's set the mtu and get the address
     * of the other side
     */
    if (BIT_TEST(if_info_ptr->ifi_state, IFS_POINTOPOINT)) {

			if ( if_info_ptr->ifi_mtu == DEFAULT_MTU )
				if_info_ptr->ifi_mtu = POINTOPOINT_MTU;

			if (task_ioctl(sockfd, siocgifdstaddr,
										(caddr_t) &ifr_buffer, sizeof (ifr_buffer)) < 0) {
				trace_log_tp(task_ptr, 0, LOG_ERR,
										("krt_ifread: %s: ioctl SIOCGIFDSTADDR: %m",
										ifr_buffer.lifr_name));
			}
			else {
				sockaddr_ptr = sock2gated(&ifr_buffer.lifr_dstaddr,
																	unix_socksize(&ifr_buffer.lifr_dstaddr, addr->ss_family));
				if (sockaddr_ptr) 
					if_info_ptr->ifi_addr_remote = sockdup(sockaddr_ptr);
				else
					trace_log_tp(task_ptr, 0, LOG_ERR,
											("krt_ifread: no destination address for %A (%s)",
											if_info_ptr->ifi_addr_local, ifr_buffer.lifr_name));

			}
		}
#endif   /* SIOCGIFDSTADDR */


#ifdef SIOCGLIFBRDADDR
    /*
     * if we are a broadcast medium, set the mtu and get
     * the broadcast address
     */
    if (BIT_TEST(if_info_ptr->ifi_state, IFS_BROADCAST)) {

      if( if_info_ptr->ifi_mtu == DEFAULT_MTU)
        if_info_ptr->ifi_mtu = ETHER_MTU;

			if (task_ioctl(sockfd, siocgifbrdaddr,
										(caddr_t) &ifr_buffer, sizeof (ifr_buffer)) < 0) {
				trace_log_tp(task_ptr, 0, LOG_ERR,
										("krt_ifread: %s: ioctl SIOCGIFBRDADDR: %m",
										ifr_buffer.lifr_name));
			}
			else {
				sockaddr_ptr = sock2gated(&ifr_buffer.lifr_broadaddr,
																	unix_socksize(&ifr_buffer.lifr_broadaddr, addr->ss_family));
				if (sockaddr_ptr)
					if_info_ptr->ifi_addr_broadcast = sockdup(sockaddr_ptr);
				else
					trace_log_tp(task_ptr, 0, LOG_ERR,
											("krt_ifread: no broadcast address for %A (%s)",
											if_info_ptr->ifi_addr_local, ifr_buffer.lifr_name));
			}
		}
#endif  /* SIOCGIFBRDADDR */

#ifdef  SIOCGLIFNETMASK
    /*
     * get the netmask address for the interface
     */
    if (task_ioctl(sockfd, siocgifnetmask,
                  (caddr_t) &ifr_buffer, sizeof (ifr_buffer)) < 0) {
			trace_log_tp(task_ptr, 0, LOG_ERR,
									("krt_ifread: %s: ioctl SIOCGIFNETMASK: %m",
									ifr_buffer.lifr_name));
		}
		else  {
			/* build a netmask from kernel info */
			sockaddr_ptr = sock2gated(&ifr_buffer.lifr_addr,
																unix_socksize(&ifr_buffer.lifr_addr, addr->ss_family));
			if (sockaddr_ptr)
          if_info_ptr->ifi_netmask = mask_locate(sockaddr_ptr);
			else
					trace_log_tp(task_ptr, 0, LOG_ERR,
											("krt_ifread: no network mask for %A (%s)",
											if_info_ptr->ifi_addr_local, ifr_buffer.lifr_name));

		}
#endif /* SIOCGIFNETMASK */

    if (!if_info_ptr->ifi_addr_remote)
      if_info_ptr->ifi_addr_remote = sockdup(if_info_ptr->ifi_addr_local);
    /*
     * XXX what if we don't have a netmask?
     * or its wrong e.g., p2p2 bsdi
     */
    sockmask(if_info_ptr->ifi_addr_remote, if_info_ptr->ifi_netmask);
#endif  /* PROTO_INET */

  }

}
#endif /* PROTO_INET6  */







/*
 * Let's do some ioctls to get the interface flags, mtu, and metrics.
 */
static void
get_interface_parameter_info(task *task_ptr, struct _if_info *if_info_ptr, char *name, int sockfd)
{
	struct ifreq ifr_buffer_ptr;

	/* copy interface name to ioctl structure */
	strcpy(ifr_buffer_ptr.ifr_name, name);

  /*
   * get the interface flags
   */
#ifdef SIOCGIFFLAGS 
	if (task_ioctl(sockfd, (u_long) siocgifflags,
								(char *) &ifr_buffer_ptr, sizeof (ifr_buffer_ptr)) < 0)  {
			trace_log_tp(task_ptr, 0, LOG_ERR,
									("krt_ifread: %s: ioctl SIOCGIFFLAGS: %m",
									ifr_buffer_ptr.ifr_name));
	}
	else
	 if_info_ptr->ifi_state = krt_if_flags(ifr_buffer_ptr.ifr_flags);
#else /* !SIOCGIFFLAGS */
	if_info_ptr->ifi_state = 0;
#endif /* !SIOCGIFFLAGS */

  /*
   * get the interface MTU
   */
#ifdef SIOCGIFMTU 
	bzero ((caddr_t) &ifr_buffer_ptr.ifr_ifru, sizeof (ifr_buffer_ptr.ifr_ifru));
	if (task_ioctl(sockfd, (u_long) siocgifmtu,
								(char *) &ifr_buffer_ptr, sizeof (ifr_buffer_ptr)) < 0) { 
		trace_log_tp(task_ptr, 0, LOG_ERR,
								("krt_ifread: %s: ioctl SIOCGIFMTU: %m, Gated using default mtu",
								ifr_buffer_ptr.ifr_name));
		if_info_ptr->ifi_mtu = DEFAULT_MTU;
	}
	else
	    	if_info_ptr->ifi_mtu = ifr_buffer_ptr.KRT_IFR_MTU;
#else /* !SIOCGIFMTU */
	if_info_ptr->ifi_mtu = DEFAULT_MTU;
#endif 

  /*
   * get the interface metrics
   */
#ifdef  SIOCGIFMETRIC     	    
	bzero ((caddr_t) &ifr_buffer_ptr.ifr_ifru, sizeof (ifr_buffer_ptr.ifr_ifru));
	if (task_ioctl(sockfd, (u_long) siocgifmetric,
								(char *) &ifr_buffer_ptr, sizeof (ifr_buffer_ptr)) < 0) { 
 		trace_log_tp(task_ptr, 0, LOG_ERR,
								("krt_ifread: %s: ioctl SIOCGIFMETRIC: %m",
								ifr_buffer_ptr.ifr_name));
		if_info_ptr->ifi_metric = 0;
 	}
	else
 		if_info_ptr->ifi_metric = ifr_buffer_ptr.ifr_metric;
#else  /* !SIOCGIFMETRIC */
	if_info_ptr->ifi_metric = 0;
#endif  /* !SIOCGIFMETRIC */

}



#ifdef PROTO_INET6
/*
 * Let's do some ioctls to get the interface flags, mtu, and metrics.
 */
static void 
get_interface_parameter_info6(task *task_ptr, struct _if_info *if_info_ptr, char *name, int sockfd)
{
  struct lifreq ifr_buffer_ptr;

  /* copy interface name to ioctl structure */
  strcpy(ifr_buffer_ptr.lifr_name, name);

  /*
   * get the interface flags
   */
#ifdef SIOCGIFFLAGS
	if (task_ioctl(sockfd, (u_long) siocgifflags,
								(char *) &ifr_buffer_ptr, sizeof (ifr_buffer_ptr)) < 0) {
		trace_log_tp(task_ptr, 0, LOG_ERR,
								("krt_ifread: %s: ioctl SIOCGIFFLAGS: %m",
                ifr_buffer_ptr.lifr_name));
		if_info_ptr->ifi_state = 0;
	}
	else 
   if_info_ptr->ifi_state = krt_if_flags(ifr_buffer_ptr.lifr_flags);
#else
  if_info_ptr->ifi_state = 0;
#endif

  /*
   * get the interface MTU
   */
#ifdef SIOCGIFMTU
  bzero ((caddr_t) &ifr_buffer_ptr.lifr_lifru, sizeof (ifr_buffer_ptr.lifr_lifru));
  if (task_ioctl(sockfd, (u_long) siocgifmtu,
             (char *) &ifr_buffer_ptr, sizeof (ifr_buffer_ptr)) < 0) {
      trace_log_tp(task_ptr,
                             0,
                             LOG_ERR,
                             ("krt_ifread: %s: ioctl SIOCGIFMTU: %m, Gated using default mtu",
                              ifr_buffer_ptr.lifr_name));
      if_info_ptr->ifi_mtu = DEFAULT_MTU;
      }
  else
        if_info_ptr->ifi_mtu = ifr_buffer_ptr.lifr_lifru.lifru_mtu;
#else
  if_info_ptr->ifi_mtu = DEFAULT_MTU;
#endif

  /*
   * get the interface metrics
   */
#ifdef  SIOCGIFMETRIC
  /* do an ioctl to get the interface metrics */
	bzero ((caddr_t) &ifr_buffer_ptr.lifr_lifru, sizeof (ifr_buffer_ptr.lifr_lifru));
	if (task_ioctl(sockfd, (u_long) siocgifmetric,
								(char *) &ifr_buffer_ptr, sizeof (ifr_buffer_ptr)) < 0) {
		trace_log_tp(task_ptr, 0, LOG_ERR,
								("krt_ifread: %s: ioctl SIOCGIFMETRIC: %m",
								ifr_buffer_ptr.lifr_name));
    if_info_ptr->ifi_metric = 0;
  }
  else
    if_info_ptr->ifi_metric = ifr_buffer_ptr.lifr_metric;
#else /* !SIOCGIFMETRIC */
  if_info_ptr->ifi_metric = 0;
#endif /* !SIOCGIFMETRIC */

}
#endif /* PROTO_INET6  */


int krt_ifread_v4 (flag_t save_task_state)
{
	static int sockfd = -1;

	struct ifconf ifc_buffer;
	struct ifreq  *ifr_buffer_ptr;
	struct _if_info if_info_buffer;
	if_link *if_plink = (if_link *) 0, *ifl_ptr;
	task *task_ptr = krt_task;
	char *cp, *ptr, name[32];    
	int isalias, slen, test_bit_set,interface_count = 0; 

	task_ptr = krt_task; 
	test_bit_set = 0;  
  isalias = FALSE; 

	siocgifconf = SIOCGIFCONF;
	siocgifaddr = SIOCGIFADDR;
	siocgifdstaddr = SIOCGIFDSTADDR;
	siocgifbrdaddr = SIOCGIFBRDADDR;
	siocgifnetmask = SIOCGIFNETMASK;
#ifdef SIOCGIFFLAGS
	siocgifflags = SIOCGIFFLAGS;
#endif /* SIOCGIFFLAGS */
#ifdef SIOCGIFMTU
	siocgifmtu = SIOCGIFMTU;
#endif /* SIOCGIFMTU */
#ifdef SIOCGIFMETRIC
	siocgifmetric = SIOCGIFMETRIC;
#endif /* SIOCGIFMETRIC */

	/* grab a socket for use with ioctl calls. Note task_get_socket checks 
     for test mode so have to reset bit. */
	if(sockfd == -1) {
		if(BIT_TEST(task_state, TASKS_TEST)) {
			test_bit_set = 1;
			BIT_RESET(task_state, TASKS_TEST);	
		}

		sockfd = task_floating_socket(task_ptr, 
																	task_get_socket(task_ptr, AF_INET, SOCK_DGRAM, 0),
																	"krt_ifread_task");
		if(test_bit_set)
			BIT_SET(task_state, TASKS_TEST);
	}

	if (krt_task->task_socket < 0) {
		return EBADF;
	}

	/* read the interfaces from the kernel */
	if( !read_interface_list(task_ptr, &ifc_buffer, sockfd)  )  {
		/* we got problems, cannot do successful ioctl call */
		trace_log_tp(task_ptr, 0, LOG_ERR, ("krt_ifread: ioctl SIOCGIFCONF: %m"));
		return errno;
	}

	/* write our status to the log */
	trace_tp(task_ptr, TR_KRT_IFLIST, TRC_NL_BEFORE,
					("krt_iflist: SIOCGIFCONF returns %u bytes", ifc_buffer.ifc_len));

	/* loop through all the data */
	for(ptr = ifc_buffer.ifc_buf; ptr < ifc_buffer.ifc_buf + ifc_buffer.ifc_len;) { 

			/* zero out temporary data structure for storing values from kernel */
			bzero( &if_info_buffer, sizeof (if_info_buffer));

			/* get pointer to next interface */
				ifr_buffer_ptr = (struct ifreq *) ptr;

			/* keep track of how many interfaces we have */
			interface_count++;

      /* We use the name for two distinct reasons. In GateD we have a one to many relationship
       with a physical interface and its one or more interface addresses. For this we need a
       name that has no alias. e.g. iprb0 and iprb0:1 both fall under the physical interface
       iprb0. For the ioctl calls we need an unmolested name.
      */
      strcpy(name, ifr_buffer_ptr->ifr_name);

      /* Remove the :n extension from the name */
      cp = index(name, ':');
      if (cp) {
        if (*(cp + 1) != '0')
            isalias = TRUE;
        *cp = (char)0;
      }

			/* xxx - dump the ifrp we just read */        
			if (TRACE_TP(krt_task, TR_KRT_IFLIST)) {      
				dump_ifrp(krt_task, ifr_buffer_ptr);                
			}                                             

			/* read interface specific info from kernel */
			get_interface_parameter_info(task_ptr, &if_info_buffer, ifr_buffer_ptr->ifr_name, sockfd);

		/*
     * Have to have a physical interface to link to
     * If no previous or previous name is different
     *
     * XXX the third check seems iffy, what if there is a new
     * XXX different name of the same length as the
     * XXX previous with a ':' in it
     *
     * naamato 5/12/99
     * By removing the ':' that should be fixed.  In the
     * above problem, an interface with ifrp->ifr_name
     * of "lan1:0" (not an alias) might get linked to
     * the previous piflp.
     *
     * Now, lan1, lan1:0, lan1:1, lan1:2, etc. mean the same
     * if_link.
     */

			if ( !(if_plink) 
					|| (strncmp(if_plink->ifl_name, ifr_buffer_ptr->ifr_name, IFNAMSIZ) 
					&& (isalias == FALSE))) {
				 /*
					* either no physical interface or the name doesn't
					* match, and it's not an alias
					*
					* xxx - krt_lladdr() is broke, we are using a
					* hacked krt_lladdr() in krt_lladdr_sunos4.c.
					* krt_lladdr() on sunos doesn't return correct llevel
					* addr info, causing the ifr_buffer_ptr info to be
					* munged.  not using this code does away with correct
					* ll info. so let's try to hack around it.
					*/
 
				slen = strlen(name);
				ifl_ptr = ifl_locate_name(name, slen);

				if_plink = ifl_addup(task_ptr, ifl_ptr,
						interface_count, if_info_buffer.ifi_state, 
						if_info_buffer.ifi_metric, 
						if_info_buffer.ifi_mtu, name,
						slen, krt_lladdr(ifr_buffer_ptr),
						(sockaddr_un *)0); 
	                        
				if (BIT_TEST(if_info_buffer.ifi_state, IFS_LOOPBACK)) {
						/* Set the loopback flag and mtu for this physical interface */
						BIT_SET(if_plink->ifl_state, IFS_LOOPBACK);
						if_info_buffer.ifi_mtu = LOOPBACK_MTU;
				}

			}

			/* read address information from kernel. */
			get_interface_address_info(task_ptr, &ifr_buffer_ptr->ifr_addr, 
					&if_info_buffer, if_plink, ifr_buffer_ptr->ifr_name, sockfd);

			if (isalias == FALSE)
				BIT_SET(if_info_buffer.ifi_state, IFS_ALIAS_PRIMARY);

			/* Add the logical interface structure to the ifap list */
			if_conf_addaddr(task_ptr, &if_info_buffer);	

			/* all done with that address let's do it again */
			ptr += sizeof(ifr_buffer_ptr->ifr_name) + addr_size(ifr_buffer_ptr);

		}
	return(1);
}



#ifdef PROTO_INET6
int krt_ifread_v6 (flag_t save_task_state)
{
	static int sockfd = -1;

  struct lifconf ifc_buffer;
  struct lifreq *ifr_buffer_ptr;
  struct _if_info if_info_buffer;
  if_link *if_plink = (if_link *) 0, *ifl_ptr;
  task *task_ptr;
  char *ptr, *cp, name[32];
	int isalias, slen, test_bit_set, interface_count = 0;

  task_ptr = krt_task;
	if_plink = (if_link *) 0;
  test_bit_set = 0;
  isalias = FALSE;

	siocgifconf = SIOCGLIFCONF;
	siocgifaddr = SIOCGLIFADDR;
	siocgifdstaddr = SIOCGLIFDSTADDR;
	siocgifbrdaddr = SIOCGLIFBRDADDR;
	siocgifnetmask = SIOCGLIFNETMASK;
	siocgifflags = SIOCGLIFFLAGS;
	siocgifmtu = SIOCGLIFMTU;
	siocgifmetric = SIOCGLIFMETRIC;
	ifc_buffer.lifc_family = AF_INET6;
	ifc_buffer.lifc_flags = 0;

  /* grab a socket for use with ioctl calls. Note task_get_socket checks
     for test mode so have to reset bit. */
  if(sockfd == -1) {
    if(BIT_TEST(task_state, TASKS_TEST)) {
      test_bit_set = 1;
      BIT_RESET(task_state, TASKS_TEST);
    }

    sockfd = task_floating_socket(task_ptr,
                                  task_get_socket(task_ptr, AF_INET6, SOCK_DGRAM, 0),
                                  "krt_ifread_task");
    if(test_bit_set)
      BIT_SET(task_state, TASKS_TEST);
  }

  if (krt_task->task_socket < 0) {
    return EBADF;
  }

  /* read the interfaces from the kernel */
  if( !read_interface_list6(task_ptr, &ifc_buffer, sockfd)  )  {
    /* we got problems, cannot do successful ioctl call */
    trace_log_tp(task_ptr, 0, LOG_ERR, ("krt_ifread: ioctl SIOCGIFCONF: %m"));
    return errno;
  }

	/* write our status to the log */
	trace_tp(task_ptr, TR_KRT_IFLIST, TRC_NL_BEFORE,
					("krt_iflist: SIOCGIFCONF returns %u bytes", ifc_buffer.lifc_len));

	/* loop through all the data */
	for(ptr = ifc_buffer.lifc_buf; ptr < ifc_buffer.lifc_buf + ifc_buffer.lifc_len;) {

		/* zero out temporary data structure for storing values from kernel */
		bzero( &if_info_buffer, sizeof (if_info_buffer));

		/* get pointer to next interface */
		ifr_buffer_ptr = (struct lifreq *) ptr;

		/* keep track of how many interfaces we have */
		interface_count++;

    /* We use the name for two distinct reasons. In GateD we have a one to many relationship
       with a physical interface and its one or more interface addresses. For this we need a
       name that has no alias. e.g. iprb0 and iprb0:1 both fall under the physical interface
       iprb0. For the ioctl calls we need an unmolested name.
    */
    strcpy(name, ifr_buffer_ptr->lifr_name);

    /* Remove the :n extension from the name */
    cp = index(name, ':');
    if (cp) {
      if (*(cp + 1) != '0')
          isalias = TRUE;
      *cp = (char)0;
    }


		/* xxx - dump the ifrp we just read */
		if (TRACE_TP(krt_task, TR_KRT_IFLIST)) {
			dump_ifrp(krt_task, ifr_buffer_ptr);
		}

		/* read interface specific info from kernel */
		get_interface_parameter_info6(task_ptr, &if_info_buffer, ifr_buffer_ptr->lifr_name, sockfd);

    /*
     * Have to have a physical interface to link to
     * If no previous or previous name is different
     *
     * XXX the third check seems iffy, what if there is a new
     * XXX different name of the same length as the
     * XXX previous with a ':' in it
     *
     * naamato 5/12/99
     * By removing the ':' that should be fixed.  In the
     * above problem, an interface with ifrp->ifr_name
     * of "lan1:0" (not an alias) might get linked to
     * the previous piflp.
     *
     * Now, lan1, lan1:0, lan1:1, lan1:2, etc. mean the same
     * if_link.
     */

      if ( !(if_plink)
          || (strncmp(if_plink->ifl_name, ifr_buffer_ptr->lifr_name, IFNAMSIZ)
          && (isalias == FALSE))) {
         /*
          * either no physical interface or the name doesn't
          * match, and it's not an alias
          *
          * xxx - krt_lladdr() is broke, we are using a
          * hacked krt_lladdr() in krt_lladdr_sunos4.c.
          * krt_lladdr() on sunos doesn't return correct llevel
          * addr info, causing the ifr_buffer_ptr info to be
          * munged.  not using this code does away with correct
          * ll info. so let's try to hack around it.
          */

        slen = strlen(name);
        ifl_ptr = ifl_locate_name(name, slen);

        if_plink = ifl_addup(task_ptr, ifl_ptr,
            interface_count, if_info_buffer.ifi_state,
            if_info_buffer.ifi_metric,
            if_info_buffer.ifi_mtu, name,
            slen, krt_lladdr(ifr_buffer_ptr),
            (sockaddr_un *)0);
 
        if (BIT_TEST(if_info_buffer.ifi_state, IFS_LOOPBACK)) {
					/* Set the loopback flag and mtu for this physical interface */
					BIT_SET(if_plink->ifl_state, IFS_LOOPBACK);
					if_info_buffer.ifi_mtu = LOOPBACK_MTU;
				}

      }
			else
					interface_count--;

      /* read address information from kernel. */
			get_interface_address_info6(task_ptr, &ifr_buffer_ptr->lifr_addr,
																	&if_info_buffer, if_plink, 
																	ifr_buffer_ptr->lifr_name, sockfd);

      if (isalias == FALSE)
        BIT_SET(if_info_buffer.ifi_state, IFS_ALIAS_PRIMARY);

      /* Add the logical interface structure to the ifap list */
      if_conf_addaddr(task_ptr, &if_info_buffer);

      /* all done with that address let's do it again */
			ptr += sizeof(struct lifreq) ;

  }
  return(1);
}
#endif /* PROTO_INET6 */

/* Dump interface information */
static void
dump_ifrp(tp, ifrp)
   task         *tp;
   struct ifreq *ifrp;
{
   int size = unix_socksize(&ifrp->ifr_addr, ifrp->ifr_addr.sa_family);
   const char *cp = trace_value(task_domain_bits, ifrp->ifr_addr.sa_family);

   tracef("krt_ifread: name %.*s  length %u  family %u",
     IFNAMSIZ, ifrp->ifr_name,
     size,
     ifrp->ifr_addr.sa_family);
   if (cp) {
  tracef("(%s)", cp);
   }

   switch (ifrp->ifr_addr.sa_family) {
#ifdef  PROTO_INET
    case AF_INET:
    {
  struct sockaddr_in *sinp = (struct sockaddr_in *) ((void_t) &ifrp->ifr_addr);

  tracef("  port %u  addr %A",
         ntohs(sinp->sin_port),
         sockbuild_in(0, sinp->sin_addr.s_addr));
    }
  break;
#endif  /* PROTO_INET */

#ifdef  PROTO_ISO
    case AF_ISO:
    {
  struct sockaddr_iso *siso = (struct sockaddr_iso *) &ifrp->ifr_addr;
  byte *dp = (byte *) siso->siso_pad;

  tracef("  addr %A",
         siso->siso_addr.isoa_genaddr,
         siso->siso_addr.isoa_len);

  if (siso->siso_plen) {
      tracef("  psel %A",
       sockbuild_ll(0, dp, siso->siso_plen));
      dp += siso->siso_plen;
  }
  if (siso->siso_slen) {
      tracef("  ssel %A",
       sockbuild_ll(0, dp, siso->siso_slen));
      dp += siso->siso_slen;
  }
  if (siso->siso_tlen) {
      tracef("  tsel %A",
       sockbuild_ll(0, dp, siso->siso_tlen));
  }
    }
  break;
#endif  /* PROTO_ISO */

#ifdef  SOCKADDR_DL
    case AF_LINK:
    {
  struct sockaddr_dl *sdl = (struct sockaddr_dl *) &ifrp->ifr_addr;
  byte *dp = (byte *) sdl->sdl_data;
 
  tracef("  index %u  type %u",
         sdl->sdl_index,
         sdl->sdl_type);
  if (sdl->sdl_nlen) {
      tracef("  name %.*s",
       sdl->sdl_nlen, dp);
      dp += sdl->sdl_nlen;
  }
  if (sdl->sdl_alen) {
      tracef("  addr %A",
       sockbuild_ll(0, dp, sdl->sdl_alen));
      dp += sdl->sdl_alen;
  }
  if (sdl->sdl_slen) {
      tracef("  selector %A",
       sockbuild_ll(0, dp, sdl->sdl_slen));
  }
    }
  break;
#endif  /* SOCKADDR_DL */

    default:
  tracef("  addr %A",
         sockbuild_ll(0,
          (byte *) ifrp->ifr_addr.sa_data,
          (size_t) (size - ((byte *) ifrp->ifr_addr.sa_data - (byte *) &ifrp->ifr_addr))));
   }
   trace_only_tp(tp, TRC_NL_BEFORE, (NULL));
}




int krt_ifread (flag_t save_task_state)
/* int krt_ifread (save_task_state, flag_t) */
{

	task *task_ptr = krt_task;

	/* set interface lists to known state, IFC_NOCHANGE */
	if_conf_open(task_ptr, TRUE);

  krt_ifread_v4(save_task_state);
#ifdef PROTO_INET6
#ifdef SIOCGLIFCONF
  krt_ifread_v6(save_task_state);
#endif  /* PROTO_INET6  */
#endif  /* SIOCGLIFCONF  */

	if_conf_close(task_ptr, FALSE);
}

