/*
 * RttThreadId.h
 *
 * Copyright 1994 The University of British Columbia
 * No part of this code may be sold or used for commercial
 * purposes without permission.	
 *
 * Authour: Roland Mechler
 *
 */

#ifndef _RTTHREADID_H
#define	_RTTHREADID_H

#ifndef RTT_KEA
#include <sys/types.h>
#ifndef	WIN32
#include <sys/socket.h>  /* otherwise, compiler complains about rpc.h */
#include <netinet/in.h>
#include <rpc/rpc.h>
#else /* WIN32 */
#include <winsock.h>
/*typedef int bool_t;*/
#define bool_t int
#endif /* WIN32 */
#endif /* RTT_KEA */

#define INSTANCE_BITS 4

#define PORTNO_MASK    0x0000ffff
#define PORTNO_SHIFT   16
#define INSTANCE_SHIFT 12
#define INSTANCE_MASK  0xffff0fff
#define INDEX_MASK     0xfffff000


struct RttThreadId {
	unsigned long hid;
	unsigned long lid;
};
typedef struct RttThreadId RttThreadId;
#ifndef RTT_KEA
bool_t xdr_RttThreadId();
#endif /* RTT_KEA */

#define GetIpAddrFromThreadId(X)    ((X).hid)
#define GetPortNoFromThreadId(X)    ((X).lid >> PORTNO_SHIFT)
#define GetInstanceFromThreadId(X) \
  (((X).lid & ~INSTANCE_MASK) >> INSTANCE_SHIFT)
#define GetIndexFromThreadId(X)     ((X).lid & ~INDEX_MASK)

#define SetThreadIdIpAddr(X,V)   ((X).hid = (V))
#define SetThreadIdPortNo(X,V)  \
  ((X).lid = ((V) << PORTNO_SHIFT) | ((X).lid & PORTNO_MASK))
#define SetThreadIdInstance(X,V) \
  ((X).lid = ((V) << INSTANCE_SHIFT) | ((X).lid & INSTANCE_MASK))
#define SetThreadIdIndex(X,V)    ((X).lid = (V) | ((X).lid & INDEX_MASK))




#define RTTTHREADEQUAL(X,Y) \
((GetIpAddrFromThreadId(X) == GetIpAddrFromThreadId(Y)) && \
 (GetPortNoFromThreadId(X) == GetPortNoFromThreadId(Y)) && \
 (GetInstanceFromThreadId(X) == GetInstanceFromThreadId(Y)) && \
 (GetIndexFromThreadId(X) == GetIndexFromThreadId(Y)))

#endif /* _RTTHREADID_H */
