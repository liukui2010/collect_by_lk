/****************************************************************************
 * 
 * rttkernel.h
 * 
 * Header file included by all "RT Threads kernel" modules.
 * 
 ***************************************************************************
 * 
 * This code is Copyright 1994, 1995, 1996 by the Department of Computer
 * Science, University of British Columbia, British Columbia, Canada.
 * 
 * No part of of this code may be sold or used for any commercial purposes
 * without the expressed written permission of the University of
 * British Columbia.
 * 
 * RT Threads may be freely used, copied, modified, or distributed for
 * noncommercial purposes, provided that this copyright notice is
 * included in all sources.
 * 
 * RT Threads is provided as is.  The UBC Department of Computer Science
 * makes no warranty as to the correctness or fitness for use of the
 * RT Threads code or environment.
 * 
 ***************************************************************************
 */

#ifndef RTTKERNEL_H
#define RTTKERNEL_H

#include "rtthreads.h"

#ifdef	WIN32
  #include <winsock.h>
  #include <time.h>
#else /* not WIN32 */
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#ifdef ibm
  #include <sys/select.h>
  #include <fcntl.h>
  #include <unistd.h>
#else
#include <sys/fcntl.h>
#endif /* ibm */
#include <netdb.h>
#include <netinet/in.h>
#endif /* WIN32 */
#include <errno.h>
#include <signal.h>
#include <assert.h>

#include "rttconfig.h"
#include "rttptrace.h"
#include "rtttypes.h"
#include "rttattr.h"
#include "rttmem.h"
#include "rttsem.h"
#include "rttio.h"
#include "rttitc.h"
#include "rttreadyqueue.h"
#include "rttsched.h"
#include "rttqueuemgmt.h"
#include "rttthreadmgmt.h"

#endif /* RTTKERNEL_H */
