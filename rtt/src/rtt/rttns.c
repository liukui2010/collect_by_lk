/****************************************************************************
 * 
 * rttns.c
 * 
 * Name server thread module.
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

#include "rttkernel.h"

/*------------------------------------------------------------------------
 * RttCreateNS  --  create a thread to serve as nameserver
 *
 * Notes:           uses instance number of 0 so it can be identified
 *------------------------------------------------------------------------
 */
int RttCreateNS(RttThreadId *thread, void(*addr)(), int stksize, 
		char *name, void *arg, RttSchAttr sched_attr, int level)
{
  if (GetNameServerCreated()) {
    return (RTTFAILED);
  }
  if (RttCreate(thread, addr, stksize, name, arg, sched_attr, level) == RTTOK){
    SetInstance(getTcbFromThreadId(*thread),0);
    SetThreadIdInstance(*thread, 0);
    SetNameServerId(*thread);
    SetNameServerCreated(1);
    return(RTTOK); 
  }
  else return (RTTFAILED);
}

/*------------------------------------------------------------------------
 * RttGetNS  --  get thread id of nameserver
 *------------------------------------------------------------------------
 */
int RttGetNS(unsigned long ipAddr, unsigned short portNo, 
	     RttThreadId *nServerId) 
{
  SetThreadIdIpAddr(*nServerId, ipAddr);
  SetThreadIdPortNo(*nServerId, portNo);
  SetThreadIdInstance(*nServerId, 0);
  SetThreadIdIndex(*nServerId, 0);
  
  return(RTTOK);
}
