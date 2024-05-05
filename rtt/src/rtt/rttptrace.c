/****************************************************************************
 * 
 * rttptrace.c
 * 
 * Stack overflow detection module.
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

#ifdef PTRACE
#include <fcntl.h>
#include <errno.h>
#include "rttkernel.h"

#define MAX_WATCH_VALUES 25

void PTraceInit_();
void PTraceSync_();
void PTraceEnd_();

int *WatchPointer[MAX_WATCH_VALUES], WatchValue[MAX_WATCH_VALUES], WatchCounter;

static char	*baseTraceFile = "/tmp/ptrace";
static char	traceFile[256];
int		traceFD_;

/* Assumed to be called *before* threads have started */
void PTraceInit_()
{
  pid_t	mypid;
  
  mypid = getpid();

  sprintf(traceFile, "%s.%d", baseTraceFile, (int)mypid);
  traceFD_ = open(traceFile, O_CREAT | O_TRUNC |  O_WRONLY, 0664);
  if (traceFD_ < 0)
  {
    printf("Can't open trace file %s, errno was %d\n", traceFile, errno);
    SysExit_(-1);
  }
  fprintf(stderr, "PTRACE:  Trace file %s\n", traceFile);
  fflush(stderr);
}

void PTraceSync_()
{
  RttBeginCritical();
  fsync(traceFD_);
  RttEndCritical();
}

void PTraceEnd_()
{
  PTraceSync_();
  close(traceFD_);
}


int CheckStack(unsigned long limit)
{
  int approx;
  
  return ((((unsigned long)&approx) < limit) ? 1 : 0);
}
#endif /* PTRACE */
