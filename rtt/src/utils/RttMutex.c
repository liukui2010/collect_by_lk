/****************************************************************/
/*							        */
/* RttMutex.c							*/
/*							    	*/
/* Simple mutex locks, implemented using semaphores.		*/
/*							    	*/
/* Copyright 1994 The University of British Columbia		*/
/* No part of this code may be sold or used for commercial	*/
/* purposes without permission.					*/
/*							    	*/
/*							    DXF */
/****************************************************************/

#include "rtthreads.h"
#include "RttMutex.h"

int RttNewMutex(u_long *mutexvar)
{
  RttSem	*mutexSem;
  int		status;

  mutexSem = (RttSem *)RttMalloc(sizeof(RttSem));
  if (mutexSem == NULL)
    return RTTFAILED;
  
  status = RttAllocSem(mutexSem, 1, RTTPRIORITY);

  if (status == RTTOK)
  {
    *mutexvar = (u_long)mutexSem;
  }
  else
  {
    *mutexvar = 0;
  }
  
  return status;
}


int RttMutexLock(u_long mutexvar)
{
  RttSem	mutexSem;
  
  mutexSem = *(RttSem *)mutexvar;
  return (RttP(mutexSem));
}


int RttMutexUnlock(u_long mutexvar)
{
  RttSem	mutexSem;
  int		mutexState;
  int		status;

  mutexSem = *(RttSem *)mutexvar;
  status = RttSemValue(mutexSem, &mutexState);			    /* Check to make sure the mutex was actually locked	 */
  if ((status == RTTOK) && (mutexState < 1))
  {
    return (RttV(mutexSem));
  }
  return RTTFAILED;
}


int RttReapMutex(u_long mutexvar)
{
  RttSem	mutexSem;
  
  mutexSem = *(RttSem *)mutexvar;
  if (RttFreeSem(mutexSem) == RTTOK)
  {
    RttFree((char *)mutexvar);
    return RTTOK;
  }
  return RTTFAILED;
}


