/****************************************************************/
/*							        */
/* RttCommon.c							*/
/*							    	*/
/* Common utilities for use with the RT Threads package		*/
/*							    	*/
/* Copyright 1994 The University of British Columbia		*/
/* No part of this code may be sold or used for commercial	*/
/* purposes without permission.					*/
/*							    	*/
/*							    DXF */
/****************************************************************/

#include "rtthreads.h"
#include "RttCommon.h"

#define USECINSEC	1000000


int RttSleep(unsigned int seconds)
{
  RttTimeValue	now;
  RttThreadId	me;
  RttSchAttr	myAttr;
  int		status;
  
  me = RttMyThreadId();
  status = RttGetThreadSchedAttr(me, &myAttr);
  status = RttGetTimeOfDay(&now);
  now.seconds += seconds;
  myAttr.startingtime = now;
  status = RttSetThreadSchedAttr(me, myAttr);
  return RTTOK;
}


int RttUSleep(unsigned int microseconds)
{
  RttTimeValue	now;
  RttThreadId	me;
  RttSchAttr	myAttr;
  int		status;
  
  me = RttMyThreadId();
  status = RttGetThreadSchedAttr(me, &myAttr);
  status = RttGetTimeOfDay(&now);
  now.microseconds += (microseconds % USECINSEC);
  now.seconds += (microseconds / USECINSEC);
  if (now.microseconds >= USECINSEC)
  {
    now.microseconds -= USECINSEC;
    now.seconds += 1;
  }
  myAttr.startingtime = now;
  status = RttSetThreadSchedAttr(me, myAttr);
  return RTTOK;
}

  
int RttSleepFor(RttTimeValue sleepTime)
{
  RttTimeValue	now;
  RttThreadId	me;
  RttSchAttr	myAttr;
  int		status;
  
  me = RttMyThreadId();
  status = RttGetThreadSchedAttr(me, &myAttr);
  status = RttGetTimeOfDay(&now);
  now.microseconds += sleepTime.microseconds;
  if (now.microseconds >= USECINSEC)
  {
    now.microseconds -= USECINSEC;
    now.seconds += 1;
  }
  now.seconds += sleepTime.seconds;
  myAttr.startingtime = now;
  status = RttSetThreadSchedAttr(me, myAttr);
  return RTTOK;
}

  
int RttSleepThread(RttThreadId sleeper, int seconds)
{
  RttTimeValue	now;
  RttSchAttr	sleeperAttr;
  int		status;
  
  status = RttGetThreadSchedAttr(sleeper, &sleeperAttr);
  if (status != RTTOK)
  {
    return status;
  }
  
  status = RttGetTimeOfDay(&now);
  now.seconds += seconds;
  sleeperAttr.startingtime = now;
  status = RttSetThreadSchedAttr(sleeper, sleeperAttr);
  return status;
}



int RttUSleepThread(RttThreadId sleeper, int microseconds)
{
  RttTimeValue	now;
  RttSchAttr	sleeperAttr;
  int		status;
  
  status = RttGetThreadSchedAttr(sleeper, &sleeperAttr);
  if (status != RTTOK)
  {
    return status;
  }
  
  status = RttGetTimeOfDay(&now);
  now.microseconds += (microseconds % USECINSEC);
  now.seconds += (microseconds / USECINSEC);
  if (now.microseconds >= USECINSEC)
  {
    now.microseconds -= USECINSEC;
    now.seconds += 1;
  }
  sleeperAttr.startingtime = now;
  status = RttSetThreadSchedAttr(sleeper, sleeperAttr);
  return status;
}

int RttSleepThreadFor(RttThreadId sleeper, RttTimeValue sleepTime)
{
  RttTimeValue	now;
  RttSchAttr	sleeperAttr;
  int		status;
  
  status = RttGetThreadSchedAttr(sleeper, &sleeperAttr);
  if (status != RTTOK)
  {
    return status;
  }
  
  status = RttGetTimeOfDay(&now);
  now.microseconds += sleepTime.microseconds;
  if (now.microseconds >= USECINSEC)
  {
    now.microseconds -= USECINSEC;
    now.seconds += 1;
  }
  now.seconds += sleepTime.seconds;
  sleeperAttr.startingtime = now;
  status = RttSetThreadSchedAttr(sleeper, sleeperAttr);
  return status;
}



int RttSuspend(void)
{
  RttThreadId	me;
  RttSchAttr	myAttr;
  int		status;
  
  me = RttMyThreadId();
  status = RttGetThreadSchedAttr(me, &myAttr);
  myAttr.startingtime = RTTINFINITE;
  status = RttSetThreadSchedAttr(me, myAttr);
  return RTTOK;
}




int RttResume(RttThreadId thread)
{
  RttSchAttr	threadAttr;
  int		status;
  RttTimeValue	now;
  RttTimeValue	infinite = RTTINFINITE;
  
  
  status = RttGetThreadSchedAttr(thread, &threadAttr);
  if (status != RTTOK)
  {
    return status;
  }
  if (memcmp((char *)&threadAttr.startingtime, (char *)&infinite,
	     sizeof(RttTimeValue)) != 0)
  {
    return RTTFAILED;
  }
  
  RttGetTimeOfDay(&now);
  threadAttr.startingtime = now;
  status = RttSetThreadSchedAttr(thread, threadAttr);
  return status;
}
