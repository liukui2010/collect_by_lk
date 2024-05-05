/****************************************************************/
/*							        */
/* RttCommon.h  						*/
/*							    	*/
/* Copyright 1994 The University of British Columbia		*/
/* No part of this code may be sold or used for commercial	*/
/* purposes without permission.					*/
/*							    	*/
/*							    DXF */
/****************************************************************/

#ifndef _RTTCOMMON_H__
#define _RTTCOMMON_H__

/*
   Sleep routines.

   RttSleep() causes the calling thread to be suspended for the number
   of seconds given in the argument.  It is similar to the unix
   sleep(3V) function.

   RttUSleep() causes the calling thread to be suspended for the number
   of microseconds given in the argument.  It is similar to the unix
   usleep(3) function.  NOTE:  The granularity of the system clock
   will be a lower bound on the minimum amount of time you can
   actually sleep.

   RttSleepFor() causes the calling thread to be suspended for the
   amount (seconds and microseconds) of time given in the argument.

   The RttSleepThread variants are designed to put the given thread to
   sleep for the specified amount of time.  Since the other thread is
   (obviously) not currently running, it is either already asleep or
   of a lower priority than the current thread.  The RttSleepThread
   routines are therefore generally designed to reset the wakeup time
   of an already sleeping thread, and are therefore similar to
   ReSleep() functions.  Putting a lower priority thread to sleep
   won't accomplish much unless the currently running thread becomes
   blocked in some fashion or goes to sleep itself.

   RttSleepThread() will put the thread given in the first argument
   to sleep for the number of seconds given in the second argument.
   If the thread is already asleep, its wakeup time will be adjusted
   so that it wakes up after the given number of seconds.

   RttUSleepThread() will put the thread given in the first argument
   to sleep for the number of microseconds given in the second argument.
   If the thread is already asleep, its wakeup time will be adjusted
   so that it wakes up after the given number of microseconds.

   RttSleepThreadFor() will put the thread given in the first argument
   to sleep for amount of time given in the second argument.  If the
   thread is already asleep, its wakeup time will be adjusted so
   that it wakes up after the given time.

   RttSleep() and its variants always return RTTOK.
   RttSleepThread() and its vairants return RTTOK if successful or
   RTTNOSUCHTHREAD if the thread to be slept does not exist. */

int RttSleep(unsigned int seconds);
int RttUSleep(unsigned int microseconds);
int RttSleepFor(RttTimeValue sleepTime);
int RttSleepThread(RttThreadId sleeper, int seconds);
int RttUSleepThread(RttThreadId sleeper, int microseconds);
int RttSleepThreadFor(RttThreadId sleeper, RttTimeValue sleepTime);


/*
   Suspend/Resume routines.

   RttSuspend() suspends the calling process until another process
   awakens it with a call to RttResume().

   RttSuspend() always returns RTTOK.

   RttResume() will return RTTOK if successful, RTTFAILED if the
   thread was not suspended, or RTTNOSUCHTHREAD if the thread to be
   resumed does not exist.
  */

int RttSuspend(void);
int RttResume(RttThreadId thread);


#endif

