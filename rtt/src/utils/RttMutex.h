/****************************************************************/
/*							        */
/* RttMutex.h    						*/
/*							    	*/
/* Copyright 1994 The University of British Columbia		*/
/* No part of this code may be sold or used for commercial	*/
/* purposes without permission.					*/
/*							    	*/
/*							    DXF */
/****************************************************************/

#ifndef _RTTMUTEX_H__
#define _RTTMUTEX_H__

/*
   Get a new mutex lock.
 */

int	RttNewMutex(u_long *mutexvar);


/*
   Lock the given mutex.
 */

int	RttMutexLock(u_long mutexvar);

/*
   Unlock the given mutex.  Returns RTTFAILED
   if the mutex is not currently locked.
 */

int	RttMutexUnlock(u_long mutexvar);


/*
   Free up the given mutex.
 */

int	RttReapMutex(u_long mutexvar);

#endif

