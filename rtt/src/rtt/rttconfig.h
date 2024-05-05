/****************************************************************************
 * 
 * rttconfig.h
 * 
 * RT THreads configuration parameters.
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

#ifndef RTTCONFIG_H
#define RTTCONFIG_H

#define MAXTNAMELEN 32       /* max thread name length */

/* highest resolution available on most UNIX systems.  */
#define TICKINTERVAL   10000 

/* defines maximum number of threads in the system     */
#define NUMBTCBS 4096  /* MUST be a power of 2          */

/* defines the number of priorities supported          */
#define NUM_READYQ_PRIORITIES  32

#endif /* RTTCONFIG_H */
