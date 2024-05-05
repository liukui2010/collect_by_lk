/****************************************************************************
 * 
 * rttattr.h
 * 
 * Header file for scheduling attributes module.
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

#ifndef _RTTATTR_H
#define _RTTATTR_H

/*
 * Note that CompTime_ only works for cmp values of !=, >, and <.
 */
#define CompTime_(t1, t2, cmp)					\
	((t1).seconds cmp (t2).seconds ||			\
	 (t1).seconds == (t2).seconds &&			\
	 (t1).microseconds cmp (t2).microseconds)

#define EqualTime_(t1, t2)					\
	((t1).seconds == (t2).seconds &&			\
	 (t1).microseconds == (t2).microseconds)


int SetTimeout_(TCB *, RttTimeValue);


#endif /* _RTTATTR_H */
