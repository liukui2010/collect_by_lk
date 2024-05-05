/****************************************************************************
 * 
 * rttremoteitc.h
 * 
 * Header file for remote (cross address space) inter-thread communication
 * module.
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

#ifndef RTTREMOTEITC_H
#define RTTREMOTEITC_H

int ExecuteRemoteRequest_(RttThreadId to, u_int slen, void *sData, 
			  u_int *rlen, void *rData);

#endif /* RTTREMOTEITC_H */

