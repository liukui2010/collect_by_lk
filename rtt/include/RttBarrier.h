/****************************************************************/
/*							        */
/* RttBarrier.h 						*/
/*							    	*/
/* Copyright 1994 The University of British Columbia		*/
/* No part of this code may be sold or used for commercial	*/
/* purposes without permission.					*/
/*							    	*/
/*							    DXF */
/****************************************************************/

#ifndef _RTTBARRIER_H_
#define _RTTBARRIER_H_

typedef unsigned long *RttBarrier;

int RttNewBarrier(RttBarrier *barrier, int size);
int RttWaitOnBarrier(RttBarrier barrier, int status);
int RttReapBarrier(RttBarrier barrier);
int RttGrowBarrier(RttBarrier barrier);
int RttShrinkBarrier(RttBarrier barrier);


#endif
