/****************************************************************************
 * 
 * rttsem.h
 * 
 * Header file for semaphore module.
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

#ifndef RTTSEM_H
#define RTTSEM_H

#define SEM_MAGIC_NUMBER 0xabcadaba

typedef struct semaphore
    {
      int magicNumb;
      TCB *firstBlockedThread;
      TCB *lastBlockedThread;
      int semaphValue;
      int mode;
    } SemaphoreStruct;

#define SEMTCBINIT( TCB ) {               \
  SetSemaphPrev(TCB, NULL);               \
  SetSemaphNext(TCB, NULL);               \
  SetSemaphore(TCB, NULL);                \
}

#define SEMAPHINRANGE(X) (((X) >= 0) && ((X) < NUMBSEMAPHORES))

void SemCleanup_(TCB *tcbPtr);

#endif /* RTTSEM_H */
