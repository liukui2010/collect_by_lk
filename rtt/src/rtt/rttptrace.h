/****************************************************************************
 * 
 * rttptrace.h
 * 
 * RT Threads Ptrace facility.
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

#ifndef RTTPTRACE_H
#define RTTPTRACE_H

#ifdef PTRACE
extern int traceFD_;

#define PTRACE_NAMEOFFSET  9
#define PtraceTname(X) (GetTname(X)-PTRACE_NAMEOFFSET)

#define PTRACE_INIT() PTraceInit_()

#define PTRACE_CREATE(X)	{ \
    write(traceFD_, "C: [", 4); \
    write(traceFD_, (const void *)PtraceTname(X), strlen(PtraceTname(X))); \
    write(traceFD_, "]\n", 2); \
    }

#define PTRACE_START(X)		{ \
    write(traceFD_, "B: [", 4); \
    write(traceFD_, (const void *)PtraceTname(X), strlen(PtraceTname(X))); \
    write(traceFD_, "]\n", 2); \
    }

#define PTRACE_EXIT(X)		{ \
    write(traceFD_, "X: [", 4); \
    write(traceFD_, (const void *)PtraceTname(X), strlen(PtraceTname(X))); \
    write(traceFD_, "]\n", 2); \
    }

#define PTRACE_CTXTSW(X,V)	{ \
      if (((X) != TNULL) && ((V) != TNULL)) { \
        write(traceFD_, "CTX:\n\ts[", 8); \
        write(traceFD_, PtraceTname(X), 8); \
        write(traceFD_, "]\n\tr[", 5); \
        write(traceFD_, PtraceTname(V), 8); \
        write(traceFD_, "]\n", 2); \
      } \
    }

#define PTRACE_SIGIO()	{ \
    write(traceFD_, "SIO\n", 4); \
    }

#define PTRACE_STOMP()	{\
     write(traceFD_, "STOMP\n", 6); \
     }

#define PTRACE_END() PTraceEnd_()

#define PTRACE_FILLMEM(X) { \
      int i; \
      int *lp = (int *)GetStmembeg(X); \
      for (i = 0; i < (GetStackSize(X) / sizeof(int)); i++) \
      { \
	*lp = 0xfeedface; \
	lp++; \
      } \
    }

#define PTRACE_NAMEPREFIX(X) { \
      sprintf(GetTname(X), "%.8x ", (int)(X)); \
      SetTname(X, GetNameArea(X)+9); \
    }

#define PTRACE_SYNC() PTraceSync_()

#define PTRACE_CHECK(X,S) { \
      if ((X) != TNULL) { \
        if (CheckStack(GetStmembeg(X) + 8)) { \
          { \
	    int statusp = 0; \
            RttBeginCritical(); \
            printf("Stack overflow %s\n", S); \
	    printf("Offending TCB: %x\n", X); \
	    fsync(traceFD_); \
            *((int *)statusp) = 1; \
          } \
        } \
      } \
    }

#define PTRACE_WATCH() { \
      if (WatchCounter) { \
        { \
          int lc; \
          for (lc = 0; lc < WatchCounter; lc++) \
            { \
	      if (*WatchPointer[lc] != WatchValue[lc]) { \
	        PTRACE_STOMP(); \
	      } \
            } \
        } \
      } \
    }

#define PTRACE_SYSMALLOC(X,Y) { \
      Y = malloc(X + 128); \
      return ((void *)((char *)Y + 16)); \
    }

#define PTRACE_MALLOC(X,Y) { \
      Y = malloc(X + 128); \
      LEAVINGOS; \
      return ((void *)((char *)Y + 16)); \
    }

#define PTRACE_SYSFREE(X)  { \
      free((char *)mem - 16); \
      return; \
    }

#define PTRACE_FREE(X)  { \
      free((char *)mem - 16); \
      LEAVINGOS; \
      return; \
    }

#define PTRACE_REALLOC(X,Y,Z)  { \
      Z = (void *)realloc((char *)(X) - 16, (Y) + 128); \
      LEAVINGOS; \
      return ((void *)((char *)(Z) + 16)); \
    }

#define PTRACE_CALLOC(X,Y)  { \
      Y = (void *)RttMalloc(X); \
      memset(Y, 0, X); \
      return (Y); \
    }

#else
#define PTRACE_NAMEOFFSET  0
#define PTRACE_INIT() 
#define PTRACE_CREATE(X) 
#define PTRACE_START(X) 
#define PTRACE_EXIT(X) 
#define PTRACE_CTXTSW(X,V) 
#define PTRACE_SIGIO() 
#define PTRACE_END() 
#define PTRACE_FILLMEM(X) 
#define PTRACE_NAMEPREFIX(X) 
#define PTRACE_SYNC() 
#define PTRACE_CHECK(X,S) 
#define PTRACE_WATCH() 
#define PTRACE_SYSMALLOC(X,Y) 
#define PTRACE_MALLOC(X,Y) 
#define PTRACE_SYSFREE(X) 
#define PTRACE_FREE(X) 
#define PTRACE_REALLOC(X,Y,Z) 
#define PTRACE_CALLOC(X,Y) 
#endif /* PTRACE */

#endif /* RTTPTRACE_H */
