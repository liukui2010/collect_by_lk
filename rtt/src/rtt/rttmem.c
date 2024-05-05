/****************************************************************************
 * 
 * rttmem.c
 * 
 * Memory allocation module.
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


#define _FILE_OFFSET_BITS 64
/*#define __USE_FILE_OFFSET64 */

#ifdef RTT_MEM_DEBUG
#undef RTT_MEM_DEBUG
#define USE_MEM_DEBUGGING
#else
#define USE_MEM_DEBUGGING
#endif


#include <stdlib.h> 

#ifndef USE_RTTTRACING
#define USE_RTTTRACING
#endif

#include "rttkernel.h"

/*------------------------------------------------------------------------
 * SysMalloc_  --  allocate "size" bytes of memory using malloc(), when
 *                already in OS context
 *------------------------------------------------------------------------
 */
void *SysMalloc_(int size)
{
  void *rv;

  PTRACE_SYSMALLOC(size,rv);
  
  rv = malloc(size);
  return(rv);
}

/*------------------------------------------------------------------------
 * RttMalloc  --  allocate "size" bytes of memory using malloc(), called
 *                in OS context to prevent context switches
 *------------------------------------------------------------------------
 */
void *RttMalloc(int size)
{
  void *rv;

  ENTERINGOS;

  PTRACE_SYSMALLOC(size,rv);

  rv = malloc(size);
  LEAVINGOS;

  return(rv);
}

/*------------------------------------------------------------------------
 * SysFree_  --  free memory using free(), when already in OS context
 *------------------------------------------------------------------------
 */
void SysFree_(void *mem)
{
  PTRACE_SYSFREE(mem);

  free(mem);
}

/*------------------------------------------------------------------------
 * RttFree  --  free memory using free(), called in OS context to prevent 
 *              context switches
 *------------------------------------------------------------------------
 */
void RttFree(void *mem)
{
  ENTERINGOS;

  PTRACE_FREE(mem);
 
  free(mem);
  LEAVINGOS;
}

/*------------------------------------------------------------------------
 * RttRealloc  --  reallocate memory using realloc(), called in OS context
 *                 to prevent context switches
 *------------------------------------------------------------------------
 */
void *RttRealloc(void *ptr, int size)
{
  void *rv;

  ENTERINGOS;

  PTRACE_REALLOC(ptr, size, rv);

  rv = (void *)realloc((char *)ptr, size);
  LEAVINGOS;
  return(rv);
}

/*------------------------------------------------------------------------
 * RttCalloc  --  allocate and clear "size" bytes of memory using 
 *                calloc(), calledin OS context to prevent context 
 *                switches
 *------------------------------------------------------------------------
 */
void *RttCalloc( int numElems, int elemSize )
{
  void *rv;

  PTRACE_CALLOC((numElems * elemSize), rv);

  ENTERINGOS;
  rv = (void *)calloc(numElems, elemSize);
  LEAVINGOS;
  return(rv);
}

#ifdef USE_MEM_DEBUGGING
/*****************************************************************************
 *
 * The following code implements memory debugging facilities for RT Threads,
 * used to find memory leaks. This facility is enabled when RT Threads is
 * compiled with RTT_MEM_DEBUG defined. The routine RttMemPrint() can
 * be called at any time by the application to print a list showing the
 * specific line number and file where memory has been allocated, as well
 * the number of allocations and number of corresponding frees, plus the
 * total bytes allocated and freed per line and overall.
 * 
 *****************************************************************************/

#define HTBL_SIZE 200
#define HASH(X) ((X)%HTBL_SIZE)

#define FILENAMESIZE 80

typedef struct {
  int inUse;
  int line;
  char file[FILENAMESIZE];
  int count;
  int bytes;
} HtblEntry;

typedef struct {
  int index;
  int bytes;
} MemHdr;

static HtblEntry htbl[HTBL_SIZE];

static int mCount = 0, mBytes = 0;

/*------------------------------------------------------------------------
 * MemStore_  --  store (or update) an entry in the hash table for a
 *                memory allocation
 *------------------------------------------------------------------------
 */
static int MemStore_(char *file, int line, int size, int *count, int *bytes)
{
  int counter, index;
  int retVal = RTTFAILED;

  index = HASH(line);

  for (counter = 0; counter < HTBL_SIZE; counter++) {
    if (htbl[index].inUse == 0) {
      htbl[index].inUse = 1;
      htbl[index].count = 1;
      htbl[index].bytes = size;
      htbl[index].line = line;
      strcpy(htbl[index].file, file);
      *count = htbl[index].count;
      *bytes = htbl[index].bytes;
      retVal = index;
      break;
    }
    else if ((htbl[index].line == line) && (!strcmp(file, htbl[index].file))) {
      htbl[index].count++;
      htbl[index].bytes += size;
      *count = htbl[index].count;
      *bytes = htbl[index].bytes;
      retVal = index;
      break;
    }
    index = (index + 1) % HTBL_SIZE;
  }

  return (retVal);
}

/*------------------------------------------------------------------------
 * MemFree_  --  update an entry in the hash table for a free operation
 *------------------------------------------------------------------------
 */
static int MemFree_(int index, 
		    char *file, int *line, int size, int *count, int *bytes)
{
  if (htbl[index].inUse == 0) {
    return (RTTFAILED);
  }

  *line = htbl[index].line;
  strcpy(file, htbl[index].file);
  *count = --htbl[index].count;

#ifndef WIN32
  if (htbl[index].count < 0){
    printf("HERE:\n");
    kill(getpid(), SIGILL);
  }
#endif /* WIN32 */
  
  htbl[index].bytes -= size;
  *bytes = htbl[index].bytes;

  return (RTTOK);
}

/*------------------------------------------------------------------------
 * RttDebugMalloc  --  debug version of RttMalloc
 *------------------------------------------------------------------------
 */
void *RttDebugMalloc(int size, char *file, int line)
{
  MemHdr *mem;
  int count, bytes;

  ENTERINGOS;
  mem = (MemHdr *) malloc(size+sizeof(MemHdr));

  if (mem != NULL) {
    mem->index = MemStore_(file, line, size, &count, &bytes);
    mem->bytes = size;
    mCount++;
    mBytes += size;
  }

  LEAVINGOS;

  return((void *)(mem+1));
}

/*------------------------------------------------------------------------
 * RttDebugCalloc  --  debug version of RttCalloc
 *------------------------------------------------------------------------
 */
void *RttDebugCalloc(int numElems, int elemSize, char *file, int line)
{
  MemHdr *mem;
  int count, bytes, size;

  size = numElems*elemSize;

  ENTERINGOS;
  mem = (MemHdr *) calloc(numElems, elemSize);

  if (mem != NULL) {
    mem->index = MemStore_(file, line, size, &count, &bytes);
    mem->bytes = size;
    mCount++;
    mBytes += size;
  }

  LEAVINGOS;

  return((void *)(mem+1));
}

/*------------------------------------------------------------------------
 * RttDebugRealloc  --  debug version of RttRealloc
 *------------------------------------------------------------------------
 */
void *RttDebugRealloc(void *mem, int size, char *file, int line)
{
  MemHdr *memhdr;
  int count, bytes, mLine;
  char mFile[FILENAMESIZE];

  ENTERINGOS;

  memhdr = ((MemHdr *)mem) - 1;

  mCount--;
  mBytes -= memhdr->bytes;
  
  MemFree_(memhdr->index, mFile, &mLine, memhdr->bytes, &count, &bytes);

  memhdr = (MemHdr *) realloc((void *)memhdr, size+sizeof(MemHdr));

  if (memhdr != NULL) {
    memhdr->index = MemStore_(file, line, size, &count, &bytes);
    memhdr->bytes = size;
    mCount++;
    mBytes += size;
  }

  LEAVINGOS;

  return((void *)(memhdr+1));
}

/*------------------------------------------------------------------------
 * RttDebugFree  --  debug version of RttFree
 *------------------------------------------------------------------------
 */
void RttDebugFree(void *mem, char *file, int line)
{
  MemHdr *memhdr;
  int count, bytes, mLine;
  char mFile[FILENAMESIZE];
  
  ENTERINGOS;

  memhdr = ((MemHdr *)mem) - 1;

  mCount--;
  mBytes -= memhdr->bytes;
  
  MemFree_(memhdr->index, mFile, &mLine, memhdr->bytes, &count, &bytes);

  free(memhdr);
  LEAVINGOS;
}

/*------------------------------------------------------------------------
 * SysDebugMalloc_  --  debug version of SysMalloc_
 *------------------------------------------------------------------------
 */
void *SysDebugMalloc_(int size, char *file, int line)
{
  MemHdr *mem;
  int count, bytes;

  mem = (MemHdr *) malloc(size+sizeof(MemHdr));

  if (mem != NULL) {
    mem->index = MemStore_(file, line, size, &count, &bytes);
    mem->bytes = size;
    mCount++;
    mBytes += size;
  }

  return((void *)(mem+1));
}

/*------------------------------------------------------------------------
 * SysDebugFree_  --  debug version of SysFree_
 *------------------------------------------------------------------------
 */
void SysDebugFree_(void *mem, char *file, int line)
{
  MemHdr *memhdr;
  int count, bytes, mLine;
  char mFile[FILENAMESIZE];
  
  memhdr = ((MemHdr *)mem) - 1;

  mCount--;
  mBytes -= memhdr->bytes;
  
  MemFree_(memhdr->index, mFile, &mLine, memhdr->bytes, &count, &bytes);

  free(memhdr);
}

/*------------------------------------------------------------------------
 * RttMemPrint  --  print out debug information
 *------------------------------------------------------------------------
 */
void RttMemPrint() {
  int i;

  printf("****************************************************************\n");
  printf("RttMemPrint():\n");
  printf("--------------\n");
  printf("memory used: \t%10d    \t(%d)\n", mBytes, mCount);
  printf("----------------------------------------------------------------\n");

  for (i = 0; i < HTBL_SIZE; i++) {
    if (htbl[i].inUse) {
      printf("%s %d: \t%10d    \t(%d)\n",
	     htbl[i].file, htbl[i].line, htbl[i].bytes, htbl[i].count);
    }
  }
  printf("****************************************************************\n");
}
#else
void RttMemPrint() {
  printf("****************************************************************\n");
  printf("RttMemPrint(): Memory debugging disabled\n");
  printf("****************************************************************\n");
}
#endif /* USE_MEM_DEBUGGING */
