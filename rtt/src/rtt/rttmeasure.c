#include <math.h>
#include "rttkernel.h"
#include "rttmeasure.h"

#define SQUARE(X) ((X)*(X))

#ifdef max
#undef max
#endif
#define max(X,Y) ((X) > (Y) ? (X) : (Y))

static int head = -1;
static int tail = -1;

typedef struct {
  RttThreadId threadId;
  int prev;
  int next;
} MeasureEntry;

static MeasureEntry entries[NUMBTCBS];

static void addThread(RttThreadId threadId)
{
  int index;

  index = GetIndexFromThreadId(threadId);

  if (head == -1) {
    tail = index;
  }
  else {
    entries[head].prev = index;
    entries[index].next = head;
  }
  head = index;
  entries[index].threadId = threadId;
}


static void removeThread(RttThreadId threadId)
{
  int index;

  index = GetIndexFromThreadId(threadId);

  if (index == head) {
    if (index == tail) {
      head = tail = -1;
    }
    else {
      head = entries[index].next;
    }
  }
  else if (index == tail) {
    tail = entries[index].prev;
  }
  else {
    entries[entries[index].prev].next = entries[index].next;
    entries[entries[index].next].prev = entries[index].prev;
  }
}



int RttEnableSchedMeasurement(RttThreadId thread, int numEntries)
{
  TCB *tcbPtr;
  RttMeasure *measure;

  ENTERINGOS;

  /* XXX dangerous! need to check whether RttThreadId is valid */
  tcbPtr = getTcbFromThreadId(thread);

  if (GetSysData(tcbPtr) != NULL) {
	LEAVINGOS;
	return (RTTFAILED);
  }

  measure = (RttMeasure *)SysMalloc_(sizeof(RttMeasure) + numEntries*sizeof(int));
  assert(measure);

  measure->type =  RTTSCHEDMEASUREMENT;

  measure->count = 0;

  measure->data = (int *)(measure+1);

  SetSysData(tcbPtr, (void *)measure);

  addThread(thread);

  LEAVINGOS;

  return (RTTOK);
}

int RttDisableSchedMeasurement(RttThreadId thread)
{
  TCB *tcbPtr;
  RttMeasure *measure;

  ENTERINGOS;

  /* XXX dangerous! need to check whether RttThreadId is valid */
  tcbPtr = getTcbFromThreadId(thread);

  measure = (RttMeasure *)GetSysData(tcbPtr);

  if ((measure == NULL) || (measure->type != RTTSCHEDMEASUREMENT)) {
	LEAVINGOS;
	return (RTTFAILED);
  }

  SysFree_(measure);
  SetSysData(tcbPtr, NULL);

  removeThread(thread);

  LEAVINGOS;

  return (RTTOK);
}

static int schedMeasurement(RttThreadId thread, int *count, int *avgdiff, 
			    int *maxdiff, int *sd)
{
  TCB *tcbPtr;
  RttMeasure *measure;
  int *diffs;
  int i, total = 0;
  double squares = 0.0, average;

  /* XXX dangerous! need to check whether RttThreadId is valid */
  tcbPtr = getTcbFromThreadId(thread);

  measure = (RttMeasure *)GetSysData(tcbPtr);

  if ((measure == NULL) || (measure->type != RTTSCHEDMEASUREMENT)) {
	return (RTTFAILED);
  }
  
  *count = measure->count;
  diffs = (int *)(measure->data);

  *maxdiff = 0;
  for (i = 0; i < *count; i++) {
	total += diffs[i];
	*maxdiff = max(*maxdiff, diffs[i]);
  }
    
  average = (double)total/(double)(*count);
  *avgdiff = average + 0.5;

  for (i = 0; i < *count; i++) {
	squares += SQUARE((double)diffs[i]-average);
  }
  *sd = sqrt(squares/(double)(*count)) + 0.5;

  return (RTTOK);
}

int RttSchedMeasurement(RttThreadId thread, int *count, int *avgdiff, 
			int *maxdiff, int *sd)
{
  int rv;

  ENTERINGOS;
  rv = schedMeasurement(thread, count, avgdiff, maxdiff, sd);
  LEAVINGOS;

  return (rv);
}


int RttGetLastWakeTime(RttThreadId thread, RttTimeValue *wakeTime)
{
  TCB *tcbPtr;
  RttMeasure *measure;
  int *diffs;
  int i, total = 0;
  double squares, average;

  ENTERINGOS;

  /* XXX dangerous! need to check whether RttThreadId is valid */
  tcbPtr = getTcbFromThreadId(thread);

  measure = (RttMeasure *)GetSysData(tcbPtr);

  if ((measure == NULL) || (measure->type != RTTSCHEDMEASUREMENT)) {
	LEAVINGOS;
	return (RTTFAILED);
  }
  
  *wakeTime = measure->lastWakeTime;

  LEAVINGOS;

  return (RTTOK);
}

void RttPrintMeasurements(FILE *fp)
{
  int index;
  int count, avg, sd, maxi;

  ENTERINGOS;

  index = head;

  fprintf(fp, "-----------------------------------------------------------\n");
  fprintf(fp, "RttPrintMeasurements()\n");
  fprintf(fp, "-----------------------------------------------------------\n");
  while (index != -1) {
    schedMeasurement(entries[index].threadId, &count, &avg, &maxi, &sd);
    fprintf(fp, "%s  %d %d %d %d\n", 
	    GetTname(getTcbFromThreadId(entries[index].threadId)), 
	    count, avg, sd, maxi);
    if (index == tail) break;
    index = entries[index].next;
  }
  fprintf(fp, "-----------------------------------------------------------\n");

  LEAVINGOS;
}
