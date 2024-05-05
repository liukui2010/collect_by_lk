#ifndef RTTMEASURE_H
#define RTTMEASURE_H

#include <rtthreads.h>

#define RTTSCHEDMEASUREMENT 1

typedef struct {
  int type;
  int count;
  RttTimeValue lastWakeTime;
  void *data;
} RttMeasure;

#define RTTTIMEDIFF(t1, t2) (((long)(t1).microseconds - (long)(t2).microseconds)\
			  + (((t1).seconds - (t2).seconds)*1000000))

#define RTTSCHEDMEASURE(tp,wt,st) {                               \
	RttMeasure *measure;                                      \
	int *diffs;                                               \
	measure = (RttMeasure *)GetSysData(tp);                   \
        if (measure && (measure->type == RTTSCHEDMEASUREMENT)) {  \
          diffs = (int *)measure->data;                           \
          diffs[measure->count++] = RTTTIMEDIFF(wt, st);          \
          measure->lastWakeTime = wt;                             \
        }                                                         \
}

#endif /* RTTMEASURE_H */
