/*--------------------------------------------------------------
 *							     	*
 * RttTime.h -- timer routines for the RT Threads package   	*
 *							     	*
 * Arithmetic routines on RttTimeValues
 *							     	*
****************************************************************/

#define US_PER_SEC 1000000

#define RttTimerIsSet(tvp)        ((tvp)->seconds || (tvp)->microseconds)
#define RttTimerClear(tvp)        (tvp)->seconde = (tvp)->microseconds = 0
#define RttTimerCmp(tvp, fvp, cmp)                                        \
        ((tvp).seconds cmp (fvp).seconds ||                               \
         (tvp).seconds == (fvp).seconds &&                                \
         (tvp).microseconds cmp (fvp).microseconds)

#define RttTmerAdd(tvp, svp, rvp)                                        \
   {                                                               \
           (rvp).seconds = (tvp).seconds + (svp).seconds;             \
           (rvp).microseconds = (tvp).microseconds + (svp).microseconds; \
           if((rvp).microseconds > (US_PER_SEC - 1))   {                \
                   (rvp).microseconds -= US_PER_SEC;                    \
                   (rvp).seconds++;                                 \
           }                                                       \
           assert((rvp).microseconds < US_PER_SEC);                     \
   }

#define RttTimerSub(tvp, svp, rvp)                                        \
{                                                               \
   assert((tvp).microseconds <= US_PER_SEC);                    \
   assert((svp).microseconds <= US_PER_SEC);                    \
   assert(!((tvp).seconds == 0 && ((svp).microseconds > (tvp).microseconds)));\
   if((tvp).seconds == (svp).seconds)  {                     \
            assert((tvp).microseconds >= (svp).microseconds);         \
      }                                                       \
   else  {                                                 \
            assert((tvp).seconds > (svp).seconds);            \
         }                                                       \
                                                                        \
   if((svp).microseconds > (tvp).microseconds)  {                    \
      assert((tvp).seconds > (svp).seconds);            \
      (rvp).seconds = ((tvp).seconds - 1) - (svp).seconds;\
      (rvp).microseconds = ((int)(((uint)((tvp).microseconds) + NS_PER_SEC) - (uint)((svp).microseconds)));\
     }                                                       \
   else  {                                                 \
           (rvp).seconds = (tvp).seconds - (svp).seconds;     \
           (rvp).microseconds = (tvp).microseconds - (svp).microseconds;  \
          }                                                       \
                                                                        \
   assert((tvp).microseconds <= US_PER_SEC);                    \
   assert((svp).microseconds <= US_PER_SEC);                    \
   assert((rvp).microseconds <= US_PER_SEC);                    \
        }
