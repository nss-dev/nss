/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * file:            prinrval.c
 * description:     implementation for the kernel interval timing functions
 */

#include "primpl.h"

/*
 *-----------------------------------------------------------------------
 *
 * _PR_InitClock --
 *
 *
 *-----------------------------------------------------------------------
 */

void _PR_InitClock(void) {
  _PR_MD_INTERVAL_INIT();
#ifdef DEBUG
  {
    PRIntervalTime ticksPerSec = MPR_TicksPerSecond();

    PR_ASSERT(ticksPerSec >= PR_INTERVAL_MIN);
    PR_ASSERT(ticksPerSec <= PR_INTERVAL_MAX);
  }
#endif /* DEBUG */
}

PR_IMPLEMENT(PRIntervalTime) MPR_IntervalNow(void) {
  if (!_pr_initialized) {
    _PR_ImplicitInitialization();
  }
  return _PR_MD_GET_INTERVAL();
} /* MPR_IntervalNow */

PR_EXTERN(PRUint32) MPR_TicksPerSecond(void) {
  if (!_pr_initialized) {
    _PR_ImplicitInitialization();
  }
  return _PR_MD_INTERVAL_PER_SEC();
} /* MPR_TicksPerSecond */

PR_IMPLEMENT(PRIntervalTime) MPR_SecondsToInterval(PRUint32 seconds) {
  return seconds * MPR_TicksPerSecond();
} /* MPR_SecondsToInterval */

PR_IMPLEMENT(PRIntervalTime) MPR_MillisecondsToInterval(PRUint32 milli) {
  PRIntervalTime ticks;
  PRUint64 tock, tps, msecPerSec, rounding;
  LL_UI2L(tock, milli);
  LL_I2L(msecPerSec, PR_MSEC_PER_SEC);
  LL_I2L(rounding, (PR_MSEC_PER_SEC >> 1));
  LL_I2L(tps, MPR_TicksPerSecond());
  LL_MUL(tock, tock, tps);
  LL_ADD(tock, tock, rounding);
  LL_DIV(tock, tock, msecPerSec);
  LL_L2UI(ticks, tock);
  return ticks;
} /* MPR_MillisecondsToInterval */

PR_IMPLEMENT(PRIntervalTime) MPR_MicrosecondsToInterval(PRUint32 micro) {
  PRIntervalTime ticks;
  PRUint64 tock, tps, usecPerSec, rounding;
  LL_UI2L(tock, micro);
  LL_I2L(usecPerSec, PR_USEC_PER_SEC);
  LL_I2L(rounding, (PR_USEC_PER_SEC >> 1));
  LL_I2L(tps, MPR_TicksPerSecond());
  LL_MUL(tock, tock, tps);
  LL_ADD(tock, tock, rounding);
  LL_DIV(tock, tock, usecPerSec);
  LL_L2UI(ticks, tock);
  return ticks;
} /* MPR_MicrosecondsToInterval */

PR_IMPLEMENT(PRUint32) MPR_IntervalToSeconds(PRIntervalTime ticks) {
  return ticks / MPR_TicksPerSecond();
} /* MPR_IntervalToSeconds */

PR_IMPLEMENT(PRUint32) MPR_IntervalToMilliseconds(PRIntervalTime ticks) {
  PRUint32 milli;
  PRUint64 tock, tps, msecPerSec, rounding;
  LL_UI2L(tock, ticks);
  LL_I2L(msecPerSec, PR_MSEC_PER_SEC);
  LL_I2L(tps, MPR_TicksPerSecond());
  LL_USHR(rounding, tps, 1);
  LL_MUL(tock, tock, msecPerSec);
  LL_ADD(tock, tock, rounding);
  LL_DIV(tock, tock, tps);
  LL_L2UI(milli, tock);
  return milli;
} /* MPR_IntervalToMilliseconds */

PR_IMPLEMENT(PRUint32) MPR_IntervalToMicroseconds(PRIntervalTime ticks) {
  PRUint32 micro;
  PRUint64 tock, tps, usecPerSec, rounding;
  LL_UI2L(tock, ticks);
  LL_I2L(usecPerSec, PR_USEC_PER_SEC);
  LL_I2L(tps, MPR_TicksPerSecond());
  LL_USHR(rounding, tps, 1);
  LL_MUL(tock, tock, usecPerSec);
  LL_ADD(tock, tock, rounding);
  LL_DIV(tock, tock, tps);
  LL_L2UI(micro, tock);
  return micro;
} /* MPR_IntervalToMicroseconds */

/* prinrval.c */
