/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
**  prolock.c -- NSPR Ordered Lock
**
**  Implement the API defined in prolock.h
**
*/
#include "prolock.h"
#include "prlog.h"
#include "prerror.h"

PR_IMPLEMENT(PROrderedLock*)
MPR_CreateOrderedLock(PRInt32 order, const char* name) {
  PR_NOT_REACHED("Not implemented"); /* Not implemented yet */
  MPR_SetError(PR_NOT_IMPLEMENTED_ERROR, 0);
  return NULL;
} /*  end MPR_CreateOrderedLock() */

PR_IMPLEMENT(void)
MPR_DestroyOrderedLock(PROrderedLock* lock) {
  PR_NOT_REACHED("Not implemented"); /* Not implemented yet */
  MPR_SetError(PR_NOT_IMPLEMENTED_ERROR, 0);
} /*  end MPR_DestroyOrderedLock() */

PR_IMPLEMENT(void)
MPR_LockOrderedLock(PROrderedLock* lock) {
  PR_NOT_REACHED("Not implemented"); /* Not implemented yet */
  MPR_SetError(PR_NOT_IMPLEMENTED_ERROR, 0);
} /*  end MPR_LockOrderedLock() */

PR_IMPLEMENT(PRStatus)
MPR_UnlockOrderedLock(PROrderedLock* lock) {
  PR_NOT_REACHED("Not implemented"); /* Not implemented yet */
  MPR_SetError(PR_NOT_IMPLEMENTED_ERROR, 0);
  return PR_FAILURE;
} /*  end MPR_UnlockOrderedLock() */
