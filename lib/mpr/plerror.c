/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
** File:plerror.c
** Description: Simple routine to print translate the calling thread's
**  error numbers and print them to "syserr".
*/

#include "plerror.h"

#include "prprf.h"
#include "prerror.h"

PR_IMPLEMENT(void) MPL_FPrintError(PRFileDesc* fd, const char* msg) {
  PRErrorCode error = MPR_GetError();
  PRInt32 oserror = MPR_GetOSError();
  const char* name = MPR_ErrorToName(error);

  if (NULL != msg) {
    MPR_fprintf(fd, "%s: ", msg);
  }
  if (NULL == name)
    MPR_fprintf(fd, " (%d)OUT OF RANGE, oserror = %d\n", error, oserror);
  else
    MPR_fprintf(fd, "%s(%d), oserror = %d\n", name, error, oserror);
} /* MPL_FPrintError */

PR_IMPLEMENT(void) MPL_PrintError(const char* msg) {
  static PRFileDesc* fd = NULL;
  if (NULL == fd) {
    fd = MPR_GetSpecialFD(PR_StandardError);
  }
  MPL_FPrintError(fd, msg);
} /* MPL_PrintError */

/* plerror.c */
