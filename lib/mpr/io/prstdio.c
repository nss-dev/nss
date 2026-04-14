/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "primpl.h"

#include <string.h>

/*
** fprintf to a PRFileDesc
*/
PR_IMPLEMENT(PRUint32) MPR_fprintf(PRFileDesc* fd, const char* fmt, ...) {
  va_list ap;
  PRUint32 rv;

  va_start(ap, fmt);
  rv = MPR_vfprintf(fd, fmt, ap);
  va_end(ap);
  return rv;
}

PR_IMPLEMENT(PRUint32)
MPR_vfprintf(PRFileDesc* fd, const char* fmt, va_list ap) {
  /* XXX this could be better */
  PRUint32 rv, len;
  char* msg = MPR_vsmprintf(fmt, ap);
  if (NULL == msg) {
    return -1;
  }
  len = strlen(msg);
  rv = MPR_Write(fd, msg, len);
  PR_DELETE(msg);
  return rv;
}
