/* THIS IS A GENERATED FILE */
/* 
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 * 
 * The Original Code is the Netscape security libraries.
 * 
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation.  Portions created by Netscape are 
 * Copyright (C) 1994-2000 Netscape Communications Corporation.  All
 * Rights Reserved.
 * 
 * Contributor(s):
 * 
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU General Public License Version 2 or later (the
 * "GPL"), in which case the provisions of the GPL are applicable 
 * instead of those above.  If you wish to allow use of your 
 * version of this file only under the terms of the GPL and not to
 * allow others to use your version of this file under the MPL,
 * indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by
 * the GPL.  If you do not delete the provisions above, a recipient
 * may use your version of this file under either the MPL or the
 * GPL.
 */

#ifndef NSSBASE_H
#include "nssbase.h"
#endif /* NSSBASE_H */

struct error_strings_str {
  NSSError e;
  char *text;
};

static const struct error_strings_str error_strings[] = {
  {
    NSS_ERROR_NO_ERROR,
    "no error"
  },
  {
    NSS_ERROR_INTERNAL_ERROR,
    "internal library error"
  },
  {
    NSS_ERROR_NO_MEMORY,
    "out of memory"
  },
  {
    NSS_ERROR_INVALID_POINTER,
    "invalid pointer"
  },
  {
    NSS_ERROR_INVALID_ARENA,
    "invalid arena"
  },
  {
    NSS_ERROR_INVALID_ARENA_MARK,
    "invalid arena mark"
  },
  {
    NSS_ERROR_ARENA_MARKED_BY_ANOTHER_THREAD,
    "arena marked by another thread"
  },
  {
    NSS_ERROR_VALUE_TOO_LARGE,
    "value too large"
  },
  {
    NSS_ERROR_UNSUPPORTED_TYPE,
    "unsupported type"
  },
  {
    NSS_ERROR_BUFFER_TOO_SHORT,
    "buffer too short"
  },
  {
    NSS_ERROR_INVALID_ATOB_CONTEXT,
    "invalid atob context"
  },
  {
    NSS_ERROR_INVALID_BASE64,
    "invalid base-64 encoded data"
  },
  {
    NSS_ERROR_INVALID_BTOA_CONTEXT,
    "invalid btoa context"
  },
  {
    NSS_ERROR_INVALID_ITEM,
    "invalid item"
  },
  {
    NSS_ERROR_INVALID_STRING,
    "invalid string"
  },
  {
    NSS_ERROR_INVALID_ASN1ENCODER,
    "invalid ASN.1 encoder"
  },
  {
    NSS_ERROR_INVALID_ASN1DECODER,
    "invalid ASN.1 decoder"
  },
  {
    NSS_ERROR_INVALID_BER,
    "invalid BER encoded data"
  },
  {
    NSS_ERROR_INVALID_ATAV,
    "invalid attribute-type-and-value"
  },
  {
    NSS_ERROR_INVALID_ARGUMENT,
    "invalid argument"
  },
  {
    NSS_ERROR_INVALID_UTF8,
    "invalid UTF-8 encoded data"
  },
  {
    NSS_ERROR_INVALID_NSSOID,
    "invalid OID"
  },
  {
    NSS_ERROR_UNKNOWN_ATTRIBUTE,
    "unknown attribute"
  },
  {
    NSS_ERROR_NOT_FOUND,
    "not found???"
  },
  {
    NSS_ERROR_INVALID_PASSWORD,
    "invalid password"
  },
  {
    NSS_ERROR_USER_CANCELED,
    "user canceled"
  },
  {
    NSS_ERROR_MAXIMUM_FOUND,
    "maximum found"
  },
  {
    NSS_ERROR_INVALID_SIGNATURE,
    "invalid signature"
  },
  {
    NSS_ERROR_INVALID_DATA,
    "invalid data"
  },
  {
    NSS_ERROR_TOKEN_FAILURE,
    "token failure"
  },
  {
    NSS_ERROR_INVALID_CERTIFICATE,
    "invalid certificate"
  },
  {
    NSS_ERROR_CERTIFICATE_ISSUER_NOT_FOUND,
    "certificate issuer not found"
  },
  {
    NSS_ERROR_CERTIFICATE_USAGE_INSUFFICIENT,
    "certificate not valid for operation"
  },
  {
    NSS_ERROR_CERTIFICATE_EXCEEDED_PATH_LENGTH_CONSTRAINT,
    "certificate exceeded path length constraint"
  },
  {
    NSS_ERROR_CERTIFICATE_HAS_NO_TRUSTED_ISSUER,
    "certificate does not have trusted issuer"
  },
  {
    NSS_ERROR_CERTIFICATE_NOT_VALID_AT_TIME,
    "certificate is not valid at specified time"
  },
  {
    NSS_ERROR_INVALID_CRYPTO_CONTEXT,
    "invalid crypto context"
  }
};

static const PRUint32 num_errors = 37;

static char *get_error_text(NSSError e)
{
    PRInt32 i, low = 0, high = num_errors;

    /* XXX make sure table is in ascending order */

    while (low + 1 < high) {
	i = (low + high) / 2;
	if (e == error_strings[i].e)
	    return error_strings[i].text;
	if (e < error_strings[i].e)
	    high = i;
	else
	    low = i;
    }
    if (e == error_strings[low].e)
	return error_strings[low].text;
    if (e == error_strings[high].e)
	return error_strings[high].text;
    return NULL;
}

void
CMD_PrintError(char *message, ...)
{
    NSSError e;
    char *text;
    va_list args;

    e = NSS_GetError();

    va_start(args, message);

    PR_vfprintf(PR_STDERR, message, args);
    if (e) {
	text = get_error_text(e);
	if (text) {
	    PR_fprintf(PR_STDERR, ": %s\n", text);
	} else {
	    PR_fprintf(PR_STDERR, ": (%d)\n", e);
	}
    } else {
	PR_fprintf(PR_STDERR, "\n");
    }

    va_end(args);
}

