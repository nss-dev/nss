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

#ifndef NSSERRORS_H
#define NSSERRORS_H

#ifdef DEBUG
static const char NSSERRORS_CVS_ID[] = "@(#) $RCSfile$ $Revision$ $Date$ $Name$";
#endif /* DEBUG */

#define NSS_ERROR_NO_ERROR                         0
#define NSS_ERROR_INTERNAL_ERROR                   1
#define NSS_ERROR_NO_MEMORY                        2
#define NSS_ERROR_INVALID_POINTER                  3
#define NSS_ERROR_INVALID_ARENA                    4
#define NSS_ERROR_INVALID_ARENA_MARK               5
#define NSS_ERROR_ARENA_MARKED_BY_ANOTHER_THREAD  10
#define NSS_ERROR_VALUE_TOO_LARGE                 11
#define NSS_ERROR_UNSUPPORTED_TYPE                12
#define NSS_ERROR_BUFFER_TOO_SHORT                13
#define NSS_ERROR_INVALID_ATOB_CONTEXT            14
#define NSS_ERROR_INVALID_BASE64                  15
#define NSS_ERROR_INVALID_BTOA_CONTEXT            16
#define NSS_ERROR_INVALID_ITEM                    17
#define NSS_ERROR_INVALID_STRING                  18
#define NSS_ERROR_INVALID_ASN1ENCODER             19
#define NSS_ERROR_INVALID_ASN1DECODER             20

#define NSS_ERROR_INVALID_BER                     21
#define NSS_ERROR_INVALID_ATAV                    22
#define NSS_ERROR_INVALID_ARGUMENT                23
#define NSS_ERROR_INVALID_UTF8                    24
#define NSS_ERROR_INVALID_NSSOID                  25
#define NSS_ERROR_UNKNOWN_ATTRIBUTE               26

#define NSS_ERROR_NOT_FOUND                       27

#define NSS_ERROR_INVALID_PASSWORD                28
#define NSS_ERROR_USER_CANCELED                   29

#define NSS_ERROR_MAXIMUM_FOUND                   30
#define NSS_ERROR_INVALID_SIGNATURE               31
#define NSS_ERROR_INVALID_DATA                    32

/* token errors */
#define NSS_ERROR_TOKEN_FAILURE                   100

/* certificate errors */
#define NSS_ERROR_CERTIFICATE_ISSUER_NOT_FOUND    500

/* crypto context errors */
#define NSS_ERROR_INVALID_CRYPTO_CONTEXT          800

#endif /* NSSERRORS_H */
