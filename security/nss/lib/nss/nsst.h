/*
 * NSS utility functions
 *
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
 *
 * $Id$
 */

#ifndef NSST_H
#define NSST_H

#include "nsspkit.h"

PR_BEGIN_EXTERN_C

typedef struct 
{

  /*
   * Decode the cert
   */
  void * (PR_CALLBACK *decode)(NSSArena *arenaOpt, NSSBER *encoding);

  /*
   * gettors
   *
   * buffers are controlled by the decoded cert
   */
  NSSBER *    (PR_CALLBACK *      getSubject)(void *cert);
  NSSBER *    (PR_CALLBACK *       getIssuer)(void *cert);
  NSSBER *    (PR_CALLBACK * getSerialNumber)(void *cert);
  NSSASCII7 * (PR_CALLBACK * getEmailAddress)(void *cert);

  /*
   * Unique identifiers for chain construction
   */
  void * (PR_CALLBACK * getIssuerIdentifier)(void *cert);
  PRBool (PR_CALLBACK *      isMyIdentifier)(void *cert, void *id);
  void   (PR_CALLBACK *      freeIdentifier)(void *id);

  /*
   * validity period
   */
  PRStatus (PR_CALLBACK *getValidityPeriod)(void *cert, 
                                            NSSTime *notBefore, 
                                            NSSTime *notAfter);

  /*
   * usages
   */
  PRStatus (PR_CALLBACK *getUsages)(void *cert, NSSUsages *usages);

  /*
   * policies
   */
  NSSPolicies * (PR_CALLBACK *getPolicies)(void *cert);

  /*
   * chain validation
   */
  void *   (PR_CALLBACK *    startChainValidation)();
  PRStatus (PR_CALLBACK *       validateChainLink)(void *cert, 
                                                   void *issuer, 
                                                   void *vData);
  void     (PR_CALLBACK * freeChainValidationData)(void *vData);

  /*
   * free the decoded cert
   */
  void (PR_CALLBACK *destroy)(void *cert);
}
NSSCertificateMethods;

PR_END_EXTERN_C

#endif /* NSST_H */
