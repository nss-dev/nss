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

#ifndef NSSPKI_H
#include "nsspki.h"
#endif /* NSSPKI_H */

#include "ssl.h"

/*
 * This callback used by SSL to pull client certificate upon
 * server request
 */
PRStatus 
SSL_GetClientAuthData(void *                       arg, 
                      PRFileDesc *                 socket, 
                      NSSTrustDomain *             td,
                      NSSDER **                    caNames,
                      NSSCert **                   pRetCert,
                      NSSPrivateKey **             pRetKey)
{
  NSSCert *   cert = NULL;
  NSSPrivateKey *    privkey = NULL;
  NSSUTF8 *          chosenNickName = (NSSUTF8 *)arg;    /* CONST */
  NSSCallback *      pinCallback  = NULL;
  
  pinCallback = SSL_RevealPinArg(socket);
  
  if (chosenNickName) {
    NSSUsages sslClientAuth = { 0, NSSUsage_SSLClient };
    cert = NSSTrustDomain_FindBestCertByNickname(td, chosenNickName,
                                                 NSSTime_Now(), 
                                                 &sslClientAuth, 
                                                 NULL);
  } else { /* no name given, automatically find the right cert. */
    cert = NSSTrustDomain_FindBestUserCertForSSLClientAuth(td, 
                                    /* sslHostOpt? */      NULL,
                                                           caNames, 0, 
                                                           NULL, NULL);
  }
  if (cert) {
    privkey = NSSCert_FindPrivateKey(cert, NULL /*XXX pinCallback*/);
    if (privkey) {
      *pRetCert = cert;
      *pRetKey = privkey;
      return PR_SUCCESS;
    } else {
      NSSCert_Destroy(cert);
    }
  }
  return PR_FAILURE;
}

