/*
 * Return SSLKEAType derived from cert's Public Key algorithm info.
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
 # $Id$
 */

#ifndef NSSPKI_H
#include "nsspki.h"
#endif /* NSSPKI_H */

#ifndef NSSPKI1_H
#include "nsspki1.h"
#endif /* NSSPKI1_H */

#ifndef NSSPKIX_H
#include "nsspkix.h"
#endif /* NSSPKIX_H */

#include "ssl.h"	/* for SSLKEAType */

SSLKEAType
SSL_FindCertKEAType(NSSCertificate *cert)
{
  SSLKEAType keaType = kt_null; 
  int tag;
  
  if (!cert) goto loser;
  
  if (NSSCertificate_GetType(cert) == NSSCertificateType_PKIX) {
    NSSPKIXCertificate *pkixCert;
    NSSPKIXTBSCertificate *tbsCert;
    NSSPKIXSubjectPublicKeyInfo *spki;
    NSSPKIXAlgorithmIdentifier *bkAlg;

    pkixCert = (NSSPKIXCertificate *)NSSCertificate_GetDecoding(cert);
    if (!pkixCert) {
	goto loser;
    }
    tbsCert = NSSPKIXCertificate_GetTBSCertificate(pkixCert);
    if (!tbsCert) {
	goto loser;
    }
    spki = NSSPKIXTBSCertificate_GetSubjectPublicKeyInfo(tbsCert);
    if (!spki) {
	goto loser;
    }
    bkAlg = NSSPKIXSubjectPublicKeyInfo_GetAlgorithm(spki);
    if (!bkAlg) {
	goto loser;
    }
    oid = NSSPKIXAlgorithmIdentifier_GetAlgorithm(bkAlg);
    if (!oid) {
	goto loser;
    }
  } else {
    goto loser;
  }
  
  switch (NSSOID_GetTag(oid)) {
  case NSS_OID_X500_RSA_ENCRYPTION:
  case NSS_OID_PKCS1_RSA_ENCRYPTION:
    keaType = kt_rsa;
    break;
  case NSS_OID_MISSI_KEA_DSS_OLD:
  case NSS_OID_MISSI_KEA_DSS:
  case NSS_OID_MISSI_DSS_OLD:
  case NSS_OID_MISSI_DSS:
    keaType = kt_fortezza;
    break;
  case NSS_OID_X942_DIFFIE_HELMAN_KEY:
    keaType = kt_dh;
    break;
  default:
    keaType = kt_null;
  }
  
 loser:
  
  return keaType;

}

