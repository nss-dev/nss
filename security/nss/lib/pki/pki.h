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

#ifndef PKI_H
#define PKI_H

#ifdef DEBUG
static const char PKI_CVS_ID[] = "@(#) $RCSfile$ $Revision$ $Date$ $Name$";
#endif /* DEBUG */

#ifndef NSSDEVT_H
#include "nssdevt.h"
#endif /* NSSDEVT_H */

#ifndef NSSPKI_H
#include "nsspki.h"
#endif /* NSSPKI_H */

#ifndef PKIT_H
#include "pkit.h"
#endif /* PKIT_H */

PR_BEGIN_EXTERN_C

NSS_EXTERN NSSToken *
nssTrustDomain_FindTokenForAlgNParam (
  NSSTrustDomain *td,
  const NSSAlgNParam *ap
);

NSS_EXTERN NSSToken *
nssTrustDomain_FindTokenForAlgorithm (
  NSSTrustDomain *td,
  NSSOIDTag algorithm
);

NSS_EXTERN NSSCallback *
nssTrustDomain_GetDefaultCallback (
  NSSTrustDomain *td,
  PRStatus *statusOpt
);

NSS_EXTERN NSSCert **
nssTrustDomain_FindCertsByNickname (
  NSSTrustDomain *td,
  NSSUTF8 *name,
  NSSCert *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
);

NSS_EXTERN NSSCert **
nssTrustDomain_FindCertsBySubject (
  NSSTrustDomain *td,
  NSSDER *subject,
  NSSCert *rvOpt[],
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN NSSCert *
nssTrustDomain_FindCertByIssuerAndSerialNumber (
  NSSTrustDomain *td,
  NSSDER *issuer,
  NSSDER *serialNumber
);

NSS_EXTERN NSSCert **
nssTrustDomain_FindCertsByEmail (
  NSSTrustDomain *td,
  NSSASCII7 *email,
  NSSCert *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
);

NSS_EXTERN NSSCert *
nssTrustDomain_FindCertByEncodedCert (
  NSSTrustDomain *td,
  NSSBER *encodedCert
);

NSS_EXTERN PRStatus *
nssTrustDomain_TraverseCerts (
  NSSTrustDomain *td,
  PRStatus (*callback)(NSSCert *c, void *arg),
  void *arg
);

NSS_EXTERN nssTrust *
nssTrustDomain_FindTrustForCert (
  NSSTrustDomain *td,
  NSSCert *c
);

NSS_EXTERN NSSCert *
nssCert_Decode (
  NSSBER *ber
);

NSS_EXTERN NSSCert *
nssCert_AddRef (
  NSSCert *c
);

NSS_EXTERN PRStatus
nssCert_Destroy (
  NSSCert *c
);

NSS_EXTERN NSSDER *
nssCert_GetEncoding (
  NSSCert *c
);

NSS_EXTERN NSSDER *
nssCert_GetIssuer (
  NSSCert *c
);

NSS_EXTERN NSSDER *
nssCert_GetSerialNumber (
  NSSCert *c
);

NSS_EXTERN NSSDER *
nssCert_GetSubject (
  NSSCert *c
);

NSS_EXTERN NSSItem *
nssCert_GetID (
  NSSCert *c
);

NSS_EXTERN PRStatus
nssCert_SetNickname (
  NSSCert *c,
  NSSToken *tokenOpt,
  NSSUTF8 *nickname
);

NSS_EXTERN NSSUTF8 *
nssCert_GetNickname (
  NSSCert *c,
  NSSToken *tokenOpt
);

NSS_EXTERN NSSASCII7 *
nssCert_GetEmailAddress (
  NSSCert *c
);

NSS_EXTERN PRBool
nssCert_IssuerAndSerialEqual (
  NSSCert *c1,
  NSSCert *c2
);

NSS_EXTERN NSSPublicKey *
nssCert_GetPublicKey (
  NSSCert *c
);

NSS_EXTERN NSSPrivateKey *
nssCert_FindPrivateKey (
  NSSCert *c,
  NSSCallback *uhh
);

NSS_EXTERN PRBool
nssCert_IsPrivateKeyAvailable (
  NSSCert *c,
  NSSCallback *uhh,
  PRStatus *statusOpt
);

NSS_EXTERN NSSUsages *
nssCert_GetUsages (
  NSSCert *c,
  PRStatus *statusOpt
);

NSS_EXTERN PRBool
nssCert_IsValidAtTime (
  NSSCert *c,
  NSSTime time,
  PRStatus *statusOpt
);

NSS_EXTERN PRBool
nssCert_IsNewer (
  NSSCert *c1,
  NSSCert *c2,
  PRStatus *statusOpt
);

NSS_EXTERN NSSCert **
nssCert_BuildChain (
  NSSCert *c,
  NSSTime time,
  const NSSUsages *usagesOpt,
  NSSPolicies *policiesOpt,
  NSSCert **rvOpt,
  PRUint32 rvLimit,
  NSSArena *arenaOpt,
  PRStatus *statusOpt
);

NSS_EXTERN NSSPrivateKey *
nssPrivateKey_AddRef (
  NSSPrivateKey *vk
);

NSS_EXTERN NSSPrivateKey *
nssPrivateKey_Decode (
  NSSBER *ber,
  NSSKeyPairType keyPairType,
  NSSOperations operations,
  NSSProperties properties,
  NSSUTF8 *passwordOpt,
  NSSCallback *uhhOpt,
  NSSToken *destination,
  NSSTrustDomain *td,
  NSSVolatileDomain *vdOpt
);

NSS_EXTERN PRStatus
nssPrivateKey_Destroy (
  NSSPrivateKey *vk
);

NSS_EXTERN NSSItem *
nssPrivateKey_GetID (
  NSSPrivateKey *vk
);

NSS_EXTERN NSSUTF8 *
nssPrivateKey_GetNickname (
  NSSPrivateKey *vk,
  NSSToken *tokenOpt
);

NSS_EXTERN NSSPublicKey *
nssPublicKey_AddRef (
  NSSPublicKey *bk
);

NSS_EXTERN PRStatus
nssPublicKey_Destroy (
  NSSPublicKey *bk
);

NSS_EXTERN NSSItem *
nssPublicKey_GetID (
  NSSPublicKey *vk
);

NSS_EXTERN NSSItem *
nssPublicKey_WrapSymKey (
  NSSPublicKey *bk,
  const NSSAlgNParam *ap,
  NSSSymKey *keyToWrap,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN NSSSymKey *
nssSymKey_AddRef (
  NSSSymKey *mk
);

NSS_EXTERN NSSVolatileDomain *
nssVolatileDomain_Create (
  NSSTrustDomain *td,
  NSSCallback *uhhOpt
);

NSS_EXTERN NSSCert **
nssVolatileDomain_FindCertsBySubject (
  NSSVolatileDomain *vd,
  NSSDER *subject,
  NSSCert *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
);

NSS_EXTERN void
nssPublicKeyArray_Destroy (
  NSSPublicKey **bkeys
);

NSS_EXTERN void
nssPrivateKeyArray_Destroy (
  NSSPrivateKey **vkeys
);

NSS_EXTERN void
nssSymKeyArray_Destroy (
  NSSSymKey **mkeys
);

NSS_EXTERN nssTrust *
nssTrust_AddRef (
  nssTrust *trust
);

NSS_EXTERN PRStatus
nssTrust_Destroy (
  nssTrust *trust
);

NSS_EXTERN nssSMIMEProfile *
nssSMIMEProfile_AddRef (
  nssSMIMEProfile *profile
);

NSS_EXTERN PRStatus
nssSMIMEProfile_Destroy (
  nssSMIMEProfile *profile
);

NSS_EXTERN nssSMIMEProfile *
nssSMIMEProfile_Create (
  NSSCert *cert,
  NSSItem *profileTime,
  NSSItem *profileData
);

NSS_EXTERN PRBool
nssTime_WithinRange (
  NSSTime time,
  NSSTime start,
  NSSTime finish
);

NSS_EXTERN PRBool
nssTime_IsAfter (
  NSSTime time,
  NSSTime compareTime
);

PR_END_EXTERN_C

#endif /* PKI_H */
