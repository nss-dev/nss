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

#ifndef PKIM_H
#define PKIM_H

#ifdef DEBUG
static const char PKIM_CVS_ID[] = "@(#) $RCSfile$ $Revision$ $Date$ $Name$";
#endif /* DEBUG */

#ifndef BASE_H
#include "base.h"
#endif /* BASE_H */

#ifndef PKI_H
#include "pki.h"
#endif /* PKI_H */

#ifndef PKITM_H
#include "pkitm.h"
#endif /* PKITM_H */

PR_BEGIN_EXTERN_C

/* nssPKIObject
 *
 * This is the base object class, common to all PKI objects defined in
 * in this module.  Each object can be safely 'casted' to an nssPKIObject,
 * then passed to these methods.
 *
 * nssPKIObject_Create
 * nssPKIObject_Destroy
 * nssPKIObject_AddRef
 * nssPKIObject_AddInstance
 * nssPKIObject_HasInstance
 * nssPKIObject_GetTokens
 * nssPKIObject_HasInstanceOnToken
 * nssPKIObject_SetNickname
 * nssPKIObject_GetNickname
 * nssPKIObject_RemoveInstanceForToken
 * nssPKIObject_DeleteStoredObject
 */

/* nssPKIObject_Create
 *
 * A generic PKI object.  It must live in a trust domain.  It may be
 * initialized with a token instance, or alternatively in a volatile domain.
 */
NSS_EXTERN nssPKIObject *
nssPKIObject_Create (
  NSSTrustDomain *td,
  nssCryptokiObject *instanceOpt,
  PRUint32 size
);

#define nssPKIObject_CREATE(td, instanceOpt, type) \
    (type *)nssPKIObject_Create(td, instanceOpt, sizeof(type))

/* nssPKIObject_AddRef
 */
NSS_EXTERN nssPKIObject *
nssPKIObject_AddRef (
  nssPKIObject *object
);

/* nssPKIObject_Destroy
 *
 * Returns true if object was destroyed.  This notifies the subclass that
 * all references are gone and it should delete any members it owns.
 */
NSS_EXTERN PRBool
nssPKIObject_Destroy (
  nssPKIObject *object
);

/* nssPKIObject_AddInstance
 *
 * Add a token instance to the object, if it does not have it already.
 */
NSS_EXTERN PRStatus
nssPKIObject_AddInstance (
  nssPKIObject *object,
  nssCryptokiObject *instance
);

/* nssPKIObject_HasInstance
 *
 * Query the object for a token instance.
 */
NSS_EXTERN PRBool
nssPKIObject_HasInstance (
  nssPKIObject *object,
  nssCryptokiObject *instance
);

NSS_EXTERN PRIntn
nssPKIObject_CountInstances (
  nssPKIObject *object
);

/* nssPKIObject_GetTokens
 *
 * Get all tokens which have an instance of the object.
 */
NSS_EXTERN NSSToken **
nssPKIObject_GetTokens (
  nssPKIObject *object,
  NSSToken **rvOpt,
  PRUint32 rvMaxOpt,
  PRStatus *statusOpt
);

NSS_EXTERN PRBool
nssPKIObject_HasInstanceOnToken (
  nssPKIObject *object,
  NSSToken *token
);

NSS_EXTERN nssCryptokiObject *
nssPKIObject_GetInstance (
  nssPKIObject *object,
  NSSToken *token
);

/* nssPKIObject_SetNickname
 *
 * tokenOpt == NULL means set the either temp nickname (for volatile 
 * domains) or the "first" token, otherwise set nickname for the 
 * specified token.
 */
NSS_EXTERN PRStatus
nssPKIObject_SetNickname (
  nssPKIObject *object,
  NSSToken *tokenOpt,
  NSSUTF8 *nickname
);

/* nssPKIObject_GetNickname
 *
 * tokenOpt == NULL means take the first available, otherwise return the
 * nickname for the specified token.
 */
NSS_EXTERN NSSUTF8 *
nssPKIObject_GetNickname (
  nssPKIObject *object,
  NSSToken *tokenOpt
);

/* nssPKIObject_RemoveInstanceForToken
 *
 * Remove the instance of the object on the specified token.
 */
NSS_EXTERN PRStatus
nssPKIObject_RemoveInstanceForToken (
  nssPKIObject *object,
  NSSToken *token
);

/* nssPKIObject_DeleteStoredObject
 *
 * Delete all token instances of the object, as well as any crypto context
 * instances (TODO).  If any of the instances are read-only, or if the
 * removal fails, the object will keep those instances.  'isFriendly' refers
 * to the object -- can this object be permanently removed from a friendly 
 * token without login?  For example, softoken certificates are friendly, 
 * private keys are not.  Note that if the token is not friendly, 
 * authentication will be required regardless of the value of 'isFriendly'.
 */
NSS_EXTERN PRStatus
nssPKIObject_DeleteStoredObject (
  nssPKIObject *object,
  NSSCallback *uhh,
  PRBool isFriendly
);

NSS_EXTERN NSSTrustDomain *
nssPKIObject_GetTrustDomain (
  nssPKIObject *object,
  PRStatus *statusOpt
);

NSS_EXTERN NSSVolatileDomain *
nssPKIObject_GetVolatileDomain (
  nssPKIObject *object,
  PRStatus *statusOpt
);

NSS_EXTERN NSSToken *
nssPKIObject_GetWriteToken (
  nssPKIObject *object,
  nssSession **rvSessionOpt
);

NSS_EXTERN nssCryptokiObject **
nssPKIObject_GetInstances (
  nssPKIObject *object
);

NSS_EXTERN nssCryptokiObject *
nssPKIObject_FindInstanceForAlgorithm (
  nssPKIObject *object,
  const NSSAlgNParam *ap
);

NSS_EXTERN NSSToken *
nssTrustDomain_FindSourceToken (
  NSSTrustDomain *td,
  const NSSAlgNParam *ap,
  NSSToken *candidate
);

/* XXX */
NSS_EXTERN nssSession *
nssTrustDomain_GetSessionForToken (
  NSSTrustDomain *td,
  NSSToken *token,
  PRBool readWrite
);

/* XXX */
NSS_EXTERN NSSSlot **
nssTrustDomain_GetActiveSlots (
  NSSTrustDomain *td,
  nssUpdateLevel *updateLevel
);

NSS_EXTERN nssPKIObjectTable *
nssTrustDomain_GetObjectTable (
  NSSTrustDomain *td
);

NSS_EXTERN NSSCert **
nssTrustDomain_FindCertsByID (
  NSSTrustDomain *td,
  NSSItem *id,
  NSSCert **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN NSSPrivateKey *
nssTrustDomain_FindPrivateKeyByID (
  NSSTrustDomain *td,
  NSSItem *keyID
);

NSS_EXTERN NSSCRL **
nssTrustDomain_FindCRLsBySubject (
  NSSTrustDomain *td,
  NSSDER *subject
);

NSS_EXTERN PRStatus
nssTrustDomain_SetCertTrust (
  NSSTrustDomain *td,
  NSSCert *c,
  nssTrust *trust
);

/* module-private nsspki methods */

NSS_EXTERN NSSCryptoContext *
nssCryptoContext_Create (
  NSSTrustDomain *td,
  NSSVolatileDomain *vdOpt,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhhOpt
);

NSS_EXTERN NSSCryptoContext *
nssCryptoContext_CreateForSymKey (
  NSSSymKey *mk,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhh
);

NSS_EXTERN NSSCryptoContext *
nssCryptoContext_CreateForPrivateKey (
  NSSPrivateKey *vkey,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhhOpt
);

NSS_EXTERN NSSCert *
nssCert_CreateFromInstance (
  nssCryptokiObject *instance,
  NSSTrustDomain *td,
  NSSVolatileDomain *vdOpt
);

/* XXX XXX most of these belong in pki.h */

NSS_EXTERN nssCryptokiObject *
nssCert_FindInstanceForAlgorithm (
  NSSCert *c,
  NSSAlgNParam *ap
);

NSS_EXTERN void
nssCert_SetVolatileDomain (
  NSSCert *c,
  NSSVolatileDomain *vd
);

NSS_EXTERN PRStatus
nssCert_RemoveInstanceForToken (
  NSSCert *c,
  NSSToken *token
);

NSS_EXTERN PRBool
nssCert_HasInstanceOnToken (
  NSSCert *c,
  NSSToken *token
);

NSS_EXTERN PRIntn
nssCert_CountInstances (
  NSSCert *c
);

NSS_EXTERN PRStatus
nssCert_CopyToToken (
  NSSCert *c,
  NSSToken *token,
  NSSUTF8 *nicknameOpt
);

NSS_EXTERN PRBool
nssCert_HasCANameInChain (
  NSSCert *c,
  NSSDER **rootCAs,
  PRUint32 rootCAsMaxOpt,
  NSSTime time,
  const NSSUsages *usages,
  NSSPolicies *policiesOpt
);

NSS_EXTERN NSSCRL *
nssCRL_AddRef (
  NSSCRL *crl
);

NSS_EXTERN PRStatus
nssCRL_Destroy (
  NSSCRL *crl
);

NSS_EXTERN PRStatus
nssCRL_DeleteStoredObject (
  NSSCRL *crl,
  NSSCallback *uhh
);

NSS_EXTERN NSSSymKey *
nssSymKey_CreateFromInstance (
  nssCryptokiObject *instance,
  NSSTrustDomain *td,
  NSSVolatileDomain *vdOpt
);

NSS_EXTERN PRStatus
nssSymKey_Destroy (
  NSSSymKey *mk
);

NSS_EXTERN void
nssSymKey_SetVolatileDomain (
  NSSSymKey *mk,
  NSSVolatileDomain *vd
);

NSS_IMPLEMENT nssCryptokiObject *
nssSymKey_CopyToToken (
  NSSSymKey *mk,
  NSSToken *destination,
  PRBool asPersistentObject
);

NSS_EXTERN NSSToken **
nssSymKey_GetTokens (
  NSSSymKey *mk,
  NSSToken **rvOpt,
  PRUint32 rvMaxOpt,
  PRStatus *statusOpt
);

NSS_EXTERN NSSTrustDomain *
nssSymKey_GetTrustDomain (
  NSSSymKey *mk,
  PRStatus *statusOpt
);

NSS_EXTERN PRBool
nssSymKey_HasInstanceOnToken (
  NSSSymKey *mk,
  NSSToken *token
);

NSS_EXTERN nssCryptokiObject *
nssSymKey_GetInstance (
  NSSSymKey *mk,
  NSSToken *token
);

NSS_EXTERN nssCryptokiObject *
nssSymKey_FindInstanceForAlgorithm (
  NSSSymKey *mk,
  const NSSAlgNParam *ap
);

NSS_EXTERN NSSDER *
nssCRL_GetEncoding (
  NSSCRL *crl
);

NSS_EXTERN NSSPublicKey *
nssPublicKey_CreateFromInfo (
  NSSTrustDomain *td,
  NSSVolatileDomain *vdOpt,
  NSSOIDTag keyAlg,
  NSSBitString *keyBits
);

NSS_EXTERN NSSPublicKey *
nssPublicKey_CreateFromInstance (
  nssCryptokiObject *instance,
  NSSTrustDomain *td,
  NSSVolatileDomain *vdOpt
);

NSS_EXTERN void
nssPublicKey_SetVolatileDomain (
  NSSPublicKey *bk,
  NSSVolatileDomain *vd
);

NSS_EXTERN PRBool
nssPublicKey_HasInstanceOnToken (
  NSSPublicKey *bk,
  NSSToken *token
);

NSS_EXTERN nssCryptokiObject *
nssPublicKey_GetInstance (
  NSSPublicKey *bk,
  NSSToken *token
);

NSS_EXTERN nssCryptokiObject *
nssPublicKey_FindInstanceForAlgorithm (
  NSSPublicKey *bk,
  const NSSAlgNParam *ap
);

NSS_EXTERN PRStatus
nssPublicKey_RemoveInstanceForToken (
  NSSPublicKey *bk,
  NSSToken *token
);

NSS_EXTERN PRIntn
nssPublicKey_CountInstances (
  NSSPublicKey *bk
);

NSS_EXTERN nssCryptokiObject *
nssPublicKey_CopyToToken (
  NSSPublicKey *bk,
  NSSToken *destination,
  PRBool asPersistentObject
);

NSS_EXTERN NSSPrivateKey *
nssPrivateKey_CreateFromInstance (
  nssCryptokiObject *instance,
  NSSTrustDomain *td,
  NSSVolatileDomain *vdOpt
);

NSS_EXTERN void
nssPrivateKey_SetVolatileDomain (
  NSSPrivateKey *vk,
  NSSVolatileDomain *vd
);

NSS_EXTERN PRBool
nssPrivateKey_HasInstanceOnToken (
  NSSPrivateKey *vk,
  NSSToken *token
);

NSS_EXTERN nssCryptokiObject *
nssPrivateKey_GetInstance (
  NSSPrivateKey *vk,
  NSSToken *token
);

NSS_EXTERN nssCryptokiObject *
nssPrivateKey_FindInstanceForAlgorithm (
  NSSPrivateKey *vk,
  const NSSAlgNParam *ap
);

NSS_EXTERN PRStatus
nssPrivateKey_RemoveInstanceForToken (
  NSSPrivateKey *vk,
  NSSToken *token
);

NSS_EXTERN PRIntn
nssPrivateKey_CountInstances (
  NSSPrivateKey *vk
);

NSS_EXTERN nssCryptokiObject *
nssPrivateKey_CopyToToken (
  NSSPrivateKey *vk,
  NSSToken *destination
);

NSS_EXTERN PRIntn
nssObjectArray_Count (
  void **objects
);

/* nssCertArray
 *
 * These are being thrown around a lot, might as well group together some
 * functionality.
 *
 * nssCertArray_Destroy
 * nssCertArray_Join
 * nssCertArray_FindBestCert
 * nssCertArray_Traverse
 */

NSS_EXTERN NSSCert **
nssCertArray_CreateFromInstances (
  nssCryptokiObject **instances,
  NSSTrustDomain *td,
  NSSVolatileDomain *vdOpt,
  NSSArena *arenaOpt
);

/* nssCertArray_Destroy
 *
 * Will destroy the array and the certs within it.  If the array was created
 * in an arena, will *not* (of course) destroy the arena.  However, is safe
 * to call this method on an arena-allocated array.
 */
NSS_EXTERN void
nssCertArray_Destroy (
  NSSCert **certs
);

NSS_EXTERN NSSCert **
nssCertArray_Duplicate (
  NSSCert **certs,
  NSSArena *arenaOpt
);

/* nssCertArray_Join
 *
 * Join two arrays into one.  The two arrays, certs1 and certs2, should
 * be considered invalid after a call to this function (they may be destroyed
 * as part of the join).  certs1 and/or certs2 may be NULL.  Safe to
 * call with arrays allocated in an arena, the result will also be in the
 * arena.
 */
NSS_EXTERN NSSCert **
nssCertArray_Join (
  NSSCert **certs1,
  NSSCert **certs2
);

/* nssCertArray_FindBestCert
 *
 * Use the usual { time, usage, policies } to find the best cert in the
 * array.
 */
NSS_EXTERN NSSCert * 
nssCertArray_FindBestCert (
  NSSCert **certs, 
  NSSTime time,
  const NSSUsages *usagesOpt,
  NSSPolicies *policiesOpt
);

/* nssCertArray_Traverse
 *
 * Do the callback for each cert, terminate the traversal if the callback
 * fails.
 */
NSS_EXTERN PRStatus
nssCertArray_Traverse (
  NSSCert **certs,
  PRStatus (* callback)(NSSCert *c, void *arg),
  void *arg
);

NSS_EXTERN void
nssCRLArray_Destroy (
  NSSCRL **crls
);

NSS_EXTERN NSSPublicKey **
nssPublicKeyArray_CreateFromInstances (
  nssCryptokiObject **instances,
  NSSTrustDomain *td,
  NSSVolatileDomain *vdOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN NSSPrivateKey **
nssPrivateKeyArray_CreateFromInstances (
  nssCryptokiObject **instances,
  NSSTrustDomain *td,
  NSSVolatileDomain *vdOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN PRStatus
nssPKIObjectCreator_GenerateKeyPair (
  nssPKIObjectCreator *creator,
  NSSPublicKey **pbkOpt,
  NSSPrivateKey **pvkOpt
);

NSS_EXTERN NSSSymKey *
nssPKIObjectCreator_GenerateSymKey (
  nssPKIObjectCreator *creator,
  PRUint32 keysize
);

NSS_EXTERN nssHash *
nssHash_CreateCert (
  NSSArena *arenaOpt,
  PRUint32 numBuckets
);

NSS_EXTERN nssTokenSessionHash *
nssTokenSessionHash_Create (
  void
);

NSS_IMPLEMENT void
nssTokenSessionHash_Destroy (
  nssTokenSessionHash *tsHash
);

NSS_EXTERN nssSession *
nssTokenSessionHash_GetSession (
  nssTokenSessionHash *tsHash,
  NSSToken *token,
  PRBool readWrite
);

NSS_EXTERN nssTokenStore *
nssTokenStore_Create (
  NSSTrustDomain *td,
  NSSToken **tokens
);

NSS_EXTERN void
nssTokenStore_Destroy (
  nssTokenStore *store
);

NSS_EXTERN void
nssTokenStore_Refresh (
  nssTokenStore *store
);

NSS_EXTERN PRStatus
nssTokenStore_AddToken (
  nssTokenStore *store,
  NSSToken *token
);

NSS_EXTERN PRStatus
nssTokenStore_ImportCert (
  nssTokenStore *store,
  NSSCert *cert,
  NSSUTF8 *nicknameOpt,
  NSSToken *destination
);

NSS_EXTERN NSSCert *
nssTokenStore_ImportPrivateKey (
  nssTokenStore *store,
  NSSPrivateKey *vkey,
  NSSUTF8 *nicknameOpt,
  NSSUTF8 *passwordOpt,
  NSSOperations operations,
  NSSProperties properties,
  NSSCallback uhhOpt,
  NSSToken *destination
);

/* XXX Delete */
NSS_EXTERN void
nssTokenStore_RemoveCert (
  nssTokenStore *store,
  NSSCert *cert
);

NSS_EXTERN PRStatus
nssTokenStore_DeletePrivateKey (
  nssTokenStore *store,
  NSSPrivateKey *vkey,
  NSSToken *source
);

NSS_EXTERN NSSCert **
nssTokenStore_FindCertsByNickname (
  nssTokenStore *store,
  NSSUTF8 *name,
  NSSCert **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN NSSCert **
nssTokenStore_FindCertsBySubject (
  nssTokenStore *store,
  NSSBER *subject,
  NSSCert **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN NSSCert **
nssTokenStore_FindCertsByEmail (
  nssTokenStore *store,
  NSSASCII7 *email,
  NSSCert **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN NSSCert *
nssTokenStore_FindCertByIssuerAndSerialNumber (
  nssTokenStore *store,
  NSSBER *issuer,
  NSSBER *serial
);

NSS_EXTERN NSSCert *
nssTokenStore_FindCertByEncodedCert (
  nssTokenStore *store,
  NSSBER *ber
);

NSS_EXTERN NSSCert **
nssTokenStore_FindCertsByID (
  nssTokenStore *store,
  NSSItem *id,
  NSSCert **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN PRStatus
nssTokenStore_TraverseCerts (
  nssTokenStore *store,
  PRStatus (*callback)(NSSCert *c, void *arg),
  void *arg
);

NSS_EXTERN NSSPublicKey *
nssTokenStore_FindPublicKeyByID (
  nssTokenStore *store,
  NSSItem *id
);

NSS_EXTERN NSSPrivateKey *
nssTokenStore_FindPrivateKeyByID (
  nssTokenStore *store,
  NSSItem *id
);

NSS_EXTERN PRStatus *
nssTokenStore_TraversePrivateKeys (
  nssTokenStore *store,
  PRStatus (*callback)(NSSPrivateKey *vk, void *arg),
  void *arg
);

NSS_EXTERN nssPKIDatabase *
nssPKIDatabase_Open (
  NSSTrustDomain *td,
  const char *path,
  PRUint32 flags
);

NSS_EXTERN PRStatus
nssPKIDatabase_Close (
  nssPKIDatabase *pkidb
);

NSS_EXTERN PRStatus
nssPKIDatabase_ImportCert (
  nssPKIDatabase *pkidb,
  NSSCert *cert,
  NSSUTF8 *nicknameOpt,
  nssTrust *trustOpt
);

NSS_EXTERN PRStatus
nssPKIDatabase_ImportCertTrust (
  nssPKIDatabase *pkidb,
  NSSCert *cert,
  nssTrust *trust
);

NSS_EXTERN PRStatus
nssPKIDatabase_DeleteCert (
  nssPKIDatabase *pkidb,
  NSSCert *cert
);

NSS_EXTERN PRStatus
nssPKIDatabase_SetCertTrust (
  nssPKIDatabase *pkidb,
  NSSCert *cert,
  nssTrust *trust
);

NSS_EXTERN NSSCert **
nssPKIDatabase_FindCertsByNickname (
  nssPKIDatabase *pkidb,
  NSSUTF8 *nickname,
  NSSCert **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN NSSCert **
nssPKIDatabase_FindCertsBySubject (
  nssPKIDatabase *pkidb,
  NSSBER *subject,
  NSSCert **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN NSSCert **
nssPKIDatabase_FindCertsByEmail (
  nssPKIDatabase *pkidb,
  NSSASCII7 *email,
  NSSCert **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN NSSCert *
nssPKIDatabase_FindCertByIssuerAndSerialNumber (
  nssPKIDatabase *pkidb,
  NSSBER *issuer,
  NSSBER *serial
);

NSS_EXTERN NSSCert *
nssPKIDatabase_FindCertByEncodedCert (
  nssPKIDatabase *pkidb,
  NSSBER *ber
);

NSS_EXTERN PRStatus
nssPKIDatabase_FindTrustForCert (
  nssPKIDatabase *pkidb,
  NSSCert *cert,
  nssTrust *rvTrust
);

NSS_EXTERN PRStatus
nssPKIDatabase_TraverseCerts (
  nssPKIDatabase *pkidb,
  PRStatus (*callback)(NSSCert *c, void *arg),
  void *arg
);

NSS_EXTERN nssPKIObjectTable *
nssPKIObjectTable_Create (
  NSSArena *arena
);

NSS_EXTERN void
nssPKIObjectTable_Destroy (
  nssPKIObjectTable *table
);

NSS_EXTERN nssPKIObject *
nssPKIObjectTable_Add (
  nssPKIObjectTable *table,
  nssPKIObject *object
);

PR_END_EXTERN_C

#endif /* PKIM_H */
