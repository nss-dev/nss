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
 * nssPKIObject_IsOnToken
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
  NSSArena *arenaOpt,
  nssCryptokiObject *instanceOpt,
  NSSTrustDomain *td,
  NSSVolatileDomain *vdOpt
);

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
nssPKIObject_IsOnToken (
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

NSS_EXTERN NSSCert **
nssTrustDomain_FindCertsByID (
  NSSTrustDomain *td,
  NSSItem *id,
  NSSCert **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN NSSCRL **
nssTrustDomain_FindCRLsBySubject (
  NSSTrustDomain *td,
  NSSDER *subject
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

/* XXX for the collection */
NSS_EXTERN NSSCert *
nssCert_Create (
  nssPKIObject *object
);

NSS_EXTERN NSSCert *
nssCert_CreateFromInstance (
  nssCryptokiObject *instance,
  NSSTrustDomain *td,
  NSSVolatileDomain *vdOpt,
  NSSArena *arenaOpt
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

NSS_EXTERN nssTrust *
nssTrust_Create (
  nssPKIObject *object
);

NSS_EXTERN NSSCRL *
nssCRL_Create (
  nssPKIObject *object
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
nssSymKey_Create (
  nssPKIObject *object
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
nssSymKey_IsOnToken (
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
nssPublicKey_Create (
  nssPKIObject *object
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
  NSSVolatileDomain *vdOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN PRBool
nssPublicKey_IsOnToken (
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

NSS_EXTERN nssCryptokiObject *
nssPublicKey_CopyToToken (
  NSSPublicKey *bk,
  NSSToken *destination,
  PRBool asPersistentObject
);

NSS_EXTERN NSSPrivateKey *
nssPrivateKey_Create (
  nssPKIObject *o
);

NSS_EXTERN PRBool
nssPrivateKey_IsOnToken (
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

NSS_EXTERN nssCryptokiObject *
nssPrivateKey_CopyToToken (
  NSSPrivateKey *vk,
  NSSToken *destination
);

NSS_EXTERN PRBool
nssUsages_Match (
  const NSSUsages *usages,
  const NSSUsages *testUsages
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

/* nssPKIObjectCollection
 *
 * This is a handy way to group objects together and perform operations
 * on them.  It can also handle "proto-objects"-- references to
 * objects instances on tokens, where the actual object hasn't 
 * been formed yet.
 *
 * nssCertCollection_Create
 * nssPrivateKeyCollection_Create
 * nssPublicKeyCollection_Create
 *
 * If this was a language that provided for inheritance, each type would
 * inherit all of the following methods.  Instead, there is only one
 * type (nssPKIObjectCollection), shared among all.  This may cause
 * confusion; an alternative would be to define all of the methods
 * for each subtype (nssCertCollection_Destroy, ...), but that doesn't
 * seem worth the code bloat..  It is left up to the caller to remember 
 * what type of collection he/she is dealing with.
 *
 * nssPKIObjectCollection_Destroy
 * nssPKIObjectCollection_Count
 * nssPKIObjectCollection_AddObject
 * nssPKIObjectCollection_AddInstances
 * nssPKIObjectCollection_Traverse
 *
 * Back to type-specific methods.
 *
 * nssPKIObjectCollection_GetCerts
 * nssPKIObjectCollection_GetCRLs
 * nssPKIObjectCollection_GetPrivateKeys
 * nssPKIObjectCollection_GetPublicKeys
 */

/* nssCertCollection_Create
 *
 * Create a collection of certificates in the specified trust domain.
 * Optionally provide a starting set of certs.
 */
NSS_EXTERN nssPKIObjectCollection *
nssCertCollection_Create (
  NSSTrustDomain *td,
  NSSCert **certsOpt
);

/* nssCRLCollection_Create
 *
 * Create a collection of CRLs/KRLs in the specified trust domain.
 * Optionally provide a starting set of CRLs.
 */
NSS_EXTERN nssPKIObjectCollection *
nssCRLCollection_Create (
  NSSTrustDomain *td,
  NSSCRL **crlsOpt
);

/* nssPrivateKeyCollection_Create
 *
 * Create a collection of private keys in the specified trust domain.
 * Optionally provide a starting set of keys.
 */
NSS_EXTERN nssPKIObjectCollection *
nssPrivateKeyCollection_Create (
  NSSTrustDomain *td,
  NSSPrivateKey **pvkOpt
);

/* nssPublicKeyCollection_Create
 *
 * Create a collection of public keys in the specified trust domain.
 * Optionally provide a starting set of keys.
 */
NSS_EXTERN nssPKIObjectCollection *
nssPublicKeyCollection_Create (
  NSSTrustDomain *td,
  NSSPublicKey **pvkOpt
);

/* nssPKIObjectCollection_Destroy
 */
NSS_EXTERN void
nssPKIObjectCollection_Destroy (
  nssPKIObjectCollection *collection
);

/* nssPKIObjectCollection_Count
 */
NSS_EXTERN PRUint32
nssPKIObjectCollection_Count (
  nssPKIObjectCollection *collection
);

NSS_EXTERN PRStatus
nssPKIObjectCollection_AddObject (
  nssPKIObjectCollection *collection,
  nssPKIObject *object
);

/* nssPKIObjectCollection_AddInstances
 *
 * Add a set of object instances to the collection.  The instances
 * will be sorted into any existing certs/proto-certs that may be in
 * the collection.  The instances will be absorbed by the collection,
 * the array should not be used after this call (except to free it).
 *
 * Failure means the collection is in an invalid state.
 *
 * numInstances = 0 means the array is NULL-terminated
 */
NSS_EXTERN PRStatus
nssPKIObjectCollection_AddInstances (
  nssPKIObjectCollection *collection,
  nssCryptokiObject **instances,
  PRUint32 numInstances
);

/* nssPKIObjectCollection_Traverse
 */
NSS_EXTERN PRStatus
nssPKIObjectCollection_Traverse (
  nssPKIObjectCollection *collection,
  nssPKIObjectCallback *callback
);

/* This function is being added for NSS 3.5.  It corresponds to the function
 * nssToken_TraverseCerts.  The idea is to use the collection during
 * a traversal, creating certs each time a new instance is added for which
 * a cert does not already exist.
 */
NSS_EXTERN PRStatus
nssPKIObjectCollection_AddInstanceAsObject (
  nssPKIObjectCollection *collection,
  nssCryptokiObject *instance
);

/* nssPKIObjectCollection_GetCerts
 *
 * Get all of the certificates in the collection. 
 */
NSS_EXTERN NSSCert **
nssPKIObjectCollection_GetCerts (
  nssPKIObjectCollection *collection,
  NSSCert **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN NSSCRL **
nssPKIObjectCollection_GetCRLs (
  nssPKIObjectCollection *collection,
  NSSCRL **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN NSSPrivateKey **
nssPKIObjectCollection_GetPrivateKeys (
  nssPKIObjectCollection *collection,
  NSSPrivateKey **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN NSSPublicKey **
nssPKIObjectCollection_GetPublicKeys (
  nssPKIObjectCollection *collection,
  NSSPublicKey **rvOpt,
  PRUint32 maximumOpt,
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
nssTokenObjectStore_Create (
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

PR_END_EXTERN_C

#endif /* PKIM_H */
