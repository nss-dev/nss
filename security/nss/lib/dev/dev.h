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

#ifndef DEV_H
#define DEV_H

/*
 * dev.h
 *
 * Low-level methods for interaction with cryptoki devices
 */

#ifdef DEBUG
static const char DEV_CVS_ID[] = "@(#) $RCSfile$ $Revision$ $Date$ $Name$";
#endif /* DEBUG */

#ifndef NSSCKT_H
#include "nssckt.h"
#endif /* NSSCKT_H */

#ifndef NSSDEV_H
#include "nssdev.h"
#endif /* NSSDEV_H */

#ifndef DEVT_H
#include "devt.h"
#endif /* DEVT_H */

#ifndef PKI1T_H
#include "pki1t.h"
#endif /* PKI1T_H */
#include "oiddata.h"

PR_BEGIN_EXTERN_C

/*
 *  |-----------|<---> NSSSlot <--> NSSToken
 *  | NSSModule |<---> NSSSlot <--> NSSToken
 *  |-----------|<---> NSSSlot <--> NSSToken
 */

/* NSSModule
 *
 * nssModule_Create
 * nssModule_CreateFromSpec
 * nssModule_AddRef
 * nssModule_Unload
 * nssModule_GetName
 * nssModule_GetSlots
 * nssModule_FindSlotByName
 * nssModule_FindTokenByName
 * nssModule_GetCertOrder
 * nssModule_GetTrustOrder
 */

NSS_EXTERN NSSModule *
nssModule_Create (
  NSSUTF8 *moduleOpt,
  NSSUTF8 *uriOpt,
  NSSUTF8 *opaqueOpt,
  void    *reserved
);

NSS_EXTERN NSSModule *
nssModule_CreateFromSpec (
  NSSUTF8 *moduleSpec,
  NSSModule *parent,
  PRBool loadSubModules
);

NSS_EXTERN PRStatus
nssModule_Destroy (
  NSSModule *mod
);

NSS_EXTERN NSSModule *
nssModule_AddRef (
  NSSModule *mod
);

NSS_EXTERN PRStatus
nssModule_Unload (
  NSSModule *mod
);

NSS_EXTERN NSSUTF8 *
nssModule_GetName (
  NSSModule *mod
);

NSS_EXTERN NSSSlot **
nssModule_GetSlots (
  NSSModule *mod
);

NSS_EXTERN NSSSlot *
nssModule_FindSlotByName (
  NSSModule *mod,
  NSSUTF8 *slotName
);

NSS_EXTERN NSSToken *
nssModule_FindTokenByName (
  NSSModule *mod,
  NSSUTF8 *tokenName
);

NSS_EXTERN PRInt32
nssModule_GetCertOrder (
  NSSModule *module
);

NSS_EXTERN PRInt32
nssModule_GetTrustOrder (
  NSSModule *module
);

NSS_EXTERN PRBool
nssModule_IsThreadSafe (
  NSSModule *module
);

NSS_EXTERN PRBool
nssModule_IsInternal (
  NSSModule *mod
);

NSS_EXTERN PRBool
nssModule_IsModuleDBOnly (
  NSSModule *mod
);

/* NSSSlot
 *
 * nssSlot_Destroy
 * nssSlot_AddRef
 * nssSlot_GetName
 * nssSlot_GetTokenName
 * nssSlot_IsTokenPresent
 * nssSlot_IsPermanent
 * nssSlot_IsFriendly
 * nssSlot_IsHardware
 * nssSlot_Refresh
 * nssSlot_GetModule
 * nssSlot_GetToken
 * nssSlot_Login
 * nssSlot_Logout
 * nssSlot_SetPassword
 * nssSlot_CreateSession
 */

NSS_EXTERN PRStatus
nssSlot_Destroy (
  NSSSlot *slot
);

NSS_EXTERN NSSSlot *
nssSlot_AddRef (
  NSSSlot *slot
);

NSS_EXTERN NSSUTF8 *
nssSlot_GetName (
  NSSSlot *slot
);

NSS_EXTERN NSSUTF8 *
nssSlot_GetTokenName (
  NSSSlot *slot
);

NSS_EXTERN NSSModule *
nssSlot_GetModule (
  NSSSlot *slot
);

NSS_EXTERN NSSToken *
nssSlot_GetToken (
  NSSSlot *slot
);

NSS_EXTERN PRBool
nssSlot_IsTokenPresent (
  NSSSlot *slot
);

NSS_EXTERN PRBool
nssSlot_IsPermanent (
  NSSSlot *slot
);

NSS_EXTERN PRBool
nssSlot_IsFriendly (
  NSSSlot *slot
);

NSS_EXTERN PRBool
nssSlot_IsHardware (
  NSSSlot *slot
);

/*
 * nssSlot_IsLoggedIn
 */

NSS_EXTERN PRBool
nssSlot_IsLoggedIn (
  NSSSlot *slot
);

NSS_EXTERN PRStatus
nssSlot_Refresh (
  NSSSlot *slot
);

NSS_EXTERN PRStatus
nssSlot_Login (
  NSSSlot *slot,
  NSSCallback *pwcb
);

NSS_EXTERN PRStatus
nssSlot_Logout (
  NSSSlot *slot,
  nssSession *session
);

NSS_EXTERN PRStatus
nssSlot_CheckPassword (
  NSSSlot *slot,
  const NSSUTF8 *password
);

#define NSSSLOT_ASK_PASSWORD_FIRST_TIME -1
#define NSSSLOT_ASK_PASSWORD_EVERY_TIME  0
NSS_EXTERN void
nssSlot_SetPasswordDefaults (
  NSSSlot *slot,
  PRInt32 askPasswordTimeout
);

NSS_EXTERN PRStatus
nssSlot_SetPassword (
  NSSSlot *slot,
  NSSUTF8 *oldPasswordOpt,
  NSSUTF8 *newPassword
);

NSS_EXTERN nssSession *
nssSlot_CreateSession (
  NSSSlot *slot,
  PRBool readWrite /* so far, this is the only flag used */
);

/* NSSToken
 *
 * nssToken_Destroy
 * nssToken_AddRef
 *
 *   ------- gettors ----------
 * nssToken_GetName
 * nssToken_GetModule
 * nssToken_GetSlot
 * nssToken_IsReadOnly
 * nssToken_DoesAlgorithm
 * nssToken_CreateSession
 *
 *   ------- login -------
 * nssToken_NeedsPINInitialization
 *
 *   ------ certificate objects --------
 * nssToken_ImportCert
 * nssToken_FindCerts
 * nssToken_FindCertsBySubject
 * nssToken_FindCertsByNickname
 * nssToken_FindCertsByEmail
 * nssToken_FindCertByIssuerAndSerialNumber
 * nssToken_FindCertByEncodedCert
 *
 *   ------ trust objects --------
 * nssToken_ImportTrust
 * nssToken_FindTrustObjects
 * nssToken_FindTrustForCert
 *
 *   ------ CRL objects --------
 * nssToken_ImportCRL
 * nssToken_FindCRLs
 * nssToken_FindCRLsBySubject
 *
 *   ------ public/private key objects --------
 * nssToken_GenerateKeyPair
 * nssToken_FindPrivateKeys
 * nssToken_FindPrivateKeyByID
 * nssToken_FindPublicKeyByID
 *
 *   ------ secret key objects --------
 * nssToken_GenerateSymKey
 *
 *   ------ generic key stuff -------
 * nssToken_UnwrapPrivateKey
 * nssToken_UnwrapSymKey
 * nssToken_WrapKey
 * nssToken_DeriveKey
 *
 *   ------ crypto operations --------
 * nssToken_Encrypt
 * nssToken_BeginEncrypt
 * nssToken_ContinueEncrypt
 * nssToken_FinishEncrypt
 * nssToken_Decrypt
 * nssToken_BeginDecrypt
 * nssToken_ContinueDecrypt
 * nssToken_FinishDecrypt
 * nssToken_Sign
 * nssToken_BeginSign
 * nssToken_ContinueSign
 * nssToken_FinishSign
 * nssToken_SignRecover
 * nssToken_Verify
 * nssToken_BeginVerify
 * nssToken_ContinueVerify
 * nssToken_FinishVerify
 * nssToken_VerifyRecover
 * nssToken_Digest
 * nssToken_BeginDigest
 * nssToken_ContinueDigest
 * nssToken_FinishDigest
 */

NSS_EXTERN PRStatus
nssToken_Destroy (
  NSSToken *tok
);

NSS_EXTERN NSSToken *
nssToken_AddRef (
  NSSToken *tok
);

NSS_EXTERN NSSUTF8 *
nssToken_GetName (
  NSSToken *tok
);

NSS_EXTERN NSSModule *
nssToken_GetModule (
  NSSToken *token
);

NSS_EXTERN NSSSlot *
nssToken_GetSlot (
  NSSToken *tok
);

NSS_EXTERN PRBool
nssToken_IsReadOnly (
  NSSToken *token
);

NSS_EXTERN PRBool
nssToken_DoesAlgorithm (
  NSSToken *token,
  NSSOIDTag alg
);

/* XXX keep both? */
NSS_EXTERN PRBool
nssToken_DoesAlgNParam (
  NSSToken *token,
  const NSSAlgNParam *ap
);

NSS_EXTERN nssSession *
nssToken_CreateSession (
  NSSToken *token,
  PRBool readWrite
);

NSS_EXTERN PRBool
nssToken_NeedsPINInitialization (
  NSSToken *token
);

NSS_EXTERN nssCryptokiObject *
nssToken_ImportCert (
  NSSToken *tok,
  nssSession *session,
  NSSCertType certType,
  NSSItem *id,
  NSSUTF8 *nickname,
  NSSDER *encoding,
  NSSDER *issuer,
  NSSDER *subject,
  NSSDER *serial,
  NSSASCII7 *emailAddr,
  PRBool asTokenObject
);

NSS_EXTERN nssCryptokiObject **
nssToken_FindCerts (
  NSSToken *token,
  nssSession *session,
  nssTokenSearchType searchType,
  PRUint32 maximumOpt,
  PRStatus *statusOpt
);

NSS_EXTERN nssCryptokiObject **
nssToken_FindCertsBySubject (
  NSSToken *token,
  nssSession *session,
  NSSDER *subject,
  nssTokenSearchType searchType,
  PRUint32 maximumOpt,
  PRStatus *statusOpt
);

NSS_EXTERN nssCryptokiObject **
nssToken_FindCertsByNickname (
  NSSToken *token,
  nssSession *session,
  NSSUTF8 *name,
  nssTokenSearchType searchType,
  PRUint32 maximumOpt,
  PRStatus *statusOpt
);

NSS_EXTERN nssCryptokiObject **
nssToken_FindCertsByEmail (
  NSSToken *token,
  nssSession *session,
  NSSASCII7 *email,
  nssTokenSearchType searchType,
  PRUint32 maximumOpt,
  PRStatus *statusOpt
);

NSS_EXTERN nssCryptokiObject **
nssToken_FindCertsByID (
  NSSToken *token,
  nssSession *session,
  NSSItem *id,
  nssTokenSearchType searchType,
  PRUint32 maximumOpt,
  PRStatus *statusOpt
);

NSS_EXTERN nssCryptokiObject *
nssToken_FindCertByIssuerAndSerialNumber (
  NSSToken *token,
  nssSession *session,
  NSSDER *issuer,
  NSSDER *serial,
  nssTokenSearchType searchType,
  PRStatus *statusOpt
);

NSS_EXTERN nssCryptokiObject *
nssToken_FindCertByEncodedCert (
  NSSToken *token,
  nssSession *session,
  NSSBER *encodedCert,
  nssTokenSearchType searchType,
  PRStatus *statusOpt
);

NSS_EXTERN nssCryptokiObject *
nssToken_ImportTrust (
  NSSToken *tok,
  nssSession *session,
  NSSDER *certEncoding,
  NSSDER *certIssuer,
  NSSDER *certSerial,
  nssTrustLevel serverAuth,
  nssTrustLevel clientAuth,
  nssTrustLevel codeSigning,
  nssTrustLevel emailProtection,
  PRBool asTokenObject
);

NSS_EXTERN nssCryptokiObject **
nssToken_FindTrustObjects (
  NSSToken *token,
  nssSession *session,
  nssTokenSearchType searchType,
  PRUint32 maximumOpt,
  PRStatus *statusOpt
);

NSS_EXTERN nssCryptokiObject *
nssToken_FindTrustForCert (
  NSSToken *token,
  nssSession *session,
  NSSDER *certEncoding,
  NSSDER *certIssuer,
  NSSDER *certSerial,
  nssTokenSearchType searchType
);

NSS_EXTERN nssCryptokiObject *
nssToken_ImportCRL (
  NSSToken *token,
  nssSession *session,
  NSSDER *subject,
  NSSDER *encoding,
  PRBool isKRL,
  NSSUTF8 *url,
  PRBool asTokenObject
);

NSS_EXTERN nssCryptokiObject **
nssToken_FindCRLs (
  NSSToken *token,
  nssSession *session,
  nssTokenSearchType searchType,
  PRUint32 maximumOpt,
  PRStatus *statusOpt
);

NSS_EXTERN nssCryptokiObject **
nssToken_FindCRLsBySubject (
  NSSToken *token,
  nssSession *session,
  NSSDER *subject,
  nssTokenSearchType searchType,
  PRUint32 maximumOpt,
  PRStatus *statusOpt
);

NSS_EXTERN PRStatus
nssToken_GenerateKeyPair (
  NSSToken *tok,
  nssSession *session,
  const NSSAlgNParam *ap,
  PRBool asTokenObjects,
  const NSSUTF8 *labelOpt,
  NSSProperties properties,
  NSSOperations operations,
  nssCryptokiObject **publicKey,
  nssCryptokiObject **privateKey
);

NSS_EXTERN nssCryptokiObject *
nssToken_ImportPublicKey (
  NSSToken *token,
  nssSession *session,
  NSSPublicKeyInfo *bki,
  PRBool asTokenObject
);

NSS_EXTERN nssCryptokiObject **
nssToken_FindPrivateKeys (
  NSSToken *token,
  nssSession *session,
  nssTokenSearchType searchType,
  PRUint32 maximumOpt,
  PRStatus *statusOpt
);

NSS_EXTERN nssCryptokiObject *
nssToken_FindPrivateKeyByID (
  NSSToken *token,
  nssSession *session,
  NSSItem *keyID
);

NSS_EXTERN nssCryptokiObject *
nssToken_FindPublicKeyByID (
  NSSToken *token,
  nssSession *session,
  NSSItem *keyID
);

NSS_EXTERN nssCryptokiObject *
nssToken_GenerateSymKey (
  NSSToken *token,
  nssSession *session,
  const NSSAlgNParam *ap,
  PRUint32 keysize,
  const NSSUTF8 *labelOpt,
  PRBool asTokenObject,
  NSSOperations operations,
  NSSProperties properties
);

NSS_EXTERN nssCryptokiObject *
nssToken_ImportRawSymKey (
  NSSToken *token,
  nssSession *session,
  NSSItem *keyData,
  NSSSymKeyType symKeyType,
  PRBool asTokenObject,
  const NSSUTF8 *labelOpt,
  NSSOperations operations,
  NSSProperties properties
);

NSS_EXTERN nssCryptokiObject *
nssToken_UnwrapPrivateKey (
  NSSToken *token,
  nssSession *session,
  const NSSAlgNParam *ap,
  nssCryptokiObject *wrappingKey,
  NSSItem *wrappedKey,
  PRBool asTokenObject,
  NSSOperations operations,
  NSSProperties properties,
  NSSKeyPairType privKeyType
);

NSS_IMPLEMENT nssCryptokiObject *
nssToken_UnwrapSymKey (
  NSSToken *token,
  nssSession *session,
  const NSSAlgNParam *ap,
  nssCryptokiObject *wrappingKey,
  NSSItem *wrappedKey,
  PRBool asTokenObject,
  NSSOperations operations,
  NSSProperties properties,
  NSSSymKeyType symKeyType
);

NSS_EXTERN NSSItem *
nssToken_WrapKey (
  NSSToken *token,
  nssSession *session,
  const NSSAlgNParam *ap,
  nssCryptokiObject *wrappingKey,
  nssCryptokiObject *targetKey,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN nssCryptokiObject *
nssToken_DeriveKey (
  NSSToken *token,
  nssSession *session,
  const NSSAlgNParam *ap,
  nssCryptokiObject *baseKey,
  PRBool asTokenObject,
  NSSOperations operations,
  NSSProperties properties
);

/*
 *
 * rvSessionKeys -- [0] client MAC
 *                  [1] server MAC
 *                  [2] client write
 *                  [3] server write
 */
NSS_EXTERN PRStatus
nssToken_DeriveSSLSessionKeys (
  NSSToken *token,
  nssSession *session,
  const NSSAlgNParam *ap,
  nssCryptokiObject *masterSecret,
  PRUint32 keySize,
  NSSSymKeyType keyType,
  nssCryptokiObject **rvSessionKeys /* [4] */
);

NSS_EXTERN PRStatus
nssToken_SeedRandom (
  NSSToken *token,
  NSSItem *seed
);

NSS_EXTERN PRUint8 *
nssToken_GenerateRandom (
  NSSToken *token,
  PRUint8 *rvOpt,
  PRUint32 numBytes,
  NSSArena *arenaOpt
);

NSS_EXTERN NSSItem *
nssToken_Encrypt (
  NSSToken *tok,
  nssSession *session,
  const NSSAlgNParam *ap,
  nssCryptokiObject *key,
  NSSItem *data,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN PRStatus
nssToken_BeginEncrypt (
  NSSToken *token,
  nssSession *session,
  const NSSAlgNParam *ap,
  nssCryptokiObject *key
);

NSS_EXTERN NSSItem *
nssToken_ContinueEncrypt (
  NSSToken *token,
  nssSession *session,
  NSSItem *data,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN NSSItem *
nssToken_FinishEncrypt (
  NSSToken *token,
  nssSession *session,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN NSSItem *
nssToken_Decrypt (
  NSSToken *tok,
  nssSession *session,
  const NSSAlgNParam *ap,
  nssCryptokiObject *key,
  NSSItem *data,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN PRStatus
nssToken_BeginDecrypt (
  NSSToken *token,
  nssSession *session,
  const NSSAlgNParam *ap,
  nssCryptokiObject *key
);

NSS_EXTERN NSSItem *
nssToken_ContinueDecrypt (
  NSSToken *token,
  nssSession *session,
  NSSItem *data,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN NSSItem *
nssToken_FinishDecrypt (
  NSSToken *token,
  nssSession *session,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN NSSItem *
nssToken_Sign (
  NSSToken *token,
  nssSession *session,
  const NSSAlgNParam *ap,
  nssCryptokiObject *key,
  NSSItem *data,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN PRStatus
nssToken_BeginSign (
  NSSToken *token,
  nssSession *session,
  const NSSAlgNParam *ap,
  nssCryptokiObject *key
);

NSS_EXTERN PRStatus
nssToken_ContinueSign (
  NSSToken *token,
  nssSession *session,
  NSSItem *data
);

NSS_EXTERN NSSItem *
nssToken_FinishSign (
  NSSToken *tok,
  nssSession *session,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN NSSItem *
nssToken_SignRecover (
  NSSToken *tok,
  nssSession *session,
  const NSSAlgNParam *ap,
  nssCryptokiObject *key,
  NSSItem *data,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);


NSS_EXTERN PRStatus
nssToken_Verify (
  NSSToken *token,
  nssSession *session,
  const NSSAlgNParam *ap,
  nssCryptokiObject *key,
  NSSItem *data,
  NSSItem *signature
);

NSS_EXTERN PRStatus
nssToken_BeginVerify (
  NSSToken *token,
  nssSession *session,
  const NSSAlgNParam *ap,
  nssCryptokiObject *key
);

NSS_EXTERN PRStatus
nssToken_ContinueVerify (
  NSSToken *token,
  nssSession *session,
  NSSItem *data
);

NSS_EXTERN PRStatus
nssToken_FinishVerify (
  NSSToken *tok,
  nssSession *session,
  NSSItem *signature
);

NSS_EXTERN NSSItem *
nssToken_VerifyRecover (
  NSSToken *tok,
  nssSession *session,
  const NSSAlgNParam *ap,
  nssCryptokiObject *key,
  NSSItem *signature,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN NSSItem *
nssToken_Digest (
  NSSToken *tok,
  nssSession *session,
  const NSSAlgNParam *ap,
  NSSItem *data,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN PRStatus
nssToken_BeginDigest (
  NSSToken *tok,
  nssSession *session,
  const NSSAlgNParam *ap
);

NSS_EXTERN PRStatus
nssToken_ContinueDigest (
  NSSToken *tok,
  nssSession *session,
  NSSItem *item
);

NSS_EXTERN PRStatus
nssToken_DigestKey (
  NSSToken *tok,
  nssSession *session,
  nssCryptokiObject *key
);

NSS_EXTERN NSSItem *
nssToken_FinishDigest (
  NSSToken *tok,
  nssSession *session,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSAlgNParam
 */

NSS_EXTERN NSSAlgNParam *
nssAlgNParam_Create (
  NSSArena *arenaOpt,
  const NSSOID *algorithm,
  NSSParameters *parametersOpt
);

NSS_EXTERN NSSAlgNParam *
nssAlgNParam_CreateForKeyGen (
  NSSArena *arenaOpt,
  const NSSOID *algorithm,
  NSSParameters *parametersOpt
);

NSS_EXTERN NSSAlgNParam *
nssAlgNParam_Decode (
  NSSArena *arenaOpt,
  NSSBER *algIDber
);

NSS_EXTERN NSSAlgNParam *
nssAlgNParam_Clone (
  const NSSAlgNParam *ap,
  NSSArena *arenaOpt
);

NSS_EXTERN NSSBER *
nssAlgNParam_Encode (
  const NSSAlgNParam *ap,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN NSSAlgNParam *
nssAlgNParam_CreateDefaultForSymKey (
  NSSArena *arenaOpt,
  NSSSymKeyType symKeyType
);

NSS_EXTERN NSSAlgNParam *
nssAlgNParam_ConvertPBEToCrypto (
  const NSSAlgNParam *ap,
  PRBool usePadding
);

NSS_EXTERN PRStatus
nssAlgNParam_SetPBEPassword (
  NSSAlgNParam *ap,
  NSSUTF8 *password
);

NSS_EXTERN void
nssAlgNParam_Destroy (
  NSSAlgNParam *ap
);

/* nssSession
 *
 * nssSession_AddRef
 * nssSession_Destroy
 * nssSession_EnterMonitor
 * nssSession_ExitMonitor
 * nssSession_IsReadWrite
 */

NSS_EXTERN nssSession *
nssSession_AddRef (
  nssSession *s
);

NSS_EXTERN PRStatus
nssSession_Destroy (
  nssSession *s
);

/* would like to inline */
NSS_EXTERN PRStatus
nssSession_EnterMonitor (
  nssSession *s
);

/* would like to inline */
NSS_EXTERN PRStatus
nssSession_ExitMonitor (
  nssSession *s
);

/* would like to inline */
NSS_EXTERN PRBool
nssSession_IsReadWrite (
  nssSession *s
);

NSS_EXTERN PRStatus
nssSession_Save (
  nssSession *s,
  NSSItem *state,
  NSSArena *arenaOpt
);

NSS_EXTERN PRStatus
nssSession_Restore (
  nssSession *s,
  NSSItem *state
);

NSS_EXTERN nssSession *
nssSession_Clone (
  nssSession *s
);

/* nssCryptokiObject
 *
 * An object living on a cryptoki token.
 * Not really proper to mix up the object types just because 
 * nssCryptokiObject itself is generic, but doing so anyway.
 *
 * nssCryptokiObject_Destroy
 * nssCryptokiObject_DeleteStoredObject
 * nssCryptokiObject_Equal
 * nssCryptokiObject_Clone
 * nssCryptokiCert_GetAttributes
 * nssCryptokiPrivateKey_GetAttributes
 * nssCryptokiPublicKey_GetAttributes
 * nssCryptokiTrust_GetAttributes
 * nssCryptokiCRL_GetAttributes
 * nssCryptokiSymKey_GetAttributes
 */

NSS_EXTERN void
nssCryptokiObject_Destroy (
  nssCryptokiObject *object
);

/*
 * The object will also be destroyed.
 *
 * This may be a little confusing, because other objects (e.g., in PKI) are
 * deleted and then destroyed (because they are ref-counted).  But with
 * cryptoki objects, once they are deleted from the token, the object no
 * longer exists.  Caller beware, the object is no longer valid after this!
 */
NSS_EXTERN PRStatus
nssCryptokiObject_DeleteStoredObject (
  nssCryptokiObject *object
);

NSS_EXTERN PRStatus
nssCryptokiObject_SetLabel (
  nssCryptokiObject *object,
  NSSUTF8 *label
);

NSS_EXTERN PRBool
nssCryptokiObject_Equal (
  nssCryptokiObject *object1,
  nssCryptokiObject *object2
);

NSS_EXTERN nssCryptokiObject *
nssCryptokiObject_Clone (
  nssCryptokiObject *object
);

NSS_EXTERN nssCryptokiObject *
nssCryptokiObject_WeakClone (
  nssCryptokiObject *object,
  nssCryptokiObject *copyObject
);

NSS_EXTERN PRStatus
nssCryptokiCert_GetAttributes (
  nssCryptokiObject *object,
  NSSArena *arenaOpt,
  NSSCertType *certTypeOpt,
  NSSItem *idOpt,
  NSSDER *encodingOpt,
  NSSDER *issuerOpt,
  NSSDER *serialOpt,
  NSSDER *subjectOpt,
  NSSASCII7 **emailOpt
);

NSS_EXTERN PRStatus
nssCryptokiPrivateKey_GetAttributes (
  nssCryptokiObject *object,
  NSSArena *arenaOpt,
  NSSKeyPairType *keyTypeOpt,
  NSSItem *idOpt
);

NSS_EXTERN PRStatus
nssCryptokiPublicKey_GetAttributes (
  nssCryptokiObject *object,
  NSSArena *arenaOpt,
  NSSPublicKeyInfo *keyInfoOpt,
  NSSItem *idOpt
);

NSS_EXTERN PRStatus
nssCryptokiTrust_GetAttributes (
  nssCryptokiObject *trustObject,
  nssTrustLevel *serverAuth,
  nssTrustLevel *clientAuth,
  nssTrustLevel *codeSigning,
  nssTrustLevel *emailProtection
);

NSS_EXTERN PRStatus
nssCryptokiCRL_GetAttributes (
  nssCryptokiObject *crlObject,
  NSSArena *arenaOpt,
  NSSItem *encodingOpt,
  NSSUTF8 **urlOpt,
  PRBool *isKRLOpt
);

NSS_EXTERN PRStatus
nssCryptokiSymKey_GetAttributes (
  nssCryptokiObject *keyObject,
  NSSArena *arenaOpt,
  NSSSymKeyType *keyTypeOpt,
  PRUint32 *keyLengthOpt,
  NSSOperations *opsOpt
);

NSS_EXTERN nssCryptokiObject *
nssCryptokiSymKey_Copy (
  nssCryptokiObject *sourceKey,
  nssSession *sourceSession,
  NSSToken *destination,
  nssSession *destinationSession,
  PRBool asTokenObject
);

NSS_EXTERN PRUint32
nssCryptokiRSAKey_GetModulusLength (
  nssCryptokiObject *rsaKey
);

/* I'm including this to handle import of certificates in NSS 3.5.  This
 * function will set the cert-related attributes of a key, in order to
 * associate it with a cert.  Does it stay like this for 4.0?
 */
NSS_EXTERN PRStatus
nssCryptokiPrivateKey_SetCert (
  nssCryptokiObject *keyObject,
  nssSession *session,
  NSSUTF8 *nickname,
  NSSItem *id,
  NSSDER *subject
);

/* nssModuleArray
 *
 * nssModuleArray_Destroy
 */

NSS_EXTERN void
nssModuleArray_Destroy (
  NSSModule **modules
);

/* nssSlotArray
 *
 * nssSlotArray_Destroy
 */

NSS_EXTERN void
nssSlotArray_Destroy (
  NSSSlot **slots
);

/* nssTokenArray
 *
 * nssTokenArray_Destroy
 */

NSS_EXTERN void
nssTokenArray_Destroy (
  NSSToken **tokens
);

/* nssCryptokiObjectArray
 *
 * nssCryptokiObjectArray_Destroy
 */
NSS_EXTERN void
nssCryptokiObjectArray_Destroy (
  nssCryptokiObject **object
);

/* nssSlotList
*
 * An ordered list of slots.  The order can be anything, it is set in the
 * Add methods.  Perhaps it should be CreateInCertOrder, ...?
 *
 * nssSlotList_Create
 * nssSlotList_Destroy
 * nssSlotList_Add
 * nssSlotList_AddModuleSlots
 * nssSlotList_GetSlots
 * nssSlotList_FindSlotByName
 * nssSlotList_FindTokenByName
 * nssSlotList_GetBestSlot
 * nssSlotList_GetBestSlotForAlgNParam
 * nssSlotList_GetBestSlotForAlgorithmsAndParameters
 */

/* nssSlotList_Create
 */
NSS_EXTERN nssSlotList *
nssSlotList_Create (
  NSSArena *arenaOpt
);

/* nssSlotList_Destroy
 */
NSS_EXTERN void
nssSlotList_Destroy (
  nssSlotList *slotList
);

/* nssSlotList_Add
 *
 * Add the given slot in the given order.
 */
NSS_EXTERN PRStatus
nssSlotList_Add (
  nssSlotList *slotList,
  NSSSlot *slot,
  PRUint32 order
);

/* nssSlotList_AddModuleSlots
 *
 * Add all slots in the module, in the given order (the slots will have
 * equal weight).
 */
NSS_EXTERN PRStatus
nssSlotList_AddModuleSlots (
  nssSlotList *slotList,
  NSSModule *module,
  PRUint32 order
);

/* nssSlotList_GetSlots
 */
NSS_EXTERN NSSSlot **
nssSlotList_GetSlots (
  nssSlotList *slotList
);

/* nssSlotList_FindSlotByName
 */
NSS_EXTERN NSSSlot *
nssSlotList_FindSlotByName (
  nssSlotList *slotList,
  NSSUTF8 *slotName
);

/* nssSlotList_FindTokenByName
 */
NSS_EXTERN NSSToken *
nssSlotList_FindTokenByName (
  nssSlotList *slotList,
  NSSUTF8 *tokenName
);

/* nssSlotList_GetBestSlot
 *
 * The best slot is the highest ranking in order, i.e., the first in the
 * list.
 */
NSS_EXTERN NSSSlot *
nssSlotList_GetBestSlot (
  nssSlotList *slotList
);

/* nssSlotList_GetBestTokenForAlgNParam
 *
 * Highest-ranking token than can handle algorithm/parameters.
 */
NSS_IMPLEMENT NSSToken *
nssSlotList_GetBestTokenForAlgNParam (
  nssSlotList *slotList,
  const NSSAlgNParam *ap
);

/* nssSlotList_GetBestSlotForAlgorithmsAndParameters
 *
 * Highest-ranking slot than can handle all algorithms/parameters.
 */
NSS_EXTERN NSSSlot *
nssSlotList_GetBestSlotForAlgorithmsAndParameters (
  nssSlotList *slotList,
  NSSAlgNParam **ap
);

NSS_EXTERN NSSToken *
nssSlotList_GetBestTokenForAlgorithm (
  nssSlotList *slotList,
  NSSOIDTag alg
);

NSS_EXTERN PRStatus
nssToken_TraverseCerts (
  NSSToken *token,
  nssSession *session,
  nssTokenSearchType searchType,
  PRStatus (* callback)(nssCryptokiObject *instance, void *arg),
  void *arg
);

PR_END_EXTERN_C

#endif /* DEV_H */
