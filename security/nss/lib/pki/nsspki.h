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

#ifndef NSSPKI_H
#define NSSPKI_H

#ifdef DEBUG
static const char NSSPKI_CVS_ID[] = "@(#) $RCSfile$ $Revision$ $Date$ $Name$";
#endif /* DEBUG */

/*
 * nsspki.h
 *
 * This file prototypes the methods of the top-level PKI objects.
 */

#ifndef NSSBASET_H
#include "nssbaset.h"
#endif /* NSSBASET_H */

#ifndef NSSDEVT_H
#include "nssdevt.h"
#endif /* NSSDEVT_H */

#ifndef NSSPKI1T_H
#include "nsspki1t.h"
#endif /* NSSPKI1T_H */

#ifndef NSSPKIT_H
#include "nsspkit.h"
#endif /* NSSPKIT_H */

#include "oiddata.h" /* XXX */

PR_BEGIN_EXTERN_C

/*
 * A note about interfaces
 *
 * Although these APIs are specified in C, a language which does
 * not have fancy support for abstract interfaces, this library
 * was designed from an object-oriented perspective.  It may be
 * useful to consider the standard interfaces which went into
 * the writing of these APIs.
 *
 * Basic operations on all objects:
 *  Destroy -- free a pointer to an object
 *  DeleteStoredObject -- delete an object permanently
 *
 * Public Key cryptographic operations:
 *  Encrypt
 *  Verify
 *  VerifyRecover
 *  Wrap
 *  Derive
 *
 * Private Key cryptographic operations:
 *  IsStillPresent
 *  Decrypt
 *  Sign
 *  SignRecover
 *  Unwrap
 *  Derive
 *
 * Symmetric Key cryptographic operations:
 *  IsStillPresent
 *  Encrypt
 *  Decrypt
 *  Sign
 *  SignRecover
 *  Verify
 *  VerifyRecover
 *  Wrap
 *  Unwrap
 *  Derive
 *
 */

/*
 * NSSCert
 *
 * These things can do crypto ops like public keys, except that the trust, 
 * usage, and other constraints are checked.  These objects are "high-level,"
 * so trust, usages, etc. are in the form we throw around (client auth,
 * email signing, etc.).  Remember that theoretically another implementation
 * (think PGP) could be beneath this object.
 */

/* XXX I suspect this will be required and thus public */
NSS_EXTERN NSSCert *
nssCert_AddRef (
  NSSCert *c
);

/*
 * NSSCert_Destroy
 *
 * Free a pointer to a certificate object.
 */

NSS_EXTERN PRStatus
NSSCert_Destroy (
  NSSCert *c
);

NSS_EXTERN NSSUTF8 **
NSSCert_GetNames (
  NSSCert *c,
  NSSUTF8 **rvOpt,
  PRUint32 rvMaxOpt,
  NSSArena *arenaOpt
);

NSS_EXTERN NSSUTF8 **
NSSCert_GetIssuerNames (
  NSSCert *c,
  NSSUTF8 **rvOpt,
  PRUint32 rvMaxOpt,
  NSSArena *arenaOpt
);

/*
 * NSSCert_DeleteStoredObject
 *
 * Permanently remove this certificate from storage.  If this is the
 * only (remaining) certificate corresponding to a private key, 
 * public key, and/or other object; then that object (those objects)
 * are deleted too.
 */

NSS_EXTERN PRStatus
NSSCert_DeleteStoredObject (
  NSSCert *c,
  NSSCallback *uhh
);

/*
 * NSSCert_Validate
 *
 * Verify that this certificate is trusted, for the specified usage(s), 
 * at the specified time, {word word} the specified policies.
 */

NSS_EXTERN PRStatus
NSSCert_Validate (
  NSSCert *c,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt /* NULL for none */
);

/*
 * NSSCert_ValidateCompletely
 *
 * Verify that this certificate is trusted.  The difference between
 * this and the previous call is that NSSCert_Validate merely
 * returns success or failure with an appropriate error stack.
 * However, there may be (and often are) multiple problems with a
 * certificate.  This routine returns an array of errors, specifying
 * every problem.
 */

/* 
 * Return value must be an array of objects, each of which has
 * an NSSError, and any corresponding certificate (in the chain)
 * and/or policy.
 */

NSS_EXTERN void ** /* void *[] */
NSSCert_ValidateCompletely (
  NSSCert *c,
  NSSTime time, /* NULL for "now" */
  NSSUsages *usages,
  NSSPolicies *policiesOpt, /* NULL for none */
  void **rvOpt, /* NULL for allocate */
  PRUint32 rvLimit, /* zero for no limit */
  NSSArena *arenaOpt /* NULL for heap */
);

/*
 * NSSCert_ValidateAndDiscoverUsagesAndPolicies
 *
 * Returns PR_SUCCESS if the certificate is valid for at least something.
 */

NSS_EXTERN PRStatus
NSSCert_ValidateAndDiscoverUsagesAndPolicies (
  NSSCert *c,
  NSSTime **notBeforeOutOpt,
  NSSTime **notAfterOutOpt,
  void *allowedUsages,
  void *disallowedUsages,
  void *allowedPolicies,
  void *disallowedPolicies,
  /* more args.. work on this fgmr */
  NSSArena *arenaOpt
);

NSS_EXTERN NSSUsages *
NSSCert_GetTrustedUsages (
  NSSCert *c,
  NSSUsages *usagesOpt
);

NSS_EXTERN PRStatus
NSSCert_SetTrustedUsages (
  NSSCert *c,
  NSSUsages *usages
);

/*
 * NSSCert_Encode
 *
 */

NSS_EXTERN NSSBER *
NSSCert_Encode (
  NSSCert *c,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSCert_BuildChain
 *
 * This routine returns NSSCert *'s for each certificate
 * in the "chain" starting from the specified one up to and
 * including the root.  The zeroth element in the array is the
 * specified ("leaf") certificate.
 *
 * If statusOpt is supplied, and is returned as PR_FAILURE, possible
 * error values are:
 *
 * NSS_ERROR_CERTIFICATE_ISSUER_NOT_FOUND - the chain is incomplete
 *
 */


NSS_EXTERN NSSCert **
NSSCert_BuildChain (
  NSSCert *c,
  NSSTime time,
  const NSSUsages *usagesOpt,
  NSSPolicies *policiesOpt,
  NSSCert **rvOpt,
  PRUint32 rvLimit, /* zero for no limit */
  NSSArena *arenaOpt,
  PRStatus *statusOpt
);

/*
 * NSSCert_GetTrustDomain
 *
 */

NSS_EXTERN NSSTrustDomain *
NSSCert_GetTrustDomain (
  NSSCert *c
);

/*
 * NSSCert_GetTokens
 *
 * There doesn't have to be any.
 */

NSS_EXTERN NSSToken **
NSSCert_GetTokens (
  NSSCert *c,
  NSSToken **rvOpt,
  PRUint32 rvMaxOpt,
  PRStatus *statusOpt
);

/*
 * NSSCert_GetSlot
 *
 * There doesn't have to be one.
 */

NSS_EXTERN NSSSlot *
NSSCert_GetSlot (
  NSSCert *c,
  PRStatus *statusOpt
);

/*
 * NSSCert_GetModule
 *
 * There doesn't have to be one.
 */

NSS_EXTERN NSSModule *
NSSCert_GetModule (
  NSSCert *c,
  PRStatus *statusOpt
);

/* XXX make sure this is right */
NSS_EXTERN void *
NSSCert_GetDecoding (
  NSSCert *c
);

/* XXX make sure this is right */
NSS_EXTERN NSSCertType
NSSCert_GetType (
  NSSCert *c
);

/*
 * NSSCert_Encrypt
 *
 * Encrypt a single chunk of data with the public key corresponding to
 * this certificate.
 */

NSS_EXTERN NSSItem *
NSSCert_Encrypt (
  NSSCert *c,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSCert_Verify
 *
 */

NSS_EXTERN PRStatus
NSSCert_Verify (
  NSSCert *c,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSItem *signature,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt,
  NSSCallback *uhh
);

/*
 * NSSCert_VerifyRecover
 *
 */

NSS_EXTERN NSSItem *
NSSCert_VerifyRecover (
  NSSCert *c,
  const NSSAlgNParam *apOpt,
  NSSItem *signature,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSCert_WrapSymKey
 *
 * This method tries very hard to to succeed, even in situations 
 * involving sensitive keys and multiple modules.
 * { relyea: want to add verbiage? }
 */

NSS_EXTERN NSSItem *
NSSCert_WrapSymKey (
  NSSCert *c,
  const NSSAlgNParam *ap,
  NSSSymKey *keyToWrap,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSCert_CreateCryptoContext
 *
 * Create a crypto context, in this certificate's trust domain, with this
 * as the distinguished certificate.
 */

NSS_EXTERN NSSCryptoContext *
NSSCert_CreateCryptoContext (
  NSSCert *c,
  const NSSAlgNParam *apOpt,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt,
  NSSCallback *uhh  
);

/*
 * NSSCert_GetPublicKey
 *
 * Returns the public key corresponding to this certificate.
 */

NSS_EXTERN NSSPublicKey *
NSSCert_GetPublicKey (
  NSSCert *c
);

/*
 * NSSCert_FindPrivateKey
 *
 * Finds and returns the private key corresponding to this certificate,
 * if it is available.
 *
 * { Should this hang off of NSSUserCert? }
 */

NSS_EXTERN NSSPrivateKey *
NSSCert_FindPrivateKey (
  NSSCert *c,
  NSSCallback *uhh
);

/*
 * NSSCert_IsPrivateKeyAvailable
 *
 * Returns success if the private key corresponding to this certificate
 * is available to be used.
 *
 * { Should *this* hang off of NSSUserCert?? }
 */

NSS_EXTERN PRBool
NSSCert_IsPrivateKeyAvailable (
  NSSCert *c,
  NSSCallback *uhh,
  PRStatus *statusOpt
);

/*
 * If we make NSSUserCert not a typedef of NSSCert, 
 * then we'll need implementations of the following:
 *
 *  NSSUserCert_Destroy
 *  NSSUserCert_DeleteStoredObject
 *  NSSUserCert_Validate
 *  NSSUserCert_ValidateCompletely
 *  NSSUserCert_ValidateAndDiscoverUsagesAndPolicies
 *  NSSUserCert_Encode
 *  NSSUserCert_BuildChain
 *  NSSUserCert_GetTrustDomain
 *  NSSUserCert_GetTokens
 *  NSSUserCert_GetSlot
 *  NSSUserCert_GetModule
 *  NSSUserCert_GetCryptoContext
 *  NSSUserCert_GetPublicKey
 */

/*
 * NSSUserCert_IsStillPresent
 *
 * Verify that if this certificate lives on a token, that the token
 * is still present and the certificate still exists.  This is a
 * lightweight call which should be used whenever it should be
 * verified that the user hasn't perhaps popped out his or her
 * token and strolled away.
 */

NSS_EXTERN PRBool
NSSUserCert_IsStillPresent (
  NSSUserCert *uc,
  PRStatus *statusOpt
);

/*
 * NSSUserCert_Decrypt
 *
 * Decrypt a single chunk of data with the private key corresponding
 * to this certificate.
 */

NSS_EXTERN NSSItem *
NSSUserCert_Decrypt (
  NSSUserCert *uc,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSUserCert_Sign
 *
 */

NSS_EXTERN NSSItem *
NSSUserCert_Sign (
  NSSUserCert *uc,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSUserCert_SignRecover
 *
 */

NSS_EXTERN NSSItem *
NSSUserCert_SignRecover (
  NSSUserCert *uc,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSUserCert_UnwrapSymKey
 *
 */

NSS_EXTERN NSSSymKey *
NSSUserCert_UnwrapSymKey (
  NSSUserCert *uc,
  const NSSAlgNParam *apOpt,
  NSSItem *wrappedKey,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSUserCert_DeriveSymKey
 *
 */

NSS_EXTERN NSSSymKey *
NSSUserCert_DeriveSymKey (
  NSSUserCert *uc, /* provides private key */
  NSSCert *c, /* provides public key */
  const NSSAlgNParam *apOpt,
  NSSSymKeyType targetKeyType,
  PRUint32 keySizeOpt, /* zero for best allowed */
  NSSOperations operations,
  NSSCallback *uhh
);

/* filter-certs function(s) */

/**
 ** fgmr -- trust objects
 **/

/*
 * NSSPrivateKey
 *
 */

/*
 * NSSPrivateKey_Destroy
 *
 * Free a pointer to a private key object.
 */

NSS_EXTERN PRStatus
NSSPrivateKey_Destroy (
  NSSPrivateKey *vk
);

/*
 * NSSPrivateKey_DeleteStoredObject
 *
 * Permanently remove this object, and any related objects (such as the
 * certificates corresponding to this key).
 */

NSS_EXTERN PRStatus
NSSPrivateKey_DeleteStoredObject (
  NSSPrivateKey *vk,
  NSSCallback *uhh
);

NSS_EXTERN NSSKeyPairType
NSSPrivateKey_GetKeyType (
  NSSPrivateKey *vk
);

/*
 * NSSPrivateKey_GetSignatureLength
 *
 */

NSS_EXTERN PRUint32
NSSPrivateKey_GetSignatureLength (
  NSSPrivateKey *vk
);

/*
 * NSSPrivateKey_GetPrivateModulusLength
 *
 */

NSS_EXTERN PRUint32
NSSPrivateKey_GetPrivateModulusLength (
  NSSPrivateKey *vk
);

/*
 * NSSPrivateKey_IsStillPresent
 *
 */

NSS_EXTERN PRBool
NSSPrivateKey_IsStillPresent (
  NSSPrivateKey *vk,
  PRStatus *statusOpt
);

/*
 * NSSPrivateKey_Encode
 *
 */

NSS_EXTERN NSSItem *
NSSPrivateKey_Encode (
  NSSPrivateKey *vk,
  NSSAlgNParam *ap,
  NSSUTF8 *passwordOpt, /* NULL means prompt */
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSPrivateKey_GetTrustDomain
 *
 * There doesn't have to be one.
 */

NSS_EXTERN NSSTrustDomain *
NSSPrivateKey_GetTrustDomain (
  NSSPrivateKey *vk,
  PRStatus *statusOpt
);

/*
 * NSSPrivateKey_GetTokens
 *
 */

NSS_EXTERN NSSToken **
NSSPrivateKey_GetTokens (
  NSSPrivateKey *vk,
  NSSToken **rvOpt,
  PRUint32 rvMaxOpt,
  PRStatus *statusOpt
);

/*
 * NSSPrivateKey_GetSlot
 *
 */

NSS_EXTERN NSSSlot *
NSSPrivateKey_GetSlot (
  NSSPrivateKey *vk
);

/*
 * NSSPrivateKey_GetModule
 *
 */

NSS_EXTERN NSSModule *
NSSPrivateKey_GetModule (
  NSSPrivateKey *vk
);

/*
 * NSSPrivateKey_Decrypt
 *
 */

NSS_EXTERN NSSItem *
NSSPrivateKey_Decrypt (
  NSSPrivateKey *vk,
  const NSSAlgNParam *apOpt,
  NSSItem *encryptedData,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSPrivateKey_Sign
 *
 */

NSS_EXTERN NSSItem *
NSSPrivateKey_Sign (
  NSSPrivateKey *vk,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSPrivateKey_SignRecover
 *
 */

NSS_EXTERN NSSItem *
NSSPrivateKey_SignRecover (
  NSSPrivateKey *vk,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSPrivateKey_UnwrapSymKey
 *
 */

NSS_EXTERN NSSSymKey *
NSSPrivateKey_UnwrapSymKey (
  NSSPrivateKey *vk,
  const NSSAlgNParam *apOpt,
  NSSItem *wrappedKey,
  NSSSymKeyType targetType,
  NSSUTF8 *labelOpt,
  NSSOperations operations,
  NSSProperties properties,
  NSSToken *destinationOpt,
  NSSVolatileDomain *vdOpt,
  NSSCallback *uhhOpt
);

/*
 * NSSPrivateKey_DeriveSymKey
 *
 */

NSS_EXTERN NSSSymKey *
NSSPrivateKey_DeriveSymKey (
  NSSPrivateKey *vk,
  NSSPublicKey *bk,
  const NSSAlgNParam *apOpt,
  NSSSymKeyType targetKeyType,
  PRUint32 keySizeOpt, /* zero for best allowed */
  NSSOperations operations,
  NSSCallback *uhh
);

/*
 * NSSPrivateKey_FindPublicKey
 *
 */

NSS_EXTERN NSSPublicKey *
NSSPrivateKey_FindPublicKey (
  NSSPrivateKey *vk
  /* { don't need the callback here, right? } */
);

/*
 * NSSPrivateKey_CreateCryptoContext
 *
 * Create a crypto context, in this key's trust domain,
 * with this as the distinguished private key.
 */

NSS_EXTERN NSSCryptoContext *
NSSPrivateKey_CreateCryptoContext (
  NSSPrivateKey *vk,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhh
);

/*
 * NSSPrivateKey_FindCerts
 *
 * Note that there may be more than one certificate for this
 * private key.  { FilterCerts function to further
 * reduce the list. }
 */

NSS_EXTERN NSSCert **
NSSPrivateKey_FindCerts (
  NSSPrivateKey *vk,
  NSSCert *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
);

/*
 * NSSPrivateKey_FindBestCert
 *
 * The parameters for this function will depend on what the users
 * need.  This is just a starting point.
 */

NSS_EXTERN NSSCert *
NSSPrivateKey_FindBestCert (
  NSSPrivateKey *vk,
  NSSTime time,
  NSSUsages *usagesOpt,
  NSSPolicies *policiesOpt
);

/*
 * NSSPublicKey
 *
 * Once you generate, find, or derive one of these, you can use it
 * to perform (simple) cryptographic operations.  Though there may
 * be certificates associated with these public keys, they are not
 * verified.
 */

/*
 * NSSPublicKey_Destroy
 *
 * Free a pointer to a public key object.
 */

NSS_EXTERN PRStatus
NSSPublicKey_Destroy (
  NSSPublicKey *bk
);

/*
 * NSSPublicKey_DeleteStoredObject
 *
 * Permanently remove this object, and any related objects (such as the
 * corresponding private keys and certificates).
 */

NSS_EXTERN PRStatus
NSSPublicKey_DeleteStoredObject (
  NSSPublicKey *bk,
  NSSCallback *uhh
);

/*
 * NSSPublicKey_Encode
 *
 */

NSS_EXTERN NSSItem *
NSSPublicKey_Encode (
  NSSPublicKey *bk,
  const NSSAlgNParam *ap,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSPublicKey_GetTrustDomain
 *
 * There doesn't have to be one.
 */

NSS_EXTERN NSSTrustDomain *
NSSPublicKey_GetTrustDomain (
  NSSPublicKey *bk,
  PRStatus *statusOpt
);

/*
 * NSSPublicKey_GetTokens
 *
 * There doesn't have to be any.
 */

NSS_EXTERN NSSToken **
NSSPublicKey_GetTokens (
  NSSPublicKey *bk,
  NSSToken **rvOpt,
  PRUint32 rvMaxOpt,
  PRStatus *statusOpt
);

/*
 * NSSPublicKey_GetSlot
 *
 * There doesn't have to be one.
 */

NSS_EXTERN NSSSlot *
NSSPublicKey_GetSlot (
  NSSPublicKey *bk,
  PRStatus *statusOpt
);

/*
 * NSSPublicKey_GetModule
 *
 * There doesn't have to be one.
 */

NSS_EXTERN NSSModule *
NSSPublicKey_GetModule (
  NSSPublicKey *bk,
  PRStatus *statusOpt
);

NSS_EXTERN NSSKeyPairType
NSSPublicKey_GetKeyType (
  NSSPublicKey *bk
);

NSS_EXTERN PRUint32
NSSPublicKey_GetKeyStrength (
  NSSPublicKey *bk
);

NSS_EXTERN NSSPublicKeyInfo *
NSSPublicKey_GetKeyInfo (
  NSSPublicKey *bk,
  NSSPublicKeyInfo *rvOpt
);

/*
 * NSSPublicKey_Encrypt
 *
 * Encrypt a single chunk of data with the public key corresponding to
 * this certificate.
 */

NSS_EXTERN NSSItem *
NSSPublicKey_Encrypt (
  NSSPublicKey *bk,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSPublicKey_Verify
 *
 */

NSS_EXTERN PRStatus
NSSPublicKey_Verify (
  NSSPublicKey *bk,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSItem *signature,
  NSSCallback *uhh
);

/*
 * NSSPublicKey_VerifyRecover
 *
 */

NSS_EXTERN NSSItem *
NSSPublicKey_VerifyRecover (
  NSSPublicKey *bk,
  const NSSAlgNParam *apOpt,
  NSSItem *signature,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSPublicKey_WrapSymKey
 *
 */

NSS_EXTERN NSSItem *
NSSPublicKey_WrapSymKey (
  NSSPublicKey *bk,
  const NSSAlgNParam *ap,
  NSSSymKey *keyToWrap,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSPublicKey_CreateCryptoContext
 *
 * Create a crypto context, in this key's trust domain, with this
 * as the distinguished public key.
 */

NSS_EXTERN NSSCryptoContext *
NSSPublicKey_CreateCryptoContext (
  NSSPublicKey *bk,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhh
);

/*
 * NSSPublicKey_FindCerts
 *
 * Note that there may be more than one certificate for this
 * public key.  The current implementation may not find every
 * last certificate available for this public key: that would
 * involve trolling e.g. huge ldap databases, which will be
 * grossly inefficient and not generally useful.
 * { FilterCerts function to further reduce the list }
 */

NSS_EXTERN NSSCert **
NSSPublicKey_FindCerts (
  NSSPublicKey *bk,
  NSSCert *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
);

/*
 * NSSPrivateKey_FindBestCert
 *
 * The parameters for this function will depend on what the users
 * need.  This is just a starting point.
 */

NSS_EXTERN NSSCert *
NSSPublicKey_FindBestCert (
  NSSPublicKey *bk,
  NSSTime time,
  NSSUsages *usagesOpt,
  NSSPolicies *policiesOpt
);

/*
 * NSSPublicKey_FindPrivateKey
 *
 */

NSS_EXTERN NSSPrivateKey *
NSSPublicKey_FindPrivateKey (
  NSSPublicKey *bk,
  NSSCallback *uhh
);

/*
 * NSSSymKey
 *
 */

/*
 * NSSSymKey_Destroy
 *
 * Free a pointer to a symmetric key object.
 */

NSS_EXTERN PRStatus
NSSSymKey_Destroy (
  NSSSymKey *mk
);

/*
 * NSSSymKey_DeleteStoredObject
 *
 * Permanently remove this object.
 */

NSS_EXTERN PRStatus
NSSSymKey_DeleteStoredObject (
  NSSSymKey *mk,
  NSSCallback *uhh
);

/*
 * NSSSymKey_GetKeyLength
 *
 */

NSS_EXTERN PRUint32
NSSSymKey_GetKeyLength (
  NSSSymKey *mk
);

/*
 * NSSSymKey_GetKeyStrength
 *
 */

NSS_EXTERN PRUint32
NSSSymKey_GetKeyStrength (
  NSSSymKey *mk
);

/*
 * NSSSymKey_IsStillPresent
 *
 */

NSS_EXTERN PRStatus
NSSSymKey_IsStillPresent (
  NSSSymKey *mk
);

/*
 * NSSSymKey_GetTrustDomain
 *
 * There doesn't have to be one.
 */

NSS_EXTERN NSSTrustDomain *
NSSSymKey_GetTrustDomain (
  NSSSymKey *mk,
  PRStatus *statusOpt
);

/*
 * NSSSymKey_GetTokens
 *
 * There doesn't have to be any.
 */

NSS_EXTERN NSSToken **
NSSSymKey_GetTokens (
  NSSSymKey *mk,
  NSSToken **rvOpt,
  PRUint32 rvMaxOpt,
  PRStatus *statusOpt
);

/*
 * NSSSymKey_GetSlot
 *
 * There doesn't have to be one.
 */

NSS_EXTERN NSSSlot *
NSSSymKey_GetSlot (
  NSSSymKey *mk,
  PRStatus *statusOpt
);

/*
 * NSSSymKey_GetModule
 *
 * There doesn't have to be one.
 */

NSS_EXTERN NSSModule *
NSSSymKey_GetModule (
  NSSSymKey *mk,
  PRStatus *statusOpt
);

/*
 * NSSSymKey_Encrypt
 *
 */

NSS_EXTERN NSSItem *
NSSSymKey_Encrypt (
  NSSSymKey *mk,
  const NSSAlgNParam *ap,
  NSSItem *data,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSSymKey_Decrypt
 *
 */

NSS_EXTERN NSSItem *
NSSSymKey_Decrypt (
  NSSSymKey *mk,
  const NSSAlgNParam *ap,
  NSSItem *encryptedData,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSSymKey_Sign
 *
 */

NSS_EXTERN NSSItem *
NSSSymKey_Sign (
  NSSSymKey *mk,
  const NSSAlgNParam *ap,
  NSSItem *data,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSSymKey_Verify
 *
 */

NSS_EXTERN PRStatus
NSSSymKey_Verify (
  NSSSymKey *mk,
  const NSSAlgNParam *ap,
  NSSItem *data,
  NSSItem *signature,
  NSSCallback *uhh
);

/*
 * NSSSymKey_WrapSymKey
 *
 */

NSS_EXTERN NSSItem *
NSSSymKey_WrapSymKey (
  NSSSymKey *wrappingKey,
  const NSSAlgNParam *ap,
  NSSSymKey *keyToWrap,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSSymKey_WrapPrivateKey
 *
 */

NSS_EXTERN NSSItem *
NSSSymKey_WrapPrivateKey (
  NSSSymKey *wrappingKey,
  const NSSAlgNParam *ap,
  NSSPrivateKey *keyToWrap,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSSymKey_UnwrapSymKey
 *
 */

NSS_EXTERN NSSSymKey *
NSSSymKey_UnwrapSymKey (
  NSSSymKey *wrappingKey,
  const NSSAlgNParam *ap,
  NSSItem *wrappedKey,
  NSSSymKeyType targetKeyType,
  PRUint32 keySizeOpt,
  NSSOperations operations,
  NSSCallback *uhh
);

/*
 * NSSSymKey_UnwrapPrivateKey
 *
 */

NSS_EXTERN NSSPrivateKey *
NSSSymKey_UnwrapPrivateKey (
  NSSSymKey *wrappingKey,
  const NSSAlgNParam *ap,
  NSSItem *wrappedKey,
  NSSUTF8 *labelOpt,
  NSSItem *keyIDOpt,
  PRBool persistant,
  PRBool sensitive,
  NSSToken *destinationOpt,
  NSSCallback *uhh
);

/*
 * NSSSymKey_DeriveSymKey
 *
 */

NSS_EXTERN NSSSymKey *
NSSSymKey_DeriveSymKey (
  NSSSymKey *originalKey,
  const NSSAlgNParam *ap,
  NSSSymKeyType target,
  PRUint32 keySizeOpt,
  NSSOperations operations,
  NSSProperties properties,
  NSSToken *destinationOpt,
  NSSVolatileDomain *vdOpt,
  NSSCallback *uhhOpt
);

NSS_EXTERN PRStatus
nssSymKey_DeriveSSLSessionKeys (
  NSSSymKey *masterSecret,
  const NSSAlgNParam *ap,
  PRUint32 keySize,
  NSSSymKeyType keyType,
  NSSSymKey **rvSessionKeys
);

/*
 * NSSSymKey_CreateCryptoContext
 *
 * Create a crypto context, in this key's trust domain,
 * with this as the distinguished symmetric key.
 */

NSS_EXTERN NSSCryptoContext *
NSSSymKey_CreateCryptoContext (
  NSSSymKey *mk,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhh
);

/*
 * NSSTrustDomain
 *
 */

/*
 * NSSTrustDomain_Create
 *
 * This creates a trust domain, optionally with an initial cryptoki
 * module.  If the module name is not null, the module is loaded if
 * needed (using the uriOpt argument), and initialized with the
 * opaqueOpt argument.  If mumble mumble priority settings, then
 * module-specification objects in the module can cause the loading
 * and initialization of further modules.
 *
 * The uriOpt is defined to take a URI.  At present, we only
 * support file: URLs pointing to platform-native shared libraries.
 * However, by specifying this as a URI, this keeps open the 
 * possibility of supporting other, possibly remote, resources.
 *
 * The "reserved" arguments is held for when we figure out the
 * module priority stuff.
 */

NSS_EXTERN NSSTrustDomain *
NSSTrustDomain_Create (
  NSSUTF8 *moduleOpt,
  NSSUTF8 *uriOpt,
  NSSUTF8 *opaqueOpt,
  void *reserved
);

/*
 * NSSTrustDomain_Destroy
 *
 */

NSS_EXTERN PRStatus
NSSTrustDomain_Destroy (
  NSSTrustDomain *td
);

/*
 * NSSTrustDomain_SetDefaultCallback
 *
 */

NSS_EXTERN PRStatus
NSSTrustDomain_SetDefaultCallback (
  NSSTrustDomain *td,
  NSSCallback *newCallback,
  NSSCallback **oldCallbackOpt
);

/*
 * NSSTrustDomain_GetDefaultCallback
 *
 */

NSS_EXTERN NSSCallback *
NSSTrustDomain_GetDefaultCallback (
  NSSTrustDomain *td,
  PRStatus *statusOpt
);

/*
 * Default policies?
 * Default usage?
 * Default time, for completeness?
 */

/*
 * NSSTrustDomain_LoadModule
 *
 */

/*
NSS_EXTERN PRStatus
NSSTrustDomain_LoadModule (
  NSSTrustDomain *td,
  NSSUTF8 *moduleOpt,
  NSSUTF8 *uriOpt,
  NSSUTF8 *opaqueOpt,
  void *reserved
);
*/

NSS_EXTERN PRStatus
NSSTrustDomain_AddModule (
  NSSTrustDomain *td,
  NSSModule *module
);

NSS_EXTERN PRStatus
NSSTrustDomain_AddSlot (
  NSSTrustDomain *td,
  NSSSlot *slot
);

/*
 * XXX NSSTrustDomain_UnloadModule
 * Managing modules, slots, tokens; priorities;
 * Traversing all of the above
 * this needs more work
 */

/*
 * NSSTrustDomain_DisableToken
 *
 */

NSS_EXTERN PRStatus
NSSTrustDomain_DisableToken (
  NSSTrustDomain *td,
  NSSToken *token,
  NSSError why
);

/*
 * NSSTrustDomain_EnableToken
 *
 */

NSS_EXTERN PRStatus
NSSTrustDomain_EnableToken (
  NSSTrustDomain *td,
  NSSToken *token
);

/*
 * NSSTrustDomain_IsTokenEnabled
 *
 * If disabled, "why" is always on the error stack.
 * The optional argument is just for convenience.
 */

NSS_EXTERN PRStatus
NSSTrustDomain_IsTokenEnabled (
  NSSTrustDomain *td,
  NSSToken *token,
  NSSError *whyOpt
);

/*
 * NSSTrustDomain_FindSlotByName
 *
 */

NSS_EXTERN NSSSlot *
NSSTrustDomain_FindSlotByName (
  NSSTrustDomain *td,
  NSSUTF8 *slotName
);

/*
 * NSSTrustDomain_FindTokenByName
 *
 */

NSS_EXTERN NSSToken *
NSSTrustDomain_FindTokenByName (
  NSSTrustDomain *td,
  NSSUTF8 *tokenName
);

/*
 * NSSTrustDomain_FindTokenBySlotName
 *
 */

NSS_EXTERN NSSToken *
NSSTrustDomain_FindTokenBySlotName (
  NSSTrustDomain *td,
  NSSUTF8 *slotName
);

/*
 * NSSTrustDomain_FindBestTokenForAlgorithm
 *
 */

NSS_EXTERN NSSToken *
NSSTrustDomain_FindTokenForAlgorithm (
  NSSTrustDomain *td,
  NSSOIDTag algorithm
);

/*
 * NSSTrustDomain_FindBestTokenForAlgorithms
 *
 */

NSS_EXTERN NSSToken *
NSSTrustDomain_FindBestTokenForAlgorithms (
  NSSTrustDomain *td,
  NSSOIDTag *algorithms,
  PRUint32 nAlgorithmsOpt /* limits the array if nonzero */
);

NSS_EXTERN NSSToken *
NSSTrustDomain_FindTokenForAlgNParam (
  NSSTrustDomain *td,
  const NSSAlgNParam *ap
);

/*
 * NSSTrustDomain_Login
 *
 */

NSS_EXTERN PRStatus
NSSTrustDomain_Login (
  NSSTrustDomain *td,
  NSSCallback *uhhOpt
);

/*
 * NSSTrustDomain_Logout
 *
 */

NSS_EXTERN PRStatus
NSSTrustDomain_Logout (
  NSSTrustDomain *td
);

/* Importing things */

/*
 * NSSTrustDomain_ImportCert
 *
 * The implementation will pull some data out of the certificate
 * (e.g. e-mail address) for use in pkcs#11 object attributes.
 */

NSS_EXTERN NSSCert *
NSSTrustDomain_ImportCert (
  NSSTrustDomain *td,
  NSSCert *c,
  NSSToken *destinationOpt
);

/*
 * NSSTrustDomain_ImportPKIXCert
 *
 */

NSS_EXTERN NSSCert *
NSSTrustDomain_ImportPKIXCert (
  NSSTrustDomain *td,
  /* declared as a struct until these "data types" are defined */
  struct NSSPKIXCertStr *pc
);

/*
 * NSSTrustDomain_ImportEncodedCert
 *
 * Imports any type of certificate we support.
 */

NSS_EXTERN NSSCert *
NSSTrustDomain_ImportEncodedCert (
  NSSTrustDomain *td,
  NSSBER *ber,
  NSSUTF8 *nicknameOpt,
  NSSToken *destinationOpt
);

/*
 * NSSTrustDomain_ImportEncodedCertChain
 *
 */

NSS_EXTERN NSSCertChain *
NSSTrustDomain_ImportEncodedCertChain (
  NSSTrustDomain *td,
  NSSBER *ber,
  NSSToken *destinationOpt
);

/*
 * NSSTrustDomain_ImportEncodedPrivateKey
 *
 */

NSS_EXTERN NSSPrivateKey *
NSSTrustDomain_ImportEncodedPrivateKey (
  NSSTrustDomain *td,
  NSSBER *ber,
  NSSKeyPairType keyPairType,
  NSSOperations operations,
  NSSProperties properties,
  NSSUTF8 *passwordOpt, /* NULL will cause a callback */
  NSSCallback *uhhOpt,
  NSSToken *destination
);

/*
 * NSSTrustDomain_ImportEncodedPublicKey
 *
 */

NSS_EXTERN NSSPublicKey *
NSSTrustDomain_ImportEncodedPublicKey (
  NSSTrustDomain *td,
  NSSBER *ber,
  NSSToken *destinationOpt
);

NSS_EXTERN NSSPublicKey *
NSSTrustDomain_ImportPublicKeyByInfo (
  NSSTrustDomain *td,
  NSSPublicKeyInfo *keyInfo,
  NSSUTF8 *nicknameOpt,
  NSSOperations operations,
  NSSProperties properties,
  NSSToken *destinationOpt
);

NSS_EXTERN NSSCRL *
NSSTrustDomain_ImportEncodedCRL (
  NSSTrustDomain *td,
  NSSBER *ber,
  NSSToken *destinationOpt
);

/* Other importations: S/MIME capabilities */

/*
 * NSSTrustDomain_FindBestCertByNickname
 *
 */

NSS_EXTERN NSSCert *
NSSTrustDomain_FindBestCertByNickname (
  NSSTrustDomain *td,
  NSSUTF8 *name,
  NSSTime time,
  NSSUsages *usagesOpt,
  NSSPolicies *policiesOpt /* NULL for none */
);

/*
 * NSSTrustDomain_FindCertsByNickname
 *
 */

NSS_EXTERN NSSCert **
NSSTrustDomain_FindCertsByNickname (
  NSSTrustDomain *td,
  NSSUTF8 *name,
  NSSCert *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
);

/*
 * NSSTrustDomain_FindCertByIssuerAndSerialNumber
 *
 */

NSS_EXTERN NSSCert *
NSSTrustDomain_FindCertByIssuerAndSerialNumber (
  NSSTrustDomain *td,
  NSSDER *issuer,
  NSSDER *serialNumber
);

/*
 * NSSTrustDomain_FindCertsByIssuerAndSerialNumber
 *
 * Theoretically, this should never happen.  However, some companies
 * we know have issued duplicate certificates with the same issuer
 * and serial number.  Do we just ignore them?  I'm thinking yes.
 */

/*
 * NSSTrustDomain_FindBestCertBySubject
 *
 * This does not search through alternate names hidden in extensions.
 */

NSS_EXTERN NSSCert *
NSSTrustDomain_FindBestCertBySubject (
  NSSTrustDomain *td,
  NSSDER *subject,
  NSSTime time,
  NSSUsages *usagesOpt,
  NSSPolicies *policiesOpt
);

/*
 * NSSTrustDomain_FindCertsBySubject
 *
 * This does not search through alternate names hidden in extensions.
 */

NSS_EXTERN NSSCert **
NSSTrustDomain_FindCertsBySubject (
  NSSTrustDomain *td,
  NSSDER *subject,
  NSSCert *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
);

/*
 * NSSTrustDomain_FindBestCertByNameComponents
 *
 * This call does try several tricks, including a pseudo pkcs#11 
 * attribute for the ldap module to try as a query.  Eventually
 * this call falls back to a traversal if that's what's required.
 * It will search through alternate names hidden in extensions.
 */

NSS_EXTERN NSSCert *
NSSTrustDomain_FindBestCertByNameComponents (
  NSSTrustDomain *td,
  NSSUTF8 *nameComponents,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt
);

/*
 * NSSTrustDomain_FindCertsByNameComponents
 *
 * This call, too, tries several tricks.  It will stop on the first
 * attempt that generates results, so it won't e.g. traverse the
 * entire ldap database.
 */

NSS_EXTERN NSSCert **
NSSTrustDomain_FindCertsByNameComponents (
  NSSTrustDomain *td,
  NSSUTF8 *nameComponents,
  NSSCert *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
);

/*
 * NSSTrustDomain_FindCertByEncodedCert
 *
 */

NSS_EXTERN NSSCert *
NSSTrustDomain_FindCertByEncodedCert (
  NSSTrustDomain *td,
  NSSBER *encodedCert
);

/*
 * NSSTrustDomain_FindBestCertByEmail
 *
 */

NSS_EXTERN NSSCert *
NSSTrustDomain_FindBestCertByEmail (
  NSSTrustDomain *td,
  NSSASCII7 *email,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt
);

/*
 * NSSTrustDomain_FindCertsByEmail
 *
 */

NSS_EXTERN NSSCert **
NSSTrustDomain_FindCertsByEmail (
  NSSTrustDomain *td,
  NSSASCII7 *email,
  NSSCert *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
);

/*
 * NSSTrustDomain_FindCertByOCSPHash
 *
 * There can be only one.
 */

NSS_EXTERN NSSCert *
NSSTrustDomain_FindCertByOCSPHash (
  NSSTrustDomain *td,
  NSSItem *hash
);

/*
 * NSSTrustDomain_TraverseCerts
 *
 * This function descends from one in older versions of NSS which
 * traverses the certs in the permanent database.  That function
 * was used to implement selection routines, but was directly
 * available too.  Trust domains are going to contain a lot more
 * certs now (e.g., an ldap server), so we'd really like to
 * discourage traversal.  Thus for now, this is commented out.
 * If it's needed, let's look at the situation more closely to
 * find out what the actual requirements are.
 */
 
/* For now, adding this function.  This may only be for debugging
 * purposes.
 * Perhaps some equivalent function, on a specified token, will be
 * needed in a "friend" header file?
 */
NSS_EXTERN PRStatus *
NSSTrustDomain_TraverseCerts (
  NSSTrustDomain *td,
  PRStatus (*callback)(NSSCert *c, void *arg),
  void *arg
);

/*
 * NSSTrustDomain_FindBestUserCert
 *
 */

NSS_EXTERN NSSCert *
NSSTrustDomain_FindBestUserCert (
  NSSTrustDomain *td,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt
);

/*
 * NSSTrustDomain_FindUserCerts
 *
 */

NSS_EXTERN NSSCert **
NSSTrustDomain_FindUserCerts (
  NSSTrustDomain *td,
  NSSCert **rvOpt,
  PRUint32 rvLimit, /* zero for no limit */
  NSSArena *arenaOpt
);

/*
 * NSSTrustDomain_FindBestUserCertForSSLClientAuth
 *
 */

NSS_EXTERN NSSCert *
NSSTrustDomain_FindBestUserCertForSSLClientAuth (
  NSSTrustDomain *td,
  NSSUTF8 *sslHostOpt,
  NSSDER **rootCAsOpt, /* null pointer for none */
  PRUint32 rootCAsMaxOpt, /* zero means list is null-terminated */
  const NSSAlgNParam *apOpt,
  NSSPolicies *policiesOpt
);

/*
 * NSSTrustDomain_FindUserCertsForSSLClientAuth
 *
 */

NSS_EXTERN NSSCert **
NSSTrustDomain_FindUserCertsForSSLClientAuth (
  NSSTrustDomain *td,
  NSSUTF8 *sslHostOpt,
  NSSDER *rootCAsOpt[], /* null pointer for none */
  PRUint32 rootCAsMaxOpt, /* zero means list is null-terminated */
  const NSSAlgNParam *apOpt,
  NSSPolicies *policiesOpt,
  NSSCert **rvOpt,
  PRUint32 rvLimit, /* zero for no limit */
  NSSArena *arenaOpt
);

/*
 * NSSTrustDomain_FindBestUserCertForEmailSigning
 *
 */

NSS_EXTERN NSSCert *
NSSTrustDomain_FindBestUserCertForEmailSigning (
  NSSTrustDomain *td,
  NSSASCII7 *signerOpt,
  NSSASCII7 *recipientOpt,
  /* anything more here? */
  const NSSAlgNParam *apOpt,
  NSSPolicies *policiesOpt
);

/*
 * NSSTrustDomain_FindUserCertsForEmailSigning
 *
 */

NSS_EXTERN NSSCert **
NSSTrustDomain_FindUserCertsForEmailSigning (
  NSSTrustDomain *td,
  NSSASCII7 *signerOpt,
  NSSASCII7 *recipientOpt,
  /* anything more here? */
  const NSSAlgNParam *apOpt,
  NSSPolicies *policiesOpt,
  NSSCert **rvOpt,
  PRUint32 rvLimit, /* zero for no limit */
  NSSArena *arenaOpt
);

/*
 * Here is where we'd add more Find[Best]UserCert[s]For<usage>
 * routines.
 */

/* Private Keys */

/*
 * NSSTrustDomain_GenerateKeyPair
 *
 * Creates persistant objects.  If you want session objects, use
 * NSSCryptoContext_GenerateKeyPair.  The destination token is where
 * the keys are stored.  If that token can do the required math, then
 * that's where the keys are generated too.  Otherwise, the keys are
 * generated elsewhere and moved to that token.
 */

NSS_EXTERN PRStatus
NSSTrustDomain_GenerateKeyPair (
  NSSTrustDomain *td,
  const NSSAlgNParam *ap,
  NSSPublicKey **pbkOpt,
  NSSPrivateKey **pvkOpt,
  NSSUTF8 *nicknameOpt,
  NSSProperties properties,
  NSSOperations operations,
  NSSToken *destination,
  NSSCallback *uhhOpt
);

/*
 * NSSTrustDomain_TraversePrivateKeys
 *
 * XXX idm -- for testing
 */

NSS_EXTERN PRStatus *
NSSTrustDomain_TraversePrivateKeys (
  NSSTrustDomain *td,
  PRStatus (*callback)(NSSPrivateKey *vk, void *arg),
  void *arg
);

/* Symmetric Keys */

/*
 * NSSTrustDomain_GenerateSymKey
 *
 */

NSS_EXTERN NSSSymKey *
NSSTrustDomain_GenerateSymKey (
  NSSTrustDomain *td,
  const NSSAlgNParam *ap,
  PRUint32 keysize,
  NSSToken *destination,
  NSSCallback *uhhOpt
);

/*
 * NSSTrustDomain_GenerateSymKeyFromPassword
 *
 */

NSS_EXTERN NSSSymKey *
NSSTrustDomain_GenerateSymKeyFromPassword (
  NSSTrustDomain *td,
  const NSSAlgNParam *ap,
  NSSUTF8 *passwordOpt, /* if null, prompt */
  NSSToken *destinationOpt,
  NSSCallback *uhhOpt
);

/*
 * NSSTrustDomain_FindSymKeyByAlgorithm
 *
 * Is this still needed?
 * 
 * NSS_EXTERN NSSSymKey *
 * NSSTrustDomain_FindSymKeyByAlgorithm
 * (
 *   NSSTrustDomain *td,
 *   NSSOID *algorithm,
 *   NSSCallback *uhhOpt
 * );
 */

/*
 * NSSTrustDomain_FindSymKeyByAlgorithmAndKeyID
 *
 */

NSS_EXTERN NSSSymKey *
NSSTrustDomain_FindSymKeyByAlgorithmAndKeyID (
  NSSTrustDomain *td,
  NSSOIDTag algorithm,
  NSSItem *keyID,
  NSSCallback *uhhOpt
);

/*
 * NSSTrustDomain_TraverseSymKeys
 *
 * 
 * NSS_EXTERN PRStatus *
 * NSSTrustDomain_TraverseSymKeys
 * (
 *   NSSTrustDomain *td,
 *   PRStatus (*callback)(NSSSymKey *mk, void *arg),
 *   void *arg
 * );
 */

/*
 * NSSTrustDomain_CreateVolatileDomain
 *
 * If a callback object is specified, it becomes the default callback 
 * for the volatile domain; otherwise, this trust domain's default 
 * (if any) is inherited.
 */

NSS_EXTERN NSSVolatileDomain *
NSSTrustDomain_CreateVolatileDomain (
  NSSTrustDomain *td,
  NSSCallback *uhhOpt
);

/*
 * NSSTrustDomain_CreateCryptoContext
 *
 * If a callback object is specified, it becomes the default callback 
 * for the crypto context; otherwise, this trust domain's default 
 * (if any) is inherited.
 * If algorithm and parameters are specified, they will be the default
 * for the context.
 */

NSS_EXTERN NSSCryptoContext *
NSSTrustDomain_CreateCryptoContext (
  NSSTrustDomain *td,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhhOpt
);

/*
 * NSSTrustDomain_CreateCryptoContextForAlgorithm
 *
 */

NSS_EXTERN NSSCryptoContext *
NSSTrustDomain_CreateCryptoContextForAlgorithm (
  NSSTrustDomain *td,
  NSSOIDTag algorithm
);

/* find/traverse other objects, e.g. s/mime profiles */

/*
 * NSSVolatileDomain
 *
 *
 */

NSS_EXTERN PRStatus
NSSVolatileDomain_Destroy (
  NSSVolatileDomain *vd
);

/*
 * NSSVolatileDomain_FindBestCertByNickname
 *
 */

NSS_EXTERN NSSCert *
NSSVolatileDomain_FindBestCertByNickname (
  NSSVolatileDomain *vd,
  NSSUTF8 *name,
  NSSTime time, /* NULL for "now" */
  NSSUsages *usages,
  NSSPolicies *policiesOpt /* NULL for none */
);

/*
 * NSSVolatileDomain_FindCertsByNickname
 *
 */

NSS_EXTERN NSSCert **
NSSVolatileDomain_FindCertsByNickname (
  NSSVolatileDomain *vd,
  NSSUTF8 *name,
  NSSCert *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
);

/*
 * NSSVolatileDomain_FindCertByIssuerAndSerialNumber
 *
 */

NSS_EXTERN NSSCert *
NSSVolatileDomain_FindCertByIssuerAndSerialNumber (
  NSSVolatileDomain *vd,
  NSSDER *issuer,
  NSSDER *serialNumber
);

/*
 * NSSVolatileDomain_FindBestCertBySubject
 *
 * This does not search through alternate names hidden in extensions.
 */

NSS_EXTERN NSSCert *
NSSVolatileDomain_FindBestCertBySubject (
  NSSVolatileDomain *vd,
  NSSDER *subject,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt
);

/*
 * NSSVolatileDomain_FindCertsBySubject
 *
 * This does not search through alternate names hidden in extensions.
 */

NSS_EXTERN NSSCert **
NSSVolatileDomain_FindCertsBySubject (
  NSSVolatileDomain *vd,
  NSSDER *subject,
  NSSCert *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
);

/*
 * NSSVolatileDomain_FindCertByEncodedCert
 *
 */

NSS_EXTERN NSSCert *
NSSVolatileDomain_FindCertByEncodedCert (
  NSSVolatileDomain *vd,
  NSSBER *encodedCert
);

/*
 * NSSVolatileDomain_FindBestCertByEmail
 *
 */

NSS_EXTERN NSSCert *
NSSVolatileDomain_FindBestCertByEmail (
  NSSVolatileDomain *vd,
  NSSASCII7 *email,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt
);

/*
 * NSSVolatileDomain_FindCertsByEmail
 *
 */

NSS_EXTERN NSSCert **
NSSVolatileDomain_FindCertsByEmail (
  NSSVolatileDomain *vd,
  NSSASCII7 *email,
  NSSCert *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
);

/*
 * NSSVolatileDomain_TraverseCerts
 *
 * 
 * NSS_EXTERN PRStatus *
 * NSSVolatileDomain_TraverseCerts
 * (
 *   NSSVolatileDomain *vd,
 *   PRStatus (*callback)(NSSCert *c, void *arg),
 *   void *arg
 * );
 */

/*
 * NSSVolatileDomain_FindBestUserCert
 *
 */

NSS_EXTERN NSSCert *
NSSVolatileDomain_FindBestUserCert (
  NSSVolatileDomain *vd,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt
);

/*
 * NSSVolatileDomain_FindUserCerts
 *
 */

NSS_EXTERN NSSCert **
NSSVolatileDomain_FindUserCerts (
  NSSVolatileDomain *vd,
  NSSTime time,
  NSSUsages *usagesOpt,
  NSSPolicies *policiesOpt,
  NSSCert **rvOpt,
  PRUint32 rvLimit, /* zero for no limit */
  NSSArena *arenaOpt
);

/*
 * NSSVolatileDomain_FindBestUserCertForSSLClientAuth
 *
 */

NSS_EXTERN NSSCert *
NSSVolatileDomain_FindBestUserCertForSSLClientAuth (
  NSSVolatileDomain *vd,
  NSSUTF8 *sslHostOpt,
  NSSDER *rootCAsOpt[], /* null pointer for none */
  PRUint32 rootCAsMaxOpt, /* zero means list is null-terminated */
  const NSSAlgNParam *apOpt,
  NSSPolicies *policiesOpt
);

/*
 * NSSVolatileDomain_FindUserCertsForSSLClientAuth
 *
 */

NSS_EXTERN NSSCert **
NSSVolatileDomain_FindUserCertsForSSLClientAuth (
  NSSVolatileDomain *vd,
  NSSUTF8 *sslHostOpt,
  NSSDER *rootCAsOpt[], /* null pointer for none */
  PRUint32 rootCAsMaxOpt, /* zero means list is null-terminated */
  const NSSAlgNParam *apOpt,
  NSSPolicies *policiesOpt,
  NSSCert **rvOpt,
  PRUint32 rvLimit, /* zero for no limit */
  NSSArena *arenaOpt
);

/*
 * NSSVolatileDomain_FindBestUserCertForEmailSigning
 *
 */

NSS_EXTERN NSSCert *
NSSVolatileDomain_FindBestUserCertForEmailSigning (
  NSSVolatileDomain *vd,
  NSSASCII7 *signerOpt,
  NSSASCII7 *recipientOpt,
  /* anything more here? */
  const NSSAlgNParam *apOpt,
  NSSPolicies *policiesOpt
);

/*
 * NSSVolatileDomain_FindUserCertsForEmailSigning
 *
 */

NSS_EXTERN NSSCert *
NSSVolatileDomain_FindUserCertsForEmailSigning (
  NSSVolatileDomain *vd,
  NSSASCII7 *signerOpt, /* fgmr or a more general name? */
  NSSASCII7 *recipientOpt,
  /* anything more here? */
  const NSSAlgNParam *apOpt,
  NSSPolicies *policiesOpt,
  NSSCert **rvOpt,
  PRUint32 rvLimit, /* zero for no limit */
  NSSArena *arenaOpt
);

/* Importing things */

/*
 * NSSVolatileDomain_ImportCert
 *
 */

NSS_EXTERN PRStatus
NSSVolatileDomain_ImportCert (
  NSSVolatileDomain *vd,
  NSSCert *c
);

/*
 * NSSVolatileDomain_ImportEncodedCert
 *
 */

NSS_EXTERN NSSCert *
NSSVolatileDomain_ImportEncodedCert (
  NSSVolatileDomain *vd,
  NSSBER *ber,
  NSSUTF8 *nicknameOpt,
  NSSToken *destinationOpt
);

/*
 * NSSVolatileDomain_ImportEncodedCertChain
 *
 */

NSS_EXTERN NSSCertChain *
NSSVolatileDomain_ImportEncodedCertChain (
  NSSVolatileDomain *vd,
  NSSBER *ber,
  NSSToken *destinationOpt
);

/*
 * NSSVolatileDomain_ImportEncodedPrivateKey
 *
 */

NSS_EXTERN NSSPrivateKey *
NSSVolatileDomain_ImportEncodedPrivateKey (
  NSSVolatileDomain *vd,
  NSSBER *ber,
  NSSKeyPairType keyPairType,
  NSSOperations operations,
  NSSProperties properties,
  NSSUTF8 *passwordOpt, /* NULL will cause a callback */
  NSSCallback *uhhOpt,
  NSSToken *destination
);

NSS_EXTERN NSSPublicKey *
NSSVolatileDomain_ImportPublicKey (
  NSSVolatileDomain *vd,
  NSSPublicKeyInfo *keyInfo,
  NSSUTF8 *nicknameOpt,
  NSSOperations operations,
  NSSProperties properties,
  NSSToken *destinationOpt
);

/* Other importations: S/MIME capabilities
 */

/* Private Keys */

/*
 * NSSVolatileDomain_GenerateKeyPair
 *
 * Creates session objects.  If you want persistant objects, use
 * NSSTrustDomain_GenerateKeyPair.  The destination token is where
 * the keys are stored.  If that token can do the required math, then
 * that's where the keys are generated too.  Otherwise, the keys are
 * generated elsewhere and moved to that token.
 */

NSS_EXTERN PRStatus
NSSVolatileDomain_GenerateKeyPair (
  NSSVolatileDomain *vd,
  const NSSAlgNParam *ap,
  NSSPrivateKey **pvkOpt,
  NSSPublicKey **pbkOpt,
  PRBool privateKeyIsSensitive,
  NSSToken *destination,
  NSSCallback *uhhOpt
);

/*
 * NSSVolatileDomain_TraversePrivateKeys
 *
 * 
 * NSS_EXTERN PRStatus *
 * NSSVolatileDomain_TraversePrivateKeys
 * (
 *   NSSVolatileDomain *vd,
 *   PRStatus (*callback)(NSSPrivateKey *vk, void *arg),
 *   void *arg
 * );
 */

/* Symmetric Keys */

/*
 * NSSVolatileDomain_GenerateSymKey
 *
 */

NSS_EXTERN NSSSymKey *
NSSVolatileDomain_GenerateSymKey (
  NSSVolatileDomain *vd,
  const NSSAlgNParam *ap,
  PRUint32 keysize,
  const NSSUTF8 *labelOpt,
  NSSOperations operations,
  NSSProperties properties,
  NSSToken *destination,
  NSSCallback *uhhOpt
);

/*
 * NSSVolatileDomain_GenerateSymKeyFromPassword
 *
 */

NSS_EXTERN NSSSymKey *
NSSVolatileDomain_GenerateSymKeyFromPassword (
  NSSVolatileDomain *vd,
  const NSSAlgNParam *ap,
  NSSUTF8 *passwordOpt, /* if null, prompt */
  NSSToken *destinationOpt,
  NSSCallback *uhhOpt
);

/*
 * NSSVolatileDomain_FindSymKeyByAlgorithm
 *
 * 
 * NSS_EXTERN NSSSymKey *
 * NSSVolatileDomain_FindSymKeyByType
 * (
 *   NSSVolatileDomain *vd,
 *   NSSOID *type,
 *   NSSCallback *uhhOpt
 * );
 */

/*
 * NSSVolatileDomain_FindSymKeyByAlgorithmAndKeyID
 *
 */

NSS_EXTERN NSSSymKey *
NSSVolatileDomain_FindSymKeyByAlgorithmAndKeyID (
  NSSVolatileDomain *vd,
  NSSOIDTag algorithm,
  NSSItem *keyID,
  NSSCallback *uhhOpt
);

/*
 * NSSVolatileDomain_UnwrapSymKey
 *
 */

NSS_EXTERN NSSSymKey *
NSSVolatileDomain_UnwrapSymKey (
  NSSVolatileDomain *vd,
  const NSSAlgNParam *ap,
  NSSPrivateKey *wrapKey,
  NSSItem *wrappedKey,
  NSSSymKeyType targetSymKeyType,
  NSSCallback *uhhOpt,
  NSSOperations operations,
  NSSProperties properties
);

/*
 * NSSVolatileDomain_TraverseSymKeys
 *
 * 
 * NSS_EXTERN PRStatus *
 * NSSVolatileDomain_TraverseSymKeys
 * (
 *   NSSVolatileDomain *vd,
 *   PRStatus (*callback)(NSSSymKey *mk, void *arg),
 *   void *arg
 * );
 */

/*
 * NSSVolatileDomain_DeriveSymKey
 *
 */

NSS_EXTERN NSSSymKey *
NSSVolatileDomain_DeriveSymKey (
  NSSVolatileDomain *vd,
  NSSPublicKey *bkOpt,
  const NSSAlgNParam *apOpt,
  NSSSymKeyType targetSymKeyType,
  PRUint32 keySizeOpt, /* zero for best allowed */
  NSSOperations operations,
  NSSCallback *uhhOpt
);

NSS_EXTERN NSSCryptoContext *
NSSVolatileDomain_CreateCryptoContext (
  NSSVolatileDomain *vd,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhhOpt
);

NSS_EXTERN NSSCertChain *
NSSVolatileDomain_CreateCertChain (
  NSSVolatileDomain *vd,
  NSSCert *vdCertOpt,
  NSSTime time,
  const NSSUsages *usages,
  NSSPolicies *policiesOpt
);

/*
 * NSSCertChain
 *
 *
 */

NSS_EXTERN PRStatus
NSSCertChain_Destroy (
  NSSCertChain *chain
);

NSS_EXTERN PRStatus
NSSCertChain_AddEncodedCert (
  NSSCertChain *chain,
  NSSBER *encodedCert,
  NSSUTF8 *nicknameOpt,
  NSSToken *destinationOpt,
  NSSCert **rvCertOpt
);

NSS_EXTERN PRIntn
NSSCertChain_GetNumCerts (
  NSSCertChain *chain
);

NSS_EXTERN NSSCert *
NSSCertChain_GetCert (
  NSSCertChain *chain,
  PRIntn index
);


/*
 * NSSCryptoContext
 *
 * A crypto context is sort of a short-term snapshot of a PKI domain,
 * used for the lifetime of "one crypto operation."
 * 
 * If the context was created for a key, cert, and/or algorithm; or
 * if such objects have been "associated" with the context, then the context
 * can do everything the keys can, like crypto operations.
 * 
 * And finally, because it keeps the state of the crypto operations, it
 * can do streaming crypto ops.
 */

/*
 * NSSCryptoContext_Destroy
 *
 */

NSS_EXTERN PRStatus
NSSCryptoContext_Destroy (
  NSSCryptoContext *cc
);

/* establishing a default callback */

/*
 * NSSCryptoContext_SetDefaultCallback
 *
 */

NSS_EXTERN PRStatus
NSSCryptoContext_SetDefaultCallback (
  NSSCryptoContext *cc,
  NSSCallback *newCallback,
  NSSCallback **oldCallbackOpt
);

/*
 * NSSCryptoContext_GetDefaultCallback
 *
 */

NSS_EXTERN NSSCallback *
NSSCryptoContext_GetDefaultCallback (
  NSSCryptoContext *cc,
  PRStatus *statusOpt
);

/*
 * NSSCryptoContext_GetTrustDomain
 *
 */

NSS_EXTERN NSSTrustDomain *
NSSCryptoContext_GetTrustDomain (
  NSSCryptoContext *cc
);

/* AddModule, etc: should we allow "temporary" changes here? */
/* DisableToken, etc: ditto */
/* Ordering of tokens? */
/* Finding slots+token etc. */
/* login+logout */


/* Crypto ops on distinguished keys */

/*
 * NSSItem semantics:
 *
 *   If rvOpt is NULL, a new NSSItem and buffer are allocated.
 *   If rvOpt is not null, but the buffer pointer is null,
 *     then rvOpt is returned but a new buffer is allocated.
 *     In this case, if the length value is not zero, then
 *     no more than that much space will be allocated.
 *   If rvOpt is not null and the buffer pointer is not null,
 *     then that buffer is re-used.  No more than the buffer
 *     length value will be used; if it's not enough, an
 *     error is returned.  If less is used, the number is
 *     adjusted downwards.
 *
 *  Note that although this is short of some ideal "Item"
 *  definition, we can usually tell how big these buffers
 *  have to be.
 *
 *  Feedback is requested; and earlier is better than later.
 */

/*
 * NSSCryptoContext_Encrypt
 *
 * Encrypt a single chunk of data with the distinguished public key
 * of this crypto context.
 */


NSS_EXTERN NSSItem *
NSSCryptoContext_Encrypt (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSCryptoContext_BeginEncrypt
 *
 */

NSS_EXTERN PRStatus
NSSCryptoContext_BeginEncrypt (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhhOpt
);

/*
 * NSSCryptoContext_ContinueEncrypt
 *
 */

NSS_EXTERN NSSItem *
NSSCryptoContext_ContinueEncrypt (
  NSSCryptoContext *cc,
  NSSItem *data,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSCryptoContext_FinishEncrypt
 *
 */

NSS_EXTERN NSSItem *
NSSCryptoContext_FinishEncrypt (
  NSSCryptoContext *cc,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);


/*
 * NSSCryptoContext_Decrypt
 *
 */

NSS_EXTERN NSSItem *
NSSCryptoContext_Decrypt (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSItem *encryptedData,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSCryptoContext_BeginDecrypt
 *
 */

NSS_EXTERN PRStatus
NSSCryptoContext_BeginDecrypt (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhhOpt
);

/*
 * NSSCryptoContext_ContinueDecrypt
 *
 */

NSS_EXTERN NSSItem *
NSSCryptoContext_ContinueDecrypt (
  NSSCryptoContext *cc,
  NSSItem *data,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSCryptoContext_FinishDecrypt
 *
 */

NSS_EXTERN NSSItem *
NSSCryptoContext_FinishDecrypt (
  NSSCryptoContext *cc,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSCryptoContext_Sign
 *
 */

NSS_EXTERN NSSItem *
NSSCryptoContext_Sign (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSCryptoContext_BeginSign
 *
 */

NSS_EXTERN PRStatus
NSSCryptoContext_BeginSign (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhhOpt
);

/*
 * NSSCryptoContext_ContinueSign
 *
 */

NSS_EXTERN PRStatus
NSSCryptoContext_ContinueSign (
  NSSCryptoContext *cc,
  NSSItem *data
);

/*
 * NSSCryptoContext_FinishSign
 *
 */

NSS_EXTERN NSSItem *
NSSCryptoContext_FinishSign (
  NSSCryptoContext *cc,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSCryptoContext_SignRecover
 *
 */

NSS_EXTERN NSSItem *
NSSCryptoContext_SignRecover (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSCryptoContext_Verify
 *
 */

NSS_EXTERN PRStatus
NSSCryptoContext_Verify (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSItem *signature,
  NSSCallback *uhhOpt
);

/*
 * NSSCryptoContext_BeginVerify
 *
 */

NSS_EXTERN PRStatus
NSSCryptoContext_BeginVerify (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhhOpt
);

/*
 * NSSCryptoContext_ContinueVerify
 *
 */

NSS_EXTERN PRStatus
NSSCryptoContext_ContinueVerify (
  NSSCryptoContext *cc,
  NSSItem *data
);

/*
 * NSSCryptoContext_FinishVerify
 *
 */

NSS_EXTERN PRStatus
NSSCryptoContext_FinishVerify (
  NSSCryptoContext *cc,
  NSSItem *signature
);

/*
 * NSSCryptoContext_VerifyRecover
 *
 */

NSS_EXTERN NSSItem *
NSSCryptoContext_VerifyRecover (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSItem *signature,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSCryptoContext_WrapSymKey
 *
 */

NSS_EXTERN NSSItem *
NSSCryptoContext_WrapSymKey (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSSymKey *keyToWrap,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSCryptoContext_Digest
 *
 * Digest a single chunk of data.
 */

NSS_EXTERN NSSItem *
NSSCryptoContext_Digest (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * NSSCryptoContext_BeginDigest
 *
 */

NSS_EXTERN PRStatus
NSSCryptoContext_BeginDigest (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhhOpt
);

/*
 * NSSCryptoContext_ContinueDigest
 *
 */

NSS_EXTERN PRStatus
NSSCryptoContext_ContinueDigest (
  NSSCryptoContext *cc,
  NSSItem *item
);

NSS_EXTERN PRStatus
NSSCryptoContext_DigestKey (
  NSSCryptoContext *cc,
  NSSSymKey *mkOpt
);

/*
 * NSSCryptoContext_FinishDigest
 *
 */

NSS_EXTERN NSSItem *
NSSCryptoContext_FinishDigest (
  NSSCryptoContext *cc,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
);

/*
 * tbd: Combination ops
 */

/*
 * NSSCryptoContext_Clone
 *
 */

NSS_EXTERN NSSCryptoContext *
NSSCryptoContext_Clone (
  NSSCryptoContext *cc
);

NSS_EXTERN NSSCryptoContextMark *
NSSCryptoContext_Mark (
  NSSCryptoContext *cc
);

NSS_EXTERN PRStatus
NSSCryptoContext_Unmark (
  NSSCryptoContext *cc,
  NSSCryptoContextMark *mark
);

NSS_EXTERN PRStatus
NSSCryptoContext_Release (
  NSSCryptoContext *cc,
  NSSCryptoContextMark *mark
);

/*
 * ..._SignTBSCert
 *
 * This requires feedback from the cert server team.
 */

/*
 * PRBool NSSCert_GetIsTrustedFor{xxx}(NSSCert *c);
 * PRStatus NSSCert_SetIsTrustedFor{xxx}(NSSCert *c, PRBool trusted);
 *
 * These will be helper functions which get the trust object for a cert,
 * and then call the corresponding function(s) on it.
 *
 * PKIX trust objects will have methods to manipulate the low-level trust
 * bits (which are based on key usage and extended key usage), and also the
 * conceptual high-level usages (e.g. ssl client auth, email encryption, etc.)
 *
 * Other types of trust objects (if any) might have different low-level
 * representations, but hopefully high-level concepts would map.
 *
 * Only these high-level general routines would be promoted to the
 * general certificate level here.  Hence the {xxx} above would be things
 * like "EmailSigning."
 *
 *
 * NSSPKIXTrust *NSSCert_GetPKIXTrustObject(NSSCert *c);
 * PRStatus NSSCert_SetPKIXTrustObject(NSSCert *c, NSPKIXTrust *t);
 *
 * I want to hold off on any general trust object until we've investigated
 * other models more thoroughly.
 */

NSS_EXTERN NSSTime
NSSTime_Now (
  void
);

NSS_EXTERN NSSUTF8 *
NSSTime_GetUTCTime (
  NSSTime time,
  NSSArena *arenaOpt
);

NSS_EXTERN NSSTime
NSSTime_CreateFromUTCTime (
  NSSUTF8 *utcTime,
  PRStatus *statusOpt
);

PR_END_EXTERN_C

#endif /* NSSPKI_H */
