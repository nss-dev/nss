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

#ifdef DEBUG
static const char CVS_ID[] = "@(#) $RCSfile$ $Revision$ $Date$ $Name$";
#endif /* DEBUG */

#ifndef DEV_H
#include "dev.h"
#endif /* DEV_H */

#ifndef PKIM_H
#include "pkim.h"
#endif /* PKIM_H */

extern const NSSError NSS_ERROR_NOT_FOUND;

struct NSSSymmetricKeyStr
{
  nssPKIObject object;
  NSSSymmetricKeyType kind;
  PRUint32 length; /* XXX 64-bit... */
  NSSOperations operations;
};

NSS_IMPLEMENT NSSSymmetricKey *
nssSymmetricKey_Create
(
  nssPKIObject *object
)
{
    PRStatus status;
    NSSSymmetricKey *rvKey;
    NSSArena *arena = object->arena;
    PR_ASSERT(object->instances != NULL && object->numInstances > 0);
    rvKey = nss_ZNEW(arena, NSSSymmetricKey);
    if (!rvKey) {
	return (NSSSymmetricKey *)NULL;
    }
    rvKey->object = *object;
    /* XXX should choose instance based on some criteria */
    status = nssCryptokiSymmetricKey_GetAttributes(object->instances[0],
                                                   arena,
                                                   &rvKey->kind,
                                                   &rvKey->length,
                                                   &rvKey->operations);
    if (status != PR_SUCCESS) {
	return (NSSSymmetricKey *)NULL;
    }
    return rvKey;
}

NSS_IMPLEMENT NSSSymmetricKey *
nssSymmetricKey_AddRef
(
  NSSSymmetricKey *mk
)
{
    if (mk) {
	nssPKIObject_AddRef(&mk->object);
    }
    return mk;
}

NSS_IMPLEMENT PRStatus
nssSymmetricKey_Destroy
(
  NSSSymmetricKey *mk
)
{
    return nssPKIObject_Destroy(&mk->object);
}

NSS_IMPLEMENT PRStatus
NSSSymmetricKey_Destroy
(
  NSSSymmetricKey *mk
)
{
    nssSymmetricKey_Destroy(mk);
    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSToken **
nssSymmetricKey_GetTokens
(
  NSSSymmetricKey *mk,
  PRStatus *statusOpt
)
{
    return nssPKIObject_GetTokens(&mk->object, statusOpt);
}

NSS_IMPLEMENT nssCryptokiObject *
nssSymmetricKey_GetInstance
(
  NSSSymmetricKey *mk,
  NSSToken *token
)
{
    return nssPKIObject_GetInstance(&mk->object, token);
}

NSS_IMPLEMENT nssCryptokiObject *
nssSymmetricKey_FindInstanceForAlgorithm
(
  NSSSymmetricKey *mk,
  NSSAlgorithmAndParameters *ap
)
{
    return nssPKIObject_FindInstanceForAlgorithm(&mk->object, ap);
}

NSS_IMPLEMENT PRBool
nssSymmetricKey_IsOnToken
(
  NSSSymmetricKey *mk,
  NSSToken *token
)
{
    return nssPKIObject_IsOnToken(&mk->object, token);
}

NSS_IMPLEMENT PRStatus
nssSymmetricKey_DeleteStoredObject
(
  NSSSymmetricKey *mk,
  NSSCallback *uhh
)
{
    return nssPKIObject_DeleteStoredObject(&mk->object, uhh, PR_TRUE);
}

NSS_IMPLEMENT PRStatus
NSSSymmetricKey_DeleteStoredObject
(
  NSSSymmetricKey *mk,
  NSSCallback *uhh
)
{
    return nssSymmetricKey_DeleteStoredObject(mk, uhh);
}

NSS_IMPLEMENT NSSSymmetricKey *
nssSymmetricKey_Copy
(
  NSSSymmetricKey *mk,
  NSSToken *destination
)
{
    /* XXX this could get complicated... might have to wrap the key, etc. */
    PR_ASSERT(0);
    return NULL;
}

NSS_IMPLEMENT PRUint32
nssSymmetricKey_GetKeyLength
(
  NSSSymmetricKey *mk
)
{
    return mk->length;
}

NSS_IMPLEMENT PRUint32
NSSSymmetricKey_GetKeyLength
(
  NSSSymmetricKey *mk
)
{
    return nssSymmetricKey_GetKeyLength(mk);
}

#ifndef BPB
#define BPB 8
#endif

NSS_IMPLEMENT PRUint32
NSSSymmetricKey_GetKeyStrength
(
  NSSSymmetricKey *mk
)
{
    /* XXX look these up */
    switch (mk->kind) {
    case NSSSymmetricKeyType_DES:       return 56;
    case NSSSymmetricKeyType_TripleDES: return 112; /* IIRC */
    case NSSSymmetricKeyType_RC2:       return -1; /* need eff. len. */
    case NSSSymmetricKeyType_RC4:       return mk->length * BPB;
    case NSSSymmetricKeyType_AES:       return mk->length * BPB;
    default: return -1;
    }
}

NSS_IMPLEMENT PRStatus
NSSSymmetricKey_IsStillPresent
(
  NSSSymmetricKey *mk
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return PR_FAILURE;
}

NSS_IMPLEMENT NSSTrustDomain *
nssSymmetricKey_GetTrustDomain
(
  NSSSymmetricKey *mk,
  PRStatus *statusOpt
)
{
    return nssPKIObject_GetTrustDomain(&mk->object, statusOpt);
}

NSS_IMPLEMENT NSSTrustDomain *
NSSSymmetricKey_GetTrustDomain
(
  NSSSymmetricKey *mk,
  PRStatus *statusOpt
)
{
    return nssSymmetricKey_GetTrustDomain(mk, statusOpt);
}

NSS_IMPLEMENT NSSToken *
NSSSymmetricKey_GetToken
(
  NSSSymmetricKey *mk,
  PRStatus *statusOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSSlot *
NSSSymmetricKey_GetSlot
(
  NSSSymmetricKey *mk,
  PRStatus *statusOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSModule *
NSSSymmetricKey_GetModule
(
  NSSSymmetricKey *mk,
  PRStatus *statusOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSItem *
nssSymmetricKey_Encrypt
(
  NSSSymmetricKey *mk,
  const NSSAlgorithmAndParameters *ap,
  NSSItem *data,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nssSession *session;
    nssCryptokiObject **op, **objects;
    NSSItem *rvIt = NULL;

    /* XXX in cipher order */
    objects = nssPKIObject_GetInstances(&mk->object);
    for (op = objects; *op; op++) {
	session = nssToken_CreateSession((*op)->token, PR_FALSE);
	if (!session) {
	    break;
	}
	rvIt = nssToken_Encrypt((*op)->token, session, ap, *op, 
	                        data, rvOpt, arenaOpt);
	nssSession_Destroy(session);
	if (rvIt) {
	    break;
	} /* XXX some errors should cause us to break out of the loop here */
    }
    nssCryptokiObjectArray_Destroy(objects);
    return rvIt;
}

NSS_IMPLEMENT NSSItem *
NSSSymmetricKey_Encrypt
(
  NSSSymmetricKey *mk,
  const NSSAlgorithmAndParameters *ap,
  NSSItem *data,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssSymmetricKey_Encrypt(mk, ap, data, uhh, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
nssSymmetricKey_Decrypt
(
  NSSSymmetricKey *mk,
  const NSSAlgorithmAndParameters *ap,
  NSSItem *encryptedData,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nssSession *session;
    nssCryptokiObject **op, **objects;
    NSSItem *rvIt = NULL;

    /* XXX in cipher order */
    objects = nssPKIObject_GetInstances(&mk->object);
    for (op = objects; *op; op++) {
	session = nssToken_CreateSession((*op)->token, PR_FALSE);
	if (!session) {
	    break;
	}
	rvIt = nssToken_Decrypt((*op)->token, session, ap, *op, 
	                        encryptedData, rvOpt, arenaOpt);
	nssSession_Destroy(session);
	if (rvIt) {
	    break;
	} /* XXX some errors should cause us to break out of the loop here */
    }
    nssCryptokiObjectArray_Destroy(objects);
    return rvIt;
}

NSS_IMPLEMENT NSSItem *
NSSSymmetricKey_Decrypt
(
  NSSSymmetricKey *mk,
  const NSSAlgorithmAndParameters *ap,
  NSSItem *encryptedData,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssSymmetricKey_Decrypt(mk, ap, encryptedData, 
                                   uhh, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
nssSymmetricKey_Sign
(
  NSSSymmetricKey *mk,
  const NSSAlgorithmAndParameters *ap,
  NSSItem *data,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nssSession *session;
    nssCryptokiObject **op, **objects;
    NSSItem *rvIt = NULL;

    /* XXX in cipher order */
    objects = nssPKIObject_GetInstances(&mk->object);
    for (op = objects; *op; op++) {
	session = nssToken_CreateSession((*op)->token, PR_FALSE);
	if (!session) {
	    break;
	}
	rvIt = nssToken_Sign((*op)->token, session, ap, *op, 
	                     data, rvOpt, arenaOpt);
	nssSession_Destroy(session);
	if (rvIt) {
	    break;
	} /* XXX some errors should cause us to break out of the loop here */
    }
    nssCryptokiObjectArray_Destroy(objects);
    return rvIt;
}

NSS_IMPLEMENT NSSItem *
NSSSymmetricKey_Sign
(
  NSSSymmetricKey *mk,
  const NSSAlgorithmAndParameters *ap,
  NSSItem *data,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssSymmetricKey_Sign(mk, ap, data, uhh, rvOpt, arenaOpt);
}

NSS_IMPLEMENT PRStatus
nssSymmetricKey_Verify
(
  NSSSymmetricKey *mk,
  const NSSAlgorithmAndParameters *ap,
  NSSItem *data,
  NSSItem *signature,
  NSSCallback *uhh
)
{
    nssSession *session;
    nssCryptokiObject **op, **objects;
    PRStatus status;

    /* XXX in cipher order */
    objects = nssPKIObject_GetInstances(&mk->object);
    for (op = objects; *op; op++) {
	session = nssToken_CreateSession((*op)->token, PR_FALSE);
	if (!session) {
	    break;
	}
	status = nssToken_Verify((*op)->token, session, ap, *op, 
	                         data, signature);
	nssSession_Destroy(session);
	if (status == PR_SUCCESS) {
	    break;
	} else {
	    NSSError e = NSS_GetError();
	    if (e == NSS_ERROR_INVALID_SIGNATURE ||
	        e == NSS_ERROR_INVALID_DATA)
	    {
		break;
	    }
	    /* otherwise, a token failure, so try other tokens */
	}
    }
    nssCryptokiObjectArray_Destroy(objects);
    return status;
}

NSS_IMPLEMENT PRStatus
NSSSymmetricKey_Verify
(
  NSSSymmetricKey *mk,
  const NSSAlgorithmAndParameters *ap,
  NSSItem *data,
  NSSItem *signature,
  NSSCallback *uhh
)
{
    return nssSymmetricKey_Verify(mk, ap, data, signature, uhh);
}

NSS_IMPLEMENT NSSItem *
NSSSymmetricKey_WrapSymmetricKey
(
  NSSSymmetricKey *wrappingKey,
  const NSSAlgorithmAndParameters *ap,
  NSSSymmetricKey *keyToWrap,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSItem *
NSSSymmetricKey_WrapPrivateKey
(
  NSSSymmetricKey *wrappingKey,
  const NSSAlgorithmAndParameters *ap,
  NSSPrivateKey *keyToWrap,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSSymmetricKey *
NSSSymmetricKey_UnwrapSymmetricKey
(
  NSSSymmetricKey *wrappingKey,
  const NSSAlgorithmAndParameters *ap,
  NSSItem *wrappedKey,
  NSSOID *target,
  PRUint32 keySizeOpt,
  NSSOperations operations,
  NSSCallback *uhh
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSPrivateKey *
NSSSymmetricKey_UnwrapPrivateKey
(
  NSSSymmetricKey *wrappingKey,
  const NSSAlgorithmAndParameters *ap,
  NSSItem *wrappedKey,
  NSSUTF8 *labelOpt,
  NSSItem *keyIDOpt,
  PRBool persistant,
  PRBool sensitive,
  NSSToken *destinationOpt,
  NSSCallback *uhh
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSSymmetricKey *
NSSSymmetricKey_DeriveSymmetricKey
(
  NSSSymmetricKey *originalKey,
  const NSSAlgorithmAndParameters *ap,
  NSSOID *target,
  PRUint32 keySizeOpt,
  NSSOperations operations,
  NSSCallback *uhh
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCryptoContext *
nssSymmetricKey_CreateCryptoContext
(
  NSSSymmetricKey *mk,
  const NSSAlgorithmAndParameters *apOpt,
  NSSCallback *uhh
)
{
    return nssCryptoContext_CreateForSymmetricKey(mk, apOpt, uhh);
}

NSS_IMPLEMENT NSSCryptoContext *
NSSSymmetricKey_CreateCryptoContext
(
  NSSSymmetricKey *mk,
  const NSSAlgorithmAndParameters *apOpt,
  NSSCallback *uhh
)
{
    return nssSymmetricKey_CreateCryptoContext(mk, apOpt, uhh);
}

