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

#ifndef BASE_H
#include "base.h"
#endif /* BASE_H */

#ifndef DEV_H
#include "dev.h"
#endif /* DEV_H */

#ifndef PKIM_H
#include "pkim.h"
#endif /* PKIM_H */

extern const NSSError NSS_ERROR_NOT_FOUND;

#ifdef nodef
typedef union 
{
  nssRSAPrivateKeyData rsa;
  nssDSAPrivateKeyData dsa;
}
nssPrivateKeyData;
#endif

struct NSSPrivateKeyStr
{
  nssPKIObject object;
  NSSKeyPairType kind;
  NSSItem id;
#ifdef nodef
  NSSTime startDate;
  NSSTime endDate;
  nssPrivateKeyData keyData;
#endif
};

NSS_IMPLEMENT NSSPrivateKey *
nssPrivateKey_Create
(
  nssPKIObject *object
)
{
    PRStatus status;
    NSSPrivateKey *rvKey;
    NSSArena *arena = object->arena;
    PR_ASSERT(object->instances != NULL && object->numInstances > 0);
    rvKey = nss_ZNEW(arena, NSSPrivateKey);
    if (!rvKey) {
	return (NSSPrivateKey *)NULL;
    }
    rvKey->object = *object;
    /* XXX should choose instance based on some criteria */
    status = nssCryptokiPrivateKey_GetAttributes(object->instances[0],
                                                 arena,
                                                 &rvKey->kind,
                                                 &rvKey->id);
    if (status != PR_SUCCESS) {
	return (NSSPrivateKey *)NULL;
    }
    return rvKey;
}

NSS_IMPLEMENT NSSPrivateKey *
nssPrivateKey_AddRef
(
  NSSPrivateKey *vk
)
{
    if (vk) {
	(void)nssPKIObject_AddRef(&vk->object);
    }
    return vk;
}

NSS_IMPLEMENT PRStatus
nssPrivateKey_Destroy
(
  NSSPrivateKey *vk
)
{
    PRBool destroyed;
    if (vk) {
	destroyed = nssPKIObject_Destroy(&vk->object);
	/*
	if (destroyed) {
	}
	*/
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT PRStatus
NSSPrivateKey_Destroy
(
  NSSPrivateKey *vk
)
{
    return nssPrivateKey_Destroy(vk);
}

NSS_IMPLEMENT NSSItem *
nssPrivateKey_GetID
(
  NSSPrivateKey *vk
)
{
    if (vk->id.data != NULL && vk->id.size > 0) {
	return &vk->id;
    } else {
	return (NSSItem *)NULL;
    }
}

NSS_IMPLEMENT NSSUTF8 *
nssPrivateKey_GetNickname
(
  NSSPrivateKey *vk,
  NSSToken *tokenOpt
)
{
    return nssPKIObject_GetNicknameForToken(&vk->object, tokenOpt);
}

NSS_IMPLEMENT PRBool
nssPrivateKey_IsOnToken
(
  NSSPrivateKey *vk,
  NSSToken *token
)
{
    return nssPKIObject_IsOnToken(&vk->object, token);
}

NSS_IMPLEMENT nssCryptokiObject *
nssPrivateKey_GetInstance
(
  NSSPrivateKey *vk,
  NSSToken *token
)
{
    return nssPKIObject_GetInstance(&vk->object, token);
}

NSS_IMPLEMENT nssCryptokiObject *
nssPrivateKey_FindInstanceForAlgorithm
(
  NSSPrivateKey *vk,
  NSSAlgorithmAndParameters *ap
)
{
    return nssPKIObject_FindInstanceForAlgorithm(&vk->object, ap);
}

NSS_IMPLEMENT PRStatus
NSSPrivateKey_DeleteStoredObject
(
  NSSPrivateKey *vk,
  NSSCallback *uhh
)
{
    return nssPKIObject_DeleteStoredObject(&vk->object, uhh, PR_FALSE);
}

NSS_IMPLEMENT NSSPrivateKey *
nssPrivateKey_Copy
(
  NSSPrivateKey *vk,
  NSSToken *destination
)
{
    /* XXX this could get complicated... might have to wrap the key, etc. */
    PR_ASSERT(0);
    return NULL;
}

NSS_IMPLEMENT PRUint32
NSSPrivateKey_GetSignatureLength
(
  NSSPrivateKey *vk
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return -1;
}

NSS_IMPLEMENT PRUint32
NSSPrivateKey_GetPrivateModulusLength
(
  NSSPrivateKey *vk
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return -1;
}

NSS_IMPLEMENT PRBool
NSSPrivateKey_IsStillPresent
(
  NSSPrivateKey *vk,
  PRStatus *statusOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return PR_FALSE;
}

NSS_IMPLEMENT NSSItem *
NSSPrivateKey_Encode
(
  NSSPrivateKey *vk,
  const NSSAlgorithmAndParameters *ap,
  NSSItem *passwordOpt, /* NULL will cause a callback; "" for no password */
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCryptoContext *
nssPrivateKey_GetCryptoContext
(
  NSSPrivateKey *vk,
  PRStatus *statusOpt
)
{
    return vk->object.cryptoContext;
}

NSS_IMPLEMENT NSSTrustDomain *
nssPrivateKey_GetTrustDomain
(
  NSSPrivateKey *vk,
  PRStatus *statusOpt
)
{
    return vk->object.trustDomain;
}

NSS_IMPLEMENT NSSTrustDomain *
NSSPrivateKey_GetTrustDomain
(
  NSSPrivateKey *vk,
  PRStatus *statusOpt
)
{
    return nssPrivateKey_GetTrustDomain(vk, statusOpt);
}

NSS_IMPLEMENT NSSToken *
NSSPrivateKey_GetToken
(
  NSSPrivateKey *vk
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSSlot *
NSSPrivateKey_GetSlot
(
  NSSPrivateKey *vk
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSModule *
NSSPrivateKey_GetModule
(
  NSSPrivateKey *vk
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSItem *
NSSPrivateKey_Decrypt
(
  NSSPrivateKey *vk,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *encryptedData,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSItem *
NSSPrivateKey_Sign
(
  NSSPrivateKey *vk,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *data,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSItem *
NSSPrivateKey_SignRecover
(
  NSSPrivateKey *vk,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *data,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSSymmetricKey *
NSSPrivateKey_UnwrapSymmetricKey
(
  NSSPrivateKey *vk,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *wrappedKey,
  NSSCallback *uhh
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSSymmetricKey *
NSSPrivateKey_DeriveSymmetricKey
(
  NSSPrivateKey *vk,
  NSSPublicKey *bk,
  const NSSAlgorithmAndParameters *apOpt,
  NSSOID *target,
  PRUint32 keySizeOpt, /* zero for best allowed */
  NSSOperations operations,
  NSSCallback *uhh
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSPublicKey *
nssPrivateKey_FindPublicKey
(
  NSSPrivateKey *vk
)
{
    PRStatus status;
    NSSItem *id;
    NSSPublicKey *rvPubKey = NULL;
    nssPKIObjectCollection *collection = NULL;
    id = nssPrivateKey_GetID(vk);
    if (id) {
	/* XXX
	 * This would ostensibly search the trust domain.  However, that
	 * means searching every active token for the key, when it is
	 * almost assuredly only on the token with the private key.  Even
	 * if not, the token that has the pair is the most desirable.
	 * In general, this is another place where multiple instances
	 * can be confusing/non-optimal, so needs to be handled correctly.
	 * For now, restricting the search to the private key's tokens.
	 */
	NSSToken **tokens, **tp;
	nssCryptokiObject *instance;
	NSSTrustDomain *td = nssPrivateKey_GetTrustDomain(vk, NULL);
	tokens = nssPKIObject_GetTokens(&vk->object, &status);
	if (!tokens) {
	    return (NSSPublicKey *)NULL; /* defer to trust domain ??? */
	}
	for (tp = tokens; *tp; tp++) {
	    /* XXX think of something better */
	    nssCryptokiObject *vko;
	    vko = nssPKIObject_GetInstance(&vk->object, *tp);
	    if (!vko) {
		continue;
	    }
	    instance = nssToken_FindPublicKeyByID(*tp, vko->session, id);
	    nssCryptokiObject_Destroy(vko);
	    if (instance) {
		if (!collection) {
		    collection = nssPublicKeyCollection_Create(td, NULL);
		    if (!collection) {
			nssCryptokiObject_Destroy(instance);
			return (NSSPublicKey *)NULL;
		    }
		}
		status = nssPKIObjectCollection_AddInstances(collection, 
		                                             &instance, 1);
	    }
	}
    }
    if (collection) {
	(void)nssPKIObjectCollection_GetPublicKeys(collection, 
	                                           &rvPubKey, 1, NULL);
	nssPKIObjectCollection_Destroy(collection);
    }
    return rvPubKey;
}

NSS_IMPLEMENT NSSPublicKey *
NSSPrivateKey_FindPublicKey
(
  NSSPrivateKey *vk
)
{
    return nssPrivateKey_FindPublicKey(vk);;
}

NSS_IMPLEMENT NSSCryptoContext *
NSSPrivateKey_CreateCryptoContext
(
  NSSPrivateKey *vk,
  const NSSAlgorithmAndParameters *apOpt,
  NSSCallback *uhh
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCertificate **
nssPrivateKey_FindCertificates
(
  NSSPrivateKey *vk,
  NSSCertificate **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    NSSTrustDomain *td = nssPrivateKey_GetTrustDomain(vk, NULL);
    return nssTrustDomain_FindCertificatesByID(td, &vk->id, 
                                               rvOpt, maximumOpt, arenaOpt);
}

NSS_IMPLEMENT NSSCertificate **
NSSPrivateKey_FindCertificates
(
  NSSPrivateKey *vk,
  NSSCertificate **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    return nssPrivateKey_FindCertificates(vk, rvOpt, maximumOpt, arenaOpt);
}

NSS_IMPLEMENT NSSCertificate *
NSSPrivateKey_FindBestCertificate
(
  NSSPrivateKey *vk,
  NSSTime time,
  NSSUsage *usageOpt,
  NSSPolicies *policiesOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

struct NSSPublicKeyStr
{
  nssPKIObject object;
  NSSKeyPairType kind;
  NSSItem id;
#ifdef nodef
  NSSTime startDate;
  NSSTime endDate;
  PRUint32 flags;
  NSSDER subject;
  nssPublicKeyData keyData;
#endif
};

NSS_IMPLEMENT NSSPublicKey *
nssPublicKey_Create
(
  nssPKIObject *object
)
{
    PRStatus status;
    NSSPublicKey *rvKey;
    NSSArena *arena = object->arena;
    PR_ASSERT(object->instances != NULL && object->numInstances > 0);
    rvKey = nss_ZNEW(arena, NSSPublicKey);
    if (!rvKey) {
	return (NSSPublicKey *)NULL;
    }
    rvKey->object = *object;
    /* XXX should choose instance based on some criteria */
    status = nssCryptokiPublicKey_GetAttributes(object->instances[0],
                                                arena,
                                                &rvKey->kind,
                                                &rvKey->id);
    if (status != PR_SUCCESS) {
	return (NSSPublicKey *)NULL;
    }
    return rvKey;
}

NSS_IMPLEMENT NSSPublicKey *
nssPublicKey_AddRef
(
  NSSPublicKey *bk
)
{
    if (bk) {
	(void)nssPKIObject_AddRef(&bk->object);
    }
    return bk;
}

NSS_IMPLEMENT PRStatus
nssPublicKey_Destroy
(
  NSSPublicKey *bk
)
{
    PRBool destroyed;
    if (bk) {
	destroyed = nssPKIObject_Destroy(&bk->object);
	/*
	if (destroyed) {
	}
	*/
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT PRStatus
NSSPublicKey_Destroy
(
  NSSPublicKey *bk
)
{
    return nssPublicKey_Destroy(bk);
}

NSS_IMPLEMENT NSSItem *
nssPublicKey_GetID
(
  NSSPublicKey *bk
)
{
    if (bk->id.data != NULL && bk->id.size > 0) {
	return &bk->id;
    } else {
	return (NSSItem *)NULL;
    }
}

NSS_IMPLEMENT PRBool
nssPublicKey_IsOnToken
(
  NSSPublicKey *bk,
  NSSToken *token
)
{
    return nssPKIObject_IsOnToken(&bk->object, token);
}

NSS_IMPLEMENT nssCryptokiObject *
nssPublicKey_GetInstance
(
  NSSPublicKey *bk,
  NSSToken *token
)
{
    return nssPKIObject_GetInstance(&bk->object, token);
}

NSS_IMPLEMENT nssCryptokiObject *
nssPublicKey_FindInstanceForAlgorithm
(
  NSSPublicKey *bk,
  NSSAlgorithmAndParameters *ap
)
{
    return nssPKIObject_FindInstanceForAlgorithm(&bk->object, ap);
}

NSS_IMPLEMENT PRStatus
nssPublicKey_DeleteStoredObject
(
  NSSPublicKey *bk,
  NSSCallback *uhh
)
{
    return nssPKIObject_DeleteStoredObject(&bk->object, uhh, PR_FALSE);
}

NSS_IMPLEMENT PRStatus
NSSPublicKey_DeleteStoredObject
(
  NSSPublicKey *bk,
  NSSCallback *uhh
)
{
    return nssPublicKey_DeleteStoredObject(bk, uhh);
}

NSS_IMPLEMENT NSSPublicKey *
nssPublicKey_Copy
(
  NSSPublicKey *bk,
  NSSToken *destination
)
{
    /* XXX this could get complicated... might have to wrap the key, etc. */
    PR_ASSERT(0);
    return NULL;
}

NSS_IMPLEMENT NSSItem *
NSSPublicKey_Encode
(
  NSSPublicKey *bk,
  const NSSAlgorithmAndParameters *ap,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSTrustDomain *
nssPublicKey_GetTrustDomain
(
  NSSPublicKey *bk,
  PRStatus *statusOpt
)
{
    return bk->object.trustDomain;
}

NSS_IMPLEMENT NSSTrustDomain *
NSSPublicKey_GetTrustDomain
(
  NSSPublicKey *bk,
  PRStatus *statusOpt
)
{
    return nssPublicKey_GetTrustDomain(bk, statusOpt);
}

NSS_IMPLEMENT NSSToken *
NSSPublicKey_GetToken
(
  NSSPublicKey *bk,
  PRStatus *statusOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSSlot *
NSSPublicKey_GetSlot
(
  NSSPublicKey *bk,
  PRStatus *statusOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSModule *
NSSPublicKey_GetModule
(
  NSSPublicKey *bk,
  PRStatus *statusOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSItem *
NSSPublicKey_Encrypt
(
  NSSPublicKey *bk,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *data,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT PRStatus
NSSPublicKey_Verify
(
  NSSPublicKey *bk,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *data,
  NSSItem *signature,
  NSSCallback *uhh
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return PR_FAILURE;
}

NSS_IMPLEMENT NSSItem *
NSSPublicKey_VerifyRecover
(
  NSSPublicKey *bk,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *signature,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSItem *
NSSPublicKey_WrapSymmetricKey
(
  NSSPublicKey *bk,
  const NSSAlgorithmAndParameters *apOpt,
  NSSSymmetricKey *keyToWrap,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCryptoContext *
NSSPublicKey_CreateCryptoContext
(
  NSSPublicKey *bk,
  const NSSAlgorithmAndParameters *apOpt,
  NSSCallback *uhh
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCertificate **
nssPublicKey_FindCertificates
(
  NSSPublicKey *bk,
  NSSCertificate **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    NSSTrustDomain *td = nssPublicKey_GetTrustDomain(bk, NULL);
    return nssTrustDomain_FindCertificatesByID(td, &bk->id, 
                                               rvOpt, maximumOpt, arenaOpt);
}

NSS_IMPLEMENT NSSCertificate **
NSSPublicKey_FindCertificates
(
  NSSPublicKey *bk,
  NSSCertificate **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    return nssPublicKey_FindCertificates(bk, rvOpt, maximumOpt, arenaOpt);
}

NSS_IMPLEMENT NSSCertificate *
nssPublicKey_FindBestCertificate
(
  NSSPublicKey *bk,
  NSSTime time,
  NSSUsage *usageOpt,
  NSSPolicies *policiesOpt
)
{
    NSSCertificate *rvCert = NULL;
    NSSCertificate **certs;

    certs = nssPublicKey_FindCertificates(bk, NULL, 0, NULL);
    if (!certs) {
	return (NSSCertificate *)NULL;
    }
    rvCert = nssCertificateArray_FindBestCertificate(certs, time, 
                                                     usageOpt, policiesOpt);
    nssCertificateArray_Destroy(certs);
    return rvCert;
}

NSS_IMPLEMENT NSSCertificate *
NSSPublicKey_FindBestCertificate
(
  NSSPublicKey *bk,
  NSSTime time,
  NSSUsage *usageOpt,
  NSSPolicies *policiesOpt
)
{
    return nssPublicKey_FindBestCertificate(bk, time, 
                                            usageOpt, policiesOpt);
}

NSS_IMPLEMENT NSSPrivateKey *
NSSPublicKey_FindPrivateKey
(
  NSSPublicKey *bk,
  NSSCallback *uhh
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

