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

#ifndef ASN1_H
#include "asn1.h"
#endif /* ASN1_H */

#ifndef DEV_H
#include "dev.h"
#endif /* DEV_H */

#ifndef PKI1_H
#include "pki1.h"
#endif /* PKI1_H */

#ifndef PKIM_H
#include "pkim.h"
#endif /* PKIM_H */

#include "pki1.h" /* XXX */
#include "oiddata.h"


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
nssPrivateKey_Create (
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
nssPrivateKey_CreateFromInstance (
  nssCryptokiObject *instance,
  NSSTrustDomain *td,
  NSSVolatileDomain *vdOpt
)
{
    nssPKIObject *pkio;

    pkio = nssPKIObject_Create(NULL, instance, td, vdOpt);
    if (pkio) {
	return nssPrivateKey_Create(pkio);
    }
    return (NSSPrivateKey *)NULL;
}

NSS_IMPLEMENT NSSPrivateKey *
nssPrivateKey_AddRef (
  NSSPrivateKey *vk
)
{
    if (vk) {
	(void)nssPKIObject_AddRef(&vk->object);
    }
    return vk;
}

NSS_IMPLEMENT PRStatus
nssPrivateKey_Destroy (
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
NSSPrivateKey_Destroy (
  NSSPrivateKey *vk
)
{
    return nssPrivateKey_Destroy(vk);
}

NSS_IMPLEMENT NSSItem *
nssPrivateKey_GetID (
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
nssPrivateKey_GetNickname (
  NSSPrivateKey *vk,
  NSSToken *tokenOpt
)
{
    return nssPKIObject_GetNickname(&vk->object, tokenOpt);
}

NSS_IMPLEMENT PRBool
nssPrivateKey_IsOnToken (
  NSSPrivateKey *vk,
  NSSToken *token
)
{
    return nssPKIObject_IsOnToken(&vk->object, token);
}

NSS_IMPLEMENT nssCryptokiObject *
nssPrivateKey_GetInstance (
  NSSPrivateKey *vk,
  NSSToken *token
)
{
    return nssPKIObject_GetInstance(&vk->object, token);
}

NSS_IMPLEMENT nssCryptokiObject *
nssPrivateKey_FindInstanceForAlgorithm (
  NSSPrivateKey *vk,
  const NSSAlgorithmAndParameters *ap
)
{
    return nssPKIObject_FindInstanceForAlgorithm(&vk->object, ap);
}

NSS_IMPLEMENT PRStatus
NSSPrivateKey_DeleteStoredObject (
  NSSPrivateKey *vk,
  NSSCallback *uhh
)
{
    return nssPKIObject_DeleteStoredObject(&vk->object, uhh, PR_FALSE);
}

NSS_IMPLEMENT nssCryptokiObject *
nssPrivateKey_CopyToToken (
  NSSPrivateKey *vk,
  NSSToken *destination
)
{
    /* XXX this could get complicated... might have to wrap the key, etc. */
    PR_ASSERT(0);
    return NULL;
}

NSS_IMPLEMENT PRUint32
NSSPrivateKey_GetSignatureLength (
  NSSPrivateKey *vk
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return -1;
}

NSS_IMPLEMENT PRUint32
NSSPrivateKey_GetPrivateModulusLength (
  NSSPrivateKey *vk
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return -1;
}

NSS_IMPLEMENT PRBool
NSSPrivateKey_IsStillPresent (
  NSSPrivateKey *vk,
  PRStatus *statusOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return PR_FALSE;
}

typedef struct {
  NSSItem encAlg;
  NSSItem encData;
} EPKI;

static const NSSASN1Template encrypted_private_key_info_tmpl[] =
{
 { NSSASN1_SEQUENCE, 0, NULL, sizeof(EPKI) },
 { NSSASN1_ANY,          offsetof(EPKI, encAlg)  },
 { NSSASN1_OCTET_STRING, offsetof(EPKI, encData) },
 { 0 }
};

NSS_IMPLEMENT NSSItem *
nssPrivateKey_Encode (
  NSSPrivateKey *vk,
  NSSAlgorithmAndParameters *ap,
  NSSUTF8 *passwordOpt,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    PRStatus status;
    nssCryptokiObject *pbeKey;
    nssCryptokiObject *vkey;
    NSSAlgorithmAndParameters *wrapAP;
    NSSItem *wrap;
    EPKI epki;
    NSSBER *pbeAlgBER;
    NSSItem *epkiData = NULL;
    NSSUTF8 *password;

    /* get the encryption password */
    if (passwordOpt) {
	password = passwordOpt;
    } else {
	NSSCallback *uhh;
	uhh = uhhOpt ? uhhOpt : 
	      nssTrustDomain_GetDefaultCallback(vk->object.td, NULL);
	status = uhh->getPW(NULL, NULL, uhh->arg, &password);
	if (status == PR_FAILURE) {
	    return (NSSItem *)NULL;
	}
    }
    (void)nssAlgorithmAndParameters_SetPBEPassword(ap, password);

    vkey = nssPrivateKey_FindInstanceForAlgorithm(vk, ap);
    if (!vkey) {
	/* XXX defer to trust domain? */
	nss_ZFreeIf(password);
	return (NSSItem *)NULL;
    }

    /* use the supplied PBE alg/param to create a wrapping key */
    pbeKey = nssToken_GenerateSymmetricKey(vkey->token, vkey->session, ap,
                                           0, NULL, PR_FALSE,
                                           NSSOperations_WRAP, 0);
    nss_ZFreeIf(password);
    if (!pbeKey) {
	return (NSSItem *)NULL;
    }

    /* convert the PBE alg/param to a corresponding encryption alg/param */
    wrapAP = nssAlgorithmAndParameters_ConvertPBEToCrypto(ap, PR_TRUE);
    if (!wrapAP) {
	return (NSSItem *)NULL;
    }

    /* wrap the private key with the PBE key */
    wrap = nssToken_WrapKey(vkey->token, vkey->session, wrapAP, 
                            pbeKey, vkey, 
                            rvOpt, arenaOpt);
    nssAlgorithmAndParameters_Destroy(wrapAP);
    nssCryptokiObject_Destroy(pbeKey);
    nssCryptokiObject_Destroy(vkey);
    if (!wrap) {
	return (NSSItem *)NULL;
    }

    /* encode result in PKCS#8 format */
    pbeAlgBER = nssAlgorithmAndParameters_Encode(ap, &epki.encAlg, arenaOpt);
    if (!pbeAlgBER) {
	return (NSSItem *)NULL;
    }
    epki.encData = *wrap;
    epkiData = nssASN1_EncodeItem(arenaOpt, rvOpt, &epki,
                                  encrypted_private_key_info_tmpl, 
                                  NSSASN1DER);

    return epkiData;
}

NSS_IMPLEMENT NSSItem *
NSSPrivateKey_Encode (
  NSSPrivateKey *vk,
  NSSAlgorithmAndParameters *ap,
  NSSUTF8 *passwordOpt,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssPrivateKey_Encode(vk, ap, passwordOpt, uhhOpt, 
                                rvOpt, arenaOpt);
}

/* XXX move to a lower layer to avoid extra translation? */
/* or keep data with oid? */
static NSSKeyPairType
get_key_pair_type(NSSOID *kpAlg)
{
    switch (nssOID_GetTag(kpAlg)) {
    case NSS_OID_PKCS1_RSA_ENCRYPTION:
    case NSS_OID_PKCS1_MD2_WITH_RSA_ENCRYPTION:
    case NSS_OID_PKCS1_MD5_WITH_RSA_ENCRYPTION:
    case NSS_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION:
    case NSS_OID_ISO_SHA_WITH_RSA_SIGNATURE:
    case NSS_OID_X500_RSA_ENCRYPTION:
	return NSSKeyPairType_RSA;
    case NSS_OID_ANSIX9_DSA_SIGNATURE:
    case NSS_OID_ANSIX9_DSA_SIGNATURE_WITH_SHA1_DIGEST:
	return NSSKeyPairType_DSA;
    case NSS_OID_X942_DIFFIE_HELLMAN_KEY:
	return NSSKeyPairType_DH;
    default:  
	return NSSKeyPairType_Unknown;
    }
}

NSS_IMPLEMENT NSSPrivateKey *
nssPrivateKey_Decode (
  NSSBER *ber,
  NSSOID *keyPairAlg,
  NSSOperations operations,
  NSSProperties properties,
  NSSUTF8 *passwordOpt,
  NSSCallback *uhhOpt,
  NSSToken *destination,
  NSSTrustDomain *td,
  NSSVolatileDomain *vdOpt
)
{
    PRStatus status;
    nssCryptokiObject *pbeKey = NULL;
    nssCryptokiObject *vkey = NULL;
    NSSAlgorithmAndParameters *wrapAP = NULL;
    NSSAlgorithmAndParameters *pbeAP = NULL;
    EPKI epki = { 0 };
    NSSItem *epkiData = NULL;
    NSSUTF8 *password = NULL;
    nssSession *session = NULL;
    NSSArena *tmparena;
    NSSPrivateKey *rvKey = NULL;
    NSSSlot *slot;
    NSSKeyPairType keyPairType;

    tmparena = nssArena_Create();
    if (!tmparena) {
	return (NSSPrivateKey *)NULL;
    }

    /* decode PKCS#8 formatted encoded key */
    status = nssASN1_DecodeBER(tmparena, &epki,
                               encrypted_private_key_info_tmpl, ber);
    if (status == PR_FAILURE) {
	goto cleanup;
    }
    pbeAP = nssAlgorithmAndParameters_Decode(NULL, &epki.encAlg);
    if (!pbeAP) {
	goto cleanup;
    }

    /* get the encryption password */
    if (passwordOpt) {
	password = passwordOpt;
    } else {
	NSSCallback *uhh;
	uhh = uhhOpt ? uhhOpt : nssTrustDomain_GetDefaultCallback(td, NULL);
	status = uhh->getPW(NULL, NULL, uhh->arg, &password);
	if (status == PR_FAILURE) {
	    goto cleanup;
	}
    }
    (void)nssAlgorithmAndParameters_SetPBEPassword(pbeAP, password);

    session = nssToken_CreateSession(destination, PR_TRUE);
    if (!session) {
	goto cleanup;
    }

    /* use the supplied PBE alg/param to create a wrapping key */
    pbeKey = nssToken_GenerateSymmetricKey(destination, session, pbeAP,
                                           0, NULL, PR_FALSE,
                                           NSSOperations_UNWRAP, 0);
    nss_ZFreeIf(password);
    if (!pbeKey) {
	goto cleanup;
    }

    /* convert the PBE alg/param to a corresponding encryption alg/param */
    wrapAP = nssAlgorithmAndParameters_ConvertPBEToCrypto(pbeAP, PR_TRUE);
    if (!wrapAP) {
	goto cleanup;
    }

    slot = nssToken_GetSlot(destination);
    status = nssSlot_Login(slot, 
                           nssTrustDomain_GetDefaultCallback(td, NULL));
    nssSlot_Destroy(slot);

    /* XXX */
    keyPairType = get_key_pair_type(keyPairAlg);

    /* unwrap the private key with the PBE key */
    vkey = nssToken_UnwrapPrivateKey(destination, session, wrapAP, 
                                     pbeKey, &epki.encData, !vdOpt, 
                                     operations, properties, 
                                     keyPairType);
    if (!vkey) {
	goto cleanup;
    }

    rvKey = nssPrivateKey_CreateFromInstance(vkey, td, vdOpt);

cleanup:
    if (session) {
	nssSession_Destroy(session);
    }
    if (pbeAP) {
	nssAlgorithmAndParameters_Destroy(pbeAP);
    }
    if (wrapAP) {
	nssAlgorithmAndParameters_Destroy(wrapAP);
    }
    if (pbeKey) {
	nssCryptokiObject_Destroy(pbeKey);
    }
    nssArena_Destroy(tmparena);
    return rvKey;
}

NSS_IMPLEMENT NSSVolatileDomain *
nssPrivateKey_GetVolatileDomain (
  NSSPrivateKey *vk,
  PRStatus *statusOpt
)
{
    return vk->object.vd;
}

NSS_IMPLEMENT NSSTrustDomain *
nssPrivateKey_GetTrustDomain (
  NSSPrivateKey *vk,
  PRStatus *statusOpt
)
{
    return vk->object.td;
}

NSS_IMPLEMENT NSSTrustDomain *
NSSPrivateKey_GetTrustDomain (
  NSSPrivateKey *vk,
  PRStatus *statusOpt
)
{
    return nssPrivateKey_GetTrustDomain(vk, statusOpt);
}

NSS_IMPLEMENT NSSToken *
NSSPrivateKey_GetToken (
  NSSPrivateKey *vk
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSSlot *
NSSPrivateKey_GetSlot (
  NSSPrivateKey *vk
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSModule *
NSSPrivateKey_GetModule (
  NSSPrivateKey *vk
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSItem *
NSSPrivateKey_Decrypt (
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
NSSPrivateKey_Sign (
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
NSSPrivateKey_SignRecover (
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
NSSPrivateKey_UnwrapSymmetricKey (
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
NSSPrivateKey_DeriveSymmetricKey (
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
nssPrivateKey_FindPublicKey (
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
NSSPrivateKey_FindPublicKey (
  NSSPrivateKey *vk
)
{
    return nssPrivateKey_FindPublicKey(vk);;
}

NSS_IMPLEMENT NSSCryptoContext *
NSSPrivateKey_CreateCryptoContext (
  NSSPrivateKey *vk,
  const NSSAlgorithmAndParameters *apOpt,
  NSSCallback *uhh
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCertificate **
nssPrivateKey_FindCertificates (
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
NSSPrivateKey_FindCertificates (
  NSSPrivateKey *vk,
  NSSCertificate **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    return nssPrivateKey_FindCertificates(vk, rvOpt, maximumOpt, arenaOpt);
}

NSS_IMPLEMENT NSSCertificate *
NSSPrivateKey_FindBestCertificate (
  NSSPrivateKey *vk,
  NSSTime time,
  NSSUsages *usagesOpt,
  NSSPolicies *policiesOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT void
nssPrivateKeyArray_Destroy (
  NSSPrivateKey **vkeys
)
{
    NSSPrivateKey **vk = vkeys;
    if (vkeys) {
	while (vk++) {
	    nssPrivateKey_Destroy(*vk);
	}
    }
    nss_ZFreeIf(vkeys);
}

struct NSSPublicKeyStr
{
  nssPKIObject object;
  NSSItem id;
#ifdef nodef
  NSSTime startDate;
  NSSTime endDate;
  PRUint32 flags;
  NSSDER subject;
#endif
  NSSPublicKeyInfo info;
};

NSS_IMPLEMENT NSSPublicKey *
nssPublicKey_Create (
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
                                                &rvKey->info,
                                                &rvKey->id);
    if (status != PR_SUCCESS) {
	nssPublicKey_Destroy(rvKey);
	return (NSSPublicKey *)NULL;
    }
    return rvKey;
}

NSS_IMPLEMENT NSSPublicKey *
nssPublicKey_CreateFromInstance (
  nssCryptokiObject *instance,
  NSSTrustDomain *td,
  NSSVolatileDomain *vdOpt,
  NSSArena *arenaOpt
)
{
    nssPKIObject *pkio;

    pkio = nssPKIObject_Create(arenaOpt, instance, td, vdOpt);
    if (pkio) {
	return nssPublicKey_Create(pkio);
    }
    return (NSSPublicKey *)NULL;
}

/* XXX same here */
const NSSASN1Template NSSASN1Template_RSAPublicKey[] = 
{
  { NSSASN1_SEQUENCE, 0, NULL, sizeof(NSSPublicKeyInfo)               },
  { NSSASN1_INTEGER, offsetof(NSSPublicKeyInfo, u.rsa.modulus)        },
  { NSSASN1_INTEGER, offsetof(NSSPublicKeyInfo, u.rsa.publicExponent) },
  { 0 }
};

NSS_IMPLEMENT NSSPublicKey *
nssPublicKey_CreateFromInfo (
  NSSTrustDomain *td,
  NSSVolatileDomain *vd,
  NSSOID *keyAlg,
  NSSBitString *keyBits
)
{
    PRStatus status;
    NSSArena *arena;
    nssCryptokiObject *bko = NULL;
    NSSPublicKeyInfo bki;
    NSSPublicKey *rvbk = NULL;
    NSSBER keyBER;
    NSSToken *token = NULL;
    nssSession *session = NULL;

    keyBER = *keyBits;
    NSSASN1_ConvertBitString(&keyBER);

    arena = nssArena_Create();
    if (!arena) {
	return (NSSPublicKey *)NULL;
    }

    switch (nssOID_GetTag(keyAlg)) {
    case NSS_OID_PKCS1_RSA_ENCRYPTION:
	status = nssASN1_DecodeBER(arena, &bki, 
	                           NSSASN1Template_RSAPublicKey, 
	                           &keyBER);
	bki.kind = NSSKeyPairType_RSA;
	break;
    default:
	PR_ASSERT(0); /* XXX under construction */
	return NULL;
    }
    if (status == PR_FAILURE) {
	goto loser;
    }

    token = nssTrustDomain_FindTokenForAlgorithm(td, keyAlg);
    if (!token) {
	goto loser;
    }

    session = nssToken_CreateSession(token, PR_FALSE);
    if (!session) {
	goto loser;
    }

    bko = nssToken_ImportPublicKey(token, session, &bki, PR_FALSE);
    if (bko) {
	rvbk = nssPublicKey_CreateFromInstance(bko, td, vd, arena);
	if (!rvbk) {
	    nssCryptokiObject_Destroy(bko);
	}
    }

    nssSession_Destroy(session);
    nssToken_Destroy(token);
    return rvbk;
loser:
    if (session) {
	nssSession_Destroy(session);
    }
    if (token) {
	nssToken_Destroy(token);
    }
    if (bko) {
	nssCryptokiObject_Destroy(bko);
    }
    nssArena_Destroy(arena);
    return (NSSPublicKey *)NULL;
}

NSS_IMPLEMENT NSSPublicKey *
nssPublicKey_AddRef (
  NSSPublicKey *bk
)
{
    if (bk) {
	(void)nssPKIObject_AddRef(&bk->object);
    }
    return bk;
}

NSS_IMPLEMENT PRStatus
nssPublicKey_Destroy (
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
NSSPublicKey_Destroy (
  NSSPublicKey *bk
)
{
    return nssPublicKey_Destroy(bk);
}

NSS_IMPLEMENT NSSItem *
nssPublicKey_GetID (
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
nssPublicKey_IsOnToken (
  NSSPublicKey *bk,
  NSSToken *token
)
{
    return nssPKIObject_IsOnToken(&bk->object, token);
}

NSS_IMPLEMENT nssCryptokiObject *
nssPublicKey_GetInstance (
  NSSPublicKey *bk,
  NSSToken *token
)
{
    return nssPKIObject_GetInstance(&bk->object, token);
}

NSS_IMPLEMENT nssCryptokiObject *
nssPublicKey_FindInstanceForAlgorithm (
  NSSPublicKey *bk,
  const NSSAlgorithmAndParameters *ap
)
{
    return nssPKIObject_FindInstanceForAlgorithm(&bk->object, ap);
}

NSS_IMPLEMENT PRStatus
nssPublicKey_DeleteStoredObject (
  NSSPublicKey *bk,
  NSSCallback *uhh
)
{
    return nssPKIObject_DeleteStoredObject(&bk->object, uhh, PR_FALSE);
}

NSS_IMPLEMENT PRStatus
NSSPublicKey_DeleteStoredObject (
  NSSPublicKey *bk,
  NSSCallback *uhh
)
{
    return nssPublicKey_DeleteStoredObject(bk, uhh);
}

NSS_IMPLEMENT nssCryptokiObject *
nssPublicKey_CopyToToken (
  NSSPublicKey *bk,
  NSSToken *destination,
  PRBool asPersistentObject
)
{
    nssSession *session;
    nssCryptokiObject *bko;

    session = nssToken_CreateSession(destination, asPersistentObject);
    if (!session) {
	return (nssCryptokiObject *)NULL;
    }
    bko = nssToken_ImportPublicKey(destination, session, 
                                   &bk->info, asPersistentObject);
    nssSession_Destroy(session);
    if (bko) {
	if (nssPKIObject_AddInstance(&bk->object, bko) == PR_FAILURE) {
	    nssCryptokiObject_Destroy(bko);
	    bko = NULL;
	}
    }
    return bko;
}

NSS_IMPLEMENT NSSItem *
NSSPublicKey_Encode (
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
nssPublicKey_GetTrustDomain (
  NSSPublicKey *bk,
  PRStatus *statusOpt
)
{
    return bk->object.td;
}

NSS_IMPLEMENT NSSTrustDomain *
NSSPublicKey_GetTrustDomain (
  NSSPublicKey *bk,
  PRStatus *statusOpt
)
{
    return nssPublicKey_GetTrustDomain(bk, statusOpt);
}

NSS_IMPLEMENT NSSToken *
NSSPublicKey_GetToken (
  NSSPublicKey *bk,
  PRStatus *statusOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSSlot *
NSSPublicKey_GetSlot (
  NSSPublicKey *bk,
  PRStatus *statusOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSModule *
NSSPublicKey_GetModule (
  NSSPublicKey *bk,
  PRStatus *statusOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSPublicKeyInfo *
nssPublicKey_GetInfo (
  NSSPublicKey *bk
)
{
    return &bk->info;
}

NSS_IMPLEMENT NSSPublicKeyInfo *
NSSPublicKey_GetInfo (
  NSSPublicKey *bk
)
{
    return nssPublicKey_GetInfo(bk);
}

NSS_IMPLEMENT NSSItem *
NSSPublicKey_Encrypt (
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
nssPublicKey_Verify (
  NSSPublicKey *bk,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *data,
  NSSItem *signature,
  NSSCallback *uhh
)
{
    PRStatus status;
    nssSession *session;
    nssCryptokiObject **op, **objects;

    /* XXX in cipher order */
    objects = nssPKIObject_GetInstances(&bk->object);
    for (op = objects; *op; op++) {
	session = nssToken_CreateSession((*op)->token, PR_FALSE);
	if (!session) {
	    break;
	}
	status = nssToken_Verify((*op)->token, session, apOpt, *op,
	                         data, signature);
	nssSession_Destroy(session);
	/* XXX */
	break;
	/* XXX this logic needs to be rethunk */
    }
    nssCryptokiObjectArray_Destroy(objects);
    return status;
}

NSS_IMPLEMENT PRStatus
NSSPublicKey_Verify (
  NSSPublicKey *bk,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *data,
  NSSItem *signature,
  NSSCallback *uhh
)
{
    return nssPublicKey_Verify(bk, apOpt, data, signature, uhh);
}

NSS_IMPLEMENT NSSItem *
NSSPublicKey_VerifyRecover (
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

/* XXX this is kinda hacky, with the use of void * and a cast, but
 *     the idea is to prefer moving the public key to another token
 *     when necessary, by choosing among the target object's instances
 */
static nssCryptokiObject *
nssPublicKey_GetInstanceForAlgorithmAndObject (
  NSSPublicKey *bk,
  const NSSAlgorithmAndParameters *ap,
  void *ob,
  nssCryptokiObject **targetInstance
)
{
    PRStatus status;
    NSSToken **tokens, **tp;
    NSSToken *candidate = NULL;
    nssCryptokiObject *instance = NULL;

    /* look on the target object's tokens */
    tokens = nssPKIObject_GetTokens((nssPKIObject *)ob, &status);
    if (tokens) {
	for (tp = tokens; *tp; tp++) {
	    if (nssToken_DoesAlgorithm(*tp, ap)) {
		/* found one for the algorithm */
		instance = nssPublicKey_GetInstance(bk, *tp);
		if (instance) {
		    /* and the public key is there as well, done */
		    break;
		} else if (!candidate) {
		    /* remember this token, since it can do the math */
		    candidate = *tp;
		}
	    }
	}
	if (!instance && candidate) {
	    /* didn't find a token with both objects, but did find
	     * one that can do the operation
	     */
	     instance = nssPublicKey_CopyToToken(bk, candidate, PR_FALSE);
	}
	nssTokenArray_Destroy(tokens);
    }
    if (instance) {
	*targetInstance = nssPKIObject_GetInstance((nssPKIObject *)ob,
	                                           instance->token);
    }
    return instance;
}

NSS_IMPLEMENT NSSItem *
nssPublicKey_WrapSymmetricKey (
  NSSPublicKey *bk,
  const NSSAlgorithmAndParameters *ap,
  NSSSymmetricKey *keyToWrap,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nssCryptokiObject *bko, *mko;
    NSSItem *rvIt = NULL;

    bko = nssPublicKey_GetInstanceForAlgorithmAndObject(bk, ap, 
                                                        keyToWrap, &mko);
    if (!bko) {
	return (NSSItem *)NULL;
    }

    rvIt = nssToken_WrapKey(bko->token, bko->session, ap, 
                            bko, mko, rvOpt, arenaOpt);
    return rvIt;
}

NSS_IMPLEMENT NSSItem *
NSSPublicKey_WrapSymmetricKey (
  NSSPublicKey *bk,
  const NSSAlgorithmAndParameters *ap,
  NSSSymmetricKey *keyToWrap,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssPublicKey_WrapSymmetricKey(bk, ap, keyToWrap,
                                         uhh, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSCryptoContext *
NSSPublicKey_CreateCryptoContext (
  NSSPublicKey *bk,
  const NSSAlgorithmAndParameters *apOpt,
  NSSCallback *uhh
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCertificate **
nssPublicKey_FindCertificates (
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
NSSPublicKey_FindCertificates (
  NSSPublicKey *bk,
  NSSCertificate **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    return nssPublicKey_FindCertificates(bk, rvOpt, maximumOpt, arenaOpt);
}

NSS_IMPLEMENT NSSCertificate *
nssPublicKey_FindBestCertificate (
  NSSPublicKey *bk,
  NSSTime time,
  NSSUsages *usageOpt,
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
NSSPublicKey_FindBestCertificate (
  NSSPublicKey *bk,
  NSSTime time,
  NSSUsages *usageOpt,
  NSSPolicies *policiesOpt
)
{
    return nssPublicKey_FindBestCertificate(bk, time, 
                                            usageOpt, policiesOpt);
}

NSS_IMPLEMENT NSSPrivateKey *
NSSPublicKey_FindPrivateKey (
  NSSPublicKey *bk,
  NSSCallback *uhh
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT void
nssPublicKeyArray_Destroy (
  NSSPublicKey **bkeys
)
{
    NSSPublicKey **bk = bkeys;
    if (bkeys) {
	while (bk++) {
	    nssPublicKey_Destroy(*bk);
	}
    }
    nss_ZFreeIf(bkeys);
}

