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
nssPrivateKey_CreateFromInstance (
  nssCryptokiObject *instance,
  NSSTrustDomain *td,
  NSSVolatileDomain *vdOpt
)
{
    PRStatus status;
    nssPKIObject *pkio;
    NSSPrivateKey *rvKey = NULL;
    nssPKIObjectTable *objectTable = nssTrustDomain_GetObjectTable(td);

    rvKey = nssPKIObject_CREATE(td, instance, NSSPrivateKey);
    if (!rvKey) {
	goto loser;
    }
    pkio = &rvKey->object;
    status = nssCryptokiPrivateKey_GetAttributes(instance, pkio->arena,
                                                 &rvKey->kind,
                                                 &rvKey->id);
    if (status != PR_SUCCESS) {
	goto loser;
    }
    pkio->objectType = pkiObjectType_PrivateKey;
    pkio->numIDs = 1;
    pkio->uid[0] = &rvKey->id;
    rvKey = (NSSPrivateKey *)nssPKIObjectTable_Add(objectTable, pkio);
    if (!rvKey) {
	rvKey = (NSSPrivateKey *)pkio;
	goto loser;
    } else if ((nssPKIObject *)rvKey != pkio) {
	nssPrivateKey_Destroy((NSSPrivateKey *)pkio);
    }
    if (rvKey && vdOpt) {
	status = nssVolatileDomain_ImportPrivateKey(vdOpt, rvKey);
	if (status == PR_FAILURE) {
	    nssPrivateKey_Destroy(rvKey);
	    rvKey = NULL;
	}
    }
    return rvKey;
loser:
    nssPrivateKey_Destroy(rvKey);
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
nssPrivateKey_HasInstanceOnToken (
  NSSPrivateKey *vk,
  NSSToken *token
)
{
    return nssPKIObject_HasInstanceOnToken(&vk->object, token);
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
  const NSSAlgNParam *ap
)
{
    return nssPKIObject_FindInstanceForAlgorithm(&vk->object, ap);
}

NSS_IMPLEMENT PRStatus
nssPrivateKey_RemoveInstanceForToken (
  NSSPrivateKey *vk,
  NSSToken *token
)
{
    return nssPKIObject_RemoveInstanceForToken(&vk->object, token);
}

NSS_IMPLEMENT PRIntn
nssPrivateKey_CountInstances (
  NSSPrivateKey *vk
)
{
    return nssPKIObject_CountInstances(&vk->object);
}

NSS_IMPLEMENT void
nssPrivateKey_SetVolatileDomain (
  NSSPrivateKey *vk,
  NSSVolatileDomain *vd
)
{
    vk->object.vd = vd; /* volatile domain holds ref */
}

NSS_IMPLEMENT PRStatus
NSSPrivateKey_DeleteStoredObject (
  NSSPrivateKey *vk,
  NSSCallback *uhh
)
{
    return nssPKIObject_DeleteStoredObject(&vk->object, uhh, PR_FALSE);
}

NSS_IMPLEMENT NSSKeyPairType
nssPrivateKey_GetKeyType (
  NSSPrivateKey *vk
)
{
    return vk->kind;
}

NSS_IMPLEMENT NSSKeyPairType
NSSPrivateKey_GetKeyType (
  NSSPrivateKey *vk
)
{
    return nssPrivateKey_GetKeyType(vk);
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
nssPrivateKey_GetPrivateModulusLength (
  NSSPrivateKey *vk
)
{
    /* XXX based on PK11_GetPrivateModulusLen, always only for RSA?
     *     maybe GetKeyStrength?
     */
    switch (vk->kind) {
    case NSSKeyPairType_RSA:
	    /* XXX cheating by using first instance */
	return nssCryptokiRSAKey_GetModulusLength(vk->object.instances[0]);
    default:
	return -1;
    }
}

NSS_IMPLEMENT PRUint32
NSSPrivateKey_GetPrivateModulusLength (
  NSSPrivateKey *vk
)
{
    return nssPrivateKey_GetPrivateModulusLength(vk);
}

NSS_IMPLEMENT PRUint32
nssPrivateKey_GetSignatureLength (
  NSSPrivateKey *vk
)
{
    /* XXX based on PK11_SignatureLen */
    switch (vk->kind) {
    case NSSKeyPairType_RSA:
	/* old function had fallback for non-compliant tokens, still needed? */
	return nssPrivateKey_GetPrivateModulusLength(vk);
    case NSSKeyPairType_DSA:
	return 40;
    default:
	return 0;
    }
}

NSS_IMPLEMENT PRUint32
NSSPrivateKey_GetSignatureLength (
  NSSPrivateKey *vk
)
{
    return nssPrivateKey_GetSignatureLength(vk);
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
  NSSAlgNParam *ap,
  NSSUTF8 *passwordOpt,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    PRStatus status;
    nssCryptokiObject *pbeKey;
    nssCryptokiObject *vkey;
    NSSAlgNParam *wrapAP;
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
    (void)nssAlgNParam_SetPBEPassword(ap, password);

    vkey = nssPrivateKey_FindInstanceForAlgorithm(vk, ap);
    if (!vkey) {
	/* XXX defer to trust domain? */
	nss_ZFreeIf(password);
	return (NSSItem *)NULL;
    }

    /* XXX use GenByPassword!!! */
    /* use the supplied PBE alg/param to create a wrapping key */
    pbeKey = nssToken_GenerateSymKey(vkey->token, vkey->session, ap,
                                           0, NULL, PR_FALSE,
                                           NSSOperations_WRAP, 0);
    nss_ZFreeIf(password);
    if (!pbeKey) {
	return (NSSItem *)NULL;
    }

    /* convert the PBE alg/param to a corresponding encryption alg/param */
    wrapAP = nssAlgNParam_ConvertPBEToCrypto(ap, PR_TRUE);
    if (!wrapAP) {
	return (NSSItem *)NULL;
    }

    /* wrap the private key with the PBE key */
    wrap = nssToken_WrapKey(vkey->token, vkey->session, wrapAP, 
                            pbeKey, vkey, 
                            rvOpt, arenaOpt);
    nssAlgNParam_Destroy(wrapAP);
    nssCryptokiObject_Destroy(pbeKey);
    nssCryptokiObject_Destroy(vkey);
    if (!wrap) {
	return (NSSItem *)NULL;
    }

    /* encode result in PKCS#8 format */
    pbeAlgBER = nssAlgNParam_Encode(ap, &epki.encAlg, arenaOpt);
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
  NSSAlgNParam *ap,
  NSSUTF8 *passwordOpt,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssPrivateKey_Encode(vk, ap, passwordOpt, uhhOpt, 
                                rvOpt, arenaOpt);
}

#if 0
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
#endif

NSS_IMPLEMENT NSSPrivateKey *
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
)
{
    PRStatus status;
    nssCryptokiObject *pbeKey = NULL;
    nssCryptokiObject *vkey = NULL;
    NSSAlgNParam *wrapAP = NULL;
    NSSAlgNParam *pbeAP = NULL;
    EPKI epki;
    NSSUTF8 *password = NULL;
    nssSession *session = NULL;
    NSSArena *tmparena;
    NSSPrivateKey *rvKey = NULL;
    NSSSlot *slot;

    tmparena = nssArena_Create();
    if (!tmparena) {
	return (NSSPrivateKey *)NULL;
    }

    nsslibc_memset(&epki, 0, sizeof(EPKI));

    /* decode PKCS#8 formatted encoded key */
    status = nssASN1_DecodeBER(tmparena, &epki,
                               encrypted_private_key_info_tmpl, ber);
    if (status == PR_FAILURE) {
	goto cleanup;
    }
    pbeAP = nssAlgNParam_Decode(NULL, &epki.encAlg);
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
    (void)nssAlgNParam_SetPBEPassword(pbeAP, password);

    session = nssToken_CreateSession(destination, PR_TRUE);
    if (!session) {
	goto cleanup;
    }

    /* use the supplied PBE alg/param to create a wrapping key */
    pbeKey = nssToken_GenerateSymKey(destination, session, pbeAP,
                                           0, NULL, PR_FALSE,
                                           NSSOperations_UNWRAP, 0);
    nss_ZFreeIf(password);
    if (!pbeKey) {
	goto cleanup;
    }

    /* convert the PBE alg/param to a corresponding encryption alg/param */
    wrapAP = nssAlgNParam_ConvertPBEToCrypto(pbeAP, PR_TRUE);
    if (!wrapAP) {
	goto cleanup;
    }

    slot = nssToken_GetSlot(destination);
    status = nssSlot_Login(slot, 
                           nssTrustDomain_GetDefaultCallback(td, NULL));
    nssSlot_Destroy(slot);

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
	nssAlgNParam_Destroy(pbeAP);
    }
    if (wrapAP) {
	nssAlgNParam_Destroy(wrapAP);
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
    return nssPKIObject_GetVolatileDomain(&vk->object, statusOpt);
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

NSS_IMPLEMENT NSSToken **
nssPrivateKey_GetTokens (
  NSSPrivateKey *vk,
  NSSToken **rvTokensOpt,
  PRUint32 rvMaxOpt,
  PRStatus *statusOpt
)
{
    return nssPKIObject_GetTokens(&vk->object, 
                                  rvTokensOpt, rvMaxOpt, statusOpt);
}

NSS_IMPLEMENT NSSToken **
NSSPrivateKey_GetTokens (
  NSSPrivateKey *vk,
  NSSToken **rvTokensOpt,
  PRUint32 rvMaxOpt,
  PRStatus *statusOpt
)
{
    return nssPrivateKey_GetTokens(vk, rvTokensOpt, rvMaxOpt, statusOpt);
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
nssPrivateKey_Decrypt (
  NSSPrivateKey *vk,
  const NSSAlgNParam *apOpt,
  NSSItem *encryptedData,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nssCryptokiObject *vko;
    NSSAlgNParam *ap;
    NSSItem *rvIt = NULL;

    if (apOpt) {
	ap = (NSSAlgNParam *)apOpt;
    } else {
	NSSOIDTag alg;
	/* XXX are these defaults reasonable? */
	switch (vk->kind) {
	case NSSKeyPairType_RSA: alg = NSS_OID_X500_RSA_ENCRYPTION; break;
	default:
	    /* set invalid arg err */
	    return (NSSItem *)NULL;
	}
	ap = nssOIDTag_CreateAlgNParam(alg, NULL, NULL);
	if (!ap) {
	    return (NSSItem *)NULL;
	}
    }

    vko = nssPrivateKey_FindInstanceForAlgorithm(vk, ap);
    if (!vko) {
	if (!apOpt) nssAlgNParam_Destroy(ap);
	return (NSSItem *)NULL;
    }

    rvIt = nssToken_Decrypt(vko->token, vko->session, ap, vko,
                            encryptedData, rvOpt, arenaOpt);

    if (!apOpt) nssAlgNParam_Destroy(ap);
    nssCryptokiObject_Destroy(vko);

    return rvIt;
}

NSS_IMPLEMENT NSSItem *
NSSPrivateKey_Decrypt (
  NSSPrivateKey *vk,
  const NSSAlgNParam *apOpt,
  NSSItem *encryptedData,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssPrivateKey_Decrypt(vk, apOpt, encryptedData, 
                                 uhh, rvOpt, arenaOpt);
}

/* XXX in 3.x, only CKM_RSA_PKCS and CKM_DSA sigs were done */
/* XXX do we ever want raw DSA sigs?  or always DER-encoded? */
NSS_IMPLEMENT NSSItem *
nssPrivateKey_Sign (
  NSSPrivateKey *vk,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nssCryptokiObject *vko;
    NSSAlgNParam *ap;
    NSSItem *rvIt;

    if (apOpt) {
	ap = (NSSAlgNParam *)apOpt; /* XXX hmmmm.... */
    } else {
	NSSOIDTag alg;
	/* XXX are these defaults reasonable? */
	switch (vk->kind) {
	case NSSKeyPairType_RSA: alg = NSS_OID_PKCS1_RSA_ENCRYPTION; break;
	default:
	    /* set invalid arg err */
	    return (NSSItem *)NULL;
	}
	ap = nssOIDTag_CreateAlgNParam(alg, NULL, NULL);
	if (!ap) {
	    return (NSSItem *)NULL;
	}
    }

    vko = nssPrivateKey_FindInstanceForAlgorithm(vk, ap);
    if (!vko) {
	if (!apOpt) nssAlgNParam_Destroy(ap);
	return NULL;
    }
    rvIt = nssToken_Sign(vko->token, vko->session, ap, vko,
                         data, rvOpt, arenaOpt);
    nssCryptokiObject_Destroy(vko);
    if (!apOpt) nssAlgNParam_Destroy(ap);
    return rvIt;
}

NSS_IMPLEMENT NSSItem *
NSSPrivateKey_Sign (
  NSSPrivateKey *vk,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssPrivateKey_Sign(vk, apOpt, data, uhh, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
NSSPrivateKey_SignRecover (
  NSSPrivateKey *vk,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSSymKey *
nssPrivateKey_UnwrapSymKey (
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
)
{
    if (vdOpt) {
	    /* XXX destinationOpt */
	return nssVolatileDomain_UnwrapSymKey(vdOpt, apOpt, vk, wrappedKey,
	                                      targetType, /* labelOpt, */
	                                      NULL, operations, properties);
    } else {
	PR_ASSERT(1);
	return NULL;
    }
}

NSS_IMPLEMENT NSSSymKey *
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
)
{
    return nssPrivateKey_UnwrapSymKey(vk, apOpt, wrappedKey, targetType,
                                      labelOpt, operations, properties,
                                      destinationOpt, vdOpt, uhhOpt);
}

NSS_IMPLEMENT NSSSymKey *
NSSPrivateKey_DeriveSymKey (
  NSSPrivateKey *vk,
  NSSPublicKey *bk,
  const NSSAlgNParam *apOpt,
  NSSSymKeyType targetSymKeyType,
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
    NSSTrustDomain *td = nssPrivateKey_GetTrustDomain(vk, NULL);
    return nssTrustDomain_FindPublicKeyByID(td, &vk->id);
}

NSS_IMPLEMENT NSSPublicKey *
NSSPrivateKey_FindPublicKey (
  NSSPrivateKey *vk
)
{
    return nssPrivateKey_FindPublicKey(vk);;
}

NSS_IMPLEMENT NSSCert **
nssPrivateKey_FindCerts (
  NSSPrivateKey *vk,
  NSSCert **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    NSSTrustDomain *td = nssPrivateKey_GetTrustDomain(vk, NULL);
    return nssTrustDomain_FindCertsByID(td, &vk->id, 
                                        rvOpt, maximumOpt, arenaOpt);
}

NSS_IMPLEMENT NSSCert **
NSSPrivateKey_FindCerts (
  NSSPrivateKey *vk,
  NSSCert **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    return nssPrivateKey_FindCerts(vk, rvOpt, maximumOpt, arenaOpt);
}

NSS_IMPLEMENT NSSCert *
NSSPrivateKey_FindBestCert (
  NSSPrivateKey *vk,
  NSSTime time,
  NSSUsages *usagesOpt,
  NSSPolicies *policiesOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCryptoContext *
nssPrivateKey_CreateCryptoContext (
  NSSPrivateKey *vk,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhh
)
{
    NSSCryptoContext *cc;
    cc = nssCryptoContext_CreateForPrivateKey(vk, apOpt, uhh);
    return cc;
}

NSS_IMPLEMENT NSSCryptoContext *
NSSPrivateKey_CreateCryptoContext (
  NSSPrivateKey *vk,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhh
)
{
    return nssPrivateKey_CreateCryptoContext(vk, apOpt, uhh);
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
nssPublicKey_CreateFromInstance (
  nssCryptokiObject *instance,
  NSSTrustDomain *td,
  NSSVolatileDomain *vdOpt
)
{
    PRStatus status;
    nssPKIObject *pkio;
    NSSPublicKey *rvKey = NULL;
    nssPKIObjectTable *objectTable = nssTrustDomain_GetObjectTable(td);

    rvKey = nssPKIObject_CREATE(td, instance, NSSPublicKey);
    if (!rvKey) {
	goto loser;
    }
    pkio = &rvKey->object;
    status = nssCryptokiPublicKey_GetAttributes(instance, pkio->arena,
                                                &rvKey->info,
                                                &rvKey->id);
    if (status != PR_SUCCESS) {
	goto loser;
    }
    pkio->objectType = pkiObjectType_PublicKey;
    pkio->numIDs = 1;
    pkio->uid[0] = &rvKey->id;
    rvKey = (NSSPublicKey *)nssPKIObjectTable_Add(objectTable, pkio);
    if (!rvKey) {
	rvKey = (NSSPublicKey *)pkio;
	goto loser;
    } else if ((nssPKIObject *)rvKey != pkio) {
	nssPublicKey_Destroy((NSSPublicKey *)pkio);
    }
    if (rvKey && vdOpt) {
	status = nssVolatileDomain_ImportPublicKey(vdOpt, rvKey);
	if (status == PR_FAILURE) {
	    nssPublicKey_Destroy(rvKey);
	    rvKey = NULL;
	}
    }
    return rvKey;
loser:
    nssPublicKey_Destroy(rvKey);
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
  NSSOIDTag keyAlg,
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

    switch (keyAlg) {
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
	rvbk = nssPublicKey_CreateFromInstance(bko, td, vd);
	if (!rvbk) {
	    nssCryptokiObject_Destroy(bko);
	}
    }

    /* XXX leak arena */
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
nssPublicKey_HasInstanceOnToken (
  NSSPublicKey *bk,
  NSSToken *token
)
{
    return nssPKIObject_HasInstanceOnToken(&bk->object, token);
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
  const NSSAlgNParam *ap
)
{
    return nssPKIObject_FindInstanceForAlgorithm(&bk->object, ap);
}

NSS_IMPLEMENT PRStatus
nssPublicKey_RemoveInstanceForToken (
  NSSPublicKey *bk,
  NSSToken *token
)
{
    return nssPKIObject_RemoveInstanceForToken(&bk->object, token);
}

NSS_IMPLEMENT PRIntn
nssPublicKey_CountInstances (
  NSSPublicKey *bk
)
{
    return nssPKIObject_CountInstances(&bk->object);
}

NSS_IMPLEMENT void
nssPublicKey_SetVolatileDomain (
  NSSPublicKey *bk,
  NSSVolatileDomain *vd
)
{
    bk->object.vd = vd; /* volatile domain holds ref */
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
	} else {
	    /* XXX maybe AddInstance should rethink not cloning */
	    bko = nssCryptokiObject_Clone(bko);
	}
    }
    return bko;
}

NSS_IMPLEMENT NSSItem *
NSSPublicKey_Encode (
  NSSPublicKey *bk,
  const NSSAlgNParam *ap,
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
nssPublicKey_GetKeyInfo (
  NSSPublicKey *bk,
  NSSPublicKeyInfo *rvOpt
)
{
    if (rvOpt) {
	*rvOpt = bk->info;
	return rvOpt;
    } else {
	return &bk->info;
    }
}

NSS_IMPLEMENT NSSPublicKeyInfo *
NSSPublicKey_GetKeyInfo (
  NSSPublicKey *bk,
  NSSPublicKeyInfo *rvOpt
)
{
    return nssPublicKey_GetKeyInfo(bk, rvOpt);
}

NSS_IMPLEMENT NSSKeyPairType
nssPublicKey_GetKeyType (
  NSSPublicKey *bk
)
{
    return bk->info.kind;
}

NSS_IMPLEMENT NSSKeyPairType
NSSPublicKey_GetKeyType (
  NSSPublicKey *bk
)
{
    return nssPublicKey_GetKeyType(bk);
}

NSS_IMPLEMENT PRUint32
nssPublicKey_GetKeyStrength (
  NSSPublicKey *bk
)
{
    switch (bk->info.kind) {
    case NSSKeyPairType_RSA:
	    /* XXX cheating by using first instance */
	return nssCryptokiRSAKey_GetModulusLength(bk->object.instances[0]);
    default:
	return -1;
    }
}

NSS_IMPLEMENT PRUint32
NSSPublicKey_GetKeyStrength (
  NSSPublicKey *bk
)
{
    return nssPublicKey_GetKeyStrength(bk);
}

NSS_IMPLEMENT NSSItem *
nssPublicKey_Encrypt (
  NSSPublicKey *bk,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nssCryptokiObject *bko;
    NSSAlgNParam *ap;
    NSSItem *rvIt = NULL;

    if (apOpt) {
	ap = (NSSAlgNParam *)apOpt; /* XXX hmmmm.... */
    } else {
	NSSOIDTag alg;
	/* XXX are these defaults reasonable? */
	switch (bk->info.kind) {
	case NSSKeyPairType_RSA: alg = NSS_OID_X500_RSA_ENCRYPTION; break;
	default:
	    /* set invalid arg err */
	    return (NSSItem *)NULL;
	}
	ap = nssOIDTag_CreateAlgNParam(alg, NULL, NULL);
	if (!ap) {
	    return (NSSItem *)NULL;
	}
    }

    bko = nssPublicKey_FindInstanceForAlgorithm(bk, ap);
    if (!bko) {
	if (!apOpt) nssAlgNParam_Destroy(ap);
	return (NSSItem *)NULL;
    }

    rvIt = nssToken_Encrypt(bko->token, bko->session, ap, bko,
                            data, rvOpt, arenaOpt);

    if (!apOpt) nssAlgNParam_Destroy(ap);
    nssCryptokiObject_Destroy(bko);

    return rvIt;
}

NSS_IMPLEMENT NSSItem *
NSSPublicKey_Encrypt (
  NSSPublicKey *bk,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssPublicKey_Encrypt(bk, apOpt, data, uhh, rvOpt, arenaOpt);
}

NSS_IMPLEMENT PRStatus
nssPublicKey_Verify (
  NSSPublicKey *bk,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSItem *signature,
  NSSCallback *uhh
)
{
    PRStatus status;
    nssSession *session;
    nssCryptokiObject **op, **objects;
    NSSAlgNParam *ap;

    if (apOpt) {
	ap = (NSSAlgNParam *)apOpt; /* XXX hmmmm.... */
    } else {
	NSSOIDTag alg;
	/* XXX are these defaults reasonable? */
	switch (bk->info.kind) {
	case NSSKeyPairType_RSA: alg = NSS_OID_PKCS1_RSA_ENCRYPTION; break;
	default:
	    /* set invalid arg err */
	    return PR_FAILURE;
	}
	ap = nssOIDTag_CreateAlgNParam(alg, NULL, NULL);
	if (!ap) {
	    return PR_FAILURE;
	}
    }

    /* XXX in cipher order */
    objects = nssPKIObject_GetInstances(&bk->object);
    for (op = objects; *op; op++) {
	session = nssToken_CreateSession((*op)->token, PR_FALSE);
	if (!session) {
	    break;
	}
	status = nssToken_Verify((*op)->token, session, ap, *op,
	                         data, signature);
	nssSession_Destroy(session);
	/* XXX */
	break;
	/* XXX this logic needs to be rethunk */
    }
    nssCryptokiObjectArray_Destroy(objects);
    if (!apOpt) nssAlgNParam_Destroy(ap);
    return status;
}

NSS_IMPLEMENT PRStatus
NSSPublicKey_Verify (
  NSSPublicKey *bk,
  const NSSAlgNParam *apOpt,
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
  const NSSAlgNParam *apOpt,
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
  const NSSAlgNParam *ap,
  void *ob,
  nssCryptokiObject **targetInstance
)
{
    PRStatus status;
    NSSToken **tokens, **tp;
    NSSToken *candidate = NULL;
    nssCryptokiObject *instance = NULL;

    /* look on the target object's tokens */
    tokens = nssPKIObject_GetTokens((nssPKIObject *)ob, NULL, 0, &status);
    if (tokens) {
	for (tp = tokens; *tp; tp++) {
	    if (nssToken_DoesAlgNParam(*tp, ap)) {
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
nssPublicKey_WrapSymKey (
  NSSPublicKey *bk,
  const NSSAlgNParam *ap,
  NSSSymKey *keyToWrap,
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

    nssCryptokiObject_Destroy(bko);
    nssCryptokiObject_Destroy(mko);
    return rvIt;
}

NSS_IMPLEMENT NSSItem *
NSSPublicKey_WrapSymKey (
  NSSPublicKey *bk,
  const NSSAlgNParam *ap,
  NSSSymKey *keyToWrap,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssPublicKey_WrapSymKey(bk, ap, keyToWrap, uhh, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSCryptoContext *
NSSPublicKey_CreateCryptoContext (
  NSSPublicKey *bk,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhh
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCert **
nssPublicKey_FindCerts (
  NSSPublicKey *bk,
  NSSCert **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    NSSTrustDomain *td = nssPublicKey_GetTrustDomain(bk, NULL);
    return nssTrustDomain_FindCertsByID(td, &bk->id, 
                                        rvOpt, maximumOpt, arenaOpt);
}

NSS_IMPLEMENT NSSCert **
NSSPublicKey_FindCerts (
  NSSPublicKey *bk,
  NSSCert **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    return nssPublicKey_FindCerts(bk, rvOpt, maximumOpt, arenaOpt);
}

NSS_IMPLEMENT NSSCert *
nssPublicKey_FindBestCert (
  NSSPublicKey *bk,
  NSSTime time,
  NSSUsages *usageOpt,
  NSSPolicies *policiesOpt
)
{
    NSSCert *rvCert = NULL;
    NSSCert **certs;

    certs = nssPublicKey_FindCerts(bk, NULL, 0, NULL);
    if (!certs) {
	return (NSSCert *)NULL;
    }
    rvCert = nssCertArray_FindBestCert(certs, time, 
                                                     usageOpt, policiesOpt);
    nssCertArray_Destroy(certs);
    return rvCert;
}

NSS_IMPLEMENT NSSCert *
NSSPublicKey_FindBestCert (
  NSSPublicKey *bk,
  NSSTime time,
  NSSUsages *usageOpt,
  NSSPolicies *policiesOpt
)
{
    return nssPublicKey_FindBestCert(bk, time, 
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

