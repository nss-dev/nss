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

#ifndef DEVM_H
#include "devm.h"
#endif /* DEVM_H */

#ifndef CKHELPER_H
#include "ckhelper.h"
#endif /* CKHELPER_H */

#ifndef ASN1_H
#include "asn1.h"
#endif /* ASN1_H */

/*
 * NSSAlgorithmAndParametersStr
 *
 * This generic container should hold everything we need to know
 * to use an algorithm, with the specific exclusion of keysizes when 
 * doing key generation (this is specified in the API, thus the same
 * AlgorithmAndParameters can be reused to generate keys of different
 * length).
 *
 * Internally, we need to communicate the following information to
 * Cryptoki:
 *
 * 1) a CK_MECHANISM
 * 2) template values for key generation and derivation
 *
 * The CK_MECHANISM is always set when the AlgorithmAndParameters is
 * created.  The template values are set upon request, and are extracted
 * from the the params field.
 *
 * Once an AlgorithmAndParamters is created, it is considered read-only.
 * Thus is it used as 'const' throughout the API.
 *
 * An AlgorithmAndParameters can be created the following ways:
 *
 * 1) from an { NSSAlgorithmType, NSSParameters } pair (generic crypto),
 * 2) from an { NSSKeyPairType, NSSParameters } pair (key pair generation),
 * 3) from an { NSSSymmetricKeyType, NSSParameters } pair (symkey gen),
 * 4) from an { CK_MECHANISM_TYPE, NSSParameters } pair
 *     --- this is a 'friendly' method used to convert OID's to Alg&Params
 */
struct NSSAlgorithmAndParametersStr
{
  NSSArena *arena;
  CK_MECHANISM mechanism; /* alg&param in cryptoki terms */
  NSSParameters params;   /* template values kept here */

  /* every happy algorithm sets a mechanism the same way, but each
   * unhappy one sets a template a different way.
   */
  PRIntn (* set_template)(const NSSAlgorithmAndParameters *ap,
                          CK_ATTRIBUTE_PTR aTemplate,
                          CK_ULONG templateSize);
};

/*
 * For each algorithm that requires a parameter, the following methods
 * may exist (depending on what kind of parameters it requires):
 *
 * set_xxx_mechanism -- convert an NSSParameters to a CK_MECHANISM
 *                      for algorithm xxx
 * xxx_settor -- callback function to set template values for xxx
 * decode_xxx -- decode an octet string into parameters for
 *               algorithm xxx (used when creating from OID's)
 */

/* For all mechanisms where the only parameter is an IV */
static PRStatus
set_iv_parameter
(
  CK_MECHANISM_PTR mechPtr,
  NSSItem *iv,
  NSSArena *arena
)
{
    mechPtr->pParameter = nss_ZAlloc(arena, iv->size);
    if (!mechPtr->pParameter) {
	return PR_FAILURE;
    }
    nsslibc_memcpy(mechPtr->pParameter, iv->data, iv->size);
    mechPtr->ulParameterLen = iv->size;
    return PR_SUCCESS;
}

/* For all mechanisms where the only parameter is a length in bits */
static PRStatus
set_bits_parameter
(
  CK_MECHANISM_PTR mechPtr,
  PRUint32 numBits,
  NSSArena *arena
)
{
    CK_ULONG ulBits = numBits;
    PRUint32 pLen = sizeof(CK_ULONG);
    mechPtr->pParameter = nss_ZAlloc(arena, pLen);
    if (!mechPtr->pParameter) {
	return PR_FAILURE;
    }
    nsslibc_memcpy(mechPtr->pParameter, &ulBits, pLen);
    mechPtr->ulParameterLen = pLen;
    return PR_SUCCESS;
}

/* For all mechanisms that don't need to set template values (default) */
static PRIntn
null_settor (
  const NSSAlgorithmAndParameters *ap,
  CK_ATTRIBUTE_PTR aTemplate,
  CK_ULONG templateSize
)
{
    return 0;
}

/*
 * Decoding IV parameters
 */

static PRStatus
decode_iv(NSSAlgorithmAndParameters *ap, const NSSItem *params)
{
    PRStatus status;
    NSSItem iv;

    status = nssASN1_DecodeBER(ap->arena, &iv, 
                               nssASN1Template_OctetString, params);
    if (status == PR_SUCCESS) {
	ap->mechanism.pParameter = iv.data;
	ap->mechanism.ulParameterLen = iv.size;
    }
    return status;
}

/*
 * RSA key generation
 */

/* set template parameters for RSA key generation */
static PRIntn
rsa_keygen_settor (
  const NSSAlgorithmAndParameters *ap,
  CK_ATTRIBUTE_PTR aTemplate,
  CK_ULONG templateSize
)
{
    PRUint32 rsape;
    CK_ATTRIBUTE_PTR attr = aTemplate;
    /* N */
    NSS_CK_SET_ATTRIBUTE_VAR(attr, CKA_MODULUS_BITS,
                             ap->params.rsakg.modulusBits);
    /* e */
    rsape = PR_htonl(ap->params.rsakg.publicExponent);
    attr->type = CKA_PUBLIC_EXPONENT; 
    attr->pValue = (CK_BYTE_PTR)rsape;
    attr->ulValueLen = sizeof(rsape);
    attr++;
    return attr - aTemplate;
}

/* 
 * RSA cipher
 */
static PRStatus
set_rsa_mechanism
(
  CK_MECHANISM_PTR mechPtr,
  NSSParameters *parameters
)
{
    NSSParameters defaultParams;
    if (!parameters) {
	defaultParams.rsa = NSSRSABlockFormat_Raw;
	parameters = &defaultParams;
    }
    switch (parameters->rsa) {
    case NSSRSABlockFormat_Raw:
	mechPtr->mechanism = CKM_RSA_X_509;
	break;
    case NSSRSABlockFormat_PKCS1:
	mechPtr->mechanism = CKM_RSA_PKCS;
	break;
    case NSSRSABlockFormat_PKCS1_WITH_MD2:
	mechPtr->mechanism = CKM_MD2_RSA_PKCS;
	break;
    case NSSRSABlockFormat_PKCS1_WITH_MD5:
	mechPtr->mechanism = CKM_MD5_RSA_PKCS;
	break;
    case NSSRSABlockFormat_PKCS1_WITH_SHA1:
	mechPtr->mechanism = CKM_SHA1_RSA_PKCS;
	break;
    case NSSRSABlockFormat_PKCS1_OAEP:
	mechPtr->mechanism = CKM_RSA_PKCS_OAEP;
	break;
    default:
	return PR_FAILURE;
    }
    return PR_SUCCESS;
}

/* 
 * DSA key generation
 */

/* set template parameters for DSA key generation */
static PRIntn
dsa_keygen_settor (
  const NSSAlgorithmAndParameters *ap,
  CK_ATTRIBUTE_PTR aTemplate,
  CK_ULONG templateSize
)
{
    CK_ATTRIBUTE_PTR attr = aTemplate;
    if (ap->params.dsakg.p.data == NULL) {
	/* XXX ? */
	PR_ASSERT(0);
    } else {
	/* P */
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_PRIME, &ap->params.dsakg.p);
	/* Q */
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_SUBPRIME, &ap->params.dsakg.q);
	/* G */
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_BASE, &ap->params.dsakg.g);
    }
    return attr - aTemplate;
}

/*
 * DSA cipher
 */
static PRStatus
set_dsa_mechanism
(
  CK_MECHANISM_PTR mechPtr,
  NSSParameters *parameters
)
{
    NSSParameters defaultParams;
    if (!parameters) {
	defaultParams.dsa = NSSAlgorithmType_NULL;
	parameters = &defaultParams;
    }
    switch (parameters->dsa) {
    case NSSAlgorithmType_NULL:
	mechPtr->mechanism = CKM_DSA;
	break;
    case NSSAlgorithmType_SHA1:
	mechPtr->mechanism = CKM_DSA_SHA1;
	break;
    default:
	return PR_FAILURE;
    }
    return PR_SUCCESS;
}

/*
 * Diffie-Hellman key generation
 */

/* set template parameters for Diffie-Hellman key generation */
static PRIntn
dh_keygen_settor (
  const NSSAlgorithmAndParameters *ap,
  CK_ATTRIBUTE_PTR aTemplate,
  CK_ULONG templateSize
)
{
    CK_ATTRIBUTE_PTR attr = aTemplate;
    if (ap->params.dhkg.p.data == NULL) {
	/* XXX ? */
	PR_ASSERT(0);
    } else {
	/* P */
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_PRIME, &ap->params.dhkg.p);
	/* G */
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_BASE, &ap->params.dhkg.g);
	/* constraint on private value */
	NSS_CK_SET_ATTRIBUTE_VAR(attr, CKA_VALUE_BITS,
	                         ap->params.dhkg.valueBits);
    }
    return attr - aTemplate;
}

/*
 * Diffie-Hellman key derivation
 */
static PRStatus
set_dh_mechanism
(
  CK_MECHANISM_PTR mechPtr,
  NSSParameters *parameters
)
{
	/* XXX */
    return PR_FAILURE;
}

/*
 * DES
 */
static PRStatus
set_des_mechanism
(
  CK_MECHANISM_PTR mechPtr,
  NSSParameters *parameters,
  NSSArena *arena
)
{
    if (parameters) {
	if (parameters->des.pkcsPad) {
	    mechPtr->mechanism = CKM_DES_CBC_PAD;
	} else {
	    mechPtr->mechanism = CKM_DES_CBC;
	}
	return set_iv_parameter(mechPtr, &parameters->des.iv, arena);
    } else {
	mechPtr->mechanism = CKM_DES_ECB;
    }
    return PR_SUCCESS;
}

/*
 * Triple-DES
 */
static PRStatus
set_des3_mechanism
(
  CK_MECHANISM_PTR mechPtr,
  NSSParameters *parameters,
  NSSArena *arena
)
{
    if (parameters) {
	if (parameters->des.pkcsPad) {
	    mechPtr->mechanism = CKM_DES3_CBC_PAD;
	} else {
	    mechPtr->mechanism = CKM_DES3_CBC;
	}
	return set_iv_parameter(mechPtr, &parameters->des.iv, arena);
    } else {
	mechPtr->mechanism = CKM_DES3_ECB;
    }
    return PR_SUCCESS;
}

/*
 * AES
 */
static PRStatus
set_aes_mechanism
(
  CK_MECHANISM_PTR mechPtr,
  NSSParameters *parameters,
  NSSArena *arena
)
{
    if (parameters) {
	if (parameters->aes.pkcsPad) {
	    mechPtr->mechanism = CKM_AES_CBC_PAD;
	} else {
	    mechPtr->mechanism = CKM_AES_CBC;
	}
	return set_iv_parameter(mechPtr, &parameters->des.iv, arena);
    } else {
	mechPtr->mechanism = CKM_AES_ECB;
    }
    return PR_SUCCESS;
}

/*
 * RC2
 */

/* setting mechanism */

static PRStatus
set_rc2_mechanism
(
  CK_MECHANISM_PTR mechPtr,
  NSSParameters *parameters,
  NSSArena *arena
)
{
    if (parameters) {
	CK_RC2_CBC_PARAMS_PTR rc2p;
	if (parameters->rc2.pkcsPad) {
	    mechPtr->mechanism = CKM_RC2_CBC_PAD;
	} else {
	    mechPtr->mechanism = CKM_RC2_CBC;
	}
	rc2p = nss_ZNEW(arena, CK_RC2_CBC_PARAMS);
	if (!rc2p) {
	    return PR_FAILURE;
	}
	nsslibc_memcpy(rc2p->iv, 
	               parameters->rc2.iv.data, 
	               parameters->rc2.iv.size);
	rc2p->ulEffectiveBits = parameters->rc2.effectiveKeySizeInBits;
	mechPtr->pParameter = rc2p;
	mechPtr->ulParameterLen = sizeof(rc2p);
    } else {
	mechPtr->mechanism = CKM_RC2_ECB;
	return set_bits_parameter(mechPtr, 
	                          parameters->rc2.effectiveKeySizeInBits, 
	                          arena);
    }
    return PR_SUCCESS;
}

/* decoding */

struct rc2_param_str {
  NSSItem version; /* number? */
  NSSItem iv;
};

static const nssASN1Template rc2_ecb_param_tmpl[] = {
  { nssASN1_SEQUENCE, 0, NULL, sizeof(struct rc2_param_str)  },
  { nssASN1_INTEGER, offsetof(struct rc2_param_str, version) },
  { 0 }
};

static const nssASN1Template rc2_cbc_param_tmpl[] = {
  { nssASN1_SEQUENCE, 0, NULL, sizeof(struct rc2_param_str)  },
  { nssASN1_INTEGER, offsetof(struct rc2_param_str, version) },
  { nssASN1_OCTET_STRING, offsetof(struct rc2_param_str, iv) },
  { 0 }
};

static CK_ULONG rc2_map(NSSItem *version)
{
    PRStatus status;
    PRUint32 x;
    status = nssASN1_CreatePRUint32FromBER(version, &x);
    if (status == PR_SUCCESS) {
	switch (x) {
	case 120: return  64;
	case 160: return  40;
	case 58:
	default:  return 128;
	}
    }
    return -1;
}

static PRStatus
decode_rc2_ecb(NSSAlgorithmAndParameters *ap, const NSSItem *params)
{
    PRStatus status;
    CK_RC2_PARAMS *ckrc2p;
    struct rc2_param_str rc2p;

    status = nssASN1_DecodeBER(ap->arena, &rc2p, rc2_ecb_param_tmpl, params);
    if (status == PR_FAILURE) {
	return PR_FAILURE;
    }
    ckrc2p = nss_ZNEW(ap->arena, CK_RC2_PARAMS);
    if (!ckrc2p) {
	return PR_FAILURE;
    }
    *ckrc2p = rc2_map(&rc2p.version);
    if (*ckrc2p == (CK_ULONG)-1) {
	return PR_FAILURE;
    }
    ap->mechanism.pParameter = (void *)ckrc2p;
    ap->mechanism.ulParameterLen = sizeof(CK_RC2_PARAMS);
    return PR_SUCCESS;
}

static PRStatus
decode_rc2_cbc(NSSAlgorithmAndParameters *ap, const NSSItem *params)
{
    PRStatus status;
    CK_RC2_CBC_PARAMS *ckrc2p;
    struct rc2_param_str rc2p;

    status = nssASN1_DecodeBER(ap->arena, &rc2p, rc2_cbc_param_tmpl, params);
    if (status == PR_FAILURE) {
	return PR_FAILURE;
    }
    ckrc2p = nss_ZNEW(ap->arena, CK_RC2_CBC_PARAMS);
    if (!ckrc2p) {
	return PR_FAILURE;
    }
    ckrc2p->ulEffectiveBits = rc2_map(&rc2p.version);
    if (ckrc2p->ulEffectiveBits == (CK_ULONG)-1) {
	return PR_FAILURE;
    }

    /* sanity check before copying iv */
    PR_ASSERT(rc2p.iv.size == sizeof(ckrc2p->iv));
    if (rc2p.iv.size != sizeof(ckrc2p->iv)) {
	return PR_FAILURE;
    }
    nsslibc_memcpy(ckrc2p->iv, rc2p.iv.data, sizeof(ckrc2p->iv));

    ap->mechanism.pParameter = (void *)ckrc2p;
    ap->mechanism.ulParameterLen = sizeof(CK_RC2_CBC_PARAMS);
    return PR_SUCCESS;
}

/*
 * RC5
 */
static PRStatus
set_rc5_mechanism
(
  CK_MECHANISM_PTR mechPtr,
  NSSParameters *parameters,
  NSSArena *arena
)
{
    if (parameters) {
	CK_RC5_CBC_PARAMS_PTR rc5p;
	if (parameters->rc5.pkcsPad) {
	    mechPtr->mechanism = CKM_RC5_CBC_PAD;
	} else {
	    mechPtr->mechanism = CKM_RC5_CBC;
	}
	rc5p = nss_ZNEW(arena, CK_RC5_CBC_PARAMS);
	if (!rc5p) {
	    return PR_FAILURE;
	}
	rc5p->pIv = nss_ZAlloc(arena, parameters->rc5.iv.size);
	if (!rc5p) {
	    return PR_FAILURE;
	}
	nsslibc_memcpy(rc5p->pIv, 
	               parameters->rc5.iv.data, 
	               parameters->rc5.iv.size);
	rc5p->ulIvLen = parameters->rc5.iv.size;
	rc5p->ulWordsize = parameters->rc5.wordSize;
	rc5p->ulRounds = parameters->rc5.numRounds;
	mechPtr->pParameter = rc5p;
	mechPtr->ulParameterLen = sizeof(rc5p);
    } else {
	CK_RC5_PARAMS_PTR rc5p;
	mechPtr->mechanism = CKM_RC5_ECB;
	rc5p = nss_ZNEW(arena, CK_RC5_PARAMS);
	if (!rc5p) {
	    return PR_FAILURE;
	}
	rc5p->ulWordsize = parameters->rc5.wordSize;
	rc5p->ulRounds = parameters->rc5.numRounds;
	mechPtr->pParameter = rc5p;
	mechPtr->ulParameterLen = sizeof(rc5p);
    }
    return PR_SUCCESS;
}

/*
 * SSL algorithms
 */

/*
 * SSL Pre-Master secret key generation
 */
static PRStatus
set_sslpms_mechanism (
  CK_MECHANISM_PTR mechPtr,
  NSSParameters *parameters,
  NSSArena *arena
)
{
    CK_VERSION *sslVersion = NULL;
    CK_VERSION sv;

    switch (parameters->sslpms) {
    case NSSSSLVersion_SSLv3: 
	mechPtr->mechanism = CKM_SSL3_PRE_MASTER_KEY_GEN;
	sv.major = 3; sv.minor = 0; break;
    case NSSSSLVersion_TLS:   
	mechPtr->mechanism = CKM_TLS_PRE_MASTER_KEY_GEN;
	sv.major = 3; sv.minor = 1; break;
    default:
	/* XXX error invalid args */
	return PR_FAILURE;
    }

    sslVersion = nss_ZNEW(arena, CK_VERSION);
    if (!sslVersion) {
	return PR_FAILURE;
    }
    *sslVersion = sv;

    mechPtr->pParameter = sslVersion;
    mechPtr->ulParameterLen = sizeof(CK_VERSION);
    return PR_SUCCESS;
}

static PRStatus
copy_item(NSSItem *it, CK_BYTE_PTR *buf, CK_ULONG *len, NSSArena *arena)
{
    *buf = nss_ZAlloc(arena, it->size);
    if (*buf) {
	nsslibc_memcpy(*buf, it->data, it->size);
	*len = it->size;
	return PR_SUCCESS;
    }
    return PR_FAILURE;
}

/*
 * SSL Master secret key derivation
 */
static PRStatus
set_sslms_mechanism (
  CK_MECHANISM_PTR mechPtr,
  NSSParameters *parameters,
  NSSArena *arena
)
{
    PRStatus status;
    CK_VERSION sv;
    CK_SSL3_MASTER_KEY_DERIVE_PARAMS *msp;

    switch (parameters->sslms.version) {
    case NSSSSLVersion_SSLv3: 
	mechPtr->mechanism = parameters->sslms.isDH ?
	                      CKM_SSL3_MASTER_KEY_DERIVE_DH :
	                      CKM_SSL3_MASTER_KEY_DERIVE;
	sv.major = 3; sv.minor = 0; break;
    case NSSSSLVersion_TLS:   
	mechPtr->mechanism = parameters->sslms.isDH ?
	                      CKM_TLS_MASTER_KEY_DERIVE_DH :
	                      CKM_TLS_MASTER_KEY_DERIVE;
	sv.major = 3; sv.minor = 1; break;
    default:
	/* XXX error invalid args */
	return PR_FAILURE;
    }

    msp = nss_ZNEW(arena, CK_SSL3_MASTER_KEY_DERIVE_PARAMS);
    if (!msp) {
	return PR_FAILURE;
    }
    msp->pVersion = nss_ZNEW(arena, CK_VERSION);
    if (!msp->pVersion) {
	return PR_FAILURE;
    }
    *msp->pVersion = sv;

    status = copy_item(&parameters->sslms.clientRandom,
                       &msp->RandomInfo.pClientRandom,
                       &msp->RandomInfo.ulClientRandomLen, arena);
    if (status == PR_FAILURE) {
	return PR_FAILURE;
    }

    status = copy_item(&parameters->sslms.serverRandom,
                       &msp->RandomInfo.pServerRandom,
                       &msp->RandomInfo.ulServerRandomLen, arena);
    if (status == PR_FAILURE) {
	return PR_FAILURE;
    }

    mechPtr->pParameter = msp;
    mechPtr->ulParameterLen = sizeof(CK_SSL3_MASTER_KEY_DERIVE_PARAMS);
    return PR_SUCCESS;
}

/*
 * SSL session secret keys derivation
 */
static PRStatus
set_sslsession_derive_mechanism (
  CK_MECHANISM_PTR mechPtr,
  NSSSSLSessionKeyParameters *parameters,
  NSSArena *arena
)
{
    PRStatus status;
    CK_SSL3_KEY_MAT_PARAMS *kmp;
    CK_SSL3_KEY_MAT_OUT *kmo;

    switch (parameters->version) {
    case NSSSSLVersion_SSLv3: 
	mechPtr->mechanism = CKM_SSL3_KEY_AND_MAC_DERIVE;
    case NSSSSLVersion_TLS:   
	mechPtr->mechanism = CKM_TLS_KEY_AND_MAC_DERIVE;
    default:
	/* XXX error invalid args */
	return PR_FAILURE;
    }

    kmp = nss_ZNEW(arena, CK_SSL3_KEY_MAT_PARAMS);
    if (!kmp) {
	return PR_FAILURE;
    }
    kmp->ulMacSizeInBits = parameters->macSizeInBits;
    kmp->ulKeySizeInBits = parameters->keySizeInBits;
    kmp->ulIVSizeInBits = parameters->ivSizeInBits;
    kmp->bIsExport = parameters->isExport;

    status = copy_item(&parameters->clientRandom,
                       &kmp->RandomInfo.pClientRandom,
                       &kmp->RandomInfo.ulClientRandomLen, arena);
    if (status == PR_FAILURE) {
	return PR_FAILURE;
    }

    status = copy_item(&parameters->serverRandom,
                       &kmp->RandomInfo.pServerRandom,
                       &kmp->RandomInfo.ulServerRandomLen, arena);
    if (status == PR_FAILURE) {
	return PR_FAILURE;
    }

    kmo = nss_ZNEW(arena, CK_SSL3_KEY_MAT_OUT);
    if (!kmo) {
	return PR_FAILURE;
    }
    kmo->pIVClient = parameters->clientIV;
    kmo->pIVServer = parameters->serverIV;

    mechPtr->pParameter = kmp;
    mechPtr->ulParameterLen = sizeof(CK_SSL3_KEY_MAT_PARAMS);
    return PR_SUCCESS;
}

/*
 * convert and algorithm type and algorithm-specific parameters
 * to a CK_MECHANISM.
 */
static PRStatus
set_cryptoki_mechanism
(
  CK_MECHANISM_PTR mechPtr,
  NSSAlgorithmType algorithm,
  NSSParameters *parameters,
  NSSArena *arena
)
{
    switch (algorithm) {
    case NSSAlgorithmType_RSA: 
	return set_rsa_mechanism(mechPtr, parameters);
    case NSSAlgorithmType_DSA:
	return set_dsa_mechanism(mechPtr, parameters);
    case NSSAlgorithmType_DH:
	return set_dh_mechanism(mechPtr, parameters);
    case NSSAlgorithmType_DES:
	return set_des_mechanism(mechPtr, parameters, arena);
    case NSSAlgorithmType_3DES:
	return set_des3_mechanism(mechPtr, parameters, arena);
    case NSSAlgorithmType_AES:
	return set_aes_mechanism(mechPtr, parameters, arena);
    case NSSAlgorithmType_RC2:
	return set_rc2_mechanism(mechPtr, parameters, arena);
    case NSSAlgorithmType_RC4:
	mechPtr->mechanism = CKM_RC4;
	break;
    case NSSAlgorithmType_RC5:
	return set_rc5_mechanism(mechPtr, parameters, arena);
    case NSSAlgorithmType_MD2:
	mechPtr->mechanism = CKM_MD2;
	break;
    case NSSAlgorithmType_MD5:
	mechPtr->mechanism = CKM_MD5;
	break;
    case NSSAlgorithmType_SHA1:
	mechPtr->mechanism = CKM_SHA_1;
	break;
    case NSSAlgorithmType_PBE:
    case NSSAlgorithmType_MAC:
    case NSSAlgorithmType_HMAC:
    default:
	return PR_FAILURE;
    }
    return PR_SUCCESS;
}

/*
 * convert a keypair type and keypair-specific parameters to a
 * CK_MECHANISM.
 */
static PRStatus
set_cryptoki_mechanism_for_keypair_gen
(
  NSSAlgorithmAndParameters *ap,
  NSSKeyPairType keyPairType,
  NSSParameters *parameters
)
{
    CK_MECHANISM_PTR mechPtr = &ap->mechanism;
    switch (keyPairType) {
    case NSSKeyPairType_RSA:
	mechPtr->mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
	ap->params.rsakg = parameters->rsakg;
	ap->set_template = rsa_keygen_settor;
	break;
    case NSSAlgorithmType_DSA:
	mechPtr->mechanism = CKM_DSA_KEY_PAIR_GEN;
	ap->params.dsakg.primeBits = parameters->dsakg.primeBits;
	if (parameters->dsakg.p.data != NULL) {
	    nssItem_Duplicate(&parameters->dsakg.p, ap->arena,
	                      &ap->params.dsakg.p);
	    nssItem_Duplicate(&parameters->dsakg.q, ap->arena,
	                      &ap->params.dsakg.q);
	    nssItem_Duplicate(&parameters->dsakg.g, ap->arena,
	                      &ap->params.dsakg.g);
	}
	ap->set_template = dsa_keygen_settor;
	break;
    case NSSAlgorithmType_DH:
	mechPtr->mechanism = CKM_DH_PKCS_KEY_PAIR_GEN;
	ap->params.dhkg.valueBits = parameters->dhkg.valueBits;
	ap->params.dhkg.primeBits = parameters->dhkg.primeBits;
	if (parameters->dhkg.p.data != NULL) {
	    nssItem_Duplicate(&parameters->dhkg.p, ap->arena,
	                      &ap->params.dhkg.p);
	    nssItem_Duplicate(&parameters->dhkg.g, ap->arena,
	                      &ap->params.dhkg.g);
	}
	ap->set_template = dh_keygen_settor;
	break;
    case NSSAlgorithmType_DES:
	mechPtr->mechanism = CKM_DES_KEY_GEN;
	break;
    case NSSAlgorithmType_3DES:
	mechPtr->mechanism = CKM_DES3_KEY_GEN;
	break;
    case NSSAlgorithmType_AES:
	mechPtr->mechanism = CKM_AES_KEY_GEN;
	break;
    case NSSAlgorithmType_RC2:
	mechPtr->mechanism = CKM_RC2_KEY_GEN;
	break;
    case NSSAlgorithmType_RC4:
	mechPtr->mechanism = CKM_RC4_KEY_GEN;
	break;
    case NSSAlgorithmType_RC5:
	mechPtr->mechanism = CKM_RC5_KEY_GEN;
	break;
    case NSSAlgorithmType_PBE:
    case NSSAlgorithmType_MAC:
    case NSSAlgorithmType_HMAC:
    default:
	return PR_FAILURE;
    }
    return PR_SUCCESS;
}

static PRStatus
set_cryptoki_mechanism_for_symkey_gen
(
  NSSAlgorithmAndParameters *ap,
  NSSSymmetricKeyType symKeyType,
  NSSParameters *parameters
)
{
    CK_MECHANISM_PTR mechPtr = &ap->mechanism;
    switch (symKeyType) {
    case NSSSymmetricKeyType_SSLPMS:
	return set_sslpms_mechanism(mechPtr, parameters, ap->arena);
    case NSSSymmetricKeyType_SSLMS:
	return set_sslms_mechanism(mechPtr, parameters, ap->arena);
    default:
	/* XXX invalid args */
	return PR_FAILURE;
    }
}

static NSSAlgorithmAndParameters *
create_algparam
(
  NSSArena *arenaOpt,
  nssArenaMark **mark
)
{
    NSSArena *arena;
    NSSAlgorithmAndParameters *rvAP = NULL;
    if (arenaOpt) {
	arena = arenaOpt;
	*mark = nssArena_Mark(arena);
	if (!*mark) {
	    return (NSSAlgorithmAndParameters *)NULL;
	}
    } else {
	arena = nssArena_Create();
	if (!arena) {
	    return (NSSAlgorithmAndParameters *)NULL;
	}
    }
    rvAP = nss_ZNEW(arena, NSSAlgorithmAndParameters);
    if (!rvAP) {
	if (*mark) {
	    nssArena_Release(arena, *mark);
	} else {
	    nssArena_Destroy(arena);
	}
	return (NSSAlgorithmAndParameters *)NULL;
    }
    rvAP->arena = arena;
    rvAP->set_template = null_settor; /* by default */
    return rvAP;
}

static NSSAlgorithmAndParameters *
finish_create_algparam
(
  NSSAlgorithmAndParameters *ap,
  NSSArena *arena,
  nssArenaMark *mark,
  PRStatus isOK
)
{
    if (isOK == PR_SUCCESS) {
	if (mark) {
	    nssArena_Unmark(arena, mark);
	}
    } else {
	if (mark) {
	    nssArena_Release(arena, mark);
	} else {
	    nssArena_Destroy(arena);
	}
	ap = (NSSAlgorithmAndParameters *)NULL;
    }
    return ap;
}

NSS_IMPLEMENT NSSAlgorithmAndParameters *
nssAlgorithmAndParameters_Create
(
  NSSArena *arenaOpt,
  NSSAlgorithmType algorithm,
  NSSParameters *parametersOpt
)
{
    PRStatus status;
    nssArenaMark *mark = NULL;
    NSSAlgorithmAndParameters *rvAP = NULL;

    rvAP = create_algparam(arenaOpt, &mark);
    if (!rvAP) {
	return (NSSAlgorithmAndParameters *)NULL;
    }

    status = set_cryptoki_mechanism(&rvAP->mechanism, 
                                    algorithm, parametersOpt, rvAP->arena);

    return finish_create_algparam(rvAP, rvAP->arena, mark, status);
}

NSS_IMPLEMENT NSSAlgorithmAndParameters *
nssAlgorithmAndParameters_CreateKeyPairGen
(
  NSSArena *arenaOpt,
  NSSKeyPairType keyPairType,
  NSSParameters *parametersOpt
)
{
    PRStatus status;
    nssArenaMark *mark = NULL;
    NSSAlgorithmAndParameters *rvAP = NULL;

    rvAP = create_algparam(arenaOpt, &mark);
    if (!rvAP) {
	return (NSSAlgorithmAndParameters *)NULL;
    }

    status = set_cryptoki_mechanism_for_keypair_gen(rvAP, 
                                                    keyPairType, 
                                                    parametersOpt);

    return finish_create_algparam(rvAP, rvAP->arena, mark, status);
}

NSS_IMPLEMENT NSSAlgorithmAndParameters *
nssAlgorithmAndParameters_CreateSSLSessionKeyDerivation
(
  NSSArena *arenaOpt,
  NSSSSLSessionKeyParameters *parameters
)
{
    PRStatus status;
    nssArenaMark *mark = NULL;
    NSSAlgorithmAndParameters *rvAP = NULL;

    rvAP = create_algparam(arenaOpt, &mark);
    if (!rvAP) {
	return (NSSAlgorithmAndParameters *)NULL;
    }

    status = set_sslsession_derive_mechanism(&rvAP->mechanism,
                                             parameters,
                                             rvAP->arena);

    return finish_create_algparam(rvAP, rvAP->arena, mark, status);
}

/* this is how it was done in 3.X, but something not involving a
 * huge switch would be nicer
 */
static PRStatus
decode_params(NSSAlgorithmAndParameters *ap, const NSSItem *params)
{
    /* Algorithms that only take an IV parameter */
    switch (ap->mechanism.mechanism) {
    case CKM_AES_CBC:
    case CKM_AES_CBC_PAD:
    case CKM_DES_CBC:
    case CKM_DES_CBC_PAD:
    case CKM_DES3_CBC:
    case CKM_DES3_CBC_PAD:
    case CKM_IDEA_CBC:
    case CKM_IDEA_CBC_PAD:
    case CKM_CDMF_CBC:
    case CKM_CDMF_CBC_PAD:
    case CKM_CAST_CBC:
    case CKM_CAST_CBC_PAD:
    case CKM_CAST3_CBC:
    case CKM_CAST3_CBC_PAD:
    case CKM_CAST5_CBC:
    case CKM_CAST5_CBC_PAD:
    case CKM_SKIPJACK_CFB8:
    case CKM_SKIPJACK_CFB16:
    case CKM_SKIPJACK_CFB32:
    case CKM_SKIPJACK_ECB64:
    case CKM_SKIPJACK_CBC64:
    case CKM_SKIPJACK_OFB64:
    case CKM_SKIPJACK_CFB64:
    case CKM_BATON_ECB96:
    case CKM_BATON_ECB128:
    case CKM_BATON_CBC128:
    case CKM_BATON_COUNTER:
    case CKM_BATON_SHUFFLE:
    case CKM_JUNIPER_ECB128:
    case CKM_JUNIPER_CBC128:
    case CKM_JUNIPER_COUNTER:
    case CKM_JUNIPER_SHUFFLE:  
	return decode_iv(ap, params);
    default: /* keep going */
	break;
    }

    /* Algorithms that take more complicated parameters */
    switch (ap->mechanism.mechanism) {
    case CKM_RC2_ECB:          return decode_rc2_ecb(ap, params);
    case CKM_RC2_CBC:
    case CKM_RC2_CBC_PAD:      return decode_rc2_cbc(ap, params);
    default:
	/* XXX unsupported alg or something */
	return PR_FAILURE;
    }
}

NSS_IMPLEMENT NSSAlgorithmAndParameters *
nssAlgorithmAndParameters_CreateFromOID
(
  NSSArena *arenaOpt,
  CK_MECHANISM_TYPE algorithm,
  const NSSItem *parametersOpt
)
{
    PRStatus status;
    NSSArena *arena;
    nssArenaMark *mark = NULL;
    NSSAlgorithmAndParameters *rvAP = NULL;

    rvAP = create_algparam(arenaOpt, &mark);
    if (!rvAP) {
	return (NSSAlgorithmAndParameters *)NULL;
    }

    rvAP->mechanism.mechanism = algorithm;

    if (parametersOpt) {
	status = decode_params(rvAP, parametersOpt);
    } else {
	/* XXX not catching algorithms that require parameters here */
	status = PR_SUCCESS;
    }

    return finish_create_algparam(rvAP, arena, mark, status);
}

NSS_IMPLEMENT void
nssAlgorithmAndParameters_Destroy
(
  NSSAlgorithmAndParameters *ap
)
{
    if (ap && ap->arena) {
	nssArena_Destroy(ap->arena);
    }
}

NSS_IMPLEMENT CK_MECHANISM_PTR
nssAlgorithmAndParameters_GetMechanism
(
  const NSSAlgorithmAndParameters *ap
)
{
    return &((NSSAlgorithmAndParameters *)ap)->mechanism;
}

#if 0
This alternative does not break const-ness.
NSS_IMPLEMENT void
nssAlgorithmAndParameters_GetMechanism2
(
  const NSSAlgorithmAndParameters *ap,
  CK_MECHANISM_PTR pMechanism
)
{
    *pMechanism = ap->mechanism;
}
#endif

NSS_IMPLEMENT PRIntn
nssAlgorithmAndParameters_SetTemplateValues
(
  const NSSAlgorithmAndParameters *ap,
  CK_ATTRIBUTE_PTR aTemplate,
  CK_ULONG templateSize
)
{
    return ap->set_template(ap, aTemplate, templateSize);
}

static PRStatus
copy_algparam
(
  NSSAlgorithmAndParameters *copy,
  const NSSAlgorithmAndParameters *orig
)
{
    copy->mechanism.mechanism = orig->mechanism.mechanism;
    copy->mechanism.pParameter = nss_ZAlloc(copy->arena,
                                            orig->mechanism.ulParameterLen);
    if (!copy->mechanism.pParameter) {
	return PR_FAILURE;
    }
    nsslibc_memcpy(copy->mechanism.pParameter,
                   orig->mechanism.pParameter,
                   orig->mechanism.ulParameterLen);
    copy->mechanism.ulParameterLen = orig->mechanism.ulParameterLen;
    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSAlgorithmAndParameters *
nssAlgorithmAndParameters_Clone
(
  const NSSAlgorithmAndParameters *ap,
  NSSArena *arenaOpt
)
{
    PRStatus status;
    NSSArena *arena;
    nssArenaMark *mark = NULL;
    NSSAlgorithmAndParameters *rvAP = NULL;

    rvAP = create_algparam(arenaOpt, &mark);
    if (!rvAP) {
	return (NSSAlgorithmAndParameters *)NULL;
    }

    status = copy_algparam(rvAP, ap);

    return finish_create_algparam(rvAP, arena, mark, status);
}

NSS_IMPLEMENT NSSAlgorithmAndParameters *
NSSAlgorithmAndParameters_Create
(
  NSSArena *arenaOpt,
  NSSAlgorithmType algorithm,
  NSSParameters *parametersOpt
)
{
    return nssAlgorithmAndParameters_Create(arenaOpt, 
                                            algorithm, 
                                            parametersOpt);
}

NSS_IMPLEMENT NSSAlgorithmAndParameters *
NSSAlgorithmAndParameters_CreateKeyPairGen
(
  NSSArena *arenaOpt,
  NSSKeyPairType keyPairType,
  NSSParameters *parametersOpt
)
{
    return nssAlgorithmAndParameters_CreateKeyPairGen(arenaOpt, 
                                                      keyPairType, 
                                                      parametersOpt);
}

NSS_IMPLEMENT void
NSSAlgorithmAndParameters_Destroy
(
  NSSAlgorithmAndParameters *ap
)
{
    nssAlgorithmAndParameters_Destroy(ap);
}

