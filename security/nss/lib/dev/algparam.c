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

#ifndef PKI1_H
#include "pki1.h"
#endif /* PKI1_H */

#ifndef OIDDATA_H
#include "oiddata.h"
#endif /* OIDDATA_H */

/* XXX grr -- not defined in stan header yet */
#ifndef CKM_INVALID_MECHANISM
#define CKM_INVALID_MECHANISM 0xffffffff
#endif

/*
 * NSSAlgNParamStr
 *
 * This generic container should hold everything we need to know
 * to use an algorithm, with the specific exclusion of keysizes when 
 * doing key generation (this is specified in the API, thus the same
 * AlgNParam can be reused to generate keys of different
 * length).
 *
 * Internally, we need to communicate the following information to
 * Cryptoki:
 *
 * 1) a CK_MECHANISM
 * 2) template values for key generation and derivation
 *
 * The CK_MECHANISM is always set when the AlgNParam is
 * created.  The template values are set upon request, and are extracted
 * from the the params field.
 *
 * We also need to move back and forth between AlgorithmIDs and AlgParams.
 * Each algorithm that has a template for params will set it when the
 * AlgParam is created.
 *
 * Once an AlgNParam is created, it is considered read-only.
 * Thus is it used as 'const' throughout the API.
 */
struct NSSAlgNParamStr
{
  NSSArena *arena;
  PRBool i_allocated_arena;
  CK_MECHANISM mechanism; /* alg&param in cryptoki terms */
  NSSOIDTag alg;          /* NSS algorithm */
  NSSParameters params;   /* NSS params (template values kept here) */

  /* every happy algorithm sets a mechanism the same way, but each
   * unhappy one sets a template a different way.
   */
  PRIntn (* set_template)(const NSSAlgNParam *ap,
                          CK_ATTRIBUTE_PTR aTemplate,
                          CK_ULONG templateSize);

  /* ASN.1 template for BER en/decoding parameters */
  const NSSASN1Template *paramTemplate;
};

/*
 * For each algorithm that requires a parameter, the following methods
 * may exist (depending on what kind of parameters it requires):
 *
 * set_xxx_mechanism -- convert an OID and NSSParameters to a 
 *                      CK_MECHANISM for algorithm xxx
 * xxx_settor -- callback function to set PKCS#11 template values for xxx
 * xxx_param_template -- ASN.1 template for parameters
 */

/* For all mechanisms where the only parameter is an IV */
static PRStatus
set_iv_parameter (
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

/* For all mechanisms where the only parameter is a ulong */
static PRStatus
set_ulong_parameter (
  CK_MECHANISM_PTR mechPtr,
  PRUint32 value,
  NSSArena *arena
)
{
    CK_ULONG ul = value;
    mechPtr->pParameter = (void *)nss_ZNEW(arena, CK_ULONG);
    if (!mechPtr->pParameter) {
	return PR_FAILURE;
    }
    nsslibc_memcpy(mechPtr->pParameter, &ul, sizeof(CK_ULONG));
    mechPtr->ulParameterLen = sizeof(CK_ULONG);
    return PR_SUCCESS;
}

/* For all mechanisms where the only parameter is a version */
static PRStatus
set_version_parameter (
  CK_MECHANISM_PTR mechPtr,
  CK_VERSION_PTR version,
  NSSArena *arena
)
{
    mechPtr->pParameter = (void *)nss_ZNEW(arena, CK_VERSION);
    if (!mechPtr->pParameter) {
	return PR_FAILURE;
    }
    nsslibc_memcpy(mechPtr->pParameter, version, sizeof(CK_VERSION));
    mechPtr->ulParameterLen = sizeof(CK_VERSION);
    return PR_SUCCESS;
}

/* For all mechanisms that don't need to set template values (default) */
static PRIntn
null_settor (
  const NSSAlgNParam *ap,
  CK_ATTRIBUTE_PTR aTemplate,
  CK_ULONG templateSize
)
{
    return 0;
}

/*
 * Decoding IV parameters
 */

/* XXX 
static PRStatus
decode_iv(NSSAlgNParam *ap, const NSSItem *params)
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
*/

/*
 * RSA key generation
 */

/* set template parameters for RSA key generation */
static PRIntn
rsa_keygen_settor (
  const NSSAlgNParam *ap,
  CK_ATTRIBUTE_PTR aTemplate,
  CK_ULONG templateSize
)
{
    CK_ATTRIBUTE_PTR attr = aTemplate;
    /* N */
    NSS_CK_SET_ATTRIBUTE_VAR(attr, CKA_MODULUS_BITS,
                             ap->params.rsakg.modulusBits);
    /* e */
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_PUBLIC_EXPONENT,
                              &ap->params.rsakg.publicExponent);
    return attr - aTemplate;
}

/* 
 * RSA
 */
static PRStatus
set_rsa_mechanism (
  NSSAlgNParam *ap,
  CK_MECHANISM_TYPE mech,
  NSSParameters *parameters,
  NSSItem *encodedParams,
  PRBool keygen
)
{
    if (keygen) {
	ap->mechanism.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
	ap->params.rsakg = parameters->rsakg;
	ap->set_template = rsa_keygen_settor;
    } else {
	ap->mechanism.mechanism = mech;
    }
    return PR_SUCCESS;
}

/* 
 * DSA key generation
 */

/* set template parameters for DSA key generation */
static PRIntn
dsa_keygen_settor (
  const NSSAlgNParam *ap,
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
 * DSA
 */
static PRStatus
set_dsa_mechanism (
  NSSAlgNParam *ap,
  CK_MECHANISM_TYPE mech,
  NSSParameters *parameters,
  NSSItem *encodedParams,
  PRBool keygen
)
{
    if (keygen) {
	ap->mechanism.mechanism = CKM_DSA_KEY_PAIR_GEN;
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
    } else {
	ap->mechanism.mechanism = mech;
    }
    return PR_SUCCESS;
}

/*
 * Diffie-Hellman key generation
 */

/* set template parameters for Diffie-Hellman key generation */
#if 0
static PRIntn
dh_keygen_settor (
  const NSSAlgNParam *ap,
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
#endif

/*
 * Diffie-Hellman key derivation
 */
static PRStatus
set_dh_mechanism (
  NSSAlgNParam *ap,
  CK_MECHANISM_TYPE mech,
  NSSParameters *parameters,
  NSSItem *encodedParams,
  PRBool keygen
)
{
#if 0
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
#endif
	/* XXX */
    return PR_FAILURE;
}

/*
 * DES
 */
static PRStatus
set_des_mechanism (
  NSSAlgNParam *ap,
  CK_MECHANISM_TYPE mech,
  NSSParameters *parameters,
  NSSItem *encodedParams,
  PRBool keygen
)
{
    PRStatus status;
    if (keygen) {
	ap->mechanism.mechanism = CKM_DES_KEY_GEN;
    } else {
	ap->mechanism.mechanism = mech;
	if (mech == CKM_DES_CBC) {
	    PR_ASSERT(parameters != NULL || encodedParams != NULL);
	    ap->paramTemplate = nssASN1Template_OctetString; /* just IV */
	    if (encodedParams) {
		status = nssASN1_DecodeBER(ap->arena, &ap->params.iv, 
		                           ap->paramTemplate, 
	                                   encodedParams);
		if (status == PR_FAILURE) {
		    return PR_FAILURE;
		}
	    } else {
		ap->params.iv = parameters->iv;
	    }
	    return set_iv_parameter(&ap->mechanism, 
	                            &ap->params.iv, ap->arena);
	}
    }
    return PR_SUCCESS;
}

/*
 * Triple-DES
 */
static PRStatus
set_des3_mechanism (
  NSSAlgNParam *ap,
  CK_MECHANISM_TYPE mech,
  NSSParameters *parameters,
  NSSItem *encodedParams,
  PRBool keygen
)
{
    PRStatus status;
    if (keygen) {
	ap->mechanism.mechanism = CKM_DES3_KEY_GEN;
    } else {
	ap->mechanism.mechanism = mech;
	if (mech == CKM_DES3_CBC) {
	    PR_ASSERT(parameters != NULL || encodedParams != NULL);
	    ap->paramTemplate = nssASN1Template_OctetString; /* just IV */
	    if (encodedParams) {
		status = nssASN1_DecodeBER(ap->arena, &ap->params.iv, 
		                           ap->paramTemplate, 
	                                   encodedParams);
		if (status == PR_FAILURE) {
		    return PR_FAILURE;
		}
	    } else {
		ap->params.iv = parameters->iv;
	    }
	    return set_iv_parameter(&ap->mechanism, 
	                            &ap->params.iv, ap->arena);
	}
    }
    return PR_SUCCESS;
}

#if 0
/*
 * AES
 */
static PRStatus
set_aes_mechanism (
  NSSAlgNParam *ap,
  CK_MECHANISM_TYPE mech,
  NSSParameters *parameters,
  NSSItem *encodedParams,
  PRBool keygen
)
{
    PRStatus status;
    if (keygen) {
	ap->mechanism.mechanism = CKM_AES_KEY_GEN;
    } else {
	ap->mechanism.mechanism = mech;
	if (mech == CKM_AES_CBC) {
	    PR_ASSERT(parameters != NULL || encodedParams != NULL);
	    ap->paramTemplate = nssASN1Template_OctetString; /* just IV */
	    if (encodedParams) {
		status = nssASN1_DecodeBER(ap->arena, &ap->params.iv, 
		                           ap->paramTemplate, 
	                                   encodedParams);
		if (status == PR_FAILURE) {
		    return PR_FAILURE;
		}
	    } else {
		ap->params.iv = parameters->iv;
	    }
	    return set_iv_parameter(&ap->mechanism, 
	                            &ap->params.iv, ap->arena);
	}
    }
    return PR_SUCCESS;
}
#endif

/*
 * RC2
 */

/* en/decoding */

static const nssASN1Template rc2_ecb_param_tmpl[] = {
  { nssASN1_SEQUENCE, 0, NULL, sizeof(NSSRC2Parameters)  },
  { nssASN1_INTEGER, offsetof(NSSRC2Parameters, version) },
  { 0 }
};

static const nssASN1Template rc2_cbc_param_tmpl[] = {
  { nssASN1_SEQUENCE, 0, NULL, sizeof(NSSRC2Parameters)  },
  { nssASN1_INTEGER, offsetof(NSSRC2Parameters, version) },
  { nssASN1_OCTET_STRING, offsetof(NSSRC2Parameters, iv) },
  { 0 }
};

static PRStatus rc2_map(NSSRC2Parameters *params)
{
    PRStatus status;
    PRUint32 x;
    status = nssASN1_CreatePRUint32FromBER(&params->version, &x);
    if (status == PR_SUCCESS) {
	switch (x) {
	case 120: params->effectiveKeySizeInBits =  64; break;
	case 160: params->effectiveKeySizeInBits =  40; break;
	case 58:
	default:  params->effectiveKeySizeInBits = 128; break;
	}
    }
    return status;
}

static PRStatus rc2_unmap(NSSRC2Parameters *params, NSSArena *arena)
{
    PRUint32 v;
    switch (params->effectiveKeySizeInBits) {
    case  40: v = 160; break;
    case  64: v = 120; break;
    case 128: 
    default:  v =  58; break;
    }
    return (nssASN1_GetDERFromPRUint32(arena, &params->version, v) != NULL) ?
             PR_SUCCESS : PR_FAILURE;
}

/* constructor */

static PRStatus
rc2_constructor (
  NSSAlgNParam *ap,
  CK_MECHANISM_TYPE mech,
  NSSParameters *parameters,
  NSSItem *encodedParams,
  PRBool keygen
)
{
    PRStatus status;
    if (keygen) {
	ap->mechanism.mechanism = CKM_RC2_KEY_GEN;
    } else {
	CK_RC2_CBC_PARAMS_PTR rc2p;
	ap->mechanism.mechanism = mech;
	if (mech == CKM_RC2_ECB) {
	    ap->paramTemplate = rc2_ecb_param_tmpl;
	} else if (mech == CKM_RC2_CBC) {
	    PR_ASSERT(parameters != NULL || encodedParams != NULL);
	    ap->paramTemplate = rc2_cbc_param_tmpl;
	} else {
	    return PR_FAILURE;
	}
	if (encodedParams) {
	    status = nssASN1_DecodeBER(ap->arena, &ap->params.rc2, 
	                               ap->paramTemplate, encodedParams);
	    if (status == PR_FAILURE) {
		return PR_FAILURE;
	    }
	    status = rc2_map(&ap->params.rc2);
	} else {
	    status = rc2_unmap(&ap->params.rc2, ap->arena);
	    /* XXX generate IV somehow */
	}
	if (status == PR_FAILURE) {
	    return PR_FAILURE;
	}
	rc2p = nss_ZNEW(ap->arena, CK_RC2_CBC_PARAMS);
	if (!rc2p) {
	    return PR_FAILURE;
	}
	nsslibc_memcpy(rc2p->iv, 
	               ap->params.rc2.iv.data, 
	               ap->params.rc2.iv.size);
	rc2p->ulEffectiveBits = ap->params.rc2.effectiveKeySizeInBits;
	ap->mechanism.pParameter = rc2p;
	ap->mechanism.ulParameterLen = sizeof(CK_RC2_CBC_PARAMS);
    }
    return PR_SUCCESS;
}

/*
 * RC5
 */
static PRStatus
set_rc5_mechanism (
  NSSAlgNParam *ap,
  CK_MECHANISM_TYPE mech,
  NSSParameters *parameters,
  NSSItem *encodedParams,
  PRBool keygen
)
{
#if 0
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
#endif
return PR_FAILURE;
}

/*
 * PBE
 */

static const NSSASN1Template pkcs5_pbe_param_tmpl[] =
{
 { NSSASN1_SEQUENCE, 0, NULL, sizeof(NSSPBEParameters)      },
 { NSSASN1_OCTET_STRING, offsetof(NSSPBEParameters, salt)   },
 { NSSASN1_INTEGER,      offsetof(NSSPBEParameters, iterIt) },
 { 0 }
};

/* XXX
have password come in later (& iv)?
not really part of params
*/
static PRStatus
pbe_constructor (
  NSSAlgNParam *ap,
  CK_MECHANISM_TYPE mech,
  NSSParameters *parameters,
  NSSItem *encodedParams
)
{
    PRStatus status;
    CK_PBE_PARAMS_PTR pbeParam;
    PR_ASSERT(parameters != NULL || encodedParams != NULL);
    ap->mechanism.mechanism = mech;
    ap->paramTemplate = pkcs5_pbe_param_tmpl;
    if (encodedParams) {
        PRUint8 itit;
	status = nssASN1_DecodeBER(ap->arena, &ap->params.pbe, 
	                           ap->paramTemplate, encodedParams);
	if (status == PR_FAILURE) {
	    return PR_FAILURE;
	}
	/* XXX until asn.1 decodes ints */
	itit = *(PRUint8*)ap->params.pbe.iterIt.data;
	ap->params.pbe.iteration = (PRUint32)itit;
    } else {
	/* XXX copy? */
	ap->params.pbe = parameters->pbe;
	/* XXX hacky */
	ap->params.pbe.iterIt.data = nss_ZAlloc(ap->arena, 1);
	*((PRUint8*)ap->params.pbe.iterIt.data) = parameters->pbe.iteration;
	ap->params.pbe.iterIt.size = 1;
    }
    pbeParam = nss_ZNEW(ap->arena, CK_PBE_PARAMS);
    if (!pbeParam) {
	return PR_FAILURE;
    }
    /* PR_ASSERT(ap->params.pbe.iv.size == PBE_IV_LENGTH); */
    pbeParam->pInitVector = (CK_CHAR_PTR)ap->params.pbe.iv;
    pbeParam->pSalt = (CK_CHAR_PTR)ap->params.pbe.salt.data;
    pbeParam->ulSaltLen = (CK_ULONG)ap->params.pbe.salt.size;
    pbeParam->ulIteration = (CK_ULONG)ap->params.pbe.iteration;
    ap->mechanism.pParameter = pbeParam;
    ap->mechanism.ulParameterLen = sizeof(CK_PBE_PARAMS);
    return PR_SUCCESS;
}

NSS_IMPLEMENT PRStatus
nssAlgNParam_SetPBEPassword (
  NSSAlgNParam *ap,
  NSSUTF8 *password
)
{
    CK_PBE_PARAMS_PTR pbeParam;
    /* soft check for correctness */
    PR_ASSERT(ap->mechanism.ulParameterLen == sizeof(CK_PBE_PARAMS));
    pbeParam = (CK_PBE_PARAMS_PTR)ap->mechanism.pParameter;
    pbeParam->pPassword = (CK_CHAR_PTR)password;
    pbeParam->ulPasswordLen = (CK_ULONG)nssUTF8_Length(password, NULL);
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
 * convert and algorithm type and algorithm-specific parameters
 * to a CK_MECHANISM.
 */
static PRStatus
set_cryptoki_mechanism (
  NSSAlgNParam *ap,
  const NSSOID *algorithm,
  NSSParameters *params,
  NSSItem *encodedParams,
  PRBool keygen
)
{
    NSSOIDTag algTag = nssOID_GetTag(algorithm);
    CK_MECHANISM_TYPE mech = algorithm->mechanism;

    switch (algTag) {
    /* RSA */
    case NSS_OID_PKCS1_RSA_ENCRYPTION:
    case NSS_OID_PKCS1_MD2_WITH_RSA_ENCRYPTION:
    case NSS_OID_PKCS1_MD5_WITH_RSA_ENCRYPTION:
    case NSS_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION:
    case NSS_OID_X500_RSA_ENCRYPTION:
	return set_rsa_mechanism(ap, mech, params, encodedParams, keygen);
    /* DSA */
    case NSS_OID_ANSIX9_DSA_SIGNATURE:
    case NSS_OID_ANSIX9_DSA_SIGNATURE_WITH_SHA1_DIGEST:
	return set_dsa_mechanism(ap, mech, params, encodedParams, keygen);
    case NSS_OID_X942_DIFFIE_HELLMAN_KEY:
	return set_dh_mechanism(ap, mech, params, encodedParams, keygen);
    case NSS_OID_DES_ECB:
    case NSS_OID_DES_CBC:
	return set_des_mechanism(ap, mech, params, encodedParams, keygen);
    case NSS_OID_DES_EDE3_CBC:
	return set_des3_mechanism(ap, mech, params, encodedParams, keygen);
/*
    case NSS_OID_AES_ECB:
    case NSS_OID_AES_CBC:
	return set_aes_mechanism(mechPtr, mech, parameters, arena);
*/
    case NSS_OID_RC2_CBC:
	return rc2_constructor(ap, mech, params, encodedParams, keygen);
    case NSS_OID_RC4:
	PR_ASSERT(params == NULL && encodedParams == NULL);
	ap->mechanism.mechanism = keygen ? CKM_RC4_KEY_GEN : CKM_RC4;
	break;
    case NSS_OID_RC5_CBC_PAD:
	return set_rc5_mechanism(ap, mech, params, encodedParams, keygen);
    case NSS_OID_MD5_HMAC:
    case NSS_OID_SHA1_HMAC:
	/* XXX should be doing some checking here (ever encoded?) */
	ap->mechanism.mechanism = algorithm->mechanism;
	return set_ulong_parameter(&ap->mechanism, params->hmac, ap->arena);
    case NSS_OID_PKCS5_PBE_WITH_MD2_AND_DES_CBC:
    case NSS_OID_PKCS5_PBE_WITH_MD5_AND_DES_CBC:
    case NSS_OID_PKCS5_PBE_WITH_SHA1_AND_DES_CBC:
	return pbe_constructor(ap, mech, params, encodedParams);
    default:
	if (mech != CKM_INVALID_MECHANISM) {
	    /* algorithms that need no parameters go here */
	    PR_ASSERT(params == NULL && encodedParams == NULL);
	    ap->mechanism.mechanism = mech;
	    break;
	}
	return PR_FAILURE;
    }
    return PR_SUCCESS;
}

static NSSAlgNParam *
create_algparam (
  NSSArena *arenaOpt,
  nssArenaMark **mark
)
{
    NSSArena *arena;
    NSSAlgNParam *rvAP = NULL;
    PRBool i_allocated_arena = PR_FALSE;

    if (arenaOpt) {
	arena = arenaOpt;
	*mark = nssArena_Mark(arena);
	if (!*mark) {
	    return (NSSAlgNParam *)NULL;
	}
    } else {
	arena = nssArena_Create();
	if (!arena) {
	    return (NSSAlgNParam *)NULL;
	}
	i_allocated_arena = PR_TRUE;
    }
    rvAP = nss_ZNEW(arena, NSSAlgNParam);
    if (!rvAP) {
	if (*mark) {
	    nssArena_Release(arena, *mark);
	} else {
	    nssArena_Destroy(arena);
	}
	return (NSSAlgNParam *)NULL;
    }
    rvAP->arena = arena;
    rvAP->set_template = null_settor; /* by default */
    rvAP->i_allocated_arena = i_allocated_arena;
    return rvAP;
}

static NSSAlgNParam *
finish_create_algparam (
  NSSAlgNParam *ap,
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
	ap = (NSSAlgNParam *)NULL;
    }
    return ap;
}

NSS_IMPLEMENT NSSAlgNParam *
nssAlgNParam_Create (
  NSSArena *arenaOpt,
  const NSSOID *algorithm,
  NSSParameters *parametersOpt
)
{
    PRStatus status;
    nssArenaMark *mark = NULL;
    NSSAlgNParam *rvAP = NULL;

    rvAP = create_algparam(arenaOpt, &mark);
    if (!rvAP) {
	return (NSSAlgNParam *)NULL;
    }

    status = set_cryptoki_mechanism(rvAP, algorithm, 
                                    parametersOpt, NULL, PR_FALSE);
    rvAP->alg = nssOID_GetTag(algorithm);

    return finish_create_algparam(rvAP, rvAP->arena, mark, status);
}

NSS_IMPLEMENT NSSAlgNParam *
nssAlgNParam_CreateForKeyGen (
  NSSArena *arenaOpt,
  const NSSOID *algorithm,
  NSSParameters *parametersOpt
)
{
    PRStatus status;
    nssArenaMark *mark = NULL;
    NSSAlgNParam *rvAP = NULL;

    rvAP = create_algparam(arenaOpt, &mark);
    if (!rvAP) {
	return (NSSAlgNParam *)NULL;
    }

    status = set_cryptoki_mechanism(rvAP, algorithm, 
                                    parametersOpt, NULL, PR_TRUE);
    rvAP->alg = nssOID_GetTag(algorithm);

    return finish_create_algparam(rvAP, rvAP->arena, mark, status);
}

NSS_IMPLEMENT NSSAlgNParam *
nssAlgNParam_CreateDefaultForSymKey (
  NSSArena *arenaOpt,
  NSSSymKeyType symKeyType
)
{
    NSSOID *alg;
    NSSOIDTag algTag;

    switch(symKeyType) {
    case NSSSymKeyType_RC4:       algTag = NSS_OID_RC4;     break;
    case NSSSymKeyType_TripleDES: algTag = NSS_OID_DES_EDE; break;
    case NSSSymKeyType_DES:       algTag = NSS_OID_DES_ECB; break;
    /* XXX default params for RC2, RC5, etc.? */
    default:
	/* err=params required? */
	return (NSSAlgNParam *)NULL;
    }
    alg = nssOID_CreateFromTag(algTag);
    if (!alg) {
	return (NSSAlgNParam *)NULL;
    }
    return nssAlgNParam_Create(arenaOpt, alg, NULL);
}

typedef struct {
  NSSItem algorithmOID;
  NSSItem parameters;
} nssAlgorithmID;

const NSSASN1Template nssASN1Template_AlgorithmID[] =
{
 { NSSASN1_SEQUENCE, 0, NULL, sizeof(nssAlgorithmID) },
 { NSSASN1_OBJECT_ID, offsetof(nssAlgorithmID, algorithmOID) },
 { NSSASN1_OPTIONAL |
    NSSASN1_ANY,      offsetof(nssAlgorithmID, parameters) },
 { 0 }
};

NSS_IMPLEMENT NSSAlgNParam *
nssAlgNParam_Decode (
  NSSArena *arenaOpt,
  NSSBER *algIDber
)
{
    PRStatus status;
    nssArenaMark *mark = NULL;
    NSSAlgNParam *rvAP = NULL;
    NSSOID *alg;
    nssAlgorithmID algID;
    NSSItem *params;

    nsslibc_memset(&algID, 0, sizeof(algID));

    rvAP = create_algparam(arenaOpt, &mark);
    if (!rvAP) {
	return (NSSAlgNParam *)NULL;
    }

    status = nssASN1_DecodeBER(rvAP->arena, &algID, 
                               nssASN1Template_AlgorithmID, algIDber);
    if (status == PR_FAILURE) {
	goto finish;
    }
    alg = nssOID_CreateFromBER(&algID.algorithmOID);
    if (!alg) {
	status = PR_FAILURE;
	goto finish;
    }

    /* XXX ever used for keygen? */
    params = (algID.parameters.size > 0) ? &algID.parameters : NULL;
    status = set_cryptoki_mechanism(rvAP, alg, NULL, params, PR_FALSE);
    rvAP->alg = nssOID_GetTag(alg);

finish:
    return finish_create_algparam(rvAP, rvAP->arena, mark, status);
}

NSS_IMPLEMENT NSSAlgNParam *
NSSAlgNParam_Decode (
  NSSBER *algIDber,
  NSSArena *arenaOpt
)
{
/* XXX turn this around */
    return nssAlgNParam_Decode(arenaOpt, algIDber);
}

NSS_IMPLEMENT NSSBER *
nssAlgNParam_Encode (
  const NSSAlgNParam *ap,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
    nssAlgorithmID algID;
    NSSBER *params = NULL;
    NSSBER *rvBER = NULL;
    NSSOID *algOID = nssOID_CreateFromTag(ap->alg);

    nsslibc_memset(&algID, 0, sizeof(algID));

    algID.algorithmOID = algOID->data;
    if (ap->paramTemplate) {
	params = nssASN1_EncodeItem(NULL, &algID.parameters, 
	                            &ap->params, ap->paramTemplate, 
	                            NSSASN1BER);
	if (!params) {
	    return (NSSBER *)NULL;
	}
    }
    rvBER = nssASN1_EncodeItem(arenaOpt, rvOpt, &algID,
                               nssASN1Template_AlgorithmID, NSSASN1BER);
    if (params) {
	nss_ZFreeIf(params->data);
    }
    return rvBER;
}

NSS_IMPLEMENT NSSBER *
NSSAlgNParam_Encode (
  const NSSAlgNParam *ap,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssAlgNParam_Encode(ap, rvOpt, arenaOpt);
}

NSS_IMPLEMENT void
nssAlgNParam_Destroy (
  NSSAlgNParam *ap
)
{
    if (ap && ap->i_allocated_arena) {
	nssArena_Destroy(ap->arena);
    }
}

NSS_IMPLEMENT CK_MECHANISM_PTR
nssAlgNParam_GetMechanism (
  const NSSAlgNParam *ap
)
{
    return &((NSSAlgNParam *)ap)->mechanism;
}

#if 0
This alternative does not break const-ness.
NSS_IMPLEMENT void
nssAlgNParam_GetMechanism2 (
  const NSSAlgNParam *ap,
  CK_MECHANISM_PTR pMechanism
)
{
    *pMechanism = ap->mechanism;
}
#endif

NSS_IMPLEMENT PRIntn
nssAlgNParam_SetTemplateValues (
  const NSSAlgNParam *ap,
  CK_ATTRIBUTE_PTR aTemplate,
  CK_ULONG templateSize
)
{
    return ap->set_template(ap, aTemplate, templateSize);
}

static PRStatus
copy_algparam (
  NSSAlgNParam *copy,
  const NSSAlgNParam *orig
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
    copy->alg = orig->alg;
    /* XXX copy->params = ; */
    copy->set_template = orig->set_template;
    copy->paramTemplate = orig->paramTemplate;
    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSAlgNParam *
nssAlgNParam_Clone (
  const NSSAlgNParam *ap,
  NSSArena *arenaOpt
)
{
    PRStatus status;
    nssArenaMark *mark = NULL;
    NSSAlgNParam *rvAP = NULL;

    rvAP = create_algparam(arenaOpt, &mark);
    if (!rvAP) {
	return (NSSAlgNParam *)NULL;
    }

    status = copy_algparam(rvAP, ap);

    return finish_create_algparam(rvAP, rvAP->arena, mark, status);
}

NSS_IMPLEMENT NSSOIDTag
nssAlgNParam_GetAlgorithm (
  const NSSAlgNParam *ap
)
{
    return ap->alg;
}

NSS_IMPLEMENT NSSOIDTag
NSSAlgNParam_GetAlgorithm (
  const NSSAlgNParam *ap
)
{
    return nssAlgNParam_GetAlgorithm(ap);
}


/*
 * convert a PBE mechanism used to generate a key to a crypto mechanism
 * that can use the key
 */
NSS_IMPLEMENT NSSAlgNParam *
nssAlgNParam_ConvertPBEToCrypto (
  const NSSAlgNParam *ap,
  PRBool usePadding
)
{
    PRStatus status = PR_SUCCESS;
    CK_RC2_CBC_PARAMS_PTR rc2p;
    CK_PBE_PARAMS_PTR pPBE;
    CK_MECHANISM_PTR mech;
    NSSAlgNParam *rvAP = NULL;

    rvAP = create_algparam(NULL, NULL);
    if (!rvAP) {
	return (NSSAlgNParam *)NULL;
    }
    mech = &rvAP->mechanism;
    pPBE = (CK_PBE_PARAMS_PTR)ap->mechanism.pParameter;

    switch (ap->mechanism.mechanism) {
    /* DES */
    case CKM_PBE_MD2_DES_CBC:
    case CKM_PBE_MD5_DES_CBC:
    case CKM_NETSCAPE_PBE_SHA1_DES_CBC:
	mech->mechanism = usePadding ? CKM_DES_CBC_PAD : CKM_DES_CBC;
	mech->pParameter = pPBE->pInitVector;
	mech->ulParameterLen = PBE_IV_LENGTH;
	break;
    /* Triple-DES */
    case CKM_PBE_SHA1_DES3_EDE_CBC:
    case CKM_NETSCAPE_PBE_SHA1_TRIPLE_DES_CBC:
	mech->mechanism = usePadding ? CKM_DES3_CBC_PAD : CKM_DES3_CBC;
	mech->pParameter = pPBE->pInitVector;
	mech->ulParameterLen = PBE_IV_LENGTH;
	break;
    /* RC4 */
    case CKM_PBE_SHA1_RC4_40:
    case CKM_PBE_SHA1_RC4_128:
    case CKM_NETSCAPE_PBE_SHA1_40_BIT_RC4:
    case CKM_NETSCAPE_PBE_SHA1_128_BIT_RC4:
	mech->mechanism = CKM_RC4;
	break;
    /* RC2 */
    case CKM_PBE_SHA1_RC2_40_CBC:
    case CKM_NETSCAPE_PBE_SHA1_40_BIT_RC2_CBC:
    case CKM_NETSCAPE_PBE_SHA1_128_BIT_RC2_CBC:
	mech->mechanism = (usePadding) ? CKM_RC2_CBC_PAD : CKM_RC2_CBC;
	mech->pParameter = nss_ZNEW(rvAP->arena, CK_RC2_CBC_PARAMS);
	if (mech->pParameter == NULL) {
	    status = PR_FAILURE;
	    break;
	}
	mech->ulParameterLen = (CK_ULONG)sizeof(CK_RC2_CBC_PARAMS);
	rc2p = (CK_RC2_CBC_PARAMS_PTR)mech->pParameter;
	nsslibc_memcpy(rc2p->iv, pPBE->pInitVector, PBE_IV_LENGTH);
	if (ap->mechanism.mechanism == 
	          CKM_NETSCAPE_PBE_SHA1_128_BIT_RC2_CBC) 
        {
	    rc2p->ulEffectiveBits = 128;
	} else {
	    rc2p->ulEffectiveBits = 40;
	}
	break;
    default:
	status = PR_FAILURE;
	nss_SetError(NSS_ERROR_INVALID_ALGORITHM);
	break;
    }

    return finish_create_algparam(rvAP, rvAP->arena, NULL, status);
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
  NSSParameters *params,
  NSSArena *arena
)
{
    PRStatus status;
    CK_SSL3_KEY_MAT_PARAMS *kmp;
    CK_SSL3_KEY_MAT_OUT *kmo;
    NSSSSLSessionKeyParameters *skParams = &params->sslsk;

    switch (skParams->version) {
    case NSSSSLVersion_SSLv3: 
	mechPtr->mechanism = CKM_SSL3_KEY_AND_MAC_DERIVE;
	break;
    case NSSSSLVersion_TLS:   
	mechPtr->mechanism = CKM_TLS_KEY_AND_MAC_DERIVE;
	break;
    default:
	/* XXX error invalid args */
	return PR_FAILURE;
    }

    kmp = nss_ZNEW(arena, CK_SSL3_KEY_MAT_PARAMS);
    if (!kmp) {
	return PR_FAILURE;
    }
    kmp->ulMacSizeInBits = skParams->macSizeInBits;
    kmp->ulKeySizeInBits = skParams->keySizeInBits;
    kmp->ulIVSizeInBits = skParams->ivSizeInBits;
    kmp->bIsExport = skParams->isExport;

    status = copy_item(&skParams->clientRandom,
                       &kmp->RandomInfo.pClientRandom,
                       &kmp->RandomInfo.ulClientRandomLen, arena);
    if (status == PR_FAILURE) {
	return PR_FAILURE;
    }

    status = copy_item(&skParams->serverRandom,
                       &kmp->RandomInfo.pServerRandom,
                       &kmp->RandomInfo.ulServerRandomLen, arena);
    if (status == PR_FAILURE) {
	return PR_FAILURE;
    }

    kmo = nss_ZNEW(arena, CK_SSL3_KEY_MAT_OUT);
    if (!kmo) {
	return PR_FAILURE;
    }
    kmo->pIVClient = skParams->clientIV;
    kmo->pIVServer = skParams->serverIV;
    kmp->pReturnedKeyMaterial = kmo;

    mechPtr->pParameter = kmp;
    mechPtr->ulParameterLen = sizeof(CK_SSL3_KEY_MAT_PARAMS);
    return PR_SUCCESS;
}

static void get_ssl_version(NSSSSLVersion version, CK_VERSION_PTR pv)
{
    switch (version) {
    case NSSSSLVersion_SSLv2: pv->major = 2; pv->minor = 0; break;
    case NSSSSLVersion_SSLv3: pv->major = 3; pv->minor = 0; break;
    case NSSSSLVersion_TLS:   pv->major = 3; pv->minor = 1; break;
    }
}

NSS_IMPLEMENT NSSAlgNParam *
nssAlgNParam_CreateForSSL (
  NSSArena *arenaOpt,
  NSSSSLAlgorithm alg,
  NSSParameters *params
)
{
    PRStatus status;
    CK_VERSION version;
    nssArenaMark *mark = NULL;
    NSSAlgNParam *rvAP = NULL;

    rvAP = create_algparam(arenaOpt, &mark);
    if (!rvAP) {
	return (NSSAlgNParam *)NULL;
    }

    switch (alg) {
    case NSSSSLAlgorithm_PMSGen:
	get_ssl_version(params->sslpms, &version);
	rvAP->mechanism.mechanism = CKM_SSL3_PRE_MASTER_KEY_GEN;
	status = set_version_parameter(&rvAP->mechanism, 
	                               &version, rvAP->arena);
	rvAP->params.sslpms = params->sslpms; /*XXX also below */
	break;
    case NSSSSLAlgorithm_MSDerive:
	status = set_sslms_mechanism(&rvAP->mechanism, params, rvAP->arena);
	break;
    case NSSSSLAlgorithm_SessionKeyDerive:
	status = set_sslsession_derive_mechanism(&rvAP->mechanism, 
	                                         params, rvAP->arena);
	break;
    case NSSSSLAlgorithm_MD5_MAC:
	rvAP->mechanism.mechanism = CKM_SSL3_MD5_MAC;
	status = set_ulong_parameter(&rvAP->mechanism, 
	                             params->hmac, rvAP->arena);
	break;
    case NSSSSLAlgorithm_SHA1_MAC:
	rvAP->mechanism.mechanism = CKM_SSL3_SHA1_MAC;
	status = set_ulong_parameter(&rvAP->mechanism, 
	                             params->hmac, rvAP->arena);
	break;
    case NSSSSLAlgorithm_TLS_PRF:
	/* XXX non-standard, methinks */
	rvAP->mechanism.mechanism = CKM_TLS_PRF_GENERAL;
	/* XXX no params */
	status = PR_SUCCESS;
	break;
    default:
	/* XXX err */
	return (NSSAlgNParam *)NULL;
    }

    return finish_create_algparam(rvAP, rvAP->arena, mark, status);
}

NSS_IMPLEMENT NSSAlgNParam *
NSSAlgNParam_CreateForSSL (
  NSSArena *arena,
  NSSSSLAlgorithm alg,
  NSSParameters *params
)
{
    return nssAlgNParam_CreateForSSL(arena, alg, params);
}

NSS_EXTERN NSSSSLVersion
nssAlgNParam_GetSSLVersionFromMSDerive (
  const NSSAlgNParam *ap
)
{
    CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR params;
    params = (CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR)ap->mechanism.pParameter;
    if (params->pVersion->major == 2 && params->pVersion->minor == 0) 
	return NSSSSLVersion_SSLv2;
    else if (params->pVersion->major == 3 && params->pVersion->minor == 0) 
	return NSSSSLVersion_SSLv3;
    else if (params->pVersion->major == 3 && params->pVersion->minor == 1) 
	return NSSSSLVersion_TLS;
    else return -1; /* XXX */
}

NSS_IMPLEMENT void
NSSAlgNParam_Destroy (
  NSSAlgNParam *ap
)
{
    nssAlgNParam_Destroy(ap);
}

