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

struct NSSAlgorithmAndParametersStr
{
  NSSArena *arena;
  CK_MECHANISM mechanism;
  NSSAlgorithmType algorithm;
  NSSParameters params;
  PRBool isKeyGen;
  unsigned char rsape[4]; /* XXX hack to make RSA easier */
};

static const NSSAlgorithmAndParameters s_deskg = {
  NULL,
  { CKM_DES_KEY_GEN, NULL, 0 }
};

static const NSSAlgorithmAndParameters s_3deskg = {
  NULL,
  { CKM_DES3_KEY_GEN, NULL, 0 }
};

static const NSSAlgorithmAndParameters s_rc2kg = {
  NULL,
  { CKM_RC2_KEY_GEN, NULL, 0 }
};

static const NSSAlgorithmAndParameters s_rc4kg = {
  NULL,
  { CKM_RC4_KEY_GEN, NULL, 0 }
};

static const NSSAlgorithmAndParameters s_rc5kg = {
  NULL,
  { CKM_RC5_KEY_GEN, NULL, 0 }
};

static const NSSAlgorithmAndParameters s_aeskg = {
  NULL,
  { CKM_AES_KEY_GEN, NULL, 0 }
};

static const NSSAlgorithmAndParameters s_md2 = {
  NULL,
  { CKM_MD2, NULL, 0 }
};

static const NSSAlgorithmAndParameters s_md5 = {
  NULL,
  { CKM_MD5, NULL, 0 }
};

const NSSAlgorithmAndParameters s_sha1 = {
  NULL,
  { CKM_SHA_1, NULL, 0 }
};

NSS_IMPLEMENT_DATA const NSSAlgorithmAndParameters *
                    NSSAlgorithmAndParameters_DESKeyGen = &s_deskg;

NSS_IMPLEMENT_DATA const NSSAlgorithmAndParameters *
                    NSSAlgorithmAndParameters_3DESKeyGen = &s_3deskg;

NSS_IMPLEMENT_DATA const NSSAlgorithmAndParameters *
                    NSSAlgorithmAndParameters_RC2KeyGen = &s_rc2kg;

NSS_IMPLEMENT_DATA const NSSAlgorithmAndParameters *
                    NSSAlgorithmAndParameters_RC4KeyGen = &s_rc4kg;

NSS_IMPLEMENT_DATA const NSSAlgorithmAndParameters *
                    NSSAlgorithmAndParameters_RC5KeyGen = &s_rc5kg;

NSS_IMPLEMENT_DATA const NSSAlgorithmAndParameters *
                    NSSAlgorithmAndParameters_AESKeyGen = &s_aeskg;

NSS_IMPLEMENT_DATA const NSSAlgorithmAndParameters *
                    NSSAlgorithmAndParameters_MD2  = &s_md2;

NSS_IMPLEMENT_DATA const NSSAlgorithmAndParameters *
                    NSSAlgorithmAndParameters_MD5  = &s_md5;

NSS_IMPLEMENT_DATA const NSSAlgorithmAndParameters *
                    NSSAlgorithmAndParameters_SHA1 = &s_sha1;

static PRStatus
set_rsa_mechanism
(
  CK_MECHANISM_PTR mechPtr,
  NSSAlgorithmType algorithm,
  NSSParameters *parameters
)
{
    NSSParameters defaultParams;
    if (!parameters) {
	defaultParams.rsa = NSSRSABlockFormat_RAW;
	parameters = &defaultParams;
    }
    switch (parameters->rsa) {
    case NSSRSABlockFormat_RAW:
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

static PRStatus
set_dsa_mechanism
(
  CK_MECHANISM_PTR mechPtr,
  NSSAlgorithmType algorithm,
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

static PRStatus
set_dh_mechanism
(
  CK_MECHANISM_PTR mechPtr,
  NSSAlgorithmType algorithm,
  NSSParameters *parameters
)
{
    return PR_SUCCESS;
}

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

static PRStatus
set_des_mechanism
(
  CK_MECHANISM_PTR mechPtr,
  NSSAlgorithmType algorithm,
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

static PRStatus
set_des3_mechanism
(
  CK_MECHANISM_PTR mechPtr,
  NSSAlgorithmType algorithm,
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

static PRStatus
set_aes_mechanism
(
  CK_MECHANISM_PTR mechPtr,
  NSSAlgorithmType algorithm,
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

static PRStatus
set_rc2_mechanism
(
  CK_MECHANISM_PTR mechPtr,
  NSSAlgorithmType algorithm,
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

static PRStatus
set_rc5_mechanism
(
  CK_MECHANISM_PTR mechPtr,
  NSSAlgorithmType algorithm,
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
	return set_rsa_mechanism(mechPtr, algorithm, parameters);
    case NSSAlgorithmType_DSA:
	return set_dsa_mechanism(mechPtr, algorithm, parameters);
    case NSSAlgorithmType_DH:
	return set_dh_mechanism(mechPtr, algorithm, parameters);
    case NSSAlgorithmType_DES:
	return set_des_mechanism(mechPtr, algorithm, parameters, arena);
    case NSSAlgorithmType_3DES:
	return set_des3_mechanism(mechPtr, algorithm, parameters, arena);
    case NSSAlgorithmType_AES:
	return set_aes_mechanism(mechPtr, algorithm, parameters, arena);
    case NSSAlgorithmType_RC2:
	return set_rc2_mechanism(mechPtr, algorithm, parameters, arena);
    case NSSAlgorithmType_RC4:
	mechPtr->mechanism = CKM_RC4;
	break;
    case NSSAlgorithmType_RC5:
	return set_rc5_mechanism(mechPtr, algorithm, parameters, arena);
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

static PRStatus
set_cryptoki_mechanism_for_keygen
(
  NSSAlgorithmAndParameters *ap,
  NSSAlgorithmType algorithm,
  NSSParameters *parameters
)
{
    CK_MECHANISM_PTR mechPtr = &ap->mechanism;
    switch (algorithm) {
    case NSSAlgorithmType_RSA:
	mechPtr->mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
	ap->params.rsakg = parameters->rsakg;
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
copy_algparam
(
  NSSAlgorithmAndParameters *copy,
  const NSSAlgorithmAndParameters *orig
)
{
    copy->algorithm = orig->algorithm;
    copy->isKeyGen = orig->isKeyGen;
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
    if (orig->isKeyGen) {
	set_cryptoki_mechanism_for_keygen(copy, orig->algorithm, 
	                                  (NSSParameters *)&orig->params);
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSAlgorithmAndParameters *
create_algparam
(
  NSSArena *arenaOpt,
  NSSAlgorithmType algorithm,
  NSSParameters *parametersOpt,
  PRBool forKeyGen,
  const NSSAlgorithmAndParameters *originalOpt
)
{
    PRStatus status;
    NSSArena *arena;
    nssArenaMark *mark = NULL;
    NSSAlgorithmAndParameters *rvAP = NULL;
    if (arenaOpt) {
	arena = arenaOpt;
	mark = nssArena_Mark(arena);
	if (!mark) {
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
	goto loser;
    }
    rvAP->algorithm = algorithm;
    if (forKeyGen) {
	status = set_cryptoki_mechanism_for_keygen(rvAP,
	                                           algorithm, parametersOpt);
	rvAP->isKeyGen = PR_TRUE;
    } else if (!originalOpt) {
	status = set_cryptoki_mechanism(&rvAP->mechanism, 
	                                algorithm, parametersOpt, arena);
	rvAP->isKeyGen = PR_FALSE;
    } else {
	status = copy_algparam(rvAP, originalOpt);
    }
    if (status != PR_SUCCESS) {
	goto loser;
    }
    if (mark) {
	nssArena_Unmark(arena, mark);
    } else {
	rvAP->arena = arena;
    }
    return rvAP;
loser:
    if (mark) {
	nssArena_Release(arena, mark);
    } else {
	nssArena_Destroy(arena);
    }
    return (NSSAlgorithmAndParameters *)NULL;
}

NSS_IMPLEMENT NSSAlgorithmAndParameters *
nssAlgorithmAndParameters_Create
(
  NSSArena *arenaOpt,
  NSSAlgorithmType algorithm,
  NSSParameters *parametersOpt
)
{
    return create_algparam(arenaOpt, algorithm, parametersOpt, 
                           PR_FALSE, NULL);
}

NSS_IMPLEMENT NSSAlgorithmAndParameters *
nssAlgorithmAndParameters_CreateKeyGen
(
  NSSArena *arenaOpt,
  NSSAlgorithmType algorithm,
  NSSParameters *parametersOpt
)
{
    return create_algparam(arenaOpt, algorithm, parametersOpt, 
                           PR_TRUE, NULL);
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

/* returns the number of template values set */
NSS_IMPLEMENT PRUint32
nssAlgorithmAndParameters_SetTemplateValues
(
  const NSSAlgorithmAndParameters *ap,
  CK_ATTRIBUTE_PTR aTemplate,
  CK_ULONG templateSize
)
{
    CK_ATTRIBUTE_PTR attr = aTemplate;
    switch(ap->algorithm) {
    case NSSAlgorithmType_RSA: 
	if (ap->isKeyGen) {
	    PRUint32 tmp;
	    /* set the modulus bits parameter in the template */
	    NSS_CK_SET_ATTRIBUTE_VAR(attr, CKA_MODULUS_BITS,
	                             ap->params.rsakg.modulusBits);
	    /* set the public exponent parameter in the template */
	    tmp = PR_htonl(ap->params.rsakg.publicExponent);
	    nsslibc_memcpy((void *)ap->rsape, &tmp, sizeof(tmp));
	    attr->type = CKA_PUBLIC_EXPONENT; 
	    attr->pValue = (CK_BYTE_PTR)ap->rsape;
	    attr->ulValueLen = sizeof(ap->rsape);
	    attr++;
	}
	break;
    case NSSAlgorithmType_DSA:
	if (ap->isKeyGen) {
	    if (ap->params.dsakg.p.data == NULL) {
		/* XXX ? */
		PR_ASSERT(0);
	    } else {
		/* P */
		NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_PRIME,
		                          &ap->params.dsakg.p);
		/* Q */
		NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_SUBPRIME,
		                          &ap->params.dsakg.q);
		/* G */
		NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_BASE,
		                          &ap->params.dsakg.g);
	    }
	}
	break;
    case NSSAlgorithmType_DH:
	if (ap->isKeyGen) {
	    if (ap->params.dhkg.p.data == NULL) {
		/* XXX ? */
		PR_ASSERT(0);
	    } else {
		/* P */
		NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_PRIME,
		                          &ap->params.dhkg.p);
		/* G */
		NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_BASE,
		                          &ap->params.dhkg.g);
		/* constraint on private value */
		NSS_CK_SET_ATTRIBUTE_VAR(attr, CKA_VALUE_BITS,
		                         ap->params.dhkg.valueBits);
	    }
	}
	break;
    default:
	break;
    }
    return attr - aTemplate;
}

NSS_IMPLEMENT NSSAlgorithmAndParameters *
nssAlgorithmAndParameters_Clone
(
  const NSSAlgorithmAndParameters *ap,
  NSSArena *arenaOpt
)
{
    return create_algparam(arenaOpt, ap->algorithm, NULL, PR_FALSE, ap);
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
NSSAlgorithmAndParameters_CreateKeyGen
(
  NSSArena *arenaOpt,
  NSSAlgorithmType algorithm,
  NSSParameters *parametersOpt
)
{
    return nssAlgorithmAndParameters_CreateKeyGen(arenaOpt, 
                                                  algorithm, 
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

