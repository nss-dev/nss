/*
 * Verification stuff.
 *
 * ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Netscape security libraries.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 1994-2000
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *   Dr Vipul Gupta <vipul.gupta@sun.com>, Sun Microsystems Laboratories
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */
/* $Id$ */

#include <stdio.h>
#include "cryptohi.h"
#include "sechash.h"
#include "keyhi.h"
#include "secasn1.h"
#include "secoid.h"
#include "pk11func.h"
#include "secdig.h"
#include "secerr.h"
#include "secport.h"

/*
** Decrypt signature block using public key
** Store the hash algorithm oid tag in *tagp
** Store the digest in the digest buffer
** Store the digest length in *digestlen
** XXX this is assuming that the signature algorithm has WITH_RSA_ENCRYPTION
*/
static SECStatus
DecryptSigBlock(SECOidTag *tagp, unsigned char *digest,
		unsigned int *digestlen, unsigned int maxdigestlen,
		SECKEYPublicKey *key, const SECItem *sig, char *wincx)
{
    SGNDigestInfo *di   = NULL;
    unsigned char *buf  = NULL;
    SECStatus      rv;
    SECOidTag      tag;
    SECItem        it;

    if (key == NULL) goto loser;

    it.len  = SECKEY_PublicKeyStrength(key);
    if (!it.len) goto loser;
    it.data = buf = (unsigned char *)PORT_Alloc(it.len);
    if (!buf) goto loser;

    /* decrypt the block */
    rv = PK11_VerifyRecover(key, (SECItem *)sig, &it, wincx);
    if (rv != SECSuccess) goto loser;

    di = SGN_DecodeDigestInfo(&it);
    if (di == NULL) goto sigloser;

    /*
    ** Finally we have the digest info; now we can extract the algorithm
    ** ID and the signature block
    */
    tag = SECOID_GetAlgorithmTag(&di->digestAlgorithm);
    /* Check that tag is an appropriate algorithm */
    if (tag == SEC_OID_UNKNOWN) {
	goto sigloser;
    }
    /* make sure the "parameters" are not too bogus. */
    if (di->digestAlgorithm.parameters.len > 2) {
	goto sigloser;
    }
    if (di->digest.len > maxdigestlen) {
	PORT_SetError(SEC_ERROR_OUTPUT_LEN);
	goto loser;
    }
    PORT_Memcpy(digest, di->digest.data, di->digest.len);
    *tagp = tag;
    *digestlen = di->digest.len;
    goto done;

  sigloser:
    PORT_SetError(SEC_ERROR_BAD_SIGNATURE);

  loser:
    rv = SECFailure;

  done:
    if (di   != NULL) SGN_DestroyDigestInfo(di);
    if (buf  != NULL) PORT_Free(buf);
    
    return rv;
}

typedef enum { VFY_RSA, VFY_DSA, VFY_ECDSA } VerifyType;

struct VFYContextStr {
    SECOidTag alg;  /* the hash algorithm */
    VerifyType type;
    SECKEYPublicKey *key;
    /*
     * This buffer holds either the digest or the full signature
     * depending on the type of the signature.  It is defined as a
     * union to make sure it always has enough space.
     *
     * Use the "buffer" union member to reference the buffer.
     * Note: do not take the size of the "buffer" union member.  Take
     * the size of the union or some other union member instead.
     */
    union {
	unsigned char buffer[1];

	/* the digest in the decrypted RSA signature */
	unsigned char rsadigest[HASH_LENGTH_MAX];
	/* the full DSA signature... 40 bytes */
	unsigned char dsasig[DSA_SIGNATURE_LEN];
	/* the full ECDSA signature */
	unsigned char ecdsasig[2 * MAX_ECKEY_LEN];
    } u;
    unsigned int rsadigestlen;
    void * wincx;
    void *hashcx;
    const SECHashObject *hashobj;
    SECOidTag sigAlg;  /* the (composite) signature algorithm */
    PRBool hasSignature;  /* true if the signature was provided in the
                           * VFY_CreateContext call.  If false, the
                           * signature must be provided with a
                           * VFY_EndWithSignature call. */
};

/*
 * decode the ECDSA or DSA signature from it's DER wrapping.
 * The unwrapped/raw signature is placed in the buffer pointed
 * to by dsig and has enough room for len bytes.
 */
static SECStatus
decodeECorDSASignature(SECOidTag algid, SECItem *sig, unsigned char *dsig,
		       unsigned int len) {
    SECItem *dsasig = NULL; /* also used for ECDSA */
    SECStatus rv=SECSuccess;

    switch (algid) {
    case SEC_OID_ANSIX962_ECDSA_SHA1_SIGNATURE:
    case SEC_OID_ANSIX962_ECDSA_SHA256_SIGNATURE:
    case SEC_OID_ANSIX962_ECDSA_SHA384_SIGNATURE:
    case SEC_OID_ANSIX962_ECDSA_SHA512_SIGNATURE:
    case SEC_OID_ANSIX962_ECDSA_SIGNATURE_RECOMMENDED_DIGEST:
    case SEC_OID_ANSIX962_ECDSA_SIGNATURE_SPECIFIED_DIGEST:
	if (len > MAX_ECKEY_LEN * 2) {
	    PORT_SetError(SEC_ERROR_BAD_DER);
	    return SECFailure;
	}
	/* fall through */
    case SEC_OID_ANSIX9_DSA_SIGNATURE_WITH_SHA1_DIGEST:
    case SEC_OID_BOGUS_DSA_SIGNATURE_WITH_SHA1_DIGEST:
    case SEC_OID_ANSIX9_DSA_SIGNATURE:
	dsasig = DSAU_DecodeDerSigToLen(sig, len);

	if ((dsasig == NULL) || (dsasig->len != len)) {
	    rv = SECFailure;
	} else {
	    PORT_Memcpy(dsig, dsasig->data, dsasig->len);
	}
	break;
    default:
        if (sig->len != len) {
	    rv = SECFailure;
	} else {
	    PORT_Memcpy(dsig, sig->data, sig->len);
	}
	break;
    }

    if (dsasig != NULL) SECITEM_FreeItem(dsasig, PR_TRUE);
    if (rv == SECFailure) PORT_SetError(SEC_ERROR_BAD_DER);
    return rv;
}

const static SEC_ASN1Template hashParameterTemplate[] =
{
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(SECItem) },
    { SEC_ASN1_OBJECT_ID, 0 },
    { SEC_ASN1_SKIP_REST },
    { 0, }
};
/*
 * Pulls the hash algorithm, signing algorithm, and key type out of a
 * composite algorithm.
 *
 * alg: the composite algorithm to dissect.
 * hashalg: address of a SECOidTag which will be set with the hash algorithm.
 * params:  specific signature parameter (from the signature AlgorithmID).
 * key:     public key to verify against.
 * Returns: SECSuccess if the alg algorithm was acceptable, SECFailure if the
 *	algorithm was not found or was not a signing algorithm.
 */
static SECStatus
decodeSigAlg(SECOidTag alg, const SECItem *params, const SECKEYPublicKey *key, 
	     SECOidTag *hashalg)
{
    PRArenaPool *arena;
    SECStatus rv;
    SECItem oid;
    unsigned int len;
    PR_ASSERT(hashalg!=NULL);

    switch (alg) {
      /* We probably shouldn't be generating MD2 signatures either */
      case SEC_OID_PKCS1_MD2_WITH_RSA_ENCRYPTION:
        *hashalg = SEC_OID_MD2;
	break;
      case SEC_OID_PKCS1_MD5_WITH_RSA_ENCRYPTION:
        *hashalg = SEC_OID_MD5;
	break;
      case SEC_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION:
      case SEC_OID_ISO_SHA_WITH_RSA_SIGNATURE:
        *hashalg = SEC_OID_SHA1;
	break;

      case SEC_OID_ANSIX962_ECDSA_SHA256_SIGNATURE:
      case SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION:
	*hashalg = SEC_OID_SHA256;
	break;
      case SEC_OID_ANSIX962_ECDSA_SHA384_SIGNATURE:
      case SEC_OID_PKCS1_SHA384_WITH_RSA_ENCRYPTION:
	*hashalg = SEC_OID_SHA384;
	break;
      case SEC_OID_ANSIX962_ECDSA_SHA512_SIGNATURE:
      case SEC_OID_PKCS1_SHA512_WITH_RSA_ENCRYPTION:
	*hashalg = SEC_OID_SHA512;
	break;
      case SEC_OID_ANSIX962_ECDSA_SIGNATURE_RECOMMENDED_DIGEST:
	/* This is an EC algorithm. Recommended means the largest
	 * hash algorithm that is not truncated by the keysize of 
	 * the EC algorithm. Note that key strength is in bytes and
	 * algorithms are specified in bits. Never use an algorithm
	 * weaker than sha1. */
	len = SECKEY_PublicKeyStrength((SECKEYPublicKey *)key);
	if (len < 28) { /* 28 bytes == 244 bits */
	    *hashalg = SEC_OID_SHA1;
	} else if (len < 32) { /* 32 bytes == 256 bits */
	    /* we don't support 244 bit hash algorithms */
	    PORT_SetError(SEC_ERROR_INVALID_ALGORITHM);
	    return SECFailure;
	} else if (len < 48) { /* 48 bytes == 384 bits */
	    *hashalg = SEC_OID_SHA256;
	} else if (len < 64) { /* 48 bytes == 512 bits */
	    *hashalg = SEC_OID_SHA384;
	} else {
	    /* use the largest in this case */
	    *hashalg = SEC_OID_SHA512;
	}
	break;
      case SEC_OID_ANSIX962_ECDSA_SIGNATURE_SPECIFIED_DIGEST:
	if (params == NULL) {
	    PORT_SetError(SEC_ERROR_INVALID_ALGORITHM);
	    return SECFailure;
	}
	arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	if (arena == NULL) {
	    return SECFailure;
	}
	rv = SEC_QuickDERDecodeItem(arena, &oid, hashParameterTemplate, params);
	if (rv != SECSuccess) {
	    PORT_FreeArena(arena, PR_FALSE);
	    return rv;
	}

	*hashalg = SECOID_FindOIDTag(&oid);
	PORT_FreeArena(arena, PR_FALSE);
	if (*hashalg == SEC_OID_UNKNOWN) {
	    PORT_SetError(SEC_ERROR_INVALID_ALGORITHM);
	    return SECFailure;
	}
	break;

      /* what about normal DSA? */
      case SEC_OID_ANSIX9_DSA_SIGNATURE_WITH_SHA1_DIGEST:
      case SEC_OID_BOGUS_DSA_SIGNATURE_WITH_SHA1_DIGEST:
      case SEC_OID_ANSIX962_ECDSA_SHA1_SIGNATURE:
        *hashalg = SEC_OID_SHA1;
	break;
      case SEC_OID_MISSI_DSS:
      case SEC_OID_MISSI_KEA_DSS:
      case SEC_OID_MISSI_KEA_DSS_OLD:
      case SEC_OID_MISSI_DSS_OLD:
        *hashalg = SEC_OID_SHA1;
	break;
      /* we don't implement MD4 hashes */
      case SEC_OID_PKCS1_MD4_WITH_RSA_ENCRYPTION:
      default:
	return SECFailure;
    }
    return SECSuccess;
}

static VFYContext *
vfy_CreateContextPrivate(const SECKEYPublicKey *key, const SECItem *sig, 
		  SECOidTag algid, const SECItem *params, void *wincx)
{
    VFYContext *cx;
    SECStatus rv;
    unsigned int sigLen;

    cx = (VFYContext*) PORT_ZAlloc(sizeof(VFYContext));
    if (cx) {
        cx->wincx = wincx;
	cx->hasSignature = (sig != NULL);
	cx->sigAlg = algid;
	rv = SECSuccess;
	switch (key->keyType) {
	case rsaKey:
	    cx->type = VFY_RSA;
	    /* keep our own copy */
	    cx->key = SECKEY_CopyPublicKey((SECKEYPublicKey *)key); 
	    if (sig) {
		SECOidTag hashid = SEC_OID_UNKNOWN;
		unsigned int digestlen = 0;
	    	rv = DecryptSigBlock(&hashid, cx->u.buffer, &digestlen,
			HASH_LENGTH_MAX, cx->key, sig, (char*)wincx);
		cx->alg = hashid;
		cx->rsadigestlen = digestlen;
	    } else {
		rv = decodeSigAlg(algid, params, key, &cx->alg);
	    }
	    break;
	case fortezzaKey:
	case dsaKey:
	case ecKey:
	    if (key->keyType == ecKey) {
	        cx->type = VFY_ECDSA;
		/* Unlike DSA, ECDSA does not have a fixed signature length
		 * (it depends on the key size)
		 */
		sigLen = SECKEY_SignatureLen(key);
	    } else {
	        cx->type = VFY_DSA;
		sigLen = DSA_SIGNATURE_LEN;
	    }
	    if (sigLen == 0) {
		rv = SECFailure;
		break;
	    }
	    rv = decodeSigAlg(algid, params, key, &cx->alg);
	    if (rv != SECSuccess) {
		break;
	    }
  	    cx->key = SECKEY_CopyPublicKey((SECKEYPublicKey *)key);
  	    if (sig) {
	        rv = decodeECorDSASignature(algid,sig,cx->u.buffer,sigLen);
  	    }
  	    break;
	default:
	    rv = SECFailure;
	    break;
	}
	if (rv) goto loser;
	switch (cx->alg) {
	case SEC_OID_MD2:
	case SEC_OID_MD5:
	case SEC_OID_SHA1:
	case SEC_OID_SHA256:
	case SEC_OID_SHA384:
	case SEC_OID_SHA512:
	    break;
	default:
	    PORT_SetError(SEC_ERROR_INVALID_ALGORITHM);
	    goto loser;
	}
    }
    return cx;

  loser:
    VFY_DestroyContext(cx, PR_TRUE);
    return 0;
}

VFYContext *
VFY_CreateContext(SECKEYPublicKey *key, SECItem *sig, SECOidTag algid,
		  void *wincx)
{
   return vfy_CreateContextPrivate(key, sig, algid, NULL, wincx);
}

void
VFY_DestroyContext(VFYContext *cx, PRBool freeit)
{
    if (cx) {
	if (cx->hashcx != NULL) {
	    (*cx->hashobj->destroy)(cx->hashcx, PR_TRUE);
	    cx->hashcx = NULL;
	}
	if (cx->key) {
	    SECKEY_DestroyPublicKey(cx->key);
	}
	if (freeit) {
	    PORT_ZFree(cx, sizeof(VFYContext));
	}
    }
}

SECStatus
VFY_Begin(VFYContext *cx)
{
    if (cx->hashcx != NULL) {
	(*cx->hashobj->destroy)(cx->hashcx, PR_TRUE);
	cx->hashcx = NULL;
    }

    cx->hashobj = HASH_GetHashObjectByOidTag(cx->alg);
    if (!cx->hashobj) 
	return SECFailure;	/* error code is set */

    cx->hashcx = (*cx->hashobj->create)();
    if (cx->hashcx == NULL)
	return SECFailure;

    (*cx->hashobj->begin)(cx->hashcx);
    return SECSuccess;
}

SECStatus
VFY_Update(VFYContext *cx, unsigned char *input, unsigned inputLen)
{
    if (cx->hashcx == NULL) {
	PORT_SetError(SEC_ERROR_INVALID_ARGS);
	return SECFailure;
    }
    (*cx->hashobj->update)(cx->hashcx, input, inputLen);
    return SECSuccess;
}

SECStatus
VFY_EndWithSignature(VFYContext *cx, SECItem *sig)
{
    unsigned char final[HASH_LENGTH_MAX];
    unsigned part;
    SECItem hash,dsasig; /* dsasig is also used for ECDSA */
    SECStatus rv;

    if ((cx->hasSignature == PR_FALSE) && (sig == NULL)) {
	PORT_SetError(SEC_ERROR_INVALID_ARGS);
	return SECFailure;
    }

    if (cx->hashcx == NULL) {
	PORT_SetError(SEC_ERROR_INVALID_ARGS);
	return SECFailure;
    }
    (*cx->hashobj->end)(cx->hashcx, final, &part, sizeof(final));
    switch (cx->type) {
      case VFY_DSA:
      case VFY_ECDSA:
	dsasig.data = cx->u.buffer;
	if (cx->type == VFY_DSA) {
	    dsasig.len = DSA_SIGNATURE_LEN;
	} else {
	    dsasig.len = SECKEY_SignatureLen(cx->key);
	}
	if (dsasig.len == 0) {
	    return SECFailure;
	}
	if (sig) {
	    rv = decodeECorDSASignature(cx->sigAlg,sig,dsasig.data,
					dsasig.len);
	    if (rv != SECSuccess) {
		PORT_SetError(SEC_ERROR_BAD_SIGNATURE);
		return SECFailure;
	    }
	} 
	hash.data = final;
	hash.len = part;
	if (PK11_Verify(cx->key,&dsasig,&hash,cx->wincx) != SECSuccess) {
		PORT_SetError(SEC_ERROR_BAD_SIGNATURE);
		return SECFailure;
	}
	break;
      case VFY_RSA:
	if (sig) {
	    SECOidTag hashid = SEC_OID_UNKNOWN;
	    rv = DecryptSigBlock(&hashid, cx->u.buffer, &cx->rsadigestlen,
		    HASH_LENGTH_MAX, cx->key, sig, (char*)cx->wincx);
	    if ((rv != SECSuccess) || (hashid != cx->alg)) {
		PORT_SetError(SEC_ERROR_BAD_SIGNATURE);
		return SECFailure;
	    }
	}
	if ((part != cx->rsadigestlen) ||
		PORT_Memcmp(final, cx->u.buffer, part)) {
	    PORT_SetError(SEC_ERROR_BAD_SIGNATURE);
	    return SECFailure;
	}
	break;
      default:
	PORT_SetError(SEC_ERROR_BAD_SIGNATURE);
	return SECFailure; /* shouldn't happen */
    }
    return SECSuccess;
}

SECStatus
VFY_End(VFYContext *cx)
{
    return VFY_EndWithSignature(cx,NULL);
}

/************************************************************************/
/*
 * Verify that a previously-computed digest matches a signature.
 * XXX This should take a parameter that specifies the digest algorithm,
 * and we should compare that the algorithm found in the DigestInfo
 * matches it!
 */
SECStatus
VFY_VerifyDigest(SECItem *digest, SECKEYPublicKey *key, SECItem *sig,
		 SECOidTag algid, void *wincx)
{
    SECStatus rv;
    VFYContext *cx;
    SECItem dsasig; /* also used for ECDSA */

    rv = SECFailure;

    cx = VFY_CreateContext(key, sig, algid, wincx);
    if (cx != NULL) {
	switch (key->keyType) {
	case rsaKey:
	    if ((digest->len != cx->rsadigestlen) ||
		PORT_Memcmp(digest->data, cx->u.buffer, digest->len)) {
		PORT_SetError(SEC_ERROR_BAD_SIGNATURE);
	    } else {
		rv = SECSuccess;
	    }
	    break;
	case fortezzaKey:
	case dsaKey:
	case ecKey:
	    dsasig.data = cx->u.buffer;
	    if (key->keyType == ecKey) {
		dsasig.len = SECKEY_SignatureLen(cx->key);
	    } else {
		/* magic size of dsa signature */
		dsasig.len = DSA_SIGNATURE_LEN;
	    }
	    if (dsasig.len == 0) {
		break;
	    }
	    if (PK11_Verify(cx->key, &dsasig, digest, cx->wincx)
		!= SECSuccess) {
		PORT_SetError(SEC_ERROR_BAD_SIGNATURE);
	    } else {
		rv = SECSuccess;
	    }
	    break;
	default:
	    break;
	}
	VFY_DestroyContext(cx, PR_TRUE);
    }
    return rv;
}

static SECStatus
vfy_VerifyDataPrivate(const unsigned char *buf, int len, 
		const SECKEYPublicKey *key, const SECItem *sig, 
		SECOidTag algid, const SECItem *params, void *wincx)
{
    SECStatus rv;
    VFYContext *cx;

    cx = vfy_CreateContextPrivate(key, sig, algid, params, wincx);
    if (cx == NULL)
	return SECFailure;

    rv = VFY_Begin(cx);
    if (rv == SECSuccess) {
	rv = VFY_Update(cx, (unsigned char *)buf, len);
	if (rv == SECSuccess)
	    rv = VFY_End(cx);
    }

    VFY_DestroyContext(cx, PR_TRUE);
    return rv;
}

SECStatus
VFY_VerifyData(unsigned char *buf, int len, SECKEYPublicKey *key,
	       SECItem *sig, SECOidTag algid, void *wincx)
{
    return vfy_VerifyDataPrivate(buf, len, key, sig, algid, NULL, wincx);
}

/*
 * this function is private to nss3.dll in NSS 3.11
 */
SECStatus
VFY_VerifyDataWithAlgorithmID(const unsigned char *buf, int len,
                              const SECKEYPublicKey *key,
                              const SECItem *sig,
                              const SECAlgorithmID *sigAlgorithm,
                              SECOidTag *reserved, void *wincx)
{
    /* the hash parameter is only provided to match the NSS 3.12 signature */
    PORT_Assert(reserved == NULL);
    if (reserved) {
	/* shouldn't happen, This function is not exported, and the only
	 * NSS callers pass 'NULL' */
	PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
	return SECFailure;
    }
    return vfy_VerifyDataPrivate(buf, len, key, sig, 
           SECOID_GetAlgorithmTag((SECAlgorithmID *)sigAlgorithm),
           &sigAlgorithm->parameters, wincx);
}

