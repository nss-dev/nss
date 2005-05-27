/*
 * SSL3 Protocol
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
 *   Dr Vipul Gupta <vipul.gupta@sun.com> and
 *   Douglas Stebila <douglas@stebila.ca>, Sun Microsystems Laboratories
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

/* ECC code moved here from ssl3con.c */
/* $Id$ */

#ifdef NSS_ENABLE_ECC

#include "nssrenam.h"
#include "cert.h"
#include "ssl.h"
#include "cryptohi.h"	/* for DSAU_ stuff */
#include "keyhi.h"
#include "secder.h"
#include "secitem.h"

#include "sslimpl.h"
#include "sslproto.h"
#include "sslerr.h"
#include "prtime.h"
#include "prinrval.h"
#include "prerror.h"
#include "pratom.h"
#include "prthread.h"

#include "pk11func.h"
#include "secmod.h"
#include "nsslocks.h"
#include "ec.h"
#ifdef PK11_BYPASS
#include "blapi.h"
#endif

#include <stdio.h>

#ifndef PK11_SETATTRS
#define PK11_SETATTRS(x,id,v,l) (x)->type = (id); \
		(x)->pValue=(v); (x)->ulValueLen = (l);
#endif

/* Types and names of elliptic curves used in TLS */
typedef enum { ec_type_explicitPrime = 1,
	       ec_type_explicitChar2Curve,
	       ec_type_named
} ECType;

typedef enum { ec_noName = 0,
	       ec_sect163k1, ec_sect163r1, ec_sect163r2,
	       ec_sect193r1, ec_sect193r2, ec_sect233k1,
	       ec_sect233r1, ec_sect239k1, ec_sect283k1,
	       ec_sect283r1, ec_sect409k1, ec_sect409r1,
	       ec_sect571k1, ec_sect571r1, ec_secp160k1,
	       ec_secp160r1, ec_secp160r2, ec_secp192k1,
	       ec_secp192r1, ec_secp224k1, ec_secp224r1,
	       ec_secp256k1, ec_secp256r1, ec_secp384r1,
	       ec_secp521r1,
	       ec_pastLastName
} ECName;

#define supportedCurve(x) (((x) > ec_noName) && ((x) < ec_pastLastName))

/* Table containing OID tags for elliptic curves named in the
 * ECC-TLS IETF draft.
 */
static const SECOidTag ecName2OIDTag[] = {
	0,  
	SEC_OID_SECG_EC_SECT163K1,  /*  1 */
	SEC_OID_SECG_EC_SECT163R1,  /*  2 */
	SEC_OID_SECG_EC_SECT163R2,  /*  3 */
	SEC_OID_SECG_EC_SECT193R1,  /*  4 */
	SEC_OID_SECG_EC_SECT193R2,  /*  5 */
	SEC_OID_SECG_EC_SECT233K1,  /*  6 */
	SEC_OID_SECG_EC_SECT233R1,  /*  7 */
	SEC_OID_SECG_EC_SECT239K1,  /*  8 */
	SEC_OID_SECG_EC_SECT283K1,  /*  9 */
	SEC_OID_SECG_EC_SECT283R1,  /* 10 */
	SEC_OID_SECG_EC_SECT409K1,  /* 11 */
	SEC_OID_SECG_EC_SECT409R1,  /* 12 */
	SEC_OID_SECG_EC_SECT571K1,  /* 13 */
	SEC_OID_SECG_EC_SECT571R1,  /* 14 */
	SEC_OID_SECG_EC_SECP160K1,  /* 15 */
	SEC_OID_SECG_EC_SECP160R1,  /* 16 */
	SEC_OID_SECG_EC_SECP160R2,  /* 17 */
	SEC_OID_SECG_EC_SECP192K1,  /* 18 */
	SEC_OID_SECG_EC_SECP192R1,  /* 19 */
	SEC_OID_SECG_EC_SECP224K1,  /* 20 */
	SEC_OID_SECG_EC_SECP224R1,  /* 21 */
	SEC_OID_SECG_EC_SECP256K1,  /* 22 */
	SEC_OID_SECG_EC_SECP256R1,  /* 23 */
	SEC_OID_SECG_EC_SECP384R1,  /* 24 */
	SEC_OID_SECG_EC_SECP521R1,  /* 25 */
};

static SECStatus 
ecName2params(PRArenaPool * arena, ECName curve, SECKEYECParams * params)
{
    SECOidData *oidData = NULL;

    if ((curve <= ec_noName) || (curve >= ec_pastLastName) ||
	((oidData = SECOID_FindOIDByTag(ecName2OIDTag[curve])) == NULL)) {
        PORT_SetError(SEC_ERROR_UNSUPPORTED_ELLIPTIC_CURVE);
	return SECFailure;
    }

    SECITEM_AllocItem(arena, params, (2 + oidData->oid.len));
    /* 
     * params->data needs to contain the ASN encoding of an object ID (OID)
     * representing the named curve. The actual OID is in 
     * oidData->oid.data so we simply prepend 0x06 and OID length
     */
    params->data[0] = SEC_ASN1_OBJECT_ID;
    params->data[1] = oidData->oid.len;
    memcpy(params->data + 2, oidData->oid.data, oidData->oid.len);

    return SECSuccess;
}

static ECName 
params2ecName(SECKEYECParams * params)
{
    SECItem oid = { siBuffer, NULL, 0};
    SECOidData *oidData = NULL;
    ECName i;

    /* 
     * params->data needs to contain the ASN encoding of an object ID (OID)
     * representing a named curve. Here, we strip away everything
     * before the actual OID and use the OID to look up a named curve.
     */
    if (params->data[0] != SEC_ASN1_OBJECT_ID) return ec_noName;
    oid.len = params->len - 2;
    oid.data = params->data + 2;
    if ((oidData = SECOID_FindOID(&oid)) == NULL) return ec_noName;
    for (i = ec_noName + 1; i < ec_pastLastName; i++) {
	if (ecName2OIDTag[i] == oidData->offset)
	    return i;
    }

    return ec_noName;
}

/* Caller must set hiLevel error code. */
static SECStatus
ssl3_ComputeECDHKeyHash(SECItem ec_params, SECItem server_ecpoint,
			     SSL3Random *client_rand, SSL3Random *server_rand,
			     SSL3Hashes *hashes)
{
    PRUint8     * hashBuf;
    PRUint8     * pBuf;
    SECStatus     rv 		= SECSuccess;
    unsigned int  bufLen;
    /*
     * XXX For now, we only support named curves (the appropriate
     * checks are made before this method is called) so ec_params
     * takes up only two bytes. ECPoint needs to fit in 256 bytes
     * (because the spec says the length must fit in one byte)
     */
    PRUint8       buf[2*SSL3_RANDOM_LENGTH + 2 + 1 + 256];

    bufLen = 2*SSL3_RANDOM_LENGTH + ec_params.len + 1 + server_ecpoint.len;
    if (bufLen <= sizeof buf) {
    	hashBuf = buf;
    } else {
    	hashBuf = PORT_Alloc(bufLen);
	if (!hashBuf) {
	    return SECFailure;
	}
    }

    memcpy(hashBuf, client_rand, SSL3_RANDOM_LENGTH); 
    	pBuf = hashBuf + SSL3_RANDOM_LENGTH;
    memcpy(pBuf, server_rand, SSL3_RANDOM_LENGTH);
    	pBuf += SSL3_RANDOM_LENGTH;
    memcpy(pBuf, ec_params.data, ec_params.len);
    	pBuf += ec_params.len;
    pBuf[0] = (PRUint8)(server_ecpoint.len);
    pBuf += 1;
    memcpy(pBuf, server_ecpoint.data, server_ecpoint.len);
    	pBuf += server_ecpoint.len;
    PORT_Assert((unsigned int)(pBuf - hashBuf) == bufLen);

    rv = PK11_HashBuf(SEC_OID_MD5, hashes->md5, hashBuf, bufLen);
    if (rv != SECSuccess) {
	ssl_MapLowLevelError(SSL_ERROR_MD5_DIGEST_FAILURE);
    	rv = SECFailure;
	goto done;
    }

    rv = PK11_HashBuf(SEC_OID_SHA1, hashes->sha, hashBuf, bufLen);
    if (rv != SECSuccess) {
	ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
    	rv = SECFailure;
	goto done;
    }

    PRINT_BUF(95, (NULL, "ECDHkey hash: ", hashBuf, bufLen));
    PRINT_BUF(95, (NULL, "ECDHkey hash: MD5 result", hashes->md5, MD5_LENGTH));
    PRINT_BUF(95, (NULL, "ECDHkey hash: SHA1 result", hashes->sha, SHA1_LENGTH));

done:
    if (hashBuf != buf && hashBuf != NULL)
    	PORT_Free(hashBuf);
    return rv;
}


/* Called from ssl3_SendClientKeyExchange(). */
static SECStatus
sendECDHClientKeyExchange(sslSocket * ss, SECKEYPublicKey * svrPubKey)
{
    PK11SymKey *	pms 		= NULL;
    SECStatus           rv    		= SECFailure;
    PRBool              isTLS;
    CK_MECHANISM_TYPE	target;
    SECKEYPublicKey	*pubKey = NULL;		/* Ephemeral ECDH key */
    SECKEYPrivateKey	*privKey = NULL;	/* Ephemeral ECDH key */
    CK_EC_KDF_TYPE	kdf;

    PORT_Assert( ssl_HaveSSL3HandshakeLock(ss) );
    PORT_Assert( ssl_HaveXmitBufLock(ss));

    isTLS = (PRBool)(ss->ssl3.pwSpec->version > SSL_LIBRARY_VERSION_3_0);

    /* Generate ephemeral EC keypair */
    privKey = SECKEY_CreateECPrivateKey(&svrPubKey->u.ec.DEREncodedParams, 
	                                &pubKey, NULL);
    if (!privKey || !pubKey) {
	    ssl_MapLowLevelError(SEC_ERROR_KEYGEN_FAIL);
	    rv = SECFailure;
	    goto loser;
    }
    PRINT_BUF(50, (ss, "ECDH public value:",
					pubKey->u.ec.publicValue.data,
					pubKey->u.ec.publicValue.len));

    if (isTLS) target = CKM_TLS_MASTER_KEY_DERIVE_DH;
    else target = CKM_SSL3_MASTER_KEY_DERIVE_DH;

    /* If field size is not more than 24 octets, then use SHA-1 hash of result;
     * otherwise, use result (see section 4.8 of draft-ietf-tls-ecc-03.txt).
     */
    if ((pubKey->u.ec.publicValue.len - 1) / 2 <= 24) {
	kdf = CKD_SHA1_KDF;
    } else {
	kdf = CKD_NULL;
    }

    /*  Determine the PMS */
    pms = PK11_PubDeriveWithKDF(privKey, svrPubKey, PR_FALSE, NULL, NULL,
			    CKM_ECDH1_DERIVE, target, CKA_DERIVE, 0,
			    kdf, NULL, NULL);

    if (pms == NULL) {
	ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	goto loser;
    }

    SECKEY_DestroyPrivateKey(privKey);
    privKey = NULL;

    rv = ssl3_InitPendingCipherSpec(ss,  pms);
    PK11_FreeSymKey(pms); pms = NULL;

    if (rv != SECSuccess) {
	ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	goto loser;
    }

    rv = ssl3_AppendHandshakeHeader(ss, client_key_exchange, 
					pubKey->u.ec.publicValue.len + 1);
    if (rv != SECSuccess) {
        goto loser;	/* err set by ssl3_AppendHandshake* */
    }

    rv = ssl3_AppendHandshakeVariable(ss, 
					pubKey->u.ec.publicValue.data,
					pubKey->u.ec.publicValue.len, 1);
    SECKEY_DestroyPublicKey(pubKey);
    pubKey = NULL;

    if (rv != SECSuccess) {
        goto loser;	/* err set by ssl3_AppendHandshake* */
    }

    rv = SECSuccess;

loser:
    if(pms) PK11_FreeSymKey(pms);
    if(privKey) SECKEY_DestroyPrivateKey(privKey);
    if(pubKey) SECKEY_DestroyPublicKey(pubKey);
    return rv;
}


/*
** Called from ssl3_HandleClientKeyExchange()
*/
static SECStatus
ssl3_HandleECDHClientKeyExchange(sslSocket *ss, SSL3Opaque *b,
				     PRUint32 length,
                                     SECKEYPublicKey *srvrPubKey,
                                     SECKEYPrivateKey *srvrPrivKey)
{
    PK11SymKey *      pms;
    SECStatus         rv;
    SECKEYPublicKey   clntPubKey;
    CK_MECHANISM_TYPE	target;
    PRBool isTLS;
    CK_EC_KDF_TYPE	kdf;

    PORT_Assert( ssl_HaveRecvBufLock(ss) );
    PORT_Assert( ssl_HaveSSL3HandshakeLock(ss) );

    clntPubKey.keyType = ecKey;
    clntPubKey.u.ec.DEREncodedParams.len = 
	srvrPubKey->u.ec.DEREncodedParams.len;
    clntPubKey.u.ec.DEREncodedParams.data = 
	srvrPubKey->u.ec.DEREncodedParams.data;

    rv = ssl3_ConsumeHandshakeVariable(ss, &clntPubKey.u.ec.publicValue, 
	                               1, &b, &length);
    if (rv != SECSuccess) {
	SEND_ALERT
	return SECFailure;	/* XXX Who sets the error code?? */
    }

    isTLS = (PRBool)(ss->ssl3.prSpec->version > SSL_LIBRARY_VERSION_3_0);

    if (isTLS) target = CKM_TLS_MASTER_KEY_DERIVE_DH;
    else target = CKM_SSL3_MASTER_KEY_DERIVE_DH;

    /* If field size is not more than 24 octets, then use SHA-1 hash of result;
     * otherwise, use result (see section 4.8 of draft-ietf-tls-ecc-03.txt).
     */
    if (srvrPubKey->u.ec.size <= 24 * 8) {
	kdf = CKD_SHA1_KDF;
    } else {
	kdf = CKD_NULL;
    }

    /*  Determine the PMS */
    pms = PK11_PubDeriveWithKDF(srvrPrivKey, &clntPubKey, PR_FALSE, NULL, NULL,
			    CKM_ECDH1_DERIVE, target, CKA_DERIVE, 0,
			    kdf, NULL, NULL);

    PORT_Free(clntPubKey.u.ec.publicValue.data);

    if (pms == NULL) {
	/* last gasp.  */
	ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	return SECFailure;
    }

    rv = ssl3_InitPendingCipherSpec(ss,  pms);
    PK11_FreeSymKey(pms);
    if (rv != SECSuccess) {
	SEND_ALERT
	return SECFailure;	/* error code set by ssl3_InitPendingCipherSpec */
    }
    return SECSuccess;
}


/*
 * Creates the ephemeral public and private ECDH keys used by
 * server in ECDHE_RSA and ECDHE_ECDSA handshakes.
 * XXX For now, the elliptic curve is hardcoded to NIST P-224.
 * We need an API to specify the curve. This won't be a real
 * issue until we further develop server-side support for ECC
 * cipher suites.
 */
SECStatus
ssl3_CreateECDHEphemeralKeys(sslSocket *ss)
{
    SECStatus             rv  	 = SECSuccess;
    SECKEYPrivateKey *    privKey;
    SECKEYPublicKey *     pubKey;
    SECKEYECParams	  ecParams = { siBuffer, NULL, 0 };

    if (ss->ephemeralECDHKeyPair)
	ssl3_FreeKeyPair(ss->ephemeralECDHKeyPair);
    ss->ephemeralECDHKeyPair = NULL;

    if (ecName2params(NULL, ec_secp224r1, &ecParams) == SECFailure)
	return SECFailure;
    privKey = SECKEY_CreateECPrivateKey(&ecParams, &pubKey, NULL);    
    if (!privKey || !pubKey ||
	!(ss->ephemeralECDHKeyPair = ssl3_NewKeyPair(privKey, pubKey))) {
	    ssl_MapLowLevelError(SEC_ERROR_KEYGEN_FAIL);
	    rv = SECFailure;
    }

    PORT_Free(ecParams.data);
    return rv;
}
#endif /* NSS_ENABLE_ECC */

