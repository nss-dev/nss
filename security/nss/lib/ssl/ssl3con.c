/*
 * SSL3 Protocol
 *
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
 *	Dr Stephen Henson <stephen.henson@gemplus.com>
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
 *
 * $Id$
 */

#include <stdio.h>
#include <string.h> /* XXX for memxxx */

#include "prtime.h"
#include "prinrval.h"
#include "prerror.h"
#include "pratom.h"
#include "prthread.h"

/* XXX basef.h??? */
#include "base.h"
#ifndef NSSBASE_H
#include "nssbase.h"
#endif /* NSSBASE_H */

#ifndef NSSDEV_H
#include "nssdev.h"
#endif /* NSSDEV_H */

#ifndef NSSPKI_H
#include "nsspki.h"
#endif /* NSSPKI_H */

#include "oiddata.h"
#include "nsspki1.h"
#include "nss.h"

#include "sslimpl.h"
#include "sslproto.h"
#include "sslerr.h"

#include "nsslocks.h"

/* XXX move to base.h!!! */
#define NSSITEM_DATA(it, i) \
    ((unsigned char *)(it)->data)[i]

/* XXX */
#define SSL_ERROR_INVALID_KEY_TYPE 5555
#define SSL_ERROR_UNSUPPORTED_KEY_EXCHANGE_ALG 5556
#define NSS_ERROR_INVALID_ARGS 5557
#define SSL_ERROR_INVALID_VERSION 5558
static const NSSUsages s_ssl_server_usage = { 0, NSSUsage_SSLServer };
static const NSSUsages s_ssl_client_usage = { 0, NSSUsage_SSLClient };

static void      ssl3_CleanupPeerCerts(ssl3State *ssl3);
static NSSSymKey *ssl3_GenerateRSAPMS(sslSocket *ss, 
                                      ssl3CipherSpec *spec,
                                      NSSToken *serverKeyToken);
static PRStatus  ssl3_GenerateSessionKeys(   sslSocket *ss, NSSSymKey *pmsOpt);
static SECStatus ssl3_HandshakeFailure(      sslSocket *ss);
static SECStatus ssl3_InitState(             sslSocket *ss);
static sslSessionID *ssl3_NewSessionID(      sslSocket *ss, PRBool is_server);
static SECStatus ssl3_SendCertificate(       sslSocket *ss);
static SECStatus ssl3_SendEmptyCertificate(  sslSocket *ss);
static SECStatus ssl3_SendCertificateRequest(sslSocket *ss);
static SECStatus ssl3_SendFinished(          sslSocket *ss, PRInt32 flags);
static SECStatus ssl3_SendServerHello(       sslSocket *ss);
static SECStatus ssl3_SendServerHelloDone(   sslSocket *ss);
static SECStatus ssl3_SendServerKeyExchange( sslSocket *ss);

static NSSItem * Null_Cipher(void *ctx, NSSItem *in, NSSItem *out, NSSArena *arenaOpt);

#define MAX_SEND_BUF_LENGTH 32000 /* watch for 16-bit integer overflow */
#define MIN_SEND_BUF_LENGTH  4000

#define MAX_CIPHER_SUITES 20

/* This list of SSL3 cipher suites is sorted in descending order of
 * precedence (desirability).  It only includes cipher suites we implement.
 * This table is modified by SSL3_SetPolicy().
 */
static ssl3CipherSuiteCfg cipherSuites[ssl_V3_SUITES_IMPLEMENTED] = {
   /*      cipher_suite                         policy      enabled is_present*/
 { TLS_DHE_RSA_WITH_AES_256_CBC_SHA, 	   SSL_NOT_ALLOWED, PR_FALSE,PR_FALSE},
 { TLS_DHE_DSS_WITH_AES_256_CBC_SHA, 	   SSL_NOT_ALLOWED, PR_FALSE,PR_FALSE},
 { TLS_RSA_WITH_AES_256_CBC_SHA,     	   SSL_NOT_ALLOWED, PR_FALSE,PR_FALSE},

 { SSL_FORTEZZA_DMS_WITH_RC4_128_SHA,      SSL_NOT_ALLOWED, PR_TRUE, PR_FALSE},
 { TLS_DHE_DSS_WITH_RC4_128_SHA,           SSL_NOT_ALLOWED, PR_FALSE,PR_FALSE},
 { TLS_DHE_RSA_WITH_AES_128_CBC_SHA,       SSL_NOT_ALLOWED, PR_FALSE,PR_FALSE},
 { TLS_DHE_DSS_WITH_AES_128_CBC_SHA, 	   SSL_NOT_ALLOWED, PR_FALSE,PR_FALSE},
 { SSL_RSA_WITH_RC4_128_MD5,               SSL_NOT_ALLOWED, PR_TRUE, PR_FALSE},
 { SSL_RSA_WITH_RC4_128_SHA,               SSL_NOT_ALLOWED, PR_FALSE,PR_FALSE},
 { TLS_RSA_WITH_AES_128_CBC_SHA,     	   SSL_NOT_ALLOWED, PR_FALSE,PR_FALSE},

 { SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA,      SSL_NOT_ALLOWED, PR_FALSE,PR_FALSE},
 { SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA,      SSL_NOT_ALLOWED, PR_FALSE,PR_FALSE},
 { SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA,     SSL_NOT_ALLOWED, PR_TRUE, PR_FALSE},
 { SSL_RSA_WITH_3DES_EDE_CBC_SHA,          SSL_NOT_ALLOWED, PR_TRUE, PR_FALSE},

 { SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA, SSL_NOT_ALLOWED, PR_TRUE, PR_FALSE},

 { SSL_DHE_RSA_WITH_DES_CBC_SHA,           SSL_NOT_ALLOWED, PR_FALSE,PR_FALSE},
 { SSL_DHE_DSS_WITH_DES_CBC_SHA,           SSL_NOT_ALLOWED, PR_FALSE,PR_FALSE},
 { SSL_RSA_FIPS_WITH_DES_CBC_SHA,          SSL_NOT_ALLOWED, PR_TRUE, PR_FALSE},
 { SSL_RSA_WITH_DES_CBC_SHA,               SSL_NOT_ALLOWED, PR_TRUE, PR_FALSE},

 { TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,     SSL_NOT_ALLOWED, PR_TRUE, PR_FALSE},
 { TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,    SSL_NOT_ALLOWED, PR_TRUE, PR_FALSE},
 { SSL_RSA_EXPORT_WITH_RC4_40_MD5,         SSL_NOT_ALLOWED, PR_TRUE, PR_FALSE},
 { SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5,     SSL_NOT_ALLOWED, PR_TRUE, PR_FALSE},
 { SSL_FORTEZZA_DMS_WITH_NULL_SHA,         SSL_NOT_ALLOWED, PR_TRUE, PR_FALSE},
 { SSL_RSA_WITH_NULL_SHA,                  SSL_NOT_ALLOWED, PR_FALSE,PR_FALSE},
 { SSL_RSA_WITH_NULL_MD5,                  SSL_NOT_ALLOWED, PR_FALSE,PR_FALSE}
};

static const /*SSL3CompressionMethod*/ uint8 compressions [] = {
    compression_null
};

static const int compressionMethodsCount =
		sizeof(compressions) / sizeof(compressions[0]);

static const /*SSL3ClientCertificateType */ uint8 certificate_types [] = {
    ct_RSA_sign,
    ct_DSS_sign,
};

static const /*SSL3ClientCertificateType */ uint8 fortezza_certificate_types [] = {
    ct_Fortezza,
};

/*
 * make sure there is room in the write buffer for padding and
 * other compression and cryptographic expansions
 */
#define SSL3_BUFFER_FUDGE     100

#define SET_ERROR_CODE		/* reminder */
#define SEND_ALERT		/* reminder */
#define TEST_FOR_FAILURE	/* reminder */
#define DEAL_WITH_FAILURE	/* reminder */

#define EXPORT_RSA_KEY_LENGTH 64	/* bytes */


/* This is a hack to make sure we don't do double handshakes for US policy */
PRBool ssl3_global_policy_some_restricted = PR_FALSE;

/* This global item is used only in servers.  It is is initialized by
** SSL_ConfigSecureServer(), and is used in ssl3_SendCertificateRequest().
*/
/* XXX */
NSSDER **ssl3_server_ca_list = NULL;
static SSL3Statistics ssl3stats;

/* must use ssl_LookupCipherSuiteDef to access */
static const ssl3CipherSuiteDef cipher_suite_defs[] = {
/*  cipher_suite                    bulk_cipher_alg mac_alg key_exchange_alg */

    {SSL_NULL_WITH_NULL_NULL,       cipher_null,   ssl_mac_null, kea_null},
    {SSL_RSA_WITH_NULL_MD5,         cipher_null,   ssl_mac_md5, kea_rsa},
    {SSL_RSA_WITH_NULL_SHA,         cipher_null,   ssl_mac_sha, kea_rsa},
    {SSL_RSA_EXPORT_WITH_RC4_40_MD5,cipher_rc4_40, ssl_mac_md5, kea_rsa_export},
    {SSL_RSA_WITH_RC4_128_MD5,      cipher_rc4,    ssl_mac_md5, kea_rsa},
    {SSL_RSA_WITH_RC4_128_SHA,      cipher_rc4,    ssl_mac_sha, kea_rsa},
    {SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
                                    cipher_rc2_40, ssl_mac_md5, kea_rsa_export},
#if 0 /* not implemented */
    {SSL_RSA_WITH_IDEA_CBC_SHA,     cipher_idea,   mac_sha, kea_rsa},
    {SSL_RSA_EXPORT_WITH_DES40_CBC_SHA,
                                    cipher_des40,  mac_sha, kea_rsa_export},
#endif
    {SSL_RSA_WITH_DES_CBC_SHA,      cipher_des,    ssl_mac_sha, kea_rsa},
    {SSL_RSA_WITH_3DES_EDE_CBC_SHA, cipher_3des,   ssl_mac_sha, kea_rsa},
    {SSL_DHE_DSS_WITH_DES_CBC_SHA,  cipher_des,    ssl_mac_sha, kea_dhe_dss},
    {SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
                                    cipher_3des,   ssl_mac_sha, kea_dhe_dss},
    {TLS_DHE_DSS_WITH_RC4_128_SHA,  cipher_rc4,    ssl_mac_sha, kea_dhe_dss},
#if 0 /* not implemented */
    {SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA,
                                    cipher_des40,  mac_sha, kea_dh_dss_export},
    {SSL_DH_DSS_DES_CBC_SHA,        cipher_des,    mac_sha, kea_dh_dss},
    {SSL_DH_DSS_3DES_CBC_SHA,       cipher_3des,   mac_sha, kea_dh_dss},
    {SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
                                    cipher_des40,  mac_sha, kea_dh_rsa_export},
    {SSL_DH_RSA_DES_CBC_SHA,        cipher_des,    mac_sha, kea_dh_rsa},
    {SSL_DH_RSA_3DES_CBC_SHA,       cipher_3des,   mac_sha, kea_dh_rsa},
    {SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
                                    cipher_des40,  mac_sha, kea_dh_dss_export},
    {SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
                                    cipher_des40,  mac_sha, kea_dh_rsa_export},
#endif
    {SSL_DHE_RSA_WITH_DES_CBC_SHA,  cipher_des,    ssl_mac_sha, kea_dhe_rsa},
    {SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
                                    cipher_3des,   ssl_mac_sha, kea_dhe_rsa},
#if 0
    {SSL_DH_ANON_EXPORT_RC4_40_MD5, cipher_rc4_40, mac_md5, kea_dh_anon_export},
    {SSL_DH_ANON_EXPORT_RC4_40_MD5, cipher_rc4,    mac_md5, kea_dh_anon_export},
    {SSL_DH_ANON_EXPORT_WITH_DES40_CBC_SHA,
                                    cipher_des40,  mac_sha, kea_dh_anon_export},
    {SSL_DH_ANON_DES_CBC_SHA,       cipher_des,    mac_sha, kea_dh_anon},
    {SSL_DH_ANON_3DES_CBC_SHA,      cipher_3des,   mac_sha, kea_dh_anon},
#endif

    {SSL_FORTEZZA_DMS_WITH_NULL_SHA, cipher_null,  ssl_mac_sha, kea_fortezza},
    {SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA,
                                  cipher_fortezza, ssl_mac_sha, kea_fortezza},
    {SSL_FORTEZZA_DMS_WITH_RC4_128_SHA, cipher_rc4, ssl_mac_sha, kea_fortezza},

/* New TLS cipher suites */
    {TLS_RSA_WITH_AES_128_CBC_SHA,     	cipher_aes_128, ssl_mac_sha, kea_rsa},
    {TLS_DHE_DSS_WITH_AES_128_CBC_SHA, 	cipher_aes_128, ssl_mac_sha, kea_dhe_dss},
    {TLS_DHE_RSA_WITH_AES_128_CBC_SHA, 	cipher_aes_128, ssl_mac_sha, kea_dhe_rsa},
    {TLS_RSA_WITH_AES_256_CBC_SHA,     	cipher_aes_256, ssl_mac_sha, kea_rsa},
    {TLS_DHE_DSS_WITH_AES_256_CBC_SHA, 	cipher_aes_256, ssl_mac_sha, kea_dhe_dss},
    {TLS_DHE_RSA_WITH_AES_256_CBC_SHA, 	cipher_aes_256, ssl_mac_sha, kea_dhe_rsa},
#if 0
    {TLS_DH_DSS_WITH_AES_128_CBC_SHA,  	cipher_aes_128, mac_sha, kea_dh_dss},
    {TLS_DH_RSA_WITH_AES_128_CBC_SHA,  	cipher_aes_128, mac_sha, kea_dh_rsa},
    {TLS_DH_ANON_WITH_AES_128_CBC_SHA, 	cipher_aes_128, mac_sha, kea_dh_anon},
    {TLS_DH_DSS_WITH_AES_256_CBC_SHA,  	cipher_aes_256, mac_sha, kea_dh_dss},
    {TLS_DH_RSA_WITH_AES_256_CBC_SHA,  	cipher_aes_256, mac_sha, kea_dh_rsa},
    {TLS_DH_ANON_WITH_AES_256_CBC_SHA, 	cipher_aes_256, mac_sha, kea_dh_anon},
#endif

    {TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,
                                    cipher_des,    ssl_mac_sha,kea_rsa_export_1024},
    {TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,
                                    cipher_rc4_56, ssl_mac_sha,kea_rsa_export_1024},

    {SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA, cipher_3des, ssl_mac_sha, kea_rsa_fips},
    {SSL_RSA_FIPS_WITH_DES_CBC_SHA, cipher_des,    ssl_mac_sha, kea_rsa_fips},

};

/* indexed by SSL3BulkCipher */
static const ssl3BulkCipherDef bulk_cipher_defs[] = {
    /* cipher
     *  calg
     *   keySz secretSz  type  ivSz BlkSz keygen 
     */
    { cipher_null,
       NSS_OID_UNKNOWN,
        0,  0, type_stream,  0, 0, kg_null},
    { cipher_rc4,
       NSS_OID_RC4,
        16, 16, type_stream,  0, 0, kg_strong},
    { cipher_rc4_40,
       NSS_OID_RC4,
        16,  5, type_stream,  0, 0, kg_export},
    { cipher_rc4_56,
       NSS_OID_RC4,
        16,  7, type_stream,  0, 0, kg_export},
    { cipher_rc2,
       NSS_OID_RC2_CBC,
        16, 16, type_block,   8, 8, kg_strong},
    { cipher_rc2_40,
       NSS_OID_RC2_CBC,
        16,  5, type_block,   8, 8, kg_export},
    { cipher_des,
       NSS_OID_DES_CBC,
        8,  8, type_block,   8, 8, kg_strong},
    { cipher_3des,
       NSS_OID_DES_EDE3_CBC,
        24, 24, type_block,   8, 8, kg_strong},
    { cipher_des40,
       NSS_OID_DES_CBC,
        8,  5, type_block,   8, 8, kg_export},
#if 0
    { cipher_idea,
       IDEA,
        s_idea_ap,     16, 16, type_block,   8, 8, kg_strong},
    { cipher_fortezza,
       FORTEZZA, 
        s_fortezza_ap, 10, 10, type_block,  24, 8, kg_null},
    { cipher_aes_128,
       AES,
        s_aes_ap,      16, 16, type_block,  16,16, kg_strong},
    { cipher_aes_256,
       NSSSymKeyType_AES,
        s_aes_ap,      32, 32, type_block,  16,16, kg_strong},
#endif
    { cipher_missing,
       NSS_OID_UNKNOWN,
        0,  0, type_stream,  0, 0, kg_null},
};

static const NSSOIDTag kea_alg_defs[] = {
    NSS_OID_UNKNOWN,
    NSS_OID_PKCS1_RSA_ENCRYPTION,
    NSS_OID_X942_DIFFIE_HELLMAN_KEY,
    NSS_OID_ANSIX9_DSA_SIGNATURE
};

static const ssl3KEADef kea_defs[] = { /* indexed by SSL3KeyExchangeAlgorithm */
    /* kea              exchKeyType signKeyType is_limited limit  tls_keygen */
    {kea_null,           ssl_kea_null,     ssl_sign_null, PR_FALSE,   0, PR_FALSE},
    {kea_rsa,            ssl_kea_rsa,      ssl_sign_rsa,  PR_FALSE,   0, PR_FALSE},
    {kea_rsa_export,     ssl_kea_rsa,      ssl_sign_rsa,  PR_TRUE,  512, PR_FALSE},
    {kea_rsa_export_1024,ssl_kea_rsa,      ssl_sign_rsa,  PR_TRUE, 1024, PR_FALSE},
    {kea_dh_dss,         ssl_kea_dh,       ssl_sign_dsa,  PR_FALSE,   0, PR_FALSE},
    {kea_dh_dss_export,  ssl_kea_dh,       ssl_sign_dsa,  PR_TRUE,  512, PR_FALSE},
    {kea_dh_rsa,         ssl_kea_dh,       ssl_sign_rsa,  PR_FALSE,   0, PR_FALSE},
    {kea_dh_rsa_export,  ssl_kea_dh,       ssl_sign_rsa,  PR_TRUE,  512, PR_FALSE},
    {kea_dhe_dss,        ssl_kea_dh,       ssl_sign_dsa,  PR_FALSE,   0, PR_FALSE},
    {kea_dhe_dss_export, ssl_kea_dh,       ssl_sign_dsa,  PR_TRUE,  512, PR_FALSE},
    {kea_dhe_rsa,        ssl_kea_dh,       ssl_sign_rsa,  PR_FALSE,   0, PR_FALSE},
    {kea_dhe_rsa_export, ssl_kea_dh,       ssl_sign_rsa,  PR_TRUE,  512, PR_FALSE},
    {kea_dh_anon,        ssl_kea_dh,       ssl_sign_null, PR_FALSE,   0, PR_FALSE},
    {kea_dh_anon_export, ssl_kea_dh,       ssl_sign_null, PR_TRUE,  512, PR_FALSE},
    {kea_fortezza,       ssl_kea_fortezza, ssl_sign_dsa,  PR_FALSE,   0, PR_FALSE},
    {kea_rsa_fips,       ssl_kea_rsa,      ssl_sign_rsa,  PR_FALSE,   0, PR_TRUE },
};

/*
 * Number of bytes each hash algorithm produces
 */
/* XXX where does this belong? */
#define MD2_LENGTH	16
#define MD5_LENGTH	16
#define SHA1_LENGTH	20

static const ssl3MACDef mac_defs[] = { /* indexed by SSL3MACAlgorithm */
    /*      mac       alg&param   pad_size     mac_size */
    {  ssl_mac_null,/*           NULL,*/        0,            0 },
    {   ssl_mac_md5,/*   s_mac_md5_ap,*/       48,   MD5_LENGTH },
    {   ssl_mac_sha,/*   s_mac_sha_ap,*/       40,  SHA1_LENGTH },
    {  ssl_hmac_md5,/*  s_hmac_md5_ap,*/       48,   MD5_LENGTH },
    {  ssl_hmac_sha,/*  s_hmac_sha_ap,*/       40,  SHA1_LENGTH },
};

static NSSArena *s_algs_arena = NULL;
static const NSSAlgNParam *s_md5_ap = NULL;
static const NSSAlgNParam *s_sha1_ap = NULL;
static const NSSAlgNParam *s_rsa_wrap_ap = NULL;
static const NSSAlgNParam *s_ssl3_pms_ap = NULL;
static const NSSAlgNParam *s_tls_pms_ap = NULL;
static const NSSAlgNParam *s_mac_md5_ap = NULL;
static const NSSAlgNParam *s_mac_sha1_ap = NULL;
static const NSSAlgNParam *s_hmac_md5_ap = NULL;
static const NSSAlgNParam *s_hmac_sha1_ap = NULL;
/* this is currently used w/o params */
static const NSSAlgNParam *s_tls_prf_ap = NULL;

PRStatus
ssl3_InitAlgorithms(void)
{
    NSSParameters params;

    s_algs_arena = NSSArena_Create();
    if (!s_algs_arena) return PR_FAILURE;

    /* initialize hashes */
    s_md5_ap = NSSOIDTag_CreateAlgNParam(NSS_OID_MD5, NULL, s_algs_arena);
    s_sha1_ap = NSSOIDTag_CreateAlgNParam(NSS_OID_SHA1, NULL, s_algs_arena);

    /* initialize RSA wrap/unwrap */
    s_rsa_wrap_ap = NSSOIDTag_CreateAlgNParam(NSS_OID_PKCS1_RSA_ENCRYPTION, 
                                              NULL, s_algs_arena);

    /* initialize PMS generation algorithms */
    params.sslpms = NSSSSLVersion_SSLv3;
    s_ssl3_pms_ap = NSSAlgNParam_CreateForSSL(s_algs_arena, 
                                              NSSSSLAlgorithm_PMSGen,
                                              &params);
    params.sslpms = NSSSSLVersion_TLS;
    s_tls_pms_ap = NSSAlgNParam_CreateForSSL(s_algs_arena, 
                                             NSSSSLAlgorithm_PMSGen,
                                             &params);

    /* initialize MACs and HMACS */
    params.mac = MD5_LENGTH;
    s_mac_md5_ap = NSSAlgNParam_CreateForSSL(s_algs_arena,
                                             NSSSSLAlgorithm_MD5_MAC,
                                             &params);
    params.mac = SHA1_LENGTH;
    s_mac_sha1_ap = NSSAlgNParam_CreateForSSL(s_algs_arena,
                                              NSSSSLAlgorithm_SHA1_MAC,
                                              &params);
    params.hmac = MD5_LENGTH;
    s_hmac_md5_ap = NSSOIDTag_CreateAlgNParam(NSS_OID_MD5_HMAC,
                                              &params, s_algs_arena);
    params.hmac = SHA1_LENGTH;
    s_hmac_sha1_ap = NSSOIDTag_CreateAlgNParam(NSS_OID_SHA1_HMAC,
                                               &params, s_algs_arena);

    /* initialize TLS pseudo-random function (currently no params) */
    s_tls_prf_ap = NSSAlgNParam_CreateForSSL(s_algs_arena, 
                                             NSSSSLAlgorithm_TLS_PRF,
                                             NULL);

    return PR_SUCCESS;
}

static const NSSAlgNParam *
ssl3_GetMacAP(ssl3State *ssl3)
{
    switch(ssl3->pwSpec->mac_def->mac) {
    case ssl_mac_md5:  return s_mac_md5_ap;
    case ssl_mac_sha:  return s_mac_sha1_ap;
    case ssl_hmac_md5: return s_hmac_md5_ap;
    case ssl_hmac_sha: return s_hmac_sha1_ap;
    default: return (const NSSAlgNParam *)NULL;
    }
}

static NSSAlgNParam *
ssl3_GetBulkCipherAP(const ssl3BulkCipherDef *cipher_def, NSSItem *iv)
{
    NSSParameters params, *pp;
    switch (cipher_def->cipher) {
    case cipher_rc2:
	params.rc2.effectiveKeySizeInBits = 128; /* always? */
	params.rc2.iv = *iv;
	pp = &params;
	break;
    default:
	if (iv->size > 0) {
	    /* generic CBC */
	    params.iv = *iv;
	    pp = &params;
	} else {
	    /* no params */
	    pp = NULL;
	}
	break;
    }
    return NSSOIDTag_CreateAlgNParam(cipher_def->calg, pp, NULL);
}

static NSSSSLVersion
ssl_GetVersion(sslSocket *ss)
{
    switch (ss->version) {
    case SSL_LIBRARY_VERSION_2:       return NSSSSLVersion_SSLv2;
    case SSL_LIBRARY_VERSION_3_0:     return NSSSSLVersion_SSLv3;
    case SSL_LIBRARY_VERSION_3_1_TLS: return NSSSSLVersion_TLS;
    default:  return -1;
    }
}

/* XXX why does this info come from cryptoki? */
static SSL3ProtocolVersion 
ssl3_GetVersionFromDeriveParams(NSSAlgNParam *deriveAP)
{
    switch (nssAlgNParam_GetSSLVersionFromMSDerive(deriveAP)) {
    case NSSSSLVersion_SSLv2: return SSL_LIBRARY_VERSION_2;
    case NSSSSLVersion_SSLv3: return SSL_LIBRARY_VERSION_3_0;
    case NSSSSLVersion_TLS:   return SSL_LIBRARY_VERSION_3_1_TLS;
    default: return -1;
    }
}

/* indexed by SSL3BulkCipher */
const char * const ssl3_cipherName[] = {
    "NULL",
    "RC4",
    "RC4-40",
    "RC4-56",
    "RC2-CBC",
    "RC2-CBC-40",
    "DES-CBC",
    "3DES-EDE-CBC",
    "DES-CBC-40",
    "IDEA-CBC",
    "FORTEZZA",
    "missing"
};

#if defined(TRACE)

static char *
ssl3_DecodeHandshakeType(int msgType)
{
    char * rv;
    static char line[40];

    switch(msgType) {
    case hello_request:	        rv = "hello_request (0)";               break;
    case client_hello:	        rv = "client_hello  (1)";               break;
    case server_hello:	        rv = "server_hello  (2)";               break;
    case certificate:	        rv = "certificate  (11)";               break;
    case server_key_exchange:	rv = "server_key_exchange (12)";        break;
    case certificate_request:	rv = "certificate_request (13)";        break;
    case server_hello_done:	rv = "server_hello_done   (14)";        break;
    case certificate_verify:	rv = "certificate_verify  (15)";        break;
    case client_key_exchange:	rv = "client_key_exchange (16)";        break;
    case finished:	        rv = "finished     (20)";               break;
    default:
        sprintf(line, "*UNKNOWN* handshake type! (%d)", msgType);
	rv = line;
    }
    return rv;
}

static char *
ssl3_DecodeContentType(int msgType)
{
    char * rv;
    static char line[40];

    switch(msgType) {
    case content_change_cipher_spec:
                                rv = "change_cipher_spec (20)";         break;
    case content_alert:	        rv = "alert      (21)";                 break;
    case content_handshake:	rv = "handshake  (22)";                 break;
    case content_application_data:
                                rv = "application_data (23)";           break;
    default:
        sprintf(line, "*UNKNOWN* record type! (%d)", msgType);
	rv = line;
    }
    return rv;
}

#endif

SSL3Statistics * 
SSL_GetStatistics(void)
{
    return &ssl3stats;
}

/* return pointer to ssl3CipherSuiteDef for suite, or NULL */
/* XXX This does a linear search.  A binary search would be better. */
static const ssl3CipherSuiteDef *
ssl_LookupCipherSuiteDef(ssl3CipherSuite suite)
{
    int cipher_suite_def_len =
	sizeof(cipher_suite_defs) / sizeof(cipher_suite_defs[0]);
    int i;

    for (i = 0; i < cipher_suite_def_len; i++) {
	if (cipher_suite_defs[i].cipher_suite == suite)
	    return &cipher_suite_defs[i];
    }
    PR_ASSERT(PR_FALSE);  /* We should never get here. */
    nss_SetError(SSL_ERROR_UNKNOWN_CIPHER_SUITE);
    return NULL;
}

/* Find the cipher configuration struct associate with suite */
/* XXX This does a linear search.  A binary search would be better. */
static ssl3CipherSuiteCfg *
ssl_LookupCipherSuiteCfg(ssl3CipherSuite suite, ssl3CipherSuiteCfg *suites)
{
    int i;

    for (i = 0; i < ssl_V3_SUITES_IMPLEMENTED; i++) {
	if (suites[i].cipher_suite == suite)
	    return &suites[i];
    }
    /* return NULL and let the caller handle it.  */
    nss_SetError(SSL_ERROR_UNKNOWN_CIPHER_SUITE);
    return NULL;
}


/* Initialize the suite->isPresent value for config_match
 * Returns count of enabled ciphers supported by extant tokens,
 * regardless of policy or user preference.
 * If this returns zero, the user cannot do SSL v3.
 */
int
ssl3_config_match_init(sslSocket *ss)
{
    ssl3CipherSuiteCfg *      suite;
    const ssl3CipherSuiteDef *cipher_def;
    SSLKEAType                exchKeyType;
    int                       i;
    int                       numPresent		= 0;
    int                       numEnabled		= 0;
    PRBool                    isServer;
    sslServerCerts           *svrAuth;
    NSSOIDTag                 algTag;
    NSSToken *                token;

    if (!ss->enableSSL3 && !ss->enableTLS) {
    	return 0;
    }
    isServer = (PRBool)( ss && ss->sec.isServer );

    for (i = 0; i < ssl_V3_SUITES_IMPLEMENTED; i++) {
	suite = &ss->cipherSuites[i];
	if (suite->enabled) {
	    ++numEnabled;
	    /* We need the cipher defs to see if we have a token that can handle
	     * this cipher.  It isn't part of the static definition.
	     */
	    cipher_def = ssl_LookupCipherSuiteDef(suite->cipher_suite);
	    if (!cipher_def) {
	    	suite->isPresent = PR_FALSE;
		continue;
	    }
	    exchKeyType =
	    	    kea_defs[cipher_def->key_exchange_alg].exchKeyType;
	    svrAuth = ss->serverCerts + exchKeyType;

	    /* Mark the suites that are backed by real tokens, certs and keys */
	    if (exchKeyType != ssl_kea_null) {
		if (!isServer || (svrAuth->serverKey && 
		                  svrAuth->serverCertChain)) 
		{
		    algTag = kea_alg_defs[exchKeyType];
		    /* need to check for token for key exchange alg */
		    token = NSSTrustDomain_FindTokenForAlgorithm(ss->td, 
		                                                 algTag);
		    if (token) {
			suite->isPresent = PR_TRUE;
			NSSToken_Destroy(token);
		    } else {
			suite->isPresent = PR_FALSE;
		    }
		} else {
		    /* don't have what we need for server auth */
		    suite->isPresent = PR_FALSE;
		}
	    } else {
		/* no key exchange, good to go so far */
		suite->isPresent = PR_TRUE;
	    }
	    if (cipher_def->bulk_cipher_alg != cipher_null && 
	        suite->isPresent) 
	    {
		algTag = bulk_cipher_defs[cipher_def->bulk_cipher_alg].calg;
		/* check for the cipher algorithm */
		token = NSSTrustDomain_FindTokenForAlgorithm(ss->td, algTag);
		if (token) {
		    suite->isPresent = PR_TRUE;
		    NSSToken_Destroy(token);
		} else {
		    suite->isPresent = PR_FALSE;
		}
	    }
	    if (suite->isPresent)
	    	++numPresent;
	}
    }
    PR_ASSERT(numPresent > 0 || numEnabled == 0);
    if (numPresent <= 0) {
	nss_SetError(SSL_ERROR_NO_CIPHERS_SUPPORTED);
    }
    return numPresent;
}


/* return PR_TRUE if suite matches policy and enabled state */
/* It would be a REALLY BAD THING (tm) if we ever permitted the use
** of a cipher that was NOT_ALLOWED.  So, if this is ever called with
** policy == SSL_NOT_ALLOWED, report no match.
*/
/* adjust suite enabled to the availability of a token that can do the
 * cipher suite. */
static PRBool
config_match(ssl3CipherSuiteCfg *suite, int policy, PRBool enabled)
{
    PR_ASSERT(policy != SSL_NOT_ALLOWED && enabled != PR_FALSE);
    if (policy == SSL_NOT_ALLOWED || !enabled)
    	return PR_FALSE;
    return (PRBool)(suite->enabled &&
                    suite->isPresent &&
	            suite->policy != SSL_NOT_ALLOWED &&
		    suite->policy <= policy);
}

/* return number of cipher suites that match policy and enabled state */
/* called from ssl3_SendClientHello and ssl3_ConstructV2CipherSpecsHack */
static int
count_cipher_suites(sslSocket *ss, int policy, PRBool enabled)
{
    int i, count = 0;

    if (!ss->enableSSL3 && !ss->enableTLS) {
    	return 0;
    }
    for (i = 0; i < ssl_V3_SUITES_IMPLEMENTED; i++) {
	if (config_match(&ss->cipherSuites[i], policy, enabled))
	    count++;
    }
    if (count <= 0) {
	nss_SetError(SSL_ERROR_SSL_DISABLED);
    }
    return count;
}

#ifdef IMPLEMENT_SSL_STEP_UP
static PRBool
anyRestrictedEnabled(sslSocket *ss)
{
    int i;

    if (!ss->enableSSL3 && !ss->enableTLS) {
    	return PR_FALSE;
    }
    for (i = 0; i < ssl_V3_SUITES_IMPLEMENTED; i++) {
	ssl3CipherSuiteCfg *suite = &ss->cipherSuites[i];
	if (suite->policy == SSL_RESTRICTED &&
	    suite->enabled &&
	    suite->isPresent)
	    return PR_TRUE;
    }
    return PR_FALSE;
}
#endif /* IMPLEMENT_SSL_STEP_UP */

/*
 * Null compression, mac and encryption functions
 */

static NSSItem * 
Null_Cipher(void *ctx, NSSItem *in, NSSItem *out, NSSArena *arenaOpt)
{
    out->size = in->size;
    if (in != out)
	memcpy(out->data, in->data, in->size);
    return out;
}


/*
 * SSL3 Utility functions
 */

SECStatus
ssl3_NegotiateVersion(sslSocket *ss, SSL3ProtocolVersion peerVersion)
{
    SSL3ProtocolVersion version;
    SSL3ProtocolVersion maxVersion;

    if (ss->enableTLS) {
	maxVersion = SSL_LIBRARY_VERSION_3_1_TLS;
    } else if (ss->enableSSL3) {
	maxVersion = SSL_LIBRARY_VERSION_3_0;
    } else {
    	/* what are we doing here? */
	PR_ASSERT(ss->enableSSL3 || ss->enableTLS);
	nss_SetError(SSL_ERROR_SSL_DISABLED);
	return SECFailure;
    }

    ss->version = version = PR_MIN(maxVersion, peerVersion);

    if ((version == SSL_LIBRARY_VERSION_3_1_TLS && ss->enableTLS) ||
    	(version == SSL_LIBRARY_VERSION_3_0     && ss->enableSSL3)) {
	return SECSuccess;
    }

    nss_SetError(SSL_ERROR_NO_CYPHER_OVERLAP);
    return SECFailure;

}

static SECStatus
ssl3_GetNewRandom(SSL3Random *random)
{
    PRIntervalTime gmt = PR_IntervalToSeconds(PR_IntervalNow());
    PRUint8 *rb;

    random->rand[0] = (unsigned char)(gmt >> 24);
    random->rand[1] = (unsigned char)(gmt >> 16);
    random->rand[2] = (unsigned char)(gmt >>  8);
    random->rand[3] = (unsigned char)(gmt);

    /* first 4 bytes are reserved for time */
    rb = NSS_GenerateRandom(SSL3_RANDOM_LENGTH - 4, &random->rand[4], NULL);
    if (!rb) {
	ssl_MapLowLevelError(SSL_ERROR_GENERATE_RANDOM_FAILURE);
	return SECFailure;
    }
    return SECSuccess;
}

static SECStatus
ssl3_SignHashes(SSL3Hashes *hash, NSSPrivateKey *key, NSSItem *buf, 
                PRBool isTLS)
{
    SECStatus rv		= SECFailure;
    PRBool    doDerEncode       = PR_FALSE;
    NSSItem   hashItem;
    NSSKeyPairType keyType = NSSPrivateKey_GetKeyType(key);

    switch (keyType) {
    case NSSKeyPairType_RSA:
    	hashItem.data = hash->md5;
    	hashItem.size = sizeof(SSL3Hashes);
	break;
    case NSSKeyPairType_DSA:
#if 0
    case fortezzaKey:
#endif
	doDerEncode = isTLS;
	hashItem.data = hash->sha;
	hashItem.size = sizeof(hash->sha);
	break;
    default:
	ssl_MapLowLevelError(SSL_ERROR_INVALID_KEY_TYPE);
	goto done;
    }
    PRINT_BUF(60, (NULL, "hash(es) to be signed", hashItem.data, hashItem.size));

    if (NSSPrivateKey_Sign(key, NULL, &hashItem, NULL /* XXX */, buf, NULL)
         == NULL)
    {
	ssl_MapLowLevelError(SSL_ERROR_SIGN_HASHES_FAILURE);
#ifdef IMPLEMENT_THIS
    } else if (doDerEncode) {
	NSSItem   derSig	= { NULL, 0};

    	rv = DSAU_EncodeDerSig(&derSig, buf);
	if (rv == SECSuccess) {
	    nss_ZFreeIf(buf->data);	/* discard unencoded signature. */
	    *buf = derSig;		/* give caller encoded signature. */
	} else if (derSig.data) {
	    nss_ZFreeIf(derSig.data);
	}
#endif
    } else rv = SECSuccess;

    PRINT_BUF(60, (NULL, "signed hashes", (unsigned char*)buf->data, buf->size));
done:
    if (rv != SECSuccess && buf->data) {
	nss_ZFreeIf(buf->data);
	buf->data = NULL;
    }
    return rv;
}


static SECStatus
ssl3_VerifySignedHashes(SSL3Hashes *hash, NSSCert *cert, 
                        NSSItem *buf, PRBool isTLS, void *pwArg)
{
    NSSPublicKey * key;
    NSSItem *      signature = NULL;
    SECStatus      rv;
    NSSItem        hashItem;


    PRINT_BUF(60, (NULL, "check signed hashes",
                  buf->data, buf->size));

    key = NSSCert_GetPublicKey(cert);
    if (key == NULL) {
	nss_SetError(SSL_ERROR_EXTRACT_PUBLIC_KEY_FAILURE);
    	return SECFailure;
    }

    switch (NSSPublicKey_GetKeyType(key)) {
    case NSSKeyPairType_RSA:
    	hashItem.data = hash->md5;
    	hashItem.size = sizeof(SSL3Hashes);
	break;
    case NSSKeyPairType_DSA:
#if 0
    case fortezzaKey:
#endif
	hashItem.data = hash->sha;
	hashItem.size = sizeof(hash->sha);
#ifdef IMPLEMENT_THIS
	if (isTLS) {
	    signature = DSAU_DecodeDerSig(buf);
	    if (!signature) {
	    	nss_SetError(SSL_ERROR_BAD_HANDSHAKE_HASH_VALUE);
		return SECFailure;
	    }
	    buf = signature;
	}
#endif
	break;
    default:
	NSSPublicKey_Destroy(key);
	ssl_MapLowLevelError(SSL_ERROR_INVALID_KEY_TYPE);
	return SECFailure;
    }

    PRINT_BUF(60, (NULL, "hash(es) to be verified",
                  hashItem.data, hashItem.size));

    if (NSSPublicKey_Verify(key, NULL, &hashItem, buf, NULL /* XXX */) 
         == PR_FAILURE) 
    {
	ssl_MapLowLevelError(SSL_ERROR_BAD_HANDSHAKE_HASH_VALUE);
	rv = SECFailure;
    } else rv = SECSuccess;
    NSSPublicKey_Destroy(key);
    if (signature) {
    	nss_ZFreeIf(signature->data);
    }
    return rv;
}


/* Caller must set hiLevel error code. */
static SECStatus
ssl3_ComputeExportRSAKeyHash(NSSItem modulus, NSSItem publicExponent,
			     SSL3Random *client_rand, SSL3Random *server_rand,
			     SSL3Hashes *hashes,
                             NSSTrustDomain *td)
{
    NSSCryptoContext * hash = NULL;
    NSSItem       hashIt;
    NSSItem       hashData;
    PRUint8     * pBuf;
    SECStatus     rv 		= SECSuccess;
    unsigned int  bufLen;
    NSSItem     * it = NULL;
    PRUint8       buf[2*SSL3_RANDOM_LENGTH + 2 + 4096/8 + 2 + 4096/8];

    bufLen = 2*SSL3_RANDOM_LENGTH + 2 + modulus.size + 2 + publicExponent.size;
    if (bufLen <= sizeof buf) {
    	hashIt.data = buf;
    } else {
    	hashIt.data = nss_ZAlloc(NULL, bufLen);
	if (!hashIt.data) {
	    return SECFailure;
	}
    }
    hashIt.size = bufLen;

    memcpy(hashIt.data, client_rand, SSL3_RANDOM_LENGTH); 
    	pBuf = (PRUint8 *)hashIt.data + SSL3_RANDOM_LENGTH;
    memcpy(pBuf, server_rand, SSL3_RANDOM_LENGTH);
    	pBuf += SSL3_RANDOM_LENGTH;
    pBuf[0]  = (PRUint8)(modulus.size >> 8);
    pBuf[1]  = (PRUint8)(modulus.size);
    	pBuf += 2;
    memcpy(pBuf, modulus.data, modulus.size);
    	pBuf += modulus.size;
    pBuf[0] = (PRUint8)(publicExponent.size >> 8);
    pBuf[1] = (PRUint8)(publicExponent.size);
    	pBuf += 2;
    memcpy(pBuf, publicExponent.data, publicExponent.size);
    	pBuf += publicExponent.size;
    PR_ASSERT(pBuf - buf == bufLen);

    hash = NSSTrustDomain_CreateCryptoContext(td, NULL, NULL);
    if (hash == NULL) {
	ssl_MapLowLevelError(SSL_ERROR_MD5_DIGEST_FAILURE);
	rv = SECFailure; /* Caller must set hiLevel error code. */
	goto done;
    }

    hashData.data = hashes->md5;
    hashData.size = sizeof hashes->md5;
    it = NSSCryptoContext_Digest(hash, s_md5_ap, &hashIt, 
                                 NULL, &hashData, NULL);
    PR_ASSERT(it != NULL || it->size == MD5_LENGTH);
    if (it == NULL) {
	ssl_MapLowLevelError(SSL_ERROR_MD5_DIGEST_FAILURE);
    	rv = SECFailure;
	goto done;
    }

    hashData.data = hashes->sha;
    hashData.size = sizeof hashes->sha;
    it = NSSCryptoContext_Digest(hash, s_sha1_ap, &hashIt, 
                                 NULL, &hashData, NULL);
    PR_ASSERT(it != NULL || it->size == SHA1_LENGTH);
    if (it == NULL) {
	ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
    	rv = SECFailure;
	goto done;
    }

    PRINT_BUF(95, (NULL, "RSAkey hash: ", hashIt.data, hashIt.size));
    PRINT_BUF(95, (NULL, "RSAkey hash: MD5 result", hashes->md5, MD5_LENGTH));
    PRINT_BUF(95, (NULL, "RSAkey hash: SHA1 result", hashes->sha, SHA1_LENGTH));

done:
    if (hash != NULL) NSSCryptoContext_Destroy(hash);
    if (hashIt.data != buf && hashIt.data != NULL)
    	nss_ZFreeIf(hashIt.data);
    return rv;
}

/* Caller must set hiLevel error code. */
static SECStatus
ssl3_ComputeDHKeyHash(NSSItem dh_p, NSSItem dh_g, NSSItem dh_Ys,
                      SSL3Random *client_rand, SSL3Random *server_rand,
                      SSL3Hashes *hashes,
                      NSSTrustDomain *td)
{
    NSSCryptoContext * hash = NULL;
    NSSItem       hashIt;
    NSSItem       hashData;
    PRUint8     * pBuf;
    SECStatus     rv 		= SECSuccess;
    unsigned int  bufLen;
    NSSItem     * it = NULL;
    PRUint8       buf[2*SSL3_RANDOM_LENGTH + 2 + 4096/8 + 2 + 4096/8];

    bufLen = 2*SSL3_RANDOM_LENGTH + 2 + dh_p.size + 2 + dh_g.size + 2 + dh_Ys.size;
    if (bufLen <= sizeof buf) {
    	hashIt.data = buf;
    } else {
    	hashIt.data = nss_ZAlloc(NULL, bufLen);
	if (!hashIt.data) {
	    return SECFailure;
	}
    }
    hashIt.size = bufLen;

    memcpy(hashIt.data, client_rand, SSL3_RANDOM_LENGTH); 
    	pBuf = (PRUint8 *)hashIt.data + SSL3_RANDOM_LENGTH;
    memcpy(pBuf, server_rand, SSL3_RANDOM_LENGTH);
    	pBuf += SSL3_RANDOM_LENGTH;
    pBuf[0]  = (PRUint8)(dh_p.size >> 8);
    pBuf[1]  = (PRUint8)(dh_p.size);
    	pBuf += 2;
    memcpy(pBuf, dh_p.data, dh_p.size);
    	pBuf += dh_p.size;
    pBuf[0] = (PRUint8)(dh_g.size >> 8);
    pBuf[1] = (PRUint8)(dh_g.size);
    	pBuf += 2;
    memcpy(pBuf, dh_g.data, dh_g.size);
    	pBuf += dh_g.size;
    pBuf[0] = (PRUint8)(dh_Ys.size >> 8);
    pBuf[1] = (PRUint8)(dh_Ys.size);
    	pBuf += 2;
    memcpy(pBuf, dh_Ys.data, dh_Ys.size);
    	pBuf += dh_Ys.size;
    PR_ASSERT(pBuf - buf == bufLen);

    hash = NSSTrustDomain_CreateCryptoContext(td, NULL, NULL);
    if (hash == NULL) {
	ssl_MapLowLevelError(SSL_ERROR_MD5_DIGEST_FAILURE);
	rv = SECFailure; /* Caller must set hiLevel error code. */
	goto done;
    }

    hashData.data = hashes->md5;
    hashData.size = sizeof hashes->md5;
    it = NSSCryptoContext_Digest(hash, s_md5_ap, 
                                 &hashIt, NULL, &hashData, NULL);
    PR_ASSERT(it != NULL || it->size == MD5_LENGTH);
    if (it == NULL) {
	ssl_MapLowLevelError(SSL_ERROR_MD5_DIGEST_FAILURE);
    	rv = SECFailure;
	goto done;
    }

    it = NSSCryptoContext_Digest(hash, s_sha1_ap, 
                                 &hashIt, NULL, &hashData, NULL);
    PR_ASSERT(it != NULL || it->size == SHA1_LENGTH);
    if (it == NULL) {
	ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
    	rv = SECFailure;
	goto done;
    }

    PRINT_BUF(95, (NULL, "DHkey hash: ", hashIt.data, hashIt.size));
    PRINT_BUF(95, (NULL, "DHkey hash: MD5 result", hashes->md5, MD5_LENGTH));
    PRINT_BUF(95, (NULL, "DHkey hash: SHA1 result", hashes->sha, SHA1_LENGTH));

done:
    if (hash != NULL) NSSCryptoContext_Destroy(hash);
    if (hashIt.data != buf && hashIt.data != NULL)
    	nss_ZFreeIf(hashIt.data);
    return rv;
}

#ifdef FORTEZZA
/* Caller must set hiLevel error code. */
static SECStatus
ssl3_ComputeFortezzaPublicKeyHash(NSSItem *publicValue, unsigned char * hash)
{
    NSSCryptoContext *sha = NULL;
    SECStatus    rv	= SECFailure;
    NSSItem *it = NULL;
    NSSItem dig;

    dig.data = hash;
    dig.size = SHA1_LENGTH;

    sha = NSSTrustDomain_CreateCryptoContextForAlgorithm(td, NSS_OID_SHA1);
    if (sha == NULL) {
	return rv; /* Caller must set hiLevel error code. */
    }

    it = NSSCryptoContext_Digest(sha, NULL, publicValue, NULL, &dig, NULL);
    PR_ASSERT(it != NULL || dig->size == SHA1_LENGTH);
    if (it == NULL) 
    	rv = SECFailure;

    NSSCryptoContext_Destroy(sha);

    return rv;
}
#endif


static void
ssl3_BumpSequenceNumber(SSL3SequenceNumber *num)
{
    num->low++;
    if (num->low == 0)
	num->high++;
}

/* Called only from ssl3_DestroyCipherSpec (immediately below). */
static void
ssl3_CleanupKeyMaterial(ssl3KeyMaterial *mat)
{
    if (mat->write_key != NULL) {
	NSSSymKey_Destroy(mat->write_key);
	mat->write_key = NULL;
    }
#if 0
    if (mat->write_mac_key != NULL) {
	PK11_FreeSymKey(mat->write_mac_key);
	mat->write_mac_key = NULL;
    }
#endif
    if (mat->write_mac_context != NULL) {
	NSSCryptoContext_Destroy(mat->write_mac_context);
	mat->write_mac_context = NULL;
    }
}

/* Called from ssl3_SendChangeCipherSpecs() and ssl3_HandleChangeCipherSpecs()
** Caller must hold SpecWriteLock.
*/
static void
ssl3_DestroyCipherSpec(ssl3CipherSpec *spec)
{

/*  PR_ASSERT( ssl_HaveSpecWriteLock(ss)); Don't have ss! */

    if (spec->destroy) {
	spec->destroy(spec->encodeContext);
	spec->destroy(spec->decodeContext);
	spec->encodeContext = NULL; /* paranoia */
	spec->decodeContext = NULL;
    }
    if (spec->master_secret != NULL) {
	NSSSymKey_Destroy(spec->master_secret);
	spec->master_secret = NULL;
    }
    ssl3_CleanupKeyMaterial(&spec->client);
    ssl3_CleanupKeyMaterial(&spec->server);
    spec->destroy=NULL;
}

/* Called from ssl3_HandleServerHello(), ssl3_SendServerHello()
** Caller must hold the ssl3 handshake lock.
** Acquires & releases SpecWriteLock.
*/
static SECStatus
ssl3_SetupPendingCipherSpec(sslSocket *ss, ssl3State *ssl3)
{
    ssl3CipherSpec *          pwSpec;
    ssl3CipherSpec *          cwSpec;
    ssl3CipherSuite           suite     = ssl3->hs.cipher_suite;
    SSLMACAlgorithm           mac;
    SSL3BulkCipher            cipher;
    SSL3KeyExchangeAlgorithm  kea;
    const ssl3CipherSuiteDef *suite_def;
    PRBool                    isTLS;

    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss));

    ssl_GetSpecWriteLock(ss);  /*******************************/

    pwSpec = ssl3->pwSpec;
    PR_ASSERT(pwSpec == ssl3->prSpec);

    /* This hack provides maximal interoperability with SSL 3 servers. */
    cwSpec = ss->ssl3->cwSpec;
    if (cwSpec->mac_def->mac == ssl_mac_null) {
	/* SSL records are not being MACed. */
	cwSpec->version = ss->version;
    }

    pwSpec->version  = ss->version;
    isTLS  = (PRBool)(pwSpec->version > SSL_LIBRARY_VERSION_3_0);

    SSL_TRC(3, ("%d: SSL3[%d]: Set XXX Pending Cipher Suite to 0x%04x",
		SSL_GETPID(), ss->fd, suite));

    suite_def = ssl_LookupCipherSuiteDef(suite);
    if (suite_def == NULL) {
	ssl_ReleaseSpecWriteLock(ss);
	return SECFailure;	/* error code set by ssl_LookupCipherSuiteDef */
    }


    cipher = suite_def->bulk_cipher_alg;
    kea    = suite_def->key_exchange_alg;
    mac    = suite_def->mac_alg;
    if (isTLS)
	mac += 2;

    ssl3->hs.suite_def = suite_def;
    ssl3->hs.kea_def   = &kea_defs[kea];
    PR_ASSERT(ssl3->hs.kea_def->kea == kea);

    pwSpec->cipher_def   = &bulk_cipher_defs[cipher];
    PR_ASSERT(pwSpec->cipher_def->cipher == cipher);

    pwSpec->mac_def = &mac_defs[mac];
    PR_ASSERT(pwSpec->mac_def->mac == mac);


    ss->sec.keyBits       = pwSpec->cipher_def->key_size        * BPB;
    ss->sec.secretKeyBits = pwSpec->cipher_def->secret_key_size * BPB;
    ss->sec.cipherType    = cipher;

    pwSpec->encodeContext = NULL;
    pwSpec->decodeContext = NULL;

    pwSpec->mac_size = pwSpec->mac_def->mac_size;

    ssl_ReleaseSpecWriteLock(ss);  /*******************************/
    return SECSuccess;
}

/*
 * Called from: ssl3_SendClientKeyExchange 	(for Full handshake)
 *              ssl3_HandleClientKeyExchange	(for Full handshake)
 *              ssl3_HandleServerHello		(for session restart)
 *              ssl3_HandleClientHello		(for session restart)
 * Sets error code, but caller probably should override to disambiguate.
 * NULL pms means re-use old master_secret.
 */
static SECStatus
ssl3_InitPendingCipherSpec(sslSocket *ss, NSSSymKey *pms)
{
    PRStatus status;
    ssl3CipherSpec *pwSpec = ss->ssl3->pwSpec;

    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss));

    ssl_GetSpecWriteLock(ss);	/**************************************/

    PR_ASSERT(ss->ssl3->prSpec == ss->ssl3->pwSpec);

    /* generate contexts for session keys from pre-master secret 
     * (if pms is not NULL) or master secret 
     */
    status = ssl3_GenerateSessionKeys(ss, pms);
    if (status == PR_FAILURE) {
    	goto fail;  /* err code set by ssl3_GenerateSessionKeys */
    }

    if (pwSpec->cipher_def->calg == NSS_OID_UNKNOWN) {
	/* If it's the NULL cipher, we're done */
	pwSpec->encode  = Null_Cipher;
	pwSpec->decode  = Null_Cipher;
        pwSpec->destroy = NULL;
	goto success;
    }

    /* initialize ongoing encryption ops */
    status = NSSCryptoContext_BeginEncrypt(pwSpec->encodeContext, NULL, NULL);
    if (status == PR_FAILURE) goto fail;

    status = NSSCryptoContext_BeginDecrypt(pwSpec->decodeContext, NULL, NULL);
    if (status == PR_FAILURE) goto fail;

    pwSpec->encode  = (SSLCipher)  NSSCryptoContext_ContinueEncrypt;
    pwSpec->decode  = (SSLCipher)  NSSCryptoContext_ContinueDecrypt;
    pwSpec->destroy = (SSLDestroy) NSSCryptoContext_Destroy;

success:
    ssl_ReleaseSpecWriteLock(ss);	/******************************/
    return SECSuccess;

fail:
    ssl_ReleaseSpecWriteLock(ss);
    return SECFailure;
}

/*
 * 60 bytes is 3 times the maximum length MAC size that is supported.
 */
static const unsigned char mac_pad_1 [60] = {
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36
};
static const unsigned char mac_pad_2 [60] = {
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c
};

/* Called from: ssl3_SendRecord()
**		ssl3_HandleRecord()
** Caller must already hold the SpecReadLock. (wish we could assert that!)
*/
static SECStatus
ssl3_ComputeRecordMAC(
    ssl3CipherSpec *   spec,
    NSSCryptoContext * mac_context,
    SSL3ContentType    type,
    SSL3ProtocolVersion version,
    SSL3SequenceNumber seq_num,
    SSL3Opaque *       input,
    int                inputLength,
    unsigned char *    outbuf,
    unsigned int *     outLength)
{
    PRStatus           status;
    const ssl3MACDef * mac_def;
    unsigned int       tempLen;
    unsigned char      temp[MAX_MAC_LENGTH];
    NSSItem            tempIt, inputIt, outputIt;

/*  ssl_GetSpecReadLock(ss);  Don't have "ss"! */

    mac_def = spec->mac_def;
    if (mac_def->mac == ssl_mac_null) {
	*outLength = 0;
/*	ssl_ReleaseSpecReadLock(ss); */
	return SECSuccess;
    }

    temp[0] = (unsigned char)(seq_num.high >> 24);
    temp[1] = (unsigned char)(seq_num.high >> 16);
    temp[2] = (unsigned char)(seq_num.high >>  8);
    temp[3] = (unsigned char)(seq_num.high >>  0);
    temp[4] = (unsigned char)(seq_num.low  >> 24);
    temp[5] = (unsigned char)(seq_num.low  >> 16);
    temp[6] = (unsigned char)(seq_num.low  >>  8);
    temp[7] = (unsigned char)(seq_num.low  >>  0);
    temp[8] = type;

    /* TLS MAC includes the record's version field, SSL's doesn't.
    ** We decide which MAC defintion to use based on the version of 
    ** the protocol that was negotiated when the spec became current,
    ** NOT based on the version value in the record itself.
    ** But, we use the record'v version value in the computation.
    */
    if (spec->version <= SSL_LIBRARY_VERSION_3_0) {
	temp[9]  = MSB(inputLength);
	temp[10] = LSB(inputLength);
	tempLen  = 11;
    } else {
    	/* New TLS hash includes version. */
	temp[9]  = MSB(version);
	temp[10] = LSB(version);
	temp[11] = MSB(inputLength);
	temp[12] = LSB(inputLength);
	tempLen  = 13;
    }

    PRINT_BUF(95, (NULL, "frag hash1: temp", temp, tempLen));
    PRINT_BUF(95, (NULL, "frag hash1: input", input, inputLength));

    tempIt.data = temp;
    tempIt.size = tempLen;
    inputIt.data = input;
    inputIt.size = inputLength;
    outputIt.data = outbuf;
    outputIt.size = spec->mac_size;

    /* XXX begin? */
    status  = NSSCryptoContext_BeginSign(mac_context, NULL, NULL);
    status |= NSSCryptoContext_ContinueSign(mac_context, &tempIt);
    status |= NSSCryptoContext_ContinueSign(mac_context, &inputIt);
    if (NSSCryptoContext_FinishSign(mac_context, &outputIt, NULL) == NULL) {
	status = PR_FAILURE;
    }
    *outLength = outputIt.size;

    PR_ASSERT(status != PR_SUCCESS || *outLength == (unsigned)spec->mac_size);

/*  ssl_ReleaseSpecReadLock(ss); */

    PRINT_BUF(95, (NULL, "frag hash2: result", outbuf, *outLength));

    if (status == PR_FAILURE) {
	ssl_MapLowLevelError(SSL_ERROR_MAC_COMPUTATION_FAILURE);
    }
    return (status == PR_SUCCESS) ? SECSuccess : SECFailure;
}

/* Process the plain text before sending it.
 * Returns the number of bytes of plaintext that were succesfully sent
 * 	plus the number of bytes of plaintext that were copied into the
 *	output (write) buffer.
 * Returns SECFailure on a hard IO error, memory error, or crypto error.
 * Does NOT return SECWouldBlock.
 */
static PRInt32
ssl3_SendRecord(   sslSocket *        ss,
                   SSL3ContentType    type,
		   const SSL3Opaque * buf,
		   PRInt32            bytes,
		   PRInt32            flags)
{
    ssl3CipherSpec *          cwSpec;
    sslBuffer      *          write 	  = &ss->sec.writeBuf;
    const ssl3BulkCipherDef * cipher_def;
    SECStatus                 rv;
    PRUint32                  bufSize     =  0;
    PRInt32                   sent        =  0;
    PRInt32                   cipherBytes = -1;
    PRBool                    isBlocking  = ssl_SocketIsBlocking(ss);
    PRBool                    ssl3WasNull = PR_FALSE;
    NSSItem in, out, *dummy;

    SSL_TRC(3, ("%d: SSL3[%d] SendRecord type: %s bytes=%d",
		SSL_GETPID(), ss->fd, ssl3_DecodeContentType(type),
		bytes));
    PRINT_BUF(3, (ss, "Send record (plain text)", buf, bytes));

    PR_ASSERT( ssl_HaveXmitBufLock(ss) );

    if (ss->ssl3 == NULL) {
	/* This can happen on a server if the very first incoming record
	** looks like a defective ssl3 record (e.g. too long), and we're
	** trying to send an alert.
	*/
	ssl3WasNull = PR_TRUE;
	PR_ASSERT(type == content_alert);
	rv = ssl3_InitState(ss);
	if (rv != SECSuccess) {
	    return SECFailure;	/* ssl3_InitState has set the error code. */
    	}
    }

    while (bytes > 0) {
    	PRInt32   count;
	PRUint32  contentLen;
	PRUint32  fragLen;
	PRUint32  macLen;

	contentLen = PR_MIN(bytes, MAX_FRAGMENT_LENGTH);
	if (write->space < contentLen + SSL3_BUFFER_FUDGE) {
	    rv = sslBuffer_Grow(write, contentLen + SSL3_BUFFER_FUDGE);
	    if (rv != SECSuccess) {
		SSL_DBG(("%d: SSL3[%d]: SendRecord, tried to get %d bytes",
			 SSL_GETPID(), ss->fd, contentLen + SSL3_BUFFER_FUDGE));
		return SECFailure; /* sslBuffer_Grow set a memory error code. */
	    }
	}

	/* This variable records 
	 * the actual size of the buffer we allocated above. Some
	 * algorithms (FORTEZZA) will expand the number of bytes it needs to
	 * send data. If we only supply the output buffer with the same number
	 * of bytes as the input buffer, we will fail.
	 */
	bufSize = contentLen + SSL3_BUFFER_FUDGE;

	/*
	 * null compression is easy to do
	 */
	memcpy(write->buf + SSL3_RECORD_HEADER_LENGTH, buf, contentLen);
	buf   += contentLen;
	bytes -= contentLen;
	PR_ASSERT( bytes >= 0 );

	ssl_GetSpecReadLock(ss);	/********************************/

	cwSpec = ss->ssl3->cwSpec;
	cipher_def = cwSpec->cipher_def;
	/*
	 * Add the MAC
	 */
	rv = ssl3_ComputeRecordMAC(
	    cwSpec, (ss->sec.isServer) ? cwSpec->server.write_mac_context
	                               : cwSpec->client.write_mac_context,
	    type, cwSpec->version, cwSpec->write_seq_num,
	    write->buf + SSL3_RECORD_HEADER_LENGTH, contentLen,
	    write->buf + contentLen + SSL3_RECORD_HEADER_LENGTH, &macLen);
	if (rv != SECSuccess) {
	    ssl_MapLowLevelError(SSL_ERROR_MAC_COMPUTATION_FAILURE);
	    goto spec_locked_loser;
	}
	fragLen = contentLen + macLen;	/* needs to be encrypted */
	PR_ASSERT(fragLen <= MAX_FRAGMENT_LENGTH + 1024);

	/*
	 * Pad the text (if we're doing a block cipher)
	 * then Encrypt it
	 */
	if (cipher_def->type == type_block) {
	    int             padding_length;
	    int             i;
	    unsigned char * pBuf;

	    /* Assume blockSize is a power of two */
	    padding_length = cipher_def->block_size - 1 -
		((fragLen) & (cipher_def->block_size - 1));
	    fragLen += padding_length + 1;
	    PR_ASSERT((fragLen % cipher_def->block_size) == 0);

	    /* Pad according to TLS rules (also acceptable to SSL3). */
	    pBuf = &write->buf[fragLen + SSL3_RECORD_HEADER_LENGTH - 1];
	    for (i = padding_length + 1; i > 0; --i) {
	    	*pBuf-- = padding_length;
	    }
	}
	NSSITEM_INIT(&in, write->buf + SSL3_RECORD_HEADER_LENGTH, fragLen);
	NSSITEM_INIT(&out, write->buf + SSL3_RECORD_HEADER_LENGTH, bufSize);
	dummy = cwSpec->encode(cwSpec->encodeContext, &in, &out, NULL);
	cipherBytes = out.size;
	if (dummy == NULL) {
	    ssl_MapLowLevelError(SSL_ERROR_ENCRYPTION_FAILURE);
spec_locked_loser:
	    ssl_ReleaseSpecReadLock(ss);
	    return SECFailure;
	}
	PR_ASSERT(cipherBytes <= MAX_FRAGMENT_LENGTH + 1024);

	/*
	 * XXX should we zero out our copy of the buffer after compressing
	 * and encryption ??
	 */

	ssl3_BumpSequenceNumber(&cwSpec->write_seq_num);

	ssl_ReleaseSpecReadLock(ss); /************************************/

	/* PR_ASSERT(fragLen == cipherBytes); */
	write->size    = cipherBytes + SSL3_RECORD_HEADER_LENGTH;
	write->buf[0] = type;
	write->buf[1] = MSB(cwSpec->version);
	write->buf[2] = LSB(cwSpec->version);
	write->buf[3] = MSB(cipherBytes);
	write->buf[4] = LSB(cipherBytes);

	PRINT_BUF(50, (ss, "send (encrypted) record data:", write->buf, write->size));

	/* If there's still some previously saved ciphertext,
	 * or the caller doesn't want us to send the data yet,
	 * then add all our new ciphertext to the amount previously saved.
	 */
	if ((ss->pendingBuf.size > 0) ||
	    (flags & ssl_SEND_FLAG_FORCE_INTO_BUFFER)) {

	    rv = ssl_SaveWriteData(ss, &ss->pendingBuf,
				   write->buf, write->size);
	    if (rv != SECSuccess) {
		/* presumably a memory error, SEC_ERROR_NO_MEMORY */
		return SECFailure;
	    }
	    write->size = 0;	/* All cipher text is saved away. */

	    if (!(flags & ssl_SEND_FLAG_FORCE_INTO_BUFFER)) {

		ss->handshakeBegun = 1;
		count = ssl_SendSavedWriteData(ss, &ss->pendingBuf,
		                               &ssl_DefSend);
		if (count < 0 && PR_GetError() != PR_WOULD_BLOCK_ERROR) {
		    ssl_MapLowLevelError(SSL_ERROR_SOCKET_WRITE_FAILURE);
		    return SECFailure;
		}
	    }
	} else if (write->size > 0) {
	    ss->handshakeBegun = 1;
	    count = ssl_DefSend(ss, write->buf, write->size,
				flags & ~ssl_SEND_FLAG_MASK);
	    if (count < 0) {
		if (PR_GetError() != PR_WOULD_BLOCK_ERROR) {
		    ssl_MapLowLevelError(SSL_ERROR_SOCKET_WRITE_FAILURE);
		    return (sent > 0) ? sent : SECFailure;
		}
		/* we got PR_WOULD_BLOCK_ERROR, which means none was sent. */
		count = 0;
	    }
	    /* now take all the remaining unsent newly-generated ciphertext and
	     * append it to the buffer of previously unsent ciphertext.
	     */
	    if ((unsigned)count < write->size) {
		rv = ssl_SaveWriteData(ss, &ss->pendingBuf,
				       write->buf + (unsigned)count,
				       write->size - (unsigned)count);
		if (rv != SECSuccess) {
		    /* presumably a memory error, SEC_ERROR_NO_MEMORY */
		    return SECFailure;
		}
	    }
	    write->size = 0;
	}
	sent += contentLen;
	if ((flags & ssl_SEND_FLAG_NO_BUFFER) &&
	    (isBlocking || (ss->pendingBuf.size > 0))) {
	    break;
	}
    }
    return sent;
}

/* Attempt to send the content of "in" in an SSL application_data record.
 * Returns "len" or SECFailure,   never SECWouldBlock, nor SECSuccess.
 */
int
ssl3_SendApplicationData(sslSocket *ss, const unsigned char *in,
			 PRInt32 len, PRInt32 flags)
{
    PRInt32   sent	= 0;

    PR_ASSERT( ssl_HaveXmitBufLock(ss) );

    while (len > 0) {
	PRInt32   count;

	if (sent > 0) {
	    ssl_ReleaseXmitBufLock(ss);
	    PR_Sleep(PR_INTERVAL_NO_WAIT);	/* PR_Yield(); */
	    ssl_GetXmitBufLock(ss);
	}
	count = ssl3_SendRecord(ss, content_application_data, in, len,
	                           flags | ssl_SEND_FLAG_NO_BUFFER);
	if (count < 0) {
	    return (sent > 0) ? sent : count;
				    /* error code set by ssl3_SendRecord */
	}
	sent += count;
	len  -= count;
	in   += count;
    }
    return sent;
}

/* Attempt to send the content of sendBuf buffer in an SSL handshake record.
 * This function returns SECSuccess or SECFailure, never SECWouldBlock.
 * It used to always set sendBuf.size to 0, even when returning SECFailure.
 * Now it does not.
 *
 * Called from SSL3_SendAlert(), ssl3_SendChangeCipherSpecs(),
 *             ssl3_AppendHandshake(), ssl3_SendClientHello(),
 *             ssl3_SendHelloRequest(), ssl3_SendServerHelloDone(),
 *             ssl3_SendFinished(),
 */
static SECStatus
ssl3_FlushHandshake(sslSocket *ss, PRInt32 flags)
{
    PRInt32 rv;

    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss));
    PR_ASSERT( ssl_HaveXmitBufLock(ss) );

    if (!ss->sec.ci.sendBuf.buf || !ss->sec.ci.sendBuf.size)
	return SECSuccess;

    rv = ssl3_SendRecord(ss, content_handshake, ss->sec.ci.sendBuf.buf,
			 ss->sec.ci.sendBuf.size, flags);
    if (rv < 0) {
	return (SECStatus)rv;	/* error code set by ssl3_SendRecord */
    }
    ss->sec.ci.sendBuf.size = 0;
    return SECSuccess;
}

/*
 * Called from ssl3_HandleAlert and from ssl3_HandleCertificate when
 * the remote client sends a negative response to our certificate request.
 * Returns SECFailure if the application has required client auth.
 *         SECSuccess otherwise.
 */
static SECStatus
ssl3_HandleNoCertificate(sslSocket *ss)
{
    if (ss->sec.peerCert != NULL) {
	if (ss->sec.peerKey != NULL) {
	    NSSPublicKey_Destroy(ss->sec.peerKey);
	    ss->sec.peerKey = NULL;
	}
	NSSCert_Destroy(ss->sec.peerCert);
	ss->sec.peerCert = NULL;
    }
    ssl3_CleanupPeerCerts(ss->ssl3);

    /* If the server has required client-auth blindly but doesn't
     * actually look at the certificate it won't know that no
     * certificate was presented so we shutdown the socket to ensure
     * an error.  We only do this if we haven't already completed the
     * first handshake because if we're redoing the handshake we 
     * know the server is paying attention to the certificate.
     */
    if ((ss->requireCertificate == SSL_REQUIRE_ALWAYS) ||
	(!ss->firstHsDone && 
	 (ss->requireCertificate == SSL_REQUIRE_FIRST_HANDSHAKE))) {
	PRFileDesc * lower;

#ifdef IMPLEMENT_SSL_SESSION_ID_CACHE
	ss->sec.uncache(ss->sec.ci.sid);
#endif /* IMPLEMENT_SSL_SESSION_ID_CACHE */
	SSL3_SendAlert(ss, alert_fatal, bad_certificate);

	lower = ss->fd->lower;
#ifdef _WIN32
	lower->methods->shutdown(lower, PR_SHUTDOWN_SEND);
#else
	lower->methods->shutdown(lower, PR_SHUTDOWN_BOTH);
#endif
	nss_SetError(SSL_ERROR_NO_CERTIFICATE);
	return SECFailure;
    }
    return SECSuccess;
}

/************************************************************************
 * Alerts
 */

/*
** Acquires both handshake and XmitBuf locks.
** Called from: ssl3_IllegalParameter	<-
**              ssl3_HandshakeFailure	<-
**              ssl3_HandleAlert	<- ssl3_HandleRecord.
**              ssl3_HandleChangeCipherSpecs <- ssl3_HandleRecord
**              ssl3_ConsumeHandshakeVariable <-
**              ssl3_HandleHelloRequest	<-
**              ssl3_HandleServerHello	<-
**              ssl3_HandleServerKeyExchange <-
**              ssl3_HandleCertificateRequest <-
**              ssl3_HandleServerHelloDone <-
**              ssl3_HandleClientHello	<-
**              ssl3_HandleV2ClientHello <-
**              ssl3_HandleCertificateVerify <-
**              ssl3_HandleFortezzaClientKeyExchange <-
**              ssl3_HandleClientKeyExchange <-
**              ssl3_HandleCertificate	<-
**              ssl3_HandleFinished	<-
**              ssl3_HandleHandshakeMessage <-
**              ssl3_HandleRecord	<-
**
*/
SECStatus
SSL3_SendAlert(sslSocket *ss, SSL3AlertLevel level, SSL3AlertDescription desc)
{
    uint8 	bytes[2];
    SECStatus	rv;

    SSL_TRC(3, ("%d: SSL3[%d]: send alert record, level=%d desc=%d",
		SSL_GETPID(), ss->fd, level, desc));

    bytes[0] = level;
    bytes[1] = desc;

    ssl_GetSSL3HandshakeLock(ss);
    if (level == alert_fatal) {
#ifdef IMPLEMENT_SSL_SESSION_ID_CACHE
	if (ss->sec.ci.sid) {
	    ss->sec.uncache(ss->sec.ci.sid);
	}
#endif /* IMPLEMENT_SSL_SESSION_ID_CACHE */
    }
    ssl_GetXmitBufLock(ss);
    rv = ssl3_FlushHandshake(ss, ssl_SEND_FLAG_FORCE_INTO_BUFFER);
    if (rv == SECSuccess) {
	PRInt32 sent;
	sent = ssl3_SendRecord(ss, content_alert, bytes, 2, 0);
	rv = (sent >= 0) ? SECSuccess : (SECStatus)sent;
    }
    ssl_ReleaseXmitBufLock(ss);
    ssl_ReleaseSSL3HandshakeLock(ss);
    return rv;	/* error set by ssl3_FlushHandshake or ssl3_SendRecord */
}

/*
 * Send illegal_parameter alert.  Set generic error number.
 */
static SECStatus
ssl3_IllegalParameter(sslSocket *ss)
{
    PRBool isTLS;

    isTLS = (PRBool)(ss->ssl3->pwSpec->version > SSL_LIBRARY_VERSION_3_0);
    (void)SSL3_SendAlert(ss, alert_fatal, illegal_parameter);
    nss_SetError(ss->sec.isServer ? SSL_ERROR_BAD_CLIENT
                                   : SSL_ERROR_BAD_SERVER );
    return SECFailure;
}

/*
 * Send handshake_Failure alert.  Set generic error number.
 */
static SECStatus
ssl3_HandshakeFailure(sslSocket *ss)
{
    (void)SSL3_SendAlert(ss, alert_fatal, handshake_failure);
    nss_SetError( ss->sec.isServer ? SSL_ERROR_BAD_CLIENT
                                    : SSL_ERROR_BAD_SERVER );
    return SECFailure;
}

/*
 * Send handshake_Failure alert.  Set generic error number.
 */
static SECStatus
ssl3_DecodeError(sslSocket *ss)
{
    (void)SSL3_SendAlert(ss, alert_fatal, 
		  ss->version > SSL_LIBRARY_VERSION_3_0 ? decode_error 
							: illegal_parameter);
    nss_SetError( ss->sec.isServer ? SSL_ERROR_BAD_CLIENT
                                    : SSL_ERROR_BAD_SERVER );
    return SECFailure;
}

/* Called from ssl3_HandleRecord.
** Caller must hold both RecvBuf and Handshake locks.
*/
static SECStatus
ssl3_HandleAlert(sslSocket *ss, sslBuffer *buf)
{
    SSL3AlertLevel       level;
    SSL3AlertDescription desc;
    int                  error;

    PR_ASSERT( ssl_HaveRecvBufLock(ss) );
    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss) );

    SSL_TRC(3, ("%d: SSL3[%d]: handle alert record", SSL_GETPID(), ss->fd));

    if (buf->size != 2) {
	(void)ssl3_DecodeError(ss);
	nss_SetError(SSL_ERROR_RX_MALFORMED_ALERT);
	return SECFailure;
    }
    level = (SSL3AlertLevel)buf->buf[0];
    desc  = (SSL3AlertDescription)buf->buf[1];
    buf->size = 0;
    SSL_TRC(5, ("%d: SSL3[%d] received alert, level = %d, description = %d",
        SSL_GETPID(), ss->fd, level, desc));

    switch (desc) {
    case close_notify:		ss->recvdCloseNotify = 1;
		        	error = SSL_ERROR_CLOSE_NOTIFY_ALERT;     break;
    case unexpected_message: 	error = SSL_ERROR_HANDSHAKE_UNEXPECTED_ALERT;
									  break;
    case bad_record_mac: 	error = SSL_ERROR_BAD_MAC_ALERT; 	  break;
    case decryption_failed: 	error = SSL_ERROR_DECRYPTION_FAILED_ALERT; 
    									  break;
    case record_overflow: 	error = SSL_ERROR_RECORD_OVERFLOW_ALERT;  break;
    case decompression_failure: error = SSL_ERROR_DECOMPRESSION_FAILURE_ALERT;
									  break;
    case handshake_failure: 	error = SSL_ERROR_HANDSHAKE_FAILURE_ALERT;
			        					  break;
    case no_certificate: 	error = SSL_ERROR_NO_CERTIFICATE;	  break;
    case bad_certificate: 	error = SSL_ERROR_BAD_CERT_ALERT; 	  break;
    case unsupported_certificate:error = SSL_ERROR_UNSUPPORTED_CERT_ALERT;break;
    case certificate_revoked: 	error = SSL_ERROR_REVOKED_CERT_ALERT; 	  break;
    case certificate_expired: 	error = SSL_ERROR_EXPIRED_CERT_ALERT; 	  break;
    case certificate_unknown: 	error = SSL_ERROR_CERTIFICATE_UNKNOWN_ALERT;
			        					  break;
    case illegal_parameter: 	error = SSL_ERROR_ILLEGAL_PARAMETER_ALERT;break;

    /* All alerts below are TLS only. */
    case unknown_ca: 		error = SSL_ERROR_UNKNOWN_CA_ALERT;       break;
    case access_denied: 	error = SSL_ERROR_ACCESS_DENIED_ALERT;    break;
    case decode_error: 		error = SSL_ERROR_DECODE_ERROR_ALERT;     break;
    case decrypt_error: 	error = SSL_ERROR_DECRYPT_ERROR_ALERT;    break;
    case export_restriction: 	error = SSL_ERROR_EXPORT_RESTRICTION_ALERT; 
    									  break;
    case protocol_version: 	error = SSL_ERROR_PROTOCOL_VERSION_ALERT; break;
    case insufficient_security: error = SSL_ERROR_INSUFFICIENT_SECURITY_ALERT; 
    									  break;
    case internal_error: 	error = SSL_ERROR_INTERNAL_ERROR_ALERT;   break;
    case user_canceled: 	error = SSL_ERROR_USER_CANCELED_ALERT;    break;
    case no_renegotiation: 	error = SSL_ERROR_NO_RENEGOTIATION_ALERT; break;
    default: 			error = SSL_ERROR_RX_UNKNOWN_ALERT; 	  break;
    }
    if (level == alert_fatal) {
#ifdef IMPLEMENT_SSL_SESSION_ID_CACHE
	ss->sec.uncache(ss->sec.ci.sid);
#endif /* IMPLEMENT_SSL_SESSION_ID_CACHE */
	if ((ss->ssl3->hs.ws == wait_server_hello) &&
	    (desc == handshake_failure)) {
	    /* XXX This is a hack.  We're assuming that any handshake failure
	     * XXX on the client hello is a failure to match ciphers.
	     */
	    error = SSL_ERROR_NO_CYPHER_OVERLAP;
	}
	nss_SetError(error);
	return SECFailure;
    }
    if ((desc == no_certificate) && (ss->ssl3->hs.ws == wait_client_cert)) {
    	/* I'm a server. I've requested a client cert. He hasn't got one. */
	SECStatus rv;

	PR_ASSERT(ss->sec.isServer);
	ss->ssl3->hs.ws = wait_client_key;
	rv = ssl3_HandleNoCertificate(ss);
	return rv;
    }
    return SECSuccess;
}

/*
 * Change Cipher Specs
 * Called from ssl3_HandleServerHelloDone,
 *             ssl3_HandleClientHello,
 * and         ssl3_HandleFinished
 *
 * Acquires and releases spec write lock, to protect switching the current
 * and pending write spec pointers.
 */

static SECStatus
ssl3_SendChangeCipherSpecs(sslSocket *ss)
{
    uint8             change = change_cipher_spec_choice;
    ssl3State *       ssl3   = ss->ssl3;
    ssl3CipherSpec *  pwSpec;
    SECStatus         rv;
    PRInt32           sent;

    SSL_TRC(3, ("%d: SSL3[%d]: send change_cipher_spec record",
		SSL_GETPID(), ss->fd));

    PR_ASSERT( ssl_HaveXmitBufLock(ss) );
    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss));

    rv = ssl3_FlushHandshake(ss, ssl_SEND_FLAG_FORCE_INTO_BUFFER);
    if (rv != SECSuccess) {
	return rv;	/* error code set by ssl3_FlushHandshake */
    }
    sent = ssl3_SendRecord(ss, content_change_cipher_spec, &change, 1,
                              ssl_SEND_FLAG_FORCE_INTO_BUFFER);
    if (sent < 0) {
	return (SECStatus)sent;	/* error code set by ssl3_SendRecord */
    }

    /* swap the pending and current write specs. */
    ssl_GetSpecWriteLock(ss);	/**************************************/
    pwSpec                     = ss->ssl3->pwSpec;
    pwSpec->write_seq_num.high = 0;
    pwSpec->write_seq_num.low  = 0;

    ssl3->pwSpec = ssl3->cwSpec;
    ssl3->cwSpec = pwSpec;

    SSL_TRC(3, ("%d: SSL3[%d] Set Current Write Cipher Suite to Pending",
		SSL_GETPID(), ss->fd ));

    /* We need to free up the contexts, keys and certs ! */
    /* If we are really through with the old cipher spec
     * (Both the read and write sides have changed) destroy it.
     */
    if (ss->ssl3->prSpec == ss->ssl3->pwSpec) {
    	ssl3_DestroyCipherSpec(ss->ssl3->pwSpec);
    }
    ssl_ReleaseSpecWriteLock(ss); /**************************************/

    return SECSuccess;
}

/* Called from ssl3_HandleRecord.
** Caller must hold both RecvBuf and Handshake locks.
 *
 * Acquires and releases spec write lock, to protect switching the current
 * and pending write spec pointers.
*/
static SECStatus
ssl3_HandleChangeCipherSpecs(sslSocket *ss, sslBuffer *buf)
{
    ssl3CipherSpec *           prSpec;
    SSL3WaitState              ws      = ss->ssl3->hs.ws;
    SSL3ChangeCipherSpecChoice change;

    PR_ASSERT( ssl_HaveRecvBufLock(ss) );
    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss) );

    SSL_TRC(3, ("%d: SSL3[%d]: handle change_cipher_spec record",
		SSL_GETPID(), ss->fd));

    if (ws != wait_change_cipher && ws != wait_cert_verify) {
	(void)SSL3_SendAlert(ss, alert_fatal, unexpected_message);
	nss_SetError(SSL_ERROR_RX_UNEXPECTED_CHANGE_CIPHER);
	return SECFailure;
    }

    if(buf->size != 1) {
	(void)ssl3_DecodeError(ss);
	nss_SetError(SSL_ERROR_RX_MALFORMED_CHANGE_CIPHER);
	return SECFailure;
    }
    change = (SSL3ChangeCipherSpecChoice)buf->buf[0];
    if (change != change_cipher_spec_choice) {
	/* illegal_parameter is correct here for both SSL3 and TLS. */
	(void)ssl3_IllegalParameter(ss);
	nss_SetError(SSL_ERROR_RX_MALFORMED_CHANGE_CIPHER);
	return SECFailure;
    }
    buf->size = 0;

    /* Swap the pending and current read specs. */
    ssl_GetSpecWriteLock(ss);   /*************************************/
    prSpec                    = ss->ssl3->prSpec;
    prSpec->read_seq_num.high = prSpec->read_seq_num.low = 0;

    ss->ssl3->prSpec  = ss->ssl3->crSpec;
    ss->ssl3->crSpec  = prSpec;
    ss->ssl3->hs.ws         = wait_finished;

    SSL_TRC(3, ("%d: SSL3[%d] Set Current Read Cipher Suite to Pending",
		SSL_GETPID(), ss->fd ));

    /* If we are really through with the old cipher prSpec
     * (Both the read and write sides have changed) destroy it.
     */
    if (ss->ssl3->prSpec == ss->ssl3->pwSpec) {
    	ssl3_DestroyCipherSpec(ss->ssl3->prSpec);
    }
    ssl_ReleaseSpecWriteLock(ss);   /*************************************/
    return SECSuccess;
}

static PRStatus
ssl3_DeriveMasterSecret(sslSocket *ss, NSSSymKey *pmsOpt)
{
    ssl3CipherSpec *pwSpec = ss->ssl3->pwSpec;
    const ssl3KEADef *kea_def = ss->ssl3->hs.kea_def;
    PRBool isTLS  = (PRBool)(kea_def->tls_keygen ||
                             (pwSpec->version > SSL_LIBRARY_VERSION_3_0));
    PRBool isDH = (PRBool) (ss->ssl3->hs.kea_def->exchKeyType == ssl_kea_dh);
    NSSAlgNParam *msDerive = NULL;
    NSSSymKey *ms = pwSpec->master_secret;
    NSSSymKey *fpms = NULL;
    NSSSSLMSParameters msParams;
    NSSOperations keyOps = 0;
    PRStatus status;

    /* set up alg/parameters for master secret derivation */
    msParams.version = isTLS ? NSSSSLVersion_TLS : NSSSSLVersion_SSLv3;
    msParams.isDH = isDH;
    msParams.clientRandom.data = &ss->ssl3->hs.client_random;
    msParams.clientRandom.size = SSL3_RANDOM_LENGTH;
    msParams.serverRandom.data = &ss->ssl3->hs.server_random;
    msParams.serverRandom.size = SSL3_RANDOM_LENGTH;
    msDerive = NSSAlgNParam_CreateForSSL(NULL, 
                                         NSSSSLAlgorithm_MSDerive, 
                                         (NSSParameters *)&msParams);
    if (!msDerive) {
	goto loser;
    }

    /* set the default key operations */
    if (isTLS) {
	keyOps = NSSOperations_SIGN | NSSOperations_VERIFY;
    }

    if (pmsOpt) {
	/* generating master secret from existing pre-master secret */
	ms = NSSSymKey_DeriveSymKey(pmsOpt, msDerive, NSSSymKeyType_SSLMS,
	                            0, keyOps, 0, NULL, NULL, NULL);
	if (ms && !isDH && ss->detectRollBack) {
	    SSL3ProtocolVersion client_version;
	    client_version = ssl3_GetVersionFromDeriveParams(msDerive);
	    /* XXX client_version = pms_version.major << 8 | pms_version.minor; */
	    if (client_version != ss->clientHelloVersion) {
		/* Destroy it.  Version roll-back detected. */
		NSSSymKey_Destroy(ms);
		ms = NULL;
	    }
	}
	if (!ms) {
	    /* Generate a faux master secret in the same slot as the old one. */
	    NSSToken *pmsToken;
	    (void)NSSSymKey_GetTokens(pmsOpt, &pmsToken, 1, &status);
	    if (status == PR_FAILURE) {
		goto loser;
	    }
	    fpms = ssl3_GenerateRSAPMS(ss, pwSpec, pmsToken);
	    if (fpms) {
		ms = NSSSymKey_DeriveSymKey(fpms, msDerive, 
		                            NSSSymKeyType_SSLMS,
	                                    0, keyOps, 0, NULL, NULL, NULL);
		NSSSymKey_Destroy(fpms);
	    }
	    NSSToken_Destroy(pmsToken);
	}
    }
    if (!ms) {
	/* XXX is this the correct analogue to the internal token? */
#if 0
	NSSToken *internal = nssTrustDomain_GetDefaultCryptoToken(ss->td);
	if (!internal) goto loser;
#endif
	NSSToken *internal = NULL;
	/* generate a faux master secret in the internal slot */
	fpms = ssl3_GenerateRSAPMS(ss, pwSpec, internal);
	if (fpms) {
	    ms = NSSSymKey_DeriveSymKey(fpms, msDerive, NSSSymKeyType_SSLMS,
	                                0, keyOps, 0, NULL, NULL, NULL);
	    if (ms) {
		NSSSymKey_Destroy(fpms);
	    } else {
		ms = fpms;
	    }
    	}
	NSSToken_Destroy(internal);
    }
    pwSpec->master_secret = ms;
    NSSAlgNParam_Destroy(msDerive);
    return PR_SUCCESS;
loser:
    if (msDerive) {
	NSSAlgNParam_Destroy(msDerive);
    }
    return PR_FAILURE;
}

/*
 * Key generation given pre master secret, or master secret (if !pms).
 * Sets a useful error code when returning SECFailure.
 *
 * Called only from ssl3_InitPendingCipherSpec(),
 *
 * which in turn is called from
 *              ssl3_SendClientKeyExchange      (for Full handshake)
 *              ssl3_HandleClientKeyExchange    (for Full handshake)
 *              ssl3_HandleServerHello          (for session restart)
 *              ssl3_HandleClientHello          (for session restart)
 * Caller MUST hold the specWriteLock, and SSL3HandshakeLock.
 * ssl3_InitPendingCipherSpec does that.
 */
static PRStatus
ssl3_GenerateSessionKeys(sslSocket *ss, NSSSymKey *pmsOpt)
{
    ssl3CipherSpec *         pwSpec     = ss->ssl3->pwSpec;
    const ssl3BulkCipherDef *cipher_def = pwSpec->cipher_def;
    const ssl3KEADef *       kea_def    = ss->ssl3->hs.kea_def;
    PRBool skipKeysAndIVs = (PRBool)((cipher_def->calg == cipher_fortezza) ||
                                     (cipher_def->calg == cipher_null));
    PRStatus status;
    NSSSSLSessionKeyParameters skParams = { 0 };
    NSSAlgNParam *ap = NULL;
    NSSAlgNParam *skAP = NULL;
    NSSSymKey *sessionKeys[4];
    NSSItem iv1, iv2;
    PRIntn ecx, dcx;
    PRBool isTLS = (PRBool)(pwSpec->version > SSL_LIBRARY_VERSION_3_0);
    PRUint32 keySize;
    NSSSymKeyType keyType;
    PRBool haveSessionKeys = PR_FALSE;
    PRIntn i;

    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss));
    PR_ASSERT( ssl_HaveSpecWriteLock(ss));
    PR_ASSERT(ss->ssl3->prSpec == ss->ssl3->pwSpec);

    /* 
     * derive the master secret if we don't have it yet, or are generating
     * a faux master secret
     */
    status = ssl3_DeriveMasterSecret(ss, pmsOpt);
    if (status == PR_FAILURE) {
	ssl_MapLowLevelError(SSL_ERROR_SESSION_KEY_GEN_FAILURE);
	goto loser;
    }

    /* set up algorithm and parameters for session key derivation */
    skParams.macSizeInBits = pwSpec->mac_size * BPB;
    skParams.isExport = kea_def->is_limited;
    skParams.clientRandom.data = &ss->ssl3->hs.client_random;
    skParams.clientRandom.size = SSL3_RANDOM_LENGTH;
    skParams.serverRandom.data = &ss->ssl3->hs.server_random;
    skParams.serverRandom.size = SSL3_RANDOM_LENGTH;
    skParams.version = isTLS ? NSSSSLVersion_TLS : NSSSSLVersion_SSLv3;

    if (!skipKeysAndIVs) {
	skParams.keySizeInBits = cipher_def->secret_key_size * BPB;
	skParams.ivSizeInBits =  cipher_def->iv_size * BPB;
	skParams.clientIV = (PRUint8 *)pwSpec->client.write_iv; /* XXX */
	skParams.serverIV = (PRUint8 *)pwSpec->server.write_iv;
    }
    skAP = NSSAlgNParam_CreateForSSL(NULL, 
                                     NSSSSLAlgorithm_SessionKeyDerive, 
                                     (NSSParameters *)&skParams);
    if (!skAP) {
	goto loser;
    }
    keySize = cipher_def->key_size;
    keyType = NSSOIDTag_GetSymKeyType(cipher_def->calg);

    /* Derive the set of session keys from the master secret */
    status = nssSymKey_DeriveSSLSessionKeys(pwSpec->master_secret,
                                            skAP, keySize, keyType,
                                            sessionKeys);
    NSSAlgNParam_Destroy(skAP);
    if (status == PR_FAILURE) {
	ssl_MapLowLevelError(SSL_ERROR_SESSION_KEY_GEN_FAILURE);
	goto loser;
    }
    haveSessionKeys = PR_TRUE;

    /* Set up the mac contexts */
    ap = (NSSAlgNParam *)ssl3_GetMacAP(ss->ssl3); /* it's const below */
    pwSpec->client.write_mac_context = NSSSymKey_CreateCryptoContext(
                                                                sessionKeys[0],
                                                                ap, NULL);
    pwSpec->server.write_mac_context = NSSSymKey_CreateCryptoContext(
                                                                sessionKeys[1],
                                                                ap, NULL);

    /* Set up the encryption and decryption contexts */
    if (ss->sec.isServer) {
	iv1.data = skParams.serverIV; iv1.size = cipher_def->iv_size;
	iv2.data = skParams.clientIV; iv2.size = cipher_def->iv_size;
	ecx = 3;
	dcx = 2;
    } else {
	iv1.data = skParams.clientIV; iv1.size = cipher_def->iv_size;
	iv2.data = skParams.serverIV; iv2.size = cipher_def->iv_size;
	ecx = 2;
	dcx = 3;
    }

    ap = ssl3_GetBulkCipherAP(cipher_def, &iv1);
    if (!ap) {
	goto loser;
    }

    pwSpec->encodeContext = NSSSymKey_CreateCryptoContext(sessionKeys[ecx],
                                                          ap, NULL);
    NSSAlgNParam_Destroy(ap);
    if (!pwSpec->encodeContext) {
	goto loser;
    }

    ap = ssl3_GetBulkCipherAP(cipher_def, &iv2);
    if (!ap) {
	NSSCryptoContext_Destroy(pwSpec->encodeContext);
	pwSpec->encodeContext = NULL;
	goto loser;
    }

    pwSpec->decodeContext = NSSSymKey_CreateCryptoContext(sessionKeys[dcx],
                                                          ap, NULL);
    NSSAlgNParam_Destroy(ap);
    if (!pwSpec->decodeContext) {
	NSSCryptoContext_Destroy(pwSpec->encodeContext);
	pwSpec->encodeContext = NULL;
	goto loser;
    }

    for (i=0; i<4; i++) NSSSymKey_Destroy(sessionKeys[i]);
    return PR_SUCCESS;
loser:
    if (haveSessionKeys) {
	for (i=0; i<4; i++) NSSSymKey_Destroy(sessionKeys[i]);
    }
    ssl_MapLowLevelError(SSL_ERROR_SESSION_KEY_GEN_FAILURE);
    return PR_FAILURE;
}

/*
 * Handshake messages
 */
/* Called from	ssl3_AppendHandshake()
**		ssl3_StartHandshakeHash()
**		ssl3_HandleV2ClientHello()
**		ssl3_HandleHandshakeMessage()
** Caller must hold the ssl3Handshake lock.
*/
static SECStatus
ssl3_UpdateHandshakeHashes(sslSocket *ss, unsigned char *b, unsigned int l)
{
    ssl3State *ssl3	= ss->ssl3;
    PRStatus status;
    NSSItem bufIt;

    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss) );

    PRINT_BUF(90, (NULL, "MD5 & SHA handshake hash input:", b, l));

    bufIt.data = b;
    bufIt.size = l;

    status = NSSCryptoContext_ContinueDigest(ssl3->hs.md5, &bufIt);
    if (status == PR_FAILURE) {
	ssl_MapLowLevelError(SSL_ERROR_MD5_DIGEST_FAILURE);
	return SECFailure;
    }
    status = NSSCryptoContext_ContinueDigest(ssl3->hs.sha, &bufIt);
    if (status == PR_FAILURE) {
	ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
	return SECFailure;
    }
    return SECSuccess;
}

/**************************************************************************
 * Append Handshake functions.
 * All these functions set appropriate error codes.
 * Most rely on ssl3_AppendHandshake to set the error code.
 **************************************************************************/
static SECStatus
ssl3_AppendHandshake(sslSocket *ss, const void *void_src, PRInt32 bytes)
{
    unsigned char *  src  = (unsigned char *)void_src;
    int              room = ss->sec.ci.sendBuf.space - ss->sec.ci.sendBuf.size;
    SECStatus        rv;

    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss) ); /* protects sendBuf. */

    if (ss->sec.ci.sendBuf.space < MAX_SEND_BUF_LENGTH && room < bytes) {
	rv = sslBuffer_Grow(&ss->sec.ci.sendBuf, PR_MAX(MIN_SEND_BUF_LENGTH,
		 PR_MIN(MAX_SEND_BUF_LENGTH, ss->sec.ci.sendBuf.size + bytes)));
	if (rv != SECSuccess)
	    return rv;	/* sslBuffer_Grow has set a memory error code. */
	room = ss->sec.ci.sendBuf.space - ss->sec.ci.sendBuf.size;
    }

    PRINT_BUF(60, (ss, "Append to Handshake", (unsigned char*)void_src, bytes));
    rv = ssl3_UpdateHandshakeHashes(ss, src, bytes);
    if (rv != SECSuccess)
	return rv;	/* error code set by ssl3_UpdateHandshakeHashes */

    while (bytes > room) {
	if (room > 0)
	    memcpy(ss->sec.ci.sendBuf.buf + ss->sec.ci.sendBuf.size, src, room);
	ss->sec.ci.sendBuf.size += room;
	rv = ssl3_FlushHandshake(ss, ssl_SEND_FLAG_FORCE_INTO_BUFFER);
	if (rv != SECSuccess) {
	    return rv;	/* error code set by ssl3_FlushHandshake */
	}
	bytes -= room;
	src += room;
	room = ss->sec.ci.sendBuf.space;
	PR_ASSERT(ss->sec.ci.sendBuf.size == 0);
    }
    memcpy(ss->sec.ci.sendBuf.buf + ss->sec.ci.sendBuf.size, src, bytes);
    ss->sec.ci.sendBuf.size += bytes;
    return SECSuccess;
}

static SECStatus
ssl3_AppendHandshakeNumber(sslSocket *ss, PRInt32 num, PRInt32 lenSize)
{
    SECStatus rv;
    uint8     b[4];
    uint8 *   p = b;

    switch (lenSize) {
      case 4:
	*p++ = (num >> 24) & 0xff;
      case 3:
	*p++ = (num >> 16) & 0xff;
      case 2:
	*p++ = (num >> 8) & 0xff;
      case 1:
	*p = num & 0xff;
    }
    SSL_TRC(60, ("%d: number:", SSL_GETPID()));
    rv = ssl3_AppendHandshake(ss, &b[0], lenSize);
    return rv;	/* error code set by AppendHandshake, if applicable. */
}

static SECStatus
ssl3_AppendHandshakeVariable(
    sslSocket *ss, const SSL3Opaque *src, PRInt32 bytes, PRInt32 lenSize)
{
    SECStatus rv;

    PR_ASSERT((bytes < (1<<8) && lenSize == 1) ||
	      (bytes < (1L<<16) && lenSize == 2) ||
	      (bytes < (1L<<24) && lenSize == 3));

    SSL_TRC(60,("%d: append variable:", SSL_GETPID()));
    rv = ssl3_AppendHandshakeNumber(ss, bytes, lenSize);
    if (rv != SECSuccess) {
	return rv;	/* error code set by AppendHandshake, if applicable. */
    }
    SSL_TRC(60, ("data:"));
    rv = ssl3_AppendHandshake(ss, src, bytes);
    return rv;	/* error code set by AppendHandshake, if applicable. */
}

static SECStatus
ssl3_AppendHandshakeHeader(sslSocket *ss, SSL3HandshakeType t, PRUint32 length)
{
    SECStatus rv;

    SSL_TRC(30,("%d: SSL3[%d]: append handshake header: type %s",
    	SSL_GETPID(), ss->fd, ssl3_DecodeHandshakeType(t)));
    PRINT_BUF(60, (ss, "MD5 handshake hash:",
    	          (unsigned char*)ss->ssl3->hs.md5, MD5_LENGTH));
    PRINT_BUF(95, (ss, "SHA handshake hash:",
    	          (unsigned char*)ss->ssl3->hs.sha, SHA1_LENGTH));

    rv = ssl3_AppendHandshakeNumber(ss, t, 1);
    if (rv != SECSuccess) {
    	return rv;	/* error code set by AppendHandshake, if applicable. */
    }
    rv = ssl3_AppendHandshakeNumber(ss, length, 3);
    return rv;		/* error code set by AppendHandshake, if applicable. */
}

/**************************************************************************
 * Consume Handshake functions.
 *
 * All data used in these functions is protected by two locks,
 * the RecvBufLock and the SSL3HandshakeLock
 **************************************************************************/

/* Read up the next "bytes" number of bytes from the (decrypted) input
 * stream "b" (which is *length bytes long). Copy them into buffer "v".
 * Reduces *length by bytes.  Advances *b by bytes.
 *
 * If this function returns SECFailure, it has already sent an alert,
 * and has set a generic error code.  The caller should probably
 * override the generic error code by setting another.
 */
static SECStatus
ssl3_ConsumeHandshake(sslSocket *ss, void *v, PRInt32 bytes, SSL3Opaque **b,
		      PRUint32 *length)
{
    PR_ASSERT( ssl_HaveRecvBufLock(ss) );
    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss) );

    if (bytes > *length) {
	return ssl3_DecodeError(ss);
    }
    memcpy(v, *b, bytes);
    PRINT_BUF(60, (ss, "consume bytes:", *b, bytes));
    *b      += bytes;
    *length -= bytes;
    return SECSuccess;
}

/* Read up the next "bytes" number of bytes from the (decrypted) input
 * stream "b" (which is *length bytes long), and interpret them as an
 * integer in network byte order.  Returns the received value.
 * Reduces *length by bytes.  Advances *b by bytes.
 *
 * Returns SECFailure (-1) on failure.
 * This value is indistinguishable from the equivalent received value.
 * Only positive numbers are to be received this way.
 * Thus, the largest value that may be sent this way is 0x7fffffff.
 * On error, an alert has been sent, and a generic error code has been set.
 */
static PRInt32
ssl3_ConsumeHandshakeNumber(sslSocket *ss, PRInt32 bytes, SSL3Opaque **b,
			    PRUint32 *length)
{
    PRInt32   num = 0;
    int       i;
    SECStatus status;
    uint8     buf[4];

    status = ssl3_ConsumeHandshake(ss, buf, bytes, b, length);
    if (status != SECSuccess) {
	/* ssl3_DecodeError has already been called */
	return SECFailure;
    }
    for (i = 0; i < bytes; i++)
	num = (num << 8) + buf[i];
    return num;
}

/* Read in two values from the incoming decrypted byte stream "b", which is
 * *length bytes long.  The first value is a number whose size is "bytes"
 * bytes long.  The second value is a byte-string whose size is the value
 * of the first number received.  The latter byte-string, and its length,
 * is returned in the SECItem i.
 *
 * Returns SECFailure (-1) on failure.
 * On error, an alert has been sent, and a generic error code has been set.
 */
static SECStatus
ssl3_ConsumeHandshakeVariable(sslSocket *ss, NSSItem *i, PRInt32 bytes,
			      SSL3Opaque **b, PRUint32 *length, 
                              NSSArena *arenaOpt)
{
    PRInt32   count;
    SECStatus rv;

    PR_ASSERT(bytes <= 3);
    i->size  = 0;
    i->data = NULL;
    count = ssl3_ConsumeHandshakeNumber(ss, bytes, b, length);
    if (count < 0) { 		/* Can't test for SECSuccess here. */
    	return SECFailure;
    }
    if (count > 0) {
	i->data = (unsigned char*)nss_ZAlloc(arenaOpt, count);
	if (i->data == NULL) {
	    /* XXX inconsistent.  In other places, we don't send alerts for
	     * our own memory failures.  But here we do... */
	    (void)SSL3_SendAlert(ss, alert_fatal, handshake_failure);
	    nss_SetError(NSS_ERROR_NO_MEMORY);
	    return SECFailure;
	}
	i->size = count;
	rv = ssl3_ConsumeHandshake(ss, i->data, i->size, b, length);
	if (rv != SECSuccess) {
	    nss_ZFreeIf(i->data);
	    i->data = NULL;
	    return rv;	/* alert has already been sent. */
	}
    }
    return SECSuccess;
}

/**************************************************************************
 * end of Consume Handshake functions.
 **************************************************************************/

/* Extract the hashes of handshake messages to this point.
 * Called from ssl3_SendCertificateVerify
 *             ssl3_SendFinished
 *             ssl3_HandleHandshakeMessage
 *
 * Caller must hold the SSL3HandshakeLock.
 * Caller must hold a read or write lock on the Spec R/W lock.
 *	(There is presently no way to assert on a Read lock.)
 */
static SECStatus
ssl3_ComputeHandshakeHashes(sslSocket *     ss,
                            ssl3CipherSpec *spec,   /* uses ->master_secret */
			    SSL3Hashes *    hashes, /* output goes here. */
			    uint32          sender)
{
    ssl3State *   ssl3      = ss->ssl3;
    NSSCryptoContext * md5  = NULL;
    NSSCryptoContext * sha  = NULL;
    SECStatus     rv        = SECFailure; /* set success at end */
    unsigned int  outLength;
    PRBool        isTLS;
    SSL3Opaque    md5_inner[MAX_MAC_LENGTH];
    SSL3Opaque    sha_inner[MAX_MAC_LENGTH];
    unsigned char s[4];
    NSSCryptoContextMark *md5State = NULL;
    NSSCryptoContextMark *shaState = NULL;
    NSSItem in, out;
    PRStatus status = PR_SUCCESS;

    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss) );

    isTLS = (PRBool)(spec->version > SSL_LIBRARY_VERSION_3_0);

    md5State = NSSCryptoContext_Mark(ssl3->hs.md5);
    if (!md5State) {
	ssl_MapLowLevelError(SSL_ERROR_MD5_DIGEST_FAILURE);
	goto loser;
    }
    md5 = ssl3->hs.md5;

    shaState = NSSCryptoContext_Mark(ssl3->hs.sha);
    if (!shaState) {
	ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
	goto loser;
    }
    sha = ssl3->hs.sha;

    if (!isTLS) {
	/* compute hashes for SSL3. */

	s[0] = (unsigned char)(sender >> 24);
	s[1] = (unsigned char)(sender >> 16);
	s[2] = (unsigned char)(sender >> 8);
	s[3] = (unsigned char)sender;

	if (sender != 0) {
	    in.data = s;
	    in.size = sizeof(s);
	    status = NSSCryptoContext_ContinueDigest(md5, &in);
	    if (status == PR_FAILURE) {
		ssl_MapLowLevelError(SSL_ERROR_MD5_DIGEST_FAILURE);
		goto loser;
	    }
	    PRINT_BUF(95, (NULL, "MD5 inner: sender", s, 4));
	}

	PRINT_BUF(95, (NULL, "MD5 inner: MAC Pad 1", 
	                      mac_pad_1, mac_defs[ssl_mac_md5].pad_size));

	status = NSSCryptoContext_DigestKey(md5, spec->master_secret);
	if (status == PR_FAILURE) {
	    ssl_MapLowLevelError(SSL_ERROR_MD5_DIGEST_FAILURE);
	    goto loser;
	}

	NSSITEM_INIT(&in, mac_pad_1, mac_defs[ssl_mac_md5].pad_size);
	status = NSSCryptoContext_ContinueDigest(md5, &in);
	if (status == PR_FAILURE) {
	    ssl_MapLowLevelError(SSL_ERROR_MD5_DIGEST_FAILURE);
	    goto loser;
	}

	NSSITEM_INIT(&out, md5_inner, sizeof(md5_inner));
	if (NSSCryptoContext_FinishDigest(md5, &out, NULL) == NULL) {
	    ssl_MapLowLevelError(SSL_ERROR_MD5_DIGEST_FAILURE);
	    goto loser;
	}

	PRINT_BUF(95, (NULL, "MD5 inner: result", md5_inner, outLength));

	if (sender != 0) {
	    in.data = s; 
	    in.size = sizeof(s);
	    status = NSSCryptoContext_ContinueDigest(sha, &in);
	    if (status == PR_FAILURE) {
		ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
		goto loser;
	    }
	    PRINT_BUF(95, (NULL, "SHA inner: sender", s, 4));
	}

	PRINT_BUF(95, (NULL, "SHA inner: MAC Pad 1", 
	                      mac_pad_1, mac_defs[ssl_mac_sha].pad_size));

	status = NSSCryptoContext_DigestKey(sha, spec->master_secret);
	if (status == PR_FAILURE) {
	    ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
	    goto loser;
	}

	NSSITEM_INIT(&in, mac_pad_1, mac_defs[ssl_mac_md5].pad_size);
	status = NSSCryptoContext_ContinueDigest(sha, &in);
	if (status == PR_FAILURE) {
	    ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
	    goto loser;
	}

	NSSITEM_INIT(&out, sha_inner, sizeof(sha_inner));
	if (NSSCryptoContext_FinishDigest(sha, &out, NULL) == NULL) {
	    ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
	    goto loser;
	}

	PRINT_BUF(95, (NULL, "SHA inner: result", sha_inner, outLength));

	PRINT_BUF(95, (NULL, "MD5 outer: MAC Pad 2", 
	                      mac_pad_2, mac_defs[ssl_mac_md5].pad_size));
	PRINT_BUF(95, (NULL, "MD5 outer: MD5 inner", md5_inner, MD5_LENGTH));

	status = NSSCryptoContext_BeginDigest(md5, NULL, NULL);
	if (status == PR_FAILURE) {
	    ssl_MapLowLevelError(SSL_ERROR_MD5_DIGEST_FAILURE);
	    goto loser;
	}
	status = NSSCryptoContext_DigestKey(md5, spec->master_secret);
	if (status == PR_FAILURE) {
	    ssl_MapLowLevelError(SSL_ERROR_MD5_DIGEST_FAILURE);
	    goto loser;
	}

	NSSITEM_INIT(&in, mac_pad_2, mac_defs[ssl_mac_md5].pad_size);
	status = NSSCryptoContext_ContinueDigest(md5, &in);
	if (status == PR_FAILURE) {
	    ssl_MapLowLevelError(SSL_ERROR_MD5_DIGEST_FAILURE);
	    goto loser;
	}

	NSSITEM_INIT(&in, md5_inner, MD5_LENGTH);
	status = NSSCryptoContext_ContinueDigest(md5, &in);
	if (status == PR_FAILURE) {
	    ssl_MapLowLevelError(SSL_ERROR_MD5_DIGEST_FAILURE);
	    goto loser;
	}
    }

    NSSITEM_INIT(&out, hashes->md5, sizeof(hashes->md5));
    if (NSSCryptoContext_FinishDigest(md5, &out, NULL) == NULL) {
	ssl_MapLowLevelError(SSL_ERROR_MD5_DIGEST_FAILURE);
	goto loser;
    }

    PRINT_BUF(60, (NULL, "MD5 outer: result", hashes->md5, MD5_LENGTH));

    if (!isTLS) {
	PRINT_BUF(95, (NULL, "SHA outer: MAC Pad 2", 
	                      mac_pad_2, mac_defs[ssl_mac_sha].pad_size));
	PRINT_BUF(95, (NULL, "SHA outer: SHA inner", sha_inner, SHA1_LENGTH));

	status = NSSCryptoContext_BeginDigest(sha, NULL, NULL);
	if (status == PR_FAILURE) {
	    ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
	    goto loser;
	}
	status = NSSCryptoContext_DigestKey(sha, spec->master_secret);
	if (status == PR_FAILURE) {
	    ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
	    goto loser;
	}
	NSSITEM_INIT(&in, mac_pad_2, mac_defs[ssl_mac_sha].pad_size);
	status = NSSCryptoContext_ContinueDigest(sha, &in);
	if (status == PR_FAILURE) {
	    ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
	    goto loser;
	}
	NSSITEM_INIT(&in, sha_inner, SHA1_LENGTH);
	status = NSSCryptoContext_ContinueDigest(sha, &in);
	if (status == PR_FAILURE) {
	    ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
	    goto loser;
	}
    }

    NSSITEM_INIT(&out, hashes->sha, sizeof(hashes->sha));
    if (NSSCryptoContext_FinishDigest(sha, &out, NULL) == NULL) {
	ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
	goto loser;
    }

    PRINT_BUF(60, (NULL, "SHA outer: result", hashes->sha, SHA1_LENGTH));

    rv = SECSuccess;

    /* always release the state, even when successful */

loser:
    if (md5State) {
	if (NSSCryptoContext_Release(ssl3->hs.md5, md5State) != PR_SUCCESS) {
	    ssl_MapLowLevelError(SSL_ERROR_MD5_DIGEST_FAILURE);
	    rv = SECFailure;
	}
    }
    if (shaState) {
	if (NSSCryptoContext_Release(ssl3->hs.sha, shaState) != PR_SUCCESS) {
	    ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
	    rv = SECFailure;
	}
    }

    return rv;
}

/*
 * SSL 2 based implementations pass in the initial outbound buffer
 * so that the handshake hash can contain the included information.
 *
 * Called from ssl2_BeginClientHandshake() in sslcon.c
 */
SECStatus
ssl3_StartHandshakeHash(sslSocket *ss, unsigned char * buf, int length)
{
    SECStatus rv;

    ssl_GetSSL3HandshakeLock(ss);  /**************************************/

    rv = ssl3_InitState(ss);
    if (rv != SECSuccess) {
	goto done;		/* ssl3_InitState has set the error code. */
    }

    memset(&ss->ssl3->hs.client_random, 0, SSL3_RANDOM_LENGTH);
    memcpy(
	&ss->ssl3->hs.client_random.rand[SSL3_RANDOM_LENGTH - SSL_CHALLENGE_BYTES],
	&ss->sec.ci.clientChallenge,
	SSL_CHALLENGE_BYTES);

    rv = ssl3_UpdateHandshakeHashes(ss, buf, length);
    /* if it failed, ssl3_UpdateHandshakeHashes has set the error code. */

done:
    ssl_ReleaseSSL3HandshakeLock(ss);  /**************************************/
    return rv;
}

/**************************************************************************
 * end of Handshake Hash functions.
 * Begin Send and Handle functions for handshakes.
 **************************************************************************/

/* Called from ssl3_HandleHelloRequest(),
 *             ssl3_HandleFinished() (for step-up)
 *             ssl3_RedoHandshake()
 *             ssl2_BeginClientHandshake (when resuming ssl3 session)
 */
SECStatus
ssl3_SendClientHello(sslSocket *ss)
{
    sslSessionID *   sid;
    ssl3CipherSpec * cwSpec;
    SECStatus        rv;
    int              i;
    int              length;
    int              num_suites;
    int              actual_count = 0;
    PRStatus         status;

    SSL_TRC(3, ("%d: SSL3[%d]: send client_hello handshake", SSL_GETPID(),
		ss->fd));

    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss) );
    PR_ASSERT( ssl_HaveXmitBufLock(ss) );

    rv = ssl3_InitState(ss);
    if (rv != SECSuccess) {
	return rv;		/* ssl3_InitState has set the error code. */
    }

    SSL_TRC(30,("%d: SSL3[%d]: reset handshake hashes",
	    SSL_GETPID(), ss->fd ));
    status = NSSCryptoContext_BeginDigest(ss->ssl3->hs.md5, NULL, NULL);
    if (status == PR_FAILURE) {
	ssl_MapLowLevelError(SSL_ERROR_MD5_DIGEST_FAILURE);
	return SECFailure;
    }
    status = NSSCryptoContext_BeginDigest(ss->ssl3->hs.sha, NULL, NULL);
    if (status == PR_FAILURE) {
	ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
	return SECFailure;
    }

    /* We ignore ss->sec.ci.sid here, and use ssl_Lookup because Lookup
     * handles expired entries and other details.
     * XXX If we've been called from ssl2_BeginClientHandshake, then
     * this lookup is duplicative and wasteful.
     */
    sid = NULL; /* XXX while not implemented */
#ifdef IMPLEMENT_SSL_SESSION_ID_CACHE
    sid = (ss->noCache) ? NULL
	    : ssl_LookupSID(&ss->sec.ci.peer, ss->sec.ci.port, ss->peerID, ss->url);

    /* We can't resume based on a different token. If the sid exists,
     * make sure the token that holds the master secret still exists ...
     * If we previously did client-auth, make sure that the token that holds
     * the private key still exists, is logged in, hasn't been removed, etc.
     * Also for fortezza, make sure that the card that holds the session keys
     * exist as well... */
    if (sid) {
	PK11SlotInfo *slot;
	PRBool sidOK = PR_TRUE;
	slot = (!sid->u.ssl3.masterValid) ? NULL :
	                     SECMOD_LookupSlot(sid->u.ssl3.masterModuleID,
	                                       sid->u.ssl3.masterSlotID);
	if (slot == NULL) {
	   sidOK = PR_FALSE;
	} else {
	    PK11SymKey *wrapKey = NULL;
	    if (!PK11_IsPresent(slot) ||
		((wrapKey = PK11_GetWrapKey(slot, sid->u.ssl3.masterWrapIndex,
					    sid->u.ssl3.masterWrapMech,
					    sid->u.ssl3.masterWrapSeries,
					    ss->pkcs11PinArg)) == NULL) ) {
		sidOK = PR_FALSE;
	    }
	    if (wrapKey) PK11_FreeSymKey(wrapKey);
	    PK11_FreeSlot(slot);
	    slot = NULL;
	}
	/* do sid-has-FORTEZZA-slot check */
    	if (sid->u.ssl3.hasFortezza) {
	    /* do has fortezza check */
	    if (!PK11_VerifyKeyOK(sid->u.ssl3.tek))
	    	sidOK = PR_FALSE;
	}

	/* If we previously did client-auth, make sure that the token that
	** holds the private key still exists, is logged in, hasn't been
	** removed, etc.
	*/
	if (sidOK && sid->u.ssl3.clAuthValid) {
	    slot = SECMOD_LookupSlot(sid->u.ssl3.clAuthModuleID,
	                             sid->u.ssl3.clAuthSlotID);
	    if (slot == NULL ||
	        !PK11_IsPresent(slot) ||
		sid->u.ssl3.clAuthSeries     != PK11_GetSlotSeries(slot) ||
		sid->u.ssl3.clAuthSlotID     != PK11_GetSlotID(slot)     ||
		sid->u.ssl3.clAuthModuleID   != PK11_GetModuleID(slot)   ||
                !PK11_IsLoggedIn(slot, NULL)) {
	        sidOK = PR_FALSE;
	    }
	    if (slot) {
		PK11_FreeSlot(slot);
		slot = NULL;
	    }
	}

	if (!sidOK) {
	    ++ssl3stats.sch_sid_cache_not_ok;
	    (*ss->sec.uncache)(sid);
	    ssl_FreeSID(sid);
	    sid = NULL;
	}
    }
#endif /* IMPLEMENT_SSL_SESSION_ID_CACHE */

    if (sid) {
	++ssl3stats.sch_sid_cache_hits;

	rv = ssl3_NegotiateVersion(ss, sid->version);
	if (rv != SECSuccess)
	    return rv;	/* error code was set */

	PRINT_BUF(4, (ss, "client, found session-id:", sid->u.ssl3.sessionID,
		      sid->u.ssl3.sessionIDLength));

	ss->ssl3->policy = sid->u.ssl3.policy;
    } else {
	++ssl3stats.sch_sid_cache_misses;

	rv = ssl3_NegotiateVersion(ss, SSL_LIBRARY_VERSION_3_1_TLS);
	if (rv != SECSuccess)
	    return rv;	/* error code was set */

	sid = ssl3_NewSessionID(ss, PR_FALSE);
	if (!sid) {
	    return SECFailure;	/* memory error is set */
        }
    }

    ssl_GetSpecWriteLock(ss);
    cwSpec = ss->ssl3->cwSpec;
    if (cwSpec->mac_def->mac == ssl_mac_null) {
	/* SSL records are not being MACed. */
	cwSpec->version = ss->version;
    }
    ssl_ReleaseSpecWriteLock(ss);

    if (ss->sec.ci.sid != NULL) {
	ssl_FreeSID(ss->sec.ci.sid);	/* decrement ref count, free if zero */
    }
    ss->sec.ci.sid = sid;

    ss->sec.send = ssl3_SendApplicationData;

    /* shouldn't get here if SSL3 is disabled, but ... */
    PR_ASSERT(ss->enableSSL3 || ss->enableTLS);
    if (!ss->enableSSL3 && !ss->enableTLS) {
	nss_SetError(SSL_ERROR_SSL_DISABLED);
    	return SECFailure;
    }

    /* how many suites does our PKCS11 support (regardless of policy)? */
    num_suites = ssl3_config_match_init(ss);
    if (!num_suites)
    	return SECFailure;	/* ssl3_config_match_init has set error code. */

    /* how many suites are permitted by policy and user preference? */
    num_suites = count_cipher_suites(ss, ss->ssl3->policy, PR_TRUE);
    if (!num_suites)
    	return SECFailure;	/* count_cipher_suites has set error code. */

    length = sizeof(SSL3ProtocolVersion) + SSL3_RANDOM_LENGTH +
	1 + ((sid == NULL) ? 0 : sid->u.ssl3.sessionIDLength) +
	2 + num_suites*sizeof(ssl3CipherSuite) +
	1 + compressionMethodsCount;

    rv = ssl3_AppendHandshakeHeader(ss, client_hello, length);
    if (rv != SECSuccess) {
	return rv;	/* err set by ssl3_AppendHandshake* */
    }

    ss->clientHelloVersion = ss->version;
    rv = ssl3_AppendHandshakeNumber(ss, ss->clientHelloVersion, 2);
    if (rv != SECSuccess) {
	return rv;	/* err set by ssl3_AppendHandshake* */
    }
    rv = ssl3_GetNewRandom(&ss->ssl3->hs.client_random);
    if (rv != SECSuccess) {
	return rv;	/* err set by GetNewRandom. */
    }
    rv = ssl3_AppendHandshake(ss, &ss->ssl3->hs.client_random,
                              SSL3_RANDOM_LENGTH);
    if (rv != SECSuccess) {
	return rv;	/* err set by ssl3_AppendHandshake* */
    }

    if (sid)
	rv = ssl3_AppendHandshakeVariable(
	    ss, sid->u.ssl3.sessionID, sid->u.ssl3.sessionIDLength, 1);
    else
	rv = ssl3_AppendHandshakeVariable(ss, NULL, 0, 1);
    if (rv != SECSuccess) {
	return rv;	/* err set by ssl3_AppendHandshake* */
    }

    rv = ssl3_AppendHandshakeNumber(ss, num_suites*sizeof(ssl3CipherSuite), 2);
    if (rv != SECSuccess) {
	return rv;	/* err set by ssl3_AppendHandshake* */
    }


    for (i = 0; i < ssl_V3_SUITES_IMPLEMENTED; i++) {
	ssl3CipherSuiteCfg *suite = &ss->cipherSuites[i];
	if (config_match(suite, ss->ssl3->policy, PR_TRUE)) {
	    actual_count++;
	    if (actual_count > num_suites) {
		/* set error card removal/insertion error */
		nss_SetError(SSL_ERROR_TOKEN_INSERTION_REMOVAL);
		return SECFailure;
	    }
	    rv = ssl3_AppendHandshakeNumber(ss, suite->cipher_suite,
					    sizeof(ssl3CipherSuite));
	    if (rv != SECSuccess) {
		return rv;	/* err set by ssl3_AppendHandshake* */
	    }
	}
    }

    /* if cards were removed or inserted between count_cipher_suites and
     * generating our list, detect the error here rather than send it off to
     * the server.. */
    if (actual_count != num_suites) {
	/* Card removal/insertion error */
	nss_SetError(SSL_ERROR_TOKEN_INSERTION_REMOVAL);
	return SECFailure;
    }

    rv = ssl3_AppendHandshakeNumber(ss, compressionMethodsCount, 1);
    if (rv != SECSuccess) {
	return rv;	/* err set by ssl3_AppendHandshake* */
    }
    for (i = 0; i < compressionMethodsCount; i++) {
	rv = ssl3_AppendHandshakeNumber(ss, compressions[i], 1);
	if (rv != SECSuccess) {
	    return rv;	/* err set by ssl3_AppendHandshake* */
	}
    }

    rv = ssl3_FlushHandshake(ss, 0);
    if (rv != SECSuccess) {
	return rv;	/* error code set by ssl3_FlushHandshake */
    }

    ss->ssl3->hs.ws = wait_server_hello;
    return rv;
}


/* Called from ssl3_HandleHandshakeMessage() when it has deciphered a complete
 * ssl3 Hello Request.
 * Caller must hold Handshake and RecvBuf locks.
 */
static SECStatus
ssl3_HandleHelloRequest(sslSocket *ss)
{
    sslSessionID *sid = ss->sec.ci.sid;
    SECStatus     rv;

    SSL_TRC(3, ("%d: SSL3[%d]: handle hello_request handshake",
		SSL_GETPID(), ss->fd));

    PR_ASSERT(ss->ssl3);
    PR_ASSERT( ssl_HaveRecvBufLock(ss) );
    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss) );

    if (ss->ssl3->hs.ws == wait_server_hello)
	return SECSuccess;
    if (ss->ssl3->hs.ws != idle_handshake || ss->sec.isServer) {
	(void)SSL3_SendAlert(ss, alert_fatal, unexpected_message);
	nss_SetError(SSL_ERROR_RX_UNEXPECTED_HELLO_REQUEST);
	return SECFailure;
    }
    if (sid) {
#ifdef IMPLEMENT_SSL_SESSION_ID_CACHE
	ss->sec.uncache(sid);
#endif /* IMPLEMENT_SSL_SESSION_ID_CACHE */
	ssl_FreeSID(sid);
	ss->sec.ci.sid = NULL;
    }

    ssl_GetXmitBufLock(ss);
    rv = ssl3_SendClientHello(ss);
    ssl_ReleaseXmitBufLock(ss);

    return rv;
}

#ifdef IMPLEMENT_SSL_SESSION_ID_CACHE

#define UNKNOWN_WRAP_MECHANISM 0x7fffffff

static const CK_MECHANISM_TYPE wrapMechanismList[SSL_NUM_WRAP_MECHS] = {
    CKM_DES3_ECB,
    CKM_CAST5_ECB,
    CKM_DES_ECB,
    CKM_KEY_WRAP_LYNKS,
    CKM_IDEA_ECB,
    CKM_CAST3_ECB,
    CKM_CAST_ECB,
    CKM_RC5_ECB,
    CKM_RC2_ECB,
    CKM_CDMF_ECB,
    CKM_SKIPJACK_WRAP,
    CKM_SKIPJACK_CBC64,
    UNKNOWN_WRAP_MECHANISM
};

static int
ssl_FindIndexByWrapMechanism(CK_MECHANISM_TYPE mech)
{
    const CK_MECHANISM_TYPE *pMech = wrapMechanismList;

    while (mech != *pMech && *pMech != UNKNOWN_WRAP_MECHANISM) {
    	++pMech;
    }
    return (*pMech == UNKNOWN_WRAP_MECHANISM) ? -1
                                              : (pMech - wrapMechanismList);
}

static PK11SymKey *
ssl_UnwrapSymWrappingKey(
	SSLWrappedSymWrappingKey *pWswk,
	SECKEYPrivateKey *        svrPrivKey,
	SSL3KEAType               exchKeyType,
	CK_MECHANISM_TYPE         masterWrapMech,
	void *                    pwArg)
{
    PK11SymKey *             unwrappedWrappingKey  = NULL;
    SECItem                  wrappedKey;

    /* found the wrapping key on disk. */
    PR_ASSERT(pWswk->symWrapMechanism == masterWrapMech);
    PR_ASSERT(pWswk->exchKeyType      == exchKeyType);
    if (pWswk->symWrapMechanism != masterWrapMech ||
	pWswk->exchKeyType      != exchKeyType) {
	goto loser;
    }
    wrappedKey.type = siBuffer;
    wrappedKey.data = pWswk->wrappedSymmetricWrappingkey;
    wrappedKey.size  = pWswk->wrappedSymKeyLen;
    PR_ASSERT(wrappedKey.size <= sizeof pWswk->wrappedSymmetricWrappingkey);

    switch (exchKeyType) {
    PK11SymKey *      Ks;
    PK11SlotInfo *    slot;
    SECItem           param;

    case ssl_kea_fortezza:
	/* get the slot that the fortezza server private key is in. */
	slot = PK11_GetSlotFromPrivateKey(svrPrivKey);
	if (slot == NULL) {
	    SET_ERROR_CODE
	    goto loser;
	}

	/* Look up the Token Fixed Key */
	Ks = PK11_FindFixedKey(slot, CKM_SKIPJACK_CBC64, NULL, pwArg);
	PK11_FreeSlot(slot);
	if (Ks == NULL) {
	    SET_ERROR_CODE
	    goto loser;
	}

	/* unwrap client write key with the local Ks and IV */
	param.type = siBuffer;
    	param.data = pWswk->wrapIV;
    	param.size  = pWswk->wrapIVLen;
	unwrappedWrappingKey =
	    PK11_UnwrapSymKey(Ks, CKM_SKIPJACK_CBC64, &param, &wrappedKey,
			      masterWrapMech, CKA_UNWRAP, 0);
	PK11_FreeSymKey(Ks);
	break;

    case ssl_kea_rsa:
	unwrappedWrappingKey =
	    PK11_PubUnwrapSymKey(svrPrivKey, &wrappedKey,
				 masterWrapMech, CKA_UNWRAP, 0);
	break;
    default:
	/* Assert? */
	SET_ERROR_CODE
	goto loser;
    }
loser:
    return unwrappedWrappingKey;
}

/* Each process sharing the server session ID cache has its own array of
 * SymKey pointers for the symmetric wrapping keys that are used to wrap
 * the master secrets.  There is one key for each KEA type.  These Symkeys
 * correspond to the wrapped SymKeys kept in the server session cache.
 */

typedef struct {
    PK11SymKey *      symWrapKey[ssl_kea_kea_size];
} ssl3SymWrapKey;

/* Try to get wrapping key for mechanism from in-memory array.
 * If that fails, look for one on disk.
 * If that fails, generate a new one, put the new one on disk,
 * Put the new key in the in-memory array.
 */
static PK11SymKey *
getWrappingKey( sslSocket *       ss,
		PK11SlotInfo *    masterSecretSlot,
		SSL3KEAType       exchKeyType,
                CK_MECHANISM_TYPE masterWrapMech,
	        void *            pwArg)
{
    CERTCertificate *        svrCert;
    SECKEYPrivateKey *       svrPrivKey;
    SECKEYPublicKey *        svrPubKey             = NULL;
    PK11SymKey *             unwrappedWrappingKey  = NULL;
    PK11SymKey **            pSymWrapKey;
    CK_MECHANISM_TYPE        asymWrapMechanism = CKM_INVALID_MECHANISM;
    int                      length;
    int                      symWrapMechIndex;
    SECStatus                rv;
    SECItem                  wrappedKey;
    SSLWrappedSymWrappingKey wswk;

    static PZLock *          symWrapKeysLock;
    static ssl3SymWrapKey    symWrapKeys[SSL_NUM_WRAP_MECHS];

    svrPrivKey  = ss->serverCerts[exchKeyType].serverKey;
    PR_ASSERT(svrPrivKey != NULL);
    if (!svrPrivKey) {
    	return NULL;	/* why are we here?!? */
    }

    symWrapMechIndex = ssl_FindIndexByWrapMechanism(masterWrapMech);
    PR_ASSERT(symWrapMechIndex >= 0);
    if (symWrapMechIndex < 0)
    	return NULL;	/* invalid masterWrapMech. */

    pSymWrapKey = &symWrapKeys[symWrapMechIndex].symWrapKey[exchKeyType];

    /* atomically initialize the lock */
    if (!symWrapKeysLock)
	nss_InitLock(&symWrapKeysLock, nssILockOther);

    PZ_Lock(symWrapKeysLock);

    unwrappedWrappingKey = *pSymWrapKey;
    if (unwrappedWrappingKey != NULL) {
	if (PK11_VerifyKeyOK(unwrappedWrappingKey)) {
	    unwrappedWrappingKey = PK11_ReferenceSymKey(unwrappedWrappingKey);
	    goto done;
	}
	/* slot series has changed, so this key is no good any more. */
	PK11_FreeSymKey(unwrappedWrappingKey);
	*pSymWrapKey = unwrappedWrappingKey = NULL;
    }

    /* Try to get wrapped SymWrapping key out of the (disk) cache. */
    /* Following call fills in wswk on success. */
    if (ssl_GetWrappingKey(symWrapMechIndex, exchKeyType, &wswk)) {
    	/* found the wrapped sym wrapping key on disk. */
	unwrappedWrappingKey =
	    ssl_UnwrapSymWrappingKey(&wswk, svrPrivKey, exchKeyType,
                                     masterWrapMech, pwArg);
	if (unwrappedWrappingKey) {
	    goto install;
	}
    }

    if (!masterSecretSlot) 	/* caller doesn't want to create a new one. */
    	goto loser;

    length = PK11_GetBestKeyLength(masterSecretSlot, masterWrapMech);
    /* Zero length means fixed key length algorithm, or error.
     * It's ambiguous.
     */
    unwrappedWrappingKey = PK11_KeyGen(masterSecretSlot, masterWrapMech, NULL,
                                       length, pwArg);
    if (!unwrappedWrappingKey) {
    	goto loser;
    }

    /* Prepare the buffer to receive the wrappedWrappingKey,
     * the symmetric wrapping key wrapped using the server's pub key.
     */
    memset(&wswk, 0, sizeof wswk);	/* eliminate UMRs. */

    svrCert         = ss->serverCerts[exchKeyType].serverCert;
    svrPubKey       = CERT_ExtractPublicKey(svrCert);
    if (svrPubKey == NULL) {
	/* CERT_ExtractPublicKey doesn't set error code */
	nss_SetError(SSL_ERROR_EXTRACT_PUBLIC_KEY_FAILURE);
    	goto loser;
    }
    wrappedKey.type = siBuffer;
    wrappedKey.size  = SECKEY_PublicKeyStrength(svrPubKey);
    wrappedKey.data = wswk.wrappedSymmetricWrappingkey;

    PR_ASSERT(wrappedKey.size <= sizeof wswk.wrappedSymmetricWrappingkey);
    if (wrappedKey.size > sizeof wswk.wrappedSymmetricWrappingkey)
    	goto loser;

    /* wrap symmetric wrapping key in server's public key. */
    switch (exchKeyType) {
    PK11SymKey *      Ks;
    PK11SlotInfo *    fSlot;
    SECItem           param;

    case ssl_kea_fortezza:
	/* get the slot that the fortezza server private key is in. */
	fSlot = PK11_GetSlotFromPrivateKey(svrPrivKey);
	if (fSlot == NULL) {
	    SET_ERROR_CODE
	    goto loser;
	}

	/* Look up the Token Fixed Key */
	Ks = PK11_FindFixedKey(fSlot, CKM_SKIPJACK_CBC64, NULL, pwArg);
	PK11_FreeSlot(fSlot);
	if (Ks == NULL) {
	    SET_ERROR_CODE
	    goto loser;
	}

	/* wrap symmetricWrapping key with the local Ks */
	param.type = siBuffer;
    	param.data = wswk.wrapIV;
    	param.size  = sizeof wswk.wrapIV;
	rv = PK11_WrapSymKey(CKM_SKIPJACK_CBC64, &param, Ks,
	                     unwrappedWrappingKey, &wrappedKey);
	wswk.wrapIVLen = param.size;
	PK11_FreeSymKey(Ks);
	asymWrapMechanism = CKM_SKIPJACK_CBC64;
	break;

    case ssl_kea_rsa:
	asymWrapMechanism = CKM_RSA_PKCS;
	rv = PK11_PubWrapSymKey(asymWrapMechanism, svrPubKey,
	                        unwrappedWrappingKey, &wrappedKey);
	break;

    default:
	rv = SECFailure;
	break;
    }

    if (rv != SECSuccess) {
	ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	goto loser;
    }

    PR_ASSERT(asymWrapMechanism != CKM_INVALID_MECHANISM);

    wswk.symWrapMechanism  = masterWrapMech;
    wswk.symWrapMechIndex  = symWrapMechIndex;
    wswk.asymWrapMechanism = asymWrapMechanism;
    wswk.exchKeyType       = exchKeyType;
    wswk.wrappedSymKeyLen  = wrappedKey.size;

    /* put it on disk. */
    /* If the wrapping key for this KEA type has already been set, 
     * then abandon the value we just computed and 
     * use the one we got from the disk.
     */
    if (ssl_SetWrappingKey(&wswk)) {
    	/* somebody beat us to it.  The original contents of our wswk
	 * has been replaced with the content on disk.  Now, discard
	 * the key we just created and unwrap this new one.
	 */
    	PK11_FreeSymKey(unwrappedWrappingKey);

	unwrappedWrappingKey =
	    ssl_UnwrapSymWrappingKey(&wswk, svrPrivKey, exchKeyType,
                                     masterWrapMech, pwArg);
    }

install:
    if (unwrappedWrappingKey) {
	*pSymWrapKey = PK11_ReferenceSymKey(unwrappedWrappingKey);
    }

loser:
done:
    if (svrPubKey) {
    	SECKEY_DestroyPublicKey(svrPubKey);
	svrPubKey = NULL;
    }
    PZ_Unlock(symWrapKeysLock);
    return unwrappedWrappingKey;
}

#endif /* IMPLEMENT_SSL_SESSION_ID_CACHE */

#ifdef FORTEZZA
static SECStatus
ssl3_FortezzaAppendHandshake(sslSocket *ss, unsigned char * data, int len)
{
    SSL3FortezzaKeys *fortezza_CKE  = NULL;
    SECStatus         rv            = SECFailure;

    rv = ssl3_AppendHandshakeHeader(ss, client_key_exchange,
	    (sizeof(*fortezza_CKE)-sizeof(fortezza_CKE->y_c)) + 1 + len);
    if (rv == SECSuccess) {
        rv = ssl3_AppendHandshakeVariable(ss, data, len, 1);
    }
    return rv;	/* err set by ssl3_AppendHandshake* */
}
#endif /* FORTEZZA */

/* Called from ssl3_SendClientKeyExchange(). */
static SECStatus
sendRSAClientKeyExchange(sslSocket * ss, NSSPublicKey * svrPubKey)
{
    NSSSymKey *	        pms             = NULL;
    SECStatus           rv              = SECFailure;
    NSSItem             enc_pms         = { NULL, 0 };
    PRBool              isTLS;

    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss) );
    PR_ASSERT( ssl_HaveXmitBufLock(ss));

    /* Generate the pre-master secret ...  */
    ssl_GetSpecWriteLock(ss);
    isTLS = (PRBool)(ss->ssl3->pwSpec->version > SSL_LIBRARY_VERSION_3_0);

    pms = ssl3_GenerateRSAPMS(ss, ss->ssl3->pwSpec, NULL);
    ssl_ReleaseSpecWriteLock(ss);
    if (pms == NULL) {
	ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	goto loser;
    }

    /* wrap pre-master secret in server's public key. */
    if (NSSPublicKey_WrapSymKey(svrPubKey, s_rsa_wrap_ap, 
                                pms, NULL, &enc_pms, NULL)
          == NULL) {
	ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	goto loser;
    }

    rv = ssl3_InitPendingCipherSpec(ss, pms);
    NSSSymKey_Destroy(pms); pms = NULL;

    if (rv != SECSuccess) {
	ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	goto loser;
    }

    rv = ssl3_AppendHandshakeHeader(ss, client_key_exchange, 
				    isTLS ? enc_pms.size + 2 : enc_pms.size);
    if (rv != SECSuccess) {
	goto loser;	/* err set by ssl3_AppendHandshake* */
    }
    if (isTLS) {
    	rv = ssl3_AppendHandshakeVariable(ss, enc_pms.data, enc_pms.size, 2);
    } else {
	rv = ssl3_AppendHandshake(ss, enc_pms.data, enc_pms.size);
    }
    if (rv != SECSuccess) {
	goto loser;	/* err set by ssl3_AppendHandshake* */
    }

    rv = SECSuccess;

loser:
    if (enc_pms.data != NULL) {
	nss_ZFreeIf(enc_pms.data);
    }
    if (pms != NULL) {
	NSSSymKey_Destroy(pms);
    }
    return rv;
}

#ifdef IMPLEMENT_DH_EPHEMERAL
/* Called from ssl3_SendClientKeyExchange(). */
static SECStatus
sendDHClientKeyExchange(sslSocket * ss, NSSPublicKey * svrPubKey)
{
    NSSSymKey *	pms             = NULL;
    SECStatus           rv      = SECFailure;
    PRBool              isTLS;

    CK_MECHANISM_TYPE	target;
    SECKEYDHParams	dhParam;		/* DH parameters */
    SECKEYPublicKey	*pubKey = NULL;		/* Ephemeral DH key */
    SECKEYPrivateKey	*privKey = NULL;	/* Ephemeral DH key */

    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss) );
    PR_ASSERT( ssl_HaveXmitBufLock(ss));

    isTLS = (PRBool)(ss->ssl3->pwSpec->version > SSL_LIBRARY_VERSION_3_0);

    /* Copy DH parameters from server key */

    dhParam.prime.data = svrPubKey->u.dh.prime.data;
    dhParam.prime.size = svrPubKey->u.dh.prime.size;
    dhParam.base.data = svrPubKey->u.dh.base.data;
    dhParam.base.size = svrPubKey->u.dh.base.size;

    /* Generate ephemeral DH keypair */
    privKey = SECKEY_CreateDHPrivateKey(&dhParam, &pubKey, NULL);
    if (!privKey || !pubKey) {
	    ssl_MapLowLevelError(SEC_ERROR_KEYGEN_FAIL);
	    rv = SECFailure;
	    goto loser;
    }
    PRINT_BUF(50, (ss, "DH public value:",
					pubKey->u.dh.publicValue.data,
					pubKey->u.dh.publicValue.size));

    if (isTLS) target = CKM_TLS_MASTER_KEY_DERIVE_DH;
    else target = CKM_SSL3_MASTER_KEY_DERIVE_DH;

    /* Determine the PMS */

    pms = PK11_PubDerive(privKey, svrPubKey, PR_FALSE, NULL, NULL,
			    CKM_DH_PKCS_DERIVE, target, CKA_DERIVE, 0, NULL);

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
					pubKey->u.dh.publicValue.size + 2);
    if (rv != SECSuccess) {
	goto loser;	/* err set by ssl3_AppendHandshake* */
    }
    rv = ssl3_AppendHandshakeVariable(ss, 
					pubKey->u.dh.publicValue.data,
					pubKey->u.dh.publicValue.size, 2);
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
#endif /* IMPLEMENT_DH_EPHEMERAL */

#ifdef FORTEZZA
/* fortezza client-auth portion of ClientKeyExchange message
 * This function appends the KEA public key from the client's  V3 cert
 * (empty for a V1 cert) to the outgoing ClientKeyExchange message.
 * For a V3 cert, it also computes the Fortezza public key hash of that key
 * and signs that hash with the client's signing private key.
 * It also finds and returns the client's KEA private key.
 *
 * Called from sendFortezzaClientKeyExchange <- ssl3_SendClientKeyExchange()
 */
static SECKEYPrivateKey *
sendFortezzaCKXClientAuth(sslSocket *ss, SSL3FortezzaKeys * fortezza_CKE)
{
    SECKEYPublicKey *	pubKey 		= NULL;
    SECKEYPrivateKey *	privKeaKey 	= NULL;
    CERTCertificate *	peerCert 	= ss->sec.peerCert;
    void *		pwArg 		= ss->pkcs11PinArg;
    SECStatus 		rv 		= SECFailure;
    SECItem 		sigItem;
    SECItem 		hashItem;

    /* extract our own local public key. */
    pubKey = CERT_ExtractPublicKey(ss->ssl3->clientCertificate);
    if (!pubKey) {
	ssl_MapLowLevelError(SSL_ERROR_EXTRACT_PUBLIC_KEY_FAILURE);
	goto loser;
    }

    if (pubKey->keyType == fortezzaKey) {
	/* fortezza clientauth with fortezza V1 certificate */
	rv = ssl3_FortezzaAppendHandshake(ss, NULL, 0);
	if (rv != SECSuccess) {
	    goto loser;	/* err was set by AppendHandshake. */
	}
	privKeaKey = PK11_FindKeyByAnyCert(ss->ssl3->clientCertificate, pwArg);
	if (!privKeaKey) {
	    ssl_MapLowLevelError(SEC_ERROR_NO_KEY);
	}

    } else {
	/* fortezza clientauth w/ V3 certificate or non fortezza cert*/
	CERTCertificate *   ccert 		= NULL;
	SECKEYPublicKey *   foundPubKey 	= NULL;
	unsigned char       hash[SHA1_LENGTH];

	ccert = PK11_FindBestKEAMatch(peerCert, pwArg);
	if (ccert == NULL) {
	    nss_SetError(SSL_ERROR_FORTEZZA_PQG);
	    goto v3_loser;
	}

	foundPubKey = CERT_ExtractPublicKey(ccert);
	if (foundPubKey == NULL) {
	    ssl_MapLowLevelError(SSL_ERROR_EXTRACT_PUBLIC_KEY_FAILURE);
	    goto v3_loser;
	}

	if (foundPubKey->keyType == keaKey) {
	    rv = ssl3_FortezzaAppendHandshake(ss,
			    foundPubKey->u.kea.publicValue.data,
			    foundPubKey->u.kea.publicValue.size);
	    if (rv != SECSuccess) {
		goto v3_loser; /* err was set by AppendHandshake. */
	    }

	    rv = ssl3_ComputeFortezzaPublicKeyHash(
			    foundPubKey->u.kea.publicValue, hash);
	    if (rv != SECSuccess) {
		ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
		goto v3_loser;
	    }
	} else {
	    rv = ssl3_FortezzaAppendHandshake(ss,
			    foundPubKey->u.fortezza.KEAKey.data,
			    foundPubKey->u.fortezza.KEAKey.size);
	    if (rv != SECSuccess) {
		goto v3_loser; /* err was set by AppendHandshake. */
	    }

	    rv = ssl3_ComputeFortezzaPublicKeyHash(
			    foundPubKey->u.fortezza.KEAKey, hash);
	    if (rv != SECSuccess) {
		ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
		goto v3_loser;
	    }
	}

	hashItem.data = (unsigned char *) hash;
	hashItem.size  = SHA1_LENGTH;

	sigItem.data  = fortezza_CKE->y_signature;
	sigItem.size   = sizeof fortezza_CKE->y_signature;

	rv = PK11_Sign(ss->ssl3->clientPrivateKey, &sigItem, &hashItem);
	if (rv != SECSuccess) {
	    ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	    goto v3_loser;
	}

	privKeaKey = PK11_FindKeyByAnyCert(ccert, pwArg);
	if (!privKeaKey) {
	    ssl_MapLowLevelError(SEC_ERROR_NO_KEY);
	}

v3_loser:
	if (foundPubKey)
	    SECKEY_DestroyPublicKey(foundPubKey);
	if (ccert)
	    CERT_DestroyCertificate(ccert);
    } /* fortezza clientauth w/ V3 certificate or non fortezza cert*/

loser:

    if (pubKey)
	SECKEY_DestroyPublicKey(pubKey);
    return privKeaKey;
} /* End of fortezza client-auth. */


/* fortezza without client-auth */
/* fortezza client-auth portion of ClientKeyExchange message
 * This function appends the public KEA key from the client's cert
 * to the outgoing ClientKeyExchange message.
 * It also finds and returns the client's KEA private key.
 *
 * Called from sendFortezzaClientKeyExchange <- ssl3_SendClientKeyExchange()
 */
static SECKEYPrivateKey *
sendFortezzaCKXNoClientAuth(sslSocket *ss)
{
    SECKEYPublicKey *   foundPubKey 	= NULL;
    SECKEYPrivateKey *	privKeaKey 	= NULL;
    CERTCertificate *	ccert 		= NULL;
    CERTCertificate *	peerCert 	= ss->sec.peerCert;
    void *		pwArg 		= ss->pkcs11PinArg;
    SECStatus 		rv 		= SECFailure;

    ccert = PK11_FindBestKEAMatch(peerCert, pwArg);
    if (ccert == NULL) {
	nss_SetError(SSL_ERROR_FORTEZZA_PQG);
	goto loser;
    }

    foundPubKey = CERT_ExtractPublicKey(ccert);
    if (foundPubKey == NULL) {
	ssl_MapLowLevelError(SSL_ERROR_EXTRACT_PUBLIC_KEY_FAILURE);
	goto loser;
    }

    if (foundPubKey->keyType == fortezzaKey) {
	/* fortezza V1 cert */
	rv = ssl3_FortezzaAppendHandshake(ss,
				    foundPubKey->u.fortezza.KEAKey.data,
				    foundPubKey->u.fortezza.KEAKey.size);
	if (rv != SECSuccess) {
	    goto loser; /* err was set by AppendHandshake. */
	}
	privKeaKey = PK11_FindKeyByAnyCert(ccert, pwArg);
	if (!privKeaKey) {
	    ssl_MapLowLevelError(SEC_ERROR_NO_KEY);
	}
    } else {
	/* fortezza V3 cert */
	rv = ssl3_FortezzaAppendHandshake(ss,
				    foundPubKey->u.kea.publicValue.data,
				    foundPubKey->u.kea.publicValue.size);
	if (rv != SECSuccess) {
	    goto loser; /* err was set by AppendHandshake. */
	}
	privKeaKey = PK11_FindKeyByAnyCert(ccert, pwArg);
	if (!privKeaKey) {
	    ssl_MapLowLevelError(SEC_ERROR_NO_KEY);
	}
    }

loser:
    if (foundPubKey)
	SECKEY_DestroyPublicKey(foundPubKey);
    if (ccert)
	CERT_DestroyCertificate(ccert);
    return privKeaKey;
}

/* Called from ssl3_SendClientKeyExchange().  */
static SECStatus
sendFortezzaClientKeyExchange(sslSocket * ss, SECKEYPublicKey * serverKey)
{
    ssl3CipherSpec *	pwSpec = NULL;
    sslSessionID *	sid 		= ss->sec.ci.sid;
    PK11SlotInfo *	slot		= NULL;
    PK11SymKey *	pms 		= NULL;
    PK11SymKey *	tek		= NULL;
    PK11SymKey *	client_write_key = NULL;
    PK11SymKey *	server_write_key = NULL;
    SECKEYPrivateKey *	privKeaKey 	= NULL;
    void *		pwArg 		= ss->pkcs11PinArg;
    SECStatus 		rv 		= SECFailure;
    CK_VERSION 		version;
    SECItem 		param;
    SECItem 		raItem;
    SECItem 		rbItem;
    SECItem 		enc_pms;
    SECItem 		item;
    SSL3FortezzaKeys	fortezza_CKE;
    PRBool              releaseSpecWriteLock = PR_FALSE;

    PR_ASSERT( ssl_HaveXmitBufLock(ss));
    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss) );

    /* first get an appropriate slot for doing MACing.
     * Note: This slot will NOT be a Fortezza slot because Fortezza
     * cannot generate an SSL3 pre-master-secret.
     */
    slot = PK11_GetBestSlot(CKM_SSL3_PRE_MASTER_KEY_GEN, pwArg);
    if (slot == NULL) {
	nss_SetError(SSL_ERROR_TOKEN_SLOT_NOT_FOUND);
	goto loser;
    }

    /* create a pre-Master secret */
    version.major = MSB(ss->version);
    version.minor = LSB(ss->version);

    param.data = (unsigned char *)&version;
    param.size  = sizeof version;

    pms = PK11_KeyGen(slot, CKM_SSL3_PRE_MASTER_KEY_GEN,
			 &param, 0, pwArg);
    PK11_FreeSlot(slot);
    slot = NULL;
    if (pms == NULL) {
	ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	goto loser;
    }

    /* If we don't have a certificate, we need to read out your public key.
     * This changes a bit when we need to deal with the PQG stuff
     */
    memset(fortezza_CKE.y_signature, 0, sizeof fortezza_CKE.y_signature);

    /* Send the KEA public key and get the KEA private key. */
    if (ss->ssl3->clientCertificate != NULL) {
	/* with client-auth */
	privKeaKey = sendFortezzaCKXClientAuth(ss, &fortezza_CKE);
    } else {
	/* without client-auth */
	privKeaKey = sendFortezzaCKXNoClientAuth(ss);
    }
    if (privKeaKey == NULL) {
	rv = SECFailure;
	goto loser;	/* error was already set. */
    }

    /* Now we derive the TEK, and generate r_c the client's "random" public key.
     * r_c is generated and filled in by the PubDerive call below.
     */
    raItem.data = fortezza_CKE.r_c;
    raItem.size  = sizeof fortezza_CKE.r_c;

    /* R_s == server's "random" public key, sent in the Server Key Exchange */
    rbItem.data = ss->ssl3->fortezza.R_s;
    rbItem.size  = sizeof ss->ssl3->fortezza.R_s;

    tek = PK11_PubDerive(privKeaKey, serverKey, PR_TRUE, /* generate r_c */
                         &raItem, &rbItem, CKM_KEA_KEY_DERIVE,
			 CKM_SKIPJACK_WRAP, CKA_WRAP, 0, pwArg);
    SECKEY_DestroyPrivateKey(privKeaKey);
    privKeaKey = NULL;
    if (tek == NULL) {
	ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	goto loser;
    }

    ss->ssl3->fortezza.tek = PK11_ReferenceSymKey(tek); /* can't fail. */

    /* encrypt the pms with the TEK.
     * NB: PK11_WrapSymKey will generate and output the encrypted PMS
     *     AND the IV for decrypting the PMS.
     */
    param.data   = fortezza_CKE.master_secret_iv;
    param.size    = sizeof fortezza_CKE.master_secret_iv;

    enc_pms.data = fortezza_CKE.encrypted_preMasterSecret;
    enc_pms.size  = sizeof fortezza_CKE.encrypted_preMasterSecret;

    rv = PK11_WrapSymKey(CKM_SKIPJACK_CBC64, &param, tek, pms, &enc_pms);
    if (rv != SECSuccess) {
	ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	goto loser;
    }
    rv = SECFailure;	/* not there yet. */

    slot = PK11_GetSlotFromKey(tek);

    ssl_GetSpecWriteLock(ss); releaseSpecWriteLock = PR_TRUE;

    pwSpec  = ss->ssl3->pwSpec;
    pwSpec->client.write_key = client_write_key =
		    PK11_KeyGen(slot, CKM_SKIPJACK_CBC64, NULL, 0, pwArg);
    if (client_write_key == NULL) {
	ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	goto loser;
    }
    /* the -1 is a hack. It's supposed to be key size, but we use it
     * to tell the wrapper that we're doing a weird PKCS #11 key gen.
     * Usually the result of key gen is an encrypt key. This is not
     * the case with SSL, where this key is a decrypt key.
     */
    pwSpec->server.write_key = server_write_key =
		    PK11_KeyGen(slot, CKM_SKIPJACK_CBC64, NULL, -1, pwArg);
    if (server_write_key == NULL) {
	ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	goto loser;
    }

    rv = ssl3_InitPendingCipherSpec(ss,  pms);
    PK11_FreeSymKey(pms); pms = NULL;
    if (rv != SECSuccess) {
	ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	goto loser;
    }

    /* copy the keys and IVs out now */
    item.data = fortezza_CKE.wrapped_client_write_key;
    item.size  = sizeof fortezza_CKE.wrapped_client_write_key;
    rv = PK11_WrapSymKey(CKM_SKIPJACK_WRAP, NULL, tek, client_write_key, &item);
    if (rv != SECSuccess) {
	ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	goto loser;
    }

    item.data = fortezza_CKE.wrapped_server_write_key;
    item.size  = sizeof fortezza_CKE.wrapped_server_write_key;
    rv = PK11_WrapSymKey(CKM_SKIPJACK_WRAP, NULL, tek, server_write_key, &item);
    if (rv != SECSuccess) {
	ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	goto loser;
    }

    /* we only get the generated IV's if we're doing skipjack.  */
    if (pwSpec->cipher_def->calg == calg_fortezza) {
	memcpy(fortezza_CKE.client_write_iv, pwSpec->client.write_iv,
				    sizeof fortezza_CKE.client_write_iv);
	memcpy(fortezza_CKE.server_write_iv, pwSpec->server.write_iv,
				    sizeof fortezza_CKE.server_write_iv);
    } else {
	/* generate IVs to make old servers happy */
	rv = PK11_GenerateFortezzaIV(client_write_key,
	                             fortezza_CKE.client_write_iv,
	                             sizeof fortezza_CKE.client_write_iv);
	if (rv != SECSuccess) {
	    ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	    goto loser;
	}
	rv = PK11_GenerateFortezzaIV(server_write_key,
	                             fortezza_CKE.server_write_iv,
	                             sizeof fortezza_CKE.server_write_iv);
	if (rv != SECSuccess) {
	    ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	    goto loser;
	}
    }

    /* NOTE: This technique of writing out the struct, rather than writing
     * out the individual members works only because all the rest of the
     * values are fixed-length strings of well-defined byte order.
     * Add one SECItem or one Number and we will need to break the elements out.
     */
    rv = ssl3_AppendHandshake(ss, &fortezza_CKE.r_c,
			      (sizeof fortezza_CKE - sizeof fortezza_CKE.y_c));
    if (rv != SECSuccess) {
	goto loser;	/* err was set by AppendHandshake. */
    }

    /* now we initialize our contexts */
    sid->u.ssl3.hasFortezza = PR_TRUE;
    sid->u.ssl3.tek         = tek; tek = NULL; 	/* adopt.. */

    if (pwSpec->cipher_def->calg == calg_fortezza) {
	sid->u.ssl3.clientWriteKey =
			    PK11_ReferenceSymKey(pwSpec->client.write_key);
	sid->u.ssl3.serverWriteKey=
			    PK11_ReferenceSymKey(pwSpec->server.write_key);

	memcpy(sid->u.ssl3.keys.client_write_iv,
	            pwSpec->client.write_iv,
		    sizeof sid->u.ssl3.keys.client_write_iv);
	memcpy(sid->u.ssl3.keys.server_write_iv,
	            pwSpec->server.write_iv,
		    sizeof sid->u.ssl3.keys.server_write_iv);

	rv = PK11_SaveContext((PK11Context *)pwSpec->encodeContext,
			      sid->u.ssl3.clientWriteSave,
			      &sid->u.ssl3.clientWriteSaveLen,
			      sizeof sid->u.ssl3.clientWriteSave);
	if (rv != SECSuccess) {
	    ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	    goto loser;
	}
    } else {
	PK11_FreeSymKey(client_write_key);
	pwSpec->client.write_key = client_write_key = NULL;

	PK11_FreeSymKey(server_write_key);
	pwSpec->server.write_key = server_write_key = NULL;

	rv = SECSuccess;
    }
    /* FALL THROUGH */

loser:
    if (tek)    PK11_FreeSymKey(tek);
    if (slot)   PK11_FreeSlot(slot);
    if (pms)    PK11_FreeSymKey(pms);
    if (rv != SECSuccess) {
    	if (client_write_key) {
	    PK11_FreeSymKey(client_write_key);
	    pwSpec->client.write_key = client_write_key = NULL;
	}
    	if (server_write_key) {
	    PK11_FreeSymKey(server_write_key);
	    pwSpec->server.write_key = server_write_key = NULL;
	}
    }
    if (releaseSpecWriteLock)
	ssl_GetSpecWriteLock(ss);
    return rv;
}
#endif /* FORTEZZA */

/* Called from ssl3_HandleServerHelloDone(). */
static SECStatus
ssl3_SendClientKeyExchange(sslSocket *ss)
{
    NSSPublicKey * serverKey = NULL;
    SECStatus      rv        = SECFailure;
    PRBool         isTLS;

    SSL_TRC(3, ("%d: SSL3[%d]: send client_key_exchange handshake",
		SSL_GETPID(), ss->fd));

    PR_ASSERT( ssl_HaveXmitBufLock(ss));
    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss));

    if (ss->sec.peerKey == NULL) {
	serverKey = NSSCert_GetPublicKey(ss->sec.peerCert);
	if (serverKey == NULL) {
	    nss_SetError(SSL_ERROR_EXTRACT_PUBLIC_KEY_FAILURE);
	    return SECFailure;
	}
    } else {
	serverKey = ss->sec.peerKey;
	ss->sec.peerKey = NULL; /* we're done with it now */
    }

    isTLS = (PRBool)(ss->ssl3->pwSpec->version > SSL_LIBRARY_VERSION_3_0);
    /* enforce limits on kea key sizes. */
    if (ss->ssl3->hs.kea_def->is_limited) {
	int keyBits = NSSPublicKey_GetKeyStrength(serverKey);

	if (keyBits > ss->ssl3->hs.kea_def->key_size_limit) {
	    if (isTLS)
		(void)SSL3_SendAlert(ss, alert_fatal, export_restriction);
	    else
		(void)ssl3_HandshakeFailure(ss);
	    nss_SetError(SSL_ERROR_PUB_KEY_SIZE_LIMIT_EXCEEDED);
	    goto loser;
	}
    }

    ss->sec.keaType    = ss->ssl3->hs.kea_def->exchKeyType;
    ss->sec.keaKeyBits = NSSPublicKey_GetKeyStrength(serverKey);

    switch (ss->ssl3->hs.kea_def->exchKeyType) {
    case ssl_kea_rsa:
	rv = sendRSAClientKeyExchange(ss, serverKey);
	break;

#ifdef FORTEZZA
    case ssl_kea_fortezza:
	rv = sendFortezzaClientKeyExchange(ss, serverKey);
	break;
#endif /* FORTEZZA */

#ifdef IMPLEMENT_DH_EPHEMERAL
    case ssl_kea_dh:
	rv = sendDHClientKeyExchange(ss, serverKey);
	break;
#endif /* IMPLEMENT_DH_EPHEMERAL */

    default:
	/* got an unknown or unsupported Key Exchange Algorithm.  */
	SEND_ALERT
	nss_SetError(SSL_ERROR_UNSUPPORTED_KEY_EXCHANGE_ALG);
	break;
    }

    SSL_TRC(3, ("%d: SSL3[%d]: DONE sending client_key_exchange",
		SSL_GETPID(), ss->fd));

loser:
    if (serverKey) 
    	NSSPublicKey_Destroy(serverKey);
    return rv;	/* err code already set. */
}

/* Called from ssl3_HandleServerHelloDone(). */
static SECStatus
ssl3_SendCertificateVerify(sslSocket *ss)
{
    ssl3State *   ssl3 		= ss->ssl3;
    SECStatus     rv		= SECFailure;
    PRBool        isTLS;
    NSSItem       buf           = { NULL, 0 };
    SSL3Hashes    hashes;

    PR_ASSERT( ssl_HaveXmitBufLock(ss));
    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss));

    SSL_TRC(3, ("%d: SSL3[%d]: send certificate_verify handshake",
		SSL_GETPID(), ss->fd));

    ssl_GetSpecReadLock(ss);
    rv = ssl3_ComputeHandshakeHashes(ss, ssl3->pwSpec, &hashes, 0);
    ssl_ReleaseSpecReadLock(ss);
    if (rv != SECSuccess) {
	goto done;	/* err code was set by ssl3_ComputeHandshakeHashes */
    }

    isTLS = (PRBool)(ssl3->pwSpec->version > SSL_LIBRARY_VERSION_3_0);
    rv = ssl3_SignHashes(&hashes, ssl3->clientPrivateKey, &buf, isTLS);
#ifdef IMPLEMENT_SESSION_ID_CACHE
    if (rv == SECSuccess) {
	PK11SlotInfo * slot;
	sslSessionID * sid   = ss->sec.ci.sid;

    	/* Remember the info about the slot that did the signing.
	** Later, when doing an SSL restart handshake, verify this.
	** These calls are mere accessors, and can't fail.
	*/
	slot = PK11_GetSlotFromPrivateKey(ss->ssl3->clientPrivateKey);
	sid->u.ssl3.clAuthSeries     = PK11_GetSlotSeries(slot);
	sid->u.ssl3.clAuthSlotID     = PK11_GetSlotID(slot);
	sid->u.ssl3.clAuthModuleID   = PK11_GetModuleID(slot);
	sid->u.ssl3.clAuthValid      = PR_TRUE;
	PK11_FreeSlot(slot);
    }
#endif /* IMPLEMENT_SESSION_ID_CACHE */
    /* If we're doing RSA key exchange, we're all done with the private key
     * here.  Diffie-Hellman & Fortezza key exchanges need the client's
     * private key for the key exchange.
     */
    if (ssl3->hs.kea_def->exchKeyType == ssl_kea_rsa) {
	NSSPrivateKey_Destroy(ssl3->clientPrivateKey);
	ssl3->clientPrivateKey = NULL;
    }
    if (rv != SECSuccess) {
	goto done;	/* err code was set by ssl3_SignHashes */
    }

    rv = ssl3_AppendHandshakeHeader(ss, certificate_verify, buf.size + 2);
    if (rv != SECSuccess) {
	goto done;	/* error code set by AppendHandshake */
    }
    rv = ssl3_AppendHandshakeVariable(ss, buf.data, buf.size, 2);
    if (rv != SECSuccess) {
	goto done;	/* error code set by AppendHandshake */
    }

done:
    if (buf.data)
	nss_ZFreeIf(buf.data);
    return rv;
}

/* Called from ssl3_HandleHandshakeMessage() when it has deciphered a complete
 * ssl3 ServerHello message.
 * Caller must hold Handshake and RecvBuf locks.
 */
static SECStatus
ssl3_HandleServerHello(sslSocket *ss, SSL3Opaque *b, PRUint32 length)
{
    sslSessionID *sid		= ss->sec.ci.sid;
    PRInt32       temp;		/* allow for consume number failure */
    PRBool        suite_found   = PR_FALSE;
    int           i;
    int           errCode	= SSL_ERROR_RX_MALFORMED_SERVER_HELLO;
    SECStatus     rv;
    NSSItem       sidBytes 	= { NULL, 0 };
    PRBool        sid_match;
    PRBool        isTLS		= PR_FALSE;
    SSL3AlertDescription desc   = illegal_parameter;
    SSL3ProtocolVersion version;

    SSL_TRC(3, ("%d: SSL3[%d]: handle server_hello handshake",
    	SSL_GETPID(), ss->fd));
    PR_ASSERT( ssl_HaveRecvBufLock(ss) );
    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss) );

    rv = ssl3_InitState(ss);
    if (rv != SECSuccess) {
	errCode = NSS_GetError(); /* ssl3_InitState has set the error code. */
	goto alert_loser;
    }
    if (ss->ssl3->hs.ws != wait_server_hello) {
        errCode = SSL_ERROR_RX_UNEXPECTED_SERVER_HELLO;
	desc    = unexpected_message;
	goto alert_loser;
    }

    temp = ssl3_ConsumeHandshakeNumber(ss, 2, &b, &length);
    if (temp < 0) {
    	goto loser; 	/* alert has been sent */
    }
    version = (SSL3ProtocolVersion)temp;

    /* this is appropriate since the negotiation is complete, and we only
    ** know SSL 3.x.
    */
    if (MSB(version) != MSB(SSL_LIBRARY_VERSION_3_0)) {
    	desc = (version > SSL_LIBRARY_VERSION_3_0) ? protocol_version : handshake_failure;
	goto alert_loser;
    }

    rv = ssl3_NegotiateVersion(ss, version);
    if (rv != SECSuccess) {
    	desc = (version > SSL_LIBRARY_VERSION_3_0) ? protocol_version : handshake_failure;
	errCode = SSL_ERROR_NO_CYPHER_OVERLAP;
	goto alert_loser;
    }
    isTLS = (ss->version > SSL_LIBRARY_VERSION_3_0);

    rv = ssl3_ConsumeHandshake(
	ss, &ss->ssl3->hs.server_random, SSL3_RANDOM_LENGTH, &b, &length);
    if (rv != SECSuccess) {
    	goto loser; 	/* alert has been sent */
    }

    rv = ssl3_ConsumeHandshakeVariable(ss, &sidBytes, 1, &b, &length, NULL);
    if (rv != SECSuccess) {
    	goto loser; 	/* alert has been sent */
    }
    if (sidBytes.size > SSL3_SESSIONID_BYTES) {
	if (isTLS)
	    desc = decode_error;
	goto alert_loser;	/* malformed. */
    }

    /* find selected cipher suite in our list. */
    temp = ssl3_ConsumeHandshakeNumber(ss, 2, &b, &length);
    if (temp < 0) {
    	goto loser; 	/* alert has been sent */
    }
    ssl3_config_match_init(ss);
    for (i = 0; i < ssl_V3_SUITES_IMPLEMENTED; i++) {
	ssl3CipherSuiteCfg *suite = &ss->cipherSuites[i];
	if ((temp == suite->cipher_suite) &&
	    (config_match(suite, ss->ssl3->policy, PR_TRUE))) {
	    suite_found = PR_TRUE;
	    break;	/* success */
	}
    }
    if (!suite_found) {
    	desc    = handshake_failure;
	errCode = SSL_ERROR_NO_CYPHER_OVERLAP;
	goto alert_loser;
    }
    ss->ssl3->hs.cipher_suite = (ssl3CipherSuite)temp;
    ss->ssl3->hs.suite_def    = ssl_LookupCipherSuiteDef((ssl3CipherSuite)temp);
    PR_ASSERT(ss->ssl3->hs.suite_def);
    if (!ss->ssl3->hs.suite_def) {
	goto loser;	/* we don't send alerts for our screw-ups. */
    }

    /* find selected compression method in our list. */
    temp = ssl3_ConsumeHandshakeNumber(ss, 1, &b, &length);
    if (temp < 0) {
    	goto loser; 	/* alert has been sent */
    }
    suite_found = PR_FALSE;
    for (i = 0; i < compressionMethodsCount; i++) {
	if (temp == compressions[i])  {
	    suite_found = PR_TRUE;
	    break;	/* success */
    	}
    }
    if (!suite_found) {
    	desc    = handshake_failure;
	errCode = SSL_ERROR_NO_COMPRESSION_OVERLAP;
	goto alert_loser;
    }
    ss->ssl3->hs.compression = (SSL3CompressionMethod)temp;

    if (length != 0) {	/* malformed */
	goto alert_loser;
    }

    /* Any errors after this point are not "malformed" errors. */
    desc    = handshake_failure;

    /* we need to call ssl3_SetupPendingCipherSpec here so we can check the
     * key exchange algorithm. */
    rv = ssl3_SetupPendingCipherSpec(ss, ss->ssl3);
    if (rv != SECSuccess) {
	goto alert_loser;	/* error code is set. */
    }

    /* We may or may not have sent a session id, we may get one back or
     * not and if so it may match the one we sent.
     * Attempt to restore the master secret to see if this is so...
     * Don't consider failure to find a matching SID an error.
     */
    sid_match = (PRBool)(sidBytes.size > 0 &&
	sidBytes.size == sid->u.ssl3.sessionIDLength &&
	!memcmp(sid->u.ssl3.sessionID, sidBytes.data, sidBytes.size));

#ifdef IMPLEMENT_SESSION_ID_CACHE
    if (sid_match &&
	sid->version == ss->version &&
	sid->u.ssl3.cipherSuite == ss->ssl3->hs.cipher_suite) do {
	PK11SlotInfo *slot;
	PK11SymKey *  wrapKey;     /* wrapping key */
	SECItem       wrappedMS;   /* wrapped master secret. */
	CK_FLAGS      keyFlags      = 0;

        ss->sec.authAlgorithm = sid->authAlgorithm;
	ss->sec.authKeyBits   = sid->authKeyBits;
	ss->sec.keaType       = sid->keaType;
	ss->sec.keaKeyBits    = sid->keaKeyBits;

	slot = SECMOD_LookupSlot(sid->u.ssl3.masterModuleID,
	                         sid->u.ssl3.masterSlotID);
	if (slot == NULL) {
	    break;		/* not considered an error. */
	}
	if (!PK11_IsPresent(slot)) {
	    PK11_FreeSlot(slot);
	    break;		/* not considered an error. */
	}
	wrapKey = PK11_GetWrapKey(slot, sid->u.ssl3.masterWrapIndex,
				  sid->u.ssl3.masterWrapMech,
				  sid->u.ssl3.masterWrapSeries,
				  ss->pkcs11PinArg);
	PK11_FreeSlot(slot);
	if (wrapKey == NULL) {
	    break;		/* not considered an error. */
	}

	if (ss->version > SSL_LIBRARY_VERSION_3_0) {	/* isTLS */
	    keyFlags = CKF_SIGN | CKF_VERIFY;
	}

        wrappedMS.data = sid->u.ssl3.keys.wrapped_master_secret;
	wrappedMS.size  = sid->u.ssl3.keys.wrapped_master_secret_len;
	ss->ssl3->pwSpec->master_secret =
	    PK11_UnwrapSymKeyWithFlags(wrapKey, sid->u.ssl3.masterWrapMech, 
	    		NULL, &wrappedMS, CKM_SSL3_MASTER_KEY_DERIVE,
		        CKA_DERIVE, sizeof(SSL3MasterSecret), keyFlags);
	errCode = NSS_GetError();
	PK11_FreeSymKey(wrapKey);
	if (ss->ssl3->pwSpec->master_secret == NULL) {
	    break;	/* errorCode set just after call to UnwrapSymKey. */
	}

	/* Got a Match */
	++ssl3stats.hsh_sid_cache_hits;
	ss->ssl3->hs.ws         = wait_change_cipher;
	ss->ssl3->hs.isResuming = PR_TRUE;

	/* copy the peer cert from the SID */
	if (sid->peerCert != NULL) {
	    ss->sec.peerCert = CERT_DupCertificate(sid->peerCert);
	}

	/* reload the FORTEZZA key material. These keys aren't generated
	 * by the master secret, but by the key exchange. We restart by
	 * reusing these keys. */
	if (sid->u.ssl3.hasFortezza) {
	    ss->ssl3->fortezza.tek = PK11_ReferenceSymKey(sid->u.ssl3.tek);
	}
	if (ss->ssl3->hs.suite_def->bulk_cipher_alg == cipher_fortezza) {
	    ss->ssl3->pwSpec->client.write_key =
	    		PK11_ReferenceSymKey(sid->u.ssl3.clientWriteKey);
	    ss->ssl3->pwSpec->server.write_key =
	    		PK11_ReferenceSymKey(sid->u.ssl3.serverWriteKey);
	    /* add the tek later for pre-encrypted files */
	    memcpy(ss->ssl3->pwSpec->client.write_iv,
			sid->u.ssl3.keys.client_write_iv,
			sizeof sid->u.ssl3.keys.client_write_iv);
	    memcpy(ss->ssl3->pwSpec->server.write_iv,
			sid->u.ssl3.keys.server_write_iv,
			sizeof sid->u.ssl3.keys.server_write_iv);
	}

	/* NULL value for PMS signifies re-use of the old MS */
	rv = ssl3_InitPendingCipherSpec(ss,  NULL);
	if (rv != SECSuccess) {
	    goto alert_loser;	/* err code was set by ssl3_InitPendingCipherSpec */
	}
	if (ss->ssl3->hs.suite_def->bulk_cipher_alg == cipher_fortezza) {
	    rv = PK11_RestoreContext(
			(PK11Context *)ss->ssl3->pwSpec->encodeContext,
			sid->u.ssl3.clientWriteSave,
			sid->u.ssl3.clientWriteSaveLen);
	    if (rv != SECSuccess) {
		goto alert_loser;	/* err is set. */
	    }
	}
	SECITEM_ZfreeItem(&sidBytes, PR_FALSE);	
	return SECSuccess;
    } while (0);

    if (sid_match)
	++ssl3stats.hsh_sid_cache_not_ok;
    else
	++ssl3stats.hsh_sid_cache_misses;

    /* throw the old one away */
    sid->u.ssl3.resumable = PR_FALSE;
    (*ss->sec.uncache)(sid);
    ssl_FreeSID(sid);

    /* get a new sid */
    ss->sec.ci.sid = sid = ssl3_NewSessionID(ss, PR_FALSE);
    if (sid == NULL) {
	goto alert_loser;	/* memory error is set. */
    }

    sid->version = ss->version;
    sid->u.ssl3.sessionIDLength = sidBytes.size;
    memcpy(sid->u.ssl3.sessionID, sidBytes.data, sidBytes.size);
#endif /* IMPLEMENT_SESSION_ID_CACHE */
    nss_ZFreeIf(sidBytes.data);


    ss->ssl3->hs.isResuming = PR_FALSE;
    ss->ssl3->hs.ws         = wait_server_cert;
    return SECSuccess;

alert_loser:
    (void)SSL3_SendAlert(ss, alert_fatal, desc);

loser:
    if (sidBytes.data != NULL)
	nss_ZFreeIf(sidBytes.data);
    errCode = ssl_MapLowLevelError(errCode);
    return SECFailure;
}

/* Called from ssl3_HandleHandshakeMessage() when it has deciphered a complete
 * ssl3 ServerKeyExchange message.
 * Caller must hold Handshake and RecvBuf locks.
 */
static SECStatus
ssl3_HandleServerKeyExchange(sslSocket *ss, SSL3Opaque *b, PRUint32 length)
{
    NSSPublicKey *   peerKey   = NULL;
    NSSPublicKeyInfo keyInfo;
    PRBool           isTLS;
    SECStatus        rv;
    int              errCode   = SSL_ERROR_RX_MALFORMED_SERVER_KEY_EXCH;
    SSL3AlertDescription desc  = illegal_parameter;
    NSSItem          signature = { NULL, 0 };
    SSL3Hashes       hashes;
    NSSArena *       arena     = NULL;

    SSL_TRC(3, ("%d: SSL3[%d]: handle server_key_exchange handshake",
		SSL_GETPID(), ss->fd));
    PR_ASSERT( ssl_HaveRecvBufLock(ss) );
    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss) );

    if (ss->ssl3->hs.ws != wait_server_key &&
	ss->ssl3->hs.ws != wait_server_cert) {
	errCode = SSL_ERROR_RX_UNEXPECTED_SERVER_KEY_EXCH;
	desc    = unexpected_message;
	goto alert_loser;
    }
    if (ss->sec.peerCert == NULL) {
	errCode = SSL_ERROR_RX_UNEXPECTED_SERVER_KEY_EXCH;
	desc    = unexpected_message;
	goto alert_loser;
    }

    isTLS = (PRBool)(ss->ssl3->prSpec->version > SSL_LIBRARY_VERSION_3_0);

    arena = NSSArena_Create();
    if (!arena) {
	goto no_memory;
    }

    switch (ss->ssl3->hs.kea_def->exchKeyType) {

    case ssl_kea_rsa:
	keyInfo.kind = NSSKeyPairType_RSA;

    	rv = ssl3_ConsumeHandshakeVariable(ss, &keyInfo.u.rsa.modulus, 
	                                   2, &b, &length, arena);
    	if (rv != SECSuccess) {
	    goto loser;		/* malformed. */
	}
    	rv = ssl3_ConsumeHandshakeVariable(ss, &keyInfo.u.rsa.publicExponent, 
	                                   2, &b, &length, arena);
    	if (rv != SECSuccess) {
	    goto loser;		/* malformed. */
	}
    	rv = ssl3_ConsumeHandshakeVariable(ss, &signature, 2, 
	                                   &b, &length, arena);
    	if (rv != SECSuccess) {
	    goto loser;		/* malformed. */
	}
    	if (length != 0) {
	    if (isTLS)
		desc = decode_error;
	    goto alert_loser;		/* malformed. */
	}

	/* failures after this point are not malformed handshakes. */
	/* TLS: send decrypt_error if signature failed. */
    	desc = isTLS ? decrypt_error : handshake_failure;

    	/*
     	 *  check to make sure the hash is signed by right guy
     	 */
    	rv = ssl3_ComputeExportRSAKeyHash(keyInfo.u.rsa.modulus, 
	                                  keyInfo.u.rsa.publicExponent,
					  &ss->ssl3->hs.client_random,
					  &ss->ssl3->hs.server_random, 
	                                  &hashes, ss->td);
        if (rv != SECSuccess) {
	    errCode =
	    	ssl_MapLowLevelError(SSL_ERROR_SERVER_KEY_EXCHANGE_FAILURE);
	    goto alert_loser;
	}
        rv = ssl3_VerifySignedHashes(&hashes, ss->sec.peerCert, &signature,
	                             isTLS, ss->pkcs11PinArg);
	if (rv != SECSuccess)  {
	    errCode =
	    	ssl_MapLowLevelError(SSL_ERROR_SERVER_KEY_EXCHANGE_FAILURE);
	    goto alert_loser;
	}

	peerKey = NSSVolatileDomain_ImportPublicKeyByInfo(ss->vd, &keyInfo, 
	                                                  NULL, 0, 0, NULL);
    	ss->sec.peerKey = peerKey;
    	ss->ssl3->hs.ws = wait_cert_request;
	NSSArena_Destroy(arena);
    	return SECSuccess;

    case ssl_kea_dh:
	keyInfo.kind = NSSKeyPairType_DH;

    	rv = ssl3_ConsumeHandshakeVariable(ss, &keyInfo.u.dh.prime, 
	                                   2, &b, &length, arena);
    	if (rv != SECSuccess) {
	    goto loser;		/* malformed. */
	}
    	rv = ssl3_ConsumeHandshakeVariable(ss, &keyInfo.u.dh.base, 
	                                   2, &b, &length, arena);
    	if (rv != SECSuccess) {
	    goto loser;		/* malformed. */
	}
    	rv = ssl3_ConsumeHandshakeVariable(ss, &keyInfo.u.dh.publicValue, 
	                                   2, &b, &length, arena);
    	if (rv != SECSuccess) {
	    goto loser;		/* malformed. */
	}
    	rv = ssl3_ConsumeHandshakeVariable(ss, &signature, 
	                                   2, &b, &length, arena);
    	if (rv != SECSuccess) {
	    goto loser;		/* malformed. */
	}
    	if (length != 0) {
	    if (isTLS)
		desc = decode_error;
	    goto alert_loser;		/* malformed. */
	}

	PRINT_BUF(60, (NULL, "Server DH p", keyInfo.u.dh.prime.data, 
	                                    keyInfo.u.dh.prime.size));
	PRINT_BUF(60, (NULL, "Server DH g", keyInfo.u.dh.base.data, 
	                                    keyInfo.u.dh.base.size));
	PRINT_BUF(60, (NULL, "Server DH Ys", keyInfo.u.dh.publicValue.data, 
	                                     keyInfo.u.dh.publicValue.size));

	/* failures after this point are not malformed handshakes. */
	/* TLS: send decrypt_error if signature failed. */
    	desc = isTLS ? decrypt_error : handshake_failure;

    	/*
     	 *  check to make sure the hash is signed by right guy
     	 */
    	rv = ssl3_ComputeDHKeyHash(keyInfo.u.dh.prime, keyInfo.u.dh.base, 
	                           keyInfo.u.dh.publicValue,
	                           &ss->ssl3->hs.client_random,
	                           &ss->ssl3->hs.server_random, 
	                           &hashes, ss->td);
        if (rv != SECSuccess) {
	    errCode =
	    	ssl_MapLowLevelError(SSL_ERROR_SERVER_KEY_EXCHANGE_FAILURE);
	    goto alert_loser;
	}
        rv = ssl3_VerifySignedHashes(&hashes, ss->sec.peerCert, &signature,
				    isTLS, ss->pkcs11PinArg);
	if (rv != SECSuccess)  {
	    errCode =
	    	ssl_MapLowLevelError(SSL_ERROR_SERVER_KEY_EXCHANGE_FAILURE);
	    goto alert_loser;
	}

	peerKey = NSSVolatileDomain_ImportPublicKeyByInfo(ss->vd, &keyInfo, 
	                                                  NULL, 0, 0, NULL);
    	ss->sec.peerKey = peerKey;
    	ss->ssl3->hs.ws = wait_cert_request;
	NSSArena_Destroy(arena);
    	return SECSuccess;

#ifdef FORTEZZA
    case ssl_kea_fortezza:

	/* Fortezza needs *BOTH* a server cert message
	 * and a server key exchange message.
 	 */
	if (ss->ssl3->hs.ws == wait_server_cert) {
	    errCode = SSL_ERROR_RX_UNEXPECTED_SERVER_KEY_EXCH;
	    desc    = unexpected_message;
	    goto alert_loser;
	}
	/* Get the server's "random" public key. */
    	rv = ssl3_ConsumeHandshake(ss, ss->ssl3->fortezza.R_s,
				   sizeof ss->ssl3->fortezza.R_s, &b, &length);
    	if (rv != SECSuccess) {
	    goto loser;		/* malformed */
	}

    	ss->ssl3->hs.ws = wait_cert_request;
    	return SECSuccess;
#endif /* FORTEZZA */

    default:
    	desc    = handshake_failure;
	errCode = SSL_ERROR_UNSUPPORTED_KEY_EXCHANGE_ALG;
	break;		/* goto alert_loser; */
    }

alert_loser:
    (void)SSL3_SendAlert(ss, alert_fatal, desc);
loser:
    if (arena) {
	NSSArena_Destroy(arena);
    }
    nss_SetError( errCode );
    return SECFailure;

no_memory:	/* no-memory error has already been set. */
    ssl_MapLowLevelError(SSL_ERROR_SERVER_KEY_EXCHANGE_FAILURE);
    return SECFailure;
}

/* Called from ssl3_HandleHandshakeMessage() when it has deciphered a complete
 * ssl3 Certificate Request message.
 * Caller must hold Handshake and RecvBuf locks.
 */
static SECStatus
ssl3_HandleCertificateRequest(sslSocket *ss, SSL3Opaque *b, PRUint32 length)
{
    ssl3State *          ssl3        = ss->ssl3;
    NSSArena *           arena       = NULL;
    unsigned char *      data;
    PRInt32              remaining;
    PRInt32              len;
    PRInt32              arraySize   = 2;
    PRInt32              numCAs      = 0;
    PRBool               isTLS       = PR_FALSE;
    int                  errCode     = SSL_ERROR_RX_MALFORMED_CERT_REQUEST;
    SECStatus            rv;
    SSL3AlertDescription desc        = illegal_parameter;
    NSSItem              cert_types  = {NULL, 0};
    NSSDER **            ca_list;

    SSL_TRC(3, ("%d: SSL3[%d]: handle certificate_request handshake",
		SSL_GETPID(), ss->fd));
    PR_ASSERT( ssl_HaveRecvBufLock(ss) );
    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss) );

    if (ssl3->hs.ws != wait_cert_request &&
    	ssl3->hs.ws != wait_server_key) {
	desc    = unexpected_message;
	errCode = SSL_ERROR_RX_UNEXPECTED_CERT_REQUEST;
	goto alert_loser;
    }

    /* clean up anything left from previous handshake. */
    if (ssl3->clientCertChain != NULL) {
       NSSCertChain_Destroy(ssl3->clientCertChain);
       ssl3->clientCertChain = NULL;
    }

    isTLS = (PRBool)(ssl3->prSpec->version > SSL_LIBRARY_VERSION_3_0);
    rv = ssl3_ConsumeHandshakeVariable(ss, &cert_types, 1, &b, &length, NULL);
    if (rv != SECSuccess)
    	goto loser;		/* malformed, alert has been sent */

    remaining = ssl3_ConsumeHandshakeNumber(ss, 2, &b, &length);
    if (remaining < 0)
    	goto loser;	 	/* malformed, alert has been sent */

    arena = NSSArena_Create();
    if (!arena)
	goto no_mem;

    ca_list = nss_ZNEWARRAY(arena, NSSDER *, arraySize + 1);
    if (ca_list == NULL)
    	goto no_mem;

    while (remaining != 0) {
	if (remaining < 2)
	    goto alert_loser;	/* malformed */

	len = ssl3_ConsumeHandshakeNumber(ss, 2, &b, &length);
	if (len < 0)
	    goto loser;		/* malformed, alert has been sent */

	remaining -= 2;
	if (remaining < len)
	    goto alert_loser;	/* malformed */

	data = nss_ZAlloc(arena, len);
	if (data == NULL)
	    goto no_mem;

	rv = ssl3_ConsumeHandshake(ss, data, len, &b, &length);
	if (rv != SECSuccess)
	    goto loser;		/* malformed, alert has been sent */

	remaining -= len;
	ca_list[numCAs] = NSSItem_Create(arena, NULL, len, data);
	if (!ca_list[numCAs])
	    goto no_mem;
	numCAs++;

	if (remaining == 0)
	    break;		/* success */

	if (numCAs == arraySize) {
	    arraySize *= 2;
	    ca_list = nss_ZREALLOCARRAY(ca_list, NSSDER *, arraySize + 1);
	    if (!ca_list) {
		goto no_mem;
	    }
	}
    }

    if (length != 0)
        goto alert_loser;   	/* malformed */

    desc = no_certificate;
    ssl3->hs.ws = wait_hello_done;

    if (ss->getClientAuthData == NULL) {
	rv = SECFailure; /* force it to send a no_certificate alert */
    } else {
	/* XXX Should pass cert_types in this call!! */
	rv = (*ss->getClientAuthData)(ss->getClientAuthDataArg,
	                              ss->fd, ss->td, ca_list,
	                              &ssl3->clientCertificate,
	                              &ssl3->clientPrivateKey);
    }
    switch (rv) {
    case SECWouldBlock:	/* getClientAuthData has put up a dialog box. */
	ssl_SetAlwaysBlock(ss);
	break;	/* not an error */

    case SECSuccess:
	/* Setting ssl3->clientCertChain non-NULL will cause
	 * ssl3_HandleServerHelloDone to call SendCertificate.
	 */
	ssl3->clientCertChain = NSSVolatileDomain_CreateCertChain(ss->vd,
	                                           ssl3->clientCertificate,
	                                           NSSTime_Now(),
	                                           &s_ssl_client_usage,
	                                           NULL);
	if (ssl3->clientCertChain == NULL) {
	    if (ssl3->clientCertificate != NULL) {
		NSSCert_Destroy(ssl3->clientCertificate);
		ssl3->clientCertificate = NULL;
	    }
	    if (ssl3->clientPrivateKey != NULL) {
		NSSPrivateKey_Destroy(ssl3->clientPrivateKey);
		ssl3->clientPrivateKey = NULL;
	    }
	    goto send_no_certificate;
	}
	break;	/* not an error */

    case SECFailure:
    default:
send_no_certificate:
	if (isTLS) {
	    ssl3->sendEmptyCert = PR_TRUE;
	} else {
	    (void)SSL3_SendAlert(ss, alert_warning, no_certificate);
	}
	rv = SECSuccess;
	break;
    }
    goto done;

no_mem:
    rv = SECFailure;
    goto done;

alert_loser:
    if (isTLS && desc == illegal_parameter)
    	desc = decode_error;
    (void)SSL3_SendAlert(ss, alert_fatal, desc);
loser:
    nss_SetError(errCode);
    rv = SECFailure;
done:
    if (arena != NULL)
    	NSSArena_Destroy(arena);
    if (cert_types.data != NULL)
    	nss_ZFreeIf(cert_types.data);
    return rv;
}

/*
 * attempt to restart the handshake after asynchronously handling
 * a request for the client's certificate.
 *
 * inputs:
 *	cert	Client cert chosen by application.
 *		Note: ssl takes this reference, and does not bump the
 *		reference count.  The caller should drop its reference
 *		without calling CERT_DestroyCert after calling this function.
 *
 *	key	Private key associated with cert.  This function makes a
 *		copy of the private key, so the caller remains responsible
 *		for destroying its copy after this function returns.
 *
 *	certChain  DER-encoded certs, client cert and its signers.
 *		Note: ssl takes this reference, and does not copy the chain.
 *		The caller should drop its reference without destroying the
 *		chain.  SSL will free the chain when it is done with it.
 *
 * Return value: XXX
 *
 * XXX This code only works on the initial handshake on a connection, XXX
 *     It does not work on a subsequent handshake (redo).
 *
 * Caller holds 1stHandshakeLock.
 */
SECStatus
ssl3_RestartHandshakeAfterCertReq(sslSocket *         ss,
                                  NSSCert *           cert,
                                  NSSPrivateKey *     key,
                                  NSSCertChain *      certChain)
{
    SECStatus        rv          = SECSuccess;

    if (MSB(ss->version) == MSB(SSL_LIBRARY_VERSION_3_0)) {
	/* XXX This code only works on the initial handshake on a connection,
	** XXX It does not work on a subsequent handshake (redo).
	*/
	if (ss->handshake != 0) {
	    ss->handshake               = ssl_GatherRecord1stHandshake;
	    ss->ssl3->clientCertificate = cert;
	    ss->ssl3->clientCertChain   = certChain;
	    if (key == NULL) {
		(void)SSL3_SendAlert(ss, alert_warning, no_certificate);
		ss->ssl3->clientPrivateKey = NULL;
	    } else {
/* XXX does this need a reference? */
		ss->ssl3->clientPrivateKey = key;
	    }
	    ssl_GetRecvBufLock(ss);
	    if (ss->ssl3->hs.msgState.buf != NULL) {
		rv = ssl3_HandleRecord(ss, NULL, &ss->gs.buf);
	    }
	    ssl_ReleaseRecvBufLock(ss);
	}
    }
    return rv;
}



/* Called from ssl3_HandleHandshakeMessage() when it has deciphered a complete
 * ssl3 Server Hello Done message.
 * Caller must hold Handshake and RecvBuf locks.
 */
static SECStatus
ssl3_HandleServerHelloDone(sslSocket *ss)
{
    SECStatus     rv;
    SSL3WaitState ws          = ss->ssl3->hs.ws;
    PRBool        send_verify = PR_FALSE;

    SSL_TRC(3, ("%d: SSL3[%d]: handle server_hello_done handshake",
		SSL_GETPID(), ss->fd));
    PR_ASSERT( ssl_HaveRecvBufLock(ss) );
    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss) );

    if (ws != wait_hello_done  &&
        ws != wait_server_cert &&
	ws != wait_server_key  &&
	ws != wait_cert_request) {
	SSL3_SendAlert(ss, alert_fatal, unexpected_message);
	nss_SetError(SSL_ERROR_RX_UNEXPECTED_HELLO_DONE);
	return SECFailure;
    }

    ssl_GetXmitBufLock(ss);		/*******************************/

    if (ss->ssl3->sendEmptyCert) {
	ss->ssl3->sendEmptyCert = PR_FALSE;
	rv = ssl3_SendEmptyCertificate(ss);
	/* Don't send verify */
	if (rv != SECSuccess) {
	    goto loser;	/* error code is set. */
    	}
    } else
    if (ss->ssl3->clientCertChain  != NULL &&
	ss->ssl3->clientPrivateKey != NULL) {
	send_verify = PR_TRUE;
	rv = ssl3_SendCertificate(ss);
	if (rv != SECSuccess) {
	    goto loser;	/* error code is set. */
    	}
    }

    rv = ssl3_SendClientKeyExchange(ss);
    if (rv != SECSuccess) {
    	goto loser;	/* err is set. */
    }

    if (send_verify) {
	rv = ssl3_SendCertificateVerify(ss);
	if (rv != SECSuccess) {
	    goto loser;	/* err is set. */
        }
    }
    rv = ssl3_SendChangeCipherSpecs(ss);
    if (rv != SECSuccess) {
	goto loser;	/* err code was set. */
    }
    rv = ssl3_SendFinished(ss, 0);
    if (rv != SECSuccess) {
	goto loser;	/* err code was set. */
    }

    ssl_ReleaseXmitBufLock(ss);		/*******************************/

    ss->ssl3->hs.ws = wait_change_cipher;
    return SECSuccess;

loser:
    ssl_ReleaseXmitBufLock(ss);
    return rv;
}

/*
 * Routines used by servers
 */
static SECStatus
ssl3_SendHelloRequest(sslSocket *ss)
{
    SECStatus rv;

    SSL_TRC(3, ("%d: SSL3[%d]: send hello_request handshake", SSL_GETPID(),
		ss->fd));

    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss) );
    PR_ASSERT( ssl_HaveXmitBufLock(ss) );

    rv = ssl3_AppendHandshakeHeader(ss, hello_request, 0);
    if (rv != SECSuccess) {
	return rv;	/* err set by AppendHandshake */
    }
    rv = ssl3_FlushHandshake(ss, 0);
    if (rv != SECSuccess) {
	return rv;	/* error code set by ssl3_FlushHandshake */
    }
    ss->ssl3->hs.ws = wait_client_hello;
    return SECSuccess;
}

/* Sets memory error when returning NULL.
 * Called from:
 *	ssl3_SendClientHello()
 *	ssl3_HandleServerHello()
 *	ssl3_HandleClientHello()
 *	ssl3_HandleV2ClientHello()
 */
static sslSessionID *
ssl3_NewSessionID(sslSocket *ss, PRBool is_server)
{
    sslSessionID *sid;

    sid = nss_ZNEW(NULL, sslSessionID);
    if (sid == NULL)
    	return sid;

    sid->peerID		= (ss->peerID == NULL) ? NULL : NSSUTF8_Duplicate(ss->peerID, NULL);
    sid->urlSvrName	= (ss->url    == NULL) ? NULL : NSSUTF8_Duplicate(ss->url, NULL);
    sid->addr           = ss->sec.ci.peer;
    sid->port           = ss->sec.ci.port;
    sid->references     = 1;
    sid->cached         = never_cached;
    sid->version        = ss->version;

    sid->u.ssl3.resumable      = PR_TRUE;
    sid->u.ssl3.policy         = SSL_ALLOWED;
    sid->u.ssl3.hasFortezza    = PR_FALSE;
#ifdef FORTEZZA
    sid->u.ssl3.clientWriteKey = NULL;
    sid->u.ssl3.serverWriteKey = NULL;
    sid->u.ssl3.tek            = NULL;
#endif /* FORTEZZA */

    if (is_server) {
	SECStatus rv;
	int       pid = SSL_GETPID();

	sid->u.ssl3.sessionIDLength = SSL3_SESSIONID_BYTES;
	sid->u.ssl3.sessionID[0]    = (pid >> 8) & 0xff;
	sid->u.ssl3.sessionID[1]    =  pid       & 0xff;
	if (NSS_GenerateRandom(SSL3_SESSIONID_BYTES - 2, 
	                       sid->u.ssl3.sessionID + 2, NULL) == NULL)
	{
	    ssl_FreeSID(sid);
	    ssl_MapLowLevelError(SSL_ERROR_GENERATE_RANDOM_FAILURE);
	    return NULL;
    	}
    }
    return sid;
}

/* Called from:  ssl3_HandleClientHello, ssl3_HandleV2ClientHello */
static SECStatus
ssl3_SendServerHelloSequence(sslSocket *ss)
{
    const ssl3KEADef *kea_def;
    SECStatus         rv;

    SSL_TRC(3, ("%d: SSL3[%d]: begin send server_hello sequence",
		SSL_GETPID(), ss->fd));

    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss) );
    PR_ASSERT( ssl_HaveXmitBufLock(ss) );

    rv = ssl3_SendServerHello(ss);
    if (rv != SECSuccess) {
	return rv;	/* err code is set. */
    }
    rv = ssl3_SendCertificate(ss);
    if (rv != SECSuccess) {
	return rv;	/* error code is set. */
    }
    /* We have to do this after the call to ssl3_SendServerHello,
     * because kea_def is set up by ssl3_SendServerHello().
     */
    kea_def = ss->ssl3->hs.kea_def;
    ss->ssl3->hs.usedStepDownKey = PR_FALSE;
    if (kea_def->kea == kea_fortezza) {
	rv = ssl3_SendServerKeyExchange(ss);
	if (rv != SECSuccess) {
	    return rv;	/* err code was set. */
	}
    } else if (kea_def->is_limited && kea_def->exchKeyType == ssl_kea_rsa) {
	/* see if we can legally use the key in the cert. */
	int keyLen;  /* bytes */

	keyLen = NSSPrivateKey_GetPrivateModulusLength(
			    ss->serverCerts[kea_def->exchKeyType].serverKey);

	if (keyLen > 0 &&
	    keyLen * BPB <= kea_def->key_size_limit ) {
	    /* XXX AND cert is not signing only!! */
	    /* just fall through and use it. */
	} else if (ss->stepDownKeyPair != NULL) {
	    ss->ssl3->hs.usedStepDownKey = PR_TRUE;
	    rv = ssl3_SendServerKeyExchange(ss);
	    if (rv != SECSuccess) {
		return rv;	/* err code was set. */
	    }
	} else {
#ifndef HACKED_EXPORT_SERVER
	    nss_SetError(SSL_ERROR_PUB_KEY_SIZE_LIMIT_EXCEEDED);
	    return rv;
#endif
	}
    }

    if (ss->requestCertificate) {
	rv = ssl3_SendCertificateRequest(ss);
	if (rv != SECSuccess) {
	    return rv;		/* err code is set. */
	}
    }
    rv = ssl3_SendServerHelloDone(ss);
    if (rv != SECSuccess) {
	return rv;		/* err code is set. */
    }

    ss->ssl3->hs.ws = (ss->requestCertificate) ? wait_client_cert
                                               : wait_client_key;
    return SECSuccess;
}

/* Called from ssl3_HandleHandshakeMessage() when it has deciphered a complete
 * ssl3 Client Hello message.
 * Caller must hold Handshake and RecvBuf locks.
 */
static SECStatus
ssl3_HandleClientHello(sslSocket *ss, SSL3Opaque *b, PRUint32 length)
{
    sslSessionID *      sid      = NULL;
    ssl3State *         ssl3;
    PRInt32		tmp;
    unsigned int        i;
    int                 j;
    SECStatus           rv;
    int                 errCode  = SSL_ERROR_RX_MALFORMED_CLIENT_HELLO;
    SSL3AlertDescription desc    = illegal_parameter;
    SSL3ProtocolVersion version;
    NSSItem             sidBytes = {NULL, 0};
    NSSItem             suites   = {NULL, 0};
    NSSItem             comps    = {NULL, 0};
    PRBool              haveSpecWriteLock = PR_FALSE;
    PRBool              haveXmitBufLock   = PR_FALSE;

    SSL_TRC(3, ("%d: SSL3[%d]: handle client_hello handshake",
    	SSL_GETPID(), ss->fd));

    PR_ASSERT( ssl_HaveRecvBufLock(ss) );
    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss));

    /* Get peer name of client */
    rv = ssl_GetPeerInfo(ss);
    if (rv != SECSuccess) {
	return rv;		/* error code is set. */
    }

    rv = ssl3_InitState(ss);
    if (rv != SECSuccess) {
	return rv;		/* ssl3_InitState has set the error code. */
    }
    ssl3 = ss->ssl3;

    if ((ssl3->hs.ws != wait_client_hello) &&
	(ssl3->hs.ws != idle_handshake)) {
	desc    = unexpected_message;
	errCode = SSL_ERROR_RX_UNEXPECTED_CLIENT_HELLO;
	goto alert_loser;
    }

    tmp = ssl3_ConsumeHandshakeNumber(ss, 2, &b, &length);
    if (tmp < 0)
	goto loser;		/* malformed, alert already sent */
    ss->clientHelloVersion = version = (SSL3ProtocolVersion)tmp;
    rv = ssl3_NegotiateVersion(ss, version);
    if (rv != SECSuccess) {
    	desc = (version > SSL_LIBRARY_VERSION_3_0) ? protocol_version : handshake_failure;
	errCode = SSL_ERROR_NO_CYPHER_OVERLAP;
	goto alert_loser;
    }

    /* grab the client random data. */
    rv = ssl3_ConsumeHandshake(
	ss, &ssl3->hs.client_random, SSL3_RANDOM_LENGTH, &b, &length);
    if (rv != SECSuccess) {
	goto loser;		/* malformed */
    }

    /* grab the client's SID, if present. */
    rv = ssl3_ConsumeHandshakeVariable(ss, &sidBytes, 1, &b, &length, NULL);
    if (rv != SECSuccess) {
	goto loser;		/* malformed */
    }

#ifdef IMPLEMENT_SESSION_ID_CACHE
    if (sidBytes.size > 0) {
	SSL_TRC(7, ("%d: SSL3[%d]: server, lookup client session-id for 0x%08x%08x%08x%08x",
                    SSL_GETPID(), ss->fd, ss->sec.ci.peer.pr_s6_addr32[0],
		    ss->sec.ci.peer.pr_s6_addr32[1], 
		    ss->sec.ci.peer.pr_s6_addr32[2],
		    ss->sec.ci.peer.pr_s6_addr32[3]));
	sid = (*ssl_sid_lookup)(&ss->sec.ci.peer, sidBytes.data, sidBytes.size,
	                        ss->dbHandle);
    }
    SECITEM_FreeItem(&sidBytes, PR_FALSE);
#endif /* IMPLEMENT_SESSION_ID_CACHE */

    /* grab the list of cipher suites. */
    rv = ssl3_ConsumeHandshakeVariable(ss, &suites, 2, &b, &length, NULL);
    if (rv != SECSuccess) {
	goto loser;		/* malformed */
    }

    /* grab the list of compression methods. */
    rv = ssl3_ConsumeHandshakeVariable(ss, &comps, 1, &b, &length, NULL);
    if (rv != SECSuccess) {
	goto loser;		/* malformed */
    }

    /* It's OK for length to be non-zero here.
     * Non-zero length means that some new protocol revision has extended
     * the client hello message.
     */

    desc = handshake_failure;

#ifdef IMPLEMENT_SESSION_ID_CACHE
    if (sid != NULL) {
	/* We've found a session cache entry for this client.
	 * Now, if we're going to require a client-auth cert,
	 * and we don't already have this client's cert in the session cache,
	 * and this is the first handshake on this connection (not a redo),
	 * then drop this old cache entry and start a new session.
	 */
	if ((sid->peerCert == NULL) && ss->requestCertificate &&
	    ((ss->requireCertificate == SSL_REQUIRE_ALWAYS) ||
	     (ss->requireCertificate == SSL_REQUIRE_NO_ERROR) ||
	     ((ss->requireCertificate == SSL_REQUIRE_FIRST_HANDSHAKE) 
	      && !ss->firstHsDone))) {

	    ++ssl3stats.hch_sid_cache_not_ok;
	    ss->sec.uncache(sid);
	    ssl_FreeSID(sid);
	    sid = NULL;
	}
    }
#endif /* IMPLEMENT_SESSION_ID_CACHE */

    /* Look for a matching cipher suite. */
    j = ssl3_config_match_init(ss);
    if (j <= 0) {		/* no ciphers are working/supported by PK11 */
    	errCode = NSS_GetError(); /* error code is already set. */
	goto alert_loser;
    }
    /* If we already have a session for this client, be sure to pick the
    ** same cipher suite we picked before.
    ** This is not a loop, despite appearances.
    */
    if (sid) do {
	ssl3CipherSuiteCfg *suite = ss->cipherSuites;
	for (j = ssl_V3_SUITES_IMPLEMENTED; j > 0; --j, ++suite) {
	    if (suite->cipher_suite == sid->u.ssl3.cipherSuite)
		break;
	}
	if (!j)
	    break;
	if (!config_match(suite, ssl3->policy, PR_TRUE))
	    break;
	for (i = 0; i < suites.size; i += 2) {
	    if ((NSSITEM_DATA(&suites, i  ) == MSB(suite->cipher_suite)) &&
	        (NSSITEM_DATA(&suites, i+1) == LSB(suite->cipher_suite))) {

		ssl3->hs.cipher_suite = suite->cipher_suite;
		ssl3->hs.suite_def =
		    ssl_LookupCipherSuiteDef(ssl3->hs.cipher_suite);
		goto suite_found;
	    }
	}
    } while (0);

    /* Select a cipher suite.
    ** NOTE: This suite selection algorithm should be the same as the one in
    ** ssl3_HandleV2ClientHello().  
    */
    for (j = 0; j < ssl_V3_SUITES_IMPLEMENTED; j++) {
	ssl3CipherSuiteCfg *suite = &ss->cipherSuites[j];
	if (!config_match(suite, ssl3->policy, PR_TRUE))
	    continue;
	for (i = 0; i < suites.size; i += 2) {
	    if ((NSSITEM_DATA(&suites, i  ) == MSB(suite->cipher_suite)) &&
	        (NSSITEM_DATA(&suites, i+1) == LSB(suite->cipher_suite))) {

		ssl3->hs.cipher_suite = suite->cipher_suite;
		ssl3->hs.suite_def =
		    ssl_LookupCipherSuiteDef(ssl3->hs.cipher_suite);
		goto suite_found;
	    }
	}
    }
    errCode = SSL_ERROR_NO_CYPHER_OVERLAP;
    goto alert_loser;

suite_found:
    /* Look for a matching compression algorithm. */
    for (i = 0; i < comps.size; i++) {
	for (j = 0; j < compressionMethodsCount; j++) {
	    if (NSSITEM_DATA(&comps, i) == compressions[j]) {
		ssl3->hs.compression = (SSL3CompressionMethod)compressions[j];
		goto compression_found;
	    }
	}
    }
    errCode = SSL_ERROR_NO_COMPRESSION_OVERLAP;
    				/* null compression must be supported */
    goto alert_loser;

compression_found:
    nss_ZFreeIf(suites.data);
    suites.data = NULL;
    nss_ZFreeIf(comps.data);
    comps.data = NULL;

    ss->sec.send = ssl3_SendApplicationData;

#ifdef IMPLEMENT_SESSION_ID_CACHE
    /* If there are any failures while processing the old sid,
     * we don't consider them to be errors.  Instead, We just behave
     * as if the client had sent us no sid to begin with, and make a new one.
     */
    if (sid != NULL) do {
	PK11SlotInfo *  slot;
	PK11SymKey *    wrapKey; 	/* wrapping key */
	SECItem         wrappedKey;  	/* wrapped key */
	ssl3CipherSpec *pwSpec;
	CK_FLAGS        keyFlags      = 0;

	if (sid->version != ss->version  ||
	    sid->u.ssl3.cipherSuite != ssl3->hs.cipher_suite) {
	    break;	/* not an error */
	}

	if (ss->sec.ci.sid) {
	    ss->sec.uncache(ss->sec.ci.sid);
	    PR_ASSERT(ss->sec.ci.sid != sid);  /* should be impossible, but ... */
	    if (ss->sec.ci.sid != sid) {
		ssl_FreeSID(ss->sec.ci.sid);
	    }
	    ss->sec.ci.sid = NULL;
	}
	/* we need to resurrect the master secret.... */

	ssl_GetSpecWriteLock(ss);  haveSpecWriteLock = PR_TRUE;
	pwSpec = ssl3->pwSpec;

	wrapKey = getWrappingKey(ss, NULL, sid->u.ssl3.exchKeyType,
	                         sid->u.ssl3.masterWrapMech, ss->pkcs11PinArg);
	if (!wrapKey) {
	    /* we have a SID cache entry, but no wrapping key for it??? */
	    break;
	}

	if (ss->version > SSL_LIBRARY_VERSION_3_0) {	/* isTLS */
	    keyFlags = CKF_SIGN | CKF_VERIFY;
	}

        wrappedKey.data = sid->u.ssl3.keys.wrapped_master_secret;
	wrappedKey.size  = sid->u.ssl3.keys.wrapped_master_secret_len;

	/* unwrap the master secret. */
	pwSpec->master_secret =
	    PK11_UnwrapSymKeyWithFlags(wrapKey, sid->u.ssl3.masterWrapMech, 
	    		NULL, &wrappedKey, CKM_SSL3_MASTER_KEY_DERIVE,
			CKA_DERIVE, sizeof(SSL3MasterSecret), keyFlags);
	PK11_FreeSymKey(wrapKey);
	if (pwSpec->master_secret == NULL) {
	    break;	/* not an error */
	}
	ss->sec.ci.sid = sid;
	if (sid->peerCert != NULL) {
	    ss->sec.peerCert = CERT_DupCertificate(sid->peerCert);
	}

	/*
	 * Old SID passed all tests, so resume this old session.
	 *
	 * XXX make sure compression still matches
	 */
	++ssl3stats.hch_sid_cache_hits;
	ssl3->hs.isResuming = PR_TRUE;

        ss->sec.authAlgorithm = sid->authAlgorithm;
	ss->sec.authKeyBits   = sid->authKeyBits;
	ss->sec.keaType       = sid->keaType;
	ss->sec.keaKeyBits    = sid->keaKeyBits;

	/* server sids don't remember the server cert we previously sent,
	** but they do remember the kea type we originally used, so we
	** can locate it again, provided that the current ssl socket
	** has had its server certs configured the same as the previous one.
	*/
	ss->sec.localCert     = 
		CERT_DupCertificate(ss->serverCerts[sid->keaType].serverCert);

	ssl_GetXmitBufLock(ss); haveXmitBufLock = PR_TRUE;

	rv = ssl3_SendServerHello(ss);
	if (rv != SECSuccess) {
	    errCode = NSS_GetError();
	    goto loser;
	}

	/* reload the FORTEZZA key material.
	 * On Fortezza, the following keys & IVs are generated by the KEA,
	 * not from the PMS.  Since we're not going to redo the KEA, we
	 * have to save & restore them for Fortezza.
	 * use kea because we haven't call InitCipher Specs yet...?
	 */
	if (ssl3->hs.suite_def->bulk_cipher_alg == cipher_fortezza) {
	    PK11SymKey *      Ks;
	    SECItem           item;

	    memcpy(pwSpec->client.write_iv,
		sid->u.ssl3.keys.client_write_iv,
		sizeof sid->u.ssl3.keys.client_write_iv);
	    memcpy(pwSpec->server.write_iv,
		sid->u.ssl3.keys.server_write_iv,
		sizeof sid->u.ssl3.keys.server_write_iv);

	    /* Now, unwrap the client and server write keys with Ks */

	    /* get the slot that the fortezza server private key is in. */
	    slot = PK11_GetSlotFromPrivateKey(
	                                ss->serverCerts[ssl_kea_fortezza].serverKey);
	    if (slot == NULL) {
		ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
		goto loser;
	    }

	    /* Look up the Token Fixed Key */
	    Ks = PK11_FindFixedKey(slot, CKM_SKIPJACK_WRAP, NULL,
	                           ss->pkcs11PinArg);
	    PK11_FreeSlot(slot);
	    if (Ks == NULL) {
		ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
		goto loser;
	    }

	    /* unwrap client write key with the local Ks */
	    item.data = sid->u.ssl3.keys.wrapped_client_write_key;
	    item.size  = sizeof sid->u.ssl3.keys.wrapped_client_write_key;

	    pwSpec->client.write_key =
		    PK11_UnwrapSymKey(Ks, CKM_SKIPJACK_WRAP, NULL, &item,
				      CKM_SKIPJACK_CBC64, CKA_DECRYPT, 0);
	    if (pwSpec->client.write_key == NULL) {
		SEND_ALERT
		ssl_MapLowLevelError(SSL_ERROR_SYM_KEY_UNWRAP_FAILURE);
		goto loser;
	    }

	    /* unwrap server write key with the local Ks */
	    item.data = sid->u.ssl3.keys.wrapped_server_write_key;
	    item.size  = sizeof sid->u.ssl3.keys.wrapped_server_write_key;

	    pwSpec->server.write_key =
		    PK11_UnwrapSymKey(Ks, CKM_SKIPJACK_WRAP, NULL, &item,
				      CKM_SKIPJACK_CBC64, CKA_ENCRYPT, 0);
	    if (pwSpec->server.write_key == NULL) {
		PK11_FreeSymKey(pwSpec->client.write_key);
		pwSpec->client.write_key = NULL;
		SEND_ALERT
		ssl_MapLowLevelError(SSL_ERROR_SYM_KEY_UNWRAP_FAILURE);
		goto loser;
	    }
	    /* Set flag that says "generate 8 byte random prefix plaintext." */
	    PK11_SetFortezzaHack(pwSpec->server.write_key);	/* can't fail */

	}

	if (haveSpecWriteLock) {
	    ssl_ReleaseSpecWriteLock(ss);
	    haveSpecWriteLock = PR_FALSE;
	}

	/* NULL value for PMS signifies re-use of the old MS */
	rv = ssl3_InitPendingCipherSpec(ss,  NULL);
	if (rv != SECSuccess) {
	    errCode = NSS_GetError();
	    goto loser;
	}

	rv = ssl3_SendChangeCipherSpecs(ss);
	if (rv != SECSuccess) {
	    errCode = NSS_GetError();
	    goto loser;
	}
	rv = ssl3_SendFinished(ss, 0);
	ssl3->hs.ws = wait_change_cipher;
	if (rv != SECSuccess) {
	    errCode = NSS_GetError();
	    goto loser;
	}

	if (haveXmitBufLock) {
	    ssl_ReleaseXmitBufLock(ss);
	    haveXmitBufLock = PR_FALSE;
	}

        return SECSuccess;
    } while (0);
#endif /* IMPLEMENT_SESSION_ID_CACHE */

    if (haveSpecWriteLock) {
	ssl_ReleaseSpecWriteLock(ss);
	haveSpecWriteLock = PR_FALSE;
    }

#ifdef IMPLEMENT_SESSION_ID_CACHE
    if (sid) { 	/* we had a sid, but it's no longer valid, free it */
	++ssl3stats.hch_sid_cache_not_ok;
	ss->sec.uncache(sid);
	ssl_FreeSID(sid);
	sid = NULL;
    }
    ++ssl3stats.hch_sid_cache_misses;
#endif /* IMPLEMENT_SESSION_ID_CACHE */

    sid = ssl3_NewSessionID(ss, PR_TRUE);
    if (sid == NULL) {
	errCode = NSS_GetError();
	goto loser;	/* memory error is set. */
    }
    ss->sec.ci.sid = sid;

    ssl3->hs.isResuming = PR_FALSE;
    ssl_GetXmitBufLock(ss);
    rv = ssl3_SendServerHelloSequence(ss);
    ssl_ReleaseXmitBufLock(ss);
    if (rv != SECSuccess) {
	errCode = NSS_GetError();
	goto loser;
    }

    if (haveXmitBufLock) {
	ssl_ReleaseXmitBufLock(ss);
	haveXmitBufLock = PR_FALSE;
    }

    return SECSuccess;

alert_loser:
    if (haveSpecWriteLock) {
	ssl_ReleaseSpecWriteLock(ss);
	haveSpecWriteLock = PR_FALSE;
    }
    (void)SSL3_SendAlert(ss, alert_fatal, desc);
    /* FALLTHRU */
loser:
    if (haveSpecWriteLock) {
	ssl_ReleaseSpecWriteLock(ss);
	haveSpecWriteLock = PR_FALSE;
    }

    if (sidBytes.data != NULL) nss_ZFreeIf(sidBytes.data);
    if (suites.data   != NULL) nss_ZFreeIf(suites.data);
    if (comps.data    != NULL) nss_ZFreeIf(comps.data);

    if (haveXmitBufLock) {
	ssl_ReleaseXmitBufLock(ss);
	haveXmitBufLock = PR_FALSE;
    }

    nss_SetError(errCode);
    return SECFailure;
}

/*
 * ssl3_HandleV2ClientHello is used when a V2 formatted hello comes
 * in asking to use the V3 handshake.
 * Called from ssl2_HandleClientHelloMessage() in sslcon.c
 */
SECStatus
ssl3_HandleV2ClientHello(sslSocket *ss, unsigned char *buffer, int length)
{
    sslSessionID *      sid 		= NULL;
    unsigned char *     suites;
    unsigned char *     random;
    SSL3ProtocolVersion version;
    SECStatus           rv;
    int                 i;
    int                 j;
    int                 sid_length;
    int                 suite_length;
    int                 rand_length;
    int                 errCode  = SSL_ERROR_RX_MALFORMED_CLIENT_HELLO;
    SSL3AlertDescription desc    = handshake_failure;

    SSL_TRC(3, ("%d: SSL3[%d]: handle v2 client_hello", SSL_GETPID(), ss->fd));

    PR_ASSERT( ssl_HaveRecvBufLock(ss) );

    ssl_GetSSL3HandshakeLock(ss);

    rv = ssl3_InitState(ss);
    if (rv != SECSuccess) {
	ssl_ReleaseSSL3HandshakeLock(ss);
	return rv;		/* ssl3_InitState has set the error code. */
    }

    if (ss->ssl3->hs.ws != wait_client_hello) {
	desc    = unexpected_message;
	errCode = SSL_ERROR_RX_UNEXPECTED_CLIENT_HELLO;
	goto loser;	/* alert_loser */
    }

    version      = (buffer[1] << 8) | buffer[2];
    suite_length = (buffer[3] << 8) | buffer[4];
    sid_length   = (buffer[5] << 8) | buffer[6];
    rand_length  = (buffer[7] << 8) | buffer[8];
    ss->clientHelloVersion = version;

    rv = ssl3_NegotiateVersion(ss, version);
    if (rv != SECSuccess) {
	/* send back which ever alert client will understand. */
    	desc = (version > SSL_LIBRARY_VERSION_3_0) ? protocol_version : handshake_failure;
	errCode = SSL_ERROR_NO_CYPHER_OVERLAP;
	goto alert_loser;
    }

    /* if we get a non-zero SID, just ignore it. */
    if (length !=
        SSL_HL_CLIENT_HELLO_HBYTES + suite_length + sid_length + rand_length) {
	SSL_DBG(("%d: SSL3[%d]: bad v2 client hello message, len=%d should=%d",
		 SSL_GETPID(), ss->fd, length,
		 SSL_HL_CLIENT_HELLO_HBYTES + suite_length + sid_length +
		 rand_length));
	goto loser;	/* malformed */	/* alert_loser */
    }

    suites = buffer + SSL_HL_CLIENT_HELLO_HBYTES;
    random = suites + suite_length + sid_length;

    if (rand_length < SSL_MIN_CHALLENGE_BYTES ||
	rand_length > SSL_MAX_CHALLENGE_BYTES) {
	goto loser;	/* malformed */	/* alert_loser */
    }

    PR_ASSERT(SSL_MAX_CHALLENGE_BYTES == SSL3_RANDOM_LENGTH);

    memset(&ss->ssl3->hs.client_random, 0, SSL3_RANDOM_LENGTH);
    memcpy(&ss->ssl3->hs.client_random.rand[SSL3_RANDOM_LENGTH - rand_length],
           random, rand_length);

    PRINT_BUF(60, (ss, "client random:", &ss->ssl3->hs.client_random.rand[0],
		   SSL3_RANDOM_LENGTH));

    i = ssl3_config_match_init(ss);
    if (i <= 0) {
    	errCode = NSS_GetError();	/* error code is already set. */
	goto alert_loser;
    }

    /* Select a cipher suite.
    ** NOTE: This suite selection algorithm should be the same as the one in
    ** ssl3_HandleClientHello().  
    */
    for (j = 0; j < ssl_V3_SUITES_IMPLEMENTED; j++) {
	ssl3CipherSuiteCfg *suite = &ss->cipherSuites[j];
	if (!config_match(suite, ss->ssl3->policy, PR_TRUE))
	    continue;
	for (i = 0; i < suite_length; i += 3) {
	    if ((suites[i]   == 0) &&
		(suites[i+1] == MSB(suite->cipher_suite)) &&
		(suites[i+2] == LSB(suite->cipher_suite))) {

		ss->ssl3->hs.cipher_suite = suite->cipher_suite;
		ss->ssl3->hs.suite_def =
		    ssl_LookupCipherSuiteDef(ss->ssl3->hs.cipher_suite);
		goto suite_found;
	    }
	}
    }
    errCode = SSL_ERROR_NO_CYPHER_OVERLAP;
    goto alert_loser;

suite_found:

    ss->ssl3->hs.compression = compression_null;
    ss->sec.send            = ssl3_SendApplicationData;

    /* we don't even search for a cache hit here.  It's just a miss. */
    ++ssl3stats.hch_sid_cache_misses;
    sid = ssl3_NewSessionID(ss, PR_TRUE);
    if (sid == NULL) {
    	errCode = NSS_GetError();
	goto loser;	/* memory error is set. */
    }
    ss->sec.ci.sid = sid;
    /* do not worry about memory leak of sid since it now belongs to ci */

    /* We have to update the handshake hashes before we can send stuff */
    rv = ssl3_UpdateHandshakeHashes(ss, buffer, length);
    if (rv != SECSuccess) {
    	errCode = NSS_GetError();
	goto loser;
    }

    ssl_GetXmitBufLock(ss);
    rv = ssl3_SendServerHelloSequence(ss);
    ssl_ReleaseXmitBufLock(ss);
    if (rv != SECSuccess) {
    	errCode = NSS_GetError();
	goto loser;
    }

    /* XXX_1 	The call stack to here is:
     * ssl_Do1stHandshake -> ssl2_HandleClientHelloMessage -> here.
     * ssl2_HandleClientHelloMessage returns whatever we return here.
     * ssl_Do1stHandshake will continue looping if it gets back either
     *		SECSuccess or SECWouldBlock.
     * SECSuccess is preferable here.  See XXX_1 in sslgathr.c.
     */
    ssl_ReleaseSSL3HandshakeLock(ss);
    return SECSuccess;

alert_loser:
    SSL3_SendAlert(ss, alert_fatal, desc);
loser:
    ssl_ReleaseSSL3HandshakeLock(ss);
    nss_SetError(errCode);
    return SECFailure;
}

/* The negotiated version number has been already placed in ss->version.
**
** Called from:  ssl3_HandleClientHello                     (resuming session),
** 	ssl3_SendServerHelloSequence <- ssl3_HandleClientHello   (new session),
** 	ssl3_SendServerHelloSequence <- ssl3_HandleV2ClientHello (new session)
*/
static SECStatus
ssl3_SendServerHello(sslSocket *ss)
{
    sslSessionID *sid;
    SECStatus     rv;
    PRUint32      length;

    SSL_TRC(3, ("%d: SSL3[%d]: send server_hello handshake", SSL_GETPID(),
		ss->fd));

    PR_ASSERT( ssl_HaveXmitBufLock(ss));
    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss));
    PR_ASSERT( MSB(ss->version) == MSB(SSL_LIBRARY_VERSION_3_0));

    if (MSB(ss->version) != MSB(SSL_LIBRARY_VERSION_3_0)) {
	nss_SetError(SSL_ERROR_NO_CYPHER_OVERLAP);
	return SECFailure;
    }

    sid = ss->sec.ci.sid;
    length = sizeof(SSL3ProtocolVersion) + SSL3_RANDOM_LENGTH + 1 +
             ((sid == NULL) ? 0: SSL3_SESSIONID_BYTES) +
	     sizeof(ssl3CipherSuite) + 1;
    rv = ssl3_AppendHandshakeHeader(ss, server_hello, length);
    if (rv != SECSuccess) {
	return rv;	/* err set by AppendHandshake. */
    }

    rv = ssl3_AppendHandshakeNumber(ss, ss->version, 2);
    if (rv != SECSuccess) {
	return rv;	/* err set by AppendHandshake. */
    }
    rv = ssl3_GetNewRandom(&ss->ssl3->hs.server_random);
    if (rv != SECSuccess) {
	ssl_MapLowLevelError(SSL_ERROR_GENERATE_RANDOM_FAILURE);
	return rv;
    }
    rv = ssl3_AppendHandshake(
	ss, &ss->ssl3->hs.server_random, SSL3_RANDOM_LENGTH);
    if (rv != SECSuccess) {
	return rv;	/* err set by AppendHandshake. */
    }

    if (sid)
	rv = ssl3_AppendHandshakeVariable(
	    ss, sid->u.ssl3.sessionID, sid->u.ssl3.sessionIDLength, 1);
    else
	rv = ssl3_AppendHandshakeVariable(ss, NULL, 0, 1);
    if (rv != SECSuccess) {
	return rv;	/* err set by AppendHandshake. */
    }

    rv = ssl3_AppendHandshakeNumber(ss, ss->ssl3->hs.cipher_suite, 2);
    if (rv != SECSuccess) {
	return rv;	/* err set by AppendHandshake. */
    }
    rv = ssl3_AppendHandshakeNumber(ss, ss->ssl3->hs.compression, 1);
    if (rv != SECSuccess) {
	return rv;	/* err set by AppendHandshake. */
    }
    rv = ssl3_SetupPendingCipherSpec(ss, ss->ssl3);
    if (rv != SECSuccess) {
	return rv;	/* err set by ssl3_SetupPendingCipherSpec */
    }

    return SECSuccess;
}


static SECStatus
ssl3_SendServerKeyExchange(sslSocket *ss)
{
const ssl3KEADef *     kea_def     = ss->ssl3->hs.kea_def;
    SECStatus          rv          = SECFailure;
    int                length;
    PRBool             isTLS;
    NSSItem            signed_hash = {NULL, 0};
    SSL3Hashes         hashes;
    NSSPublicKey *     sdPub;	/* public key for step-down */
    NSSPublicKeyInfo   sdPubInfo;

    SSL_TRC(3, ("%d: SSL3[%d]: send server_key_exchange handshake",
		SSL_GETPID(), ss->fd));

    PR_ASSERT( ssl_HaveXmitBufLock(ss));
    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss));

    if (NSSPublicKey_GetKeyInfo(sdPub, &sdPubInfo) == NULL) {
	return SECFailure;
    }

    switch (kea_def->exchKeyType) {
    case ssl_kea_rsa:
	/* Perform SSL Step-Down here. */
	sdPub = ss->stepDownKeyPair->pubKey;
	PR_ASSERT(sdPub != NULL);
	if (!sdPub) {
	    nss_SetError(SSL_ERROR_SERVER_KEY_EXCHANGE_FAILURE);
	    return SECFailure;
	}
    	rv = ssl3_ComputeExportRSAKeyHash(sdPubInfo.u.rsa.modulus,
					  sdPubInfo.u.rsa.publicExponent,
	                                  &ss->ssl3->hs.client_random,
	                                  &ss->ssl3->hs.server_random,
	                                  &hashes, ss->td);
        if (rv != SECSuccess) {
	    ssl_MapLowLevelError(SSL_ERROR_SERVER_KEY_EXCHANGE_FAILURE);
	    return rv;
	}

	isTLS = (PRBool)(ss->ssl3->pwSpec->version > SSL_LIBRARY_VERSION_3_0);
	rv = ssl3_SignHashes(&hashes, ss->serverCerts[ssl_kea_rsa].serverKey, 
	                     &signed_hash, isTLS);
        if (rv != SECSuccess) {
	    goto loser;		/* ssl3_SignHashes has set err. */
	}
	if (signed_hash.data == NULL) {
	    /* how can this happen and rv == SECSuccess ?? */
	    nss_SetError(SSL_ERROR_SERVER_KEY_EXCHANGE_FAILURE);
	    goto loser;
	}
	length = 2 + sdPubInfo.u.rsa.modulus.size +
	         2 + sdPubInfo.u.rsa.publicExponent.size +
	         2 + signed_hash.size;

	rv = ssl3_AppendHandshakeHeader(ss, server_key_exchange, length);
	if (rv != SECSuccess) {
	    goto loser; 	/* err set by AppendHandshake. */
	}

	rv = ssl3_AppendHandshakeVariable(ss, sdPubInfo.u.rsa.modulus.data,
					  sdPubInfo.u.rsa.modulus.size, 2);
	if (rv != SECSuccess) {
	    goto loser; 	/* err set by AppendHandshake. */
	}

	rv = ssl3_AppendHandshakeVariable(
				ss, sdPubInfo.u.rsa.publicExponent.data,
				sdPubInfo.u.rsa.publicExponent.size, 2);
	if (rv != SECSuccess) {
	    goto loser; 	/* err set by AppendHandshake. */
	}

	rv = ssl3_AppendHandshakeVariable(ss, signed_hash.data,
	                                  signed_hash.size, 2);
	if (rv != SECSuccess) {
	    goto loser; 	/* err set by AppendHandshake. */
	}
	nss_ZFreeIf(signed_hash.data);
	return SECSuccess;

#ifdef FORTEZZA
    case ssl_kea_fortezza:

	/* Set server's "random" public key R_s to the email value == 1 */
	memset(ss->ssl3->fortezza.R_s, 0, sizeof(ss->ssl3->fortezza.R_s));
	ss->ssl3->fortezza.R_s[127] = 1;

	/* don't waste time signing the random number */
	length = sizeof (ss->ssl3->fortezza.R_s) /*+ 2 + signed_hash.size*/;

	rv = ssl3_AppendHandshakeHeader(ss, server_key_exchange, length);
	if (rv != SECSuccess) {
	    goto loser; 	/* err set by AppendHandshake. */
	}

	rv = ssl3_AppendHandshake( ss, &ss->ssl3->fortezza.R_s,
					sizeof(ss->ssl3->fortezza.R_s));
	if (rv != SECSuccess) {
	    goto loser; 	/* err set by AppendHandshake. */
	}
	return SECSuccess;
#endif /* FORTEZZA */

    case ssl_kea_dh:
    case ssl_kea_null:
    default:
	nss_SetError(SSL_ERROR_UNSUPPORTED_KEY_EXCHANGE_ALG);
	break;
    }
loser:
    if (signed_hash.data != NULL) 
    	nss_ZFreeIf(signed_hash.data);
    return SECFailure;
}


static SECStatus
ssl3_SendCertificateRequest(sslSocket *ss)
{
    NSSDER **      it;
    NSSDER **      ca_list;
const uint8 *      certTypes;
    SECStatus      rv;
    int            length;
    int            calen	= 0;
    int            certTypesLength;

    SSL_TRC(3, ("%d: SSL3[%d]: send certificate_request handshake",
		SSL_GETPID(), ss->fd));

    PR_ASSERT( ssl_HaveXmitBufLock(ss));
    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss));

    /* ssl3->ca_list is initialized to NULL, and never changed. */
    ca_list = ss->ssl3->ca_list;
    if (!ca_list) {
	ca_list = ssl3_server_ca_list;
    }

    if (!ca_list) {
	nss_SetError(SSL_ERROR_NO_TRUSTED_SSL_CLIENT_CA);
	return SECFailure;
    }

    for (it = ca_list; *it != NULL; it++) {
	calen += 2 + (*it)->size;
    }

    if (ss->ssl3->hs.kea_def->exchKeyType == ssl_kea_fortezza) {
	certTypes       = fortezza_certificate_types;
	certTypesLength = sizeof fortezza_certificate_types;
    } else {
	certTypes       = certificate_types;
	certTypesLength = sizeof certificate_types;
    }

    length = 1 + certTypesLength + 2 + calen;

    rv = ssl3_AppendHandshakeHeader(ss, certificate_request, length);
    if (rv != SECSuccess) {
	return rv; 		/* err set by AppendHandshake. */
    }
    rv = ssl3_AppendHandshakeVariable(ss, certTypes, certTypesLength, 1);
    if (rv != SECSuccess) {
	return rv; 		/* err set by AppendHandshake. */
    }
    rv = ssl3_AppendHandshakeNumber(ss, calen, 2);
    if (rv != SECSuccess) {
	return rv; 		/* err set by AppendHandshake. */
    }
    for (it = ca_list; *it != NULL; it++) {
	rv = ssl3_AppendHandshakeVariable(ss, (*it)->data, (*it)->size, 2);
	if (rv != SECSuccess) {
	    return rv; 		/* err set by AppendHandshake. */
	}
    }

    return SECSuccess;
}

static SECStatus
ssl3_SendServerHelloDone(sslSocket *ss)
{
    SECStatus rv;

    SSL_TRC(3, ("%d: SSL3[%d]: send server_hello_done handshake",
		SSL_GETPID(), ss->fd));

    PR_ASSERT( ssl_HaveXmitBufLock(ss));
    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss));

    rv = ssl3_AppendHandshakeHeader(ss, server_hello_done, 0);
    if (rv != SECSuccess) {
	return rv; 		/* err set by AppendHandshake. */
    }
    rv = ssl3_FlushHandshake(ss, 0);
    if (rv != SECSuccess) {
	return rv;	/* error code set by ssl3_FlushHandshake */
    }
    return SECSuccess;
}

/* Called from ssl3_HandleHandshakeMessage() when it has deciphered a complete
 * ssl3 Certificate Verify message
 * Caller must hold Handshake and RecvBuf locks.
 */
static SECStatus
ssl3_HandleCertificateVerify(sslSocket *ss, SSL3Opaque *b, PRUint32 length,
			     SSL3Hashes *hashes)
{
    NSSItem              signed_hash = {NULL, 0};
    SECStatus            rv;
    int                  errCode     = SSL_ERROR_RX_MALFORMED_CERT_VERIFY;
    SSL3AlertDescription desc        = handshake_failure;
    PRBool               isTLS;

    SSL_TRC(3, ("%d: SSL3[%d]: handle certificate_verify handshake",
		SSL_GETPID(), ss->fd));
    PR_ASSERT( ssl_HaveRecvBufLock(ss) );
    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss) );

    if (ss->ssl3->hs.ws != wait_cert_verify || ss->sec.peerCert == NULL) {
	desc    = unexpected_message;
	errCode = SSL_ERROR_RX_UNEXPECTED_CERT_VERIFY;
	goto alert_loser;
    }

    rv = ssl3_ConsumeHandshakeVariable(ss, &signed_hash, 2, &b, &length, NULL);
    if (rv != SECSuccess) {
	goto loser;		/* malformed. */
    }

    isTLS = (PRBool)(ss->ssl3->prSpec->version > SSL_LIBRARY_VERSION_3_0);

    /* XXX verify that the key & kea match */
    rv = ssl3_VerifySignedHashes(hashes, ss->sec.peerCert, &signed_hash,
				 isTLS, ss->pkcs11PinArg);
    if (rv != SECSuccess) {
    	errCode = NSS_GetError();
	desc = isTLS ? decrypt_error : handshake_failure;
	goto alert_loser;
    }

    nss_ZFreeIf(signed_hash.data);
    signed_hash.data = NULL;

    if (length != 0) {
	desc    = isTLS ? decode_error : illegal_parameter;
	goto alert_loser;	/* malformed */
    }
    ss->ssl3->hs.ws = wait_change_cipher;
    return SECSuccess;

alert_loser:
    SSL3_SendAlert(ss, alert_fatal, desc);
loser:
    if (signed_hash.data != NULL) 
	nss_ZFreeIf(signed_hash.data);
    nss_SetError(errCode);
    return SECFailure;
}

#ifdef FORTEZZA
/*
** Called from ssl3_HandleClientKeyExchange()
*/
static SECStatus
ssl3_HandleFortezzaClientKeyExchange(sslSocket *ss, SSL3Opaque *b,
				     PRUint32 length,
                                     SECKEYPrivateKey *serverKey)
{
    SECKEYPublicKey * pubKey            = NULL;
    PK11SymKey *      tek               = NULL;
    PK11SymKey *      pms;
    PK11SymKey *      Ks		= NULL;
    sslSessionID *    sid 		= ss->sec.ci.sid;
    ssl3CipherSpec *  pwSpec 		= ss->ssl3->pwSpec;
    void *            pwArg             = ss->pkcs11PinArg;
    SECStatus         rv;
    SECItem           raItem;
    SECItem           rbItem;
    SECItem           param;
    SECItem           item;
    SECItem           enc_pms;
    SSL3FortezzaKeys  fortezza_CKE;

    PR_ASSERT( ssl_HaveRecvBufLock(ss) );
    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss) );

    fortezza_CKE.y_c.data = NULL;
    rv = ssl3_ConsumeHandshakeVariable(ss, &fortezza_CKE.y_c, 1, &b, &length);
    if (rv != SECSuccess) {
	nss_SetError(SSL_ERROR_RX_MALFORMED_CLIENT_KEY_EXCH);
	goto fortezza_loser;
    }
    rv = ssl3_ConsumeHandshake(ss, &fortezza_CKE.r_c,
	                       sizeof fortezza_CKE - sizeof fortezza_CKE.y_c,
	                       &b, &length);
    if (rv != SECSuccess) {
	nss_SetError(SSL_ERROR_RX_MALFORMED_CLIENT_KEY_EXCH);
	goto fortezza_loser;
    }

    /* Build a Token Encryption key (tek). TEK's can never be unloaded
     * from the card, but given these parameters, and *OUR* fortezza
     * card, we can always regenerate the same one on the fly.
     */
    if (ss->sec.peerCert != NULL) {
	/* client-auth case */

	pubKey = CERT_ExtractPublicKey(ss->sec.peerCert);
	if (pubKey == NULL) {
	    SEND_ALERT
	    nss_SetError(SSL_ERROR_EXTRACT_PUBLIC_KEY_FAILURE);
	    rv = SECFailure;
	    goto fortezza_loser;
	}

	if (pubKey->keyType != fortezzaKey) {
	    /* handle V3 client-auth case */
	    SECItem       sigItem;
	    SECItem       hashItem;
	    unsigned char hash[SHA1_LENGTH];

	    rv = ssl3_ComputeFortezzaPublicKeyHash(fortezza_CKE.y_c, hash);
	    if (rv != SECSuccess) {
		SEND_ALERT
		ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
		goto fortezza_loser;
	    }
	    sigItem.data  = fortezza_CKE.y_signature;
	    sigItem.size   = sizeof fortezza_CKE.y_signature;

	    hashItem.data = hash;
	    hashItem.size  = sizeof hash;

	    rv = PK11_Verify(pubKey, &sigItem, &hashItem, pwArg);
	    if (rv != SECSuccess) {
		SSL3_SendAlert(ss, alert_fatal, illegal_parameter);
		ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
		goto fortezza_loser;
	    }
	    SECKEY_DestroyPublicKey(pubKey); pubKey = NULL;
	}
    }
    rv = SECFailure;

    /* Make the public key if necessary */
    if (fortezza_CKE.y_c.size != 0) {
	if (pubKey != NULL) {
	    /* The client is not allowed to send the public key
	     * if it can be extracted from the certificate. */
	    SSL3_SendAlert(ss, alert_fatal, illegal_parameter);
	    nss_SetError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	    goto fortezza_loser;
	}
	pubKey = PK11_MakeKEAPubKey(fortezza_CKE.y_c.data,
				    fortezza_CKE.y_c.size);
    }
    if (pubKey == NULL) {
	/* no public Key in either the cert or the protocol message*/
	SSL3_SendAlert(ss, alert_fatal, illegal_parameter);
	nss_SetError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	goto fortezza_loser;
    }

    /* Now we derive the TEK.  r_c is the client's "random" public key. */
    raItem.data = fortezza_CKE.r_c;
    raItem.size  = sizeof(fortezza_CKE.r_c);

    /* R_s == server's "random" public key, sent in the Server Key Exchange */
    rbItem.data = ss->ssl3->fortezza.R_s;
    rbItem.size  = sizeof ss->ssl3->fortezza.R_s;

    tek = PK11_PubDerive(serverKey, pubKey, PR_FALSE, /* don't gen r_c */
                         &raItem, &rbItem, CKM_KEA_KEY_DERIVE,
			 CKM_SKIPJACK_WRAP, CKA_WRAP, 0, pwArg);
    SECKEY_DestroyPublicKey(pubKey); pubKey = NULL;
    if (tek == NULL) {
	SEND_ALERT
	ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	goto fortezza_loser;
    }

    ss->ssl3->fortezza.tek = PK11_ReferenceSymKey(tek);

    if (pwSpec->cipher_def->calg == calg_fortezza) {
	item.data = fortezza_CKE.wrapped_client_write_key;
	item.size  = sizeof fortezza_CKE.wrapped_client_write_key;

	pwSpec->client.write_key =
		PK11_UnwrapSymKey(tek, CKM_SKIPJACK_WRAP, NULL, &item,
		                  CKM_SKIPJACK_CBC64, CKA_DECRYPT, 0);
	if (pwSpec->client.write_key == NULL) {
	    SEND_ALERT
	    ssl_MapLowLevelError(SSL_ERROR_SYM_KEY_UNWRAP_FAILURE);
	    goto fortezza_loser;
	}

	item.data = fortezza_CKE.wrapped_server_write_key;
	item.size  = sizeof fortezza_CKE.wrapped_server_write_key;

	pwSpec->server.write_key =
		PK11_UnwrapSymKey(tek, CKM_SKIPJACK_WRAP, NULL, &item,
		                  CKM_SKIPJACK_CBC64, CKA_ENCRYPT, 0);
	if (pwSpec->server.write_key == NULL) {
	    PK11_FreeSymKey(pwSpec->client.write_key);
	    pwSpec->client.write_key = NULL;
	    SEND_ALERT
	    ssl_MapLowLevelError(SSL_ERROR_SYM_KEY_UNWRAP_FAILURE);
	    goto fortezza_loser;
	}
	/* Set a flag that says "generate 8 byte random prefix plaintext." */
	PK11_SetFortezzaHack(pwSpec->server.write_key);	/* can't fail */

	memcpy(pwSpec->client.write_iv, fortezza_CKE.client_write_iv,
		    sizeof fortezza_CKE.client_write_iv);
	memcpy(pwSpec->server.write_iv, fortezza_CKE.server_write_iv,
		    sizeof fortezza_CKE.server_write_iv);

    }

    /* decrypt the pms with the TEK */
    enc_pms.data = fortezza_CKE.encrypted_preMasterSecret;
    enc_pms.size  = sizeof fortezza_CKE.encrypted_preMasterSecret;

    param.data = fortezza_CKE.master_secret_iv;
    param.size  = sizeof fortezza_CKE.master_secret_iv;

    pms = PK11_UnwrapSymKey(tek, CKM_SKIPJACK_CBC64, &param, &enc_pms,
			    CKM_SSL3_MASTER_KEY_DERIVE, CKA_DERIVE, 0);
    if (pms == NULL) {
	SEND_ALERT
	ssl_MapLowLevelError(SSL_ERROR_SYM_KEY_UNWRAP_FAILURE);
	goto fortezza_loser;
    }

    rv = ssl3_InitPendingCipherSpec(ss,  pms);
    PK11_FreeSymKey(pms);
    if (rv != SECSuccess) {
	SEND_ALERT
	goto fortezza_loser; 	/* err code is set. */
    }

    if (pwSpec->cipher_def->calg == calg_fortezza) {
	PK11SlotInfo *    slot;

	sid->u.ssl3.clientWriteKey =
			    PK11_ReferenceSymKey(pwSpec->client.write_key);
	sid->u.ssl3.serverWriteKey =
			    PK11_ReferenceSymKey(pwSpec->server.write_key);

	memcpy(sid->u.ssl3.keys.client_write_iv, pwSpec->client.write_iv,
		    sizeof sid->u.ssl3.keys.client_write_iv);
	memcpy(sid->u.ssl3.keys.server_write_iv, pwSpec->server.write_iv,
		    sizeof sid->u.ssl3.keys.server_write_iv);

	/* Now, wrap the client and server write keys in Ks for storage
	 * in the on-disk sid.
	 */

	slot = PK11_GetSlotFromKey(tek); 	/* get ref to the slot */
	if (slot == NULL) {
	    ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	    goto fortezza_loser;
	}

	/* Look up the Token Fixed Key */
	Ks = PK11_FindFixedKey(slot, CKM_SKIPJACK_WRAP, NULL, ss->pkcs11PinArg);
	PK11_FreeSlot(slot);
	if (Ks == NULL) {
	    ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	    goto fortezza_loser;
	}

	/* rewrap server write key with the local Ks */
	item.data = sid->u.ssl3.keys.wrapped_server_write_key;
	item.size  = sizeof sid->u.ssl3.keys.wrapped_server_write_key;
	rv = PK11_WrapSymKey(CKM_SKIPJACK_WRAP, NULL, Ks,
	                     pwSpec->server.write_key, &item);
	if (rv != SECSuccess) {
	    ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	    goto fortezza_loser;
	}

	/* rewrap client write key with the local Ks */
	item.data = sid->u.ssl3.keys.wrapped_client_write_key;
	item.size  = sizeof sid->u.ssl3.keys.wrapped_client_write_key;
	rv = PK11_WrapSymKey(CKM_SKIPJACK_WRAP, NULL, Ks,
	                     pwSpec->client.write_key, &item);
	if (rv != SECSuccess) {
	    ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	    goto fortezza_loser;
	}

	/* wrap the master secret later, when we handle the client's
	 * finished message.
	 */
    }

    sid->u.ssl3.hasFortezza = PR_TRUE;
    sid->u.ssl3.tek = tek; tek = NULL;

    rv = SECSuccess;

fortezza_loser:
    if (Ks)  PK11_FreeSymKey(Ks);
    if (tek) PK11_FreeSymKey(tek);
    if (pubKey) SECKEY_DestroyPublicKey(pubKey);
    if (fortezza_CKE.y_c.data != NULL)
    	SECITEM_FreeItem(&fortezza_CKE.y_c, PR_FALSE);
    return rv;
}
#endif /* FORTEZZA */

/* find a slot that is able to generate a PMS and wrap it with RSA.
 * Then generate and return the PMS.
 * If the serverKeySlot parameter is non-null, this function will use
 * that slot to do the job, otherwise it will find a slot.
 *
 * Called from  ssl3_GenerateSessionKeys()         (above)
 *		sendRSAClientKeyExchange()         (above)
 *		ssl3_HandleRSAClientKeyExchange()  (below)
 * Caller must hold the SpecWriteLock, the SSL3HandshakeLock
 */
static NSSSymKey *
ssl3_GenerateRSAPMS(sslSocket *ss, ssl3CipherSpec *spec,
                    NSSToken *serverKeyToken)
{
    NSSSymKey * pms   = NULL;
    NSSToken *        token = serverKeyToken;
    const NSSAlgNParam *pmsAP;

    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss) );

    switch (ssl_GetVersion(ss)) {
    case NSSSSLVersion_SSLv3: pmsAP = s_ssl3_pms_ap; break;
    case NSSSSLVersion_TLS:   pmsAP = s_tls_pms_ap;  break;
    default:
	/* XXX is this correct? */
	nss_SetError(SSL_ERROR_INVALID_VERSION);
	return (NSSSymKey *)NULL;
    }

    if (!token) {
	/* The specReadLock would suffice here, but we cannot assert on
	** read locks.  Also, all the callers who call with a non-null
	** slot already hold the SpecWriteLock.
	*/
	PR_ASSERT( ssl_HaveSpecWriteLock(ss));
	PR_ASSERT(ss->ssl3->prSpec == ss->ssl3->pwSpec);

	token = NSSTrustDomain_FindTokenForAlgNParam(ss->td, pmsAP);
	if (!token) {
	    nss_SetError(SSL_ERROR_TOKEN_SLOT_NOT_FOUND);
	    return (NSSSymKey *)NULL;
	}
    }

    pms = NSSVolatileDomain_GenerateSymKey(ss->vd, pmsAP,
                                           0, NULL, 0, 0, token, NULL);
    if (!pms) {
	ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	return (NSSSymKey *)NULL;
    }

    if (!serverKeyToken) {
	NSSToken_Destroy(token);
    }
    return pms;
}

/* Note: The Bleichenbacher attack on PKCS#1 necessitates that we NEVER
 * return any indication of failure of the Client Key Exchange message,
 * where that failure is caused by the content of the client's message.
 * This function must not return SECFailure for any reason that is directly
 * or indirectly caused by the content of the client's encrypted PMS.
 * We must not send an alert and also not drop the connection.
 * Instead, we generate a random PMS.  This will cause a failure
 * in the processing the finished message, which is exactly where
 * the failure must occur.
 *
 * Called from ssl3_HandleClientKeyExchange
 */
static SECStatus
ssl3_HandleRSAClientKeyExchange(sslSocket *ss,
                                SSL3Opaque *b,
				PRUint32 length,
				NSSPrivateKey *serverKey)
{
    NSSSymKey  *pms;
    SECStatus         rv;
    NSSItem           enc_pms;
    PRStatus    status;

    PR_ASSERT( ssl_HaveRecvBufLock(ss) );
    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss) );

    if (ss->ssl3->prSpec->version > SSL_LIBRARY_VERSION_3_0) { /* isTLS */
	PRInt32 kLen;
	kLen = ssl3_ConsumeHandshakeNumber(ss, 2, &b, &length);
	if (kLen < 0) {
	    nss_SetError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	    return SECFailure;
	}
	if ((unsigned)kLen < length) {
	    length = kLen;
	}
    }
    NSSITEM_INIT(&enc_pms, b, length);
    /*
     * decrypt pms out of the incoming buffer into volatile domain
     */
    pms = NSSPrivateKey_UnwrapSymKey(serverKey, s_rsa_wrap_ap, 
                                     &enc_pms, NSSSymKeyType_SSLPMS,
                                     NULL, 0, 0, NULL, ss->vd, NULL);
    if (pms) {
	    /* XXX
	PRINT_BUF(60, (ss, "decrypted premaster secret:",
		       PK11_GetKeyData(pms)->data,
		       PK11_GetKeyData(pms)->size));
		       */
    } else {
	/* unwrap failed.  Generate a bogus pre-master secret and carry on. */
	NSSToken *token;
	(void)NSSPrivateKey_GetTokens(serverKey, &token, 1, &status);
	if (status == PR_SUCCESS) {
	    ssl_GetSpecWriteLock(ss);
	    pms = ssl3_GenerateRSAPMS(ss, ss->ssl3->prSpec, token);
	    ssl_ReleaseSpecWriteLock(ss);
	    NSSToken_Destroy(token);
	}
    }

    if (!pms) {
	/* last gasp.  */
	ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
	return SECFailure;
    }

    rv = ssl3_InitPendingCipherSpec(ss, pms);
    NSSSymKey_Destroy(pms);
    if (rv != SECSuccess) {
	SEND_ALERT
	return SECFailure;	/* error code set by ssl3_InitPendingCipherSpec */
    }
    return SECSuccess;
}

/* Called from ssl3_HandleHandshakeMessage() when it has deciphered a complete
 * ssl3 ClientKeyExchange message from the remote client
 * Caller must hold Handshake and RecvBuf locks.
 */
static SECStatus
ssl3_HandleClientKeyExchange(sslSocket *ss, SSL3Opaque *b, PRUint32 length)
{
    NSSPrivateKey * serverKey         = NULL;
    SECStatus       rv;
const ssl3KEADef *  kea_def;

    SSL_TRC(3, ("%d: SSL3[%d]: handle client_key_exchange handshake",
		SSL_GETPID(), ss->fd));

    PR_ASSERT( ssl_HaveRecvBufLock(ss) );
    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss) );

    if (ss->ssl3->hs.ws != wait_client_key) {
	SSL3_SendAlert(ss, alert_fatal, unexpected_message);
    	nss_SetError(SSL_ERROR_RX_UNEXPECTED_CLIENT_KEY_EXCH);
	return SECFailure;
    }

    kea_def   = ss->ssl3->hs.kea_def;

    serverKey =  (ss->ssl3->hs.usedStepDownKey
#ifdef DEBUG
		 && kea_def->is_limited /* XXX OR cert is signing only */
		 && kea_def->exchKeyType == ssl_kea_rsa 
		 && ss->stepDownKeyPair != NULL
#endif
		 ) ? ss->stepDownKeyPair->privKey
		   : ss->serverCerts[kea_def->exchKeyType].serverKey;

    if (ss->ssl3->hs.usedStepDownKey
#ifdef DEBUG
	 && kea_def->is_limited /* XXX OR cert is signing only */
	 && kea_def->exchKeyType == ssl_kea_rsa 
	 && ss->stepDownKeyPair != NULL
#endif
	 ) { 
    	serverKey = ss->stepDownKeyPair->privKey;
	ss->sec.keaKeyBits = EXPORT_RSA_KEY_LENGTH * BPB;
    } else {
	sslServerCerts * sc = ss->serverCerts + kea_def->exchKeyType;
	serverKey           = sc->serverKey;
	ss->sec.keaKeyBits = sc->serverKeyBits;
    }

    if (serverKey == NULL) {
    	SEND_ALERT
	nss_SetError(SSL_ERROR_NO_SERVER_KEY_FOR_ALG);
	return SECFailure;
    }

    ss->sec.keaType    = kea_def->exchKeyType;

    switch (kea_def->exchKeyType) {
    case ssl_kea_rsa:
	rv = ssl3_HandleRSAClientKeyExchange(ss, b, length, serverKey);
	if (rv != SECSuccess) {
	    SEND_ALERT
	    return SECFailure;	/* error code set by ssl3_InitPendingCipherSpec */
	}
	break;

#ifdef FORTEZZA
    case ssl_kea_fortezza:
	rv = ssl3_HandleFortezzaClientKeyExchange(ss, b, length, serverKey);
	if (rv != SECSuccess) {
	    return SECFailure;	/* error code set */
	}
	break;
#endif /* FORTEZZA */

    default:
	(void) ssl3_HandshakeFailure(ss);
	nss_SetError(SSL_ERROR_UNSUPPORTED_KEY_EXCHANGE_ALG);
	return SECFailure;
    }
    ss->ssl3->hs.ws = ss->sec.peerCert ? wait_cert_verify : wait_change_cipher;
    return SECSuccess;

}

/* This is TLS's equivalent of sending a no_certificate alert. */
static SECStatus
ssl3_SendEmptyCertificate(sslSocket *ss)
{
    SECStatus            rv;

    rv = ssl3_AppendHandshakeHeader(ss, certificate, 3);
    if (rv == SECSuccess) {
	rv = ssl3_AppendHandshakeNumber(ss, 0, 3);
    }
    return rv;	/* error, if any, set by functions called above. */
}

/*
 * Used by both client and server.
 * Called from HandleServerHelloDone and from SendServerHelloSequence.
 */
static SECStatus
ssl3_SendCertificate(sslSocket *ss)
{
    SECStatus            rv;
    NSSCert *            cert;
    NSSCertChain *       certChain;
    PRIntn               numCerts       = 0;
    NSSBER *             berCert;
    int                  len 		= 0;
    int                  i;

    SSL_TRC(3, ("%d: SSL3[%d]: send certificate handshake",
		SSL_GETPID(), ss->fd));

    PR_ASSERT( ssl_HaveXmitBufLock(ss));
    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss));

    if (ss->sec.localCert)
    	NSSCert_Destroy(ss->sec.localCert);
    if (ss->sec.isServer) {
	sslServerCerts * sc = 
			ss->serverCerts + ss->ssl3->hs.kea_def->exchKeyType;
	certChain             = sc->serverCertChain;
	ss->sec.authKeyBits   = sc->serverKeyBits;
	ss->sec.authAlgorithm = ss->ssl3->hs.kea_def->signKeyType;
	ss->sec.localCert     = NSSCertChain_GetCert(sc->serverCertChain, 0);
    } else {
	certChain          = ss->ssl3->clientCertChain;
	ss->sec.localCert = nssCert_AddRef(ss->ssl3->clientCertificate);
    }

    if (certChain) {
	numCerts = NSSCertChain_GetNumCerts(certChain);
	if (numCerts < 0) {
	    return SECFailure;
	}
	for (i = 0; i < numCerts; i++) {
	    cert = NSSCertChain_GetCert(certChain, i);
	    if (cert) {
		berCert = nssCert_GetEncoding(cert);
		NSSCert_Destroy(cert);
		if (berCert == NULL) {
		    return SECFailure;
		}
		len += berCert->size + 3;
	    } else {
		return SECFailure;
	    }
	}
    }

    rv = ssl3_AppendHandshakeHeader(ss, certificate, len + 3);
    if (rv != SECSuccess) {
	return rv; 		/* err set by AppendHandshake. */
    }
    rv = ssl3_AppendHandshakeNumber(ss, len, 3);
    if (rv != SECSuccess) {
	return rv; 		/* err set by AppendHandshake. */
    }
    for (i = 0; i < numCerts; i++) {
	cert = NSSCertChain_GetCert(certChain, i);
	berCert = nssCert_GetEncoding(cert);
	rv = ssl3_AppendHandshakeVariable(ss, berCert->data, berCert->size, 3);
	NSSCert_Destroy(cert);
	if (rv != SECSuccess) {
	    return rv; 		/* err set by AppendHandshake. */
	}
    }

    return SECSuccess;
}

/* This is used to delete the CA certificates in the peer certificate chain
 * from the cert database after they've been validated.
 */
static void
ssl3_CleanupPeerCerts(ssl3State *ssl3)
{
    NSSCertChain_Destroy(ssl3->peerCertChain);
    ssl3->peerCertChain = NULL;
}

/* Called from ssl3_HandleHandshakeMessage() when it has deciphered a complete
 * ssl3 Certificate message.
 * Caller must hold Handshake and RecvBuf locks.
 */
static SECStatus
ssl3_HandleCertificate(sslSocket *ss, SSL3Opaque *b, PRUint32 length)
{
    ssl3State *      ssl3  	= ss->ssl3;
    NSSCert *        cert;
    NSSCertChain *   chain;
    PRInt32          remaining  = 0;
    PRInt32          size;
    PRInt32          berSize;
    SECStatus        rv;
    PRBool           isServer	= (PRBool)(!!ss->sec.isServer);
    PRBool           isTLS;
    SSL3AlertDescription desc	= bad_certificate;
    int              errCode    = SSL_ERROR_RX_MALFORMED_CERTIFICATE;
    NSSBER           berCert;
    PRStatus         status;
    const NSSUsages *ssl_usage;

    SSL_TRC(3, ("%d: SSL3[%d]: handle certificate handshake",
		SSL_GETPID(), ss->fd));
    PR_ASSERT( ssl_HaveRecvBufLock(ss) );
    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss) );

    if ((ssl3->hs.ws != wait_server_cert) &&
	(ssl3->hs.ws != wait_client_cert)) {
	desc    = unexpected_message;
	errCode = SSL_ERROR_RX_UNEXPECTED_CERTIFICATE;
	goto alert_loser;
    }

    if (ss->sec.peerCert != NULL) {
	if (ss->sec.peerKey) {
	    NSSPublicKey_Destroy(ss->sec.peerKey);
	    ss->sec.peerKey = NULL;
	}
	NSSCert_Destroy(ss->sec.peerCert);
	ss->sec.peerCert = NULL;
    }

    ssl3_CleanupPeerCerts(ssl3);
    isTLS = (PRBool)(ssl3->prSpec->version > SSL_LIBRARY_VERSION_3_0);

    /* It is reported that some TLS client sends a Certificate message
    ** with a zero-length message body.  We'll treat that case like a
    ** normal no_certificates message to maximize interoperability.
    */
    if (length) {
	remaining = ssl3_ConsumeHandshakeNumber(ss, 3, &b, &length);
	if (remaining < 0)
	    goto loser;	/* fatal alert already sent by ConsumeHandshake. */
    }

    if (!remaining) {
	if (!(isTLS && isServer))
	    goto alert_loser;
    	/* This is TLS's version of a no_certificate alert. */
    	/* I'm a server. I've requested a client cert. He hasn't got one. */
	rv = ssl3_HandleNoCertificate(ss);
	if (rv != SECSuccess) {
	    errCode = NSS_GetError();
	    goto loser;
	}
	goto cert_block;
    }

    /* First get the peer cert */
    remaining -= 3;
    if (remaining < 0) {
	goto decode_loser;
    }

    size = ssl3_ConsumeHandshakeNumber(ss, 3, &b, &length);
    if (size < 0)
	goto loser;	/* fatal alert already sent by ConsumeHandshake. */

    remaining -= size;
    if (remaining < 0)
	goto decode_loser;

    ssl_usage = isServer ? &s_ssl_server_usage : &s_ssl_client_usage;

    ssl3->peerCertChain = chain = NSSVolatileDomain_CreateCertChain(ss->vd,
                                                              NULL,
                                                              NSSTime_Now(),
                                                              ssl_usage,
                                                              NULL);

    /* XXX or in an arena? */
    berCert.data = nss_ZAlloc(NULL, size);
    if (!berCert.data) {
	goto loser; /* don't send alerts on memory errors */
    }
    berCert.size = berSize = size;

    rv = ssl3_ConsumeHandshake(ss, berCert.data, berCert.size, &b, &length);
    if (rv != SECSuccess)
	goto loser;	/* fatal alert already sent by ConsumeHandshake. */

    status = NSSCertChain_AddEncodedCert(chain, &berCert, NULL, NULL,
                                         &ss->sec.peerCert);
    if (status == PR_FAILURE) {
	/* We should report an alert if the cert was bad, but not if the
	 * problem was just some local problem, like memory error.
	 */
	goto ambiguous_err;
    }

    /* Now get all of the CA certs. */
    while (remaining != 0) {
	remaining -= 3;
	if (remaining < 0)
	    goto decode_loser;

	size = ssl3_ConsumeHandshakeNumber(ss, 3, &b, &length);
	if (size < 0)
	    goto loser;	/* fatal alert already sent by ConsumeHandshake. */

	remaining -= size;
	if (remaining < 0)
	    goto decode_loser;

	if (size > berSize) {
	    berCert.data = nss_ZRealloc(berCert.data, size);
	    if (!berCert.data) {
		goto loser; /* don't send alerts on memory errors */
	    }
	    berSize = length;
	}
	berCert.size = size; /* the size of the cert, not buffer */

	rv = ssl3_ConsumeHandshake(ss, berCert.data, berCert.size,
				   &b, &length);
	if (rv != SECSuccess)
	    goto loser;	/* fatal alert already sent by ConsumeHandshake. */

	status = NSSCertChain_AddEncodedCert(chain, &berCert, 
	                                     NULL, NULL, NULL);
	if (status == PR_FAILURE)
	    goto ambiguous_err;
    }
    nss_ZFreeIf(berCert.data); /* XXX on error as well */

    if (remaining != 0)
        goto decode_loser;

    /* XXX ??? this should happen inside NSSCertChain or something...
    SECKEY_UpdateCertPQG(ss->sec.peerCert);
    */

#ifdef FORTEZZA
    /*
     * We're making a fortezza connection, and the card hasn't unloaded it's
     * certs, try to  unload those certs now.
     */
    if (!trusted) {
	CERTCertificate *ccert;

	ccert = PK11_FindBestKEAMatch(ss->sec.peerCert, ss->pkcs11PinArg);
	if (ccert) 
	    CERT_DestroyCertificate(ccert);
    }
#endif /* FORTEZZA */

    rv = (SECStatus)(*ss->authCertificate)(ss->authCertificateArg, ss->fd,
					   PR_TRUE, isServer);
    if (rv) {
	errCode = NSS_GetError();
	if (!ss->handleBadCert) {
	    goto bad_cert;
	}
	rv = (SECStatus)(*ss->handleBadCert)(ss->badCertArg, ss->fd);
	if ( rv ) {
	    if ( rv == SECWouldBlock ) {
		/* someone will handle this connection asynchronously*/
		SSL_DBG(("%d: SSL3[%d]: go to async cert handler",
			 SSL_GETPID(), ss->fd));
		ssl_SetAlwaysBlock(ss);
		goto cert_block;
	    }
	    /* cert is bad */
	    goto bad_cert;
	}
	/* cert is good */
    }

    /* start SSL Step Up, if appropriate */
    cert = ss->sec.peerCert;
#ifdef IMPLEMENT_SSL_STEP_UP
    if (!isServer &&
    	ssl3_global_policy_some_restricted &&
        ssl3->policy == SSL_ALLOWED &&
	anyRestrictedEnabled(ss) &&
	SECSuccess == CERT_VerifyCertNow(cert->dbhandle, cert,
	                                 PR_FALSE, /* checkSig */
				         certUsageSSLServerWithStepUp,
/*XXX*/				         ss->authCertificateArg) ) {
	ssl3->policy         = SSL_RESTRICTED;
	ssl3->hs.rehandshake = PR_TRUE;
    }
#endif /* IMPLEMENT_SSL_STEP_UP */

#ifdef IMPLEMENT_SESSION_ID_CACHE
    ss->sec.ci.sid->peerCert = CERT_DupCertificate(ss->sec.peerCert);
#endif /* IMPLEMENT_SESSION_ID_CACHE */

    if (!ss->sec.isServer) {
	/* set the server authentication and key exchange types and sizes
	** from the value in the cert.  If the key exchange key is different,
	** it will get fixed when we handle the server key exchange message.
	*/
	NSSPublicKey *pubKey = NSSCert_GetPublicKey(cert);
	ss->sec.authAlgorithm = ssl3->hs.kea_def->signKeyType;
	ss->sec.keaType       = ssl3->hs.kea_def->exchKeyType;
	if (pubKey) {
	    ss->sec.keaKeyBits = ss->sec.authKeyBits =
			                 NSSPublicKey_GetKeyStrength(pubKey);
	    NSSPublicKey_Destroy(pubKey); 
	    pubKey = NULL;
    	}
    }

cert_block:
    if (ss->sec.isServer) {
	ssl3->hs.ws = wait_client_key;
    } else {
	ssl3->hs.ws = wait_cert_request; /* disallow server_key_exchange */
	if (ssl3->hs.kea_def->is_limited ||
	    /* XXX OR server cert is signing only. */
	    ssl3->hs.kea_def->kea == kea_fortezza ||
	    ssl3->hs.kea_def->exchKeyType == ssl_kea_dh) {
	    ssl3->hs.ws = wait_server_key; /* allow server_key_exchange */
	}
    }

    /* rv must normally be equal to SECSuccess here.  If we called
     * handleBadCert, it can also be SECWouldBlock.
     */
    return rv;

ambiguous_err:
    errCode = NSS_GetError();
    switch (errCode) {
    case PR_OUT_OF_MEMORY_ERROR:
    case NSS_ERROR_NO_MEMORY:
	if (isTLS) {
	    desc = internal_error;
	    goto alert_loser;
	}
	goto loser;
    }
    /* fall through to bad_cert. */

bad_cert:	/* caller has set errCode. */
#ifdef DEFINE_MORE_ERROR_TYPES
    switch (errCode) {
    case SEC_ERROR_LIBRARY_FAILURE:     desc = unsupported_certificate; break;
    case SEC_ERROR_EXPIRED_CERTIFICATE: desc = certificate_expired;     break;
    case SEC_ERROR_REVOKED_CERTIFICATE: desc = certificate_revoked;     break;
    case SEC_ERROR_INADEQUATE_KEY_USAGE:
    case SEC_ERROR_INADEQUATE_CERT_TYPE:
		                        desc = certificate_unknown;     break;
    case SEC_ERROR_UNTRUSTED_CERT:
		    desc = isTLS ? access_denied : certificate_unknown; break;
    case SEC_ERROR_UNKNOWN_ISSUER:      
    case SEC_ERROR_UNTRUSTED_ISSUER:    
		    desc = isTLS ? unknown_ca : certificate_unknown; break;
    case SEC_ERROR_EXPIRED_ISSUER_CERTIFICATE:
		    desc = isTLS ? unknown_ca : certificate_expired; break;

    case SEC_ERROR_CERT_NOT_IN_NAME_SPACE:
    case SEC_ERROR_PATH_LEN_CONSTRAINT_INVALID:
    case SEC_ERROR_CA_CERT_INVALID:
    case SEC_ERROR_BAD_SIGNATURE:
    default:                            desc = bad_certificate;     break;
    }
#endif /* DEFINE_MORE_ERROR_TYPES */
    SSL_DBG(("%d: SSL3[%d]: peer certificate is no good: error=%d",
	     SSL_GETPID(), ss->fd, errCode));

    goto alert_loser;

decode_loser:
    desc = isTLS ? decode_error : bad_certificate;

alert_loser:
    (void)SSL3_SendAlert(ss, alert_fatal, desc);

loser:
    ssl3_CleanupPeerCerts(ssl3);

    if (ss->sec.peerCert != NULL) {
	NSSCert_Destroy(ss->sec.peerCert);
	ss->sec.peerCert = NULL;
    }
    (void)ssl_MapLowLevelError(errCode);
    return SECFailure;
}


/* restart an SSL connection that we stopped to run certificate dialogs
** XXX	Need to document here how an application marks a cert to show that
**	the application has accepted it (overridden CERT_VerifyCert).
 *
 * XXX This code only works on the initial handshake on a connection, XXX
 *     It does not work on a subsequent handshake (redo).
 *
 * Return value: XXX
 *
 * Caller holds 1stHandshakeLock.
*/
int
ssl3_RestartHandshakeAfterServerCert(sslSocket *ss)
{
    NSSCert         * cert;
    ssl3State       * ssl3	= ss->ssl3;
    SECStatus         rv	= SECSuccess;

    if (MSB(ss->version) != MSB(SSL_LIBRARY_VERSION_3_0)) {
	SET_ERROR_CODE
    	return SECFailure;
    }
    if (!ss->ssl3) {
	SET_ERROR_CODE
    	return SECFailure;
    }

    cert = ss->sec.peerCert;

#ifdef IMPLEMENT_SSL_STEP_UP
    /* Permit step up if user decided to accept the cert */
    if (!ss->sec.isServer &&
    	ssl3_global_policy_some_restricted &&
        ssl3->policy == SSL_ALLOWED &&
	anyRestrictedEnabled(ss) &&
	(SECSuccess == CERT_VerifyCertNow(cert->dbhandle, cert,
	                                  PR_FALSE, /* checksig */
				          certUsageSSLServerWithStepUp,
/*XXX*/				          ss->authCertificateArg) )) {
	ssl3->policy         = SSL_RESTRICTED;
	ssl3->hs.rehandshake = PR_TRUE;
    }
#endif /* IMPLEMENT_SSL_STEP_UP */

    if (ss->handshake != NULL) {
	ss->handshake = ssl_GatherRecord1stHandshake;
	ss->sec.ci.sid->peerCert = nssCert_AddRef(ss->sec.peerCert);

	ssl_GetRecvBufLock(ss);
	if (ssl3->hs.msgState.buf != NULL) {
	    rv = ssl3_HandleRecord(ss, NULL, &ss->gs.buf);
	}
	ssl_ReleaseRecvBufLock(ss);
    }

    return rv;
}

static SECStatus
ssl3_ComputeTLSFinished(ssl3CipherSpec *spec,
			PRBool          isServer,
                const   SSL3Finished *  hashes,
                        TLSFinished  *  tlsFinished)
{
    NSSCryptoContext *prf_context;
    const char *label;
    unsigned int len;
    NSSItem it;
    PRStatus status;
    SECStatus rv;

    label = isServer ? "server finished" : "client finished";
    len   = 15;

    prf_context = NSSSymKey_CreateCryptoContext(spec->master_secret,
                                                s_tls_prf_ap, NULL);
    if (!prf_context)
    	return SECFailure;

    status = NSSCryptoContext_BeginSign(prf_context, NULL, NULL);
    if (status == PR_FAILURE) {
	goto loser;
    }
    NSSITEM_INIT(&it, label, len);
    status = NSSCryptoContext_ContinueSign(prf_context, &it);
    if (status == PR_FAILURE) {
	goto loser;
    }
    NSSITEM_INIT(&it, hashes->md5, sizeof(*hashes));
    status = NSSCryptoContext_ContinueSign(prf_context, &it);
    if (status == PR_FAILURE) {
	goto loser;
    }
    NSSITEM_INIT(&it, tlsFinished->verify_data, sizeof(*tlsFinished));
    if (NSSCryptoContext_FinishSign(prf_context, &it, NULL) == NULL) {
	goto loser;
    }

    rv = SECSuccess;

loser:
    NSSCryptoContext_Destroy(prf_context);
    return rv;
}

/* called from ssl3_HandleServerHelloDone
 *             ssl3_HandleClientHello
 *             ssl3_HandleFinished
 */
static SECStatus
ssl3_SendFinished(sslSocket *ss, PRInt32 flags)
{
    ssl3CipherSpec *cwSpec;
    PRBool          isTLS;
    PRBool          isServer = ss->sec.isServer;
    SECStatus       rv;
    SSL3Sender      sender = isServer ? sender_server : sender_client;
    SSL3Finished    hashes;
    TLSFinished     tlsFinished;

    SSL_TRC(3, ("%d: SSL3[%d]: send finished handshake", SSL_GETPID(), ss->fd));

    PR_ASSERT( ssl_HaveXmitBufLock(ss));
    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss));

    ssl_GetSpecReadLock(ss);
    cwSpec = ss->ssl3->cwSpec;
    isTLS = (PRBool)(cwSpec->version > SSL_LIBRARY_VERSION_3_0);
    rv = ssl3_ComputeHandshakeHashes(ss, cwSpec, &hashes, sender);
    if (isTLS && rv == SECSuccess) {
	rv = ssl3_ComputeTLSFinished(cwSpec, isServer, &hashes, &tlsFinished);
    }
    ssl_ReleaseSpecReadLock(ss);
    if (rv != SECSuccess) {
	goto fail;	/* err code was set by ssl3_ComputeHandshakeHashes */
    }

    if (isTLS) {
	rv = ssl3_AppendHandshakeHeader(ss, finished, sizeof tlsFinished);
	if (rv != SECSuccess) 
	    goto fail; 		/* err set by AppendHandshake. */
	rv = ssl3_AppendHandshake(ss, &tlsFinished, sizeof tlsFinished);
	if (rv != SECSuccess) 
	    goto fail; 		/* err set by AppendHandshake. */
    } else {
	rv = ssl3_AppendHandshakeHeader(ss, finished, sizeof hashes);
	if (rv != SECSuccess) 
	    goto fail; 		/* err set by AppendHandshake. */
	rv = ssl3_AppendHandshake(ss, &hashes, sizeof hashes);
	if (rv != SECSuccess) 
	    goto fail; 		/* err set by AppendHandshake. */
    }
    rv = ssl3_FlushHandshake(ss, flags);
    if (rv != SECSuccess) {
	goto fail;	/* error code set by ssl3_FlushHandshake */
    }
    return SECSuccess;

fail:
    return rv;
}



/* Called from ssl3_HandleHandshakeMessage() when it has deciphered a complete
 * ssl3 Finished message from the peer.
 * Caller must hold Handshake and RecvBuf locks.
 */
static SECStatus
ssl3_HandleFinished(sslSocket *ss, SSL3Opaque *b, PRUint32 length,
		    const SSL3Hashes *hashes)
{
    ssl3State *       ssl3	   = ss->ssl3;
    sslSessionID *    sid	   = ss->sec.ci.sid;
#ifdef IMPLEMENT_SESSION_ID_CACHE
    NSSSymKey *       wrappingKey  = NULL;
    NSSToken *        symKeyToken;
    void *            pwArg        = ss->pkcs11PinArg;
#endif /* IMPLEMENT_SESSION_ID_CACHE */
    SECStatus         rv;
    PRBool            isServer     = ss->sec.isServer;
    PRBool            isTLS;
    PRBool            doStepUp;

    PR_ASSERT( ssl_HaveRecvBufLock(ss) );
    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss) );

    SSL_TRC(3, ("%d: SSL3[%d]: handle finished handshake",
    	SSL_GETPID(), ss->fd));

    if (ssl3->hs.ws != wait_finished) {
	SSL3_SendAlert(ss, alert_fatal, unexpected_message);
    	nss_SetError(SSL_ERROR_RX_UNEXPECTED_FINISHED);
	return SECFailure;
    }

    isTLS = (PRBool)(ssl3->crSpec->version > SSL_LIBRARY_VERSION_3_0);
    if (isTLS) {
	TLSFinished tlsFinished;

	if (length != sizeof tlsFinished) {
	    (void)SSL3_SendAlert(ss, alert_fatal, decode_error);
	    nss_SetError(SSL_ERROR_RX_MALFORMED_FINISHED);
	    return SECFailure;
	}
	rv = ssl3_ComputeTLSFinished(ssl3->crSpec, !isServer, 
	                             hashes, &tlsFinished);
	if (rv != SECSuccess ||
	    0 != memcmp(&tlsFinished, b, length)) {
	    (void)SSL3_SendAlert(ss, alert_fatal, decrypt_error);
	    nss_SetError(SSL_ERROR_BAD_HANDSHAKE_HASH_VALUE);
	    return SECFailure;
	}
    } else {
	if (length != sizeof(SSL3Hashes)) {
	    (void)ssl3_IllegalParameter(ss);
	    nss_SetError(SSL_ERROR_RX_MALFORMED_FINISHED);
	    return SECFailure;
	}

	if (0 != memcmp(hashes, b, length)) {
	    (void)ssl3_HandshakeFailure(ss);
	    nss_SetError(SSL_ERROR_BAD_HANDSHAKE_HASH_VALUE);
	    return SECFailure;
	}
    }

    doStepUp = (PRBool)(!isServer && ssl3->hs.rehandshake);

    ssl_GetXmitBufLock(ss);	/*************************************/

    if ((isServer && !ssl3->hs.isResuming) ||
	(!isServer && ssl3->hs.isResuming)) {
	PRInt32 flags = 0;

	rv = ssl3_SendChangeCipherSpecs(ss);
	if (rv != SECSuccess) {
	    goto xmit_loser;	/* err is set. */
	}
	/* If this thread is in SSL_SecureSend (trying to write some data) 
	** or if it is going to step up, 
	** then set the ssl_SEND_FLAG_FORCE_INTO_BUFFER flag, so that the 
	** last two handshake messages (change cipher spec and finished) 
	** will be sent in the same send/write call as the application data.
	*/
	if (doStepUp || ss->writerThread == PR_GetCurrentThread()) {
	    flags = ssl_SEND_FLAG_FORCE_INTO_BUFFER;
	}
	rv = ssl3_SendFinished(ss, flags);
	if (rv != SECSuccess) {
	    goto xmit_loser;	/* err is set. */
	}
    }

    /* Optimization: don't cache this connection if we're going to step up. */
    if (doStepUp) {
	ssl_FreeSID(sid);
	ss->sec.ci.sid     = sid = NULL;
	ssl3->hs.rehandshake = PR_FALSE;
	rv = ssl3_SendClientHello(ss);
xmit_loser:
	ssl_ReleaseXmitBufLock(ss);
	return rv;	/* err code is set if appropriate. */
    }

    ssl_ReleaseXmitBufLock(ss);	/*************************************/

    /* The first handshake is now completed. */
    ss->handshake           = NULL;
    ss->firstHsDone         = PR_TRUE;
    ss->gs.writeOffset = 0;
    ss->gs.readOffset  = 0;

#ifdef IMPLEMENT_SESSION_ID_CACHE
  if (sid->cached == never_cached) {

    /* fill in the sid */
    sid->u.ssl3.cipherSuite = ssl3->hs.cipher_suite;
    sid->u.ssl3.compression = ssl3->hs.compression;
    sid->u.ssl3.policy      = ssl3->policy;
    sid->u.ssl3.exchKeyType = ssl3->hs.kea_def->exchKeyType;
    sid->version            = ss->version;
    sid->authAlgorithm      = ss->sec.authAlgorithm;
    sid->authKeyBits        = ss->sec.authKeyBits;
    sid->keaType            = ss->sec.keaType;
    sid->keaKeyBits         = ss->sec.keaKeyBits;
    sid->lastAccessTime     = sid->creationTime = ssl_Time();
    sid->expirationTime     = sid->creationTime + ssl3_sid_timeout;
    sid->localCert          = nssCertificate_AddRef(ss->sec.localCert);

    ssl_GetSpecReadLock(ss);	/*************************************/
    symKeySlot = PK11_GetSlotFromKey(ssl3->crSpec->master_secret);
    if (!isServer) {
	int  wrapKeyIndex;
	int  incarnation;

	/* these next few functions are mere accessors and don't fail. */
	sid->u.ssl3.masterWrapIndex  = wrapKeyIndex =
				       PK11_GetCurrentWrapIndex(symKeySlot);
	PR_ASSERT(wrapKeyIndex == 0);	/* array has only one entry! */

	sid->u.ssl3.masterWrapSeries = incarnation =
				       PK11_GetSlotSeries(symKeySlot);
	sid->u.ssl3.masterSlotID   = PK11_GetSlotID(symKeySlot);
	sid->u.ssl3.masterModuleID = PK11_GetModuleID(symKeySlot);
	sid->u.ssl3.masterValid    = PR_TRUE;

	/* Get the default wrapping key, for wrapping the master secret before
	 * placing it in the SID cache entry. */
	wrappingKey = PK11_GetWrapKey(symKeySlot, wrapKeyIndex,
				      CKM_INVALID_MECHANISM, incarnation,
				      pwArg);
	if (wrappingKey) {
	    mechanism = PK11_GetMechanism(wrappingKey); /* can't fail. */
	} else {
	    int keyLength;
	    /* if the wrappingKey doesn't exist, attempt to create it.
	     * Note: we intentionally ignore errors here.  If we cannot
	     * generate a wrapping key, it is not fatal to this SSL connection,
	     * but we will not be able to restart this session.
	     */
	    mechanism = PK11_GetBestWrapMechanism(symKeySlot);
	    keyLength = PK11_GetBestKeyLength(symKeySlot, mechanism);
	    /* Zero length means fixed key length algorithm, or error.
	     * It's ambiguous.
	     */
	    wrappingKey = PK11_KeyGen(symKeySlot, mechanism, NULL,
                                      keyLength, pwArg);
	    if (wrappingKey) {
	    	PK11_SetWrapKey(symKeySlot, wrapKeyIndex, wrappingKey);
	    }
	}
    } else {
	/* server. */
	mechanism = PK11_GetBestWrapMechanism(symKeySlot);
	if (mechanism != CKM_INVALID_MECHANISM) {
	    wrappingKey =
	    	getWrappingKey(ss, symKeySlot, ssl3->hs.kea_def->exchKeyType,
			       mechanism, pwArg);
	    if (wrappingKey) {
		mechanism = PK11_GetMechanism(wrappingKey); /* can't fail. */
	    }
	}
    }

    sid->u.ssl3.masterWrapMech = mechanism;
    PK11_FreeSlot(symKeySlot);

    rv = SECFailure;
    if (wrappingKey) {
	SECItem msItem;

	msItem.data = sid->u.ssl3.keys.wrapped_master_secret;
	msItem.size  = sizeof sid->u.ssl3.keys.wrapped_master_secret;
	rv = PK11_WrapSymKey(mechanism, NULL, wrappingKey,
			     ssl3->crSpec->master_secret, &msItem);
	/* rv is examined below. */
	sid->u.ssl3.keys.wrapped_master_secret_len = msItem.size;
	PK11_FreeSymKey(wrappingKey);
    }
    ssl_ReleaseSpecReadLock(ss);  /*************************************/

    /* If the wrap failed, we don't cache the sid.
     * The connection continues normally however.
     */
    if (!ss->noCache && rv == SECSuccess) {
	(*ss->sec.cache)(sid);
    }
  }
#endif /* IMPLEMENT_SESSION_ID_CACHE */
    ss->ssl3->hs.ws = idle_handshake;

    /* Do the handshake callback for sslv3 here. */
    if (ss->handshakeCallback != NULL) {
	(ss->handshakeCallback)(ss->fd, ss->handshakeCallbackData);
    }

    return SECSuccess;
}

/* Called from ssl3_HandleHandshake() when it has gathered a complete ssl3
 * hanshake message.
 * Caller must hold Handshake and RecvBuf locks.
 */
static SECStatus
ssl3_HandleHandshakeMessage(sslSocket *ss, SSL3Opaque *b, PRUint32 length)
{
    PRStatus          status;
    SECStatus         rv 	= SECSuccess;
    SSL3HandshakeType type 	= ss->ssl3->hs.msg_type;
    SSL3Hashes        hashes;	/* computed hashes are put here. */
    PRUint8           hdr[4];

    PR_ASSERT( ssl_HaveRecvBufLock(ss) );
    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss) );
    /*
     * We have to compute the hashes before we update them with the
     * current message.
     */
    ssl_GetSpecReadLock(ss);	/************************************/
    if((type == finished) || (type == certificate_verify)) {
	SSL3Sender      sender = (SSL3Sender)0;
	ssl3CipherSpec *rSpec  = ss->ssl3->prSpec;

	if (type == finished) {
	    sender = ss->sec.isServer ? sender_client : sender_server;
	    rSpec  = ss->ssl3->crSpec;
	}
	rv = ssl3_ComputeHandshakeHashes(ss, rSpec, &hashes, sender);
    }
    ssl_ReleaseSpecReadLock(ss); /************************************/
    if (rv != SECSuccess) {
	return rv;	/* error code was set by ssl3_ComputeHandshakeHashes*/
    }
    SSL_TRC(30,("%d: SSL3[%d]: handle handshake message: %s", SSL_GETPID(),
		ss->fd, ssl3_DecodeHandshakeType(ss->ssl3->hs.msg_type)));
    PRINT_BUF(60, (ss, "MD5 handshake hash:",
    	      (unsigned char*)ss->ssl3->hs.md5, MD5_LENGTH));
    PRINT_BUF(95, (ss, "SHA handshake hash:",
    	      (unsigned char*)ss->ssl3->hs.sha, SHA1_LENGTH));

    hdr[0] = (PRUint8)ss->ssl3->hs.msg_type;
    hdr[1] = (PRUint8)(length >> 16);
    hdr[2] = (PRUint8)(length >>  8);
    hdr[3] = (PRUint8)(length      );

    /* Start new handshake hashes when we start a new handshake */
    if (ss->ssl3->hs.msg_type == client_hello) {
	SSL_TRC(30,("%d: SSL3[%d]: reset handshake hashes",
		SSL_GETPID(), ss->fd ));
	status = NSSCryptoContext_BeginDigest(ss->ssl3->hs.md5, NULL, NULL);
	if (status == PR_FAILURE) {
	    ssl_MapLowLevelError(SSL_ERROR_MD5_DIGEST_FAILURE);
	    return rv;
	}
	status = NSSCryptoContext_BeginDigest(ss->ssl3->hs.sha, NULL, NULL);
	if (status == PR_FAILURE) {
	    ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
	    return rv;
	}
    }
    /* We should not include hello_request messages in the handshake hashes */
    if (ss->ssl3->hs.msg_type != hello_request) {
	rv = ssl3_UpdateHandshakeHashes(ss, (unsigned char*) hdr, 4);
	if (rv != SECSuccess) return rv;	/* err code already set. */
	rv = ssl3_UpdateHandshakeHashes(ss, b, length);
	if (rv != SECSuccess) return rv;	/* err code already set. */
    }

    nss_SetError(0);	/* each message starts with no error. */
    switch (ss->ssl3->hs.msg_type) {
    case hello_request:
	if (length != 0) {
	    (void)ssl3_DecodeError(ss);
	    nss_SetError(SSL_ERROR_RX_MALFORMED_HELLO_REQUEST);
	    return SECFailure;
	}
	if (ss->sec.isServer) {
	    (void)SSL3_SendAlert(ss, alert_fatal, unexpected_message);
	    nss_SetError(SSL_ERROR_RX_UNEXPECTED_HELLO_REQUEST);
	    return SECFailure;
	}
	rv = ssl3_HandleHelloRequest(ss);
	break;
    case client_hello:
	if (!ss->sec.isServer) {
	    (void)SSL3_SendAlert(ss, alert_fatal, unexpected_message);
	    nss_SetError(SSL_ERROR_RX_UNEXPECTED_CLIENT_HELLO);
	    return SECFailure;
	}
	rv = ssl3_HandleClientHello(ss, b, length);
	break;
    case server_hello:
	if (ss->sec.isServer) {
	    (void)SSL3_SendAlert(ss, alert_fatal, unexpected_message);
	    nss_SetError(SSL_ERROR_RX_UNEXPECTED_SERVER_HELLO);
	    return SECFailure;
	}
	rv = ssl3_HandleServerHello(ss, b, length);
	break;
    case certificate:
	rv = ssl3_HandleCertificate(ss, b, length);
	break;
    case server_key_exchange:
	if (ss->sec.isServer) {
	    (void)SSL3_SendAlert(ss, alert_fatal, unexpected_message);
	    nss_SetError(SSL_ERROR_RX_UNEXPECTED_SERVER_KEY_EXCH);
	    return SECFailure;
	}
	rv = ssl3_HandleServerKeyExchange(ss, b, length);
	break;
    case certificate_request:
	if (ss->sec.isServer) {
	    (void)SSL3_SendAlert(ss, alert_fatal, unexpected_message);
	    nss_SetError(SSL_ERROR_RX_UNEXPECTED_CERT_REQUEST);
	    return SECFailure;
	}
	rv = ssl3_HandleCertificateRequest(ss, b, length);
	break;
    case server_hello_done:
	if (length != 0) {
	    (void)ssl3_DecodeError(ss);
	    nss_SetError(SSL_ERROR_RX_MALFORMED_HELLO_DONE);
	    return SECFailure;
	}
	if (ss->sec.isServer) {
	    (void)SSL3_SendAlert(ss, alert_fatal, unexpected_message);
	    nss_SetError(SSL_ERROR_RX_UNEXPECTED_HELLO_DONE);
	    return SECFailure;
	}
	rv = ssl3_HandleServerHelloDone(ss);
	break;
    case certificate_verify:
	if (!ss->sec.isServer) {
	    (void)SSL3_SendAlert(ss, alert_fatal, unexpected_message);
	    nss_SetError(SSL_ERROR_RX_UNEXPECTED_CERT_VERIFY);
	    return SECFailure;
	}
	rv = ssl3_HandleCertificateVerify(ss, b, length, &hashes);
	break;
    case client_key_exchange:
	if (!ss->sec.isServer) {
	    (void)SSL3_SendAlert(ss, alert_fatal, unexpected_message);
	    nss_SetError(SSL_ERROR_RX_UNEXPECTED_CLIENT_KEY_EXCH);
	    return SECFailure;
	}
	rv = ssl3_HandleClientKeyExchange(ss, b, length);
	break;
    case finished:
        rv = ssl3_HandleFinished(ss, b, length, &hashes);
	break;
    default:
	(void)SSL3_SendAlert(ss, alert_fatal, unexpected_message);
	nss_SetError(SSL_ERROR_RX_UNKNOWN_HANDSHAKE);
	rv = SECFailure;
    }
    return rv;
}

/* Called only from ssl3_HandleRecord, for each (deciphered) ssl3 record.
 * origBuf is the decrypted ssl record content.
 * Caller must hold the handshake and RecvBuf locks.
 */
static SECStatus
ssl3_HandleHandshake(sslSocket *ss, sslBuffer *origBuf)
{
    /*
     * There may be a partial handshake message already in the handshake
     * state. The incoming buffer may contain another portion, or a
     * complete message or several messages followed by another portion.
     *
     * Each message is made contiguous before being passed to the actual
     * message parser.
     */
    ssl3State *ssl3 = ss->ssl3;
    sslBuffer *buf = &ssl3->hs.msgState; /* do not lose the original buffer pointer */
    SECStatus rv;

    PR_ASSERT( ssl_HaveRecvBufLock(ss) );
    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss) );

    if (buf->buf == NULL) {
	*buf = *origBuf;
    }
    while (buf->size > 0) {
	while (ssl3->hs.header_bytes < 4) {
	    uint8 t;
	    t = *(buf->buf++);
	    buf->size--;
	    if (ssl3->hs.header_bytes++ == 0)
		ssl3->hs.msg_type = (SSL3HandshakeType)t;
	    else
		ssl3->hs.msg_len = (ssl3->hs.msg_len << 8) + t;

#define MAX_HANDSHAKE_MSG_LEN 0x1ffff	/* 128k - 1 */

	    if (ssl3->hs.header_bytes == 4) {
		if (ssl3->hs.msg_len > MAX_HANDSHAKE_MSG_LEN) {
		    (void)ssl3_DecodeError(ss);
		    nss_SetError(SSL_ERROR_RX_RECORD_TOO_LONG);
		    return SECFailure;
		}
	    }
#undef MAX_HANDSHAKE_MSG_LEN
	    if (buf->size == 0 && ssl3->hs.msg_len > 0) {
		buf->buf = NULL;
		return SECSuccess;
	    }
	}

	/*
	 * Header has been gathered and there is at least one byte of new
	 * data available for this message. If it can be done right out
	 * of the original buffer, then use it from there.
	 */
	if (ssl3->hs.msg_body.size == 0 && buf->size >= ssl3->hs.msg_len) {
	    /* handle it from input buffer */
	    rv = ssl3_HandleHandshakeMessage(ss, buf->buf, ssl3->hs.msg_len);
	    if (rv == SECFailure) {
		/* This test wants to fall through on either
		 * SECSuccess or SECWouldBlock.
		 * ssl3_HandleHandshakeMessage MUST set the error code.
		 */
		return rv;
	    }
	    buf->buf += ssl3->hs.msg_len;
	    buf->size -= ssl3->hs.msg_len;
	    ssl3->hs.msg_len = 0;
	    ssl3->hs.header_bytes = 0;
	    if (rv != SECSuccess) { /* return if SECWouldBlock. */
		return rv;
	    }
	} else {
	    /* must be copied to msg_body and dealt with from there */
	    unsigned int bytes;

	    bytes = PR_MIN(buf->size, ssl3->hs.msg_len);

	    /* Grow the buffer if needed */
	    if (bytes > ssl3->hs.msg_body.space - ssl3->hs.msg_body.size) {
		rv = sslBuffer_Grow(&ssl3->hs.msg_body,
		                  ssl3->hs.msg_body.size + bytes);
		if (rv != SECSuccess) {
		    /* sslBuffer_Grow has set a memory error code. */
		    return SECFailure;
	    	}
	    }
	    memcpy(ssl3->hs.msg_body.buf + ssl3->hs.msg_body.size,
		      buf->buf, buf->size);
	    buf->buf += bytes;
	    buf->size -= bytes;

	    /* should not be more than one message in msg_body */
	    PR_ASSERT(ssl3->hs.msg_body.size <= ssl3->hs.msg_len);

	    /* if we have a whole message, do it */
	    if (ssl3->hs.msg_body.size == ssl3->hs.msg_len) {
		rv = ssl3_HandleHandshakeMessage(
		    ss, ssl3->hs.msg_body.buf, ssl3->hs.msg_len);
		/*
		 * XXX This appears to be wrong.  This error handling
		 * should clean up after a SECWouldBlock return, like the
		 * error handling used 40 lines before/above this one,
		 */
		if (rv != SECSuccess) {
		    /* ssl3_HandleHandshakeMessage MUST set error code. */
		    return rv;
		}
		ssl3->hs.msg_body.size = 0;
		ssl3->hs.msg_len      = 0;
		ssl3->hs.header_bytes = 0;
	    } else {
		PR_ASSERT(buf->size == 0);
		break;
	    }
	}
    }	/* end loop */

    origBuf->size = 0;	/* So ssl3_GatherAppDataRecord will keep looping. */
    buf->buf = NULL;	/* not a leak. */
    return SECSuccess;
}

/* if cText is non-null, then decipher, check MAC, and decompress the
 * SSL record from cText->buf (typically gs->inbuf)
 * into databuf (typically gs->buf), and any previous contents of databuf
 * is lost.  Then handle databuf according to its SSL record type,
 * unless it's an application record.
 *
 * If cText is NULL, then the ciphertext has previously been deciphered and
 * checked, and is already sitting in databuf.  It is processed as an SSL
 * Handshake message.
 *
 * DOES NOT process the decrypted/decompressed application data.
 * On return, databuf contains the decrypted/decompressed record.
 *
 * Called from ssl3_GatherCompleteHandshake
 *             ssl3_RestartHandshakeAfterCertReq
 *             ssl3_RestartHandshakeAfterServerCert
 *
 * Caller must hold the RecvBufLock.
 *
 * This function aquires and releases the SSL3Handshake Lock, holding the
 * lock around any calls to functions that handle records other than
 * Application Data records.
 */
SECStatus
ssl3_HandleRecord(sslSocket *ss, SSL3Ciphertext *cText, sslBuffer *databuf)
{
const ssl3BulkCipherDef *cipher_def;
    ssl3State *          ssl3 			= ss->ssl3;
    ssl3CipherSpec *     crSpec;
    SECStatus            rv;
    unsigned int         hashBytes;
    unsigned int         padding_length;
    PRBool               isTLS;
    SSL3ContentType      rType;
    SSL3Opaque           hash[MAX_MAC_LENGTH];
    NSSItem in, out, *dummy;

    PR_ASSERT( ssl_HaveRecvBufLock(ss) );

    if (ssl3 == NULL) {
	ssl_GetSSL3HandshakeLock(ss);
	rv = ssl3_InitState(ss);
	ssl_ReleaseSSL3HandshakeLock(ss);
	if (rv != SECSuccess) {
	    return rv;		/* ssl3_InitState has set the error code. */
    	}
    }

    ssl3 = ss->ssl3;

    /* cText is NULL when we're called from ssl3_RestartHandshakeAfterXXX().
     * This implies that databuf holds a previously deciphered SSL Handshake
     * message.
     */
    if (cText == NULL) {
	SSL_DBG(("%d: SSL3[%d]: HandleRecord, resuming handshake",
		 SSL_GETPID(), ss->fd));
	rType = content_handshake;
	goto process_it;
    }

    databuf->size = 0; /* filled in by decode call below. */
    if (databuf->space < MAX_FRAGMENT_LENGTH) {
	rv = sslBuffer_Grow(databuf, MAX_FRAGMENT_LENGTH + 2048);
	if (rv != SECSuccess) {
	    SSL_DBG(("%d: SSL3[%d]: HandleRecord, tried to get %d bytes",
		     SSL_GETPID(), ss->fd, MAX_FRAGMENT_LENGTH + 2048));
	    /* sslBuffer_Grow has set a memory error code. */
	    return SECFailure;
	}
    }

    PRINT_BUF(80, (ss, "ciphertext:", cText->buf->buf, cText->buf->size));

    ssl_GetSpecReadLock(ss); /******************************************/

    crSpec = ssl3->crSpec;
    cipher_def = crSpec->cipher_def;
    isTLS = (PRBool)(crSpec->version > SSL_LIBRARY_VERSION_3_0);

    if (isTLS && cText->buf->size > (MAX_FRAGMENT_LENGTH + 2048)) {
	ssl_ReleaseSpecReadLock(ss);
	SSL3_SendAlert(ss, alert_fatal, record_overflow);
	nss_SetError(SSL_ERROR_RX_RECORD_TOO_LONG);
	return SECFailure;
    }
    /* decrypt from cText buf to databuf. */
    NSSITEM_INIT(&in, cText->buf->buf, cText->buf->size);
    NSSITEM_INIT(&out, databuf->buf, databuf->space);
    dummy = crSpec->decode(crSpec->decodeContext, &in, &out, NULL);
    databuf->size = out.size;

    PRINT_BUF(80, (ss, "cleartext:", databuf->buf, databuf->size));
    if (dummy == NULL) {
	ssl_ReleaseSpecReadLock(ss);
	ssl_MapLowLevelError(SSL_ERROR_DECRYPTION_FAILURE);
	SSL3_SendAlert(ss, alert_fatal, 
		       isTLS ? decryption_failed : bad_record_mac);
	ssl_MapLowLevelError(SSL_ERROR_DECRYPTION_FAILURE);
	return SECFailure;
    }

    /* If it's a block cipher, check and strip the padding. */
    if (cipher_def->type == type_block) {
	padding_length = *(databuf->buf + databuf->size - 1);
	/* TLS permits padding to exceed the block size, up to 255 bytes. */
	if (padding_length + crSpec->mac_size >= databuf->size)
	    goto bad_pad;
	/* if TLS, check value of first padding byte. */
	if (padding_length && isTLS && padding_length != 
		*(databuf->buf + databuf->size - 1 - padding_length))
	    goto bad_pad;
	databuf->size -= padding_length + 1;
	if (databuf->size <= 0) {
bad_pad:
	    /* must not hold spec lock when calling SSL3_SendAlert. */
	    ssl_ReleaseSpecReadLock(ss);
	    /* SSL3 & TLS must send bad_record_mac if padding check fails. */
	    SSL3_SendAlert(ss, alert_fatal, bad_record_mac);
	    nss_SetError(SSL_ERROR_BAD_BLOCK_PADDING);
	    return SECFailure;
	}
    }

    /* Check the MAC. */
    if (databuf->size < crSpec->mac_size) {
    	/* record is too short to have a valid mac. */
	goto bad_mac;
    }
    databuf->size -= crSpec->mac_size;
    rType = cText->type;
    rv = ssl3_ComputeRecordMAC(
    	crSpec, (ss->sec.isServer) ? crSpec->client.write_mac_context
				    : crSpec->server.write_mac_context,
	rType, cText->version, crSpec->read_seq_num, 
	databuf->buf, databuf->size, hash, &hashBytes);
    if (rv != SECSuccess) {
	ssl_ReleaseSpecReadLock(ss);
	ssl_MapLowLevelError(SSL_ERROR_MAC_COMPUTATION_FAILURE);
	return rv;
    }

    if (hashBytes != (unsigned)crSpec->mac_size ||
	memcmp(databuf->buf + databuf->size, hash, crSpec->mac_size) != 0) {
bad_mac:
	/* must not hold spec lock when calling SSL3_SendAlert. */
	ssl_ReleaseSpecReadLock(ss);
	SSL3_SendAlert(ss, alert_fatal, bad_record_mac);
	nss_SetError(SSL_ERROR_BAD_MAC_READ);

	SSL_DBG(("%d: SSL3[%d]: mac check failed", SSL_GETPID(), ss->fd));

	return SECFailure;
    }

    ssl3_BumpSequenceNumber(&crSpec->read_seq_num);

    ssl_ReleaseSpecReadLock(ss); /*****************************************/

    /*
     * The decrypted data is now in databuf.
     *
     * the null decompression routine is right here
     */

    /*
    ** Having completed the decompression, check the length again. 
    */
    if (isTLS && databuf->size > (MAX_FRAGMENT_LENGTH + 1024)) {
	SSL3_SendAlert(ss, alert_fatal, record_overflow);
	nss_SetError(SSL_ERROR_RX_RECORD_TOO_LONG);
	return SECFailure;
    }

    /* Application data records are processed by the caller of this
    ** function, not by this function.
    */
    if (rType == content_application_data) {
    	return SECSuccess;
    }

    /* It's a record that must be handled by ssl itself, not the application.
    */
process_it:
    /* XXX  Get the xmit lock here.  Odds are very high that we'll be xmiting
     * data ang getting the xmit lock here prevents deadlocks.
     */
    ssl_GetSSL3HandshakeLock(ss);

    /* All the functions called in this switch MUST set error code if
    ** they return SECFailure or SECWouldBlock.
    */
    switch (rType) {
    case content_change_cipher_spec:
	rv = ssl3_HandleChangeCipherSpecs(ss, databuf);
	break;
    case content_alert:
	rv = ssl3_HandleAlert(ss, databuf);
	break;
    case content_handshake:
	rv = ssl3_HandleHandshake(ss, databuf);
	break;
    case content_application_data:
	rv = SECSuccess;
	break;
    default:
	SSL_DBG(("%d: SSL3[%d]: bogus content type=%d",
		 SSL_GETPID(), ss->fd, cText->type));
	/* XXX Send an alert ???  */
	nss_SetError(SSL_ERROR_RX_UNKNOWN_RECORD_TYPE);
	rv = SECFailure;
	break;
    }

    ssl_ReleaseSSL3HandshakeLock(ss);
    return rv;

}

/*
 * Initialization functions
 */

/* Called from ssl3_InitState, immediately below. */
/* Caller must hold the SpecWriteLock. */
static void
ssl3_InitCipherSpec(sslSocket *ss, ssl3CipherSpec *spec)
{
    spec->cipher_def               = &bulk_cipher_defs[cipher_null];
    PR_ASSERT(spec->cipher_def->cipher == cipher_null);
    spec->mac_def                  = &mac_defs[ssl_mac_null];
    PR_ASSERT(spec->mac_def->mac == ssl_mac_null);
    spec->encode                   = Null_Cipher;
    spec->decode                   = Null_Cipher;
    spec->destroy                  = NULL;
    spec->mac_size                 = 0;
    spec->master_secret            = NULL;

    spec->client.write_key         = NULL;
    spec->client.write_mac_context = NULL;

    spec->server.write_key         = NULL;
    spec->server.write_mac_context = NULL;

    spec->write_seq_num.high       = 0;
    spec->write_seq_num.low        = 0;

    spec->read_seq_num.high        = 0;
    spec->read_seq_num.low         = 0;

    spec->version                  = ss->enableTLS
                                          ? SSL_LIBRARY_VERSION_3_1_TLS
                                          : SSL_LIBRARY_VERSION_3_0;
}

/* Called from:	ssl3_SendRecord
**		ssl3_StartHandshakeHash() <- ssl2_BeginClientHandshake()
**		ssl3_SendClientHello()
**		ssl3_HandleServerHello()
**		ssl3_HandleClientHello()
**		ssl3_HandleV2ClientHello()
**		ssl3_HandleRecord()
**
** This function should perhaps acquire and release the SpecWriteLock.
**
**
*/
static SECStatus
ssl3_InitState(sslSocket *ss)
{
    ssl3State *  ssl3 = NULL;
    NSSCryptoContext *md5  = NULL;
    NSSCryptoContext *sha  = NULL;
    SECStatus    rv;
    PRStatus     status;

    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss));

    /* reinitialization for renegotiated sessions XXX */
    if (ss->ssl3 != NULL)
	return SECSuccess;

    ssl3 = nss_ZNEW(NULL, ssl3State); /* zero on purpose */
    if (ssl3 == NULL)
	return SECFailure;	/* PORT_ZAlloc has set memory error code. */

    /* note that entire HandshakeState is zero, including the buffer */
    ssl3->policy = SSL_ALLOWED;

    ssl_GetSpecWriteLock(ss);
    ssl3->crSpec = ssl3->cwSpec = &ssl3->specs[0];
    ssl3->prSpec = ssl3->pwSpec = &ssl3->specs[1];
    ssl3->hs.rehandshake = PR_FALSE;
    ssl3_InitCipherSpec(ss, ssl3->crSpec);
    ssl3_InitCipherSpec(ss, ssl3->prSpec);
#ifdef FORTEZZA
    ssl3->fortezza.tek = NULL;
#endif /* FORTEZZA */

    ssl3->hs.ws = (ss->sec.isServer) ? wait_client_hello : wait_server_hello;
    ssl_ReleaseSpecWriteLock(ss);

    /*
     * note: We should probably lookup an SSL3 slot for these
     * handshake hashes in hopes that we wind up with the same slots
     * that the master secret will wind up in ...
     */
    SSL_TRC(30,("%d: SSL3[%d]: start handshake hashes", SSL_GETPID(), ss->fd));
    ssl3->hs.md5 = md5 = NSSVolatileDomain_CreateCryptoContext(ss->vd,
                                                               s_md5_ap,
                                                               NULL);
    if (md5 == NULL) {
	ssl_MapLowLevelError(SSL_ERROR_MD5_DIGEST_FAILURE);
	goto loser;
    }
    status = NSSCryptoContext_BeginDigest(md5, NULL, NULL);
    if (status == PR_FAILURE) {
	ssl_MapLowLevelError(SSL_ERROR_MD5_DIGEST_FAILURE);
	goto loser;
    }

    sha = ssl3->hs.sha = NSSVolatileDomain_CreateCryptoContext(ss->vd,
                                                               s_sha1_ap,
                                                               NULL);
    if (sha == NULL) {
	ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
	goto loser;
    }
    status = NSSCryptoContext_BeginDigest(sha, NULL, NULL);
    if (status == PR_FAILURE) {
	ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
	goto loser;
    }

    /* Don't hide this from the rest of the world any more. */
    ss->ssl3 = ssl3;

    return SECSuccess;

loser:
    if (md5 != NULL) NSSCryptoContext_Destroy(md5);
    if (sha != NULL) NSSCryptoContext_Destroy(sha);
    if (ssl3 != NULL) nss_ZFreeIf(ssl3);
    return SECFailure;
}

/* Returns a reference counted object that contains a key pair.
 * Or NULL on failure.  Initial ref count is 1.
 * Uses the keys in the pair as input.
 */
ssl3KeyPair *
ssl3_NewKeyPair(NSSPrivateKey * privKey, NSSPublicKey * pubKey)
{
    ssl3KeyPair * pair;

    if (!privKey || !pubKey) {
	nss_SetError(NSS_ERROR_INVALID_ARGS);
    	return NULL;
    }
    pair = nss_ZNEW(NULL, ssl3KeyPair);
    if (!pair)
    	return NULL;			/* error code is set. */
    pair->refCount = 1;
    pair->privKey  = privKey;
    pair->pubKey   = pubKey;
    return pair;			/* success */
}

ssl3KeyPair *
ssl3_GetKeyPairRef(ssl3KeyPair * keyPair)
{
    PR_AtomicIncrement(&keyPair->refCount);
    return keyPair;
}

void
ssl3_FreeKeyPair(ssl3KeyPair * keyPair)
{
    PRInt32 newCount =  PR_AtomicDecrement(&keyPair->refCount);
    if (!newCount) {
	NSSPrivateKey_Destroy(keyPair->privKey);
	NSSPublicKey_Destroy( keyPair->pubKey);
    	nss_ZFreeIf(keyPair);
    }
}



#ifdef IMPLEMENT_SSL_STEP_DOWN
/*
 * Creates the public and private RSA keys for SSL Step down.
 * Called from SSL_ConfigSecureServer in sslsecur.c
 */
SECStatus
ssl3_CreateRSAStepDownKeys(sslSocket *ss)
{
    SECStatus             rv  	 = SECSuccess;
    SECKEYPrivateKey *    privKey;		/* RSA step down key */
    SECKEYPublicKey *     pubKey;		/* RSA step down key */

    if (ss->stepDownKeyPair)
	ssl3_FreeKeyPair(ss->stepDownKeyPair);
    ss->stepDownKeyPair = NULL;
#ifndef HACKED_EXPORT_SERVER
    /* Sigh, should have a get key strength call for private keys */
    if (PK11_GetPrivateModulusLen(ss->serverCerts[ssl_kea_rsa].serverKey) >
                                                     EXPORT_RSA_KEY_LENGTH) {
	/* need to ask for the key size in bits */
	privKey = SECKEY_CreateRSAPrivateKey(EXPORT_RSA_KEY_LENGTH * BPB,
					     &pubKey, NULL);
    	if (!privKey || !pubKey ||
	    !(ss->stepDownKeyPair = ssl3_NewKeyPair(privKey, pubKey))) {
	    ssl_MapLowLevelError(SEC_ERROR_KEYGEN_FAIL);
	    rv = SECFailure;
	}
    }
#endif
    return rv;
}
#endif /* IMPLEMENT_SSL_STEP_DOWN */


/* record the export policy for this cipher suite */
SECStatus
ssl3_SetPolicy(ssl3CipherSuite which, int policy)
{
    ssl3CipherSuiteCfg *suite;

    suite = ssl_LookupCipherSuiteCfg(which, cipherSuites);
    if (suite == NULL) {
	return SECFailure; /* err code was set by ssl_LookupCipherSuiteCfg */
    }
    suite->policy = policy;

    if (policy == SSL_RESTRICTED) {
	ssl3_global_policy_some_restricted = PR_TRUE;
    }

    return SECSuccess;
}

SECStatus
ssl3_GetPolicy(ssl3CipherSuite which, PRInt32 *oPolicy)
{
    ssl3CipherSuiteCfg *suite;
    PRInt32             policy;
    SECStatus           rv;

    suite = ssl_LookupCipherSuiteCfg(which, cipherSuites);
    if (suite) {
    	policy = suite->policy;
	rv     = SECSuccess;
    } else {
    	policy = SSL_NOT_ALLOWED;
	rv     = SECFailure;	/* err code was set by Lookup. */
    }
    *oPolicy = policy;
    return rv;
}

/* record the user preference for this suite */
SECStatus
ssl3_CipherPrefSetDefault(ssl3CipherSuite which, PRBool enabled)
{
    ssl3CipherSuiteCfg *suite;

    suite = ssl_LookupCipherSuiteCfg(which, cipherSuites);
    if (suite == NULL) {
	return SECFailure; /* err code was set by ssl_LookupCipherSuiteCfg */
    }
    suite->enabled = enabled;
    return SECSuccess;
}

/* return the user preference for this suite */
SECStatus
ssl3_CipherPrefGetDefault(ssl3CipherSuite which, PRBool *enabled)
{
    ssl3CipherSuiteCfg *suite;
    PRBool              pref;
    SECStatus           rv;

    suite = ssl_LookupCipherSuiteCfg(which, cipherSuites);
    if (suite) {
    	pref   = suite->enabled;
	rv     = SECSuccess;
    } else {
    	pref   = SSL_NOT_ALLOWED;
	rv     = SECFailure;	/* err code was set by Lookup. */
    }
    *enabled = pref;
    return rv;
}

SECStatus
ssl3_CipherPrefSet(sslSocket *ss, ssl3CipherSuite which, PRBool enabled)
{
    ssl3CipherSuiteCfg *suite;

    suite = ssl_LookupCipherSuiteCfg(which, ss->cipherSuites);
    if (suite == NULL) {
	return SECFailure; /* err code was set by ssl_LookupCipherSuiteCfg */
    }
    suite->enabled = enabled;
    return SECSuccess;
}

SECStatus
ssl3_CipherPrefGet(sslSocket *ss, ssl3CipherSuite which, PRBool *enabled)
{
    ssl3CipherSuiteCfg *suite;
    PRBool              pref;
    SECStatus           rv;

    suite = ssl_LookupCipherSuiteCfg(which, ss->cipherSuites);
    if (suite) {
    	pref   = suite->enabled;
	rv     = SECSuccess;
    } else {
    	pref   = SSL_NOT_ALLOWED;
	rv     = SECFailure;	/* err code was set by Lookup. */
    }
    *enabled = pref;
    return rv;
}

/* copy global default policy into socket. */
void
ssl3_InitSocketPolicy(sslSocket *ss)
{
    memcpy(ss->cipherSuites, cipherSuites, sizeof cipherSuites);
}

/* ssl3_config_match_init must have already been called by
 * the caller of this function.
 */
SECStatus
ssl3_ConstructV2CipherSpecsHack(sslSocket *ss, unsigned char *cs, int *size)
{
    int i, count = 0;

    PR_ASSERT(ss != 0);
    if (!ss) {
	nss_SetError(PR_INVALID_ARGUMENT_ERROR);
	return SECFailure;
    }
    if (!ss->enableSSL3 && !ss->enableTLS) {
    	*size = 0;
	return SECSuccess;
    }
    if (cs == NULL) {
	*size = count_cipher_suites(ss, SSL_ALLOWED, PR_TRUE);
	return SECSuccess;
    }

    /* ssl3_config_match_init was called by the caller of this function. */
    for (i = 0; i < ssl_V3_SUITES_IMPLEMENTED; i++) {
	ssl3CipherSuiteCfg *suite = &ss->cipherSuites[i];
	if (config_match(suite, SSL_ALLOWED, PR_TRUE)) {
	    if (cs != NULL) {
		*cs++ = 0x00;
		*cs++ = (suite->cipher_suite >> 8) & 0xFF;
		*cs++ =  suite->cipher_suite       & 0xFF;
	    }
	    count++;
	}
    }
    *size = count;
    return SECSuccess;
}

/*
** If ssl3 socket has completed the first handshake, and is in idle state, 
** then start a new handshake.
** If flushCache is true, the SID cache will be flushed first, forcing a
** "Full" handshake (not a session restart handshake), to be done.
**
** called from SSL_RedoHandshake(), which already holds the handshake locks.
*/
SECStatus
ssl3_RedoHandshake(sslSocket *ss, PRBool flushCache)
{
    sslSessionID *   sid = ss->sec.ci.sid;
    SECStatus        rv;

    PR_ASSERT( ssl_HaveSSL3HandshakeLock(ss) );

    if (!ss->firstHsDone ||
        ((ss->version >= SSL_LIBRARY_VERSION_3_0) &&
	 ss->ssl3 && (ss->ssl3->hs.ws != idle_handshake))) {
	nss_SetError(SSL_ERROR_HANDSHAKE_NOT_COMPLETED);
	return SECFailure;
    }
    if (sid && flushCache) {
#ifdef IMPLEMENT_SSL_SESSION_ID_CACHE
	ss->sec.uncache(sid);	/* remove it from whichever cache it's in. */
#endif /* IMPLEMENT_SSL_SESSION_ID_CACHE */
	ssl_FreeSID(sid);	/* dec ref count and free if zero. */
	ss->sec.ci.sid = NULL;
    }

    ssl_GetXmitBufLock(ss);	/**************************************/

    /* start off a new handshake. */
    rv = (ss->sec.isServer) ? ssl3_SendHelloRequest(ss)
                            : ssl3_SendClientHello(ss);

    ssl_ReleaseXmitBufLock(ss);	/**************************************/
    return rv;
}

/* Called from ssl_FreeSocket() in sslsock.c */
void
ssl3_DestroySSL3Info(ssl3State *ssl3)
{
    if (ssl3 == NULL)
	return;		/* success the easy way. */

    if (ssl3->clientCertificate != NULL)
	NSSCert_Destroy(ssl3->clientCertificate);

    if (ssl3->clientPrivateKey != NULL)
	NSSPrivateKey_Destroy(ssl3->clientPrivateKey);

    if (ssl3->peerCertChain != NULL)
	ssl3_CleanupPeerCerts(ssl3);

    if (ssl3->clientCertChain != NULL) {
       NSSCertChain_Destroy(ssl3->clientCertChain);
       ssl3->clientCertChain = NULL;
    }

    /* clean up handshake */
    if (ssl3->hs.md5) {
	NSSCryptoContext_Destroy(ssl3->hs.md5);
    }
    if (ssl3->hs.sha) {
	NSSCryptoContext_Destroy(ssl3->hs.sha);
    }

#ifdef FORTEZZA
    if (ssl3->fortezza.tek != NULL) {
	PK11_FreeSymKey(ssl3->fortezza.tek);
    }
#endif /* FORTEZZA */
    /* free the SSL3Buffer (msg_body) */
    nss_ZFreeIf(ssl3->hs.msg_body.buf);

    /* free up the CipherSpecs */
    ssl3_DestroyCipherSpec(&ssl3->specs[0]);
    ssl3_DestroyCipherSpec(&ssl3->specs[1]);

    nss_ZFreeIf(ssl3);
}

/* End of ssl3con.c */
