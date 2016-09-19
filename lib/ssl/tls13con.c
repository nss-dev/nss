/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * TLS 1.3 Protocol
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
#include "stdarg.h"
#include "cert.h"
#include "ssl.h"
#include "keyhi.h"
#include "pk11func.h"
#include "secitem.h"
#include "secmod.h"
#include "sslimpl.h"
#include "sslproto.h"
#include "sslerr.h"
#include "tls13hkdf.h"
#include "tls13con.h"

typedef enum {
    TrafficKeyEarlyHandshake,
    TrafficKeyEarlyApplicationData,
    TrafficKeyHandshake,
    TrafficKeyApplicationData
} TrafficKeyType;

typedef enum {
    CipherSpecRead,
    CipherSpecWrite,
} CipherSpecDirection;

#define MAX_FINISHED_SIZE 64

static SECStatus tls13_SetCipherSpec(sslSocket *ss, TrafficKeyType type,
                                     CipherSpecDirection install,
                                     PRBool deleteSecret);
static SECStatus tls13_AESGCM(
    ssl3KeyMaterial *keys,
    PRBool doDecrypt,
    unsigned char *out, int *outlen, int maxout,
    const unsigned char *in, int inlen,
    const unsigned char *additionalData, int additionalDataLen);
static SECStatus tls13_ChaCha20Poly1305(
    ssl3KeyMaterial *keys,
    PRBool doDecrypt,
    unsigned char *out, int *outlen, int maxout,
    const unsigned char *in, int inlen,
    const unsigned char *additionalData, int additionalDataLen);
static SECStatus tls13_SendEncryptedExtensions(sslSocket *ss);
static SECStatus tls13_HandleEncryptedExtensions(sslSocket *ss, SSL3Opaque *b,
                                                 PRUint32 length);
static SECStatus tls13_HandleCertificate(
    sslSocket *ss, SSL3Opaque *b, PRUint32 length);
static SECStatus tls13_HandleCertificateRequest(sslSocket *ss, SSL3Opaque *b,
                                                PRUint32 length);
static SECStatus
tls13_SendCertificateVerify(sslSocket *ss, SECKEYPrivateKey *privKey);
static SECStatus tls13_HandleCertificateVerify(
    sslSocket *ss, SSL3Opaque *b, PRUint32 length,
    TLS13CombinedHash *hashes);
static SECStatus
tls13_DeriveSecret(sslSocket *ss, PK11SymKey *key, const char *label,
                   const TLS13CombinedHash *hashes,
                   PK11SymKey **dest);
static void tls13_SetNullCipherSpec(sslSocket *ss, ssl3CipherSpec **specp);
static SECStatus tls13_SendEndOfEarlyData(sslSocket *ss);
static SECStatus tls13_SendFinished(sslSocket *ss, PK11SymKey *baseKey);
static SECStatus tls13_VerifyFinished(sslSocket *ss, PK11SymKey *secret,
                                      SSL3Opaque *b, PRUint32 length,
                                      const TLS13CombinedHash *hashes);
static SECStatus tls13_ClientHandleFinished(sslSocket *ss,
                                            SSL3Opaque *b, PRUint32 length,
                                            const TLS13CombinedHash *hashes);
static SECStatus tls13_ServerHandleFinished(sslSocket *ss,
                                            SSL3Opaque *b, PRUint32 length,
                                            const TLS13CombinedHash *hashes);
static SECStatus tls13_SendNewSessionTicket(sslSocket *ss);
static SECStatus tls13_HandleNewSessionTicket(sslSocket *ss, SSL3Opaque *b,
                                              PRUint32 length);
static SECStatus tls13_HandleHelloRetryRequest(sslSocket *ss, SSL3Opaque *b,
                                               PRUint32 length);
static void
tls13_CombineHashes(sslSocket *ss, const PRUint8 *hhash, unsigned int hlen,
                    TLS13CombinedHash *hashes);
static SECStatus tls13_ComputeHandshakeHashes(sslSocket *ss,
                                              TLS13CombinedHash *hashes);
static SECStatus tls13_ComputeEarlySecrets(sslSocket *ss, PRBool setup0Rtt);
static SECStatus tls13_ComputeHandshakeSecrets(sslSocket *ss);
static SECStatus tls13_ComputeApplicationSecrets(sslSocket *ss);
static SECStatus tls13_ComputeFinalSecrets(sslSocket *ss);
static SECStatus tls13_ComputeFinished(
    sslSocket *ss, PK11SymKey *baseKey, const TLS13CombinedHash *hashes,
    PRBool sending, PRUint8 *output, unsigned int *outputLen,
    unsigned int maxOutputLen);
static SECStatus tls13_SendClientSecondRound(sslSocket *ss);
static SECStatus tls13_FinishHandshake(sslSocket *ss);

const char kHkdfLabelEarlyTrafficSecret[] = "early traffic secret";
const char kHkdfLabelHandshakeTrafficSecret[] = "handshake traffic secret";
const char kHkdfLabelApplicationTrafficSecret[] = "application traffic secret";
const char kHkdfLabelClientFinishedSecret[] = "client finished";
const char kHkdfLabelServerFinishedSecret[] = "server finished";
const char kHkdfLabelResumptionMasterSecret[] = "resumption master secret";
const char kHkdfLabelResumptionPsk[] = "resumption psk";
const char kHkdfLabelResumptionContext[] = "resumption context";
const char kHkdfLabelExporterMasterSecret[] = "exporter master secret";
const char kHkdfPhaseEarlyHandshakeDataKeys[] = "early handshake key expansion";
const char kHkdfPhaseEarlyApplicationDataKeys[] = "early application data key expansion";
const char kHkdfPhaseHandshakeKeys[] = "handshake key expansion";
const char kHkdfPhaseApplicationDataKeys[] = "application data key expansion";
const char kHkdfPurposeClientWriteKey[] = "client write key";
const char kHkdfPurposeServerWriteKey[] = "server write key";
const char kHkdfPurposeClientWriteIv[] = "client write iv";
const char kHkdfPurposeServerWriteIv[] = "server write iv";
const char kClientFinishedLabel[] = "client finished";
const char kServerFinishedLabel[] = "server finished";

const SSL3ProtocolVersion kTlsRecordVersion = SSL_LIBRARY_VERSION_TLS_1_0;
const SSL3ProtocolVersion kDtlsRecordVersion = SSL_LIBRARY_VERSION_TLS_1_1;

/* Belt and suspenders in case we ever add a TLS 1.4. */
PR_STATIC_ASSERT(SSL_LIBRARY_VERSION_MAX_SUPPORTED <=
                 SSL_LIBRARY_VERSION_TLS_1_3);

/* Use this instead of FATAL_ERROR when an alert isn't possible. */
#define LOG_ERROR(ss, prError)                                                     \
    do {                                                                           \
        SSL_TRC(3, ("%d: TLS13[%d]: fatal error %d in %s (%s:%d)",                 \
                    SSL_GETPID(), ss->fd, prError, __func__, __FILE__, __LINE__)); \
        PORT_SetError(prError);                                                    \
    } while (0)

/* Log an error and generate an alert because something is irreparably wrong. */
#define FATAL_ERROR(ss, prError, desc)       \
    do {                                     \
        LOG_ERROR(ss, prError);              \
        tls13_FatalError(ss, prError, desc); \
    } while (0)

void
tls13_FatalError(sslSocket *ss, PRErrorCode prError, SSL3AlertDescription desc)
{
    PORT_Assert(desc != internal_error); /* These should never happen */
    (void)SSL3_SendAlert(ss, alert_fatal, desc);
    PORT_SetError(prError);
}

#ifdef TRACE
#define STATE_CASE(a) \
    case a:           \
        return #a
static char *
tls13_HandshakeState(SSL3WaitState st)
{
    switch (st) {
        STATE_CASE(wait_client_hello);
        STATE_CASE(wait_client_cert);
        STATE_CASE(wait_cert_verify);
        STATE_CASE(wait_finished);
        STATE_CASE(wait_server_hello);
        STATE_CASE(wait_server_cert);
        STATE_CASE(wait_cert_request);
        STATE_CASE(wait_encrypted_extensions);
        STATE_CASE(wait_0rtt_finished);
        STATE_CASE(idle_handshake);
        default:
            break;
    }
    PORT_Assert(0);
    return "unknown";
}
#endif

#define TLS13_WAIT_STATE_MASK 0x80

#define TLS13_BASE_WAIT_STATE(ws) (ws & ~TLS13_WAIT_STATE_MASK)
/* We don't mask idle_handshake because other parts of the code use it*/
#define TLS13_WAIT_STATE(ws) (ws == idle_handshake ? ws : ws | TLS13_WAIT_STATE_MASK)
#define TLS13_CHECK_HS_STATE(ss, err, ...)                          \
    tls13_CheckHsState(ss, err, #err, __func__, __FILE__, __LINE__, \
                       __VA_ARGS__,                                 \
                       wait_invalid)
void
tls13_SetHsState(sslSocket *ss, SSL3WaitState ws,
                 const char *func, const char *file, int line)
{
#ifdef TRACE
    const char *new_state_name =
        tls13_HandshakeState(ws);

    SSL_TRC(3, ("%d: TLS13[%d]: %s state change from %s->%s in %s (%s:%d)",
                SSL_GETPID(), ss->fd,
                ss->sec.isServer ? "server" : "client",
                tls13_HandshakeState(TLS13_BASE_WAIT_STATE(ss->ssl3.hs.ws)),
                new_state_name,
                func, file, line));
#endif

    ss->ssl3.hs.ws = TLS13_WAIT_STATE(ws);
}

static PRBool
tls13_InHsStateV(sslSocket *ss, va_list ap)
{
    SSL3WaitState ws;

    while ((ws = va_arg(ap, SSL3WaitState)) != wait_invalid) {
        if (ws == TLS13_BASE_WAIT_STATE(ss->ssl3.hs.ws)) {
            return PR_TRUE;
        }
    }
    return PR_FALSE;
}

PRBool
tls13_InHsState(sslSocket *ss, ...)
{
    PRBool found;
    va_list ap;

    va_start(ap, ss);
    found = tls13_InHsStateV(ss, ap);
    va_end(ap);

    return found;
}

static SECStatus
tls13_CheckHsState(sslSocket *ss, int err, const char *error_name,
                   const char *func, const char *file, int line,
                   ...)
{
    va_list ap;
    va_start(ap, line);
    if (tls13_InHsStateV(ss, ap)) {
        va_end(ap);
        return SECSuccess;
    }
    va_end(ap);

    SSL_TRC(3, ("%d: TLS13[%d]: error %s state is (%s) at %s (%s:%d)",
                SSL_GETPID(), ss->fd,
                error_name,
                tls13_HandshakeState(TLS13_BASE_WAIT_STATE(ss->ssl3.hs.ws)),
                func, file, line));
    tls13_FatalError(ss, err, unexpected_message);
    return SECFailure;
}

SSLHashType
tls13_GetHash(sslSocket *ss)
{
    /* All TLS 1.3 cipher suites must have an explict PRF hash. */
    PORT_Assert(ss->ssl3.hs.suite_def->prf_hash != ssl_hash_none);
    return ss->ssl3.hs.suite_def->prf_hash;
}

static unsigned int
tls13_GetHashSizeForHash(SSLHashType hash)
{
    switch (hash) {
        case ssl_hash_sha256:
            return 32;
        case ssl_hash_sha384:
            return 48;
        default:
            PORT_Assert(0);
    }
    return 32;
}

unsigned int
tls13_GetHashSize(sslSocket *ss)
{
    return tls13_GetHashSizeForHash(tls13_GetHash(ss));
}

static CK_MECHANISM_TYPE
tls13_GetHkdfMechanismForHash(SSLHashType hash)
{
    switch (hash) {
        case ssl_hash_sha256:
            return CKM_NSS_HKDF_SHA256;
        case ssl_hash_sha384:
            return CKM_NSS_HKDF_SHA384;
        default:
            PORT_Assert(0);
    }
    return CKM_NSS_HKDF_SHA256;
}

CK_MECHANISM_TYPE
tls13_GetHkdfMechanism(sslSocket *ss)
{
    return tls13_GetHkdfMechanismForHash(tls13_GetHash(ss));
}

static CK_MECHANISM_TYPE
tls13_GetHmacMechanism(sslSocket *ss)
{
    switch (tls13_GetHash(ss)) {
        case ssl_hash_sha256:
            return CKM_SHA256_HMAC;
        case ssl_hash_sha384:
            return CKM_SHA384_HMAC;
        default:
            PORT_Assert(0);
    }
    return CKM_SHA256_HMAC;
}

SECStatus
tls13_CreateKeyShare(sslSocket *ss, const namedGroupDef *groupDef)
{
    SECStatus rv;
    sslEphemeralKeyPair *keyPair = NULL;
    const ssl3DHParams *params;

    switch (groupDef->type) {
        case group_type_ec:
            rv = ssl_CreateECDHEphemeralKeyPair(groupDef, &keyPair);
            if (rv != SECSuccess) {
                return SECFailure;
            }
            break;
        case group_type_ff:
            params = ssl_GetDHEParams(groupDef);
            PORT_Assert(params->name != ssl_grp_ffdhe_custom);
            rv = ssl_CreateDHEKeyPair(groupDef, params, &keyPair);
            if (rv != SECSuccess) {
                return SECFailure;
            }
            break;
    }

    PR_APPEND_LINK(&keyPair->link, &ss->ephemeralKeyPairs);
    return rv;
}

/*
 * Generate shares for ECDHE and FFDHE.  This picks the first enabled group of
 * the requisite type and creates a share for that.
 *
 * Called from ssl3_SendClientHello.
 */
SECStatus
tls13_SetupClientHello(sslSocket *ss)
{
    unsigned int i;
    PRBool ecNeeded = ssl_IsECCEnabled(ss);
    /* Only generate an FFDHE share when EC suites are disabled. */
    PRBool ffNeeded = !ecNeeded;

    PORT_Assert(ss->opt.noLocks || ssl_HaveSSL3HandshakeLock(ss));
    PORT_Assert(ss->opt.noLocks || ssl_HaveXmitBufLock(ss));

    PORT_Assert(PR_CLIST_IS_EMPTY(&ss->ephemeralKeyPairs));

    for (i = 0; i < SSL_NAMED_GROUP_COUNT; ++i) {
        SECStatus rv;
        const namedGroupDef *groupDef = ss->namedGroupPreferences[i];
        if (!groupDef) {
            continue;
        }

        if (!ssl_NamedGroupEnabled(ss, groupDef)) {
            continue;
        }
        switch (groupDef->type) {
            case group_type_ec:
                if (!ecNeeded) {
                    continue;
                }
                ecNeeded = PR_FALSE;
                break;
            case group_type_ff:
                if (!ffNeeded) {
                    continue;
                }
                ffNeeded = PR_FALSE;
                break;
        }

        rv = tls13_CreateKeyShare(ss, groupDef);
        if (rv != SECSuccess) {
            return SECFailure;
        }
    }

    PORT_Assert(!PR_CLIST_IS_EMPTY(&ss->ephemeralKeyPairs));
    /* We don't permit all groups of a given type to be disabled, so this should
     * never reach this point wanting for a share of either type. */
    PORT_Assert(!ecNeeded);
    PORT_Assert(!ffNeeded);

    return SECSuccess;
}

static SECStatus
tls13_ImportDHEKeyShare(sslSocket *ss, SECKEYPublicKey *peerKey,
                        SSL3Opaque *b, PRUint32 length,
                        SECKEYPublicKey *pubKey)
{
    SECStatus rv;
    SECItem publicValue = { siBuffer, NULL, 0 };

    publicValue.data = b;
    publicValue.len = length;
    if (!ssl_IsValidDHEShare(&pubKey->u.dh.prime, &publicValue)) {
        PORT_SetError(SSL_ERROR_RX_MALFORMED_DHE_KEY_SHARE);
        return SECFailure;
    }

    peerKey->keyType = dhKey;
    rv = SECITEM_CopyItem(peerKey->arena, &peerKey->u.dh.prime,
                          &pubKey->u.dh.prime);
    if (rv != SECSuccess)
        return SECFailure;
    rv = SECITEM_CopyItem(peerKey->arena, &peerKey->u.dh.base,
                          &pubKey->u.dh.base);
    if (rv != SECSuccess)
        return SECFailure;
    rv = SECITEM_CopyItem(peerKey->arena, &peerKey->u.dh.publicValue,
                          &publicValue);
    if (rv != SECSuccess)
        return SECFailure;

    return SECSuccess;
}

static SECStatus
tls13_HandleKeyShare(sslSocket *ss,
                     TLS13KeyShareEntry *entry,
                     sslKeyPair *keyPair)
{
    PORTCheapArenaPool arena;
    SECKEYPublicKey *peerKey;
    CK_MECHANISM_TYPE mechanism;
    PRErrorCode errorCode;
    SECStatus rv;

    PORT_InitCheapArena(&arena, DER_DEFAULT_CHUNKSIZE);
    peerKey = PORT_ArenaZNew(&arena.arena, SECKEYPublicKey);
    if (peerKey == NULL) {
        goto loser;
    }
    peerKey->arena = &arena.arena;
    peerKey->pkcs11Slot = NULL;
    peerKey->pkcs11ID = CK_INVALID_HANDLE;

    switch (entry->group->type) {
        case group_type_ec:
            rv = tls13_ImportECDHKeyShare(ss, peerKey,
                                          entry->key_exchange.data,
                                          entry->key_exchange.len,
                                          entry->group);
            mechanism = CKM_ECDH1_DERIVE;
            break;
        case group_type_ff:
            rv = tls13_ImportDHEKeyShare(ss, peerKey,
                                         entry->key_exchange.data,
                                         entry->key_exchange.len,
                                         keyPair->pubKey);
            mechanism = CKM_DH_PKCS_DERIVE;
            break;
        default:
            PORT_Assert(0);
            goto loser;
    }
    if (rv != SECSuccess) {
        goto loser;
    }

    ss->ssl3.hs.dheSecret = PK11_PubDeriveWithKDF(
        keyPair->privKey, peerKey, PR_FALSE, NULL, NULL, mechanism,
        tls13_GetHkdfMechanism(ss), CKA_DERIVE, 0, CKD_NULL, NULL, NULL);
    if (!ss->ssl3.hs.dheSecret) {
        ssl_MapLowLevelError(SSL_ERROR_KEY_EXCHANGE_FAILURE);
        goto loser;
    }
    PORT_DestroyCheapArena(&arena);
    return SECSuccess;

loser:
    PORT_DestroyCheapArena(&arena);
    errorCode = PORT_GetError(); /* don't overwrite the error code */
    tls13_FatalError(ss, errorCode, illegal_parameter);
    return SECFailure;
}

SECStatus
tls13_HandlePostHelloHandshakeMessage(sslSocket *ss, SSL3Opaque *b,
                                      PRUint32 length, SSL3Hashes *hashesPtr)
{
    TLS13CombinedHash hashes;

    if (ss->sec.isServer && ss->ssl3.hs.zeroRttIgnore != ssl_0rtt_ignore_none) {
        SSL_TRC(3, ("%d: TLS13[%d]: %s successfully decrypted handshake after"
                    "failed 0-RTT",
                    SSL_GETPID(), ss->fd));
        ss->ssl3.hs.zeroRttIgnore = ssl_0rtt_ignore_none;
    }

    /* TODO(ekr@rtfm.com): Would it be better to check all the states here? */
    switch (ss->ssl3.hs.msg_type) {
        case hello_retry_request:
            return tls13_HandleHelloRetryRequest(ss, b, length);

        case certificate:
            return tls13_HandleCertificate(ss, b, length);

        case certificate_request:
            return tls13_HandleCertificateRequest(ss, b, length);

        case certificate_verify:
            if (!hashesPtr) {
                FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
                return SECFailure;
            }
            tls13_CombineHashes(ss, hashesPtr->u.raw, hashesPtr->len,
                                &hashes);
            return tls13_HandleCertificateVerify(ss, b, length, &hashes);

        case encrypted_extensions:
            return tls13_HandleEncryptedExtensions(ss, b, length);

        case new_session_ticket:
            return tls13_HandleNewSessionTicket(ss, b, length);

        case finished:
            if (!hashesPtr) {
                FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
                return SECFailure;
            }
            tls13_CombineHashes(ss, hashesPtr->u.raw, hashesPtr->len,
                                &hashes);
            if (ss->sec.isServer) {
                return tls13_ServerHandleFinished(ss, b, length, &hashes);
            } else {
                return tls13_ClientHandleFinished(ss, b, length, &hashes);
            }

        default:
            FATAL_ERROR(ss, SSL_ERROR_RX_UNKNOWN_HANDSHAKE, unexpected_message);
            return SECFailure;
    }

    PORT_Assert(0); /* Unreached */
    return SECFailure;
}

static SECStatus
tls13_RecoverWrappedSharedSecret(sslSocket *ss, sslSessionID *sid)
{
    PK11SymKey *wrapKey; /* wrapping key */
    PK11SymKey *RMS = NULL;
    SECItem wrappedMS = { siBuffer, NULL, 0 };
    SSLHashType hashType;
    const ssl3CipherSuiteDef *cipherDef;
    SECStatus rv;

    SSL_TRC(3, ("%d: TLS13[%d]: recovering static secret (%s)",
                SSL_GETPID(), ss->fd,
                ss->sec.isServer ? "server" : "client"));
    if (!sid->u.ssl3.keys.msIsWrapped) {
        PORT_Assert(0); /* I think this can't happen. */
        return SECFailure;
    }

    /* Now find the hash used as the PRF for the previous handshake. */
    cipherDef = ssl_LookupCipherSuiteDef(sid->u.ssl3.cipherSuite);
    PORT_Assert(cipherDef);
    if (!cipherDef) {
        return SECFailure;
    }
    hashType = cipherDef->prf_hash;

    /* If we are the server, we compute the wrapping key, but if we
     * are the client, it's coordinates are stored with the ticket. */
    if (ss->sec.isServer) {
        const sslServerCert *serverCert;

        serverCert = ssl_FindServerCert(ss, &sid->certType);
        PORT_Assert(serverCert);
        wrapKey = ssl3_GetWrappingKey(ss, NULL, serverCert,
                                      sid->u.ssl3.masterWrapMech,
                                      ss->pkcs11PinArg);
    } else {
        PK11SlotInfo *slot = SECMOD_LookupSlot(sid->u.ssl3.masterModuleID,
                                               sid->u.ssl3.masterSlotID);
        if (!slot)
            return SECFailure;

        wrapKey = PK11_GetWrapKey(slot,
                                  sid->u.ssl3.masterWrapIndex,
                                  sid->u.ssl3.masterWrapMech,
                                  sid->u.ssl3.masterWrapSeries,
                                  ss->pkcs11PinArg);
        PK11_FreeSlot(slot);
    }
    if (!wrapKey) {
        return SECFailure;
    }

    wrappedMS.data = sid->u.ssl3.keys.wrapped_master_secret;
    wrappedMS.len = sid->u.ssl3.keys.wrapped_master_secret_len;

    /* unwrap the "master secret" which is actually RMS. */
    RMS = PK11_UnwrapSymKeyWithFlags(wrapKey, sid->u.ssl3.masterWrapMech,
                                     NULL, &wrappedMS,
                                     CKM_SSL3_MASTER_KEY_DERIVE,
                                     CKA_DERIVE,
                                     tls13_GetHashSizeForHash(hashType),
                                     CKF_SIGN | CKF_VERIFY);
    PK11_FreeSymKey(wrapKey);
    if (!RMS) {
        return SECFailure;
    }

    PRINT_KEY(50, (ss, "Recovered RMS", RMS));
    /* Now compute resumption_psk and resumption_context.
     *
     * resumption_psk = HKDF-Expand-Label(resumption_secret,
     *                                    "resumption psk", "", L)
     *
     * resumption_context = HKDF-Expand-Label(resumption_secret,
     *                                        "resumption context", "", L)
     */
    rv = tls13_HkdfExpandLabel(RMS, hashType, NULL, 0,
                               kHkdfLabelResumptionPsk,
                               strlen(kHkdfLabelResumptionPsk),
                               tls13_GetHkdfMechanismForHash(hashType),
                               tls13_GetHashSizeForHash(hashType),
                               &ss->ssl3.hs.resumptionPsk);
    if (rv != SECSuccess) {
        goto loser;
    }

    if (SECITEM_AllocItem(NULL, &ss->ssl3.hs.resumptionContext,
                          tls13_GetHashSizeForHash(hashType)) == NULL) {
        goto loser;
    }

    rv = tls13_HkdfExpandLabelRaw(RMS, hashType, NULL, 0,
                                  kHkdfLabelResumptionContext,
                                  strlen(kHkdfLabelResumptionContext),
                                  ss->ssl3.hs.resumptionContext.data,
                                  ss->ssl3.hs.resumptionContext.len);
    if (rv != SECSuccess) {
        goto loser;
    }

    PK11_FreeSymKey(RMS);
    return SECSuccess;

loser:
    if (RMS) {
        PK11_FreeSymKey(RMS);
    }
    return SECFailure;
}

/* Key Derivation Functions.
 *
 * Below is the key schedule from [draft-ietf-tls-tls13].
 *
 * The relevant functions from this file are indicated by tls13_Foo().
 *
 *                  0
 *                  |
 *                  v
 *    PSK ->  HKDF-Extract      tls13_ComputeEarlySecrets()
 *                  |
 *                  v
 *            Early Secret  --> Derive-Secret(., "early traffic secret",
 *                  |                         ClientHello)
 *                  |                         = early_traffic_secret
 *                  v
 * (EC)DHE -> HKDF-Extract      tls13_ComputeHandshakeSecrets()
 *                  |
 *                  v
 *               Handshake
 *                Secret -----> Derive-Secret(., "handshake traffic secret",
 *                  |                         ClientHello + ServerHello)
 *                  |                         = handshake_traffic_secret
 *                  v
 *       0 -> HKDF-Extract      tls13_ComputeApplicationSecret
 *                  |
 *                  v
 *             Master Secret
 *                  |
 *                  +---------> Derive-Secret(., "application traffic secret",
 *                  |                         ClientHello...Server Finished)
 *                  |                         = traffic_secret_0
 *                  |
 *                  |
 *                  |           tls13_ComputeFinalSecrets()
 *                  |
 *                  +---------> Derive-Secret(., "exporter master secret",
 *                  |                         ClientHello...Client Finished)
 *                  |                         = exporter_secret
 *                  |
 *                  +---------> Derive-Secret(., "resumption master secret",
 *                                            ClientHello...Client Finished)
 *                                            = resumption_secret
 */

static SECStatus
tls13_ComputeEarlySecrets(sslSocket *ss, PRBool setup0Rtt)
{
    SECStatus rv = SECSuccess;
    PK11Context *ctx;
    PRUint8 hash[HASH_LENGTH_MAX];
    unsigned int len;

    /* Extract off the resumptionPsk (if present), else pass the NULL
     * resumptionPsk which will be internally translated to zeroes. */
    PORT_Assert(!ss->ssl3.hs.currentSecret);
    rv = tls13_HkdfExtract(NULL, ss->ssl3.hs.resumptionPsk,
                           tls13_GetHash(ss), &ss->ssl3.hs.currentSecret);
    if (rv != SECSuccess) {
        return SECFailure;
    }
    if (ss->ssl3.hs.resumptionPsk) {
        PK11_FreeSymKey(ss->ssl3.hs.resumptionPsk);
        ss->ssl3.hs.resumptionPsk = NULL;
    }

    if (!ss->ssl3.hs.resumptionContext.data) {
        PORT_Assert(!setup0Rtt);
        /* If no resumption context, fill with zeroes. */
        if (SECITEM_AllocItem(NULL, &ss->ssl3.hs.resumptionContext,
                              tls13_GetHashSize(ss)) == NULL) {
            return SECFailure;
        }
        PORT_Memset(ss->ssl3.hs.resumptionContext.data, 0,
                    ss->ssl3.hs.resumptionContext.len);
    }

    PRINT_BUF(50, (ss, "Resumption context",
                   ss->ssl3.hs.resumptionContext.data,
                   ss->ssl3.hs.resumptionContext.len));

    /* Now compute the Hash of the resumptionContext so we can cache
     * that. */
    ctx = PK11_CreateDigestContext(ssl3_HashTypeToOID(tls13_GetHash(ss)));
    if (!ctx) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return SECFailure;
    }
    rv |= PK11_DigestBegin(ctx);
    rv |= PK11_DigestOp(ctx,
                        ss->ssl3.hs.resumptionContext.data,
                        ss->ssl3.hs.resumptionContext.len);
    rv |= PK11_DigestFinal(ctx, hash, &len, sizeof(hash));
    PK11_DestroyContext(ctx, PR_TRUE);
    if (rv != SECSuccess)
        return SECFailure;
    PORT_Assert(len == tls13_GetHashSize(ss));
    PRINT_BUF(50, (ss, "Hash of resumption context", hash, len));

    /* Stuff it back into the resumptionContext. */
    SECITEM_FreeItem(&ss->ssl3.hs.resumptionContext, PR_FALSE);
    if (SECITEM_AllocItem(NULL, &ss->ssl3.hs.resumptionContext,
                          tls13_GetHashSize(ss)) == NULL) {
        return SECFailure;
    }
    PORT_Memcpy(ss->ssl3.hs.resumptionContext.data, hash, len);

    if (setup0Rtt) {
        /* Derive the early secret. */
        rv = tls13_DeriveSecret(ss, ss->ssl3.hs.currentSecret,
                                kHkdfLabelEarlyTrafficSecret,
                                NULL,
                                &ss->ssl3.hs.earlyTrafficSecret);
        if (rv != SECSuccess)
            return SECFailure;
    }

    return SECSuccess;
}

static SECStatus
tls13_ComputeHandshakeSecrets(sslSocket *ss)
{
    SECStatus rv;
    PK11SymKey *newSecret = NULL;

    /* First update |currentSecret| to add |dheSecret|, if any. */
    PORT_Assert(ss->ssl3.hs.currentSecret);
    PORT_Assert(ss->ssl3.hs.dheSecret);
    rv = tls13_HkdfExtract(ss->ssl3.hs.currentSecret, ss->ssl3.hs.dheSecret,
                           tls13_GetHash(ss), &newSecret);
    if (rv != SECSuccess) {
        LOG_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE);
        return rv;
    }
    PK11_FreeSymKey(ss->ssl3.hs.dheSecret);
    ss->ssl3.hs.dheSecret = NULL;
    PK11_FreeSymKey(ss->ssl3.hs.currentSecret);
    ss->ssl3.hs.currentSecret = newSecret;

    /* Now compute |hsTrafficSecret| */
    rv = tls13_DeriveSecret(ss, ss->ssl3.hs.currentSecret,
                            kHkdfLabelHandshakeTrafficSecret, NULL,
                            &ss->ssl3.hs.hsTrafficSecret);
    if (rv != SECSuccess) {
        LOG_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE);
        return rv;
    }

    /* Crank HKDF forward to make master secret, which we
     * stuff in current secret. */
    rv = tls13_HkdfExtract(ss->ssl3.hs.currentSecret,
                           NULL,
                           tls13_GetHash(ss),
                           &newSecret);

    if (rv != SECSuccess) {
        LOG_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE);
        return SECFailure;
    }
    PK11_FreeSymKey(ss->ssl3.hs.currentSecret);
    ss->ssl3.hs.currentSecret = newSecret;

    return SECSuccess;
}

static SECStatus
tls13_ComputeApplicationSecrets(sslSocket *ss)
{
    SECStatus rv;

    rv = tls13_DeriveSecret(ss, ss->ssl3.hs.currentSecret,
                            kHkdfLabelApplicationTrafficSecret,
                            NULL,
                            &ss->ssl3.hs.trafficSecret);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    return SECSuccess;
}

static SECStatus
tls13_ComputeFinalSecrets(sslSocket *ss)
{
    SECStatus rv;
    PK11SymKey *resumptionMasterSecret = NULL;

    PORT_Assert(!ss->ssl3.crSpec->master_secret);
    PORT_Assert(!ss->ssl3.cwSpec->master_secret);

    rv = tls13_DeriveSecret(ss, ss->ssl3.hs.currentSecret,
                            kHkdfLabelResumptionMasterSecret,
                            NULL, &resumptionMasterSecret);
    PK11_FreeSymKey(ss->ssl3.hs.currentSecret);
    ss->ssl3.hs.currentSecret = NULL;
    if (rv != SECSuccess) {
        return SECFailure;
    }

    /* This is pretty gross. TLS 1.3 uses a number of master secrets:
     * The master secret to generate the keys and then the resumption
     * master secret for future connections. To make this work without
     * refactoring too much of the SSLv3 code, we store the RMS in
     * |crSpec->master_secret| and |cwSpec->master_secret|.
     */
    ss->ssl3.crSpec->master_secret = resumptionMasterSecret;
    ss->ssl3.cwSpec->master_secret =
        PK11_ReferenceSymKey(ss->ssl3.crSpec->master_secret);

    return SECSuccess;
}

static void
tls13_RestoreCipherInfo(sslSocket *ss, sslSessionID *sid)
{
    /* Set these to match the cached value.
     * TODO(ekr@rtfm.com): Make a version with the "true" values.
     * Bug 1256137.
     */
    ss->sec.authType = sid->authType;
    ss->sec.authKeyBits = sid->authKeyBits;
    ss->sec.keaType = sid->keaType;
    ss->sec.keaKeyBits = sid->keaKeyBits;
    ss->ssl3.hs.origCipherSuite = sid->u.ssl3.cipherSuite;
}

PRBool
tls13_AllowPskCipher(const sslSocket *ss, const ssl3CipherSuiteDef *cipher_def)
{
    if (ss->sec.isServer) {
        if (!ss->statelessResume)
            return PR_FALSE;
    } else {
        sslSessionID *sid = ss->sec.ci.sid;
        const ssl3CipherSuiteDef *cached_cipher_def;

        /* Verify that this was cached. */
        PORT_Assert(sid);
        if (sid->cached == never_cached)
            return PR_FALSE;

        cached_cipher_def = ssl_LookupCipherSuiteDef(
            sid->u.ssl3.cipherSuite);
        PORT_Assert(cached_cipher_def);

        /* Only offer a PSK cipher with the same symmetric parameters
         * as we negotiated before. */
        if (cached_cipher_def->bulk_cipher_alg !=
            cipher_def->bulk_cipher_alg)
            return PR_FALSE;

        /* PSK cipher must have the same PSK hash as was negotiated before. */
        if (cipher_def->prf_hash != cached_cipher_def->prf_hash) {
            return PR_FALSE;
        }
    }
    SSL_TRC(3, ("%d: TLS 1.3[%d]: Enabling cipher suite suite 0x%04x",
                SSL_GETPID(), ss->fd,
                cipher_def->cipher_suite));

    return PR_TRUE;
}

/* Check whether resumption-PSK is allowed. */
static PRBool
tls13_CanResume(sslSocket *ss, const sslSessionID *sid)
{
    const sslServerCert *sc;

    if (!sid) {
        return PR_FALSE;
    }

    if (sid->version != ss->version) {
        return PR_FALSE;
    }

    /* Server sids don't remember the server cert we previously sent, but they
     * do remember the type of certificate we originally used, so we can locate
     * it again, provided that the current ssl socket has had its server certs
     * configured the same as the previous one. */
    sc = ssl_FindServerCert(ss, &sid->certType);
    if (!sc || !sc->serverCert) {
        return PR_FALSE;
    }

    return PR_TRUE;
}

static PRBool
tls13_AlpnTagAllowed(sslSocket *ss, const SECItem *tag)
{
    const unsigned char *data = ss->opt.nextProtoNego.data;
    unsigned int length = ss->opt.nextProtoNego.len;
    unsigned int offset = 0;

    if (!tag->len)
        return PR_TRUE;

    while (offset < length) {
        unsigned int taglen = (unsigned int)data[offset];
        if ((taglen == tag->len) &&
            !PORT_Memcmp(data + offset + 1, tag->data, tag->len))
            return PR_TRUE;
        offset += 1 + taglen;
    }

    return PR_FALSE;
}

/* Called from tls13_HandleClientHelloPart2 to update the state of 0-RTT handling.
 *
 * 0-RTT is only permitted if:
 * 1. The early data extension was present.
 * 2. We are resuming a session.
 * 3. The 0-RTT option is set.
 * 4. The ticket allowed 0-RTT.
 * 5. We negotiated the same ALPN value as in the ticket.
 */
static void
tls13_NegotiateZeroRtt(sslSocket *ss, const sslSessionID *sid)
{
    SSL_TRC(3, ("%d: TLS13[%d]: negotiate 0-RTT %p",
                SSL_GETPID(), ss->fd, sid));

    /* tls13_ServerHandleEarlyDataXtn sets this to ssl_0rtt_sent, so this will
     * be ssl_0rtt_none unless early_data is present. */
    if (ss->ssl3.hs.zeroRttState == ssl_0rtt_none) {
        return;
    }

    /* If we rejected 0-RTT on the first ClientHello, then we can just say that
     * there is no 0-RTT for the second.  We shouldn't get any more.  Reset the
     * ignore state so that we treat decryption failure normally. */
    if (ss->ssl3.hs.zeroRttIgnore == ssl_0rtt_ignore_hrr) {
        PORT_Assert(ss->ssl3.hs.helloRetry);
        ss->ssl3.hs.zeroRttState = ssl_0rtt_none;
        ss->ssl3.hs.zeroRttIgnore = ssl_0rtt_ignore_none;
        return;
    }

    PORT_Assert(ss->ssl3.hs.zeroRttState == ssl_0rtt_sent);
    if (sid && ss->opt.enable0RttData &&
        (sid->u.ssl3.locked.sessionTicket.flags & ticket_allow_early_data) != 0 &&
        SECITEM_CompareItem(&ss->ssl3.nextProto, &sid->u.ssl3.alpnSelection) == 0) {
        SSL_TRC(3, ("%d: TLS13[%d]: enable 0-RTT",
                    SSL_GETPID(), ss->fd));
        PORT_Assert(ss->statelessResume);
        ss->ssl3.hs.zeroRttState = ssl_0rtt_accepted;
        ss->ssl3.hs.zeroRttIgnore = ssl_0rtt_ignore_none;
    } else {
        SSL_TRC(3, ("%d: TLS13[%d]: ignore 0-RTT",
                    SSL_GETPID(), ss->fd));
        ss->ssl3.hs.zeroRttState = ssl_0rtt_ignored;
        ss->ssl3.hs.zeroRttIgnore = ssl_0rtt_ignore_trial;
    }
}

/* Called from ssl3_HandleClientHello after we have parsed the
 * ClientHello and are sure that we are going to do TLS 1.3
 * or fail. */
SECStatus
tls13_HandleClientHelloPart2(sslSocket *ss,
                             const SECItem *suites,
                             sslSessionID *sid)
{
    SECStatus rv;
    SSL3Statistics *ssl3stats = SSL_GetStatistics();
    int j;
    PRBool shouldRetry = PR_FALSE;
    ssl3CipherSuite previousCipherSuite;

    if (!tls13_CanResume(ss, sid)) {
        ss->statelessResume = PR_FALSE;
    }

#ifndef PARANOID
    /* Look for a matching cipher suite. */
    j = ssl3_config_match_init(ss);
    if (j <= 0) { /* no ciphers are working/supported by PK11 */
        FATAL_ERROR(ss, PORT_GetError(), internal_error);
        goto loser;
    }
#endif

    /* Don't init hashes if this is the second ClientHello */
    previousCipherSuite = ss->ssl3.hs.cipher_suite;
    rv = ssl3_NegotiateCipherSuite(ss, suites, !ss->ssl3.hs.helloRetry);
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, SSL_ERROR_NO_CYPHER_OVERLAP, handshake_failure);
        goto loser;
    }
    /* If we are going around again, then we should make sure that the cipher
     * suite selection doesn't change. That's a sign of client shennanigans. */
    if (ss->ssl3.hs.helloRetry &&
        ss->ssl3.hs.cipher_suite != previousCipherSuite) {
        FATAL_ERROR(ss, SSL_ERROR_RX_MALFORMED_CLIENT_HELLO, handshake_failure);
        goto loser;
    }
    if (ss->ssl3.hs.kea_def->authKeyType != ssl_auth_psk) {
        ss->statelessResume = PR_FALSE;
    }

    if (ss->statelessResume) {
        PORT_Assert(sid);

        rv = tls13_RecoverWrappedSharedSecret(ss, sid);
        if (rv != SECSuccess) {
            FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
            goto loser;
        }

        tls13_RestoreCipherInfo(ss, sid);

        ss->sec.serverCert = ssl_FindServerCert(ss, &sid->certType);
        PORT_Assert(ss->sec.serverCert);
        ss->sec.localCert = CERT_DupCertificate(ss->sec.serverCert->serverCert);
        if (sid->peerCert != NULL) {
            ss->sec.peerCert = CERT_DupCertificate(sid->peerCert);
        }
        ssl3_RegisterServerHelloExtensionSender(
            ss, ssl_tls13_pre_shared_key_xtn, tls13_ServerSendPreSharedKeyXtn);

        tls13_NegotiateZeroRtt(ss, sid);
    } else {
        ss->ssl3.hs.origCipherSuite = ss->ssl3.hs.cipher_suite;

        tls13_NegotiateZeroRtt(ss, NULL);
    }

    rv = ssl3_ServerCallSNICallback(ss);
    if (rv != SECSuccess) {
        goto loser; /* An alert has already been sent. */
    }

    if (ss->statelessResume) {
        /* Check that the negotiated SID and the cached SID match. */
        if (SECITEM_CompareItem(&sid->u.ssl3.srvName,
                                &ss->ssl3.hs.srvVirtName) != SECEqual) {
            FATAL_ERROR(ss, SSL_ERROR_RX_MALFORMED_CLIENT_HELLO,
                        handshake_failure);
            goto loser;
        }
    } else {
        if (ss->ssl3.hs.numClientSigScheme == 0) {
            /* TODO test what happens when we strip signature_algorithms...
                    this might not be needed */
            PORT_SetError(SSL_ERROR_RX_MALFORMED_CLIENT_HELLO);
            FATAL_ERROR(ss, PORT_GetError(), missing_extension);
            return SECFailure;
        }

        rv = ssl3_SelectServerCert(ss);
        if (rv != SECSuccess) {
            FATAL_ERROR(ss, PORT_GetError(), handshake_failure);
            goto loser;
        }
    }

    /* If this is TLS 1.3 we are expecting a ClientKeyShare
     * extension. Missing/absent extension cause failure
     * below. */
    rv = tls13_HandleClientKeyShare(ss, &shouldRetry);
    if (rv != SECSuccess) {
        goto loser; /* An alert was sent already. */
    }
    if (shouldRetry) {
        /* Unfortunately, there's a bit of cleanup needed here to back out
         * changes from the stateless resumption setup. */
        if (ss->statelessResume) {
            PK11_FreeSymKey(ss->ssl3.hs.resumptionPsk);
            SECITEM_FreeItem(&ss->ssl3.hs.resumptionContext, PR_FALSE);
            CERT_DestroyCertificate(ss->sec.localCert);
            if (ss->sec.peerCert) {
                CERT_DestroyCertificate(ss->sec.peerCert);
            }
        }

        if (sid) { /* Free the sid. */
            if (ss->sec.uncache)
                ss->sec.uncache(sid);
            ssl_FreeSID(sid);
        }
        PORT_Assert(ss->ssl3.hs.helloRetry);
        return SECSuccess;
    }

    /* From this point we are either committed to resumption, or not. */
    if (ss->statelessResume) {
        SSL_AtomicIncrementLong(&ssl3stats->hch_sid_cache_hits);
        SSL_AtomicIncrementLong(&ssl3stats->hch_sid_stateless_resumes);
    } else {
        if (sid) {
            /* We had a sid, but it's no longer valid, free it. */
            SSL_AtomicIncrementLong(&ssl3stats->hch_sid_cache_not_ok);
            if (ss->sec.uncache)
                ss->sec.uncache(sid);
            ssl_FreeSID(sid);
        } else {
            SSL_AtomicIncrementLong(&ssl3stats->hch_sid_cache_misses);
        }

        sid = ssl3_NewSessionID(ss, PR_TRUE);
        if (!sid) {
            FATAL_ERROR(ss, PORT_GetError(), internal_error);
            return SECFailure;
        }
    }
    /* Take ownership of the session. */
    ss->sec.ci.sid = sid;
    sid = NULL;

    if (ss->ssl3.hs.zeroRttState == ssl_0rtt_accepted) {
        /* Store the handshake hash. We'll want it later. */
        ss->ssl3.hs.clientHelloHash = PK11_CloneContext(ss->ssl3.hs.sha);
        if (!ss->ssl3.hs.clientHelloHash) {
            FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
            return SECFailure;
        }

        rv = tls13_SetCipherSpec(ss, TrafficKeyEarlyHandshake,
                                 CipherSpecRead, PR_FALSE);
        if (rv != SECSuccess) {
            FATAL_ERROR(ss, PORT_GetError(), handshake_failure);
            return SECFailure;
        }
        TLS13_SET_HS_STATE(ss, wait_0rtt_finished);
    } else {
        PORT_Assert(ss->ssl3.hs.zeroRttState == ssl_0rtt_none ||
                    ss->ssl3.hs.zeroRttState == ssl_0rtt_ignored);
        ssl_GetXmitBufLock(ss);

        rv = tls13_SendServerHelloSequence(ss);
        ssl_ReleaseXmitBufLock(ss);
        if (rv != SECSuccess) {
            FATAL_ERROR(ss, PORT_GetError(), handshake_failure);
            return SECFailure;
        }
    }

    return SECSuccess;

loser:
    if (sid) {
        if (ss->sec.uncache)
            ss->sec.uncache(sid);
        ssl_FreeSID(sid);
    }
    return SECFailure;
}

static SECStatus
tls13_SendHelloRetryRequest(sslSocket *ss, const namedGroupDef *selectedGroup)
{
    SECStatus rv;

    SSL_TRC(3, ("%d: TLS13[%d]: send hello retry request handshake",
                SSL_GETPID(), ss->fd));

    PORT_Assert(ss->opt.noLocks || ssl_HaveSSL3HandshakeLock(ss));

    /* We asked already, but made no progress. */
    if (ss->ssl3.hs.helloRetry) {
        FATAL_ERROR(ss, SSL_ERROR_BAD_2ND_CLIENT_HELLO, illegal_parameter);
        return SECFailure;
    }

    ssl_GetXmitBufLock(ss);
    rv = ssl3_AppendHandshakeHeader(ss, hello_retry_request,
                                    2 +     /* version */
                                        2 + /* cipher suite */
                                        2 + /* group */
                                        2 /* (empty) extensions */);
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
        goto loser;
    }

    rv = ssl3_AppendHandshakeNumber(ss, ss->version, 2);
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
        goto loser;
    }

    rv = ssl3_AppendHandshakeNumber(ss, ss->ssl3.hs.cipher_suite, 2);
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
        goto loser;
    }

    rv = ssl3_AppendHandshakeNumber(ss, selectedGroup->name, 2);
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
        goto loser;
    }

    /* Send an empty extensions block. */
    rv = ssl3_AppendHandshakeNumber(ss, 0, 2);
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
        goto loser;
    }

    rv = ssl3_FlushHandshake(ss, 0);
    if (rv != SECSuccess) {
        goto loser; /* error code set by ssl3_FlushHandshake */
    }
    ssl_ReleaseXmitBufLock(ss);

    ss->ssl3.hs.helloRetry = PR_TRUE;

    /* We previously thought that we could accept 0-RTT.  Change of plans. */
    if (ss->ssl3.hs.zeroRttState == ssl_0rtt_accepted) {
        ss->ssl3.hs.zeroRttState = ssl_0rtt_ignored;
        ss->ssl3.hs.zeroRttIgnore = ssl_0rtt_ignore_hrr;
    }
    /* Clients will have sent Finished for 0-RTT.  We won't be seeing them, so
     * we won't count them, but they will. */
    if (IS_DTLS(ss) && ss->ssl3.hs.zeroRttState == ssl_0rtt_ignored) {
        ss->ssl3.hs.recvMessageSeq++;
    }

    return SECSuccess;

loser:
    ssl_ReleaseXmitBufLock(ss);
    return SECFailure;
}

/* Called from tls13_HandleClientHello.
 *
 * Caller must hold Handshake and RecvBuf locks.
 */
SECStatus
tls13_HandleClientKeyShare(sslSocket *ss, PRBool *shouldRetry)
{
    const namedGroupDef *selectedGroup;
    SECStatus rv;
    TLS13KeyShareEntry *peerShare = NULL; /* theirs */
    sslEphemeralKeyPair *keyPair;         /* ours */
    PRCList *cur_p;

    SSL_TRC(3, ("%d: TLS13[%d]: handle client_key_share handshake",
                SSL_GETPID(), ss->fd));

    PORT_Assert(ss->opt.noLocks || ssl_HaveRecvBufLock(ss));
    PORT_Assert(ss->opt.noLocks || ssl_HaveSSL3HandshakeLock(ss));

    /* Verify that the other side sent supported groups as required
     * by the specification. */
    if (!ssl3_ExtensionNegotiated(ss, ssl_supported_groups_xtn)) {
        FATAL_ERROR(ss, SSL_ERROR_MISSING_SUPPORTED_GROUPS_EXTENSION,
                    missing_extension);
        return SECFailure;
    }

    /* Figure out what group we expect */
    switch (ss->ssl3.hs.kea_def->exchKeyType) {
        case ssl_kea_ecdh:
        case ssl_kea_ecdh_psk:
            selectedGroup = ssl_GetECGroupForServerSocket(ss);
            if (!selectedGroup) {
                FATAL_ERROR(ss, SSL_ERROR_NO_CYPHER_OVERLAP,
                            handshake_failure);
                return SECFailure;
            }
            break;

        case ssl_kea_dh:
        case ssl_kea_dh_psk:
            rv = ssl_SelectDHEGroup(ss, &selectedGroup);
            if (rv != SECSuccess) {
                FATAL_ERROR(ss, SSL_ERROR_NO_CYPHER_OVERLAP,
                            handshake_failure);
                return SECFailure;
            }
            PORT_Assert(selectedGroup);
            break;

        default:
            /* Got an unknown or unsupported Key Exchange Algorithm.
             * Can't happen. */
            FATAL_ERROR(ss, SEC_ERROR_UNSUPPORTED_KEYALG,
                        internal_error);
            return SECFailure;
    }

    /* Now walk through the keys until we find one for our group */
    cur_p = PR_NEXT_LINK(&ss->ssl3.hs.remoteKeyShares);
    while (cur_p != &ss->ssl3.hs.remoteKeyShares) {
        TLS13KeyShareEntry *offer = (TLS13KeyShareEntry *)cur_p;

        if (offer->group == selectedGroup) {
            peerShare = offer;
            break;
        }
        cur_p = PR_NEXT_LINK(cur_p);
    }

    if (!peerShare) {
        *shouldRetry = PR_TRUE;
        return tls13_SendHelloRetryRequest(ss, selectedGroup);
    }

    PORT_Assert(ss->ssl3.hs.zeroRttState != ssl_0rtt_sent);
    rv = tls13_ComputeEarlySecrets(ss, ss->ssl3.hs.zeroRttState == ssl_0rtt_accepted);
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
        return SECFailure;
    }

    /* Generate our key */
    rv = tls13_CreateKeyShare(ss, selectedGroup);
    if (rv != SECSuccess)
        return rv;

    /* We should have exactly one key share. */
    PORT_Assert(!PR_CLIST_IS_EMPTY(&ss->ephemeralKeyPairs));
    PORT_Assert(PR_PREV_LINK(&ss->ephemeralKeyPairs) ==
                PR_NEXT_LINK(&ss->ephemeralKeyPairs));

    keyPair = ((sslEphemeralKeyPair *)PR_NEXT_LINK(&ss->ephemeralKeyPairs));

    ss->sec.keaType = ss->ssl3.hs.kea_def->exchKeyType;
    ss->sec.keaKeyBits = SECKEY_PublicKeyStrengthInBits(keyPair->keys->pubKey);

    /* Register the sender */
    rv = ssl3_RegisterServerHelloExtensionSender(ss, ssl_tls13_key_share_xtn,
                                                 tls13_ServerSendKeyShareXtn);
    if (rv != SECSuccess) {
        return SECFailure; /* Error code set already. */
    }

    rv = tls13_HandleKeyShare(ss, peerShare, keyPair->keys);
    return rv; /* Error code set already. */
}

/*
 *     [draft-ietf-tls-tls13-11] Section 6.3.3.2
 *
 *     opaque DistinguishedName<1..2^16-1>;
 *
 *     struct {
 *         opaque certificate_extension_oid<1..2^8-1>;
 *         opaque certificate_extension_values<0..2^16-1>;
 *     } CertificateExtension;
 *
 *     struct {
 *         opaque certificate_request_context<0..2^8-1>;
 *         SignatureAndHashAlgorithm
 *           supported_signature_algorithms<2..2^16-2>;
 *         DistinguishedName certificate_authorities<0..2^16-1>;
 *         CertificateExtension certificate_extensions<0..2^16-1>;
 *     } CertificateRequest;
 */
static SECStatus
tls13_SendCertificateRequest(sslSocket *ss)
{
    SECStatus rv;
    int calen;
    SECItem *names;
    int nnames;
    SECItem *name;
    int i;
    PRUint8 sigSchemes[MAX_SIGNATURE_SCHEMES * 2];
    unsigned int sigSchemesLength = 0;
    int length;

    SSL_TRC(3, ("%d: TLS13[%d]: begin send certificate_request",
                SSL_GETPID(), ss->fd));

    rv = ssl3_EncodeSigAlgs(ss, sigSchemes, sizeof(sigSchemes),
                            &sigSchemesLength);
    if (rv != SECSuccess) {
        return rv;
    }

    ssl3_GetCertificateRequestCAs(ss, &calen, &names, &nnames);
    length = 1 + 0 /* length byte for empty request context */ +
             2 + sigSchemesLength + 2 + calen + 2;

    rv = ssl3_AppendHandshakeHeader(ss, certificate_request, length);
    if (rv != SECSuccess) {
        return rv; /* err set by AppendHandshake. */
    }
    rv = ssl3_AppendHandshakeNumber(ss, 0, 1);
    if (rv != SECSuccess) {
        return rv; /* err set by AppendHandshake. */
    }
    rv = ssl3_AppendHandshakeVariable(ss, sigSchemes, sigSchemesLength, 2);
    if (rv != SECSuccess) {
        return rv; /* err set by AppendHandshake. */
    }
    rv = ssl3_AppendHandshakeNumber(ss, calen, 2);
    if (rv != SECSuccess) {
        return rv; /* err set by AppendHandshake. */
    }
    for (i = 0, name = names; i < nnames; i++, name++) {
        rv = ssl3_AppendHandshakeVariable(ss, name->data, name->len, 2);
        if (rv != SECSuccess) {
            return rv; /* err set by AppendHandshake. */
        }
    }
    rv = ssl3_AppendHandshakeNumber(ss, 0, 2);
    if (rv != SECSuccess) {
        return rv; /* err set by AppendHandshake. */
    }

    return SECSuccess;
}

static SECStatus
tls13_HandleHelloRetryRequest(sslSocket *ss, SSL3Opaque *b, PRUint32 length)
{
    SECStatus rv;
    PRInt32 tmp;
    const namedGroupDef *group;

    SSL_TRC(3, ("%d: TLS13[%d]: handle hello retry request",
                SSL_GETPID(), ss->fd));

    PORT_Assert(ss->opt.noLocks || ssl_HaveRecvBufLock(ss));
    PORT_Assert(ss->opt.noLocks || ssl_HaveSSL3HandshakeLock(ss));

    /* Client */
    rv = TLS13_CHECK_HS_STATE(ss, SSL_ERROR_RX_UNEXPECTED_HELLO_RETRY_REQUEST,
                              wait_server_hello);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    /* Fool me once, shame on you; fool me twice... */
    if (ss->ssl3.hs.helloRetry) {
        FATAL_ERROR(ss, SSL_ERROR_RX_UNEXPECTED_HELLO_RETRY_REQUEST,
                    unexpected_message);
        return SECFailure;
    }

    if (ss->ssl3.hs.zeroRttState == ssl_0rtt_sent) {
        /* Oh well, back to the start. */
        tls13_SetNullCipherSpec(ss, &ss->ssl3.cwSpec);
        ss->ssl3.hs.zeroRttState = ssl_0rtt_ignored;
    } else {
        PORT_Assert(ss->ssl3.hs.zeroRttState == ssl_0rtt_none);
    }

    tmp = ssl3_ConsumeHandshakeNumber(ss, 2, &b, &length);
    if (tmp < 0) {
        return SECFailure; /* error code already set */
    }
    if (tmp > ss->vrange.max || tmp < SSL_LIBRARY_VERSION_TLS_1_3) {
        FATAL_ERROR(ss, SSL_ERROR_RX_MALFORMED_HELLO_RETRY_REQUEST,
                    protocol_version);
        return SECFailure;
    }

    /* Ignore the cipher suite, it's going to be removed soon anyway. */
    tmp = ssl3_ConsumeHandshakeNumber(ss, 2, &b, &length);
    if (tmp < 0) {
        return SECFailure; /* error code already set */
    }

    tmp = ssl3_ConsumeHandshakeNumber(ss, 2, &b, &length);
    if (tmp < 0) {
        return SECFailure; /* error code already set */
    }
    group = ssl_LookupNamedGroup((SSLNamedGroup)tmp);
    if (!group || !ssl_NamedGroupEnabled(ss, group)) {
        FATAL_ERROR(ss, SSL_ERROR_RX_MALFORMED_HELLO_RETRY_REQUEST,
                    illegal_parameter);
        return SECFailure;
    }

    tmp = ssl3_ConsumeHandshakeNumber(ss, 2, &b, &length);
    if (tmp < 0) {
        return SECFailure; /* error code already set */
    }
    /* Ignore the extensions. */
    if (tmp != length) {
        FATAL_ERROR(ss, SSL_ERROR_RX_MALFORMED_HELLO_RETRY_REQUEST,
                    decode_error);
        return SECFailure;
    }

    /* If there is already a share for the requested group, abort. */
    if (ssl_LookupEphemeralKeyPair(ss, group)) {
        FATAL_ERROR(ss, SSL_ERROR_RX_MALFORMED_HELLO_RETRY_REQUEST,
                    illegal_parameter);
        return SECFailure;
    }

    rv = tls13_CreateKeyShare(ss, group);
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, SEC_ERROR_KEYGEN_FAIL, internal_error);
        return SECFailure;
    }

    ss->ssl3.hs.helloRetry = PR_TRUE;

    ssl_GetXmitBufLock(ss);
    rv = ssl3_SendClientHello(ss, client_hello_retry);
    ssl_ReleaseXmitBufLock(ss);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    return SECSuccess;
}

static SECStatus
tls13_HandleCertificateRequest(sslSocket *ss, SSL3Opaque *b, PRUint32 length)
{
    SECStatus rv;
    TLS13CertificateRequest *certRequest = NULL;
    SECItem context = { siBuffer, NULL, 0 };
    PLArenaPool *arena;
    PRInt32 extensionsLength;

    SSL_TRC(3, ("%d: TLS13[%d]: handle certificate_request sequence",
                SSL_GETPID(), ss->fd));

    PORT_Assert(ss->opt.noLocks || ssl_HaveRecvBufLock(ss));
    PORT_Assert(ss->opt.noLocks || ssl_HaveSSL3HandshakeLock(ss));

    /* Client */
    rv = TLS13_CHECK_HS_STATE(ss, SSL_ERROR_RX_UNEXPECTED_CERT_REQUEST,
                              wait_cert_request);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    PORT_Assert(ss->ssl3.clientCertChain == NULL);
    PORT_Assert(ss->ssl3.clientCertificate == NULL);
    PORT_Assert(ss->ssl3.clientPrivateKey == NULL);
    PORT_Assert(ss->ssl3.hs.certificateRequest == NULL);

    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if (!arena) {
        FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
        return SECFailure;
    }

    rv = ssl3_ConsumeHandshakeVariable(ss, &context, 1, &b, &length);
    if (rv != SECSuccess)
        goto loser;

    /* We don't support post-handshake client auth, the certificate request
     * context must always be null. */
    if (context.len > 0) {
        FATAL_ERROR(ss, SSL_ERROR_RX_MALFORMED_CERT_REQUEST, illegal_parameter);
        goto loser;
    }

    certRequest = PORT_ArenaZNew(arena, TLS13CertificateRequest);
    if (!certRequest)
        goto loser;
    certRequest->arena = arena;
    certRequest->ca_list.arena = arena;

    rv = ssl_ParseSignatureSchemes(ss, arena,
                                   &certRequest->signatureSchemes,
                                   &certRequest->signatureSchemeCount,
                                   &b, &length);
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, SSL_ERROR_RX_MALFORMED_CERT_REQUEST,
                    illegal_parameter);
        goto loser;
    }

    rv = ssl3_ParseCertificateRequestCAs(ss, &b, &length, arena,
                                         &certRequest->ca_list);
    if (rv != SECSuccess)
        goto loser; /* alert already sent */

    /* Verify that the extensions length is correct. */
    extensionsLength = ssl3_ConsumeHandshakeNumber(ss, 2, &b, &length);
    if (extensionsLength < 0) {
        goto loser; /* alert already sent */
    }
    if (extensionsLength != length) {
        FATAL_ERROR(ss, SSL_ERROR_RX_MALFORMED_CERT_REQUEST,
                    illegal_parameter);
        goto loser;
    }

    rv = SECITEM_CopyItem(arena, &certRequest->context, &context);
    if (rv != SECSuccess)
        goto loser;

    TLS13_SET_HS_STATE(ss, wait_server_cert);
    ss->ssl3.hs.certificateRequest = certRequest;

    return SECSuccess;

loser:
    PORT_FreeArena(arena, PR_FALSE);
    return SECFailure;
}

static SECStatus
tls13_SendEncryptedServerSequence(sslSocket *ss)
{
    SECStatus rv;

    rv = tls13_ComputeHandshakeSecrets(ss);
    if (rv != SECSuccess) {
        return SECFailure; /* error code is set. */
    }

    rv = tls13_SetCipherSpec(ss, TrafficKeyHandshake,
                             CipherSpecWrite, PR_FALSE);
    if (rv != SECSuccess) {
        LOG_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE);
        return SECFailure;
    }

    if (ss->ssl3.hs.zeroRttState == ssl_0rtt_accepted) {
        rv = ssl3_RegisterServerHelloExtensionSender(ss, ssl_tls13_early_data_xtn,
                                                     tls13_ServerSendEarlyDataXtn);
        if (rv != SECSuccess) {
            return SECFailure; /* Error code set already. */
        }
    }

    rv = tls13_SendEncryptedExtensions(ss);
    if (rv != SECSuccess) {
        return SECFailure; /* error code is set. */
    }

    if (ss->opt.requestCertificate) {
        rv = tls13_SendCertificateRequest(ss);
        if (rv != SECSuccess) {
            return SECFailure; /* error code is set. */
        }
    }
    if (ss->ssl3.hs.kea_def->authKeyType != ssl_auth_psk) {
        SECKEYPrivateKey *svrPrivKey;

        rv = ssl3_SendCertificate(ss);
        if (rv != SECSuccess) {
            return SECFailure; /* error code is set. */
        }

        svrPrivKey = ss->sec.serverCert->serverKeyPair->privKey;
        rv = tls13_SendCertificateVerify(ss, svrPrivKey);
        if (rv != SECSuccess) {
            return SECFailure; /* err code is set. */
        }
    }

    rv = tls13_SendFinished(ss, ss->ssl3.hs.hsTrafficSecret);
    if (rv != SECSuccess) {
        return SECFailure; /* error code is set. */
    }

    return SECSuccess;
}

/* Called from:  ssl3_HandleClientHello */
SECStatus
tls13_SendServerHelloSequence(sslSocket *ss)
{
    SECStatus rv;
    PRErrorCode err = 0;

    SSL_TRC(3, ("%d: TLS13[%d]: begin send server_hello sequence",
                SSL_GETPID(), ss->fd));

    PORT_Assert(ss->opt.noLocks || ssl_HaveSSL3HandshakeLock(ss));
    PORT_Assert(ss->opt.noLocks || ssl_HaveXmitBufLock(ss));

    rv = ssl3_SendServerHello(ss);
    if (rv != SECSuccess) {
        return rv; /* err code is set. */
    }

    rv = tls13_SendEncryptedServerSequence(ss);
    if (rv != SECSuccess) {
        err = PORT_GetError();
    }
    /* Even if we get an error, since the ServerHello was successfully
     * serialized, we should give it a chance to reach the network.  This gives
     * the client a chance to perform the key exchange and decrypt the alert
     * we're about to send. */
    rv |= ssl3_FlushHandshake(ss, 0);
    if (rv != SECSuccess) {
        if (err) {
            PORT_SetError(err);
        }
        return SECFailure;
    }

    /* Compute the rest of the secrets except for the resumption
     * and exporter secret. */
    rv = tls13_ComputeApplicationSecrets(ss);
    if (rv != SECSuccess) {
        LOG_ERROR(ss, PORT_GetError());
        return SECFailure;
    }

    rv = tls13_SetCipherSpec(ss, TrafficKeyApplicationData,
                             CipherSpecWrite, PR_FALSE);
    if (rv != SECSuccess) {
        LOG_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE);
        return SECFailure;
    }

    if (ss->ssl3.hs.zeroRttState == ssl_0rtt_accepted) {
        rv = tls13_SetCipherSpec(ss,
                                 TrafficKeyEarlyApplicationData,
                                 CipherSpecRead, PR_TRUE);
        if (rv != SECSuccess) {
            LOG_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE);
            return SECFailure;
        }
    } else {
        PORT_Assert(ss->ssl3.hs.zeroRttState == ssl_0rtt_none ||
                    ss->ssl3.hs.zeroRttState == ssl_0rtt_ignored);

        /* If we are ignoring 0-RTT, then we will ignore a handshake
         * message. But the client will have counted them. */
        if (IS_DTLS(ss) && ss->ssl3.hs.zeroRttState == ssl_0rtt_ignored) {
            ss->ssl3.hs.recvMessageSeq++;
        }

        rv = tls13_SetCipherSpec(ss,
                                 TrafficKeyHandshake,
                                 CipherSpecRead, PR_FALSE);
        if (rv != SECSuccess) {
            LOG_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE);
            return SECFailure;
        }
    }

    TLS13_SET_HS_STATE(ss,
                       ss->opt.requestCertificate ? wait_client_cert
                                                  : wait_finished);
    return SECSuccess;
}

SECStatus
tls13_HandleServerHelloPart2(sslSocket *ss)
{
    SECStatus rv;
    PRBool isPSK = ssl3_ExtensionNegotiated(ss, ssl_tls13_pre_shared_key_xtn);
    sslSessionID *sid = ss->sec.ci.sid;
    SSL3Statistics *ssl3stats = SSL_GetStatistics();

    if (isPSK) {
        PRBool cacheOK = PR_FALSE;
        do {
            if (ss->ssl3.hs.kea_def->authKeyType != ssl_auth_psk) {
                FATAL_ERROR(ss, SSL_ERROR_RX_MALFORMED_SERVER_HELLO,
                            illegal_parameter);
                break;
            }
            /* If we offered early data, then we already have the shared secret
             * recovered. */
            if (ss->ssl3.hs.zeroRttState == ssl_0rtt_none) {
                rv = tls13_RecoverWrappedSharedSecret(ss, sid);
                if (rv != SECSuccess) {
                    FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
                    break;
                }
            } else {
                PORT_Assert(ss->ssl3.hs.currentSecret);
            }
            cacheOK = PR_TRUE;
        } while (0);

        if (!cacheOK) {
            SSL_AtomicIncrementLong(&ssl3stats->hsh_sid_cache_not_ok);
            if (ss->sec.uncache)
                ss->sec.uncache(sid);
            return SECFailure;
        }

        tls13_RestoreCipherInfo(ss, sid);
        if (sid->peerCert) {
            ss->sec.peerCert = CERT_DupCertificate(sid->peerCert);
        }

        SSL_AtomicIncrementLong(&ssl3stats->hsh_sid_cache_hits);
        SSL_AtomicIncrementLong(&ssl3stats->hsh_sid_stateless_resumes);
    } else {
        /* No PSK negotiated.*/
        if (ss->ssl3.hs.kea_def->authKeyType == ssl_auth_psk) {
            FATAL_ERROR(ss, SSL_ERROR_RX_MALFORMED_SERVER_HELLO,
                        illegal_parameter);
            return SECFailure;
        }
        if (ss->ssl3.hs.zeroRttState != ssl_0rtt_none) {
            PORT_Assert(ss->ssl3.hs.currentSecret);
            /* If we tried 0-RTT and didn't even get PSK, we need to clean
             * stuff up. */
            PK11_FreeSymKey(ss->ssl3.hs.currentSecret);
            ss->ssl3.hs.currentSecret = NULL;
            SECITEM_FreeItem(&ss->ssl3.hs.resumptionContext, PR_FALSE);
        }
        if (ssl3_ClientExtensionAdvertised(ss, ssl_tls13_pre_shared_key_xtn)) {
            SSL_AtomicIncrementLong(&ssl3stats->hsh_sid_cache_misses);
        }
        /* Copy Signed Certificate Timestamps, if any. */
        if (ss->xtnData.signedCertTimestamps.data) {
            rv = SECITEM_CopyItem(NULL, &sid->u.ssl3.signedCertTimestamps,
                                  &ss->xtnData.signedCertTimestamps);
            if (rv != SECSuccess) {
                FATAL_ERROR(ss, SEC_ERROR_NO_MEMORY, internal_error);
                return SECFailure;
            }
            /* Clean up the temporary pointer to the handshake buffer. */
            ss->xtnData.signedCertTimestamps.data = NULL;
            ss->xtnData.signedCertTimestamps.len = 0;
        }
        ss->ssl3.hs.origCipherSuite = ss->ssl3.hs.cipher_suite;

        if (sid->cached == in_client_cache && (ss->sec.uncache)) {
            /* If we tried to resume and failed, let's not try again. */
            ss->sec.uncache(sid);
        }
    }

    if (!ss->ssl3.hs.currentSecret) {
        PORT_Assert(!isPSK || ss->ssl3.hs.zeroRttState == ssl_0rtt_none);

        /* If we don't already have the Early Secret we need to make it
         * now. */
        rv = tls13_ComputeEarlySecrets(ss, PR_FALSE);
        if (rv != SECSuccess) {
            FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
            return SECFailure;
        }
    }

    /* Discard current SID and make a new one, though it may eventually
     * end up looking a lot like the old one.
     */
    ssl_FreeSID(sid);
    ss->sec.ci.sid = sid = ssl3_NewSessionID(ss, PR_FALSE);
    if (sid == NULL) {
        FATAL_ERROR(ss, PORT_GetError(), internal_error);
        return SECFailure;
    }
    if (isPSK && ss->sec.peerCert) {
        sid->peerCert = CERT_DupCertificate(ss->sec.peerCert);
    }
    sid->version = ss->version;
    sid->u.ssl3.cipherSuite = ss->ssl3.hs.origCipherSuite;

    rv = tls13_HandleServerKeyShare(ss);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    rv = tls13_ComputeHandshakeSecrets(ss);
    if (rv != SECSuccess) {
        return SECFailure; /* error code is set. */
    }

    rv = tls13_SetCipherSpec(ss, TrafficKeyHandshake,
                             CipherSpecRead, PR_FALSE);
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, SSL_ERROR_INIT_CIPHER_SUITE_FAILURE, internal_error);
        return SECFailure;
    }
    TLS13_SET_HS_STATE(ss, wait_encrypted_extensions);

    return SECSuccess;
}

/*
 * Called from ssl3_HandleServerHello.
 *
 * Caller must hold Handshake and RecvBuf locks.
 */
SECStatus
tls13_HandleServerKeyShare(sslSocket *ss)
{
    SECStatus rv;
    TLS13KeyShareEntry *entry;
    sslEphemeralKeyPair *keyPair;

    SSL_TRC(3, ("%d: TLS13[%d]: handle server_key_share handshake",
                SSL_GETPID(), ss->fd));
    PORT_Assert(ss->opt.noLocks || ssl_HaveRecvBufLock(ss));
    PORT_Assert(ss->opt.noLocks || ssl_HaveSSL3HandshakeLock(ss));

    /* This list should have one entry. */
    if (PR_CLIST_IS_EMPTY(&ss->ssl3.hs.remoteKeyShares)) {
        FATAL_ERROR(ss, SSL_ERROR_MISSING_KEY_SHARE, missing_extension);
        return SECFailure;
    }

    entry = (TLS13KeyShareEntry *)PR_NEXT_LINK(&ss->ssl3.hs.remoteKeyShares);
    PORT_Assert(PR_NEXT_LINK(&entry->link) == &ss->ssl3.hs.remoteKeyShares);

    PORT_Assert(ssl_NamedGroupEnabled(ss, entry->group));

    /* Now get our matching key. */
    keyPair = ssl_LookupEphemeralKeyPair(ss, entry->group);
    if (!keyPair) {
        FATAL_ERROR(ss, SSL_ERROR_RX_MALFORMED_KEY_SHARE, illegal_parameter);
        return SECFailure;
    }

    rv = tls13_HandleKeyShare(ss, entry, keyPair->keys);
    if (rv != SECSuccess)
        return SECFailure; /* Error code set by caller. */

    ss->sec.keaType = ss->ssl3.hs.kea_def->exchKeyType;
    ss->sec.keaKeyBits = SECKEY_PublicKeyStrengthInBits(keyPair->keys->pubKey);

    return SECSuccess;
}

/* Called from tls13_CompleteHandleHandshakeMessage() when it has deciphered a complete
 * tls13 Certificate message.
 * Caller must hold Handshake and RecvBuf locks.
 */
static SECStatus
tls13_HandleCertificate(sslSocket *ss, SSL3Opaque *b, PRUint32 length)
{
    SECStatus rv;
    SECItem context = { siBuffer, NULL, 0 };

    SSL_TRC(3, ("%d: TLS13[%d]: handle certificate handshake",
                SSL_GETPID(), ss->fd));
    PORT_Assert(ss->opt.noLocks || ssl_HaveRecvBufLock(ss));
    PORT_Assert(ss->opt.noLocks || ssl_HaveSSL3HandshakeLock(ss));

    if (ss->sec.isServer) {
        rv = TLS13_CHECK_HS_STATE(ss, SSL_ERROR_RX_UNEXPECTED_CERTIFICATE,
                                  wait_client_cert);
    } else {
        rv = TLS13_CHECK_HS_STATE(ss, SSL_ERROR_RX_UNEXPECTED_CERTIFICATE,
                                  wait_cert_request, wait_server_cert);
    }
    if (rv != SECSuccess)
        return SECFailure;

    /* Process the context string */
    rv = ssl3_ConsumeHandshakeVariable(ss, &context, 1, &b, &length);
    if (rv != SECSuccess)
        return SECFailure;

    if (context.len) {
        /* The context string MUST be empty */
        FATAL_ERROR(ss, SSL_ERROR_RX_MALFORMED_CERTIFICATE, illegal_parameter);
        return SECFailure;
    }

    rv = ssl3_CompleteHandleCertificate(ss, b, length);
    if (rv != SECSuccess)
        return rv;

    return SECSuccess;
}

void
tls13_CipherSpecAddRef(ssl3CipherSpec *spec)
{
    ++spec->refCt;
    SSL_TRC(10, ("%d: TLS13[-]: Increment ref ct for spec %d. new ct = %d",
                 SSL_GETPID(), spec, spec->refCt));
}

/* This function is never called on a spec which is on the
 * cipherSpecs list. */
void
tls13_CipherSpecRelease(ssl3CipherSpec *spec)
{
    PORT_Assert(spec->refCt > 0);
    --spec->refCt;
    SSL_TRC(10, ("%d: TLS13[-]: decrement refct for spec %d. phase=%s new ct = %d",
                 SSL_GETPID(), spec, spec->phase, spec->refCt));
    if (!spec->refCt) {
        SSL_TRC(10, ("%d: TLS13[-]: Freeing spec %d. phase=%s",
                     SSL_GETPID(), spec, spec->phase));
        PR_REMOVE_LINK(&spec->link);
        ssl3_DestroyCipherSpec(spec, PR_TRUE);
        PORT_Free(spec);
    }
}

/* Add context to the hash functions as described in
   [draft-ietf-tls-tls13; Section 4.9.1] */
SECStatus
tls13_AddContextToHashes(sslSocket *ss, const TLS13CombinedHash *hashes,
                         SSLHashType algorithm, PRBool sending,
                         SSL3Hashes *tbsHash)
{
    SECStatus rv = SECSuccess;
    PK11Context *ctx;
    const unsigned char context_padding[] = {
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    };

    const char *client_cert_verify_string = "TLS 1.3, client CertificateVerify";
    const char *server_cert_verify_string = "TLS 1.3, server CertificateVerify";
    const char *context_string = (sending ^ ss->sec.isServer) ? client_cert_verify_string
                                                              : server_cert_verify_string;
    unsigned int hashlength;

    /* Double check that we are doing the same hash.*/
    PORT_Assert(hashes->len == tls13_GetHashSize(ss) * 2);

    ctx = PK11_CreateDigestContext(ssl3_HashTypeToOID(algorithm));
    if (!ctx) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        goto loser;
    }

    PORT_Assert(SECFailure);
    PORT_Assert(!SECSuccess);

    PRINT_BUF(50, (ss, "TLS 1.3 hash without context", hashes->hash, hashes->len));
    PRINT_BUF(50, (ss, "Context string", context_string, strlen(context_string)));
    rv |= PK11_DigestBegin(ctx);
    rv |= PK11_DigestOp(ctx, context_padding, sizeof(context_padding));
    rv |= PK11_DigestOp(ctx, (unsigned char *)context_string,
                        strlen(context_string) + 1); /* +1 includes the terminating 0 */
    rv |= PK11_DigestOp(ctx, hashes->hash, hashes->len);
    /* Update the hash in-place */
    rv |= PK11_DigestFinal(ctx, tbsHash->u.raw, &hashlength, sizeof(tbsHash->u.raw));
    PK11_DestroyContext(ctx, PR_TRUE);
    PRINT_BUF(50, (ss, "TLS 1.3 hash with context", tbsHash->u.raw, hashlength));

    tbsHash->len = hashlength;
    tbsHash->hashAlg = algorithm;

    if (rv) {
        ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
        goto loser;
    }
    return SECSuccess;

loser:
    return SECFailure;
}

/*
 *    Derive-Secret(Secret, Label, Messages) =
 *       HKDF-Expand-Label(Secret, Label,
 *                         Hash(Messages) + Hash(resumption_context), L))
 */
static SECStatus
tls13_DeriveSecret(sslSocket *ss, PK11SymKey *key, const char *label,
                   const TLS13CombinedHash *hashes,
                   PK11SymKey **dest)
{
    SECStatus rv;
    TLS13CombinedHash hashesTmp;

    SSL_TRC(3, ("%d: TLS13[%d]: deriving secret '%s'",
                SSL_GETPID(), ss->fd, label));
    if (!hashes) {
        rv = tls13_ComputeHandshakeHashes(ss, &hashesTmp);
        if (rv != SECSuccess) {
            PORT_Assert(0); /* Should never fail */
            ssl_MapLowLevelError(SEC_ERROR_LIBRARY_FAILURE);
            return SECFailure;
        }
        hashes = &hashesTmp;
    }

    rv = tls13_HkdfExpandLabel(key, tls13_GetHash(ss),
                               hashes->hash, hashes->len,
                               label, strlen(label),
                               tls13_GetHkdfMechanism(ss),
                               tls13_GetHashSize(ss), dest);
    if (rv != SECSuccess) {
        LOG_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE);
        return SECFailure;
    }
    return SECSuccess;
}

/* Derive traffic keys for the next cipher spec in the queue. */
static SECStatus
tls13_DeriveTrafficKeys(sslSocket *ss, ssl3CipherSpec *spec,
                        TrafficKeyType type,
                        CipherSpecDirection direction,
                        PRBool deleteSecret)
{
    size_t keySize = spec->cipher_def->key_size;
    size_t ivSize = spec->cipher_def->iv_size +
                    spec->cipher_def->explicit_nonce_size; /* This isn't always going to
                                                              * work, but it does for
                                                              * AES-GCM */
    CK_MECHANISM_TYPE bulkAlgorithm = ssl3_Alg2Mech(spec->cipher_def->calg);
    PK11SymKey **prkp = NULL;
    PK11SymKey *prk = NULL;
    const char *phase;
    char label[256]; /* Arbitrary buffer large enough to hold the label */
    SECStatus rv;

#define FORMAT_LABEL(phase_, purpose_)                                              \
    do {                                                                            \
        PRUint32 n = PR_snprintf(label, sizeof(label), "%s, %s", phase_, purpose_); \
        /* Check for getting close. */                                              \
        if ((n + 1) >= sizeof(label)) {                                             \
            LOG_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE);                               \
            PORT_Assert(0);                                                         \
            goto loser;                                                             \
        }                                                                           \
    } while (0)
#define EXPAND_TRAFFIC_KEY(purpose_, target_)                               \
    do {                                                                    \
        FORMAT_LABEL(phase, purpose_);                                      \
        rv = tls13_HkdfExpandLabel(prk, tls13_GetHash(ss),                  \
                                   NULL, 0,                                 \
                                   label, strlen(label),                    \
                                   bulkAlgorithm, keySize, &spec->target_); \
        if (rv != SECSuccess) {                                             \
            LOG_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE);                       \
            PORT_Assert(0);                                                 \
            goto loser;                                                     \
        }                                                                   \
    } while (0)

#define EXPAND_TRAFFIC_IV(purpose_, target_)                  \
    do {                                                      \
        FORMAT_LABEL(phase, purpose_);                        \
        rv = tls13_HkdfExpandLabelRaw(prk, tls13_GetHash(ss), \
                                      NULL, 0,                \
                                      label, strlen(label),   \
                                      spec->target_, ivSize); \
        if (rv != SECSuccess) {                               \
            LOG_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE);         \
            PORT_Assert(0);                                   \
            goto loser;                                       \
        }                                                     \
    } while (0)

    PORT_Assert(ss->opt.noLocks || ssl_HaveSSL3HandshakeLock(ss));

    switch (type) {
        case TrafficKeyEarlyHandshake:
            phase = kHkdfPhaseEarlyHandshakeDataKeys;
            prkp = &ss->ssl3.hs.earlyTrafficSecret;
            break;
        case TrafficKeyEarlyApplicationData:
            phase = kHkdfPhaseEarlyApplicationDataKeys;
            prkp = &ss->ssl3.hs.earlyTrafficSecret;
            break;
        case TrafficKeyHandshake:
            phase = kHkdfPhaseHandshakeKeys;
            prkp = &ss->ssl3.hs.hsTrafficSecret;
            break;
        case TrafficKeyApplicationData:
            phase = kHkdfPhaseApplicationDataKeys;
            prkp = &ss->ssl3.hs.trafficSecret;
            break;
        default:
            LOG_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE);
            PORT_Assert(0);
            return SECFailure;
    }
    PORT_Assert(prkp != NULL);
    prk = *prkp;

    SSL_TRC(3, ("%d: TLS13[%d]: deriving traffic keys phase='%s'",
                SSL_GETPID(), ss->fd, phase));
    PORT_Assert(phase);
    spec->phase = phase;

    if ((direction == CipherSpecWrite) ^ (ss->sec.isServer)) {
        EXPAND_TRAFFIC_KEY(kHkdfPurposeClientWriteKey, client.write_key);
        EXPAND_TRAFFIC_IV(kHkdfPurposeClientWriteIv, client.write_iv);
    } else {
        EXPAND_TRAFFIC_KEY(kHkdfPurposeServerWriteKey, server.write_key);
        EXPAND_TRAFFIC_IV(kHkdfPurposeServerWriteIv, server.write_iv);
    }

    if (deleteSecret) {
        PK11_FreeSymKey(prk);
        *prkp = NULL;
    }
    return SECSuccess;

loser:
    return SECFailure;
}

/* Install a new cipher spec for this direction. */
static SECStatus
tls13_SetCipherSpec(sslSocket *ss, TrafficKeyType type,
                    CipherSpecDirection direction, PRBool deleteSecret)
{
    SECStatus rv;
    ssl3CipherSpec *spec = NULL;
    ssl3CipherSpec **specp = (direction == CipherSpecRead) ? &ss->ssl3.crSpec : &ss->ssl3.cwSpec;
    /* Flush out old handshake data. */
    ssl_GetXmitBufLock(ss);
    rv = ssl3_FlushHandshake(ss, ssl_SEND_FLAG_FORCE_INTO_BUFFER);
    ssl_ReleaseXmitBufLock(ss);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    /* Create the new spec. */
    spec = PORT_ZNew(ssl3CipherSpec);
    if (!spec) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return SECFailure;
    }
    spec->refCt = 1;
    PR_APPEND_LINK(&spec->link, &ss->ssl3.hs.cipherSpecs);
    ss->ssl3.pwSpec = ss->ssl3.prSpec = spec;

    /* This is really overkill, because we need about 10% of
     * what ssl3_SetupPendingCipherSpec does. */
    rv = ssl3_SetupPendingCipherSpec(ss);
    if (rv != SECSuccess)
        return SECFailure;

    switch (spec->cipher_def->calg) {
        case calg_aes_gcm:
            spec->aead = tls13_AESGCM;
            break;
        case calg_chacha20:
            spec->aead = tls13_ChaCha20Poly1305;
            break;
        default:
            PORT_Assert(0);
            return SECFailure;
            break;
    }

    rv = tls13_DeriveTrafficKeys(ss, spec, type, direction,
                                 deleteSecret);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    /* We use the epoch for cipher suite identification, so increment
     * it in both TLS and DTLS. */
    if ((*specp)->epoch == PR_UINT16_MAX) {
        return SECFailure;
    }
    spec->epoch = (*specp)->epoch + 1;

    if (!IS_DTLS(ss)) {
        spec->read_seq_num = spec->write_seq_num = 0;
    } else {
        /* The sequence number has the high 16 bits as the epoch. */
        spec->read_seq_num = spec->write_seq_num =
            (sslSequenceNumber)spec->epoch << 48;

        dtls_InitRecvdRecords(&spec->recvdRecords);
    }

    /* Now that we've set almost everything up, finally cut over. */
    ssl_GetSpecWriteLock(ss);
    tls13_CipherSpecRelease(*specp); /* May delete old cipher. */
    *specp = spec;                   /* Overwrite. */
    ssl_ReleaseSpecWriteLock(ss);

    SSL_TRC(3, ("%d: TLS13[%d]: %s installed key for phase='%s'.%d dir=%s",
                SSL_GETPID(), ss->fd,
                ss->sec.isServer ? "server" : "client",
                spec->phase, spec->epoch,
                direction == CipherSpecRead ? "read" : "write"));

    return SECSuccess;
}

static void
tls13_CombineHashes(sslSocket *ss, const PRUint8 *hhash,
                    unsigned int hlen, TLS13CombinedHash *hashes)
{
    PORT_Assert(hlen == tls13_GetHashSize(ss));
    PORT_Memcpy(hashes->hash, hhash, hlen);
    hashes->len = hlen;

    PORT_Assert(ss->ssl3.hs.resumptionContext.len == tls13_GetHashSize(ss));
    PORT_Memcpy(hashes->hash + hlen,
                ss->ssl3.hs.resumptionContext.data,
                ss->ssl3.hs.resumptionContext.len);
    hashes->len += ss->ssl3.hs.resumptionContext.len;
    PRINT_BUF(10, (NULL, "Combined handshake hash computed ",
                   hashes->hash, hashes->len));
}

static SECStatus
tls13_ComputeHandshakeHashes(sslSocket *ss,
                             TLS13CombinedHash *hashes)
{
    SECStatus rv;
    PK11Context *ctx = NULL;
    PRUint8 buf[HASH_LENGTH_MAX];
    unsigned int len;

    PORT_Assert(ss->opt.noLocks || ssl_HaveSSL3HandshakeLock(ss));
    if (ss->ssl3.hs.hashType == handshake_hash_unknown) {
        /* Backup: if we haven't done any hashing, then hash now.
         * This happens when we are doing 0-RTT on the client. */
        ctx = PK11_CreateDigestContext(ssl3_HashTypeToOID(tls13_GetHash(ss)));
        if (!ctx) {
            ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
            return SECFailure;
        }

        if (PK11_DigestBegin(ctx) != SECSuccess) {
            ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
            goto loser;
        }

        PRINT_BUF(10, (NULL, "Handshake hash computed over saved messages",
                       ss->ssl3.hs.messages.buf,
                       ss->ssl3.hs.messages.len));

        if (PK11_DigestOp(ctx,
                          ss->ssl3.hs.messages.buf,
                          ss->ssl3.hs.messages.len) != SECSuccess) {
            ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
            goto loser;
        }
    } else {
        ctx = PK11_CloneContext(ss->ssl3.hs.sha);
        if (!ctx) {
            ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
            return SECFailure;
        }
    }

    rv = PK11_DigestFinal(ctx, buf, &len, sizeof(buf));
    if (rv != SECSuccess) {
        ssl_MapLowLevelError(SSL_ERROR_DIGEST_FAILURE);
        goto loser;
    }
    PORT_Assert(len == tls13_GetHashSize(ss));
    PK11_DestroyContext(ctx, PR_TRUE);

    tls13_CombineHashes(ss, buf, len, hashes);
    return SECSuccess;

loser:
    PK11_DestroyContext(ctx, PR_TRUE);
    return SECFailure;
}

void
tls13_DestroyKeyShareEntry(TLS13KeyShareEntry *offer)
{
    SECITEM_ZfreeItem(&offer->key_exchange, PR_FALSE);
    PORT_ZFree(offer, sizeof(*offer));
}

void
tls13_DestroyKeyShares(PRCList *list)
{
    PRCList *cur_p;

    while (!PR_CLIST_IS_EMPTY(list)) {
        cur_p = PR_LIST_TAIL(list);
        PR_REMOVE_LINK(cur_p);
        tls13_DestroyKeyShareEntry((TLS13KeyShareEntry *)cur_p);
    }
}

void
tls13_DestroyEarlyData(PRCList *list)
{
    PRCList *cur_p;

    while (!PR_CLIST_IS_EMPTY(list)) {
        TLS13EarlyData *msg;

        cur_p = PR_LIST_TAIL(list);
        msg = (TLS13EarlyData *)cur_p;

        PR_REMOVE_LINK(cur_p);
        SECITEM_ZfreeItem(&msg->data, PR_FALSE);
        PORT_ZFree(msg, sizeof(*msg));
    }
}

void
tls13_DestroyCipherSpecs(PRCList *list)
{
    PRCList *cur_p;

    while (!PR_CLIST_IS_EMPTY(list)) {
        cur_p = PR_LIST_TAIL(list);
        PR_REMOVE_LINK(cur_p);
        ssl3_DestroyCipherSpec((ssl3CipherSpec *)cur_p, PR_FALSE);
        PORT_Free(cur_p);
    }
}

/* draft-ietf-tls-tls13 Section 5.2.2 specifies the following
 * nonce algorithm:
 *
 * The length of the per-record nonce (iv_length) is set to max(8 bytes,
 * N_MIN) for the AEAD algorithm (see [RFC5116] Section 4).  An AEAD
 * algorithm where N_MAX is less than 8 bytes MUST NOT be used with TLS.
 * The per-record nonce for the AEAD construction is formed as follows:
 *
 * 1.  The 64-bit record sequence number is padded to the left with
 *     zeroes to iv_length.
 *
 * 2.  The padded sequence number is XORed with the static
 *     client_write_iv or server_write_iv, depending on the role.
 *
 * The resulting quantity (of length iv_length) is used as the per-
 * record nonce.
 *
 * Existing suites have the same nonce size: N_MIN = N_MAX = 12 bytes
 *
 * See RFC 5288 and https://tools.ietf.org/html/draft-ietf-tls-chacha20-poly1305-04#section-2
 */
static void
tls13_WriteNonce(ssl3KeyMaterial *keys,
                 const unsigned char *seqNumBuf, unsigned int seqNumLen,
                 unsigned char *nonce, unsigned int nonceLen)
{
    size_t i;

    PORT_Assert(nonceLen == 12);
    memcpy(nonce, keys->write_iv, 12);

    /* XOR the last 8 bytes of the IV with the sequence number. */
    PORT_Assert(seqNumLen == 8);
    for (i = 0; i < 8; ++i) {
        nonce[4 + i] ^= seqNumBuf[i];
    }
}

/* Implement the SSLAEADCipher interface defined in sslimpl.h.
 *
 * That interface takes the additional data (see below) and reinterprets that as
 * a sequence number. In TLS 1.3 there is no additional data so this value is
 * just the encoded sequence number.
 */
static SECStatus
tls13_AEAD(ssl3KeyMaterial *keys, PRBool doDecrypt,
           unsigned char *out, int *outlen, int maxout,
           const unsigned char *in, int inlen,
           CK_MECHANISM_TYPE mechanism,
           unsigned char *aeadParams, unsigned int aeadParamLength)
{
    SECStatus rv;
    unsigned int uOutLen = 0;
    SECItem param = {
        siBuffer, aeadParams, aeadParamLength
    };

    if (doDecrypt) {
        rv = PK11_Decrypt(keys->write_key, mechanism, &param,
                          out, &uOutLen, maxout, in, inlen);
    } else {
        rv = PK11_Encrypt(keys->write_key, mechanism, &param,
                          out, &uOutLen, maxout, in, inlen);
    }
    *outlen = (int)uOutLen;

    return rv;
}

static SECStatus
tls13_AESGCM(ssl3KeyMaterial *keys,
             PRBool doDecrypt,
             unsigned char *out,
             int *outlen,
             int maxout,
             const unsigned char *in,
             int inlen,
             const unsigned char *additionalData,
             int additionalDataLen)
{
    CK_GCM_PARAMS gcmParams;
    unsigned char nonce[12];

    memset(&gcmParams, 0, sizeof(gcmParams));
    gcmParams.pIv = nonce;
    gcmParams.ulIvLen = sizeof(nonce);
    gcmParams.pAAD = NULL;
    gcmParams.ulAADLen = 0;
    gcmParams.ulTagBits = 128; /* GCM measures tag length in bits. */

    tls13_WriteNonce(keys, additionalData, additionalDataLen,
                     nonce, sizeof(nonce));
    return tls13_AEAD(keys, doDecrypt, out, outlen, maxout, in, inlen,
                      CKM_AES_GCM,
                      (unsigned char *)&gcmParams, sizeof(gcmParams));
}

static SECStatus
tls13_ChaCha20Poly1305(ssl3KeyMaterial *keys, PRBool doDecrypt,
                       unsigned char *out, int *outlen, int maxout,
                       const unsigned char *in, int inlen,
                       const unsigned char *additionalData,
                       int additionalDataLen)
{
    CK_NSS_AEAD_PARAMS aeadParams;
    unsigned char nonce[12];

    memset(&aeadParams, 0, sizeof(aeadParams));
    aeadParams.pNonce = nonce;
    aeadParams.ulNonceLen = sizeof(nonce);
    aeadParams.pAAD = NULL; /* No AAD in TLS 1.3. */
    aeadParams.ulAADLen = 0;
    aeadParams.ulTagLen = 16; /* The Poly1305 tag is 16 octets. */

    tls13_WriteNonce(keys, additionalData, additionalDataLen,
                     nonce, sizeof(nonce));
    return tls13_AEAD(keys, doDecrypt, out, outlen, maxout, in, inlen,
                      CKM_NSS_CHACHA20_POLY1305,
                      (unsigned char *)&aeadParams, sizeof(aeadParams));
}

static SECStatus
tls13_HandleEncryptedExtensions(sslSocket *ss, SSL3Opaque *b, PRUint32 length)
{
    SECStatus rv;
    PRInt32 innerLength;
    SECItem oldNpn = { siBuffer, NULL, 0 };

    PORT_Assert(ss->opt.noLocks || ssl_HaveRecvBufLock(ss));
    PORT_Assert(ss->opt.noLocks || ssl_HaveSSL3HandshakeLock(ss));

    SSL_TRC(3, ("%d: TLS13[%d]: handle encrypted extensions",
                SSL_GETPID(), ss->fd));

    rv = TLS13_CHECK_HS_STATE(ss, SSL_ERROR_RX_UNEXPECTED_ENCRYPTED_EXTENSIONS,
                              wait_encrypted_extensions);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    innerLength = ssl3_ConsumeHandshakeNumber(ss, 2, &b, &length);
    if (innerLength < 0) {
        return SECFailure; /* Alert already sent. */
    }
    if (innerLength != length) {
        FATAL_ERROR(ss, SSL_ERROR_RX_MALFORMED_ENCRYPTED_EXTENSIONS,
                    illegal_parameter);
        return SECFailure;
    }

    /* If we are doing 0-RTT, then we already have an NPN value. Stash
     * it for comparison. */
    if (ss->ssl3.hs.zeroRttState == ssl_0rtt_sent &&
        ss->ssl3.nextProtoState == SSL_NEXT_PROTO_EARLY_VALUE) {
        oldNpn = ss->ssl3.nextProto;
        ss->ssl3.nextProto.data = NULL;
        ss->ssl3.nextProtoState = SSL_NEXT_PROTO_NO_SUPPORT;
    }
    rv = ssl3_HandleHelloExtensions(ss, &b, &length, encrypted_extensions);
    if (rv != SECSuccess) {
        return SECFailure; /* Error code set below */
    }

    if (ss->ssl3.hs.zeroRttState == ssl_0rtt_accepted) {
        /* Check that the server negotiated the same ALPN (if any). */
        if (SECITEM_CompareItem(&oldNpn, &ss->ssl3.nextProto)) {
            SECITEM_FreeItem(&oldNpn, PR_FALSE);
            FATAL_ERROR(ss, SSL_ERROR_NEXT_PROTOCOL_DATA_INVALID,
                        illegal_parameter);
            return SECFailure;
        }
    } else if (ss->ssl3.hs.zeroRttState == ssl_0rtt_sent) {
        /* Though we sent 0-RTT, the early_data extension wasn't present so the
         * state is unmodified; the server must have rejected 0-RTT. */
        ss->ssl3.hs.zeroRttState = ssl_0rtt_ignored;
        ss->ssl3.hs.zeroRttIgnore = ssl_0rtt_ignore_trial;
    } else {
        PORT_Assert(ss->ssl3.hs.zeroRttState == ssl_0rtt_none ||
                    (ss->ssl3.hs.helloRetry &&
                     ss->ssl3.hs.zeroRttState == ssl_0rtt_ignored));
    }

    SECITEM_FreeItem(&oldNpn, PR_FALSE);
    if (ss->ssl3.hs.kea_def->authKeyType == ssl_auth_psk) {
        TLS13_SET_HS_STATE(ss, wait_finished);
    } else {
        TLS13_SET_HS_STATE(ss, wait_cert_request);
    }

    return SECSuccess;
}

static SECStatus
tls13_SendEncryptedExtensions(sslSocket *ss)
{
    SECStatus rv;
    PRInt32 extensions_len = 0;
    PRInt32 sent_len = 0;
    PRUint32 maxBytes = 65535;

    /* TODO(ekr@rtfm.com): Implement the ticket_age xtn. */
    SSL_TRC(3, ("%d: TLS13[%d]: send encrypted extensions handshake",
                SSL_GETPID(), ss->fd));

    PORT_Assert(ss->opt.noLocks || ssl_HaveSSL3HandshakeLock(ss));
    PORT_Assert(ss->opt.noLocks || ssl_HaveXmitBufLock(ss));

    extensions_len = ssl3_CallHelloExtensionSenders(
        ss, PR_FALSE, maxBytes, &ss->xtnData.encryptedExtensionsSenders[0]);

    rv = ssl3_AppendHandshakeHeader(ss, encrypted_extensions,
                                    extensions_len + 2);
    if (rv != SECSuccess) {
        LOG_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE);
        return SECFailure;
    }
    rv = ssl3_AppendHandshakeNumber(ss, extensions_len, 2);
    if (rv != SECSuccess) {
        LOG_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE);
        return SECFailure;
    }
    sent_len = ssl3_CallHelloExtensionSenders(
        ss, PR_TRUE, extensions_len,
        &ss->xtnData.encryptedExtensionsSenders[0]);
    PORT_Assert(sent_len == extensions_len);
    if (sent_len != extensions_len) {
        LOG_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE);
        PORT_Assert(sent_len == 0);
        return SECFailure;
    }

    return SECSuccess;
}

SECStatus
tls13_SendCertificateVerify(sslSocket *ss, SECKEYPrivateKey *privKey)
{
    SECStatus rv = SECFailure;
    SECItem buf = { siBuffer, NULL, 0 };
    unsigned int len;
    SSLHashType hashAlg;
    TLS13CombinedHash hash;
    SSL3Hashes tbsHash; /* The hash "to be signed". */

    PORT_Assert(ss->opt.noLocks || ssl_HaveXmitBufLock(ss));
    PORT_Assert(ss->opt.noLocks || ssl_HaveSSL3HandshakeLock(ss));

    SSL_TRC(3, ("%d: TLS13[%d]: send certificate_verify handshake",
                SSL_GETPID(), ss->fd));

    PORT_Assert(ss->ssl3.hs.hashType == handshake_hash_single);
    rv = tls13_ComputeHandshakeHashes(ss, &hash);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    /* We should have picked a signature scheme when we received a
     * CertificateRequest, or when we picked a server certificate. */
    PORT_Assert(ss->ssl3.hs.signatureScheme != ssl_sig_none);
    if (ss->ssl3.hs.signatureScheme == ssl_sig_none) {
        PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
        return SECFailure;
    }
    hashAlg = ssl_SignatureSchemeToHashType(ss->ssl3.hs.signatureScheme);
    rv = tls13_AddContextToHashes(ss, &hash, hashAlg,
                                  PR_TRUE, &tbsHash);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    rv = ssl3_SignHashes(ss, &tbsHash, privKey, &buf);
    if (rv == SECSuccess && !ss->sec.isServer) {
        /* Remember the info about the slot that did the signing.
         * Later, when doing an SSL restart handshake, verify this.
         * These calls are mere accessors, and can't fail.
         */
        PK11SlotInfo *slot;
        sslSessionID *sid = ss->sec.ci.sid;

        slot = PK11_GetSlotFromPrivateKey(privKey);
        sid->u.ssl3.clAuthSeries = PK11_GetSlotSeries(slot);
        sid->u.ssl3.clAuthSlotID = PK11_GetSlotID(slot);
        sid->u.ssl3.clAuthModuleID = PK11_GetModuleID(slot);
        sid->u.ssl3.clAuthValid = PR_TRUE;
        PK11_FreeSlot(slot);
    }
    if (rv != SECSuccess) {
        goto done; /* err code was set by ssl3_SignHashes */
    }

    len = buf.len + 2 + 2;

    rv = ssl3_AppendHandshakeHeader(ss, certificate_verify, len);
    if (rv != SECSuccess) {
        goto done; /* error code set by AppendHandshake */
    }

    rv = ssl3_AppendHandshakeNumber(ss, ss->ssl3.hs.signatureScheme, 2);
    if (rv != SECSuccess) {
        goto done; /* err set by AppendHandshakeNumber */
    }

    rv = ssl3_AppendHandshakeVariable(ss, buf.data, buf.len, 2);
    if (rv != SECSuccess) {
        goto done; /* error code set by AppendHandshake */
    }

done:
    /* For parity with the allocation functions, which don't use
     * SECITEM_AllocItem(). */
    if (buf.data)
        PORT_Free(buf.data);
    return rv;
}

/* Called from tls13_CompleteHandleHandshakeMessage() when it has deciphered a complete
 * tls13 CertificateVerify message
 * Caller must hold Handshake and RecvBuf locks.
 */
SECStatus
tls13_HandleCertificateVerify(sslSocket *ss, SSL3Opaque *b, PRUint32 length,
                              TLS13CombinedHash *hashes)
{
    SECItem signed_hash = { siBuffer, NULL, 0 };
    SECStatus rv;
    SignatureScheme sigScheme;
    SSLHashType hashAlg;
    SSL3Hashes tbsHash;

    SSL_TRC(3, ("%d: TLS13[%d]: handle certificate_verify handshake",
                SSL_GETPID(), ss->fd));
    PORT_Assert(ss->opt.noLocks || ssl_HaveRecvBufLock(ss));
    PORT_Assert(ss->opt.noLocks || ssl_HaveSSL3HandshakeLock(ss));

    rv = TLS13_CHECK_HS_STATE(ss, SSL_ERROR_RX_UNEXPECTED_CERT_VERIFY,
                              wait_cert_verify);
    if (rv != SECSuccess) {
        return SECFailure;
    }
    PORT_Assert(hashes);

    rv = ssl_ConsumeSignatureScheme(ss, &b, &length, &sigScheme);
    if (rv != SECSuccess) {
        PORT_SetError(SSL_ERROR_RX_MALFORMED_CERT_VERIFY);
        return SECFailure;
    }

    rv = ssl_CheckSignatureSchemeConsistency(ss, sigScheme, ss->sec.peerCert);
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, SSL_ERROR_RX_MALFORMED_CERT_VERIFY, decrypt_error);
        return SECFailure;
    }
    hashAlg = ssl_SignatureSchemeToHashType(sigScheme);

    rv = tls13_AddContextToHashes(ss, hashes, hashAlg, PR_FALSE, &tbsHash);
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, SSL_ERROR_DIGEST_FAILURE, internal_error);
        return SECFailure;
    }

    rv = ssl3_ConsumeHandshakeVariable(ss, &signed_hash, 2, &b, &length);
    if (rv != SECSuccess) {
        PORT_SetError(SSL_ERROR_RX_MALFORMED_CERT_VERIFY);
        return SECFailure;
    }

    if (length != 0) {
        FATAL_ERROR(ss, SSL_ERROR_RX_MALFORMED_CERT_VERIFY, decode_error);
        return SECFailure;
    }

    rv = ssl3_VerifySignedHashes(ss, sigScheme, &tbsHash, &signed_hash);
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, PORT_GetError(), decrypt_error);
        return SECFailure;
    }

    /* Request a client certificate now if one was requested. */
    if (ss->ssl3.hs.certificateRequest) {
        TLS13CertificateRequest *req = ss->ssl3.hs.certificateRequest;

        PORT_Assert(!ss->sec.isServer);
        rv = ssl3_CompleteHandleCertificateRequest(ss, req->signatureSchemes,
                                                   req->signatureSchemeCount,
                                                   &req->ca_list);
        if (rv != SECSuccess) {
            FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
            return rv;
        }
    }

    TLS13_SET_HS_STATE(ss, wait_finished);

    return SECSuccess;
}

static SECStatus
tls13_ComputeFinished(sslSocket *ss, PK11SymKey *baseKey,
                      const TLS13CombinedHash *hashes,
                      PRBool sending, PRUint8 *output, unsigned int *outputLen,
                      unsigned int maxOutputLen)
{
    SECStatus rv;
    PK11Context *hmacCtx = NULL;
    CK_MECHANISM_TYPE macAlg = tls13_GetHmacMechanism(ss);
    SECItem param = { siBuffer, NULL, 0 };
    unsigned int outputLenUint;
    const char *label = (ss->sec.isServer ^ sending) ? kHkdfLabelClientFinishedSecret : kHkdfLabelServerFinishedSecret;
    PK11SymKey *secret = NULL;

    PORT_Assert(baseKey);
    PRINT_BUF(50, (NULL, "Handshake hash", hashes->hash, hashes->len));

    /* Now derive the appropriate finished secret from the base secret. */
    rv = tls13_HkdfExpandLabel(baseKey,
                               tls13_GetHash(ss),
                               NULL, 0,
                               label, strlen(label),
                               tls13_GetHmacMechanism(ss),
                               tls13_GetHashSize(ss), &secret);
    if (rv != SECSuccess) {
        goto abort;
    }

    PRINT_BUF(50, (NULL, "Handshake hash", hashes->hash, hashes->len));
    PORT_Assert(hashes->len == tls13_GetHashSize(ss) * 2);
    hmacCtx = PK11_CreateContextBySymKey(macAlg, CKA_SIGN,
                                         secret, &param);
    if (!hmacCtx) {
        goto abort;
    }

    rv = PK11_DigestBegin(hmacCtx);
    if (rv != SECSuccess)
        goto abort;

    rv = PK11_DigestOp(hmacCtx, hashes->hash, hashes->len);
    if (rv != SECSuccess)
        goto abort;

    PORT_Assert(maxOutputLen >= tls13_GetHashSize(ss));
    rv = PK11_DigestFinal(hmacCtx, output, &outputLenUint, maxOutputLen);
    if (rv != SECSuccess)
        goto abort;
    *outputLen = outputLenUint;

    PK11_FreeSymKey(secret);
    PK11_DestroyContext(hmacCtx, PR_TRUE);
    return SECSuccess;

abort:
    if (secret) {
        PK11_FreeSymKey(secret);
    }

    if (hmacCtx) {
        PK11_DestroyContext(hmacCtx, PR_TRUE);
    }

    PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
    return SECFailure;
}

static SECStatus
tls13_SendFinished(sslSocket *ss, PK11SymKey *baseKey)
{
    SECStatus rv;
    PRUint8 finishedBuf[MAX_FINISHED_SIZE];
    unsigned int finishedLen;
    TLS13CombinedHash hashes;

    SSL_TRC(3, ("%d: TLS13[%d]: send finished handshake", SSL_GETPID(), ss->fd));

    PORT_Assert(ss->opt.noLocks || ssl_HaveXmitBufLock(ss));
    PORT_Assert(ss->opt.noLocks || ssl_HaveSSL3HandshakeLock(ss));

    rv = tls13_ComputeHandshakeHashes(ss, &hashes);
    if (rv != SECSuccess) {
        LOG_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE);
        return SECFailure;
    }

    ssl_GetSpecReadLock(ss);
    rv = tls13_ComputeFinished(ss, baseKey, &hashes, PR_TRUE,
                               finishedBuf, &finishedLen, sizeof(finishedBuf));
    ssl_ReleaseSpecReadLock(ss);
    if (rv != SECSuccess) {
        LOG_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE);
        return SECFailure;
    }

    rv = ssl3_AppendHandshakeHeader(ss, finished, finishedLen);
    if (rv != SECSuccess) {
        return SECFailure; /* Error code already set. */
    }

    rv = ssl3_AppendHandshake(ss, finishedBuf, finishedLen);
    if (rv != SECSuccess) {
        return SECFailure; /* Error code already set. */
    }

    /* TODO(ekr@rtfm.com): Record key log */
    return SECSuccess;
}

static SECStatus
tls13_VerifyFinished(sslSocket *ss, PK11SymKey *secret,
                     SSL3Opaque *b, PRUint32 length,
                     const TLS13CombinedHash *hashes)
{
    SECStatus rv;
    PRUint8 finishedBuf[MAX_FINISHED_SIZE];
    unsigned int finishedLen;

    if (!hashes) {
        FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
        return SECFailure;
    }

    rv = tls13_ComputeFinished(ss, secret, hashes, PR_FALSE,
                               finishedBuf, &finishedLen, sizeof(finishedBuf));
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
        return SECFailure;
    }

    if (length != finishedLen) {
        FATAL_ERROR(ss, SSL_ERROR_RX_MALFORMED_FINISHED, decode_error);
        return SECFailure;
    }

    if (NSS_SecureMemcmp(b, finishedBuf, finishedLen) != 0) {
        FATAL_ERROR(ss, SSL_ERROR_BAD_HANDSHAKE_HASH_VALUE,
                    decrypt_error);
        return SECFailure;
    }

    return SECSuccess;
}

static SECStatus
tls13_ClientHandleFinished(sslSocket *ss, SSL3Opaque *b, PRUint32 length,
                           const TLS13CombinedHash *hashes)
{
    SECStatus rv;

    PORT_Assert(ss->opt.noLocks || ssl_HaveRecvBufLock(ss));
    PORT_Assert(ss->opt.noLocks || ssl_HaveSSL3HandshakeLock(ss));

    SSL_TRC(3, ("%d: TLS13[%d]: server handle finished handshake",
                SSL_GETPID(), ss->fd));

    rv = TLS13_CHECK_HS_STATE(ss, SSL_ERROR_RX_UNEXPECTED_FINISHED,
                              wait_finished);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    rv = tls13_VerifyFinished(ss, ss->ssl3.hs.hsTrafficSecret,
                              b, length, hashes);
    if (rv != SECSuccess)
        return SECFailure;

    return tls13_SendClientSecondRound(ss);
}

static SECStatus
tls13_ServerHandleFinished(sslSocket *ss, SSL3Opaque *b, PRUint32 length,
                           const TLS13CombinedHash *hashes)
{
    SECStatus rv;
    PK11SymKey *secret;

    PORT_Assert(ss->opt.noLocks || ssl_HaveRecvBufLock(ss));
    PORT_Assert(ss->opt.noLocks || ssl_HaveSSL3HandshakeLock(ss));

    SSL_TRC(3, ("%d: TLS13[%d]: server handle finished handshake",
                SSL_GETPID(), ss->fd));

    rv = TLS13_CHECK_HS_STATE(ss, SSL_ERROR_RX_UNEXPECTED_FINISHED, wait_finished,
                              wait_0rtt_finished);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    if (TLS13_IN_HS_STATE(ss, wait_finished)) {
        secret = ss->ssl3.hs.hsTrafficSecret;
    } else {
        secret = ss->ssl3.hs.earlyTrafficSecret;
    }

    rv = tls13_VerifyFinished(ss, secret, b, length, hashes);
    if (rv != SECSuccess)
        return SECFailure;

    if (TLS13_IN_HS_STATE(ss, wait_0rtt_finished)) {
        /* Reset the hashes. */
        PORT_Assert(ss->ssl3.hs.sha);
        PORT_Assert(ss->ssl3.hs.clientHelloHash);
        PK11_DestroyContext(ss->ssl3.hs.sha, PR_TRUE);
        ss->ssl3.hs.sha = ss->ssl3.hs.clientHelloHash;
        ss->ssl3.hs.clientHelloHash = NULL;

        ssl_GetXmitBufLock(ss);
        rv = tls13_SendServerHelloSequence(ss);
        ssl_ReleaseXmitBufLock(ss);
        if (rv != SECSuccess) {
            FATAL_ERROR(ss, PORT_GetError(), handshake_failure);
            return SECFailure;
        }
    } else {
        rv = tls13_SetCipherSpec(ss, TrafficKeyApplicationData,
                                 CipherSpecRead, PR_TRUE);
        if (rv != SECSuccess) {
            FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
            return SECFailure;
        }

        rv = tls13_FinishHandshake(ss);
        if (rv != SECSuccess) {
            return SECFailure; /* Error code and alerts handled below */
        }
        ssl_GetXmitBufLock(ss);
        if (ss->opt.enableSessionTickets &&
            ss->ssl3.hs.kea_def->authKeyType != ssl_auth_psk) {
            /* TODO(ekr@rtfm.com): Add support for new tickets in PSK
             * (bug 1281034).*/
            rv = tls13_SendNewSessionTicket(ss);
            if (rv != SECSuccess) {
                ssl_ReleaseXmitBufLock(ss);
                return SECFailure; /* Error code and alerts handled below */
            }
            rv = ssl3_FlushHandshake(ss, 0);
        }
        ssl_ReleaseXmitBufLock(ss);
        if (rv != SECSuccess)
            return SECFailure;
    }

    return SECSuccess;
}

static SECStatus
tls13_FinishHandshake(sslSocket *ss)
{
    SECStatus rv;

    PORT_Assert(ss->opt.noLocks || ssl_HaveRecvBufLock(ss));
    PORT_Assert(ss->opt.noLocks || ssl_HaveSSL3HandshakeLock(ss));
    PORT_Assert(ss->ssl3.hs.restartTarget == NULL);

    rv = tls13_ComputeFinalSecrets(ss);
    if (rv != SECSuccess)
        return SECFailure;

    /* The first handshake is now completed. */
    ss->handshake = NULL;

    /* Don't need this. */
    PK11_FreeSymKey(ss->ssl3.hs.hsTrafficSecret);
    ss->ssl3.hs.hsTrafficSecret = NULL;

    TLS13_SET_HS_STATE(ss, idle_handshake);

    ssl_FinishHandshake(ss);

    return SECSuccess;
}

static SECStatus
tls13_SendClientSecondRound(sslSocket *ss)
{
    SECStatus rv;
    PRBool sendClientCert;

    PORT_Assert(ss->opt.noLocks || ssl_HaveRecvBufLock(ss));
    PORT_Assert(ss->opt.noLocks || ssl_HaveSSL3HandshakeLock(ss));

    sendClientCert = !ss->ssl3.sendEmptyCert &&
                     ss->ssl3.clientCertChain != NULL &&
                     ss->ssl3.clientPrivateKey != NULL;

    /* Defer client authentication sending if we are still waiting for server
     * authentication.  This avoids unnecessary disclosure of client credentials
     * to an unauthenticated server.
     */
    if (ss->ssl3.hs.restartTarget) {
        PR_NOT_REACHED("unexpected ss->ssl3.hs.restartTarget");
        PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
        return SECFailure;
    }
    if (ss->ssl3.hs.authCertificatePending) {
        SSL_TRC(3, ("%d: TLS13[%d]: deferring ssl3_SendClientSecondRound because"
                    " certificate authentication is still pending.",
                    SSL_GETPID(), ss->fd));
        ss->ssl3.hs.restartTarget = tls13_SendClientSecondRound;
        return SECWouldBlock;
    }

    if (ss->ssl3.hs.zeroRttState != ssl_0rtt_none) {
        if (ss->ssl3.hs.zeroRttState == ssl_0rtt_accepted) {
            rv = tls13_SendEndOfEarlyData(ss);
            if (rv != SECSuccess) {
                return SECFailure; /* Error code already set. */
            }
        }
        if (IS_DTLS(ss) && !ss->ssl3.hs.helloRetry) {
            /* Reset the counters so that the next epoch isn't set
             * incorrectly. */
            tls13_SetNullCipherSpec(ss, &ss->ssl3.cwSpec);
        }
    }

    rv = tls13_SetCipherSpec(ss, TrafficKeyHandshake,
                             CipherSpecWrite, PR_FALSE);
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, SSL_ERROR_INIT_CIPHER_SUITE_FAILURE, internal_error);
        return SECFailure;
    }

    rv = tls13_ComputeApplicationSecrets(ss);
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
        return SECFailure;
    }

    rv = tls13_SetCipherSpec(ss, TrafficKeyApplicationData,
                             CipherSpecRead, PR_FALSE);
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
        return SECFailure;
    }

    ssl_GetXmitBufLock(ss); /*******************************/
    if (ss->ssl3.sendEmptyCert) {
        ss->ssl3.sendEmptyCert = PR_FALSE;
        rv = ssl3_SendEmptyCertificate(ss);
        /* Don't send verify */
        if (rv != SECSuccess) {
            goto loser; /* error code is set. */
        }
    } else if (sendClientCert) {
        rv = ssl3_SendCertificate(ss);
        if (rv != SECSuccess) {
            goto loser; /* error code is set. */
        }
    }
    if (ss->ssl3.hs.certificateRequest) {
        PORT_FreeArena(ss->ssl3.hs.certificateRequest->arena, PR_FALSE);
        ss->ssl3.hs.certificateRequest = NULL;
    }

    if (sendClientCert) {
        rv = tls13_SendCertificateVerify(ss, ss->ssl3.clientPrivateKey);
        SECKEY_DestroyPrivateKey(ss->ssl3.clientPrivateKey);
        ss->ssl3.clientPrivateKey = NULL;
        if (rv != SECSuccess) {
            goto loser; /* err is set. */
        }
    }

    rv = tls13_SendFinished(ss, ss->ssl3.hs.hsTrafficSecret);
    if (rv != SECSuccess) {
        goto loser; /* err code was set. */
    }
    rv = ssl3_FlushHandshake(ss, IS_DTLS(ss) ? ssl_SEND_FLAG_NO_RETRANSMIT : 0);
    if (rv != SECSuccess) {
        goto loser;
    }

    rv = dtls_StartHolddownTimer(ss);
    if (rv != SECSuccess) {
        goto loser; /* err code was set. */
    }
    ssl_ReleaseXmitBufLock(ss); /*******************************/

    rv = tls13_SetCipherSpec(ss, TrafficKeyApplicationData,
                             CipherSpecWrite, PR_TRUE);
    if (rv != SECSuccess) {
        PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
        return SECFailure;
    }

    /* The handshake is now finished */
    return tls13_FinishHandshake(ss);

loser:
    ssl_ReleaseXmitBufLock(ss); /*******************************/
    FATAL_ERROR(ss, PORT_GetError(), internal_error);
    return SECFailure;
}

/*
    enum { (65535) } TicketExtensionType;

    struct {
        TicketExtensionType extension_type;
        opaque extension_data<0..2^16-1>;
    } TicketExtension;

    struct {
        uint32 ticket_lifetime;
        uint32 flags;
        uint32 ticket_age_add;
        TicketExtension extensions<2..2^16-2>;
        opaque ticket<0..2^16-1>;
    } NewSessionTicket;
*/
static SECStatus
tls13_SendNewSessionTicket(sslSocket *ss)
{
    PRUint16 message_length;
    SECItem ticket_data = { 0, NULL, 0 };
    PRUint32 flags = ticket_allow_dhe_resumption;
    SECStatus rv;
    NewSessionTicket ticket = { 0 };

    ticket.flags = 0;
    if (ss->opt.enable0RttData) {
        ticket.flags |= ticket_allow_early_data;
    }
    ticket.ticket_lifetime_hint = TLS_EX_SESS_TICKET_LIFETIME_HINT;
    /* Generate a random value to add to ticket age. */
    rv = PK11_GenerateRandom((PRUint8 *)&ticket.ticket_age_add,
                             sizeof(ticket.ticket_age_add));
    if (rv != SECSuccess)
        goto loser;

    rv = ssl3_EncodeSessionTicket(ss, &ticket, &ticket_data);
    if (rv != SECSuccess)
        goto loser;

    message_length =
        4 + /* lifetime */
        4 + /* flags */
        4 + /* ticket_age_add */
        2 + /* empty extensions */
        2 + /* ticket length */
        ticket_data.len;

    rv = ssl3_AppendHandshakeHeader(ss, new_session_ticket,
                                    message_length);
    if (rv != SECSuccess)
        goto loser;

    /* This is a fixed value. */
    rv = ssl3_AppendHandshakeNumber(ss, TLS_EX_SESS_TICKET_LIFETIME_HINT, 4);
    if (rv != SECSuccess)
        goto loser;

    /* Currently we only allow DHE resumption
     * TODO(ekr@rtfm.com): Update when we add PSK-resumption and 0-RTT.
     */
    if (ss->opt.enable0RttData) {
        flags |= ticket_allow_early_data;
    }
    rv = ssl3_AppendHandshakeNumber(ss, flags, sizeof(flags));
    if (rv != SECSuccess)
        goto loser;

    rv = ssl3_AppendHandshakeNumber(ss, ticket.ticket_age_add,
                                    sizeof(ticket.ticket_age_add));
    if (rv != SECSuccess)
        goto loser;

    /* No extensions. */
    rv = ssl3_AppendHandshakeNumber(ss, 0, 2);
    if (rv != SECSuccess)
        goto loser;

    /* Encode the ticket. */
    rv = ssl3_AppendHandshakeVariable(
        ss, ticket_data.data, ticket_data.len, 2);
    if (rv != SECSuccess)
        goto loser;

    rv = SECSuccess;

loser:
    if (ticket_data.data) {
        SECITEM_FreeItem(&ticket_data, PR_FALSE);
    }
    return rv;
}

static SECStatus
tls13_HandleNewSessionTicket(sslSocket *ss, SSL3Opaque *b, PRUint32 length)
{
    SECStatus rv;
    PRInt32 tmp;
    PRUint32 tmpu;
    NewSessionTicket ticket;
    SECItem data;

    SSL_TRC(3, ("%d: TLS13[%d]: handle new session ticket message",
                SSL_GETPID(), ss->fd));

    rv = TLS13_CHECK_HS_STATE(ss, SSL_ERROR_RX_UNEXPECTED_NEW_SESSION_TICKET,
                              idle_handshake);
    if (rv != SECSuccess) {
        return SECFailure;
    }
    if (!ss->firstHsDone || ss->sec.isServer) {
        FATAL_ERROR(ss, SSL_ERROR_RX_UNEXPECTED_NEW_SESSION_TICKET,
                    unexpected_message);
        return SECFailure;
    }

    ticket.received_timestamp = ssl_Time();
    tmp = ssl3_ConsumeHandshakeNumber(ss, 4, &b, &length);
    if (tmp < 0) {
        FATAL_ERROR(ss, SSL_ERROR_RX_MALFORMED_NEW_SESSION_TICKET,
                    decode_error);
        return SECFailure;
    }
    ticket.ticket_lifetime_hint = (PRUint32)tmp;
    ticket.ticket.type = siBuffer;

    /* Flags. */
    rv = ssl3_ConsumeHandshake(ss, &tmpu, 4, &b, &length);
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, SSL_ERROR_RX_MALFORMED_NEW_SESSION_TICKET,
                    decode_error);
        return SECFailure;
    }
    ticket.flags = PR_ntohl(tmpu);

    rv = ssl3_ConsumeHandshake(ss, &tmpu, 4, &b, &length);
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, SSL_ERROR_RX_MALFORMED_NEW_SESSION_TICKET,
                    decode_error);
        return SECFailure;
    }
    ticket.ticket_age_add = (PRUint32)tmpu;

    /* Parse and discard extensions. */
    rv = ssl3_ConsumeHandshakeVariable(ss, &data, 2, &b, &length);
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, SSL_ERROR_RX_MALFORMED_NEW_SESSION_TICKET,
                    decode_error);
        return SECFailure;
    }

    rv = ssl3_ConsumeHandshakeVariable(ss, &data, 2, &b, &length);
    if (rv != SECSuccess || length != 0 || !data.len) {
        FATAL_ERROR(ss, SSL_ERROR_RX_MALFORMED_NEW_SESSION_TICKET,
                    decode_error);
        return SECFailure;
    }

    /* TODO(ekr@rtfm.com): Re-enable new tickets when PSK mode is
     * in use. I believe this works, but I can't test it until the
     * server side supports it. Bug 1257047.
     */
    if (!ss->opt.noCache && ss->sec.cache &&
        ss->ssl3.hs.kea_def->authKeyType != ssl_auth_psk) {

        /* Uncache so that we replace. */
        (*ss->sec.uncache)(ss->sec.ci.sid);

        /* We only support DHE resumption so any ticket which doesn't
         * support it we don't cache, but it can evict previous
         * cache entries. */
        if (!(ticket.flags & ticket_allow_dhe_resumption)) {
            return SECSuccess;
        }

        rv = SECITEM_CopyItem(NULL, &ticket.ticket, &data);
        if (rv != SECSuccess) {
            FATAL_ERROR(ss, SEC_ERROR_NO_MEMORY, internal_error);
            return SECFailure;
        }
        PRINT_BUF(50, (ss, "Caching session ticket",
                       ticket.ticket.data,
                       ticket.ticket.len));

        ssl3_SetSIDSessionTicket(ss->sec.ci.sid, &ticket);
        PORT_Assert(!ticket.ticket.data);

        rv = ssl3_FillInCachedSID(ss, ss->sec.ci.sid);
        if (rv != SECSuccess)
            return SECFailure;

        /* Cache the session. */
        ss->sec.ci.sid->cached = never_cached;
        (*ss->sec.cache)(ss->sec.ci.sid);
    }

    return SECSuccess;
}

typedef enum {
    ExtensionNotUsed,
    ExtensionClientOnly,
    ExtensionSendClear,
    ExtensionSendEncrypted,
} Tls13ExtensionStatus;

static const struct {
    SSLExtensionType ex_value;
    Tls13ExtensionStatus status;
} KnownExtensions[] = {
    { ssl_server_name_xtn, ExtensionSendEncrypted },
    { ssl_supported_groups_xtn, ExtensionSendEncrypted },
    { ssl_ec_point_formats_xtn, ExtensionNotUsed },
    { ssl_signature_algorithms_xtn, ExtensionClientOnly },
    { ssl_use_srtp_xtn, ExtensionSendEncrypted },
    { ssl_app_layer_protocol_xtn, ExtensionSendEncrypted },
    { ssl_padding_xtn, ExtensionNotUsed },
    { ssl_extended_master_secret_xtn, ExtensionNotUsed },
    { ssl_session_ticket_xtn, ExtensionClientOnly },
    { ssl_tls13_key_share_xtn, ExtensionSendClear },
    { ssl_tls13_pre_shared_key_xtn, ExtensionSendClear },
    { ssl_tls13_early_data_xtn, ExtensionSendEncrypted },
    { ssl_next_proto_nego_xtn, ExtensionNotUsed },
    { ssl_renegotiation_info_xtn, ExtensionNotUsed },
    { ssl_signed_cert_timestamp_xtn, ExtensionSendEncrypted },
    { ssl_cert_status_xtn, ExtensionSendEncrypted },
    { ssl_tls13_draft_version_xtn, ExtensionClientOnly }
};

PRBool
tls13_ExtensionAllowed(PRUint16 extension, SSL3HandshakeType message)
{
    unsigned int i;

    PORT_Assert((message == client_hello) ||
                (message == server_hello) ||
                (message == encrypted_extensions));

    for (i = 0; i < PR_ARRAY_SIZE(KnownExtensions); i++) {
        if (KnownExtensions[i].ex_value == extension)
            break;
    }
    if (i == PR_ARRAY_SIZE(KnownExtensions)) {
        /* We have never heard of this extension which is OK on
         * the server but not the client. */
        return message == client_hello;
    }

    switch (KnownExtensions[i].status) {
        case ExtensionNotUsed:
            return PR_FALSE;
        case ExtensionClientOnly:
            return message == client_hello;
        case ExtensionSendClear:
            return message == client_hello ||
                   message == server_hello;
        case ExtensionSendEncrypted:
            return message == client_hello ||
                   message == encrypted_extensions;
    }

    PORT_Assert(0);

    /* Not reached */
    return PR_TRUE;
}

/* TLS 1.3 doesn't actually have additional data but the aead function
 * signature overloads additional data to carry the record sequence
 * number and that's what we put here. The TLS 1.3 AEAD functions
 * just use this input as the sequence number and not as additional
 * data. */
static void
tls13_FormatAdditionalData(PRUint8 *aad, unsigned int length,
                           sslSequenceNumber seqNum)
{
    PRUint8 *ptr = aad;

    PORT_Assert(length == 8);
    ptr = ssl_EncodeUintX(seqNum, 8, ptr);
    PORT_Assert((ptr - aad) == length);
}

SECStatus
tls13_ProtectRecord(sslSocket *ss,
                    ssl3CipherSpec *cwSpec,
                    SSL3ContentType type,
                    const SSL3Opaque *pIn,
                    PRUint32 contentLen,
                    sslBuffer *wrBuf)
{
    const ssl3BulkCipherDef *cipher_def = cwSpec->cipher_def;
    SECStatus rv;
    PRUint16 headerLen;
    int cipherBytes = 0;
    const int tagLen = cipher_def->tag_size;

    SSL_TRC(3, ("%d: TLS13[%d]: spec=%d (%s) protect record 0x%0llx len=%u",
                SSL_GETPID(), ss->fd, cwSpec, cwSpec->phase,
                cwSpec->write_seq_num, contentLen));

    PORT_Assert(cipher_def->max_records <= RECORD_SEQ_MAX);
    if ((cwSpec->write_seq_num & RECORD_SEQ_MAX) >= cipher_def->max_records) {
        SSL_TRC(3, ("%d: TLS13[%d]: write sequence number at limit 0x%0llx",
                    SSL_GETPID(), ss->fd, cwSpec->write_seq_num));
        PORT_SetError(SSL_ERROR_TOO_MANY_RECORDS);
        return SECFailure;
    }

    headerLen = IS_DTLS(ss) ? DTLS_RECORD_HEADER_LENGTH : SSL3_RECORD_HEADER_LENGTH;

    if (headerLen + contentLen + 1 + tagLen > wrBuf->space) {
        PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
        return SECFailure;
    }

    /* Copy the data into the wrBuf. We're going to encrypt in-place
     * in the AEAD branch anyway */
    PORT_Memcpy(wrBuf->buf + headerLen, pIn, contentLen);

    if (cipher_def->calg == ssl_calg_null) {
        /* Shortcut for plaintext */
        cipherBytes = contentLen;
    } else {
        PRUint8 aad[8];
        PORT_Assert(cipher_def->type == type_aead);

        /* Add the content type at the end. */
        wrBuf->buf[headerLen + contentLen] = type;

        /* Stomp the content type to be application_data */
        type = content_application_data;

        tls13_FormatAdditionalData(aad, sizeof(aad), cwSpec->write_seq_num);
        cipherBytes = contentLen + 1; /* Room for the content type on the end. */
        rv = cwSpec->aead(
            ss->sec.isServer ? &cwSpec->server : &cwSpec->client,
            PR_FALSE,                               /* do encrypt */
            wrBuf->buf + headerLen,                 /* output  */
            &cipherBytes,                           /* out len */
            wrBuf->space - headerLen,               /* max out */
            wrBuf->buf + headerLen, contentLen + 1, /* input   */
            aad, sizeof(aad));
        if (rv != SECSuccess) {
            PORT_SetError(SSL_ERROR_ENCRYPTION_FAILURE);
            return SECFailure;
        }
    }

    PORT_Assert(cipherBytes <= MAX_FRAGMENT_LENGTH + 256);

    wrBuf->len = cipherBytes + headerLen;
    wrBuf->buf[0] = type;

    if (IS_DTLS(ss)) {
        (void)ssl_EncodeUintX(
            dtls_TLSVersionToDTLSVersion(kDtlsRecordVersion), 2,
            &wrBuf->buf[1]);
        (void)ssl_EncodeUintX(cwSpec->write_seq_num, 8, &wrBuf->buf[3]);
        (void)ssl_EncodeUintX(cipherBytes, 2, &wrBuf->buf[11]);
    } else {
        (void)ssl_EncodeUintX(kTlsRecordVersion, 2, &wrBuf->buf[1]);
        (void)ssl_EncodeUintX(cipherBytes, 2, &wrBuf->buf[3]);
    }
    ++cwSpec->write_seq_num;

    return SECSuccess;
}

/* Unprotect a TLS 1.3 record and leave the result in plaintext.
 *
 * Called by ssl3_HandleRecord. Caller must hold the spec read lock.
 * Therefore, we MUST not call SSL3_SendAlert().
 *
 * If SECFailure is returned, we:
 * 1. Set |*alert| to the alert to be sent.
 * 2. Call PORT_SetError() witn an appropriate code.
 */
SECStatus
tls13_UnprotectRecord(sslSocket *ss, SSL3Ciphertext *cText, sslBuffer *plaintext,
                      SSL3AlertDescription *alert)
{
    ssl3CipherSpec *crSpec = ss->ssl3.crSpec;
    const ssl3BulkCipherDef *cipher_def = crSpec->cipher_def;
    PRUint8 aad[8];
    SECStatus rv;

    *alert = bad_record_mac; /* Default alert for most issues. */

    SSL_TRC(3, ("%d: TLS13[%d]: spec=%d (%s) unprotect record 0x%0llx len=%u",
                SSL_GETPID(), ss->fd, crSpec, crSpec->phase,
                crSpec->read_seq_num, cText->buf->len));

    /* We can perform this test in variable time because the record's total
     * length and the ciphersuite are both public knowledge. */
    if (cText->buf->len < cipher_def->tag_size) {
        SSL_TRC(3,
                ("%d: TLS13[%d]: record too short to contain valid AEAD data",
                 SSL_GETPID(), ss->fd));
        PORT_SetError(SSL_ERROR_BAD_MAC_READ);
        return SECFailure;
    }

    /* Verify that the content type is right, even though we overwrite it. */
    if (cText->type != content_application_data) {
        SSL_TRC(3,
                ("%d: TLS13[%d]: record has invalid exterior content type=%d",
                 SSL_GETPID(), ss->fd, cText->type));
        /* Do we need a better error here? */
        PORT_SetError(SSL_ERROR_BAD_MAC_READ);
        return SECFailure;
    }

    /* Check the version number in the record */
    if ((IS_DTLS(ss) && cText->version != kDtlsRecordVersion) ||
        (!IS_DTLS(ss) && cText->version != kTlsRecordVersion)) {
        /* Do we need a better error here? */
        PORT_SetError(SSL_ERROR_BAD_MAC_READ);
        return SECFailure;
    }

    /* Decrypt */
    PORT_Assert(cipher_def->type == type_aead);
    tls13_FormatAdditionalData(aad, sizeof(aad),
                               IS_DTLS(ss) ? cText->seq_num
                                           : crSpec->read_seq_num);
    rv = crSpec->aead(
        ss->sec.isServer ? &crSpec->client : &crSpec->server,
        PR_TRUE,                /* do decrypt */
        plaintext->buf,         /* out */
        (int *)&plaintext->len, /* outlen */
        plaintext->space,       /* maxout */
        cText->buf->buf,        /* in */
        cText->buf->len,        /* inlen */
        aad, sizeof(aad));
    if (rv != SECSuccess) {
        SSL_TRC(3,
                ("%d: TLS13[%d]: record has bogus MAC",
                 SSL_GETPID(), ss->fd));
        PORT_SetError(SSL_ERROR_BAD_MAC_READ);
        return SECFailure;
    }

    /* The record is right-padded with 0s, followed by the true
     * content type, so read from the right until we receive a
     * nonzero byte. */
    while (plaintext->len > 0 && !(plaintext->buf[plaintext->len - 1])) {
        --plaintext->len;
    }

    /* Bogus padding. */
    if (plaintext->len < 1) {
        /* It's safe to report this specifically because it happened
         * after the MAC has been verified. */
        PORT_SetError(SSL_ERROR_BAD_BLOCK_PADDING);
        return SECFailure;
    }

    /* Record the type. */
    cText->type = plaintext->buf[plaintext->len - 1];
    --plaintext->len;

    return SECSuccess;
}

/* 0-RTT is only permitted if:
 *
 * 1. We are doing TLS 1.3
 * 2. This isn't a second ClientHello (in response to HelloRetryRequest)
 * 3. The 0-RTT option is set.
 * 4. We have a valid ticket.
 * 5. The server is willing to accept 0-RTT.
 * 6. We have not changed our ALPN settings to disallow the ALPN tag
 *    in the ticket.
 *
 * Called from tls13_ClientSendEarlyDataXtn().
 */
PRBool
tls13_ClientAllow0Rtt(sslSocket *ss, const sslSessionID *sid)
{
    if (sid->version < SSL_LIBRARY_VERSION_TLS_1_3)
        return PR_FALSE;
    if (ss->ssl3.hs.helloRetry)
        return PR_FALSE;
    if (!ss->opt.enable0RttData)
        return PR_FALSE;
    if (!ss->xtnData.ticketTimestampVerified &&
        !ssl3_ClientExtensionAdvertised(ss, ssl_tls13_pre_shared_key_xtn))
        return PR_FALSE;
    if ((sid->u.ssl3.locked.sessionTicket.flags & ticket_allow_early_data) == 0)
        return PR_FALSE;
    return tls13_AlpnTagAllowed(ss, &sid->u.ssl3.alpnSelection);
}

SECStatus
tls13_MaybeDo0RTTHandshake(sslSocket *ss)
{
    SECStatus rv;
    int bufferLen = ss->ssl3.hs.messages.len;

    /* Don't do anything if this is the second ClientHello or we decided not to
     * do 0-RTT (which means that there is no early_data extension). */
    if (ss->ssl3.hs.zeroRttState != ssl_0rtt_sent) {
        return SECSuccess;
    }

    SSL_TRC(3, ("%d: TLS13[%d]: in 0-RTT mode", SSL_GETPID(), ss->fd));

    rv = tls13_RecoverWrappedSharedSecret(ss, ss->sec.ci.sid);
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
        return SECFailure;
    }

    /* Set the ALPN data as if it was negotiated. We check in the ServerHello
     * handler that the server negotiates the same value. */
    if (ss->sec.ci.sid->u.ssl3.alpnSelection.len) {
        ss->ssl3.nextProtoState = SSL_NEXT_PROTO_EARLY_VALUE;
        rv = SECITEM_CopyItem(NULL, &ss->ssl3.nextProto,
                              &ss->sec.ci.sid->u.ssl3.alpnSelection);
        if (rv != SECSuccess)
            return rv;
    }

    /* Need to do this first so we know the PRF for the early secret
     * computation. */
    rv = ssl3_SetCipherSuite(ss, ss->sec.ci.sid->u.ssl3.cipherSuite, PR_FALSE);
    if (rv != SECSuccess)
        return rv;
    ss->ssl3.hs.preliminaryInfo = 0; /* TODO(ekr@rtfm.com) Fill this in.
                                      * bug 1281255. */
    rv = tls13_ComputeEarlySecrets(ss, PR_TRUE);
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
        return SECFailure;
    }

    ssl_GetSpecReadLock(ss);
    ss->ssl3.hs.nullSpec = ss->ssl3.cwSpec;
    tls13_CipherSpecAddRef(ss->ssl3.hs.nullSpec);
    ssl_ReleaseSpecReadLock(ss);

    rv = tls13_SetCipherSpec(ss, TrafficKeyEarlyHandshake,
                             CipherSpecWrite, PR_FALSE);
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
        return SECFailure;
    }

    rv = tls13_SendFinished(ss, ss->ssl3.hs.earlyTrafficSecret);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    /* Restore the handshake hashes to where they were before we
     * sent Finished. */
    ss->ssl3.hs.messages.len = bufferLen;

    /* We can destroy the early traffic secret now. */
    rv = tls13_SetCipherSpec(ss, TrafficKeyEarlyApplicationData,
                             CipherSpecWrite, PR_TRUE);
    if (rv != SECSuccess) {
        return rv;
    }

    return SECSuccess;
}

PRInt32
tls13_Read0RttData(sslSocket *ss, void *buf, PRInt32 len)
{
    TLS13EarlyData *msg;

    PORT_Assert(!PR_CLIST_IS_EMPTY(&ss->ssl3.hs.bufferedEarlyData));
    msg = (TLS13EarlyData *)PR_NEXT_LINK(&ss->ssl3.hs.bufferedEarlyData);

    PR_REMOVE_LINK(&msg->link);
    if (msg->data.len > len) {
        PORT_SetError(SSL_ERROR_ILLEGAL_PARAMETER_ALERT);
        return SECFailure;
    }
    len = msg->data.len;

    PORT_Memcpy(buf, msg->data.data, msg->data.len);
    SECITEM_ZfreeItem(&msg->data, PR_FALSE);
    PORT_ZFree(msg, sizeof(*msg));

    return len;
}

/* 0-RTT data will be followed by a different cipher spec; this resets the
 * current spec to the null spec so that the following state can be set as
 * though 0-RTT didn't happen. TODO: work out if this is the best plan. */
static void
tls13_SetNullCipherSpec(sslSocket *ss, ssl3CipherSpec **specp)
{
    PORT_Assert(ss->ssl3.hs.nullSpec);

    ssl_GetSpecWriteLock(ss);
    tls13_CipherSpecRelease(*specp);
    *specp = ss->ssl3.hs.nullSpec;
    ssl_ReleaseSpecWriteLock(ss);
    ss->ssl3.hs.nullSpec = NULL;
}

static SECStatus
tls13_SendEndOfEarlyData(sslSocket *ss)
{
    SECStatus rv;

    SSL_TRC(3, ("%d: TLS13[%d]: send end_of_early_data extension",
                SSL_GETPID(), ss->fd));

    rv = SSL3_SendAlert(ss, alert_warning, end_of_early_data);
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
        return SECFailure;
    }

    ss->ssl3.hs.zeroRttState = ssl_0rtt_done;
    return SECSuccess;
}

SECStatus
tls13_HandleEndOfEarlyData(sslSocket *ss)
{
    SECStatus rv;

    if (ss->version < SSL_LIBRARY_VERSION_TLS_1_3 ||
        ss->ssl3.hs.zeroRttState != ssl_0rtt_accepted) {
        (void)SSL3_SendAlert(ss, alert_fatal, unexpected_message);
        PORT_SetError(SSL_ERROR_END_OF_EARLY_DATA_ALERT);
        return SECFailure;
    }

    PORT_Assert(TLS13_IN_HS_STATE(ss, ss->opt.requestCertificate ? wait_client_cert : wait_finished));

    if (IS_DTLS(ss)) {
        /* Reset the cipher spec so that the epoch counter is properly reset. */
        tls13_SetNullCipherSpec(ss, &ss->ssl3.crSpec);
    }

    rv = tls13_SetCipherSpec(ss, TrafficKeyHandshake,
                             CipherSpecRead, PR_FALSE);
    if (rv != SECSuccess) {
        PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
        return SECFailure;
    }

    ss->ssl3.hs.zeroRttState = ssl_0rtt_done;
    return SECSuccess;
}

SECStatus
tls13_HandleEarlyApplicationData(sslSocket *ss, sslBuffer *origBuf)
{
    TLS13EarlyData *ed;
    SECItem it = { siBuffer, NULL, 0 };

    PORT_Assert(ss->sec.isServer);
    PORT_Assert(ss->ssl3.hs.zeroRttState == ssl_0rtt_accepted);
    if (ss->ssl3.hs.zeroRttState != ssl_0rtt_accepted) {
        /* Belt and suspenders. */
        FATAL_ERROR(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
        return SECFailure;
    }

    PRINT_BUF(3, (NULL, "Received early application data",
                  origBuf->buf, origBuf->len));
    ed = PORT_ZNew(TLS13EarlyData);
    if (!ed) {
        FATAL_ERROR(ss, SEC_ERROR_NO_MEMORY, internal_error);
        return SECFailure;
    }
    it.data = origBuf->buf;
    it.len = origBuf->len;
    if (SECITEM_CopyItem(NULL, &ed->data, &it) != SECSuccess) {
        FATAL_ERROR(ss, SEC_ERROR_NO_MEMORY, internal_error);
        return SECFailure;
    }
    PR_APPEND_LINK(&ed->link, &ss->ssl3.hs.bufferedEarlyData);

    origBuf->len = 0; /* So ssl3_GatherAppDataRecord will keep looping. */

    return SECSuccess;
}
