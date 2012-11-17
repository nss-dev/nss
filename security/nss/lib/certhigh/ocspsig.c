/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "prerror.h"
#include "prprf.h"
#include "plarena.h"
#include "prnetdb.h"

#include "seccomon.h"
#include "secitem.h"
#include "secoidt.h"
#include "secasn1.h"
#include "secder.h"
#include "cert.h"
#include "xconst.h"
#include "secerr.h"
#include "secoid.h"
#include "hasht.h"
#include "sechash.h"
#include "secasn1.h"
#include "keyhi.h"
#include "cryptohi.h"
#include "ocsp.h"
#include "ocspti.h"
#include "ocspi.h"
#include "genname.h"
#include "certxutl.h"
#include "pk11func.h"   /* for PK11_HashBuf */
#include <stdarg.h>
#include <plhash.h>


extern const SEC_ASN1Template ocsp_ResponderIDByNameTemplate[];
extern const SEC_ASN1Template ocsp_ResponderIDByKeyTemplate[];

extern const SEC_ASN1Template ocsp_RevokedInfoTemplate[];

extern const SEC_ASN1Template ocsp_SingleResponseTemplate[];
extern const SEC_ASN1Template ocsp_ResponseDataTemplate[];

extern const SEC_ASN1Template ocsp_OCSPResponseTemplate[];
extern const SEC_ASN1Template ocsp_ResponseBytesTemplate[];
extern const SEC_ASN1Template ocsp_PointerToResponseBytesTemplate[];

SEC_ASN1_MKSUB(SECOID_AlgorithmIDTemplate)
SEC_ASN1_MKSUB(SEC_NullTemplate)

ocspCertStatus*
ocsp_CreateCertStatus(PLArenaPool *arena,
                      ocspCertStatusType status,
                      PRTime revocationTime)
{
    if (!arena) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return NULL;
    }

    switch (status) {
        case ocspCertStatus_good:
        case ocspCertStatus_unknown:
        case ocspCertStatus_revoked:
            break;
        default:
            PORT_SetError(SEC_ERROR_INVALID_ARGS);
            return NULL;
    }
    
    ocspCertStatus *cs = PORT_ArenaZNew(arena, ocspCertStatus);
    if (!cs)
        return NULL;
    cs->certStatusType = status;
    switch (status) {
        case ocspCertStatus_good:
            cs->certStatusInfo.goodInfo = SECITEM_AllocItem(arena, NULL, 0);
            if (!cs->certStatusInfo.goodInfo)
                return NULL;
            break;
        case ocspCertStatus_unknown:
            cs->certStatusInfo.unknownInfo = SECITEM_AllocItem(arena, NULL, 0);
            if (!cs->certStatusInfo.unknownInfo)
                return NULL;
            break;
        case ocspCertStatus_revoked:
            cs->certStatusInfo.revokedInfo =
                PORT_ArenaZNew(arena, ocspRevokedInfo);
            if (!cs->certStatusInfo.revokedInfo)
                return NULL;
            cs->certStatusInfo.revokedInfo->revocationReason =
                SECITEM_AllocItem(arena, NULL, 0);
            if (!cs->certStatusInfo.revokedInfo->revocationReason)
                return NULL;
            if (DER_TimeToGeneralizedTimeArena(arena,
                    &cs->certStatusInfo.revokedInfo->revocationTime,
                    revocationTime) != SECSuccess)
                return NULL;
            break;
        default:
            PORT_Assert(PR_FALSE);
    }
    return cs;
}

#ifdef DEBUG_kaie
void dump_item_to_file(SECItem *item, const char *filename)
{
    FILE *fp = fopen(filename, "wb");
    if (fp) {
        fwrite(item->data, item->len, 1, fp);
        fclose(fp);
        fprintf(stderr, "wrote item with %d bytes\n", item->len);
    }
}
#endif

const SEC_ASN1Template ocsp_EncodeRevokedInfoTemplate[] = {
    { SEC_ASN1_GENERALIZED_TIME,
        offsetof(ocspRevokedInfo, revocationTime) },
    { SEC_ASN1_OPTIONAL | SEC_ASN1_EXPLICIT |
      SEC_ASN1_CONSTRUCTED | SEC_ASN1_CONTEXT_SPECIFIC| 0,
        offsetof(ocspRevokedInfo, revocationReason),
        SEC_ASN1_SUB(SEC_PointerToEnumeratedTemplate) },
    { 0 }
};

const SEC_ASN1Template ocsp_PointerToEncodeRevokedInfoTemplate[] = {
    { SEC_ASN1_POINTER, 0,
      ocsp_EncodeRevokedInfoTemplate }
};

const SEC_ASN1Template ocsp_CertStatusTemplate[] = {
    { SEC_ASN1_CHOICE, offsetof(ocspCertStatus, certStatusType),
        0, sizeof(ocspCertStatus) },
    { SEC_ASN1_CONTEXT_SPECIFIC | 0,
        0, SEC_ASN1_SUB(SEC_NullTemplate), ocspCertStatus_good },
    { SEC_ASN1_EXPLICIT | SEC_ASN1_CONSTRUCTED |
      SEC_ASN1_CONTEXT_SPECIFIC | 1,
        offsetof(ocspCertStatus, certStatusInfo.revokedInfo),
        ocsp_PointerToEncodeRevokedInfoTemplate, ocspCertStatus_revoked },
    { SEC_ASN1_CONTEXT_SPECIFIC | 2,
        0, SEC_ASN1_SUB(SEC_NullTemplate), ocspCertStatus_unknown },
    { 0 }
};

const SEC_ASN1Template ocsp_EncodeBasicOCSPResponseTemplate[] = {
    { SEC_ASN1_SEQUENCE,
        0, NULL, sizeof(ocspBasicOCSPResponse) },
    { SEC_ASN1_POINTER,
        offsetof(ocspBasicOCSPResponse, tbsResponseData),
        ocsp_ResponseDataTemplate },
    { SEC_ASN1_INLINE | SEC_ASN1_XTRN,
        offsetof(ocspBasicOCSPResponse, responseSignature.signatureAlgorithm),
        SEC_ASN1_SUB(SECOID_AlgorithmIDTemplate) },
    { SEC_ASN1_BIT_STRING,
        offsetof(ocspBasicOCSPResponse, responseSignature.signature) },
    { SEC_ASN1_OPTIONAL | SEC_ASN1_EXPLICIT |
      SEC_ASN1_CONSTRUCTED | SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_XTRN | 0,
        offsetof(ocspBasicOCSPResponse, responseSignature.derCerts),
        SEC_ASN1_SUB(SEC_SequenceOfAnyTemplate) },
    { 0 }
};

CERTOCSPSingleResponse*
ocsp_CreateSingleResponse(PLArenaPool *arena,
                          CERTOCSPCertID *id, ocspCertStatus *status,
                          PRTime thisUpdate, PRTime *nextUpdate)
{
    CERTOCSPSingleResponse *sr;

    if (!arena || !id || !status) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return NULL;
    }

    sr = PORT_ArenaZNew(arena, CERTOCSPSingleResponse);
    if (!sr)
        return NULL;
    sr->arena = arena;
    sr->certID = id;
    sr->certStatus = status;
    if (DER_TimeToGeneralizedTimeArena(arena, &sr->thisUpdate, thisUpdate)
             != SECSuccess)
        return NULL;
    sr->nextUpdate = NULL;
    if (nextUpdate) {
        sr->nextUpdate = SECITEM_AllocItem(arena, NULL, 0);
        if (!sr->nextUpdate)
            return NULL;
        if (DER_TimeToGeneralizedTimeArena(arena, sr->nextUpdate, *nextUpdate)
             != SECSuccess)
            return NULL;
    }

    sr->singleExtensions = PORT_ArenaNewArray(arena, CERTCertExtension*, 1);
    if (!sr->singleExtensions)
        return NULL;

    sr->singleExtensions[0] = NULL;
    
    if (!SEC_ASN1EncodeItem(arena, &sr->derCertStatus,
                            status, ocsp_CertStatusTemplate))
        return NULL;

    return sr;
}

CERTOCSPSingleResponse*
OCSP_CreateSingleResponseGood(PLArenaPool *arena,
                              CERTOCSPCertID *id,
                              PRTime thisUpdate, PRTime *nextUpdate)
{
    if (!arena) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return NULL;
    }
    ocspCertStatus * cs =
        ocsp_CreateCertStatus(arena, ocspCertStatus_good, 0);
    if (!cs)
        return NULL;
    return ocsp_CreateSingleResponse(arena, id, cs, thisUpdate, nextUpdate);
}

CERTOCSPSingleResponse*
OCSP_CreateSingleResponseUnknown(PLArenaPool *arena,
                                 CERTOCSPCertID *id,
                                 PRTime thisUpdate, PRTime *nextUpdate)
{
    if (!arena) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return NULL;
    }
    ocspCertStatus * cs =
        ocsp_CreateCertStatus(arena, ocspCertStatus_unknown, 0);
    if (!cs)
        return NULL;
    return ocsp_CreateSingleResponse(arena, id, cs, thisUpdate, nextUpdate);
}

CERTOCSPSingleResponse*
OCSP_CreateSingleResponseRevoked(PLArenaPool *arena,
                                 CERTOCSPCertID *id,
                                 PRTime thisUpdate, PRTime *nextUpdate,
                                 PRTime revocationTime)
{
    if (!arena) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return NULL;
    }
    ocspCertStatus * cs =
        ocsp_CreateCertStatus(arena, ocspCertStatus_revoked, revocationTime);
    if (!cs)
        return NULL;
    return ocsp_CreateSingleResponse(arena, id, cs, thisUpdate, nextUpdate);
}

SECItem*
OCSP_CreateSuccessResponseEncodedBasicV1(PLArenaPool *arena,
                                         CERTCertificate *responderCert,
                                         PRBool idByName, /* false: by key */
                                         PRTime producedAt,
                                         CERTOCSPSingleResponse **responses,
                                         void *wincx)
{
    PLArenaPool *tmpArena;
    ocspResponseData *rd = NULL;
    ocspResponderID *rid = NULL;
    ocspBasicOCSPResponse *br = NULL;
    ocspResponseBytes *rb = NULL;
    CERTOCSPResponse *response = NULL;
    
    SECOidTag algID;
    SECOidData *od = NULL;
    SECKEYPrivateKey *privKey = NULL;
    SECItem *result = NULL;
  
    if (!arena || !responderCert || !responses) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return NULL;
    }

    tmpArena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if (!tmpArena)
        return NULL;

    rd = PORT_ArenaZNew(tmpArena, ocspResponseData);
    if (!rd)
        goto done;
    rid = PORT_ArenaZNew(tmpArena, ocspResponderID);
    if (!rid)
        goto done;
    br = PORT_ArenaZNew(tmpArena, ocspBasicOCSPResponse);
    if (!br)
        goto done;
    rb = PORT_ArenaZNew(tmpArena, ocspResponseBytes);
    if (!rb)
        goto done;
    response = PORT_ArenaZNew(tmpArena, CERTOCSPResponse);
    if (!response)
        goto done;
    
    rd->version.data=NULL;
    rd->version.len=0;
    rd->responseExtensions = NULL;
    rd->responses = responses;
    if (DER_TimeToGeneralizedTimeArena(tmpArena, &rd->producedAt, producedAt)
            != SECSuccess)
        goto done;
    if (idByName) {
        rid->responderIDType = ocspResponderID_byName;
        if (CERT_CopyName(tmpArena, &rid->responderIDValue.name,
                           &responderCert->subject) != SECSuccess)
            goto done;
    }
    else {
        rid->responderIDType = ocspResponderID_byKey;
        if (!CERT_GetSPKIDigest(tmpArena, responderCert, SEC_OID_SHA1,
                                      &rid->responderIDValue.keyHash))
            goto done;
    }

    if (!SEC_ASN1EncodeItem(tmpArena, &rd->derResponderID, rid,
            idByName ? ocsp_ResponderIDByNameTemplate : ocsp_ResponderIDByKeyTemplate))
        goto done;

    br->tbsResponseData = rd;
    
    if (!SEC_ASN1EncodeItem(tmpArena, &br->tbsResponseDataDER, br->tbsResponseData,
            ocsp_ResponseDataTemplate))
        goto done;

    br->responseSignature.derCerts = PORT_ArenaNewArray(tmpArena, SECItem*, 1);
    if (!br->responseSignature.derCerts)
        goto done;
    br->responseSignature.derCerts[0] = NULL;

    privKey = PK11_FindKeyByAnyCert(responderCert, wincx);
    if (!privKey)
        goto done;

    algID = SEC_GetSignatureAlgorithmOidTag(privKey->keyType, SEC_OID_SHA1);
    if (algID == SEC_OID_UNKNOWN)
        goto done;

    if (SEC_SignData(&br->responseSignature.signature,
                        br->tbsResponseDataDER.data, br->tbsResponseDataDER.len,
                        privKey, algID)
            != SECSuccess)
        goto done;

    /* convert len-in-bytes to len-in-bits */
    br->responseSignature.signature.len = br->responseSignature.signature.len << 3;

    /* br->responseSignature.signature wasn't allocated from arena,
     * we must free it when done. */

#ifdef DEBUG_kaie
    dump_item_to_file(&br->responseSignature.signature, "/tmp/sig");
#endif

    if (SECOID_SetAlgorithmID(tmpArena, &br->responseSignature.signatureAlgorithm, algID, 0)
            != SECSuccess)
        goto done;

    if (!SEC_ASN1EncodeItem(tmpArena, &rb->response, br,
                            ocsp_EncodeBasicOCSPResponseTemplate))
        goto done;

#ifdef DEBUG_kaie
    dump_item_to_file(&rb->response, "/tmp/basic");
#endif

    rb->responseTypeTag = SEC_OID_PKIX_OCSP_BASIC_RESPONSE;

    od = SECOID_FindOIDByTag(rb->responseTypeTag);
    if (!od)
        goto done;

    rb->responseType = od->oid;
    rb->decodedResponse.basic = br;

    response->arena = tmpArena;
    response->responseBytes = rb;
    response->statusValue = ocspResponse_successful;

    if (!SEC_ASN1EncodeInteger(tmpArena, &response->responseStatus,
                               response->statusValue))
        goto done;

    result = SEC_ASN1EncodeItem(arena, NULL, response, ocsp_OCSPResponseTemplate);

#ifdef DEBUG_kaie
    if (result)
        dump_item_to_file(result, "/tmp/item");
#endif

done:
    if (privKey)
        SECKEY_DestroyPrivateKey(privKey);
    if (br->responseSignature.signature.data)
        SECITEM_FreeItem(&br->responseSignature.signature, PR_FALSE);
    PORT_FreeArena(tmpArena, PR_FALSE);

    return result;
}

static const SEC_ASN1Template ocsp_OCSPFailureResponseTemplate[] = {
    { SEC_ASN1_SEQUENCE,
        0, NULL, sizeof(CERTOCSPResponse) },
    { SEC_ASN1_ENUMERATED,
        offsetof(CERTOCSPResponse, responseStatus) },
    { 0, 0,
        SEC_ASN1_SUB(SEC_NullTemplate) },
    { 0 }
};

SECItem*
OCSP_CreateFailureResponse(PLArenaPool *arena, PRErrorCode reason)
{
    CERTOCSPResponse response;
    SECItem *result = NULL;

    switch (reason) {
        case SEC_ERROR_OCSP_MALFORMED_REQUEST:
            response.statusValue = ocspResponse_malformedRequest;
            break;
        case SEC_ERROR_OCSP_SERVER_ERROR:
            response.statusValue = ocspResponse_internalError;
            break;
        case SEC_ERROR_OCSP_TRY_SERVER_LATER:
            response.statusValue = ocspResponse_tryLater;
            break;
        case SEC_ERROR_OCSP_REQUEST_NEEDS_SIG:
            response.statusValue = ocspResponse_sigRequired;
            break;
        case SEC_ERROR_OCSP_UNAUTHORIZED_REQUEST:
            response.statusValue = ocspResponse_unauthorized;
            break;
        default:
            PORT_SetError(SEC_ERROR_INVALID_ARGS);
            return NULL;
    }

    if (!SEC_ASN1EncodeInteger(NULL, &response.responseStatus,
                               response.statusValue))
        return NULL;

    result = SEC_ASN1EncodeItem(arena, NULL, &response, ocsp_OCSPFailureResponseTemplate);

    SECITEM_FreeItem(&response.responseStatus, PR_FALSE);

    return result;
}
