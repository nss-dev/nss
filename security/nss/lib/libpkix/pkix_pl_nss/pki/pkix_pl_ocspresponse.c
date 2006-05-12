/* ***** BEGIN LICENSE BLOCK *****
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
 *   Sun Microsystems
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
/*
 * pkix_pl_ocspresponse.c
 *
 */

#include "pkix_pl_ocspresponse.h"

/* --Private-OcspResponse-Functions------------------------------------- */

/*
 * FUNCTION: pkix_pl_OcspResponse_Destroy
 * (see comments for PKIX_PL_DestructorCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_pl_OcspResponse_Destroy(
        PKIX_PL_Object *object,
        void *plContext)
{
        PKIX_PL_OcspResponse *ocspRsp = NULL;
        const SEC_HttpClientFcnV1 *hcv1 = NULL;

        PKIX_ENTER(OCSPRESPONSE, "pkix_pl_OcspResponse_Destroy");
        PKIX_NULLCHECK_ONE(object);

        PKIX_CHECK(pkix_CheckType(object, PKIX_OCSPRESPONSE_TYPE, plContext),
                    "Object is not an OcspResponse");

        ocspRsp = (PKIX_PL_OcspResponse *)object;

        PKIX_DECREF(ocspRsp->validityTime);

        if (ocspRsp->issuerCert != NULL) {
                PKIX_PL_NSSCALL(OCSPRESPONSE, CERT_DestroyCertificate,
                        (ocspRsp->issuerCert));
        }

        if (ocspRsp->signerCert != NULL) {
                PKIX_PL_NSSCALL(OCSPRESPONSE, CERT_DestroyCertificate,
                        (ocspRsp->signerCert));
        }

        if (ocspRsp->encodedResponse != NULL) {
                PKIX_PL_NSSCALL(OCSPRESPONSE, SECITEM_FreeItem,
                        (ocspRsp->encodedResponse, PR_TRUE));
        }

        if (ocspRsp->decoded != NULL) {
                PKIX_PL_NSSCALL(OCSPRESPONSE, CERT_DestroyOCSPResponse,
                        (ocspRsp->decoded));
        }

        hcv1 = (const SEC_HttpClientFcnV1 *)(ocspRsp->httpClient);

        if (ocspRsp->requestSession != NULL) {
                PKIX_PL_NSSCALL(OCSPRESPONSE, hcv1->freeFcn,
                        (ocspRsp->requestSession));
        }

        if (ocspRsp->serverSession != NULL) {
                PKIX_PL_NSSCALL(OCSPRESPONSE, hcv1->freeSessionFcn,
                        (ocspRsp->serverSession));
        }

        if (ocspRsp->clientIsDefault == PKIX_FALSE) {
                /* destroy ocspRsp->httpClient */
        }

        if (ocspRsp->arena != NULL) {
                PORT_FreeArena(ocspRsp->arena, PR_FALSE);
        }

cleanup:

        PKIX_RETURN(OCSPRESPONSE);
}

/*
 * FUNCTION: pkix_pl_OcspResponse_Hashcode
 * (see comments for PKIX_PL_HashcodeCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_pl_OcspResponse_Hashcode(
        PKIX_PL_Object *object,
        PKIX_UInt32 *pHashcode,
        void *plContext)
{
        PKIX_PL_OcspResponse *ocspRsp = NULL;

        PKIX_ENTER(OCSPRESPONSE, "pkix_pl_OcspResponse_Hashcode");
        PKIX_NULLCHECK_TWO(object, pHashcode);

        PKIX_CHECK(pkix_CheckType(object, PKIX_OCSPRESPONSE_TYPE, plContext),
                    "Object is not an OcspResponse");

        ocspRsp = (PKIX_PL_OcspResponse *)object;

        if (ocspRsp->encodedResponse->data == NULL) {
                *pHashcode = 0;
        } else {
                PKIX_CHECK(pkix_hash
                        (ocspRsp->encodedResponse->data,
                        ocspRsp->encodedResponse->len,
                        pHashcode,
                        plContext),
                        "pkix_hash failed");
        }

cleanup:

        PKIX_RETURN(OCSPRESPONSE);

}

/*
 * FUNCTION: pkix_pl_OcspResponse_Equals
 * (see comments for PKIX_PL_Equals_Callback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_pl_OcspResponse_Equals(
        PKIX_PL_Object *firstObj,
        PKIX_PL_Object *secondObj,
        PKIX_Boolean *pResult,
        void *plContext)
{
        PKIX_UInt32 secondType = 0;
        PKIX_UInt32 firstLen = 0;
        PKIX_UInt32 i = 0;
        PKIX_PL_OcspResponse *rsp1 = NULL;
        PKIX_PL_OcspResponse *rsp2 = NULL;
        const unsigned char *firstData = NULL;
        const unsigned char *secondData = NULL;

        PKIX_ENTER(OCSPRESPONSE, "pkix_pl_OcspResponse_Equals");
        PKIX_NULLCHECK_THREE(firstObj, secondObj, pResult);

        /* test that firstObj is a OcspResponse */
        PKIX_CHECK(pkix_CheckType(firstObj, PKIX_OCSPRESPONSE_TYPE, plContext),
                    "firstObj argument is not an OcspResponse");

        /*
         * Since we know firstObj is a OcspResponse, if both references are
         * identical, they must be equal
         */
        if (firstObj == secondObj){
                *pResult = PKIX_TRUE;
                goto cleanup;
        }

        /*
         * If secondObj isn't a OcspResponse, we don't throw an error.
         * We simply return a Boolean result of FALSE
         */
        *pResult = PKIX_FALSE;
        PKIX_CHECK(PKIX_PL_Object_GetType(secondObj, &secondType, plContext),
                "Could not get type of second argument");
        if (secondType != PKIX_OCSPRESPONSE_TYPE) {
                goto cleanup;
        }

        rsp1 = (PKIX_PL_OcspResponse *)firstObj;
        rsp2 = (PKIX_PL_OcspResponse *)secondObj;

        /* If either lacks an encoded string, they cannot be compared */
        firstData = (const unsigned char *)rsp1->encodedResponse->data;
        secondData = (const unsigned char *)rsp2->encodedResponse->data;
        if ((firstData == NULL) || (secondData == NULL)) {
                goto cleanup;
        }

        firstLen = rsp1->encodedResponse->len;

        if (firstLen != rsp2->encodedResponse->len) {
                goto cleanup;
        }

        for (i = 0; i < firstLen; i++) {
                if (*firstData++ != *secondData++) {
                        goto cleanup;
                }
        }

        *pResult = PKIX_TRUE;

cleanup:

        PKIX_RETURN(OCSPRESPONSE);
}

/*
 * FUNCTION: pkix_pl_OcspResponse_RegisterSelf
 * DESCRIPTION:
 *  Registers PKIX_OCSPRESPONSE_TYPE and its related functions with
 *  systemClasses[]
 * PARAMETERS:
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Not Thread Safe - for performance and complexity reasons
 *
 *  Since this function is only called by PKIX_PL_Initialize, which should
 *  only be called once, it is acceptable that this function is not
 *  thread-safe.
 */
PKIX_Error *
pkix_pl_OcspResponse_RegisterSelf(void *plContext)
{
        extern pkix_ClassTable_Entry systemClasses[PKIX_NUMTYPES];
        pkix_ClassTable_Entry entry;

        PKIX_ENTER(OCSPRESPONSE, "pkix_pl_OcspResponse_RegisterSelf");

        entry.description = "OcspResponse";
        entry.destructor = pkix_pl_OcspResponse_Destroy;
        entry.equalsFunction = pkix_pl_OcspResponse_Equals;
        entry.hashcodeFunction = pkix_pl_OcspResponse_Hashcode;
        entry.toStringFunction = NULL;
        entry.comparator = NULL;
        entry.duplicateFunction = pkix_duplicateImmutable;

        systemClasses[PKIX_OCSPRESPONSE_TYPE] = entry;

        PKIX_RETURN(OCSPRESPONSE);
}

/* --Public-Functions------------------------------------------------------- */

/*
 * FUNCTION: pkix_pl_OcspResponse_Create
 * DESCRIPTION:
 *
 *  This function transmits the OcspRequest pointed to by "request" and obtains
 *  an OcspResponse, which it stores at "pOcspResponse". If the HTTPClient
 *  supports non-blocking I/O this function may store a non-NULL value at
 *  "pNBIOContext" (the WOULDBLOCK condition). In that case the caller should
 *  make a subsequent call with the same value in "pNBIOContext" and
 *  "pOcspResponse" to resume the operation. Additional WOULDBLOCK returns may
 *  occur; the caller should persist until a return occurs with NULL stored at
 *  "pNBIOContext".
 *
 *  The contents of "request" are ignored on calls subsequent to a WOULDBLOCK
 *  return, and the caller is permitted to supply NULL.
 *
 * PARAMETERS
 *  "request"
 *      Address of the OcspRequest for which a response is desired.
 *  "pNBIOContext"
 *      Address at which platform-dependent information is stored for handling
 *      of non-blocking I/O. Must be non-NULL.
 *  "pOcspResponse"
 *      The address where the created OcspResponse is stored. Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns an OcspResponse Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
pkix_pl_OcspResponse_Create(
        PKIX_PL_OcspRequest *request,
        void *responder,
        void **pNBIOContext,
        PKIX_PL_OcspResponse **pResponse,
        void *plContext)
{
        void *nbioContext = NULL;
        PKIX_PL_OcspResponse *ocspResponse = NULL;
        const SEC_HttpClientFcn *httpClient = NULL;
        const SEC_HttpClientFcnV1 *hcv1 = NULL;
        SECStatus rv = SECFailure;
        char *location = NULL;
        char *hostname = NULL;
        char *path = NULL;
        PRUint16 port = 0;
        SEC_HTTP_SERVER_SESSION serverSession = NULL;
        SEC_HTTP_REQUEST_SESSION requestSession = NULL;
        SECItem *encodedRequest = NULL;
        PRUint16 responseCode = 0;
        char *responseData = NULL;
        PRUint32 responseDataLen = 0;
        PRArenaPool *arena = NULL;

        PKIX_ENTER(OCSPRESPONSE, "pkix_pl_OcspResponse_Create");
        PKIX_NULLCHECK_TWO(pNBIOContext, pResponse);

        nbioContext = *pNBIOContext;
        *pNBIOContext = NULL;

        if (nbioContext != NULL) {

                ocspResponse = *pResponse;
                PKIX_NULLCHECK_ONE(ocspResponse);

                httpClient = ocspResponse->httpClient;
                serverSession = ocspResponse->serverSession;
                requestSession = ocspResponse->requestSession;
                PKIX_NULLCHECK_THREE(httpClient, serverSession, requestSession);

        } else {

                PKIX_NULLCHECK_ONE(request);

                PKIX_CHECK(pkix_pl_OcspRequest_GetEncoded
                        (request, &encodedRequest, plContext),
                        "pkix_pl_OcspRequest_GetEncoded failed");

                /* prepare initial message to HTTPClient */

                /* Is there a default responder and is it enabled? */
                if (!responder) {
                        PKIX_PL_NSSCALLRV
                                (OCSPRESPONSE,
                                responder,
                                (void *)GetRegisteredHttpClient,
                                ());
                }

                httpClient = (const SEC_HttpClientFcn *)responder;

                if (httpClient && (httpClient->version == 1)) {

                        hcv1 = &(httpClient->fcnTable.ftable1);

                        PKIX_CHECK(pkix_pl_OcspRequest_GetLocation
                                (request, &location, plContext),
                                "pkix_pl_OcspRequest_GetLocation failed");

                        /* parse location -> hostname, port, path */    
                        PKIX_PL_NSSCALLRV(OCSPRESPONSE, rv, CERT_ParseURL,
                                (location, &hostname, &port, &path));

                        if ((hostname == NULL) || (path == NULL)) {
                                PKIX_ERROR("URL Parsing failed");
                        }

                        PKIX_PL_NSSCALLRV
                                (OCSPRESPONSE,
                                rv,
                                hcv1->createSessionFcn,
                                (hostname, port, &serverSession));

                        if (rv != SECSuccess) {
                                PKIX_ERROR("OCSP Server Error");
                        }       

                        PKIX_PL_NSSCALLRV
                                (OCSPRESPONSE, rv, hcv1->createFcn,
                                (serverSession,
                                "http",
                                path,
                                "POST",
                                PR_TicksPerSecond() * 60,
                                &requestSession));

                        if (rv != SECSuccess) {
                                PKIX_ERROR("OCSP Server Error");
                        }       

                        PKIX_PL_NSSCALLRV
                                (OCSPRESPONSE, rv, hcv1->setPostDataFcn,
                                (requestSession,
                                (char *)encodedRequest->data,
                                encodedRequest->len,
                                "application/ocsp-request"));

                        if (rv != SECSuccess) {
                                PKIX_ERROR("OCSP Server Error");
                        }       

                        /* create a PKIX_PL_OcspResponse object */
                        PKIX_CHECK(PKIX_PL_Object_Alloc
                                    (PKIX_OCSPRESPONSE_TYPE,
                                    sizeof (PKIX_PL_OcspResponse),
                                    (PKIX_PL_Object **)&ocspResponse,
                                    plContext),
                                    "Could not create object");

                        ocspResponse->httpClient = httpClient;
                        ocspResponse->serverSession = serverSession;
                        ocspResponse->requestSession = requestSession;
                        ocspResponse->encodedResponse = NULL;
                        ocspResponse->decoded = NULL;
                        ocspResponse->issuerCert = NULL;
                        ocspResponse->signerCert = NULL;
                        ocspResponse->clientIsDefault = PKIX_FALSE;
                        ocspResponse->validityTime = NULL;
                        ocspResponse->arena = NULL;

                        PKIX_CHECK(pkix_pl_OcspRequest_GetCertID
                                (request, &ocspResponse->certID, plContext),
                                "pkix_pl_OcspRequest_GetCertID failed");
                }
        }

        /* begin or resume IO to HTTPClient */
        if (httpClient && (httpClient->version == 1)) {

                hcv1 = &(httpClient->fcnTable.ftable1);

                responseDataLen = MAX_OCSP_RESPONSE_LEN;

                PKIX_PL_NSSCALLRV(OCSPRESPONSE, rv, hcv1->trySendAndReceiveFcn,
                        (requestSession,
                        (PRPollDesc **)&nbioContext,
                        &responseCode,
                        NULL,   /* responseContentType */
                        NULL,   /* responseHeaders */
                        (const char **)&responseData,
                        &responseDataLen));

                if (rv != SECSuccess) {
                        PKIX_ERROR("OCSP Server Error");
                }       

                if (nbioContext != NULL) {
                        *pNBIOContext = nbioContext;
                        goto cleanup;
                }

                if (responseCode != 200) {
                        PKIX_ERROR("Bad Http Response");
                }


                PKIX_PL_NSSCALLRV(OCSPRESPONSE, arena, PORT_NewArena,
                        (DER_DEFAULT_CHUNKSIZE));

                if (arena == NULL) {
                        PKIX_ERROR("Out of Memory");
                }

                ocspResponse->arena = arena;

                PKIX_PL_NSSCALLRV
                        (OCSPRESPONSE,
                        ocspResponse->encodedResponse,
                        SECITEM_AllocItem,
                        (arena, NULL, responseDataLen));

                if (ocspResponse->encodedResponse == NULL) {
                        PKIX_ERROR("Out of Memory");
                }

                PKIX_PL_NSSCALL(OCSPRESPONSE, PORT_Memcpy,
                        (ocspResponse->encodedResponse->data,
                        responseData,
                        responseDataLen));

        }

        *pResponse = ocspResponse;

cleanup:

        if (path != NULL) {
                PKIX_PL_NSSCALL(OCSPRESPONSE, PORT_Free, (path));
        }

        if (hostname != NULL) {
                PKIX_PL_NSSCALL(OCSPRESPONSE, PORT_Free, (hostname));
        }

        if (PKIX_ERROR_RECEIVED){
                PKIX_DECREF(ocspResponse);
        }

        PKIX_RETURN(OCSPRESPONSE);
}

/*
 * FUNCTION: pkix_pl_OcspResponse_Decode
 * DESCRIPTION:
 *
 *  This function decodes the DER data contained in the OcspResponse pointed to
 *  by "response", storing PKIX_TRUE at "pPassed" if the decoding was
 *  successful, and PKIX_FALSE otherwise.
 *
 * PARAMETERS
 *  "response"
 *      The address of the OcspResponse whose DER data is to be decoded. Must
 *      be non-NULL.
 *  "pPassed"
 *      Address at which the Boolean result is stored. Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns an OcspResponse Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */

PKIX_Error *
pkix_pl_OcspResponse_Decode(
        PKIX_PL_OcspResponse *response,
        PKIX_Boolean *pPassed,
        void *plContext)
{
        CERTOCSPResponse *decoded = NULL;

        PKIX_ENTER(OCSPRESPONSE, "PKIX_PL_OcspResponse_Decode");
        PKIX_NULLCHECK_TWO(response, response->encodedResponse);

        PKIX_PL_NSSCALLRV(OCSPRESPONSE, decoded, CERT_DecodeOCSPResponse,
                (response->encodedResponse));

        response->decoded = decoded;

        /*
         * If our caller wants better discrimination among the possible
         * sources of error, we will need to query PORT_GetError.
         */
        *pPassed = ((decoded == NULL) ? PKIX_FALSE : PKIX_TRUE);

        PKIX_RETURN(OCSPRESPONSE);
}

/*
 * FUNCTION: pkix_pl_OcspResponse_GetStatus
 * DESCRIPTION:
 *
 *  This function checks the response status of the OcspResponse pointed to
 *  by "response", storing PKIX_TRUE at "pPassed" if the responder understood
 *  the request and considered it valid, and PKIX_FALSE otherwise.
 *
 * PARAMETERS
 *  "response"
 *      The address of the OcspResponse whose status is to be retrieved. Must
 *      be non-NULL.
 *  "pPassed"
 *      Address at which the Boolean result is stored. Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns an OcspResponse Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */

PKIX_Error *
pkix_pl_OcspResponse_GetStatus(
        PKIX_PL_OcspResponse *response,
        PKIX_Boolean *pPassed,
        void *plContext)
{
        SECStatus rv = SECFailure;

        PKIX_ENTER(OCSPRESPONSE, "PKIX_PL_OcspResponse_GetStatus");
        PKIX_NULLCHECK_TWO(response, response->decoded);

        PKIX_PL_NSSCALLRV(OCSPRESPONSE, rv, CERT_GetOCSPResponseStatus,
                (response->decoded));

        *pPassed = ((rv == SECSuccess) ? PKIX_TRUE : PKIX_FALSE );

        PKIX_RETURN(OCSPRESPONSE);
}

/*
 * FUNCTION: pkix_pl_OcspResponse_VerifySignature
 * DESCRIPTION:
 *
 *  This function verifies the ocspResponse signature field in the OcspResponse
 *  pointed to by "response", storing PKIX_TRUE at "pPassed" if verification
 *  is successful and PKIX_FALSE otherwise.
 *
 * PARAMETERS
 *  "response"
 *      The address of the OcspResponse whose signature field is to be
 *      retrieved. Must be non-NULL.
 *  "pPassed"
 *      Address at which the Boolean result is stored. Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns an OcspResponse Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
pkix_pl_OcspResponse_VerifySignature(
        PKIX_PL_OcspResponse *response,
        PKIX_PL_Cert *cert,
        PKIX_Boolean *pPassed,
        void *plContext)
{
        SECStatus rv = SECFailure;
        CERTCertificate *issuerCert = NULL;
        CERTCertificate *signerCert = NULL;

        PKIX_ENTER(OCSPRESPONSE, "pkix_pl_OcspResponse_VerifySignature");
        PKIX_NULLCHECK_TWO(response, pPassed);

        PKIX_NULLCHECK_ONE(cert);

        PKIX_PL_NSSCALLRV(OCSPRESPONSE, issuerCert, CERT_FindCertIssuer, 
                (cert->nssCert, PR_Now(), certUsageAnyCA));

        response->issuerCert = issuerCert;

        PKIX_PL_NSSCALLRV
                (OCSPRESPONSE, rv, CERT_VerifyOCSPResponseSignature, 
                (response->decoded,
                CERT_GetDefaultCertDB(), /* CERTCertDBHandle *handle */
                NULL,                   /* void *pwArg */
                &signerCert,
                issuerCert));

        response->signerCert = signerCert;

        *pPassed = ((rv == SECSuccess) ? PKIX_TRUE : PKIX_FALSE );

        PKIX_RETURN(OCSPRESPONSE);
}

/*
 * FUNCTION: pkix_pl_OcspResponse_GetStatusForCert
 * DESCRIPTION:
 *
 *  This function checks the revocation status of the Cert for which the
 *  OcspResponse was obtained, storing PKIX_TRUE at "pPassed" if the Cert has
 *  not been revoked and PKIX_FALSE otherwise.
 *
 * PARAMETERS
 *  "response"
 *      The address of the OcspResponse whose certificate status is to be
 *      retrieved. Must be non-NULL.
 *  "pPassed"
 *      Address at which the Boolean result is stored. Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns an OcspResponse Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
pkix_pl_OcspResponse_GetStatusForCert(
        PKIX_PL_OcspResponse *response,
        PKIX_Boolean *pPassed,
        void *plContext)
{
        SECStatus rv = SECFailure;

        PKIX_ENTER(OCSPRESPONSE, "pkix_pl_OcspResponse_GetStatusForCert");
        PKIX_NULLCHECK_TWO(response, pPassed);

        /*
         * It is an error to call this function except following a successful
         * return from pkix_pl_OcspResponse_VerifySignature, which would have
         * set response->signerCert.
         */
        PKIX_NULLCHECK_ONE(response->signerCert);

        PKIX_PL_NSSCALLRV(OCSPRESPONSE, rv, CERT_GetOCSPStatusForCertID,
                (CERT_GetDefaultCertDB(), /* CERTCertDBHandle *handle */
                response->decoded,
                response->certID,
                response->signerCert,
                PR_Now()));

        *pPassed = ((rv == SECSuccess) ? PKIX_TRUE : PKIX_FALSE );

        PKIX_RETURN(OCSPRESPONSE);
}
