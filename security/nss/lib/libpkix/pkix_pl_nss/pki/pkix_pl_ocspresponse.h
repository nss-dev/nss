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
 * pkix_pl_ocspresponse.h
 *
 * OcspResponse Object Definitions
 *
 */

#ifndef _PKIX_PL_OCSPRESPONSE_H
#define _PKIX_PL_OCSPRESPONSE_H

#include "pkix_pl_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_OCSP_RESPONSE_LEN (64*1024)

struct PKIX_PL_OcspResponseStruct{
        const SEC_HttpClientFcn *httpClient;
        SEC_HTTP_SERVER_SESSION serverSession;
        SEC_HTTP_REQUEST_SESSION requestSession;
        /* Use name that differentiates this SECItem from encodedRequest */
        SECItem *encodedResponse;
        CERTOCSPResponse *decoded; /* We don't deal with decodedRequest */
        CERTCertificate *issuerCert;
        CERTCertificate *signerCert;
        CERTOCSPCertID *certID;
        PKIX_Boolean clientIsDefault;
        PKIX_PL_Date *validityTime;
        PRArenaPool *arena;
};

/* see source file for function documentation */

PKIX_Error *
pkix_pl_OcspResponse_Create(
        PKIX_PL_OcspRequest *request,
        void *responder,
        void **pNBIOContext,
        PKIX_PL_OcspResponse **pResponse,
        void *plContext);

PKIX_Error *
pkix_pl_OcspResponse_Decode(
        PKIX_PL_OcspResponse *response,
        PKIX_Boolean *pPassed,
        void *plContext);

PKIX_Error *
pkix_pl_OcspResponse_GetStatus(
        PKIX_PL_OcspResponse *response,
        PKIX_Boolean *pPassed,
        void *plContext);

PKIX_Error *
pkix_pl_OcspResponse_VerifySignature(
        PKIX_PL_OcspResponse *response,
        PKIX_PL_Cert *cert,
        PKIX_Boolean *pPassed,
        void *plContext);

PKIX_Error *
pkix_pl_OcspResponse_GetStatusForCert(
        PKIX_PL_OcspResponse *response,
        PKIX_Boolean *pPassed,
        void *plContext);

PKIX_Error *pkix_pl_OcspResponse_RegisterSelf(void *plContext);

#ifdef __cplusplus
}
#endif

#endif /* _PKIX_PL_OCSPRESPONSE_H */
