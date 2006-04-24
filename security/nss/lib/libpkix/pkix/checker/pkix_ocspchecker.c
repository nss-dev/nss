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
 * pkix_ocspchecker.c
 *
 * OcspChecker Object Functions
 *
 */

#include "pkix_ocspchecker.h"

/* --Private-Functions-------------------------------------------- */

/*
 * FUNCTION: pkix_OcspChecker_Destroy
 *      (see comments for PKIX_PL_DestructorCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_OcspChecker_Destroy(
        PKIX_PL_Object *object,
        void *plContext)
{
        PKIX_OcspChecker *checker = NULL;

        PKIX_ENTER(OCSPCHECKER, "pkix_OcspChecker_Destroy");
        PKIX_NULLCHECK_ONE(object);

        /* Check that this object is a ocsp checker */
        PKIX_CHECK(pkix_CheckType
                    (object, PKIX_OCSPCHECKER_TYPE, plContext),
                    "Object is not an ocsp checker");

        checker = (PKIX_OcspChecker *)object;

        PKIX_DECREF(checker->validityTime);

        /* These are not yet ref-counted objects */
        /* PKIX_DECREF(checker->passwordInfo); */
        /* PKIX_DECREF(checker->responder); */
        /* PKIX_DECREF(checker->nbioContext); */

cleanup:

        PKIX_RETURN(OCSPCHECKER);
}

/*
 * FUNCTION: pkix_OcspChecker_RegisterSelf
 * DESCRIPTION:
 *  Registers PKIX_OCSPCHECKER_TYPE and its related functions with
 *  systemClasses[]
 * THREAD SAFETY:
 *  Not Thread Safe - for performance and complexity reasons
 *
 *  Since this function is only called by PKIX_PL_Initialize, which should
 *  only be called once, it is acceptable that this function is not
 *  thread-safe.
 */
PKIX_Error *
pkix_OcspChecker_RegisterSelf(void *plContext)
{
        extern pkix_ClassTable_Entry systemClasses[PKIX_NUMTYPES];
        pkix_ClassTable_Entry entry;

        PKIX_ENTER(OCSPCHECKER, "pkix_OcspChecker_RegisterSelf");

        entry.description = "OcspChecker";
        entry.destructor = pkix_OcspChecker_Destroy;
        entry.equalsFunction = NULL;
        entry.hashcodeFunction = NULL;
        entry.toStringFunction = NULL;
        entry.comparator = NULL;
        entry.duplicateFunction = NULL;

        systemClasses[PKIX_OCSPCHECKER_TYPE] = entry;

        PKIX_RETURN(OCSPCHECKER);
}

/* --Public-Functions--------------------------------------------- */

/*
 * FUNCTION: pkix_OcspChecker_Check (see comments in pkix_checker.h)
 */

/*
 * The OCSPChecker is created in an idle state, and remains in this state until
 * either (a) the default Responder has been set and enabled, and a Check
 * request is received with no responder specified, or (b) a Check request is
 * received with a specified responder. A request message is constructed and
 * given to the HttpClient. If non-blocking I/O is used the client may return
 * with WOULDBLOCK, in which case the OCSPChecker returns the WOULDBLOCK
 * condition to its caller in turn. On a subsequent call the I/O is resumed.
 * When a response is received it is decoded and the results provided to the
 * caller.
 *
 */
static PKIX_Error *
pkix_OcspChecker_Check(
        PKIX_PL_Object *checkerObject,
        PKIX_PL_Cert *cert,
        void **pNBIOContext,
        PKIX_UInt32 *pResultCode,
        void *plContext)
{
        OCSP_ResultCode resultCode = OCSP_SUCCESS;
        PKIX_Boolean uriFound = PKIX_FALSE;
        PKIX_Boolean passed = PKIX_FALSE;
        PKIX_OcspChecker *checker = NULL;
        PKIX_PL_OcspRequest *request = NULL;
        PKIX_PL_OcspResponse *response = NULL;
        void *nbioContext = NULL;

        PKIX_ENTER(OCSPCHECKER, "pkix_OcspChecker_Check");
        PKIX_NULLCHECK_FOUR(checkerObject, cert, pNBIOContext, pResultCode);

        PKIX_CHECK(pkix_CheckType
                (checkerObject, PKIX_OCSPCHECKER_TYPE, plContext),
                "Object is not a OCSPChecker object");

        checker = (PKIX_OcspChecker *)checkerObject;

        nbioContext = *pNBIOContext;
        *pNBIOContext = 0;

        /* assert(checker->nbioContext == nbioContext) */

        if (nbioContext == 0) {
                /* We are initiating a check, not resuming previous I/O. */

                PKIX_INCREF(cert);
                checker->cert = cert;
                
                /* create request */
                PKIX_CHECK(pkix_pl_OcspRequest_Create
                        (cert,
                        NULL,           /* PKIX_PL_Date *validity */
                        PKIX_FALSE,     /* PKIX_Boolean addServiceLocator */
                        NULL,           /* PKIX_PL_Cert *signerCert */
                        &uriFound,
                        &request,
                        plContext),
                        "PKIX_PL_OcspRequest_Create failed");
                
                /* No uri to check is considered passing! */
                if (uriFound == PKIX_FALSE) {
                        passed = PKIX_TRUE;
                        resultCode = 0;
                        goto cleanup;
                }

        }

        /* send request and create response */
        PKIX_CHECK(pkix_pl_OcspResponse_Create
                (request,
                checker->responder,
                &nbioContext,
                &response,
                plContext),
                "pkix_pl_OcspResponse_Create failed");

        if (nbioContext != 0) {
                *pNBIOContext = nbioContext;
                goto cleanup;
        }

        PKIX_CHECK(pkix_pl_OcspResponse_Decode(response, &passed, plContext),
                "pkix_pl_OcspResponse_Decode failed");
                
        if (passed == PKIX_FALSE) {
                resultCode = OCSP_INVALIDRESPONSE;
                goto cleanup;
        }

        PKIX_CHECK(pkix_pl_OcspResponse_GetStatus(response, &passed, plContext),
                "pkix_pl_OcspResponse_GetStatus returned an error");
                
        if (passed == PKIX_FALSE) {
                resultCode = OCSP_BADRESPONSESTATUS;
                goto cleanup;
        }

        PKIX_CHECK(pkix_pl_OcspResponse_VerifySignature
                (response, cert, &passed, plContext),
                "pkix_pl_OcspResponse_VerifySignature failed");

        if (passed == PKIX_FALSE) {
                resultCode = OCSP_BADSIGNATURE;
                goto cleanup;
        }

        PKIX_CHECK(pkix_pl_OcspResponse_GetStatusForCert
                (response, &passed, plContext),
                "pkix_pl_OcspResponse_GetStatusForCert failed");

        if (passed == PKIX_FALSE) {
                resultCode = OCSP_CERTREVOKED;
        }

cleanup:
        *pResultCode = (PKIX_UInt32)resultCode;

        PKIX_DECREF(request);
        PKIX_DECREF(response);

        PKIX_RETURN(OCSPCHECKER);

}

/*
 * FUNCTION: PKIX_OcspChecker_Create (see comments in pkix_checker.h)
 */
PKIX_Error *
PKIX_OcspChecker_Create(
        PKIX_PL_Date *validityTime,
        void *passwordInfo,
        void *responder,
        PKIX_OcspChecker **pChecker,
        void *plContext)
{
        PKIX_OcspChecker *checkerObject = NULL;
        PKIX_RevocationChecker *revChecker = NULL;

        PKIX_ENTER(OCSPCHECKER, "PKIX_OcspChecker_Create");
        PKIX_NULLCHECK_ONE(pChecker);

        PKIX_CHECK(PKIX_PL_Object_Alloc
                    (PKIX_OCSPCHECKER_TYPE,
                    sizeof (PKIX_OcspChecker),
                    (PKIX_PL_Object **)&checkerObject,
                    plContext),
                    "Could not create cert chain checker object");

        /* initialize fields */
        PKIX_INCREF(validityTime);
        checkerObject->validityTime = validityTime;

        /* These void*'s will need INCREFs if they become PKIX_PL_Objects */
        checkerObject->passwordInfo = passwordInfo;
        checkerObject->responder = responder;
        checkerObject->nbioContext = NULL;

        PKIX_CHECK(PKIX_RevocationChecker_Create
                (pkix_OcspChecker_Check,
                (PKIX_PL_Object *)checkerObject,
                &revChecker,
                plContext),
                "PKIX_RevocationChecker_Create failed");

        *pChecker = (PKIX_OcspChecker *)revChecker;
cleanup:

        PKIX_RETURN(OCSPCHECKER);

}

/*
 * FUNCTION: PKIX_OcspChecker_SetPasswordInfo
 *      (see comments in pkix_checker.h)
 */
PKIX_Error *
PKIX_OcspChecker_SetPasswordInfo(
        PKIX_OcspChecker *checker,
        void *passwordInfo,
        void *plContext)
{
        PKIX_ENTER(OCSPCHECKER, "PKIX_OcspChecker_SetPasswordInfo");
        PKIX_NULLCHECK_ONE(checker);

        checker->passwordInfo = passwordInfo;

        PKIX_RETURN(OCSPCHECKER);
}

/*
 * FUNCTION: PKIX_OcspChecker_SetOCSPResponder
 *      (see comments in pkix_checker.h)
 */
PKIX_Error *
PKIX_OcspChecker_SetOCSPResponder(
        PKIX_OcspChecker *checker,
        void *ocspResponder,
        void *plContext)
{
        PKIX_ENTER(OCSPCHECKER, "PKIX_OcspChecker_SetOCSPResponder");
        PKIX_NULLCHECK_ONE(checker);

        checker->responder = ocspResponder;

        PKIX_RETURN(OCSPCHECKER);
}

