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
 * pkix_pl_ekuchecker.c
 *
 * User Defined ExtenedKeyUsage Function Definitions
 *
 */

#include "pkix_pl_ekuchecker.h"

char *ekuOidStrings[] = {
        "1.3.6.1.5.5.7.3.1",    /* id-kp-serverAuth */
        "1.3.6.1.5.5.7.3.2",    /* id-kp-clientAuth */
        "1.3.6.1.5.5.7.3.3",    /* id-kp-codeSigning */
        "1.3.6.1.5.5.7.3.4",    /* id-kp-emailProtection */
        "1.3.6.1.5.5.7.3.8",    /* id-kp-timeStamping */
        "1.3.6.1.5.5.7.3.9",    /* id-kp-OCSPSigning */
        NULL
};

#define CERTUSAGE_NONE (-1)

PKIX_Int32 ekuCertUsages[] = {
        1<<certUsageSSLServer,
        1<<certUsageSSLClient,
        1<<certUsageObjectSigner,
        1<<certUsageEmailRecipient | 1<<certUsageEmailSigner,
        CERTUSAGE_NONE,
        1<<certUsageStatusResponder
};

/*
 * FUNCTION: pkix_pl_EkuCheckerState_Destroy
 * (see comments for PKIX_PL_DestructorCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_pl_EkuCheckerState_Destroy(
        PKIX_PL_Object *object,
        void *plContext)
{
        pkix_pl_EkuCheckerState *ekuCheckerState = NULL;

        PKIX_ENTER(USERDEFINEDMODULES, "pkix_pl_EkuCheckerState_Destroy");
        PKIX_NULLCHECK_ONE(object);

        PKIX_CHECK(pkix_CheckType(object, PKIX_EKUCHECKERSTATE_TYPE, plContext),
                    "Object is not an EKU Checker State");

        ekuCheckerState = (pkix_pl_EkuCheckerState *)object;

        PKIX_DECREF(ekuCheckerState->ekuOID);

cleanup:

        PKIX_RETURN(USERDEFINEDMODULES);
}

/*
 * FUNCTION: pkix_pl_EkuChecker_GetRequiredEku
 *
 * DESCRIPTION:
 *  This function retrieves application specified ExtenedKeyUsage(s) from
 *  ComCertSetparams and converts its OID representations to SECCertUsageEnum.
 *  The result is stored and returned in bit mask at "pRequiredExtKeyUsage".
 *
 * PARAMETERS
 *  "certSelector"
 *      a PKIX_CertSelector links to PKIX_ComCertSelParams where a list of
 *      Extended Key Usage OIDs specified by application can be retrieved for
 *      verification. Must be non-NULL.
 *  "pRequiredExtKeyUsage"
 *      Address where the result is returned. Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 *
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 *
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a UserDefinedModules Error if the function fails in a non-fatal
 *  way.
 *  Returns a Fatal Error
 */
PKIX_Error *
pkix_pl_EkuChecker_GetRequiredEku(
        PKIX_CertSelector *certSelector,
        PKIX_UInt32 *pRequiredExtKeyUsage,
        void *plContext)
{
        PKIX_ComCertSelParams *comCertSelParams = NULL;
        PKIX_List *supportedOids = NULL;
        PKIX_List *requiredOid = NULL;
        PKIX_UInt32 requiredExtKeyUsage = 0;
        PKIX_UInt32 numItems = 0;
        PKIX_PL_OID *ekuOid = NULL;
        PKIX_UInt32 i;
        PKIX_Boolean isContained = PKIX_FALSE;

        PKIX_ENTER(USERDEFINEDMODULES, "pkix_pl_EkuChecker_GetRequiredEku");
        PKIX_NULLCHECK_TWO(certSelector, pRequiredExtKeyUsage);

        /* Get initial EKU OIDs from ComCertSelParams, if set */
        PKIX_CHECK(PKIX_CertSelector_GetCommonCertSelectorParams
                    (certSelector, &comCertSelParams, plContext),
                    "PKIX_CertSelector_GetCommonCertSelectorParams failed");

        if (comCertSelParams != NULL) {

                PKIX_CHECK(PKIX_ComCertSelParams_GetExtendedKeyUsage
                        (comCertSelParams, &requiredOid, plContext),
                        "PKIX_ComCertSelParams_GetExtendedKeyUsage failed");

        }

        /* Map application specified EKU OIDs to NSS SECCertUsageEnum */

        if (requiredOid != NULL) {

            PKIX_CHECK(PKIX_List_Create(&supportedOids, plContext),
                        "PKIX_List_Create failed");

            /* Create a supported OIDs list */
            i = 0;
            while (ekuOidStrings[i] != NULL) {

                    PKIX_CHECK(PKIX_PL_OID_Create
                                (ekuOidStrings[i],
                                &ekuOid,
                                plContext),
                                "PKIX_PL_OID_Create failed");

                    PKIX_CHECK(PKIX_List_AppendItem
                                (supportedOids,
                                (PKIX_PL_Object *)ekuOid,
                                plContext),
                                "PKIX_List_AppendItem failed");

                    PKIX_DECREF(ekuOid);
                    i++;
            }

            /* Map from OID's to SECCertUsageEnum */
            PKIX_CHECK(PKIX_List_GetLength
                        (supportedOids, &numItems, plContext),
                        "PKIX_List_GetLength failed");

            for (i = 0; i < numItems; i++) {

                    PKIX_CHECK(PKIX_List_GetItem
                        (supportedOids,
                        i,
                        (PKIX_PL_Object **)&ekuOid,
                        plContext),
                        "PKIX_List_GetItem failed");

                    PKIX_CHECK(pkix_List_Contains
                        (requiredOid,
                        (PKIX_PL_Object *)ekuOid,
                        &isContained,
                        plContext),
                        "PKIX_List_Contains failed");

                    PKIX_DECREF(ekuOid);

                    if (isContained == PKIX_TRUE &&
                        ekuCertUsages[i] != CERTUSAGE_NONE) {

                            requiredExtKeyUsage |= ekuCertUsages[i];
                    }
            }
        }

        *pRequiredExtKeyUsage = requiredExtKeyUsage;

cleanup:

        PKIX_DECREF(ekuOid);
        PKIX_DECREF(requiredOid);
        PKIX_DECREF(supportedOids);
        PKIX_DECREF(comCertSelParams);

        PKIX_RETURN(USERDEFINEDMODULES);
}

/*
 * FUNCTION: pkix_EkuCheckerState_Create
 * DESCRIPTION:
 *
 *  Creates a new Extend Key Usage CheckerState using "params" to retrieve
 *  application specified EKU for verification and stores it at "pState".
 *
 * PARAMETERS:
 *  "params"
 *      a PKIX_ProcessingParams links to PKIX_ComCertSelParams where a list of
 *      Extended Key Usage OIDs specified by application can be retrieved for
 *      verification.
 *  "pState"
 *      Address where state pointer will be stored. Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a UserDefinedModules Error if the function fails in a
 *      non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
static PKIX_Error *
pkix_pl_EkuCheckerState_Create(
        PKIX_ProcessingParams *params,
        pkix_pl_EkuCheckerState **pState,
        void *plContext)
{
        pkix_pl_EkuCheckerState *state = NULL;
        PKIX_CertSelector *certSelector = NULL;
        PKIX_UInt32 requiredExtKeyUsage = 0;

        PKIX_ENTER(USERDEFINEDMODULES, "pkix_pl_EkuCheckerState_Create");
        PKIX_NULLCHECK_TWO(params, pState);

        PKIX_CHECK(PKIX_PL_Object_Alloc
                    (PKIX_EKUCHECKERSTATE_TYPE,
                    sizeof (pkix_pl_EkuCheckerState),
                    (PKIX_PL_Object **)&state,
                    plContext),
                    "Could not create EkuCheckerState object");


        PKIX_CHECK(PKIX_ProcessingParams_GetTargetCertConstraints
                    (params, &certSelector, plContext),
                    "PKIX_ProcessingParams_GetTargetCertConstraints failed");

        if (certSelector != NULL) {

                PKIX_CHECK(pkix_pl_EkuChecker_GetRequiredEku
                            (certSelector, &requiredExtKeyUsage, plContext),
                            "pkix_pl_EkuChecker_GetRequiredEku failed");
        }

        PKIX_CHECK(PKIX_PL_OID_Create
                    (PKIX_EXTENDEDKEYUSAGE_OID,
                    &state->ekuOID,
                    plContext),
                    "PKIX_PL_OID_Create failed");

        state->requiredExtKeyUsage = requiredExtKeyUsage;

        *pState = state;

cleanup:

        PKIX_DECREF(certSelector);

        if (PKIX_ERROR_RECEIVED) {
                PKIX_DECREF(state);
        }

        PKIX_RETURN(USERDEFINEDMODULES);
}

/*
 * FUNCTION: pkix_pl_EkuChecker_Check
 * DESCRIPTION:
 *
 *  This function determines the Extended Key Usage OIDs specified by the
 *  application is included in the Extended Key Usage OIDs of this "cert".
 *
 * PARAMETERS:
 *  "checker"
 *      Address of CertChainChecker which has the state data.
 *      Must be non-NULL.
 *  "cert"
 *      Address of Certificate that is to be validated. Must be non-NULL.
 *  "unresolvedCriticalExtensions"
 *      A List OIDs. The OID for Extended Key Usage is removed.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a UserDefinedModules Error if the function fails in
 *      a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
static PKIX_Error *
pkix_pl_EkuChecker_Check(
        PKIX_CertChainChecker *checker,
        PKIX_PL_Cert *cert,
        PKIX_List *unresolvedCriticalExtensions,
        void *plContext)
{
        pkix_pl_EkuCheckerState *state = NULL;
        PKIX_List *certEkuList = NULL;
        PKIX_Boolean checkPassed = PKIX_TRUE;

        PKIX_ENTER(USERDEFINEDMODULES, "pkix_pl_EkuChecker_Check");
        PKIX_NULLCHECK_TWO(checker, cert);

        PKIX_CHECK(PKIX_CertChainChecker_GetCertChainCheckerState
                    (checker, (PKIX_PL_Object **)&state, plContext),
                    "PKIX_CertChainChecker_GetCertChainCheckerState failed");

        if (state->requiredExtKeyUsage != 0) {

                PKIX_CHECK(pkix_pl_Cert_CheckExtendedKeyUsage
                        (cert,
                        state->requiredExtKeyUsage,
                        &checkPassed,
                        plContext),
                        "pkix_pl_Cert_CheckExtendedKeyUsage failed");

                if (checkPassed == PKIX_FALSE) {
                        PKIX_ERROR("Extended Key Usage Checking failed");
                }

        }

        /* Get extended key usage OIDs from the cert */
        PKIX_CHECK(PKIX_PL_Cert_GetExtendedKeyUsage
                    (cert, &certEkuList, plContext),
                    "PKIX_PL_Cert_GetExtendedKeyUsage failed");

        if (certEkuList != NULL) {
        /* Remove Extended Key Usage OID from list */
                if (unresolvedCriticalExtensions != NULL) {
                    PKIX_CHECK(pkix_List_Remove
                            (unresolvedCriticalExtensions,
                            (PKIX_PL_Object *) state->ekuOID,
                            plContext),
                            "PKIX_List_Remove failed");
                }
        }

cleanup:

        PKIX_DECREF(certEkuList);
        PKIX_DECREF(state);

        PKIX_RETURN(USERDEFINEDMODULES);
}

/*
 * FUNCTION: pkix_pl_EkuCheckerState_Initialize
 * (see comments in pkix_sample_modules.h)
 */
PKIX_Error *
PKIX_PL_EkuChecker_Initialize(
        PKIX_ProcessingParams *params,
        void *plContext)
{
        PKIX_CertChainChecker *checker = NULL;
        pkix_pl_EkuCheckerState *state = NULL;

        PKIX_ENTER(USERDEFINEDMODULES, "PKIX_PL_EkuChecker_Initialize");
        PKIX_NULLCHECK_ONE(params);

        /*
         * This function and functions in this file provide an example of how
         * an application defined checker can be hooked into libpkix.
         */

        /* Register user type object for EKU Checker State */
        PKIX_CHECK(PKIX_PL_Object_RegisterType
                    (PKIX_EKUCHECKERSTATE_TYPE,
                    "Extended Key Usage User Object",
                    pkix_pl_EkuCheckerState_Destroy,
                    NULL,
                    NULL,
                    NULL,
                    NULL,
                    pkix_duplicateImmutable,
                    plContext),
                    "PkIX_PL_Object_RegisterType failed");

        PKIX_CHECK(pkix_pl_EkuCheckerState_Create
                    (params, &state, plContext),
                    "pkix_pl_EkuCheckerState_Create failed");

        PKIX_CHECK(PKIX_CertChainChecker_Create
                    (pkix_pl_EkuChecker_Check,
                    PKIX_FALSE,
                    PKIX_FALSE,
                    NULL,
                    (PKIX_PL_Object *) state,
                    &checker,
                    plContext),
                    "PKIX_CertChainChecker_Create failed");

        PKIX_CHECK(PKIX_ProcessingParams_AddCertChainChecker
                    (params, checker, plContext),
                    "PKIX_ProcessingParams_AddCertChainChecker failed");

cleanup:

        PKIX_DECREF(checker);
        PKIX_DECREF(state);

        PKIX_RETURN(USERDEFINEDMODULES);
}
