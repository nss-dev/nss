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
 * pkix_build.c
 *
 * Top level buildChain function
 *
 */

#include "pkix_build.h"

/* --Private-ForwardBuilderState-Functions---------------------------------- */

/*
 * FUNCTION: pkix_ForwardBuilderState_Destroy
 * (see comments for PKIX_PL_DestructorCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_ForwardBuilderState_Destroy(
        PKIX_PL_Object *object,
        void *plContext)
{
        PKIX_ForwardBuilderState *state = NULL;

        PKIX_ENTER(FORWARDBUILDERSTATE, "pkix_ForwardBuilderState_Destroy");
        PKIX_NULLCHECK_ONE(object);

        PKIX_CHECK(pkix_CheckType
                (object, PKIX_FORWARDBUILDERSTATE_TYPE, plContext),
                "Object is not a PKIX_ForwardBuilderState");

        state = (PKIX_ForwardBuilderState *)object;

        PKIX_DECREF(state->prevCert);
        PKIX_DECREF(state->buildParams);
        PKIX_DECREF(state->testDate);
        PKIX_DECREF(state->targetCert);
        PKIX_DECREF(state->traversedSubjNames);
        PKIX_DECREF(state->targetPubKey);
        PKIX_DECREF(state->certStores);
        PKIX_DECREF(state->anchors);
        PKIX_DECREF(state->crlCheckerEnabled);

        state->numCertStores = 0;
        state->numAnchors = 0;

cleanup:

        PKIX_RETURN(FORWARDBUILDERSTATE);
}

/*
 * FUNCTION: pkix_ForwardBuilderState_Create
 *
 * DESCRIPTION:
 *  Allocate and initialize ForwardBuilder state data.
 *
 * PARAMETERS
 *  "prevCert"
 *      Address of Cert just traversed. Must be non-NULL.
 *  "traversedCACerts"
 *      Number of CA certificates traversed.
 *  "traversedSubjNames"
 *      Address of List of GeneralNames that have been traversed.
 *      Must be non-NULL.
 *  "dsaParamsNeeded"
 *      Boolean value indicating whether DSA parameters are needed.
 *  "revCheckDelayed"
 *      Boolean value indicating whether rev check is delayed until after
 *      entire chain is built.
 *  "buildParams:
 *      Address of BuildParams specified by caller. Must be non-NULL.
 *  "testDate"
 *      Address of Date at which build chain must be valid.
 *  "targetCert"
 *      Address of Cert that is the target. Must be non-NULL.
 *  "targetPubKey"
 *      Address of PublicKey belonging to the target. Must be non-NULL.
 *  "certStores"
 *      Address of List of CertStores specified by caller.
 *  "numCertStores"
 *      Number of CertStores specified by caller.
 *  "anchors"
 *      Address of List of TrustAnchors specified by caller. Must be non-NULL.
 *  "numAnchors"
 *      Number of TrustAnchors specified by caller.
 *  "crlCheckerEnabled"
 *      Address of CertChainChecker representing enabled crlChecker, if any.
 *  "pState"
 *      Address where ForwardBuilderState will be stored. Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a Build Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
static PKIX_Error *
pkix_ForwardBuilderState_Create(
        PKIX_PL_Cert *prevCert,
        PKIX_Int32 traversedCACerts,
        PKIX_List *traversedSubjNames,
        PKIX_Boolean dsaParamsNeeded,
        PKIX_Boolean revCheckDelayed,
        PKIX_BuildParams *buildParams,
        PKIX_PL_Date *testDate,
        PKIX_PL_Cert *targetCert,
        PKIX_PL_PublicKey *targetPubKey,
        PKIX_List *certStores,
        PKIX_UInt32 numCertStores,
        PKIX_List *anchors,
        PKIX_UInt32 numAnchors,
        PKIX_CertChainChecker *crlCheckerEnabled,
        PKIX_ForwardBuilderState **pState,
        void *plContext)
{
        PKIX_ForwardBuilderState *state = NULL;

        PKIX_ENTER(FORWARDBUILDERSTATE, "pkix_ForwardBuilderState_Create");
        PKIX_NULLCHECK_FOUR(pState, prevCert, traversedSubjNames, buildParams);
        PKIX_NULLCHECK_THREE(targetCert, targetPubKey, anchors);

        PKIX_CHECK(PKIX_PL_Object_Alloc
                (PKIX_FORWARDBUILDERSTATE_TYPE,
                sizeof (PKIX_ForwardBuilderState),
                (PKIX_PL_Object **)&state,
                plContext),
                "Could not create forwardBuilder state object");

        PKIX_INCREF(prevCert);
        state->prevCert = prevCert;

        state->traversedCACerts = traversedCACerts;

        PKIX_INCREF(traversedSubjNames);
        state->traversedSubjNames = traversedSubjNames;

        state->dsaParamsNeeded = dsaParamsNeeded;

        state->revCheckDelayed = revCheckDelayed;

        PKIX_INCREF(buildParams);
        state->buildParams = buildParams;

        PKIX_INCREF(testDate);
        state->testDate = testDate;

        PKIX_INCREF(targetCert);
        state->targetCert = targetCert;

        PKIX_INCREF(targetPubKey);
        state->targetPubKey = targetPubKey;

        PKIX_INCREF(certStores);
        state->certStores = certStores;
        state->numCertStores = numCertStores;

        PKIX_INCREF(anchors);
        state->anchors = anchors;
        state->numAnchors = numAnchors;

        PKIX_INCREF(crlCheckerEnabled);
        state->crlCheckerEnabled = crlCheckerEnabled;

        *pState = state;

cleanup:

        if (PKIX_ERROR_RECEIVED) {
                PKIX_DECREF(state);
        }

        PKIX_RETURN(FORWARDBUILDERSTATE);
}

/*
 * FUNCTION: pkix_ForwardBuilderState_Duplicate
 * (see comments for PKIX_PL_DuplicateCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_ForwardBuilderState_Duplicate(
        PKIX_PL_Object *object,
        PKIX_PL_Object **pNewObject,
        void *plContext)
{
        PKIX_ForwardBuilderState *state = NULL;
        PKIX_ForwardBuilderState *stateDuplicate = NULL;

        PKIX_ENTER(FORWARDBUILDERSTATE, "pkix_ForwardBuilderState_Duplicate");
        PKIX_NULLCHECK_TWO(object, pNewObject);

        PKIX_CHECK(pkix_CheckType
                    (object, PKIX_FORWARDBUILDERSTATE_TYPE, plContext),
                    "Object is not a ForwardBuilderState object");

        state = (PKIX_ForwardBuilderState *)object;

        PKIX_CHECK(pkix_ForwardBuilderState_Create
                    (state->prevCert,
                    state->traversedCACerts,
                    state->traversedSubjNames,
                    state->dsaParamsNeeded,
                    state->revCheckDelayed,
                    state->buildParams,
                    state->testDate,
                    state->targetCert,
                    state->targetPubKey,
                    state->certStores,
                    state->numCertStores,
                    state->anchors,
                    state->numAnchors,
                    state->crlCheckerEnabled,
                    &stateDuplicate,
                    plContext),
                    "PKIX_ForwardBuilderState_Create failed");

        *pNewObject = (PKIX_PL_Object *)stateDuplicate;

cleanup:

        PKIX_RETURN(FORWARDBUILDERSTATE);
}

/*
 * FUNCTION: pkix_ForwardBuilderState_RegisterSelf
 *
 * DESCRIPTION:
 *  Registers PKIX_FORWARDBUILDERSTATE_TYPE and its related functions
 *  with systemClasses[]
 *
 * THREAD SAFETY:
 *  Not Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 *
 *  Since this function is only called by PKIX_PL_Initialize, which should
 *  only be called once, it is acceptable that this function is not
 *  thread-safe.
 */
PKIX_Error *
pkix_ForwardBuilderState_RegisterSelf(void *plContext)
{

        extern pkix_ClassTable_Entry systemClasses[PKIX_NUMTYPES];
        pkix_ClassTable_Entry entry;

        PKIX_ENTER(FORWARDBUILDERSTATE,
                    "pkix_ForwardBuilderState_RegisterSelf");

        entry.description = "ForwardBuilderState";
        entry.destructor = pkix_ForwardBuilderState_Destroy;
        entry.equalsFunction = NULL;
        entry.hashcodeFunction = NULL;
        entry.toStringFunction = NULL;
        entry.comparator = NULL;
        entry.duplicateFunction = pkix_ForwardBuilderState_Duplicate;

        systemClasses[PKIX_FORWARDBUILDERSTATE_TYPE] = entry;

cleanup:

        PKIX_RETURN(FORWARDBUILDERSTATE);
}


/*
 * FUNCTION: pkix_ForwardBuilderState_Update
 *
 * DESCRIPTION:
 *  Updates ForwardBuilderState pointed to by "state" using information from
 *  the Cert pointed to by "currentCert".
 *
 * PARAMETERS
 *  "state"
 *      Address of ForwardBuilderState to be updated. Must be non-NULL.
 *  "currentCert"
 *      Address of Cert whose contents are used for the update.
 *      Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Not Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a Build Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
static PKIX_Error *
pkix_ForwardBuilderState_Update(
        PKIX_ForwardBuilderState *state,
        PKIX_PL_Cert *currentCert,
        void *plContext)
{
        PKIX_List *subjectNames = NULL;
        PKIX_PL_Object *subjectName = NULL;
        PKIX_Boolean isSelfIssued = PKIX_FALSE;
        PKIX_UInt32 numSubjectNames, i;

        PKIX_ENTER(FORWARDBUILDERSTATE, "pkix_ForwardBuilderState_Update");
        PKIX_NULLCHECK_TWO(state, currentCert);

        PKIX_INCREF(currentCert);
        PKIX_DECREF(state->prevCert);
        state->prevCert = currentCert;

        PKIX_CHECK(pkix_IsCertSelfIssued
                    (currentCert, &isSelfIssued, plContext),
                    "pkix_IsCertSelfIssued failed");

        if (!isSelfIssued){
                (state->traversedCACerts)++;

                PKIX_CHECK(PKIX_PL_Cert_GetAllSubjectNames
                            (currentCert, &subjectNames, plContext),
                            "PKIX_PL_Cert_GetAllSubjectNames failed");

                if (subjectNames){
                        PKIX_CHECK(PKIX_List_GetLength
                                    (subjectNames, &numSubjectNames, plContext),
                                    "PKIX_List_GetLength failed");
                } else {
                        numSubjectNames = 0;
                }

                for (i = 0; i < numSubjectNames; i++){
                        PKIX_CHECK(PKIX_List_GetItem
                                    (subjectNames, i, &subjectName, plContext),
                                    "PKIX_List_GetItem failed");

                        PKIX_NULLCHECK_ONE(state->traversedSubjNames);

                        PKIX_CHECK(PKIX_List_AppendItem
                                    (state->traversedSubjNames,
                                    subjectName,
                                    plContext),
                                    "PKIX_List_AppendItem failed");

                        PKIX_DECREF(subjectName);
                }
        }

cleanup:

        PKIX_DECREF(subjectNames);
        PKIX_DECREF(subjectName);

        PKIX_RETURN(FORWARDBUILDERSTATE);
}

/* --Private-BuildChain-Functions------------------------------------------- */

/*
 * FUNCTION: pkix_FindMatchingCerts
 *
 * DESCRIPTION:
 *  Finds a List of Certs that match the various parameters in the
 *  ForwardBuilderState pointed to by "state" and stores the results at
 *  "pMatchingCerts". If no Certs are found , this function stores an empty
 *  List at "pMatchingCerts".
 *
 * PARAMETERS
 *  "state"
 *      Address of ForwardBuilderState that provides matching criteria.
 *      Must be non-NULL.
 *  "pMatchingCerts"
 *      Address where List of Certs will be stored. Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Not Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a Build Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
pkix_FindMatchingCerts(
        PKIX_ForwardBuilderState *state,
        PKIX_List **pMatchingCerts,
        void *plContext)
{
        PKIX_List *matchingCerts = NULL;
        PKIX_CertSelector *certSel = NULL;
        PKIX_ComCertSelParams *certSelParams = NULL;
        PKIX_PL_X500Name *currentIssuer = NULL;
        PKIX_CertStore_CertCallback certStoreGetCerts = NULL;
        PKIX_CertStore *certStore = NULL;
        PKIX_PL_Date *testDate = NULL;
        PKIX_UInt32 i = 0;

        PKIX_ENTER(BUILD, "pkix_FindMatchingCerts");
        PKIX_NULLCHECK_TWO(state, pMatchingCerts);

        if (state->numCertStores == 0){
                PKIX_ERROR("Must have at least one CertStore");
        }

        for (i = 0; i < state->numCertStores; i ++){

                PKIX_CHECK(PKIX_List_GetItem
                            (state->certStores,
                            i,
                            (PKIX_PL_Object **)&certStore,
                            plContext),
                            "PKIX_List_GetItem failed");

                PKIX_CHECK(PKIX_CertStore_GetCertCallback
                            (certStore, &certStoreGetCerts, plContext),
                            "PKIX_CertStore_GetCertCallback failed");

                PKIX_CHECK(PKIX_CertSelector_Create
                            (NULL, NULL, &certSel, plContext),
                            "PKIX_CertSelector_Create failed");

                PKIX_CHECK(PKIX_ComCertSelParams_Create
                            (&certSelParams, plContext),
                            "PKIX_ComCertSelParams_Create failed");

                PKIX_NULLCHECK_ONE(state->prevCert);

                PKIX_CHECK(PKIX_PL_Cert_GetIssuer
                            (state->prevCert, &currentIssuer, plContext),
                            "PKIX_PL_Cert_GetIssuer failed");

                PKIX_CHECK(PKIX_ComCertSelParams_SetSubject
                            (certSelParams, currentIssuer, plContext),
                            "PKIX_ComCertSelParams_SetSubject failed");

                if (state->testDate){
                        PKIX_INCREF(state->testDate);
                        testDate = state->testDate;
                } else {
                        PKIX_CHECK(PKIX_PL_Date_Create_UTCTime
                                    (NULL, &testDate, plContext),
                                    "PKIX_PL_Date_Create_UTCTime failed");
                }
                PKIX_CHECK(PKIX_ComCertSelParams_SetCertificateValid
                            (certSelParams, testDate, plContext),
                            "PKIX_ComCertSelParams_SetCertificateValid failed");

                PKIX_CHECK(PKIX_ComCertSelParams_SetBasicConstraints
                            (certSelParams, state->traversedCACerts, plContext),
                            "PKIX_ComCertSelParams_SetBasicConstraints failed");

                PKIX_NULLCHECK_ONE(state->traversedSubjNames);

                PKIX_CHECK(PKIX_ComCertSelParams_SetPathToNames
                            (certSelParams,
                            state->traversedSubjNames,
                            plContext),
                            "PKIX_ComCertSelParams_SetPathToNames failed");

                PKIX_CHECK(PKIX_CertSelector_SetCommonCertSelectorParams
                            (certSel, certSelParams, plContext),
                            "PKIX_CertSelector_SetCommonCertSelectorParams "
                            "failed");

                PKIX_CHECK(certStoreGetCerts
                            (certStore, certSel, &matchingCerts, plContext),
                            "certStoreGetCerts failed");
        }

        *pMatchingCerts = matchingCerts;

cleanup:

        PKIX_DECREF(testDate);
        PKIX_DECREF(certStore);
        PKIX_DECREF(certSel);
        PKIX_DECREF(certSelParams);
        PKIX_DECREF(currentIssuer);

        PKIX_RETURN(BUILD);
}

/*
 * FUNCTION: pkix_CheckCertAgainstAnchor
 * DESCRIPTION:
 *
 *  Checks whether the Cert pointed to by "candidateCert" successfully
 *  chains to the TrustAnchor pointed to by "anchor". Successful chaining
 *  includes successful subject/issuer name chaining and successful
 *  signature verification. If the "candidateCert" does not successfully chain,
 *  an Error pointer is returned.
 *
 * PARAMETERS:
 *  "candidateCert"
 *      Address of Cert that is being checked. Must be non-NULL.
 *  "anchor"
 *      Address of TrustAnchor with which the Cert must successfully chain.
 *      Must be non-NULL.
 *  "state"
 *      Address of ForwardBuilderState used to help with the checking.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a Build Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
pkix_CheckCertAgainstAnchor(
        PKIX_PL_Cert *candidateCert,
        PKIX_TrustAnchor *anchor,
        PKIX_ForwardBuilderState *state,
        PKIX_Boolean *pPassed,
        void *plContext)
{
        PKIX_PL_Cert *trustedCert = NULL;
        PKIX_PL_CertNameConstraints *anchorNC = NULL;
        PKIX_CertSelector *certSel = NULL;
        PKIX_ComCertSelParams *certSelParams = NULL;
        PKIX_PL_X500Name *trustedSubject = NULL;
        PKIX_PL_PublicKey *trustedPubKey = NULL;
        PKIX_PL_X500Name *candidateIssuer = NULL;
        PKIX_PL_Object *crlCheckerState = NULL;
        PKIX_CertSelector_MatchCallback selectorMatch = NULL;
        PKIX_Boolean certMatch = PKIX_TRUE;
        PKIX_Boolean anchorMatch = PKIX_FALSE;

        PKIX_ENTER(BUILD, "pkix_CheckCertAgainstAnchor");
        PKIX_NULLCHECK_THREE(anchor, candidateCert, pPassed);

        *pPassed = PKIX_TRUE;

        PKIX_CHECK(PKIX_TrustAnchor_GetTrustedCert
                    (anchor, &trustedCert, plContext),
                    "PKIX_TrustAnchor_GetTrustedCert failed");

        PKIX_CHECK(PKIX_PL_Cert_GetSubject
                    (trustedCert, &trustedSubject, plContext),
                    "PKIX_PL_Cert_GetSubject failed");

        PKIX_NULLCHECK_ONE(trustedSubject);

        PKIX_CHECK(PKIX_PL_Cert_GetIssuer
                    (candidateCert, &candidateIssuer, plContext),
                    "PKIX_PL_Cert_GetIssuer failed");

        PKIX_CHECK(PKIX_PL_X500Name_Match
                    (trustedSubject, candidateIssuer, &anchorMatch, plContext),
                    "PKIX_PL_X500Name_Match failed");

        if (!anchorMatch){
                *pPassed = PKIX_FALSE;
                goto cleanup;
        }

        PKIX_CHECK(PKIX_TrustAnchor_GetNameConstraints
                    (anchor, &anchorNC, plContext),
                    "PKIX_TrustAnchor_GetNameConstraints failed");

        if (!anchorNC){
                PKIX_CHECK(PKIX_CertSelector_Create
                            (NULL, NULL, &certSel, plContext),
                            "PKIX_CertSelector_Create failed");

                PKIX_CHECK(PKIX_ComCertSelParams_Create
                            (&certSelParams, plContext),
                            "PKIX_ComCertSelParams_Create failed");

                PKIX_NULLCHECK_ONE(state->traversedSubjNames);

                PKIX_CHECK(PKIX_ComCertSelParams_SetPathToNames
                            (certSelParams,
                            state->traversedSubjNames,
                            plContext),
                            "PKIX_ComCertSelParams_SetPathToNames failed");

                PKIX_CHECK(PKIX_CertSelector_SetCommonCertSelectorParams
                            (certSel, certSelParams, plContext),
                            "PKIX_CertSelector_SetCommonCertSelectorParams "
                            "failed");

                PKIX_CHECK(PKIX_CertSelector_GetMatchCallback
                            (certSel, &selectorMatch, plContext),
                            "PKIX_CertSelector_GetMatchCallback failed");

                PKIX_CHECK(selectorMatch
                            (certSel,
                            candidateCert,
                            &certMatch,
                            plContext),
                            "selectorMatch failed");

                if (!certMatch){
                        *pPassed = PKIX_FALSE;
                        goto cleanup;
                }

        }

        PKIX_CHECK(PKIX_PL_Cert_GetSubjectPublicKey
                    (trustedCert, &trustedPubKey, plContext),
                    "PKIX_PL_Cert_GetSubjectPublicKey failed");

        PKIX_CHECK(PKIX_PL_Cert_VerifySignature
                    (candidateCert, trustedPubKey, plContext),
                    "PKIX_PL_Cert_VerifySignature failed");

        if (state->crlCheckerEnabled){

                PKIX_CHECK(PKIX_CertChainChecker_GetCertChainCheckerState
                            (state->crlCheckerEnabled,
                            &crlCheckerState,
                            plContext),
                            "PKIX_CertChainChecker_GetCertChainCheckerState "
                            "failed");

                PKIX_CHECK(pkix_CheckType
                            (crlCheckerState,
                            PKIX_DEFAULTCRLCHECKERSTATE_TYPE,
                            plContext),
                            "Object is not a DefaultCRLCheckerState object");

                PKIX_CHECK(pkix_DefaultCRLChecker_Check_Helper
                            (state->crlCheckerEnabled,
                            candidateCert,
                            trustedPubKey,
                            (pkix_DefaultCRLCheckerState *)crlCheckerState,
                            NULL, /* unresolved crit extensions */
                            plContext),
                            "pkix_DefaultCRLChecker_Check_Helper failed");
        }

cleanup:

        PKIX_DECREF(certSel);
        PKIX_DECREF(certSelParams);
        PKIX_DECREF(trustedCert);
        PKIX_DECREF(trustedSubject);
        PKIX_DECREF(candidateIssuer);
        PKIX_DECREF(trustedPubKey);
        PKIX_DECREF(crlCheckerState);

        PKIX_RETURN(BUILD);
}



/*
 * FUNCTION: pkix_IsChainCompleted
 * DESCRIPTION:
 *
 *  Checks whether the Cert pointed to by "candidateCert" successfully
 *  chains to one of the TrustAnchors found in the ForwardBuilderState
 *  pointed to by "state". If the Cert does successfully chain to one
 *  of the TrustAnchors, that TrustAnchor is stored at "pMatchingAnchor".
 *  If the Cert does not successfully chain to one of the Trust Anchors,
 *  this function stores NULL at "pMatchingAnchor".
 *
 * PARAMETERS:
 *  "candidateCert"
 *      Address of Cert to be checked. Must be non-NULL.
 *  "state"
 *      Address of ForwardBuilderState to be used. Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a Build Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
pkix_IsChainCompleted(
        PKIX_PL_Cert *candidateCert,
        PKIX_ForwardBuilderState *state,
        PKIX_TrustAnchor **pMatchingAnchor,
        void *plContext)
{
        PKIX_TrustAnchor *anchor = NULL;
        PKIX_TrustAnchor *anchorResult = NULL;
        PKIX_Boolean passed = PKIX_FALSE;
        PKIX_UInt32 i;

        PKIX_ENTER(BUILD, "pkix_IsChainCompleted");
        PKIX_NULLCHECK_THREE(state, candidateCert, pMatchingAnchor);

        for (i = 0; i < ((state->numAnchors) && (!anchorResult)); i++){

                PKIX_CHECK_ONLY_FATAL
                        (PKIX_List_GetItem
                        (state->anchors,
                        i,
                        (PKIX_PL_Object **)&anchor,
                        plContext),
                        "PKIX_List_GetItem failed");

                if (!PKIX_ERROR_RECEIVED){

                        PKIX_CHECK_ONLY_FATAL
                                (pkix_CheckCertAgainstAnchor
                                (candidateCert,
                                anchor,
                                state,
                                &passed,
                                plContext),
                                "pkix_CheckCertAgainstAnchor failed");

                        if (!PKIX_ERROR_RECEIVED && passed == PKIX_TRUE) {
                                PKIX_INCREF(anchor);
                                anchorResult = anchor;
                        }
                }

                PKIX_DECREF(anchor);
        }

        *pMatchingAnchor = anchorResult;

cleanup:

        if (PKIX_ERROR_RECEIVED){
                PKIX_DECREF(anchor);
        }

        PKIX_RETURN(BUILD);
}

/*
 * FUNCTION: pkix_VerifyCertificate
 * DESCRIPTION:
 *
 *  Checks whether the previous Cert stored in the ForwardBuilderState
 *  pointed to by "state" successfully chains to the Cert pointed to by
 *  "candidateCert". Also checks whether the "candidateCert" has already
 *  been traversed by comparing it to the List of traversed Certs pointed to
 *  by "certs"  If either of these checks fail, an Error pointer is returned.
 *
 * PARAMETERS:
 *  "candidateCert"
 *      Address of Cert to be checked. Must be non-NULL.
 *  "state"
 *      Address of ForwardBuilderState to be used. Must be non-NULL.
 *  "certs"
 *      List of Certs that have already been traversed. Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a Build Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
pkix_VerifyCertificate(
        PKIX_PL_Cert *candidateCert,
        PKIX_ForwardBuilderState *state,
        PKIX_List *certs,
        PKIX_Boolean trusted,
        void *plContext)
{
        PKIX_Boolean loopFound = PKIX_FALSE;
        PKIX_Boolean dsaParamsNeeded = PKIX_FALSE;
        PKIX_Boolean isSelfIssued = PKIX_FALSE;
        PKIX_PL_PublicKey *candidatePubKey = NULL;
        PKIX_PL_Object *crlCheckerState = NULL;

        PKIX_ENTER(BUILD, "pkix_VerifyCertificate");
        PKIX_NULLCHECK_FOUR(candidateCert, state, state->prevCert, certs);

        /* check for loops */

        PKIX_CHECK(pkix_List_Contains
                (certs, (PKIX_PL_Object *)candidateCert, &loopFound, plContext),
                "pkix_List_Contains failed");

        if (loopFound){
                PKIX_ERROR("Loop discovered: "
                            "duplicate certificates not allowed");
        }

        /* signature check */

        if ((!state->dsaParamsNeeded) || trusted){
                PKIX_CHECK(PKIX_PL_Cert_GetSubjectPublicKey
                            (candidateCert, &candidatePubKey, plContext),
                            "PKIX_PL_Cert_GetSubjectPublicKey failed");

                PKIX_CHECK(PKIX_PL_PublicKey_NeedsDSAParameters
                            (candidatePubKey, &dsaParamsNeeded, plContext),
                            "PKIX_PL_PublicKey_NeedsDSAParameters failed");

                if (dsaParamsNeeded){
                        if (trusted){
                                PKIX_ERROR("Missing DSA parameters "
                                            "in Trusted Cert");
                        } else {
                                state->dsaParamsNeeded = PKIX_TRUE;
                                goto cleanup;
                        }
                }

                PKIX_CHECK(PKIX_PL_Cert_VerifyKeyUsage
                            (candidateCert, PKIX_KEY_CERT_SIGN, plContext),
                            "PKIX_PL_Cert_VerifyKeyUsage failed");

                PKIX_CHECK(PKIX_PL_Cert_VerifySignature
                            (state->prevCert, candidatePubKey, plContext),
                            "PKIX_PL_Cert_VerifySignature failed");

                if (state->crlCheckerEnabled){
                        if (!trusted && state->revCheckDelayed){
                                goto cleanup;
                        } else if (!trusted && !state->revCheckDelayed){
                                PKIX_CHECK(pkix_IsCertSelfIssued
                                            (candidateCert,
                                            &isSelfIssued,
                                            plContext),
                                            "pkix_IsCertSelfIssued failed");

                                if (isSelfIssued){
                                        state->revCheckDelayed = PKIX_TRUE;
                                        goto cleanup;
                                }
                        }

                        PKIX_CHECK(PKIX_PL_Cert_VerifyKeyUsage
                                    (candidateCert, PKIX_CRL_SIGN, plContext),
                                    "PKIX_PL_Cert_VerifyKeyUsage failed");

                        PKIX_CHECK
                                (PKIX_CertChainChecker_GetCertChainCheckerState
                                (state->crlCheckerEnabled,
                                &crlCheckerState,
                                plContext),
                                "PKIX_CertChainChecker_"
                                "GetCertChainCheckerState failed");

                        PKIX_CHECK(pkix_CheckType
                                    (crlCheckerState,
                                    PKIX_DEFAULTCRLCHECKERSTATE_TYPE,
                                    plContext),
                                    "Object is not a DefaultCRLCheckerState "
                                    "object");

                        PKIX_CHECK(pkix_DefaultCRLChecker_Check_Helper
                                    (state->crlCheckerEnabled,
                                    state->prevCert,
                                    candidatePubKey,
                                    (pkix_DefaultCRLCheckerState *)
                                    crlCheckerState,
                                    NULL, /* unresolved crit extensions */
                                    plContext),
                                    "pkix_DefaultCRLChecker_Check_Helper "
                                    "failed");
                }
        }

cleanup:

        PKIX_DECREF(candidatePubKey);
        PKIX_DECREF(crlCheckerState);

        PKIX_RETURN(BUILD);
}

/*
 * FUNCTION: pkix_ValidateEntireChain
 * DESCRIPTION:
 *
 *  Checks whether the List of Certs pointed to by "certs" successfully
 *  validates using the TrustAnchor pointed to by "anchor" and the
 *  ForwardBuilderState pointed to by "state". If successful, the Public Key
 *  of the target certificate (including DSA parameter inheritance, if any)
 *  is stored at "pFinalSubjPubKey" and the PolicyNode representing the policy
 *  tree output by the validation algorithm is store at "pFinalPolicyTree".
 *  If not successful, an Error pointer is returned.
 *
 * PARAMETERS:
 *  "state"
 *      Address of ForwardBuilderState to be used. Must be non-NULL.
 *  "certs"
 *      Address of List of Certs to be validated. Must be non-NULL.
 *  "anchor"
 *      Address of TrustAnchor to be used. Must be non-NULL.
 *  "pFinalSubjPubKey"
 *      Address where PublicKey of target cert is stored. Must be non-NULL.
 *  "pFinalPolicyTree"
 *      Address where PolicyNode representing policy tree is to be stored.
 *      Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a Build Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
pkix_ValidateEntireChain(
        PKIX_ForwardBuilderState *state,
        PKIX_List *certs,
        PKIX_TrustAnchor *anchor,
        PKIX_PL_PublicKey **pFinalSubjPubKey,
        PKIX_PolicyNode **pFinalPolicyTree,
        void *plContext)
{
        PKIX_List *checkers = NULL;
        PKIX_List *initPolicies = NULL;
        PKIX_PL_Cert *trustedCert = NULL;
        PKIX_PL_PublicKey *trustedPubKey = NULL;
        PKIX_PL_PublicKey *finalSubjPubKey = NULL;
        PKIX_PolicyNode *finalPolicyTree = NULL;
        PKIX_CertChainChecker *sigChecker = NULL;
        PKIX_CertChainChecker *crlCheckerEnabled = NULL;
        PKIX_CertChainChecker *policyChecker = NULL;
        PKIX_List *reversedCerts = NULL;
        PKIX_UInt32 numChainCerts;

        PKIX_ENTER(BUILD, "pkix_ValidateEntireChain");
        PKIX_NULLCHECK_THREE(state, certs, anchor);

        PKIX_CHECK(PKIX_List_Create(&checkers, plContext),
                    "PKIX_List_Create failed");

        PKIX_CHECK(PKIX_List_ReverseList(certs, &reversedCerts, plContext),
                    "PKIX_List_ReverseList failed");

        PKIX_CHECK(PKIX_List_GetLength
                    (reversedCerts, &numChainCerts, plContext),
                    "PKIX_List_GetLength failed");

        PKIX_CHECK(PKIX_List_Create(&initPolicies, plContext),
                    "PKIX_List_Create failed");

#ifdef POLICY_WORK_TO_DO
        /* XXX policy needs to be done properly */
        PKIX_CHECK(pkix_PolicyChecker_Initialize
                    (/* XXX initial policies should be gotten from params */
                    initPolicies,
                    PKIX_FALSE,
                    PKIX_FALSE,
                    PKIX_FALSE,
                    PKIX_FALSE,
                    numChainCerts,
                    &policyChecker,
                    plContext),
                    "pkix_PolicyChecker_Initialize failed");

        PKIX_CHECK(PKIX_List_AppendItem
                    (checkers, (PKIX_PL_Object *)policyChecker, plContext),
                    "PKIX_List_AppendItem failed");
#endif

        if ((state->dsaParamsNeeded) || (state->revCheckDelayed)){

                if ((state->dsaParamsNeeded) || (state->crlCheckerEnabled)){

                        PKIX_CHECK(PKIX_TrustAnchor_GetTrustedCert
                                    (anchor, &trustedCert, plContext),
                                    "PKIX_TrustAnchor_GetTrustedCert failed");

                        PKIX_CHECK(PKIX_PL_Cert_GetSubjectPublicKey
                                    (trustedCert, &trustedPubKey, plContext),
                                    "PKIX_PL_Cert_GetSubjectPublicKey failed");

                        PKIX_NULLCHECK_ONE(state->certStores);

                        PKIX_CHECK(pkix_DefaultCRLChecker_Initialize
                                    (state->certStores,
                                    state->testDate,
                                    trustedPubKey,
                                    numChainCerts,
                                    &crlCheckerEnabled,
                                    plContext),
                                    "pkix_DefaultCRLChecker_Initialize failed");

                        PKIX_CHECK(PKIX_List_AppendItem
                                    (checkers,
                                    (PKIX_PL_Object *)crlCheckerEnabled,
                                    plContext),
                                    "PKIX_List_AppendItem failed");

                        if (state->dsaParamsNeeded){

                                PKIX_CHECK(pkix_SignatureChecker_Initialize
                                            (trustedPubKey,
                                            numChainCerts,
                                            &sigChecker,
                                            plContext),
                                            "pkix_SignatureChecker_Initialize "
                                            "failed");

                                PKIX_CHECK(PKIX_List_AppendItem
                                            (checkers,
                                            (PKIX_PL_Object *)sigChecker,
                                            plContext),
                                            "PKIX_List_AppendItem failed");
                        }
                }
        }

        PKIX_CHECK(pkix_CheckChain
                    (reversedCerts,
                    numChainCerts,
                    checkers,
                    &finalSubjPubKey,
                    &finalPolicyTree,
                    plContext),
                    "pkix_CheckChain failed");

        if (!state->dsaParamsNeeded){
                PKIX_INCREF(state->targetPubKey);
                finalSubjPubKey = state->targetPubKey;
        }

        *pFinalSubjPubKey = finalSubjPubKey;
        *pFinalPolicyTree = finalPolicyTree;

cleanup:

        PKIX_DECREF(checkers);
        PKIX_DECREF(initPolicies);
        PKIX_DECREF(trustedCert);
        PKIX_DECREF(trustedPubKey);
        PKIX_DECREF(sigChecker);
        PKIX_DECREF(crlCheckerEnabled);
        PKIX_DECREF(policyChecker);
        PKIX_DECREF(reversedCerts);

        PKIX_RETURN(BUILD);
}

/*
 * FUNCTION: pkix_BuildForwardDepthFirstSearch
 * DESCRIPTION:
 *
 *  This function performs a depth first search in the "forward" direction
 *  (starting with the target Cert). A non-NULL targetCert must be stored in
 *  the ForwardBuilderState before the initial call to this function. This
 *  function is used recursively, where each call represents the searching of
 *  the next depth level in a certificate graph.
 *
 *  This function performs several steps every time it is called.
 *
 *  1) It retrieves Certs from the registered CertStores that match the
 *  criteria established by the ForwardBuilderState pointed to by "state".
 *  If there are no matching Certs, NULL is stored at "pMatchingAnchor" and
 *  the function exits returning NULL.
 *
 *  2) It duplicates the ForwardBuilderState before proceeding so that the
 *  state can be restored if backtracking is required.
 *
 *  3) It verifies the first matching Cert using the TrustAnchor pointed to by
 *  "anchor" and the ForwardBuilderState pointed to by "state". If verification
 *  fails, Step (3) is repeated using the next matching cert, if any. If there
 *  are no more matching certs, NULL is stored at "pMatchingAnchor" and the
 *  function exits returns NULL. If verification is successful, the matching
 *  Cert is appended to the List of Certs pointed by "certs".
 *
 *  4) It determines if the matchingCert chains to the TrustAnchor pointed to
 *  by "anchor".
 *
 *  5) If the matching Cert does not chain successfully, the
 *  ForwardBuilderState pointed to by "state" is updated using the contents of
 *  the matching Cert and a recursive call is made to
 *  pkix_BuildForwardDepthFirstSearch.
 *
 *  6) If the matching Cert does chain successfully, then it determines if the
 *  entire chain validates using the TrustAnchor pointed to by "anchor".
 *
 *  7) If the entire chain validates successfully, then we are done. The
 *  Public Key of the target certificate (including DSA parameter inheritance,
 *  if any) is stored at "pFinalSubjPubKey" and the PolicyNode representing
 *  the policy tree output by the validation algorithm is stored at
 *  "pFinalPolicyTree". The function exits returning NULL.
 *
 *  8) If the entire chain does not validate successfully, the algorithm
 *  returns to Step (3) using the next matching Cert, if any. If there are no
 *  more matching Certs, NULL is stored at "pMatchingAnchor" and the function
 *  exits returning NULL.
 *
 * PARAMETERS:
 *  "state"
 *      Address of ForwardBuilderState to be used. Must be non-NULL.
 *  "certs"
 *      Address of List of Certs gathered thus far. Must be non-NULL.
 *  "pMatchingAnchor"
 *      Address where TrustAnchor that was used is stored. Must be non-NULL.
 *  "pFinalSubjPubKey"
 *      Address where PublicKey of target cert is stored. Must be non-NULL.
 *  "pFinalPolicyTree"
 *      Address where PolicyNode representing policy tree is to be stored.
 *      Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a Build Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
pkix_BuildForwardDepthFirstSearch(
        PKIX_ForwardBuilderState *state,
        PKIX_List *certs,
        PKIX_TrustAnchor **pMatchingAnchor,
        PKIX_PL_PublicKey **pFinalSubjPubKey,
        PKIX_PolicyNode **pFinalPolicyTree,
        void *plContext)
{
        PKIX_Boolean trusted = PKIX_FALSE;

        PKIX_ForwardBuilderState *nextState = NULL;
        PKIX_List *matchingCerts = NULL;
        PKIX_PL_Cert *matchingCert = NULL;
        PKIX_TrustAnchor *matchingAnchor = NULL;
        PKIX_UInt32 numMatchingCerts, numChainCerts, i;
        PKIX_Boolean chainCompleted = PKIX_FALSE;
        PKIX_List *unresCritExtOIDs = NULL;
        PKIX_PL_PublicKey *finalSubjPubKey = NULL;
        PKIX_PolicyNode *finalPolicyTree = NULL;

        PKIX_ENTER(BUILD, "pkix_BuildForwardDepthFirstSearch");
        PKIX_NULLCHECK_THREE(state, certs, pMatchingAnchor);

        /* XXX once coded, use keyUsage certSelParam for filtering */
        PKIX_CHECK(pkix_FindMatchingCerts(state, &matchingCerts, plContext),
                    "pkix_FindMatchingCerts failed");

        PKIX_CHECK(PKIX_List_GetLength
                    (matchingCerts, &numMatchingCerts, plContext),
                    "PKIX_List_GetLength failed");

        /*
         * XXX Using PKIX_PL_Cert_IsCertTrusted, sort this List to put
         * trusted Certs ahead of non-trusted Certs.
         */

        for (i = 0; i < numMatchingCerts; i++){

                PKIX_CHECK(pkix_ForwardBuilderState_Duplicate
                            ((PKIX_PL_Object*)state,
                            (PKIX_PL_Object**)&nextState,
                            plContext),
                            "pkix_ForwardBuilderState_Duplicate failed");

                PKIX_CHECK(PKIX_List_GetItem
                            (matchingCerts,
                            i,
                            (PKIX_PL_Object **)&matchingCert,
                            plContext),
                            "PKIX_List_GetItem failed");

                /* XXX verify stuff we haven't checked through selector */

                PKIX_CHECK(PKIX_PL_Cert_IsCertTrusted
                        (matchingCert, &trusted, plContext),
                        "PKIX_PL_Cert_IsCertTrusted failed");

                PKIX_CHECK_ONLY_FATAL(pkix_VerifyCertificate
                        (matchingCert, nextState, certs, trusted, plContext),
                        "pkix_VerifyCertificate failed");

                if (PKIX_ERROR_RECEIVED) {
                        PKIX_DECREF(matchingCert);
                        PKIX_DECREF(nextState);
                        continue;
                }

                /*
                 * If this cert is trusted, try ValidateEntireChain
                 * using this cert as matching anchor
                 */
                if (trusted) {
                        PKIX_CHECK(PKIX_TrustAnchor_CreateWithCert
                                (matchingCert, &matchingAnchor, plContext),
                                "PKIX_TrustAnchor_CreateWithCert failed");

                        PKIX_CHECK_ONLY_FATAL(pkix_ValidateEntireChain
                                (nextState,
                                certs,
                                matchingAnchor,
                                &finalSubjPubKey,
                                &finalPolicyTree,
                                plContext),
                                "pkix_ValidateEntireChain failed");

                        if (!PKIX_ERROR_RECEIVED) {
                                *pFinalSubjPubKey = finalSubjPubKey;
                                *pFinalPolicyTree = finalPolicyTree;
                                break;
                        } else {
                                PKIX_DECREF(matchingAnchor);
                                PKIX_DECREF(matchingCert);
                                PKIX_DECREF(nextState);
                                continue;
                        }
                }

                PKIX_CHECK(PKIX_List_AppendItem
                            (certs, (PKIX_PL_Object *)matchingCert, plContext),
                            "PKIX_List_AppendItem failed");

                PKIX_CHECK(pkix_IsChainCompleted
                            (matchingCert,
                            nextState,
                            &matchingAnchor,
                            plContext),
                            "pkix_IsChainCompleted failed");

                if (matchingAnchor){ /* chainCompleted */
                        PKIX_CHECK_ONLY_FATAL
                                (pkix_ValidateEntireChain
                                (nextState,
                                certs,
                                matchingAnchor,
                                &finalSubjPubKey,
                                &finalPolicyTree,
                                plContext),
                                "pkix_ValidateEntireChain failed");

                        if (!PKIX_ERROR_RECEIVED){
                                *pFinalSubjPubKey = finalSubjPubKey;
                                *pFinalPolicyTree = finalPolicyTree;
                                break;
                        } else {
                                PKIX_DECREF(matchingAnchor);
                        }
                }

                PKIX_CHECK(pkix_ForwardBuilderState_Update
                            (nextState, matchingCert, plContext),
                            "pkix_ForwardBuilderState_Update failed");

                PKIX_CHECK(pkix_BuildForwardDepthFirstSearch
                            (nextState,
                            certs,
                            &matchingAnchor,
                            &finalSubjPubKey,
                            &finalPolicyTree,
                            plContext),
                            "pkix_BuildForwardDepthFirstSearch failed");

                /* if we receive a non-NULL matchingAnchor, we're done */
                if (matchingAnchor){
                                *pMatchingAnchor = matchingAnchor;
                                *pFinalSubjPubKey = finalSubjPubKey;
                                *pFinalPolicyTree = finalPolicyTree;
                                break;
                } else {
                        PKIX_CHECK(PKIX_List_GetLength
                                    (certs, &numChainCerts, plContext),
                                    "PKIX_List_GetLength failed");

                        PKIX_CHECK(PKIX_List_DeleteItem
                                    (certs, numChainCerts - 1, plContext),
                                    "PKIX_List_DeleteItem failed");
                }

                PKIX_DECREF(matchingAnchor);
                PKIX_DECREF(matchingCert);
                PKIX_DECREF(nextState);
        }

        /*
         * matchingAnchor is initialized to NULL and will remain NULL unless
         * IsChainCompleted or BuildForwardDepthFirstSearch return a non-NULL
         * matchingAnchor in the above loop
         */

        PKIX_INCREF(matchingAnchor);
        *pMatchingAnchor = matchingAnchor;

cleanup:

        PKIX_DECREF(matchingCerts);
        PKIX_DECREF(matchingCert);
        PKIX_DECREF(matchingAnchor);
        PKIX_DECREF(nextState);

        PKIX_RETURN(BUILD);
}

/*
 * FUNCTION: pkix_InitializeBuilderState
 *
 * DESCRIPTION:
 *  Creates a ForwardBuilderState and initializes it using the BuildParams
 *  pointed to by "params" and stores it at "pState".
 *
 * PARAMETERS
 *  "buildParams"
 *      Address of BuildParams used for initialization. Must be non-NULL.
 *  "pState"
 *      Address where ForwardBuilderState will be stored. Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a Build Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
static PKIX_Error *
pkix_InitializeBuilderState(
        PKIX_BuildParams *buildParams,
        PKIX_ForwardBuilderState **pState,
        void *plContext)
{
        PKIX_ForwardBuilderState *state = NULL;
        PKIX_ProcessingParams *procParams = NULL;
        PKIX_CertSelector *targetConstraints = NULL;
        PKIX_ComCertSelParams *targetParams = NULL;
        PKIX_List *anchors = NULL;
        PKIX_List *certStores = NULL;
        PKIX_UInt32 numAnchors, numCertStores;
        PKIX_PL_Cert *targetCert = NULL;
        PKIX_PL_PublicKey *targetPubKey = NULL;
        PKIX_Boolean dsaParamsNeeded = PKIX_FALSE;
        PKIX_Boolean revCheckDelayed = PKIX_FALSE;
        PKIX_Boolean isCrlEnabled = PKIX_TRUE;
        PKIX_CertChainChecker *defaultCrlChecker = NULL;
        PKIX_PL_Date *testDate = NULL;
        PKIX_List *targetSubjNames = NULL;

        PKIX_ENTER(BUILD, "pkix_InitializeBuilderState");
        PKIX_NULLCHECK_TWO(buildParams, pState);

        PKIX_CHECK(PKIX_BuildParams_GetProcessingParams
                    (buildParams, &procParams, plContext),
                    "PKIX_BuildParams_GetProcessingParams failed");

        PKIX_CHECK(PKIX_ProcessingParams_GetDate
                    (procParams, &testDate, plContext),
                    "PKIX_ProcessingParams_GetDate");

        /* retrieve stuff from targetCertConstraints */

        PKIX_CHECK(PKIX_ProcessingParams_GetTargetCertConstraints
                    (procParams, &targetConstraints, plContext),
                    "PKIX_ProcessingParams_GetTargetCertConstraints failed");

        PKIX_CHECK(PKIX_CertSelector_GetCommonCertSelectorParams
                    (targetConstraints, &targetParams, plContext),
                    "PKIX_CertSelector_GetCommonCertSelectorParams failed");

        PKIX_CHECK(PKIX_ComCertSelParams_GetCertificate
                    (targetParams, &targetCert, plContext),
                    "PKIX_ComCertSelParams_GetCertificate failed");

        PKIX_CHECK(PKIX_PL_Cert_GetAllSubjectNames
                    (targetCert,
                    &targetSubjNames,
                    plContext),
                    "PKIX_PL_Cert_GetAllSubjectNames failed");

        PKIX_CHECK(PKIX_PL_Cert_GetSubjectPublicKey
                    (targetCert, &targetPubKey, plContext),
                    "PKIX_PL_Cert_GetSubjectPublicKey failed");

        PKIX_CHECK(PKIX_PL_PublicKey_NeedsDSAParameters
                    (targetPubKey, &dsaParamsNeeded, plContext),
                    "PKIX_PL_PublicKey_NeedsDSAParameters failed");

        PKIX_CHECK(PKIX_PL_Cert_CheckValidity(targetCert, testDate, plContext),
                    "PKIX_PL_Cert_CheckValidity failed");

        PKIX_CHECK(pkix_ProcessingParams_GetRevocationEnabled
                    (procParams, &isCrlEnabled, plContext),
                    "PKIX_ProcessingParams_GetRevocationEnabled");

        PKIX_CHECK(PKIX_ProcessingParams_GetTrustAnchors
                    (procParams, &anchors, plContext),
                    "PKIX_ProcessingParams_GetTrustAnchors failed");

        PKIX_CHECK(PKIX_List_GetLength(anchors, &numAnchors, plContext),
                    "PKIX_List_GetLength failed");

        PKIX_CHECK(PKIX_ProcessingParams_GetCertStores
                    (procParams, &certStores, plContext),
                    "PKIX_ProcessingParams_GetCertStores failed");

        PKIX_CHECK(PKIX_List_GetLength(certStores, &numCertStores, plContext),
                    "PKIX_List_GetLength failed");

        if (isCrlEnabled) {
                if (numCertStores > 0) {
                        PKIX_CHECK(pkix_DefaultCRLChecker_Initialize
                                    (certStores,
                                    testDate,
                                    NULL,
                                    0,
                                    &defaultCrlChecker,
                                    plContext),
                                    "pkix_DefaultCRLChecker_Initialize failed");
                } else {
                        PKIX_ERROR("Can't enable Revocation without CertStore");
                }
        }

        PKIX_CHECK(pkix_ForwardBuilderState_Create
                    (targetCert,
                    0,
                    targetSubjNames,
                    dsaParamsNeeded,
                    revCheckDelayed,
                    buildParams,
                    testDate,
                    targetCert,
                    targetPubKey,
                    certStores,
                    numCertStores,
                    anchors,
                    numAnchors,
                    defaultCrlChecker,
                    &state,
                    plContext),
                    "pkix_ForwardBuilderState_Create failed");

        *pState = state;


cleanup:

        if (PKIX_ERROR_RECEIVED){
                PKIX_DECREF(state);
        }

        PKIX_DECREF(testDate);
        PKIX_DECREF(procParams);
        PKIX_DECREF(targetConstraints);
        PKIX_DECREF(targetParams);
        PKIX_DECREF(anchors);
        PKIX_DECREF(certStores);
        PKIX_DECREF(targetCert);
        PKIX_DECREF(targetSubjNames);
        PKIX_DECREF(targetPubKey);
        PKIX_DECREF(defaultCrlChecker);

        PKIX_RETURN(BUILD);
}

/* --Public-Functions--------------------------------------------- */



/*
 * FUNCTION: PKIX_BuildChain (see comments in pkix.h)
 */
PKIX_Error *
PKIX_BuildChain(
        PKIX_BuildParams *buildParams,
        PKIX_BuildResult **pResult,
        void *plContext)
{
        PKIX_List *certs = NULL;
        PKIX_UInt32 i = 0;
        PKIX_Boolean chainCompleted = PKIX_FALSE;
        PKIX_ValidateResult *valResult = NULL;
        PKIX_BuildResult *buildResult = NULL;
        PKIX_CertChain *certChain = NULL;
        PKIX_TrustAnchor *matchingAnchor = NULL;
        PKIX_ForwardBuilderState *state = NULL;
        PKIX_PL_PublicKey *finalSubjPubKey = NULL;
        PKIX_PolicyNode *finalPolicyTree = NULL;

        PKIX_ENTER(BUILD, "PKIX_BuildChain");
        PKIX_NULLCHECK_TWO(buildParams, pResult);

        /* create & initialize builderState using parameters in buildParams */
        PKIX_CHECK(pkix_InitializeBuilderState
                    (buildParams, &state, plContext),
                    "pkix_InitializeBuilderState failed");

        PKIX_CHECK(PKIX_List_Create(&certs, plContext),
                    "PKIX_List_Create failed");

        PKIX_NULLCHECK_ONE(state->targetCert);

        PKIX_CHECK(PKIX_List_AppendItem
                    (certs, (PKIX_PL_Object *)state->targetCert, plContext),
                    "PKIX_List_AppendItem");

        PKIX_CHECK(pkix_IsChainCompleted
                    (state->targetCert,
                    state,
                    &matchingAnchor,
                    plContext),
                    "pkix_IsChainCompleted failed");

        if (!matchingAnchor){
                PKIX_CHECK(pkix_BuildForwardDepthFirstSearch
                            (state,
                            certs,
                            &matchingAnchor,
                            &finalSubjPubKey,
                            &finalPolicyTree,
                            plContext),
                            "pkix_BuildForwardDepthFirstSearch failed");
        }

        /* no matchingAnchor means the build has failed */
        if (!matchingAnchor){
                PKIX_ERROR("Unable to build chain");
        }

        PKIX_CHECK(pkix_ValidateResult_Create
                    (finalSubjPubKey,
                    matchingAnchor,
                    finalPolicyTree,
                    &valResult,
                    plContext),
                    "pkix_ValidateResult_Create failed");

        PKIX_CHECK(PKIX_CertChain_Create(certs, &certChain, plContext),
                    "PKIX_CertChain_Create failed");

        PKIX_CHECK(pkix_BuildResult_Create
                    (valResult, certChain, &buildResult, plContext),
                    "pkix_BuildResult_Create failed");

        *pResult = buildResult;

cleanup:

        PKIX_DECREF(finalSubjPubKey);
        PKIX_DECREF(certs);
        PKIX_DECREF(certChain);
        PKIX_DECREF(valResult);
        PKIX_DECREF(matchingAnchor);
        PKIX_DECREF(state);

        PKIX_RETURN(BUILD);
}
