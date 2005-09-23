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

/*
 * List of critical extension OIDs associate with what build chain has
 * checked. Those OIDs need to be removed from the unresolved critical
 * extension OIDs list manually (instead of by checker automatically).
 */
static char *buildCheckedCritExtOIDs[] = {
        PKIX_CERTKEYUSAGE_OID,
        PKIX_CERTSUBJALTNAME_OID,
        PKIX_BASICCONSTRAINTS_OID,
        PKIX_NAMECONSTRAINTS_OID,
        PKIX_EXTENDEDKEYUSAGE_OID,
        NULL
};

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

        state->status = BUILD_INITIAL;
        state->traversedCACerts = 0;
        state->certStoreIndex = 0;
        state->numCerts = 0;
        state->certIndex = 0;
        state->dsaParamsNeeded = PKIX_FALSE;
        state->revCheckDelayed = PKIX_FALSE;
        state->canBeCached = PKIX_FALSE;
        PKIX_DECREF(state->validityDate);
        PKIX_DECREF(state->prevCert);
        PKIX_DECREF(state->candidateCert);
        PKIX_DECREF(state->traversedSubjNames);
        PKIX_DECREF(state->trustChain);
        PKIX_DECREF(state->candidateCerts);
        PKIX_DECREF(state->certSel);

        /*
         * If we ever add a child link we have to be careful not to have loops
         * in the Destroy process. But with one-way links we should be okay.
         */
        PKIX_DECREF(state->parentState);

cleanup:

        PKIX_RETURN(FORWARDBUILDERSTATE);
}

/*
 * FUNCTION: pkix_ForwardBuilderState_Create
 *
 * DESCRIPTION:
 *  Allocate and initialize a ForwardBuilderState.
 *
 * PARAMETERS
 *  "traversedCACerts"
 *      Number of CA certificates traversed.
 *  "dsaParamsNeeded"
 *      Boolean value indicating whether DSA parameters are needed.
 *  "revCheckDelayed"
 *      Boolean value indicating whether rev check is delayed until after
 *      entire chain is built.
 *  "canBeCached"
 *      Boolean value indicating whether all certs on the chain can be cached.
 *  "validityDate"
 *      Address of Date at which build chain Certs' most restricted validity
 *      time is kept. May be NULL.
 *  "prevCert"
 *      Address of Cert just traversed. Must be non-NULL.
 *  "traversedSubjNames"
 *      Address of List of GeneralNames that have been traversed.
 *      Must be non-NULL.
 *  "trustChain"
 *      Address of List of certificates traversed. Must be non-NULL.
 *  "parentState"
 *      Address of previous ForwardBuilder state
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
        PKIX_Int32 traversedCACerts,
        PKIX_Boolean dsaParamsNeeded,
        PKIX_Boolean revCheckDelayed,
        PKIX_Boolean canBeCached,
        PKIX_PL_Date *validityDate,
        PKIX_PL_Cert *prevCert,
        PKIX_List *traversedSubjNames,
        PKIX_List *trustChain,
        PKIX_ForwardBuilderState *parentState,
        PKIX_ForwardBuilderState **pState,
        void *plContext)
{
        PKIX_ForwardBuilderState *state = NULL;

        PKIX_ENTER(FORWARDBUILDERSTATE, "pkix_ForwardBuilderState_Create");
        PKIX_NULLCHECK_FOUR(prevCert, traversedSubjNames, pState, trustChain);

        PKIX_CHECK(PKIX_PL_Object_Alloc
                (PKIX_FORWARDBUILDERSTATE_TYPE,
                sizeof (PKIX_ForwardBuilderState),
                (PKIX_PL_Object **)&state,
                plContext),
                "Could not create forwardBuilder state object");

        state->status = BUILD_INITIAL;
        state->traversedCACerts = traversedCACerts;
        state->certStoreIndex = 0;
        state->numCerts = 0;
        state->certIndex = 0;
        state->dsaParamsNeeded = dsaParamsNeeded;
        state->revCheckDelayed = revCheckDelayed;
        state->canBeCached = canBeCached;

        PKIX_INCREF(validityDate);
        state->validityDate = validityDate;

        PKIX_INCREF(prevCert);
        state->prevCert = prevCert;

        state->candidateCert = NULL;

        PKIX_INCREF(traversedSubjNames);
        state->traversedSubjNames = traversedSubjNames;

        PKIX_INCREF(trustChain);
        state->trustChain = trustChain;

        state->candidateCerts = NULL;
        state->certSel = NULL;

        PKIX_INCREF(parentState);
        state->parentState = parentState;

        *pState = state;

cleanup:

        if (PKIX_ERROR_RECEIVED) {
                PKIX_DECREF(state);
        }

        PKIX_RETURN(FORWARDBUILDERSTATE);
}

/*
 * FUNCTION: pkix_ForwardBuilderState_ToString
 * (see comments for PKIX_PL_ToStringCallback in pkix_pl_system.h)
 */
PKIX_Error *
pkix_ForwardBuilderState_ToString
        (PKIX_PL_Object *object,
        PKIX_PL_String **pString,
        void *plContext)
{
        PKIX_ForwardBuilderState *state = NULL;
        PKIX_PL_String *formatString = NULL;
        PKIX_PL_String *resultString = NULL;
        PKIX_PL_String *buildStatusString = NULL;
        PKIX_PL_String *validityDateString = NULL;
        PKIX_PL_String *prevCertString = NULL;
        PKIX_PL_String *candidateCertString = NULL;
        PKIX_PL_String *traversedSubjNamesString = NULL;
        PKIX_PL_String *trustChainString = NULL;
        PKIX_PL_String *candidateCertsString = NULL;
        PKIX_PL_String *certSelString = NULL;
        PKIX_PL_String *parentStateString = NULL;
        char *asciiFormat = "\n"
                "\t{buildStatus: \t%s\n"
                "\ttraversedCACerts: \t%d\n"
                "\tcertStoreIndex: \t%d\n"
                "\tnumCerts: \t%d\n"
                "\tcertIndex: \t%d\n"
                "\tdsaParamsNeeded: \t%d\n"
                "\trevCheckDelayed: \t%d\n"
                "\tcanBeCached: \t%d\n"
                "\tvalidityDate: \t%s\n"
                "\tprevCert: \t%s\n"
                "\tcandidateCert: \t%s\n"
                "\ttraversedSubjNames: \t%s\n"
                "\ttrustChain: \t%s\n"
                "\tcandidateCerts: \t%s\n"
                "\tcertSel: \t%s\n"
                "\tparentState: \t%s}\n";
        char *asciiStatus = NULL;

        PKIX_ENTER(FORWARDBUILDERSTATE, "pkix_ForwardBuilderState_ToString");
        PKIX_NULLCHECK_TWO(object, pString);

        PKIX_CHECK(pkix_CheckType
                (object, PKIX_FORWARDBUILDERSTATE_TYPE, plContext),
                "Object is not a PKIX_ForwardBuilderState");

        state = (PKIX_ForwardBuilderState *)object;

        PKIX_CHECK(PKIX_PL_String_Create
                (PKIX_ESCASCII, asciiFormat, 0, &formatString, plContext),
                "PKIX_PL_String_Create failed");

        switch (state->status) {
            case BUILD_INITIAL:         asciiStatus = "BUILD_INITIAL";
                                        break;
            case BUILD_IOPENDING:       asciiStatus = "BUILD_IOPENDING";
                                        break;
            case BUILD_COLLECTINGCERTS: asciiStatus = "BUILD_COLLECTINGCERTS";
                                        break;
            case BUILD_CHAINBUILDING:   asciiStatus = "BUILD_CHAINBUILDING";
                                        break;
            default:                    asciiStatus = "INVALID STATUS";
                                        break;
        }

        PKIX_CHECK(PKIX_PL_String_Create
                (PKIX_ESCASCII, asciiStatus, 0, &buildStatusString, plContext),
                "PKIX_PL_String_Create failed");

        PKIX_TOSTRING
               (state->validityDate, &validityDateString, plContext,
                "PKIX_PL_Object_ToString failed");

        PKIX_TOSTRING
               (state->prevCert, &prevCertString, plContext,
                "PKIX_PL_Object_ToString failed");

        PKIX_TOSTRING
                (state->candidateCert, &candidateCertString, plContext,
                "PKIX_PL_Object_ToString failed");

        PKIX_TOSTRING
                (state->traversedSubjNames,
                &traversedSubjNamesString,
                plContext,
                "PKIX_PL_Object_ToString failed");

        PKIX_TOSTRING
                (state->trustChain, &trustChainString, plContext,
                "PKIX_PL_Object_ToString failed");

        PKIX_TOSTRING
                (state->candidateCerts, &candidateCertsString, plContext,
                "PKIX_PL_Object_ToString failed");

        PKIX_TOSTRING
                (state->certSel, &certSelString, plContext,
                "PKIX_PL_Object_ToString failed");

        PKIX_TOSTRING
                (state->parentState, &parentStateString, plContext,
                "PKIX_PL_Object_ToString failed");

        PKIX_CHECK(PKIX_PL_Sprintf
                (&resultString,
                plContext,
                formatString,
                buildStatusString,
                (PKIX_Int32)state->traversedCACerts,
                (PKIX_UInt32)state->certStoreIndex,
                (PKIX_UInt32)state->numCerts,
                (PKIX_UInt32)state->certIndex,
                state->dsaParamsNeeded,
                state->revCheckDelayed,
                state->canBeCached,
                validityDateString,
                prevCertString,
                candidateCertString,
                traversedSubjNamesString,
                trustChainString,
                candidateCertsString,
                certSelString,
                parentStateString),
                "PKIX_PL_Sprintf failed");

        *pString = resultString;

cleanup:
        PKIX_DECREF(formatString);
        PKIX_DECREF(buildStatusString);
        PKIX_DECREF(validityDateString);
        PKIX_DECREF(prevCertString);
        PKIX_DECREF(candidateCertString);
        PKIX_DECREF(traversedSubjNamesString);
        PKIX_DECREF(trustChainString);
        PKIX_DECREF(candidateCertsString);
        PKIX_DECREF(certSelString);
        PKIX_DECREF(parentStateString);

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
        entry.toStringFunction = pkix_ForwardBuilderState_ToString;
        entry.comparator = NULL;
        entry.duplicateFunction = NULL;

        systemClasses[PKIX_FORWARDBUILDERSTATE_TYPE] = entry;

        PKIX_RETURN(FORWARDBUILDERSTATE);
}

/* --Private-BuildChain-Functions------------------------------------------- */

/*
 * FUNCTION: pkix_Build_CheckCertAgainstAnchor
 * DESCRIPTION:
 *
 *  Checks whether the Cert pointed to by "candidateCert" successfully chains to
 *  the TrustAnchor pointed to by "anchor". Successful chaining includes
 *  successful subject/issuer name chaining, using the List of traversed subject
 *  names pointed to by "traversedSubjNames" to check for name constraints
 *  violation, successful signature verification, and passing the revocation
 *  list checking performed by the CertChainChecker pointed to by "crlChecker",
 *  if any. If the "candidateCert" successfully chains, PKIX_TRUE is stored at
 *  the address pointed to by "pPassed". Otherwise PKIX_FALSE is stored.
 *
 * PARAMETERS:
 *  "candidateCert"
 *      Address of Cert that is being checked. Must be non-NULL.
 *  "anchor"
 *      Address of TrustAnchor with which the Cert must successfully chain.
 *      Must be non-NULL.
 *  "traversedSubjNames"
 *      Address of List of subject names in certificates previously traversed.
 *      Must be non-NULL.
 *  "crlChecker"
 *      Address of a CertChainChecker to be used, if present, to check the
 *      candidateCert for revocation.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a Build Error if the function fails in a non-fatal way
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
static PKIX_Error *
pkix_Build_CheckCertAgainstAnchor(
        PKIX_PL_Cert *candidateCert,
        PKIX_TrustAnchor *anchor,
        PKIX_List *traversedSubjNames,
        PKIX_CertChainChecker *crlChecker,
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

        PKIX_ENTER(BUILD, "pkix_Build_CheckCertAgainstAnchor");
        PKIX_NULLCHECK_THREE(anchor, candidateCert, pPassed);

        *pPassed = PKIX_FALSE;

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

        if (!anchorMatch) {
                goto cleanup;
        }

        PKIX_CHECK(PKIX_TrustAnchor_GetNameConstraints
                    (anchor, &anchorNC, plContext),
                    "PKIX_TrustAnchor_GetNameConstraints failed");

        if (!anchorNC) {
                PKIX_CHECK(PKIX_CertSelector_Create
                            (NULL, NULL, &certSel, plContext),
                            "PKIX_CertSelector_Create failed");

                PKIX_CHECK(PKIX_ComCertSelParams_Create
                            (&certSelParams, plContext),
                            "PKIX_ComCertSelParams_Create failed");

                PKIX_NULLCHECK_ONE(traversedSubjNames);

                PKIX_CHECK(PKIX_ComCertSelParams_SetPathToNames
                        (certSelParams, traversedSubjNames, plContext),
                        "PKIX_ComCertSelParams_SetPathToNames failed");

                PKIX_CHECK(PKIX_CertSelector_SetCommonCertSelectorParams
                        (certSel, certSelParams, plContext),
                        "PKIX_CertSelector_SetCommonCertSelectorParams failed");

                PKIX_CHECK(PKIX_CertSelector_GetMatchCallback
                        (certSel, &selectorMatch, plContext),
                        "PKIX_CertSelector_GetMatchCallback failed");

                PKIX_CHECK(selectorMatch
                        (certSel, candidateCert, &certMatch, plContext),
                        "selectorMatch failed");

                if (!certMatch) {
                        goto cleanup;
                }

        }

        PKIX_CHECK(PKIX_PL_Cert_GetSubjectPublicKey
                (trustedCert, &trustedPubKey, plContext),
                "PKIX_PL_Cert_GetSubjectPublicKey failed");

        PKIX_CHECK(PKIX_PL_Cert_VerifySignature
                (candidateCert, trustedPubKey, plContext),
                "PKIX_PL_Cert_VerifySignature failed");

        if (crlChecker) {

                PKIX_CHECK(PKIX_CertChainChecker_GetCertChainCheckerState
                        (crlChecker, &crlCheckerState, plContext),
                        "PKIX_CertChainChecker_GetCertChainCheckerState "
                        "failed");

                PKIX_CHECK(pkix_CheckType
                        (crlCheckerState,
                        PKIX_DEFAULTCRLCHECKERSTATE_TYPE,
                        plContext),
                        "Object is not a DefaultCRLCheckerState object");

                PKIX_CHECK(pkix_DefaultCRLChecker_Check_Helper
                        (crlChecker,
                        candidateCert,
                        trustedPubKey,
                        (pkix_DefaultCRLCheckerState *)crlCheckerState,
                        NULL, /* unresolved crit extensions */
                        plContext),
                        "pkix_DefaultCRLChecker_Check_Helper failed");
        }

        *pPassed = PKIX_TRUE;

cleanup:

        PKIX_DECREF(trustedCert);
        PKIX_DECREF(anchorNC);
        PKIX_DECREF(certSel);
        PKIX_DECREF(certSelParams);
        PKIX_DECREF(trustedSubject);
        PKIX_DECREF(trustedPubKey);
        PKIX_DECREF(candidateIssuer);
        PKIX_DECREF(crlCheckerState);

        PKIX_RETURN(BUILD);
}



/*
 * FUNCTION: pkix_Build_IsChainCompleted
 * DESCRIPTION:
 *
 *  Checks whether the Cert pointed to by "candidateCert" successfully chains to
 *  one of the TrustAnchors found in the BuildConstants pointed to by
 *  "buildConstants", without name constraints being violated by any of the
 *  previous subject names traversed, in the List pointed to by
 *  "traversedSubjNames". If the Cert does successfully chain to one of the
 *  TrustAnchors, that TrustAnchor is stored at "pMatchingAnchor".  If the Cert
 *  does not successfully chain to one of the Trust Anchors, NULL is stored at
 *  "pMatchingAnchor".
 *
 * PARAMETERS:
 *  "buildConstants"
 *      Address of the BuildConstants structure used in this chain-building.
 *      Must be non-NULL.
 *  "candidateCert"
 *      Address of Cert to be checked. Must be non-NULL.
 *  "traversedSubjNames"
 *      Address of List of subject names in certificates previously traversed.
 *      Must be non-NULL.
 *  "pMatchingAnchor"
 *      Address where the successfully-chaining TrustAnchor, if any, is stored.
 *      Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a Build Error if the function fails in a non-fatal way
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
static PKIX_Error *
pkix_Build_IsChainCompleted(
        const BuildConstants *buildConstants,
        PKIX_PL_Cert *candidateCert,
        PKIX_List *traversedSubjNames,
        PKIX_TrustAnchor **pMatchingAnchor,
        void *plContext)
{
        PKIX_TrustAnchor *anchor = NULL;
        PKIX_TrustAnchor *anchorResult = NULL;
        PKIX_Boolean passed = PKIX_FALSE;
        PKIX_UInt32 i;

        PKIX_ENTER(BUILD, "pkix_Build_IsChainCompleted");
        PKIX_NULLCHECK_THREE(buildConstants, candidateCert, pMatchingAnchor);
        PKIX_NULLCHECK_ONE(buildConstants->anchors);

        for (i = 0; (i < buildConstants->numAnchors) && (!anchorResult); i++) {

                PKIX_CHECK_ONLY_FATAL(PKIX_List_GetItem
                        (buildConstants->anchors,
                        i,
                        (PKIX_PL_Object **)&anchor,
                        plContext),
                        "PKIX_List_GetItem failed");

                if (!PKIX_ERROR_RECEIVED) {

                        PKIX_CHECK(pkix_Build_CheckCertAgainstAnchor
                                (candidateCert,
                                anchor,
                                traversedSubjNames,
                                buildConstants->crlChecker,
                                &passed,
                                plContext),
                                "pkix_CheckCertAgainstAnchor failed");

                        if (passed == PKIX_TRUE) {
                                PKIX_INCREF(anchor);
                                anchorResult = anchor;
                        }
                }

                PKIX_DECREF(anchor);
        }

        *pMatchingAnchor = anchorResult;

        goto cleanup;
cleanup:

        if (PKIX_ERROR_RECEIVED){
                PKIX_DECREF(anchor);
        }

        PKIX_RETURN(BUILD);
}

/*
 * FUNCTION: pkix_Build_VerifyCertificate
 * DESCRIPTION:
 *
 *  Checks whether the previous Cert stored in the ForwardBuilderState pointed
 *  to by "state" successfully chains, including signature verification, to the
 *  candidate Cert also stored in "state", using the Boolean value in "trusted"
 *  to determine whether "candidateCert" is trusted. Also checks whether
 *  "candidateCert" has already been traversed by comparing it to the List of
 *  traversed Certs. Finally, it subjects the candidate Cert to checking by
 *  checkers, if any, in the List pointed to by "userCheckers", and to CRL
 *  verification by the CertChain Checker, if any, pointed to by "crlChecker".
 *  If any of these checks fail, an Error pointer is returned.
 *
 * PARAMETERS:
 *  "state"
 *      Address of ForwardBuilderState to be used. Must be non-NULL.
 *  "userCheckers"
 *      Address of a List of CertChainCheckers to be used, if present, to
 *      validate the candidateCert.
 *  "crlChecker"
 *      Address of a CertChainChecker to be used, if present, to check the
 *      candidateCert for revocation.
 *  "trusted"
 *      Boolean value of trust for the candidate Cert
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a Build Error if the function fails in a non-fatal way
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
static PKIX_Error *
pkix_Build_VerifyCertificate(
        PKIX_ForwardBuilderState *state,
        PKIX_List *userCheckers,
        PKIX_CertChainChecker *crlChecker,
        PKIX_Boolean trusted,
        void *plContext)
{
        PKIX_UInt32 numUserCheckers = 0;
        PKIX_UInt32 numItems = 0;
        PKIX_UInt32 i = 0;
        PKIX_Boolean loopFound = PKIX_FALSE;
        PKIX_Boolean dsaParamsNeeded = PKIX_FALSE;
        PKIX_Boolean isSelfIssued = PKIX_FALSE;
        PKIX_Boolean supportForwardChecking = PKIX_FALSE;
        PKIX_PL_Cert *candidateCert = NULL;
        PKIX_PL_PublicKey *candidatePubKey = NULL;
        PKIX_CertChainChecker *userChecker = NULL;
        PKIX_CertChainChecker_CheckCallback checkerCheck = NULL;
        PKIX_List *unresCritExtOIDs = NULL;
        PKIX_PL_Object *crlCheckerState = NULL;

        PKIX_ENTER(BUILD, "pkix_Build_VerifyCertificate");
        PKIX_NULLCHECK_FOUR
                (state,
                state->candidateCert,
                state->prevCert,
                state->trustChain);

        candidateCert = state->candidateCert;

        /* check for loops */

        PKIX_CHECK(pkix_List_Contains
                (state->trustChain,
                (PKIX_PL_Object *)candidateCert,
                &loopFound,
                plContext),
                "pkix_List_Contains failed");

        if (loopFound) {
                PKIX_ERROR("Loop discovered: "
                            "duplicate certificates not allowed");
        }

        if (userCheckers != NULL) {

                PKIX_CHECK(PKIX_List_GetLength
                    (userCheckers, &numUserCheckers, plContext),
                    "PKIX_List_GetLength failed");

                for (i = 0; i < numUserCheckers; i++) {

                        PKIX_CHECK(PKIX_List_GetItem
                            (userCheckers,
                            i,
                            (PKIX_PL_Object **) &userChecker,
                            plContext),
                            "PKIX_List_GetItem failed");

                        PKIX_CHECK
                            (PKIX_CertChainChecker_IsForwardCheckingSupported
                            (userChecker, &supportForwardChecking, plContext),
                            "PKIX_CertChainChecker_IsForwardCheckingSupported "
                            "failed");

                        if (supportForwardChecking == PKIX_TRUE) {

                            PKIX_CHECK(PKIX_CertChainChecker_GetCheckCallback
                                (userChecker, &checkerCheck, plContext),
                                "PKIX_CertChainChecker_GetCheckCallback "
                                "failed");

                            PKIX_CHECK(checkerCheck
                                (userChecker, candidateCert, NULL, plContext),
                                "checkerCheck failed");
                        }

                        PKIX_DECREF(userChecker);
                }
        }

        /* signature check */

        if ((!(state->dsaParamsNeeded)) || trusted) {
                PKIX_CHECK(PKIX_PL_Cert_GetSubjectPublicKey
                            (candidateCert, &candidatePubKey, plContext),
                            "PKIX_PL_Cert_GetSubjectPublicKey failed");

                PKIX_CHECK(PKIX_PL_PublicKey_NeedsDSAParameters
                            (candidatePubKey, &dsaParamsNeeded, plContext),
                            "PKIX_PL_PublicKey_NeedsDSAParameters failed");

                if (dsaParamsNeeded) {
                        if (trusted) {
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

                if (crlChecker){
                        if (!trusted && (state->revCheckDelayed)) {
                                goto cleanup;
                        } else if (!trusted && !(state->revCheckDelayed)) {
                                PKIX_CHECK(pkix_IsCertSelfIssued
                                        (candidateCert,
                                        &isSelfIssued,
                                        plContext),
                                        "pkix_IsCertSelfIssued failed");

                                if (isSelfIssued) {
                                        state->revCheckDelayed = PKIX_TRUE;
                                        goto cleanup;
                                }
                        }

                        PKIX_CHECK(PKIX_PL_Cert_VerifyKeyUsage
                                (candidateCert, PKIX_CRL_SIGN, plContext),
                                "PKIX_PL_Cert_VerifyKeyUsage failed");

                        PKIX_CHECK
                                (PKIX_CertChainChecker_GetCertChainCheckerState
                                (crlChecker, &crlCheckerState, plContext),
                                "PKIX_CertChainChecker_"
                                "GetCertChainCheckerState failed");

                        PKIX_CHECK(pkix_CheckType
                                (crlCheckerState,
                                PKIX_DEFAULTCRLCHECKERSTATE_TYPE,
                                plContext),
                                "Object is not a DefaultCRLCheckerState "
                                "object");

                        PKIX_CHECK(pkix_DefaultCRLChecker_Check_Helper
                                (crlChecker,
                                state->prevCert,
                                candidatePubKey,
                                (pkix_DefaultCRLCheckerState *)
                                crlCheckerState,
                                NULL, /* unresolved crit extensions */
                                plContext),
                                "pkix_DefaultCRLChecker_Check_Helper failed");
                }
        }

cleanup:

        PKIX_DECREF(candidatePubKey);
        PKIX_DECREF(crlCheckerState);

        PKIX_RETURN(BUILD);
}

/*
 * FUNCTION: pkix_Build_ValidateEntireChain
 * DESCRIPTION:
 *
 *  Checks whether the List of Certs pointed to by "certChain" successfully
 *  validates using the BuildConstants pointed to by "buildConstants", the
 *  TrustAnchor pointed to by "anchor", the DSA parameter inheritance indicator
 *  in "dsaParamsNeeded", and the revocation check indicator in
 *  "revCheckDelayed".  If successful, a ValidateResult is created containing
 *  the Public Key of the target certificate (including DSA parameter
 *  inheritance, if any) and the PolicyNode representing the policy tree output
 *  by the validation algorithm.  If not successful, an Error pointer is
 *  returned.
 *
 * PARAMETERS:
 *  "buildConstants"
 *      Address of the BuildConstants structure used in this chain-building.
 *      Must be non-NULL.
 *  "certChain"
 *      Address of List of Certs to be validated. Must be non-NULL.
 *  "anchor"
 *      Address of TrustAnchor to be used. Must be non-NULL.
 *  "dsaParamsNeeded"
 *      Boolean value indicating whether DSA parameters are needed.
 *  "revCheckDelayed"
 *      Boolean value indicating whether rev check is delayed until after
 *      entire chain is built.
 *  "pValResult"
 *      Address at which the ValidateResult is stored. Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a Build Error if the function fails in a non-fatal way
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
static PKIX_Error *
pkix_Build_ValidateEntireChain(
        const BuildConstants *buildConstants,
        PKIX_List *certChain,
        PKIX_TrustAnchor *anchor,
        PKIX_Boolean dsaParamsNeeded,
        PKIX_Boolean revCheckDelayed,
        PKIX_ValidateResult **pValResult,
        void *plContext)
{
        PKIX_List *checkers = NULL;
        PKIX_List *initialPolicies = NULL;
        PKIX_List *buildCheckedCritExtOIDsList = NULL;
        PKIX_ProcessingParams *procParams = NULL;
        PKIX_PL_Cert *trustedCert = NULL;
        PKIX_PL_PublicKey *trustedPubKey = NULL;
        PKIX_PL_PublicKey *subjPubKey = NULL;
        PKIX_PolicyNode *policyTree = NULL;
        PKIX_ValidateResult *valResult = NULL;
        PKIX_CertChainChecker *sigChecker = NULL;
        PKIX_CertChainChecker *crlChecker = NULL;
        PKIX_CertChainChecker *policyChecker = NULL;
        PKIX_CertChainChecker *userChecker = NULL;
        PKIX_List *reversedCertChain = NULL;
        PKIX_List *userCheckersList = NULL;
        PKIX_List *userCheckerExtOIDs = NULL;
        PKIX_PL_OID *oid = NULL;
        PKIX_Boolean supportForwardChecking = PKIX_FALSE;
        PKIX_Boolean policyQualifiersRejected = PKIX_FALSE;
        PKIX_Boolean initialPolicyMappingInhibit = PKIX_FALSE;
        PKIX_Boolean initialAnyPolicyInhibit = PKIX_FALSE;
        PKIX_Boolean initialExplicitPolicy = PKIX_FALSE;
        PKIX_UInt32 numChainCerts;
        PKIX_UInt32 numCertCheckers;
        PKIX_UInt32 i;

        PKIX_ENTER(BUILD, "pkix_Build_ValidateEntireChain");
        PKIX_NULLCHECK_FOUR(buildConstants, certChain, anchor, pValResult);

        PKIX_CHECK(PKIX_List_Create(&checkers, plContext),
                "PKIX_List_Create failed");

        PKIX_CHECK(PKIX_List_ReverseList
                (certChain, &reversedCertChain, plContext),
                "PKIX_List_ReverseList failed");

        PKIX_CHECK(PKIX_List_GetLength
                (reversedCertChain, &numChainCerts, plContext),
                "PKIX_List_GetLength failed");

        procParams = buildConstants->procParams;

        PKIX_CHECK(PKIX_ProcessingParams_GetInitialPolicies
                (procParams, &initialPolicies, plContext),
                "PKIX_ProcessingParams_GetInitialPolicies");

        PKIX_CHECK(PKIX_ProcessingParams_GetPolicyQualifiersRejected
                (procParams, &policyQualifiersRejected, plContext),
                "PKIX_ProcessingParams_GetPolicyQualifiersRejected");

        PKIX_CHECK(PKIX_ProcessingParams_IsPolicyMappingInhibited
                (procParams, &initialPolicyMappingInhibit, plContext),
                "PKIX_ProcessingParams_IsPolicyMappingInhibited");

        PKIX_CHECK(PKIX_ProcessingParams_IsAnyPolicyInhibited
                (procParams, &initialAnyPolicyInhibit, plContext),
                "PKIX_ProcessingParams_IsAnyPolicyInhibited");

        PKIX_CHECK(PKIX_ProcessingParams_IsExplicitPolicyRequired
                (procParams, &initialExplicitPolicy, plContext),
                "PKIX_ProcessingParams_IsExplicitPolicyRequired");

        PKIX_CHECK(pkix_PolicyChecker_Initialize
                (initialPolicies,
                policyQualifiersRejected,
                initialPolicyMappingInhibit,
                initialAnyPolicyInhibit,
                initialExplicitPolicy,
                numChainCerts,
                &policyChecker,
                plContext),
                "pkix_PolicyChecker_Initialize failed");

        PKIX_CHECK(PKIX_List_AppendItem
                (checkers, (PKIX_PL_Object *)policyChecker, plContext),
                "PKIX_List_AppendItem failed");

        /*
         * Create an OID list that contains critical extensions processed
         * by BuildChain. These are specified in a static const array.
         */
        PKIX_CHECK(PKIX_List_Create(&buildCheckedCritExtOIDsList, plContext),
                "PKIX_List_Create failed");

        for (i = 0; buildCheckedCritExtOIDs[i] != NULL; i++) {
                PKIX_CHECK(PKIX_PL_OID_Create
                        (buildCheckedCritExtOIDs[i], &oid, plContext),
                        "PKIX_PL_OID_Create failed");

                PKIX_CHECK(PKIX_List_AppendItem
                        (buildCheckedCritExtOIDsList,
                        (PKIX_PL_Object *) oid,
                        plContext),
                        "PKIX_List_AppendItem failed");

                PKIX_DECREF(oid);
        }

        if (buildConstants->userCheckers != NULL) {

                PKIX_CHECK(PKIX_List_GetLength
                        (buildConstants->userCheckers,
                        &numCertCheckers,
                        plContext),
                        "PKIX_List_GetLength failed");

                for (i = 0; i < numCertCheckers; i++) {

                        PKIX_CHECK(PKIX_List_GetItem
                            (buildConstants->userCheckers,
                            i,
                            (PKIX_PL_Object **) &userChecker,
                            plContext),
                            "PKIX_List_GetItem failed");

                        PKIX_CHECK
                            (PKIX_CertChainChecker_IsForwardCheckingSupported
                            (userChecker, &supportForwardChecking, plContext),
                            "PKIX_CertChainChecker_IsForwardCheckingSupported "
                            "failed");

                        /*
                         * If this userChecker supports forwardChecking then it
                         * should have been checked during build chain. Skip
                         * checking but need to add checker's extension OIDs
                         * to buildCheckedCritExtOIDsList.
                         */
                        if (supportForwardChecking == PKIX_TRUE) {

                            PKIX_CHECK
                                (PKIX_CertChainChecker_GetSupportedExtensions
                                (userChecker, &userCheckerExtOIDs, plContext),
                                "PKIX_CertChainChecker_GetSupportedExtensions "
                                "failed");

                            if (userCheckerExtOIDs != NULL) {
                                PKIX_CHECK(pkix_List_AppendList
                                    (buildCheckedCritExtOIDsList,
                                    userCheckerExtOIDs,
                                    plContext),
                                    "pkix_List_AppendList failed");
                            }

                        } else {
                            PKIX_CHECK(PKIX_List_AppendItem
                                (checkers,
                                (PKIX_PL_Object *)userChecker,
                                plContext),
                                "PKIX_List_AppendItem failed");
                        }

                        PKIX_DECREF(userCheckerExtOIDs);
                        PKIX_DECREF(userChecker);
                }
        }

        if (dsaParamsNeeded || revCheckDelayed) {

                if (dsaParamsNeeded || (buildConstants->crlChecker)) {

                        PKIX_CHECK(PKIX_TrustAnchor_GetTrustedCert
                                    (anchor, &trustedCert, plContext),
                                    "PKIX_TrustAnchor_GetTrustedCert failed");

                        PKIX_CHECK(PKIX_PL_Cert_GetSubjectPublicKey
                                    (trustedCert, &trustedPubKey, plContext),
                                    "PKIX_PL_Cert_GetSubjectPublicKey failed");

                        PKIX_NULLCHECK_ONE(buildConstants->certStores);

                        PKIX_CHECK(pkix_DefaultCRLChecker_Initialize
                                    (buildConstants->certStores,
                                    buildConstants->testDate,
                                    trustedPubKey,
                                    numChainCerts,
                                    &crlChecker,
                                    plContext),
                                    "pkix_DefaultCRLChecker_Initialize failed");

                        PKIX_CHECK(PKIX_List_AppendItem
                                    (checkers,
                                    (PKIX_PL_Object *)crlChecker,
                                    plContext),
                                    "PKIX_List_AppendItem failed");

                        if (dsaParamsNeeded) {

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
                    (reversedCertChain,
                    numChainCerts,
                    checkers,
                    buildCheckedCritExtOIDsList,
                    &subjPubKey,
                    &policyTree,
                    plContext),
                    "pkix_CheckChain failed");

        if (!dsaParamsNeeded) {
                PKIX_INCREF(buildConstants->targetPubKey);
                subjPubKey = buildConstants->targetPubKey;
        }

        PKIX_CHECK(pkix_ValidateResult_Create
                (subjPubKey, anchor, policyTree, &valResult, plContext),
                "pkix_ValidateResult_Create failed");

        *pValResult = valResult;

cleanup:

        PKIX_DECREF(checkers);
        PKIX_DECREF(initialPolicies);
        PKIX_DECREF(buildCheckedCritExtOIDsList);
        PKIX_DECREF(trustedCert);
        PKIX_DECREF(trustedPubKey);
        PKIX_DECREF(sigChecker);
        PKIX_DECREF(crlChecker);
        PKIX_DECREF(policyChecker);
        PKIX_DECREF(reversedCertChain);
        PKIX_DECREF(userChecker);
        PKIX_DECREF(userCheckersList);
        PKIX_DECREF(subjPubKey);
        PKIX_DECREF(policyTree);

        PKIX_RETURN(BUILD);
}

/*
 * FUNCTION: pkix_Build_BuildSelectorAndParams
 * DESCRIPTION:
 *
 *  This function creates a CertSelector, initialized with an appropriate
 *  ComCertSelParams, using the variables provided in the ForwardBuilderState
 *  pointed to by "state" and the BuildConstants pointed to by "buildConstants".
 *  The CertSelector created is stored in the certsel element of "state".
 *  returned.
 *
 * PARAMETERS:
 *  "state"
 *      Address of ForwardBuilderState to be used. Must be non-NULL.
 *  "buildConstants"
 *      Address of the BuildConstants structure used in this chain-building.
 *      Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a Build Error if the function fails in a non-fatal way
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
static PKIX_Error *
pkix_Build_BuildSelectorAndParams(
        PKIX_ForwardBuilderState *state,
        const BuildConstants *buildConstants,
        void *plContext)
{
        PKIX_ComCertSelParams *certSelParams = NULL;
        PKIX_CertSelector *certSel = NULL;
        PKIX_PL_X500Name *currentIssuer = NULL;
        PKIX_PL_Date *testDate = NULL;

        PKIX_ENTER(BUILD, "pkix_Build_BuildSelectorAndParams");
        PKIX_NULLCHECK_ONE(state);

        PKIX_NULLCHECK_TWO(state->prevCert, state->traversedSubjNames);

        PKIX_CHECK(PKIX_PL_Cert_GetIssuer
                (state->prevCert, &currentIssuer, plContext),
                "PKIX_PL_Cert_GetIssuer failed");

        PKIX_CHECK(PKIX_ComCertSelParams_Create
                    (&certSelParams, plContext),
                    "PKIX_ComCertSelParams_Create failed");

        PKIX_CHECK(PKIX_ComCertSelParams_SetSubject
                (certSelParams, currentIssuer, plContext),
                "PKIX_ComCertSelParams_SetSubject failed");

#if 0
        if (buildConstants->testDate) {
                PKIX_INCREF(buildConstants->testDate);
                testDate = buildConstants->testDate;
        } else {
                PKIX_CHECK(PKIX_PL_Date_Create_UTCTime
                        (NULL, &testDate, plContext),
                        "PKIX_PL_Date_Create_UTCTime failed");
        }
#else
        PKIX_INCREF(buildConstants->testDate);
        testDate = buildConstants->testDate;
#endif

        PKIX_CHECK(PKIX_ComCertSelParams_SetCertificateValid
                (certSelParams, testDate, plContext),
                "PKIX_ComCertSelParams_SetCertificateValid failed");

        PKIX_CHECK(PKIX_ComCertSelParams_SetBasicConstraints
                (certSelParams, state->traversedCACerts, plContext),
                "PKIX_ComCertSelParams_SetBasicConstraints failed");

        PKIX_CHECK(PKIX_ComCertSelParams_SetPathToNames
                (certSelParams, state->traversedSubjNames, plContext),
                "PKIX_ComCertSelParams_SetPathToNames failed");

        PKIX_CHECK(PKIX_CertSelector_Create
                (NULL, NULL, &state->certSel, plContext),
                "PKIX_CertSelector_Create failed");

        PKIX_CHECK(PKIX_CertSelector_SetCommonCertSelectorParams
                (state->certSel, certSelParams, plContext),
                "PKIX_CertSelector_SetCommonCertSelectorParams failed");

cleanup:
        PKIX_DECREF(certSelParams);
        PKIX_DECREF(certSel);
        PKIX_DECREF(currentIssuer);
        PKIX_DECREF(testDate);

        PKIX_RETURN(BUILD);
}

/*

 */
/*
 * FUNCTION: pkix_BuildForwardDepthFirstSearch
 * DESCRIPTION:
 *
 *  This function performs a depth first search in the "forward" direction (from
 *  the target Cert to the trust anchor). A non-NULL targetCert must be stored
 *  in the ForwardBuilderState before this function is called. It is not written
 *  recursively since execution may be suspended in step 1 pending completion of
 *  non-blocking I/O. This iterative structure makes it much easier to resume
 *  where it left off.
 *
 *  Since the nature of the search is recursive, the recursion is handled by
 *  chaining states. That is, each new step involves creating a new
 *  ForwardBuilderState linked to its predecessor. If a step turns out to be
 *  fruitless, the state of the predecessor is restored and the next alternative
 *  is tried.
 *
 *  There are two return arguments, the ValidateResult and the PRPollDesc. If
 *  both are NULL, it means the search has failed. If the ValidateResult is
 *  non-NULL, it means the search has concluded successfully. If the
 *  ValidateResult is NULL but the PRPollDesc argument is non-NULL, it means the
 *  search is suspended until the results of a non-blocking IO become available.
 *  The caller may wait for the completion using PRPoll and then call this
 *  function again, allowing it to resume the search.
 *
 *  This function performs several steps at each node in the constructed chain:
 *
 *  1) It retrieves Certs from the registered CertStores that match the
 *  criteria established by the ForwardBuilderState pointed to by "state", such
 *  as a subject name matching the issuer name of the previous Cert. If there
 *  are no matching Certs, the function returns to the previous, or "parent",
 *  state and tries to continue the chain building with another of the Certs
 *  obtained from the CertStores as possible issuers for that parent Cert.
 *
 *  2) For each candidate Cert returned by the CertStores, this function checks
 *  whether the Cert is valid. If it is trusted, this function checks whether
 *  this Cert might serve as a TrustAnchor for a complete chain.
 *
 *  3) It determines whether this Cert, in conjunction with any of the
 *  TrustAnchors, might complete a chain. A complete chain, from this or the
 *  preceding step, is checked to see whether it is valid as a complete
 *  chain, including the checks that cannot be done in the forward direction.
 *
 *  4) If this Cert chains successfully, but is not a complete chain, that is,
 *  we have not reached a trusted Cert, a new ForwardBuilderState is created
 *  with this Cert as the immediate predecessor, and we continue in step (1),
 *  attempting to get Certs from the CertStores with this Certs "issuer" as
 *  their subject.
 *
 *  5) If an entire chain validates successfully, then we are done. A
 *  ValidateResult is created containing the Public Key of the target
 *  certificate (including DSA parameter inheritance, if any) and the
 *  PolicyNode representing the policy tree output by the validation algorithm,
 *  and stored at pValResult, and the function exits returning NULL.
 *
 *  5) If the entire chain does not validate successfully, the algorithm
 *  discards the latest Cert and continues in step 2 with the next candidate
 *  Cert, backing up to a parent state when no more possibilities exist at a
 *  given level, and returning failure when we try to back up but discover we
 *  are at the top level.
 *
 * PARAMETERS:
 *  "buildConstants"
 *      Address of the BuildConstants structure used in this chain-building.
 *      Must be non-NULL.
 *  "state"
 *      Address of ForwardBuilderState to be used. Must be non-NULL.
 *  "pValResult"
 *      Address at which the ValidateResult is stored. Must be non-NULL.
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
pkix_BuildForwardDepthFirstSearch(
        const BuildConstants *buildConstants,
        PKIX_ForwardBuilderState *state,
        PKIX_ValidateResult **pValResult,
/*      PRPollDesc **pPollDesc, */
        void *plContext)
{
        PKIX_Boolean outOfOptions = PKIX_FALSE;
        PKIX_Boolean trusted = PKIX_FALSE;
        PKIX_Boolean isSelfIssued = PKIX_FALSE;
        PKIX_Boolean certStoreHasCache = PKIX_FALSE;
        PKIX_Boolean foundInCache = PKIX_FALSE;
        PKIX_Boolean canBeCached = PKIX_FALSE;
        PKIX_Int32 comparison = 0;
        PKIX_PL_Date *notAfter = NULL;
        PKIX_Int32 childTraversedCACerts = 0;
        PKIX_UInt32 numSubjectNames = 0;
        PKIX_UInt32 numChained = 0;
        PKIX_UInt32 i = 0;
        PKIX_List *childTraversedSubjNames = NULL;
        PKIX_List *certsFound = NULL;
        PKIX_List *subjectNames = NULL;
        PKIX_PL_Object *subjectName = NULL;
        PKIX_ValidateResult *valResult = NULL;
/*      PRPollDesc *pollDesc = NULL; */
        PKIX_ForwardBuilderState *childState = NULL;
        PKIX_ForwardBuilderState *parentState = NULL;
        PKIX_PL_PublicKey *finalSubjPubKey = NULL;
        PKIX_PolicyNode *finalPolicyTree = NULL;
        PKIX_CertStore *certStore = NULL;
        PKIX_ComCertSelParams *certSelParams = NULL;
        PKIX_CertStore_CertCallback getCerts = NULL;
        PKIX_TrustAnchor *trustAnchor = NULL;
#if PKIX_FORWARDBUILDERSTATEDEBUG
        PKIX_PL_String *stateString = NULL;
        char *stateAscii = NULL;
        PKIX_UInt32 length;
#endif

        PKIX_ENTER(BUILD, "pkix_BuildForwardDepthFirstSearch");
        PKIX_NULLCHECK_THREE(buildConstants, state, pValResult);
/*         PKIX_NULLCHECK_ONE(pPollDesc); */

        /*
         * We return if successful; if we fall off the end
         * of this "while" clause our search has failed.
         */
        while (outOfOptions == PKIX_FALSE) {

            /* ****Phase 1 - Finding all possible Certs***** */
            while (state->status != BUILD_CHAINBUILDING) {
                if (state->status == BUILD_INITIAL) {

                    PKIX_CHECK(pkix_Build_BuildSelectorAndParams
                        (state, buildConstants, plContext),
                        "pkix_Build_BuildSelectorAndParams failed");

                    PKIX_CHECK(PKIX_CertSelector_GetCommonCertSelectorParams
                        (state->certSel, &certSelParams, plContext),
                        "PKIX_CertSelector_GetCommonCertSelectorParams failed");

                    state->certStoreIndex = 0;
                    state->status = BUILD_COLLECTINGCERTS;
                    PKIX_CHECK(PKIX_List_Create
                        (&state->candidateCerts, plContext),
                        "PKIX_List_Create failed");
                }


#if PKIX_FORWARDBUILDERSTATEDEBUG
                PKIX_CHECK(PKIX_PL_Object_InvalidateCache
                        ((PKIX_PL_Object *)state, plContext),
                        "PKIX_PL_Object_InvalidateCache failed");

                PKIX_CHECK(PKIX_PL_Object_ToString
                        ((PKIX_PL_Object*)state, &stateString, plContext),
                        "PKIX_PL_Object_ToString failed");

                PKIX_CHECK(PKIX_PL_String_GetEncoded
                            (stateString,
                            PKIX_ESCASCII,
                            (void **)&stateAscii,
                            &length,
                            plContext),
                            "PKIX_PL_String_GetEncoded failed");

                PKIX_DEBUG_ARG("In Phase 1: state = %s\n", stateAscii);

                PKIX_FREE(stateAscii);
                PKIX_DECREF(stateString);
#endif

                /* Get the current CertStore */
                PKIX_CHECK(PKIX_List_GetItem
                        (buildConstants->certStores,
                        state->certStoreIndex,
                        (PKIX_PL_Object **)&certStore,
                        plContext),
                        "PKIX_List_GetItem failed");

                PKIX_CHECK(PKIX_CertStore_GetCertStoreCacheFlag
                        (certStore, &certStoreHasCache, plContext),
                        "PKIX_CertStore_GetCertStoreCacheFlag failed");

                foundInCache = PKIX_FALSE;
                if (certStoreHasCache) {
                /*
                 * Look for Certs in the cache, using the SubjectName as
                 * the key. Then the ComCertSelParams are used to filter for
                 * qualified certs. If none are found, then the certStores are
                 * queried. When we eventually add items to the cache, we will
                 * only add items that passed the ComCertSelParams filter,
                 * rather than all Certs which matched the SubjectName.
                 */

                        PKIX_CHECK(pkix_CacheCert_Lookup
                            (certStore,
                            certSelParams,
                            buildConstants->testDate,
                            &foundInCache,
                            &certsFound,
                            plContext),
                            "pkix_CacheCertChain_Lookup failed");

                }
                /*
                 * XXX need to verify if Cert is trusted, hence may not worth
                 * to have the Cert Cached or
                 * If it is trusted, don't cache, but once there is cached
                 * certs, we won't get certs from database any more.
                 * can use flag to force not getting certs from cache
                 */
                if (!foundInCache) {

                        PKIX_CHECK(PKIX_CertStore_GetCertCallback
                                (certStore, &getCerts, plContext),
                                "PKIX_CertStore_GetCertCallback failed");

                        PKIX_CHECK(getCerts
                                (certStore,
                                state->certSel,
                                &certsFound,
                                plContext),
                                "getCerts failed");

                        if (certStoreHasCache) {

                                PKIX_CHECK(pkix_CacheCert_Add
                                        (certStore,
                                        certSelParams,
                                        certsFound,
                                        plContext),
                                        "pkix_CacheCert_Add failed");
                        }
                }

                /*
                 * getCerts returns an empty list for "NONE FOUND",
                 * a NULL list for "would block"
                 */
                if (certsFound == NULL) {
                        state->status = BUILD_IOPENDING;
                        *pValResult = NULL;
                        /* XXX *pPollDesc = certstore->polldesc; */
                        goto cleanup;
                } else {
                        PKIX_CHECK(pkix_List_AppendUnique
                                (state->candidateCerts, certsFound, plContext),
                                "pkix_List_AppendUnique failed");
                        PKIX_DECREF(certsFound);
                }

                /* Are there any more certStores to query? */
                PKIX_DECREF(certStore);
                if (++(state->certStoreIndex) >=
                        buildConstants->numCertStores) {
                        /* No, ready for our next adventure */
                        state->status = BUILD_CHAINBUILDING;
                        PKIX_CHECK(PKIX_List_GetLength
                                (state->candidateCerts,
                                &state->numCerts,
                                plContext),
                                "PKIX_List_GetLength failed");
                        /* sort state->candidateCerts */
                        state->certIndex = 0;
                /* } else {  Yes, remain in phase 1 */
                }
            } /* while (state->status != BUILD_CHAINBUILDING) */

            /* ****Phase 2 - Chain building***** */

            /* Are there any Certs to try? */
            if (state->numCerts > 0) {

#if PKIX_FORWARDBUILDERSTATEDEBUG
                PKIX_CHECK(PKIX_PL_Object_InvalidateCache
                        ((PKIX_PL_Object *)state, plContext),
                        "PKIX_PL_Object_InvalidateCache failed");

                PKIX_CHECK(PKIX_PL_Object_ToString
                        ((PKIX_PL_Object*)state, &stateString, plContext),
                        "PKIX_PL_Object_ToString failed");

                PKIX_CHECK(PKIX_PL_String_GetEncoded
                            (stateString,
                            PKIX_ESCASCII,
                            (void **)&stateAscii,
                            &length,
                            plContext),
                            "PKIX_PL_String_GetEncoded failed");

                PKIX_DEBUG_ARG("In Phase 2: state = %s\n", stateAscii);

                PKIX_FREE(stateAscii);
                PKIX_DECREF(stateString);
#endif

                PKIX_CHECK(PKIX_List_GetItem
                        (state->candidateCerts,
                        state->certIndex,
                        (PKIX_PL_Object **)&state->candidateCert,
                        plContext),
                        "PKIX_List_GetItem failed");

                PKIX_CHECK(PKIX_PL_Cert_IsCertTrusted
                        (state->candidateCert, &trusted, plContext),
                        "PKIX_PL_Cert_IsCertTrusted failed");

                PKIX_CHECK_ONLY_FATAL(pkix_Build_VerifyCertificate
                        (state,
                        buildConstants->userCheckers,
                        buildConstants->crlChecker,
                        trusted,
                        plContext),
                        "pkix_Build_VerifyCertificate failed");

                if (!PKIX_ERROR_RECEIVED) {
                        if (trusted) {

                                /*
                                 * If this cert is trusted, try
                                 * ValidateEntireChain using this certificate
                                 * as matching anchor
                                 */
                                PKIX_CHECK(PKIX_TrustAnchor_CreateWithCert
                                    (state->candidateCert,
                                    &trustAnchor,
                                    plContext),
                                    "PKIX_TrustAnchor_CreateWithCert failed");

                                PKIX_CHECK_ONLY_FATAL
                                    (pkix_Build_ValidateEntireChain
                                    (buildConstants,
                                    state->trustChain,
                                    trustAnchor,
                                    state->dsaParamsNeeded,
                                    state->revCheckDelayed,
                                    &valResult,
                                    plContext),
                                    "pkix_Build_ValidateEntireChain failed");

                                if ((!PKIX_ERROR_RECEIVED) &&
                                    (valResult != NULL)) {
                                        *pValResult = valResult;
                                        goto cleanup;
                                }
                        }

                        /*
                         * This Cert was not trusted. Add it to our chain, and
                         * continue building. If we don't reach a trust anchor,
                         * we'll take it off later and continue without it.
                         */
                        PKIX_CHECK(PKIX_List_AppendItem
                                (state->trustChain,
                                (PKIX_PL_Object *)state->candidateCert,
                                plContext),
                                "PKIX_List_AppendItem failed");

                        /* Keep track of whether this chain can be cached */
                        PKIX_CHECK(PKIX_PL_Cert_GetCacheFlag
                                (state->candidateCert, &canBeCached, plContext),
                                "PKIX_Cert_GetCacheFlag failed");

                        canBeCached = state->canBeCached && canBeCached;
                        state->canBeCached = canBeCached;
                        if (canBeCached == PKIX_TRUE) {

                                /*
                                 * So far, all certs can be cached. Update cert
                                 * chain validity time, which is the earliest of
                                 * all certs' notAfter times.
                                 */
                                PKIX_CHECK(PKIX_PL_Cert_GetValidityNotAfter
                                    (state->candidateCert,
                                    &notAfter,
                                    plContext),
                                    "PKIX_PL_Cert_GetValidityNotAfter failed");

                                if (state->validityDate == NULL) {
                                    PKIX_INCREF(notAfter);
                                    state->validityDate = notAfter;
                                } else {
                                    PKIX_CHECK(PKIX_PL_Object_Compare
                                        ((PKIX_PL_Object *)state->validityDate,
                                        (PKIX_PL_Object *)notAfter,
                                        &comparison,
                                        plContext),
                                        "PKIX_PL_Object_Comparator failed");
                                    if (comparison > 0) {
                                        PKIX_DECREF(state->validityDate);
                                        PKIX_INCREF(notAfter);
                                        state->validityDate = notAfter;
                                    }
                                }
                        }


                        /*
                         * Does this chain, with any of our trust
                         * anchors, form a complete trust chain?
                         */
                        PKIX_CHECK(pkix_Build_IsChainCompleted
                                (buildConstants,
                                state->candidateCert,
                                state->traversedSubjNames,
                                &trustAnchor,
                                plContext),
                                "pkix_Build_IsChainCompleted failed");

                        if (trustAnchor) {
                                /*
                                 * Yes, it does! Does the chain pass all
                                 * validation tests?
                                 */
                                PKIX_CHECK_ONLY_FATAL
                                    (pkix_Build_ValidateEntireChain
                                    (buildConstants,
                                    state->trustChain,
                                    trustAnchor,
                                    state->dsaParamsNeeded,
                                    state->revCheckDelayed,
                                    &valResult,
                                    plContext),
                                    "pkix_Build_ValidateEntireChain failed");

                                if ((!PKIX_ERROR_RECEIVED) &&
                                    (valResult != NULL)) {
                                        *pValResult = valResult;
                                        goto cleanup;
                                }

                                PKIX_DECREF(trustAnchor);
                        }

                        PKIX_CHECK(pkix_IsCertSelfIssued
                                (state->candidateCert,
                                &isSelfIssued,
                                plContext),
                                "pkix_IsCertSelfIssued failed");

                        PKIX_CHECK(PKIX_PL_Object_Duplicate
                                ((PKIX_PL_Object *)state->traversedSubjNames,
                                (PKIX_PL_Object **)&childTraversedSubjNames,
                                plContext),
                                "PKIX_PL_Object_Duplicate failed");

                        if (isSelfIssued) {
                                childTraversedCACerts =
                                        state->traversedCACerts;
                        } else {
                                childTraversedCACerts =
                                        state->traversedCACerts + 1;

                                PKIX_CHECK(PKIX_PL_Cert_GetAllSubjectNames
                                    (state->candidateCert,
                                    &subjectNames,
                                    plContext),
                                    "PKIX_PL_Cert_GetAllSubjectNames failed");

                                if (subjectNames) {
                                        PKIX_CHECK(PKIX_List_GetLength
                                                (subjectNames,
                                                &numSubjectNames,
                                                plContext),
                                                "PKIX_List_GetLength failed");
                                } else {
                                        numSubjectNames = 0;
                                }
                                for (i = 0; i < numSubjectNames; i++) {
                                        PKIX_CHECK(PKIX_List_GetItem
                                                (subjectNames,
                                                i,
                                                &subjectName,
                                                plContext),
                                                "PKIX_List_GetItem failed");
                                        PKIX_NULLCHECK_ONE
                                                (state->traversedSubjNames);
                                        PKIX_CHECK(PKIX_List_AppendItem
                                                (state->traversedSubjNames,
                                                subjectName,
                                                plContext),
                                                "PKIX_List_AppendItem failed");
                                        PKIX_DECREF(subjectName);
                                } PKIX_DECREF(subjectNames);
                        }

                        PKIX_CHECK(pkix_ForwardBuilderState_Create
                                (childTraversedCACerts,
                                state->dsaParamsNeeded,
                                state->revCheckDelayed,
                                canBeCached,
                                state->validityDate,
                                state->candidateCert,
                                childTraversedSubjNames,
                                state->trustChain,
                                state,
                                &childState,
                                plContext),
                                "pkix_ForwardBuildState_Create failed");
                        PKIX_DECREF(childTraversedSubjNames);
                        PKIX_DECREF(certSelParams);
                        state = childState;
                        continue; /* with while (!outOfOptions) */

                } /* if cert was valid */ else {

                        PKIX_DECREF(state->candidateCert);
                        if (++(state->certIndex) < (state->numCerts)) {
                                continue;
                        }
                }
            }

            /*
             * Adding the current cert to the chain didn't help. Back
             * up to the parent cert, and see if there are any more to try.
             */
            do {
                if (state->parentState == NULL) {
                        /* We are at the top level, and can't back up! */
                        outOfOptions = PKIX_TRUE;
                } else {

                        /*
                         * Try the next cert for this parent, if any.
                         * Otherwise keep backing up until we reach a
                         * parent with more certs to try.
                         */
                        PKIX_CHECK(PKIX_List_GetLength
                                (state->trustChain, &numChained, plContext),
                                "PKIX_List_GetLength failed");
                        PKIX_CHECK(PKIX_List_DeleteItem
                                (state->trustChain, numChained - 1, plContext),
                                "PKIX_List_DeleteItem failed");
                        parentState = state->parentState;
                        PKIX_DECREF(state);
                        state = parentState;
                }
                PKIX_DECREF(state->candidateCert);
            } while ((outOfOptions == PKIX_FALSE) &&
                     (++(state->certIndex) >= (state->numCerts)));

        } /* while (outOfOptions == PKIX_FALSE) */

cleanup:

        /*
         * We were called with an initialState that had no parent. Any state
         * with a parent was created by us, and must be destroyed by us.
         */
        while (state->parentState) {
                parentState = state->parentState;
                PKIX_DECREF(state);
                state = parentState;
        }
        state->canBeCached = canBeCached;

        PKIX_DECREF(childTraversedSubjNames);
        PKIX_DECREF(certsFound);
        PKIX_DECREF(certSelParams);
        PKIX_DECREF(subjectNames);
        PKIX_DECREF(subjectName);
        PKIX_DECREF(finalSubjPubKey);
        PKIX_DECREF(finalPolicyTree);
        PKIX_DECREF(certStore);
        PKIX_DECREF(trustAnchor);
        PKIX_DECREF(state->candidateCert);
        PKIX_DECREF(state->validityDate);

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
        PKIX_UInt32 numAnchors = 0;
        PKIX_UInt32 numCertStores = 0;
        PKIX_Boolean dsaParamsNeeded = PKIX_FALSE;
        PKIX_Boolean revCheckDelayed = PKIX_FALSE;
        PKIX_Boolean isCrlEnabled = PKIX_TRUE;
        PKIX_Boolean cacheHit = PKIX_FALSE;
        PKIX_Boolean trusted = PKIX_FALSE;
        PKIX_PL_Cert *trustedCert = NULL;
        PKIX_ProcessingParams *procParams = NULL;
        PKIX_CertSelector *targetConstraints = NULL;
        PKIX_ComCertSelParams *targetParams = NULL;
        PKIX_List *anchors = NULL;
        PKIX_List *targetSubjNames = NULL;
        PKIX_PL_Cert *targetCert = NULL;
        PKIX_CertChainChecker *crlChecker = NULL;
        PKIX_List *certStores = NULL;
        PKIX_List *userCheckers = NULL;
        PKIX_PL_Date *testDate = NULL;
        PKIX_PL_PublicKey *targetPubKey = NULL;
        BuildConstants buildConstants;

        PKIX_List *tentativeChain = NULL;
        PKIX_ValidateResult *valResult = NULL;
        PKIX_BuildResult *buildResult = NULL;
        PKIX_CertChain *certChain = NULL;
        PKIX_List *certList = NULL;
        PKIX_TrustAnchor *matchingAnchor = NULL;
        PKIX_ForwardBuilderState *initialState = NULL;
        PKIX_PL_PublicKey *finalSubjPubKey = NULL;
        PKIX_PolicyNode *finalPolicyTree = NULL;

        PKIX_ENTER(BUILD, "PKIX_BuildChain");
        PKIX_NULLCHECK_TWO(buildParams, pResult);

        PKIX_CHECK(PKIX_BuildParams_GetProcessingParams
                (buildParams, &procParams, plContext),
                "PKIX_BuildParams_GetProcessingParams failed");

        PKIX_CHECK(PKIX_ProcessingParams_GetDate
                (procParams, &testDate, plContext),
                "PKIX_ProcessingParams_GetDate");

        if (!testDate) {
                PKIX_CHECK(PKIX_PL_Date_Create_UTCTime
                        (NULL, &testDate, plContext),
                        "PKIX_PL_Date_Create_UTCTime failed");
        }

        PKIX_CHECK(PKIX_ProcessingParams_GetTrustAnchors
                (procParams, &anchors, plContext),
                "PKIX_ProcessingParams_GetTrustAnchors failed");

        PKIX_CHECK(PKIX_List_GetLength(anchors, &numAnchors, plContext),
                "PKIX_List_GetLength failed");

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

        PKIX_CHECK(PKIX_List_Create(&tentativeChain, plContext),
                "PKIX_List_Create failed");

        PKIX_NULLCHECK_ONE(targetCert);

        PKIX_CHECK(PKIX_List_AppendItem
                (tentativeChain, (PKIX_PL_Object *)targetCert, plContext),
                "PKIX_List_AppendItem");

        PKIX_CHECK(PKIX_PL_PublicKey_NeedsDSAParameters
                (targetPubKey, &dsaParamsNeeded, plContext),
                "PKIX_PL_PublicKey_NeedsDSAParameters failed");

        PKIX_CHECK(PKIX_PL_Cert_CheckValidity(targetCert, testDate, plContext),
                "PKIX_PL_Cert_CheckValidity failed");

        PKIX_CHECK(pkix_ProcessingParams_GetRevocationEnabled
                (procParams, &isCrlEnabled, plContext),
                "PKIX_ProcessingParams_GetRevocationEnabled");

        PKIX_CHECK(PKIX_ProcessingParams_GetCertStores
                (procParams, &certStores, plContext),
                "PKIX_ProcessingParams_GetCertStores failed");

        PKIX_CHECK(PKIX_List_GetLength(certStores, &numCertStores, plContext),
                "PKIX_List_GetLength failed");

        PKIX_CHECK(PKIX_ProcessingParams_GetCertChainCheckers
                    (procParams, &userCheckers, plContext),
                    "PKIX_ProcessingParams_GetCertChainCheckers");

        if (isCrlEnabled) {
                if (numCertStores > 0) {
                        PKIX_CHECK(pkix_DefaultCRLChecker_Initialize
                                (certStores,
                                testDate,
                                NULL,
                                0,
                                &crlChecker,
                                plContext),
                                "pkix_DefaultCRLChecker_Initialize failed");
                } else {
                    PKIX_ERROR("Can't enable Revocation without CertStore");
                }
        }

        /*
         * We initialize all the fields of buildConstants here, in one place,
         * just to help keep track and ensure that we got everything.
         */

        buildConstants.numAnchors = numAnchors;
        buildConstants.numCertStores = numCertStores;
        buildConstants.procParams = procParams;
        buildConstants.testDate = testDate;
        buildConstants.targetCert = targetCert;
        buildConstants.targetPubKey = targetPubKey;
        buildConstants.certStores = certStores;
        buildConstants.anchors = anchors;
        buildConstants.userCheckers = userCheckers;
        buildConstants.crlChecker = crlChecker;

        /* Check whether this cert verification has been cached. */
        PKIX_CHECK(pkix_CacheCertChain_Lookup
                (targetCert,
                anchors,
                testDate,
                &cacheHit,
                &buildResult,
                plContext),
                "pkix_CacheCertChain_Lookup failed");

        if (cacheHit) {
                /*
                 * We found something in cache. Verify that the anchor
                 * cert is still trusted,
                 */
                PKIX_CHECK(PKIX_BuildResult_GetValidateResult
                        (buildResult, &valResult, plContext),
                        "PKIX_BuildResult_GetValidateResult failed");

                PKIX_CHECK(PKIX_ValidateResult_GetTrustAnchor
                        (valResult, &matchingAnchor, plContext),
                        "PKIX_ValidateResult_GetTrustAnchor failed");

                PKIX_DECREF(valResult);

                PKIX_CHECK(PKIX_TrustAnchor_GetTrustedCert
                        (matchingAnchor, &trustedCert, plContext),
                        "PKIX_TrustAnchor_GetTrustedCert failed");

                PKIX_CHECK(PKIX_PL_Cert_IsCertTrusted
                        (trustedCert, &trusted, plContext),
                        "PKIX_PL_Cert_IsCertTrusted failed");

                if (trusted == PKIX_TRUE) {
                        /*
                         * The key usage may vary for different applications,
                         * so we need to verify the chain again.
                         */
                        PKIX_CHECK(PKIX_BuildResult_GetCertChain
                                (buildResult, &certChain, plContext),
                                "PKIX_BuildResult_GetCertChain failed");

                        PKIX_CHECK(PKIX_CertChain_GetCertificates
                                (certChain, &certList, plContext),
                                "PKIX_CertChain_GetCertificates failed");

                        PKIX_CHECK_ONLY_FATAL(pkix_Build_ValidateEntireChain
                                (&buildConstants,
                                certList,
                                matchingAnchor,
                                dsaParamsNeeded,
                                revCheckDelayed,
                                &valResult,
                                plContext),
                                "pkix_Build_ValidateEntireChain failed");

                        if (!PKIX_ERROR_RECEIVED) {
                                *pResult = buildResult;
                                goto cleanup;
                        }
                } else {
                        /* The anchor of this chain is no longer trusted. */
                        /* Invalidate this result in the cache */
                }
                PKIX_DECREF(certList);
                PKIX_DECREF(certChain);
                PKIX_DECREF(matchingAnchor);
                PKIX_DECREF(trustedCert);
                PKIX_DECREF(buildResult);
        }

        PKIX_CHECK(pkix_Build_IsChainCompleted
                (&buildConstants,
                buildConstants.targetCert,
                targetSubjNames,
                &matchingAnchor,
                plContext),
                "pkix_Build_IsChainCompleted failed");

        if (matchingAnchor) {

                PKIX_CHECK(pkix_ValidateResult_Create
                        (targetPubKey,
                        matchingAnchor,
                        NULL,
                        &valResult,
                        plContext),
                        "pkix_ValidateResult_Create failed");

        } else {

                PKIX_CHECK(pkix_ForwardBuilderState_Create
                        (0,              /* PKIX_UInt32 traversedCACerts */
                        dsaParamsNeeded, /* PKIX_Boolean dsaParamsNeeded */
                        revCheckDelayed, /* PKIX_Boolean revCheckDelayed */
                        PKIX_TRUE,       /* PKIX_Boolean canBeCached */
                        NULL,            /* PKIX_Date *validityDate */
                        targetCert,      /* PKIX_PL_Cert *prevCert */
                        targetSubjNames, /* PKIX_List *traversedSubjNames */
                        tentativeChain,  /* PKIX_List *trustChain */
                        NULL,            /* PKIX_ForwardBuilderState *parent */
                        &initialState,   /* PKIX_ForwardBuilderState **pState */
                        plContext),
                        "pkix_BuildState_Create failed");

                PKIX_CHECK(pkix_BuildForwardDepthFirstSearch
                        (&buildConstants,
                        initialState,
                        &valResult,
/*      PRPollDesc **pPollDesc, */
                        plContext),
                        "pkix_BuildForwardDepthFirstSearch failed");
        }

        /* no valResult means the build has failed */
        if (!valResult) {
                PKIX_ERROR("Unable to build chain");
        }

        PKIX_CHECK(PKIX_CertChain_Create(tentativeChain, &certChain, plContext),
                "PKIX_CertChain_Create failed");

        PKIX_CHECK(pkix_BuildResult_Create
                (valResult, certChain, &buildResult, plContext),
                "pkix_BuildResult_Create failed");

        /* We need the canBeCached flag from the end of the successful chain */
        /*
         * If we made a successful chain by combining the target Cert with one
         * of the Trust Anchors, we never created a ForwardBuilderState. We
         * treat this situation as canBeCached = PKIX_FALSE.
         */
        if (initialState != NULL) {
                if (initialState->canBeCached) {
                        PKIX_CHECK(pkix_CacheCertChain_Add
                                (targetCert,
                                anchors,
                                testDate,
                                buildResult,
                                plContext),
                                "pkix_CacheCertChain_Add failed");
                }
        }

        *pResult = buildResult;

cleanup:

        PKIX_DECREF(procParams);
        PKIX_DECREF(targetConstraints);
        PKIX_DECREF(targetParams);
        PKIX_DECREF(anchors);
        PKIX_DECREF(targetSubjNames);
        PKIX_DECREF(targetCert);
        PKIX_DECREF(crlChecker);
        PKIX_DECREF(certStores);
        PKIX_DECREF(userCheckers);
        PKIX_DECREF(testDate);
        PKIX_DECREF(targetPubKey);
        PKIX_DECREF(tentativeChain);
        PKIX_DECREF(valResult);
        PKIX_DECREF(certChain);
        PKIX_DECREF(certList);
        PKIX_DECREF(matchingAnchor);
        PKIX_DECREF(initialState);
        PKIX_DECREF(finalSubjPubKey);
        PKIX_DECREF(finalPolicyTree);

        PKIX_RETURN(BUILD);
}
