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
 * pkix_procparams.c
 *
 * ProcessingParams Object Functions
 *
 */

#include "pkix_procparams.h"

/* --Private-Functions-------------------------------------------- */

/*
 * FUNCTION: pkix_ProcessingParams_Destroy
 * (see comments for PKIX_PL_DestructorCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_ProcessingParams_Destroy(
        PKIX_PL_Object *object,
        void *plContext)
{
        PKIX_ProcessingParams *params = NULL;

        PKIX_ENTER(PROCESSINGPARAMS, "pkix_ProcessingParams_Destroy");
        PKIX_NULLCHECK_ONE(object);

        /* Check that this object is a processing params object */
        PKIX_CHECK(pkix_CheckType
                    (object, PKIX_PROCESSINGPARAMS_TYPE, plContext),
                    "Object is not a processing params object");

        params = (PKIX_ProcessingParams *)object;

        PKIX_DECREF(params->trustAnchors);
        PKIX_DECREF(params->constraints);
        PKIX_DECREF(params->date);
        PKIX_DECREF(params->initialPolicies);
        PKIX_DECREF(params->certChainCheckers);
        PKIX_DECREF(params->revCheckers);
        PKIX_DECREF(params->certStores);

cleanup:

        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: pkix_ProcessingParams_Equals
 * (see comments for PKIX_PL_EqualsCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_ProcessingParams_Equals(
        PKIX_PL_Object *first,
        PKIX_PL_Object *second,
        PKIX_Boolean *pResult,
        void *plContext)
{
        PKIX_UInt32 secondType;
        PKIX_Boolean cmpResult;
        PKIX_ProcessingParams *firstProcParams = NULL;
        PKIX_ProcessingParams *secondProcParams = NULL;

        PKIX_ENTER(PROCESSINGPARAMS, "pkix_ProcessingParams_Equals");
        PKIX_NULLCHECK_THREE(first, second, pResult);

        PKIX_CHECK(pkix_CheckType(first, PKIX_PROCESSINGPARAMS_TYPE, plContext),
                    "First Argument is not a ProcessingParams");

        PKIX_CHECK(PKIX_PL_Object_GetType(second, &secondType, plContext),
                    "Could not get type of second argument");

        *pResult = PKIX_FALSE;

        if (secondType != PKIX_PROCESSINGPARAMS_TYPE) goto cleanup;

        firstProcParams = (PKIX_ProcessingParams *)first;
        secondProcParams = (PKIX_ProcessingParams *)second;

        /* Do the simplest tests first */
        if ((firstProcParams->qualifiersRejected) !=
            (secondProcParams->qualifiersRejected)) {
                goto cleanup;
        }

        if (firstProcParams->isCrlRevocationCheckingEnabled !=
            secondProcParams->isCrlRevocationCheckingEnabled) {
                goto cleanup;
        }

        /* trustAnchors can never be NULL */

        PKIX_EQUALS
                (firstProcParams->trustAnchors,
                secondProcParams->trustAnchors,
                &cmpResult,
                plContext,
                "PKIX_PL_Object_Equals failed");

        if (!cmpResult) goto cleanup;

        PKIX_EQUALS
                (firstProcParams->date,
                secondProcParams->date,
                &cmpResult,
                plContext,
                "PKIX_PL_Object_Equals failed");

        if (!cmpResult) goto cleanup;

        PKIX_EQUALS
                (firstProcParams->constraints,
                secondProcParams->constraints,
                &cmpResult,
                plContext,
                "PKIX_PL_Object_Equals failed");

        if (!cmpResult) goto cleanup;

        PKIX_EQUALS
                (firstProcParams->initialPolicies,
                secondProcParams->initialPolicies,
                &cmpResult,
                plContext,
                "PKIX_PL_Object_Equals failed");

        if (!cmpResult) goto cleanup;

        /* There is no Equals function for CertChainCheckers */

        PKIX_EQUALS
                    ((PKIX_PL_Object *)firstProcParams->certStores,
                    (PKIX_PL_Object *)secondProcParams->certStores,
                    &cmpResult,
                    plContext,
                    "PKIX_PL_Object_Equals failed");

        if (cmpResult == PKIX_FALSE) {
                *pResult = PKIX_FALSE;
                goto cleanup;
        }

        *pResult = cmpResult;

cleanup:

        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: pkix_ProcessingParams_Hashcode
 * (see comments for PKIX_PL_HashcodeCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_ProcessingParams_Hashcode(
        PKIX_PL_Object *object,
        PKIX_UInt32 *pHashcode,
        void *plContext)
{
        PKIX_ProcessingParams *procParams = NULL;
        PKIX_UInt32 hash = 0;
        PKIX_UInt32 anchorsHash = 0;
        PKIX_UInt32 dateHash = 0;
        PKIX_UInt32 constraintsHash = 0;
        PKIX_UInt32 initialHash = 0;
        PKIX_UInt32 rejectedHash = 0;
        PKIX_UInt32 certChainCheckersHash = 0;
        PKIX_UInt32 revCheckersHash = 0;
        PKIX_UInt32 certStoresHash = 0;

        PKIX_ENTER(PROCESSINGPARAMS, "pkix_ProcessingParams_Hashcode");
        PKIX_NULLCHECK_TWO(object, pHashcode);

        PKIX_CHECK(pkix_CheckType
                    (object, PKIX_PROCESSINGPARAMS_TYPE, plContext),
                    "Object is not a processingParams");

        procParams = (PKIX_ProcessingParams*)object;

        PKIX_HASHCODE(procParams->trustAnchors, &anchorsHash, plContext,
                "PKIX_PL_Object_Hashcode failed");

        PKIX_HASHCODE(procParams->date, &dateHash, plContext,
                "PKIX_PL_Object_Hashcode failed");

        PKIX_HASHCODE(procParams->constraints, &constraintsHash, plContext,
                "PKIX_PL_Object_Hashcode failed");

        PKIX_HASHCODE(procParams->initialPolicies, &initialHash, plContext,
                "PKIX_PL_Object_Hashcode failed");

        rejectedHash = procParams->qualifiersRejected;

        /* There is no Hash function for CertChainCheckers */

        PKIX_HASHCODE(procParams->certStores, &certStoresHash, plContext,
                "PKIX_PL_Object_Hashcode failed");

        hash = (31 * ((31 * anchorsHash) + dateHash + constraintsHash)) +
                initialHash + rejectedHash;

        hash += certStoresHash + certChainCheckersHash + revCheckersHash +
                (procParams->isCrlRevocationCheckingEnabled << 7);

        *pHashcode = hash;

cleanup:

        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: pkix_ProcessingParams_ToString
 * (see comments for PKIX_PL_ToStringCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_ProcessingParams_ToString(
        PKIX_PL_Object *object,
        PKIX_PL_String **pString,
        void *plContext)
{
        PKIX_ProcessingParams *procParams = NULL;
        char *asciiFormat = NULL;
        PKIX_PL_String *formatString = NULL;
        PKIX_PL_String *procParamsString = NULL;
        PKIX_PL_String *anchorsString = NULL;
        PKIX_PL_String *dateString = NULL;
        PKIX_PL_String *constraintsString = NULL;
        PKIX_PL_String *InitialPoliciesString = NULL;
        PKIX_PL_String *qualsRejectedString = NULL;
        PKIX_List *certStores = NULL;
        PKIX_PL_String *certStoresString = NULL;

        PKIX_ENTER(PROCESSINGPARAMS, "pkix_ProcessingParams_ToString");
        PKIX_NULLCHECK_TWO(object, pString);

        PKIX_CHECK(pkix_CheckType
                    (object, PKIX_PROCESSINGPARAMS_TYPE, plContext),
                    "Object not a ProcessingParams");

        asciiFormat =
                "[\n"
                "\tTrust Anchors: \n"
                "\t********BEGIN LIST OF TRUST ANCHORS********\n"
                "\t\t%s\n"
                "\t********END LIST OF TRUST ANCHORS********\n"
                "\tDate:    \t\t%s\n"
                "\tTarget Constraints:    %s\n"
                "\tInitial Policies:      %s\n"
                "\tQualifiers Rejected:   %s\n"
                "\tCert Stores:           %s\n"
                "\tCRL Checking Enabled:  %d\n"
                "]\n";

        PKIX_CHECK(PKIX_PL_String_Create
                    (PKIX_ESCASCII,
                    asciiFormat,
                    NULL,
                    &formatString,
                    plContext),
                    "PKIX_PL_String_Create failed");

        procParams = (PKIX_ProcessingParams*)object;

        PKIX_TOSTRING(procParams->trustAnchors, &anchorsString, plContext,
                "PKIX_PL_Object_ToString failed");

        PKIX_TOSTRING(procParams->date, &dateString, plContext,
                "PKIX_PL_Object_ToString failed");

        PKIX_TOSTRING(procParams->constraints, &constraintsString, plContext,
                "PKIX_PL_Object_ToString failed");

        PKIX_TOSTRING
                (procParams->initialPolicies, &InitialPoliciesString, plContext,
                "PKIX_PL_Object_ToString failed");

        PKIX_CHECK(PKIX_PL_String_Create
                (PKIX_ESCASCII,
                (procParams->qualifiersRejected)?"TRUE":"FALSE",
                NULL,
                &qualsRejectedString,
                plContext),
                "PKIX_PL_String_Create failed");

        /* There is no ToString function for CertChainCheckers */

        PKIX_CHECK(PKIX_ProcessingParams_GetCertStores
                (procParams, &certStores, plContext),
                "PKIX_ProcessingParams_GetCertStores failed");

        PKIX_TOSTRING(certStores, &certStoresString, plContext,
                "PKIX_LIST_ToString failed");

        PKIX_CHECK(PKIX_PL_Sprintf
                (&procParamsString,
                plContext,
                formatString,
                anchorsString,
                dateString,
                constraintsString,
                InitialPoliciesString,
                qualsRejectedString,
                certStoresString,
                procParams->isCrlRevocationCheckingEnabled),
                "PKIX_PL_Sprintf failed");

        *pString = procParamsString;

cleanup:

        PKIX_DECREF(formatString);
        PKIX_DECREF(anchorsString);
        PKIX_DECREF(dateString);
        PKIX_DECREF(constraintsString);
        PKIX_DECREF(InitialPoliciesString);
        PKIX_DECREF(qualsRejectedString);
        PKIX_DECREF(certStores);
        PKIX_DECREF(certStoresString);

        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: pkix_ProcessingParams_RegisterSelf
 * DESCRIPTION:
 *  Registers PKIX_PROCESSINGPARAMS_TYPE and its related functions with
 *  systemClasses[]
 * THREAD SAFETY:
 *  Not Thread Safe - for performance and complexity reasons
 *
 *  Since this function is only called by PKIX_PL_Initialize, which should
 *  only be called once, it is acceptable that this function is not
 *  thread-safe.
 */
PKIX_Error *
pkix_ProcessingParams_RegisterSelf(void *plContext)
{
        extern pkix_ClassTable_Entry systemClasses[PKIX_NUMTYPES];
        pkix_ClassTable_Entry entry;

        PKIX_ENTER(PROCESSINGPARAMS, "pkix_ProcessingParams_RegisterSelf");

        entry.description = "ProcessingParams";
        entry.destructor = pkix_ProcessingParams_Destroy;
        entry.equalsFunction = pkix_ProcessingParams_Equals;
        entry.hashcodeFunction = pkix_ProcessingParams_Hashcode;
        entry.toStringFunction = pkix_ProcessingParams_ToString;
        entry.comparator = NULL;
        entry.duplicateFunction = NULL; /* XXX should we have a duplicate */

        systemClasses[PKIX_PROCESSINGPARAMS_TYPE] = entry;

cleanup:

        PKIX_RETURN(PROCESSINGPARAMS);
}

/* --Public-Functions--------------------------------------------- */

/*
 * FUNCTION: PKIX_ProcessingParams_Create (see comments in pkix_params.h)
 */
PKIX_Error *
PKIX_ProcessingParams_Create(
        PKIX_List *anchors,  /* list of TrustAnchor */
        PKIX_ProcessingParams **pParams,
        void *plContext)
{
        PKIX_ProcessingParams *params = NULL;

        PKIX_ENTER(PROCESSINGPARAMS, "PKIX_ProcessingParams_Create");
        PKIX_NULLCHECK_TWO(pParams, anchors);

        PKIX_CHECK(PKIX_PL_Object_Alloc
                    (PKIX_PROCESSINGPARAMS_TYPE,
                    sizeof (PKIX_ProcessingParams),
                    (PKIX_PL_Object **)&params,
                    plContext),
                    "Could not create processing params object");

        /* initialize fields */
        PKIX_INCREF(anchors);
        params->trustAnchors = anchors;
        PKIX_CHECK(PKIX_List_SetImmutable(params->trustAnchors, plContext),
                    "PKIX_List_SetImmutable failed");

        params->constraints = NULL;
        params->date = NULL;
        params->initialPolicies = NULL;
        params->initialPolicyMappingInhibit = PKIX_FALSE;
        params->initialAnyPolicyInhibit = PKIX_FALSE;
        params->initialExplicitPolicy = PKIX_FALSE;
        params->qualifiersRejected = PKIX_FALSE;
        params->certChainCheckers = NULL;
        params->revCheckers = NULL;
        params->certStores = NULL;

        /*
         * XXX CRL checking should be enabled as default, but before
         * we encorporate CRL in all our tests, take it as disable for now
         */
        params->isCrlRevocationCheckingEnabled = PKIX_TRUE;

        *pParams = params;

cleanup:

        if (PKIX_ERROR_RECEIVED){
                PKIX_DECREF(params);
        }

        PKIX_RETURN(PROCESSINGPARAMS);

}

/*
 * FUNCTION: PKIX_ProcessingParams_GetTrustAnchors
 * (see comments in pkix_params.h)
 */
PKIX_Error *
PKIX_ProcessingParams_GetTrustAnchors(
        PKIX_ProcessingParams *params,
        PKIX_List **pAnchors,  /* list of TrustAnchor */
        void *plContext)
{
        PKIX_ENTER(PROCESSINGPARAMS, "PKIX_ProcessingParams_GetTrustAnchors");
        PKIX_NULLCHECK_TWO(params, pAnchors);

        PKIX_INCREF(params->trustAnchors);

        *pAnchors = params->trustAnchors;

cleanup:

        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: PKIX_ProcessingParams_GetDate (see comments in pkix_params.h)
 */
PKIX_Error *
PKIX_ProcessingParams_GetDate(
        PKIX_ProcessingParams *params,
        PKIX_PL_Date **pDate,
        void *plContext)
{
        PKIX_ENTER(PROCESSINGPARAMS, "PKIX_ProcessingParams_GetDate");
        PKIX_NULLCHECK_TWO(params, pDate);

        PKIX_INCREF(params->date);
        *pDate = params->date;

cleanup:

        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: PKIX_ProcessingParams_SetDate (see comments in pkix_params.h)
 */
PKIX_Error *
PKIX_ProcessingParams_SetDate(
        PKIX_ProcessingParams *params,
        PKIX_PL_Date *date,
        void *plContext)
{
        PKIX_ENTER(PROCESSINGPARAMS, "PKIX_ProcessingParams_SetDate");
        PKIX_NULLCHECK_ONE(params);

        PKIX_DECREF(params->date);

        PKIX_INCREF(date);

        params->date = date;

        PKIX_CHECK(PKIX_PL_Object_InvalidateCache
                    ((PKIX_PL_Object *)params, plContext),
                    "PKIX_PL_Object_InvalidateCache failed");
cleanup:

        if (PKIX_ERROR_RECEIVED){
                PKIX_DECREF(date);
        }

        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: PKIX_ProcessingParams_GetTargetCertConstraints
 * (see comments in pkix_params.h)
 */
PKIX_Error *
PKIX_ProcessingParams_GetTargetCertConstraints(
        PKIX_ProcessingParams *params,
        PKIX_CertSelector **pConstraints,
        void *plContext)
{
        PKIX_ENTER(PROCESSINGPARAMS,
                    "PKIX_ProcessingParams_GetTargetCertConstraints");

        PKIX_NULLCHECK_TWO(params, pConstraints);

        PKIX_INCREF(params->constraints);
        *pConstraints = params->constraints;

cleanup:

        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: PKIX_ProcessingParams_SetTargetCertConstraints
 * (see comments in pkix_params.h)
 */
PKIX_Error *
PKIX_ProcessingParams_SetTargetCertConstraints(
        PKIX_ProcessingParams *params,
        PKIX_CertSelector *constraints,
        void *plContext)
{

        PKIX_ENTER(PROCESSINGPARAMS,
                    "PKIX_ProcessingParams_SetTargetCertConstraints");

        PKIX_NULLCHECK_ONE(params);

        PKIX_DECREF(params->constraints);

        PKIX_INCREF(constraints);

        params->constraints = constraints;

        PKIX_CHECK(PKIX_PL_Object_InvalidateCache
                    ((PKIX_PL_Object *)params, plContext),
                    "PKIX_PL_Object_InvalidateCache failed");

cleanup:

        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: PKIX_ProcessingParams_GetInitialPolicies
 *      (see comments in pkix_params.h)
 */
PKIX_Error *
PKIX_ProcessingParams_GetInitialPolicies(
        PKIX_ProcessingParams *params,
        PKIX_List **pInitPolicies, /* list of PKIX_PL_OID */
        void *plContext)
{

        PKIX_ENTER(PROCESSINGPARAMS,
                "PKIX_ProcessingParams_GetInitialPolicies");

        PKIX_NULLCHECK_TWO(params, pInitPolicies);

        if (params->initialPolicies == NULL) {
                PKIX_CHECK(PKIX_List_Create
                        (&params->initialPolicies, plContext),
                        "Unable to create list");
                PKIX_CHECK(PKIX_List_SetImmutable
                        (params->initialPolicies, plContext),
                        "Unable to make list immutable");
                PKIX_CHECK(PKIX_PL_Object_InvalidateCache
                        ((PKIX_PL_Object *)params, plContext),
                        "PKIX_PL_Object_InvalidateCache failed");
        }

        PKIX_INCREF(params->initialPolicies);
        *pInitPolicies = params->initialPolicies;

cleanup:

        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: PKIX_ProcessingParams_SetInitialPolicies
 *      (see comments in pkix_params.h)
 */
PKIX_Error *
PKIX_ProcessingParams_SetInitialPolicies(
        PKIX_ProcessingParams *params,
        PKIX_List *initPolicies, /* list of PKIX_PL_OID */
        void *plContext)
{
        PKIX_ENTER(PROCESSINGPARAMS,
                "PKIX_ProcessingParams_SetInitialPolicies");

        PKIX_NULLCHECK_ONE(params);

        PKIX_DECREF(params->initialPolicies);

        PKIX_INCREF(initPolicies);
        params->initialPolicies = initPolicies;

        PKIX_CHECK(PKIX_PL_Object_InvalidateCache
                ((PKIX_PL_Object *)params, plContext),
                "PKIX_PL_Object_InvalidateCache failed");

cleanup:

        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: PKIX_ProcessingParams_GetPolicyQualifiersRejected
 *      (see comments in pkix_params.h)
 */
PKIX_Error *
PKIX_ProcessingParams_GetPolicyQualifiersRejected(
        PKIX_ProcessingParams *params,
        PKIX_Boolean *pRejected,
        void *plContext)
{
        PKIX_ENTER(PROCESSINGPARAMS,
                "PKIX_ProcessingParams_GetPolicyQualifiersRejected");

        PKIX_NULLCHECK_TWO(params, pRejected);

        *pRejected = params->qualifiersRejected;

cleanup:

        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: PKIX_ProcessingParams_SetPolicyQualifiersRejected
 *      (see comments in pkix_params.h)
 */
PKIX_Error *
PKIX_ProcessingParams_SetPolicyQualifiersRejected(
        PKIX_ProcessingParams *params,
        PKIX_Boolean rejected,
        void *plContext)
{
        PKIX_ENTER(PROCESSINGPARAMS,
                "PKIX_ProcessingParams_SetPolicyQualifiersRejected");

        PKIX_NULLCHECK_ONE(params);

        params->qualifiersRejected = rejected;

        PKIX_CHECK(PKIX_PL_Object_InvalidateCache
                ((PKIX_PL_Object *)params, plContext),
                "PKIX_PL_Object_InvalidateCache failed");

cleanup:

        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: PKIX_ProcessingParams_GetCertChainCheckers
 * (see comments in pkix_params.h)
 */
PKIX_Error *
PKIX_ProcessingParams_GetCertChainCheckers(
        PKIX_ProcessingParams *params,
        PKIX_List **pCheckers,  /* list of PKIX_CertChainChecker */
        void *plContext)
{

        PKIX_ENTER
            (PROCESSINGPARAMS, "PKIX_ProcessingParams_GetCertChainCheckers");
        PKIX_NULLCHECK_TWO(params, pCheckers);

        if (params->certChainCheckers) {
                PKIX_INCREF(params->certChainCheckers);
        }

        *pCheckers = params->certChainCheckers;

cleanup:

        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: PKIX_ProcessingParams_SetCertChainCheckers
 * (see comments in pkix_params.h)
 */
PKIX_Error *
PKIX_ProcessingParams_SetCertChainCheckers(
        PKIX_ProcessingParams *params,
        PKIX_List *checkers,  /* list of PKIX_CertChainChecker */
        void *plContext)
{

        PKIX_ENTER
            (PROCESSINGPARAMS, "PKIX_ProcessingParams_SetCertChainCheckers");
        PKIX_NULLCHECK_ONE(params);

        if (checkers == NULL) {
                /* accordingly to spec, nothing done */
                goto cleanup;

        } else {

                PKIX_INCREF(checkers);

                params->certChainCheckers = checkers;
        }

        PKIX_CHECK(PKIX_PL_Object_InvalidateCache
                ((PKIX_PL_Object *)params, plContext),
                "PKIX_PL_Object_InvalidateCache failed");

cleanup:

        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: PKIX_ProcessingParams_AddCertChainCheckers
 * (see comments in pkix_params.h)
 */
PKIX_Error *
PKIX_ProcessingParams_AddCertChainChecker(
        PKIX_ProcessingParams *params,
        PKIX_CertChainChecker *checker,
        void *plContext)
{
        PKIX_List *list = NULL;

        PKIX_ENTER
            (PROCESSINGPARAMS, "PKIX_ProcessingParams_AddCertChainChecker");
        PKIX_NULLCHECK_TWO(params, checker);

        if (params->certChainCheckers == NULL) {

                PKIX_CHECK(PKIX_List_Create(&list, plContext),
                    "PKIX_List_Create failed");

                PKIX_INCREF(list);

                params->certChainCheckers = list;

        }

        PKIX_CHECK(PKIX_List_AppendItem
            (params->certChainCheckers, (PKIX_PL_Object *)checker, plContext),
            "PKIX_List_AppendItem failed");

        PKIX_CHECK(PKIX_PL_Object_InvalidateCache
            ((PKIX_PL_Object *)params, plContext),
            "PKIX_PL_Object_InvalidateCache failed");

cleanup:

        PKIX_DECREF(list);
        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: PKIX_ProcessingParams_GetRevocationCheckers
 * (see comments in pkix_params.h)
 */
PKIX_Error *
PKIX_ProcessingParams_GetRevocationCheckers(
        PKIX_ProcessingParams *params,
        PKIX_List **pCheckers,  /* list of PKIX_RevocationChecker */
        void *plContext)
{

        PKIX_ENTER
            (PROCESSINGPARAMS, "PKIX_ProcessingParams_GetRevocationCheckers");
        PKIX_NULLCHECK_TWO(params, pCheckers);

        if (params->revCheckers) {
                PKIX_INCREF(params->revCheckers);
        }

        *pCheckers = params->revCheckers;

cleanup:

        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: PKIX_ProcessingParams_SetRevocationCheckers
 * (see comments in pkix_params.h)
 */
PKIX_Error *
PKIX_ProcessingParams_SetRevocationCheckers(
        PKIX_ProcessingParams *params,
        PKIX_List *checkers,  /* list of PKIX_RevocationChecker */
        void *plContext)
{

        PKIX_ENTER
            (PROCESSINGPARAMS, "PKIX_ProcessingParams_SetRevocationCheckers");
        PKIX_NULLCHECK_ONE(params);

        if (checkers == NULL) {
                /* accordingly to spec, nothing done */
                goto cleanup;

        } else {

                PKIX_INCREF(checkers);

                params->revCheckers = checkers;
        }

        PKIX_CHECK(PKIX_PL_Object_InvalidateCache
                ((PKIX_PL_Object *)params, plContext),
                "PKIX_PL_Object_InvalidateCache failed");

cleanup:

        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: PKIX_ProcessingParams_AddRevocationCheckers
 * (see comments in pkix_params.h)
 */
PKIX_Error *
PKIX_ProcessingParams_AddRevocationChecker(
        PKIX_ProcessingParams *params,
        PKIX_RevocationChecker *checker,
        void *plContext)
{
        PKIX_List *list = NULL;

        PKIX_ENTER
            (PROCESSINGPARAMS, "PKIX_ProcessingParams_AddRevocationChecker");
        PKIX_NULLCHECK_TWO(params, checker);

        if (params->certChainCheckers == NULL) {

                PKIX_CHECK(PKIX_List_Create(&list, plContext),
                    "PKIX_List_Create failed");

                PKIX_INCREF(list);

                params->certChainCheckers = list;

        }

        PKIX_CHECK(PKIX_List_AppendItem
            (params->certChainCheckers, (PKIX_PL_Object *)checker, plContext),
            "PKIX_List_AppendItem failed");

        PKIX_CHECK(PKIX_PL_Object_InvalidateCache
            ((PKIX_PL_Object *)params, plContext),
            "PKIX_PL_Object_InvalidateCache failed");

cleanup:

        PKIX_DECREF(list);
        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: PKIX_ProcessingParams_GetCertStores
 * (see comments in pkix_params.h)
 */
PKIX_Error *
PKIX_ProcessingParams_GetCertStores(
        PKIX_ProcessingParams *params,
        PKIX_List **pStores,  /* list of PKIX_CertStore */
        void *plContext)
{
        PKIX_ENTER(PROCESSINGPARAMS, "PKIX_ProcessingParams_GetCertStores");

        PKIX_NULLCHECK_TWO(params, pStores);

        if (!params->certStores){
                PKIX_CHECK(PKIX_List_Create(&params->certStores, plContext),
                            "Unable to create list");
        }

        PKIX_INCREF(params->certStores);
        *pStores = params->certStores;

cleanup:

        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: PKIX_ProcessingParams_SetCertStores
 * (see comments in pkix_params.h)
 */
PKIX_Error *
PKIX_ProcessingParams_SetCertStores(
        PKIX_ProcessingParams *params,
        PKIX_List *stores,  /* list of PKIX_CertStore */
        void *plContext)
{
        PKIX_ENTER(PROCESSINGPARAMS, "PKIX_ProcessingParams_SetCertStores");

        PKIX_NULLCHECK_ONE(params);

        PKIX_DECREF(params->certStores);

        PKIX_INCREF(stores);
        params->certStores = stores;

        PKIX_CHECK(PKIX_PL_Object_InvalidateCache
                ((PKIX_PL_Object *)params, plContext),
                "PKIX_PL_Object_InvalidateCache failed");

cleanup:

        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: PKIX_ProcessingParams_AddCertStore
 * (see comments in pkix_params.h)
 */
PKIX_Error *
PKIX_ProcessingParams_AddCertStore(
        PKIX_ProcessingParams *params,
        PKIX_CertStore *store,
        void *plContext)
{
        PKIX_List *certStores = NULL;

        PKIX_ENTER(PROCESSINGPARAMS, "PKIX_ProcessingParams_AddCertStore");
        PKIX_NULLCHECK_TWO(params, store);

        PKIX_CHECK(PKIX_ProcessingParams_GetCertStores
                    (params, &certStores, plContext),
                    "PKIX_ProcessingParams_GetCertStores failed");

        PKIX_CHECK(PKIX_List_AppendItem
                    (certStores, (PKIX_PL_Object *)store, plContext),
                    "PKIX_List_AppendItem failed");

        PKIX_CHECK(PKIX_PL_Object_InvalidateCache
                    ((PKIX_PL_Object *)params, plContext),
                    "PKIX_PL_Object_InvalidateCache failed");

cleanup:

        PKIX_DECREF(certStores);
        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: PKIX_ProcessingParams_IsCRLRevocationCheckingEnabled
 * (see comments in pkix_params.h)
 */
PKIX_Error *
PKIX_ProcessingParams_IsCRLRevocationCheckingEnabled(
        PKIX_ProcessingParams *params,
        PKIX_Boolean *pEnabled,
        void *plContext)
{

        PKIX_ENTER(PROCESSINGPARAMS,
                    "PKIX_ProcessingParams_IsCRLRevocationCheckingEnabled");
        PKIX_NULLCHECK_TWO(params, pEnabled);

        *pEnabled = params->isCrlRevocationCheckingEnabled;

cleanup:

        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: PKIX_ProcessingParams_SetRevocationEnabled
 * (see comments in pkix_params.h)
 */
PKIX_Error *
PKIX_ProcessingParams_SetRevocationEnabled(
        PKIX_ProcessingParams *params,
        PKIX_Boolean enabled,
        void *plContext)
{

        PKIX_ENTER(PROCESSINGPARAMS,
                    "PKIX_ProcessingParams_SetRevocationEnabled");
        PKIX_NULLCHECK_ONE(params);

        params->isCrlRevocationCheckingEnabled = enabled;

        PKIX_CHECK(PKIX_PL_Object_InvalidateCache
                    ((PKIX_PL_Object *)params, plContext),
                    "PKIX_PL_Object_InvalidateCache failed");

cleanup:

        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: pkix_ProcessingParams_GetRevocationEnabled
 *
 * DESCRIPTION:
 *  Retrieves the boolean value indicating whether Revocation Checking
 *  should be performed, from the ProcessingParams pointed to by "params",
 *  and stores the result at "pEnable".
 *
 * PARAMETERS:
 *  "params"
 *      Address of ProcessingParams whose revocationEnabled flag is to be
 *      retrieved. Must be non-NULL.
 *  "pEnable"
 *      Address where Boolean value will be stored. Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 *
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 *
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
pkix_ProcessingParams_GetRevocationEnabled(
        PKIX_ProcessingParams *params,
        PKIX_Boolean *pEnabled,
        void *plContext)
{

        PKIX_ENTER(PROCESSINGPARAMS,
                    "PKIX_ProcessingParams_GetRevocationEnabled");

        PKIX_NULLCHECK_TWO(params, pEnabled);

        *pEnabled = params->isCrlRevocationCheckingEnabled;

cleanup:

        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: PKIX_ProcessingParams_IsAnyPolicyInhibited
 * (see comments in pkix_params.h)
 */
PKIX_Error *
PKIX_ProcessingParams_IsAnyPolicyInhibited(
        PKIX_ProcessingParams *params,
        PKIX_Boolean *pInhibited,
        void *plContext)
{
        PKIX_ENTER(PROCESSINGPARAMS,
                "PKIX_ProcessingParams_IsAnyPolicyInhibited");

        PKIX_NULLCHECK_TWO(params, pInhibited);

        *pInhibited = params->initialAnyPolicyInhibit;

cleanup:

        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: PKIX_ProcessingParams_SetAnyPolicyInhibited
 * (see comments in pkix_params.h)
 */
PKIX_Error *
PKIX_ProcessingParams_SetAnyPolicyInhibited(
        PKIX_ProcessingParams *params,
        PKIX_Boolean inhibited,
        void *plContext)
{
        PKIX_ENTER(PROCESSINGPARAMS,
                "PKIX_ProcessingParams_SetAnyPolicyInhibited");

        PKIX_NULLCHECK_ONE(params);

        params->initialAnyPolicyInhibit = inhibited;

        PKIX_CHECK(PKIX_PL_Object_InvalidateCache
                    ((PKIX_PL_Object *)params, plContext),
                    "PKIX_PL_Object_InvalidateCache failed");

cleanup:

        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: PKIX_ProcessingParams_IsExplicitPolicyRequired
 * (see comments in pkix_params.h)
 */
PKIX_Error *
PKIX_ProcessingParams_IsExplicitPolicyRequired(
        PKIX_ProcessingParams *params,
        PKIX_Boolean *pRequired,
        void *plContext)
{
        PKIX_ENTER(PROCESSINGPARAMS,
                "PKIX_ProcessingParams_IsExplicitPolicyRequired");

        PKIX_NULLCHECK_TWO(params, pRequired);

        *pRequired = params->initialExplicitPolicy;

cleanup:

        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: PKIX_ProcessingParams_SetExplicitPolicyRequired
 * (see comments in pkix_params.h)
 */
PKIX_Error *
PKIX_ProcessingParams_SetExplicitPolicyRequired(
        PKIX_ProcessingParams *params,
        PKIX_Boolean required,
        void *plContext)
{
        PKIX_ENTER(PROCESSINGPARAMS,
                "PKIX_ProcessingParams_SetExplicitPolicyRequired");

        PKIX_NULLCHECK_ONE(params);

        params->initialExplicitPolicy = required;

        PKIX_CHECK(PKIX_PL_Object_InvalidateCache
                    ((PKIX_PL_Object *)params, plContext),
                    "PKIX_PL_Object_InvalidateCache failed");

cleanup:

        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: PKIX_ProcessingParams_IsPolicyMappingInhibited
 * (see comments in pkix_params.h)
 */
PKIX_Error *
PKIX_ProcessingParams_IsPolicyMappingInhibited(
        PKIX_ProcessingParams *params,
        PKIX_Boolean *pInhibited,
        void *plContext)
{
        PKIX_ENTER(PROCESSINGPARAMS,
                "PKIX_ProcessingParams_IsPolicyMappingInhibited");

        PKIX_NULLCHECK_TWO(params, pInhibited);

        *pInhibited = params->initialPolicyMappingInhibit;

cleanup:

        PKIX_RETURN(PROCESSINGPARAMS);
}

/*
 * FUNCTION: PKIX_ProcessingParams_SetPolicyMappingInhibited
 * (see comments in pkix_params.h)
 */
PKIX_Error *
PKIX_ProcessingParams_SetPolicyMappingInhibited(
        PKIX_ProcessingParams *params,
        PKIX_Boolean inhibited,
        void *plContext)
{
        PKIX_ENTER(PROCESSINGPARAMS,
                "PKIX_ProcessingParams_SetPolicyMappingInhibited");

        PKIX_NULLCHECK_ONE(params);

        params->initialPolicyMappingInhibit = inhibited;

        PKIX_CHECK(PKIX_PL_Object_InvalidateCache
                    ((PKIX_PL_Object *)params, plContext),
                    "PKIX_PL_Object_InvalidateCache failed");

cleanup:

        PKIX_RETURN(PROCESSINGPARAMS);
}
