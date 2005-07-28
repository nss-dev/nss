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
 * pkix_crlselector.c
 *
 * CRLSelector Function Definitions
 *
 */

#include "pkix_crlselector.h"

/* --CRLSelector Private-Functions-------------------------------------- */

/*
 * FUNCTION: pkix_CRLSelector_Destroy
 * (see comments for PKIX_PL_DestructorCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_CRLSelector_Destroy(
        PKIX_PL_Object *object,
        void *plContext)
{
        PKIX_CRLSelector *selector = NULL;

        PKIX_ENTER(CRLSELECTOR, "pkix_CRLSelector_Destroy");
        PKIX_NULLCHECK_ONE(object);

        PKIX_CHECK(pkix_CheckType(object, PKIX_CRLSELECTOR_TYPE, plContext),
                    "Object is not a CRLSelector");

        selector = (PKIX_CRLSelector *)object;

        selector->matchCallback = NULL;

        PKIX_DECREF(selector->params);
        PKIX_DECREF(selector->context);

cleanup:

        PKIX_RETURN(CRLSELECTOR);
}

/*
 * FUNCTION: pkix_CRLSelector_ToString_Helper
 *
 * DESCRIPTION:
 *  Helper function that creates a string representation of CRLSelector
 *  pointed to by "crlParams" and stores its address in the object pointed to
 *  by "pString".
 *
 * PARAMETERS
 *  "list"
 *      Address of CRLSelector whose string representation is desired.
 *      Must be non-NULL.
 *  "pString"
 *      Address of object pointer's destination. Must be non-NULL.
 *  "plContext" - Platform-specific context pointer.
 *
 * THREAD SAFETY:
 *  Conditionally Thread Safe
 *      (see Thread Safety Definitions in Programmer's Guide)
 *
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a CRLEntry Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
static PKIX_Error *
pkix_CRLSelector_ToString_Helper(
        PKIX_CRLSelector *crlSelector,
        PKIX_PL_String **pString,
        void *plContext)
{
        PKIX_PL_String *crlSelectorString = NULL;
        PKIX_PL_String *formatString = NULL;
        PKIX_PL_String *crlParamsString = NULL;
        PKIX_PL_String *crlContextString = NULL;
        char *asciiFormat = NULL;

        PKIX_ENTER(CRLSELECTOR, "pkix_CRLSelector_ToString_Helper");
        PKIX_NULLCHECK_TWO(crlSelector, pString);
        PKIX_NULLCHECK_TWO(crlSelector->params, crlSelector->context);

        asciiFormat =
                "\n\t[\n"
                "\tMatchCallback: 0x%x\n"
                "\tParams:          %s\n"
                "\tContext:         %s\n"
                "\t]\n";

        PKIX_CHECK(PKIX_PL_String_Create
                    (PKIX_ESCASCII,
                    asciiFormat,
                    NULL,
                    &formatString,
                    plContext),
                    "PKIX_PL_String_Create failed");

        /* Params */
        PKIX_TOSTRING
                    ((PKIX_PL_Object *)crlSelector->params,
                    &crlParamsString,
                    plContext,
                    "pkix_ComCRLSelParams_ToString failed");

        /* Context */
        PKIX_TOSTRING(crlSelector->context, &crlContextString, plContext,
                    "PKIX_LIST_ToString failed");








        PKIX_CHECK(PKIX_PL_Sprintf
                    (&crlSelectorString,
                    plContext,
                    formatString,
                    crlSelector->matchCallback,
                    crlParamsString,
                    crlContextString),
                    "PKIX_PL_Sprintf failed");

        *pString = crlSelectorString;

cleanup:

        PKIX_DECREF(crlParamsString);
        PKIX_DECREF(crlContextString);
        PKIX_DECREF(formatString);

        PKIX_RETURN(CRLSELECTOR);
}

/*
 * FUNCTION: pkix_CRLSelector_ToString
 * (see comments for PKIX_PL_ToStringCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_CRLSelector_ToString(
        PKIX_PL_Object *object,
        PKIX_PL_String **pString,
        void *plContext)
{
        PKIX_PL_String *crlSelectorString = NULL;
        PKIX_CRLSelector *crlSelector = NULL;

        PKIX_ENTER(CRLSELECTOR, "pkix_CRLSelector_ToString");
        PKIX_NULLCHECK_TWO(object, pString);

        PKIX_CHECK(pkix_CheckType(object, PKIX_CRLSELECTOR_TYPE, plContext),
                    "Object is not a CRLSelector");

        crlSelector = (PKIX_CRLSelector *) object;

        PKIX_CHECK(pkix_CRLSelector_ToString_Helper
                    (crlSelector, &crlSelectorString, plContext),
                    "pkix_CRLSelector_ToString_Helper failed");

        *pString = crlSelectorString;

cleanup:

        PKIX_RETURN(CRLSELECTOR);
}

/*
 * FUNCTION: pkix_CRLSelector_Hashcode
 * (see comments for PKIX_PL_HashcodeCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_CRLSelector_Hashcode(
        PKIX_PL_Object *object,
        PKIX_UInt32 *pHashcode,
        void *plContext)
{
        PKIX_UInt32 paramsHash = 0;
        PKIX_UInt32 contextHash = 0;
        PKIX_UInt32 hash = 0;

        PKIX_CRLSelector *crlSelector = NULL;

        PKIX_ENTER(CRLSELECTOR, "pkix_CRLSelector_Hashcode");
        PKIX_NULLCHECK_TWO(object, pHashcode);

        PKIX_CHECK(pkix_CheckType(object, PKIX_CRLSELECTOR_TYPE, plContext),
                    "Object is not a CRLSelector");

        crlSelector = (PKIX_CRLSelector *)object;

        PKIX_HASHCODE(crlSelector->params, &paramsHash, plContext,
                "PKIX_PL_Object_Hashcode failed");

        PKIX_HASHCODE(crlSelector->context, &contextHash, plContext,
                "PKIX_PL_Object_Hashcode failed");

        hash = 31 * ((PKIX_UInt32)crlSelector->matchCallback +
                    (contextHash << 3)) + paramsHash;

        *pHashcode = hash;

cleanup:

        PKIX_RETURN(CRLSELECTOR);
}

/*
 * FUNCTION: pkix_CRLSelector_Equals
 * (see comments for PKIX_PL_Equals_Callback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_CRLSelector_Equals(
        PKIX_PL_Object *firstObject,
        PKIX_PL_Object *secondObject,
        PKIX_Boolean *pResult,
        void *plContext)
{
        PKIX_CRLSelector *firstCrlSelector = NULL;
        PKIX_CRLSelector *secondCrlSelector = NULL;
        PKIX_UInt32 secondType;
        PKIX_Boolean cmpResult = PKIX_FALSE;

        PKIX_ENTER(CRLSELECTOR, "pkix_CRLSelector_Equals");
        PKIX_NULLCHECK_THREE(firstObject, secondObject, pResult);

        /* test that firstObject is a CRLSelector */
        PKIX_CHECK(pkix_CheckType
                    (firstObject, PKIX_CRLSELECTOR_TYPE, plContext),
                    "FirstObject argument is not a CRLSelector");

        firstCrlSelector = (PKIX_CRLSelector *)firstObject;
        secondCrlSelector = (PKIX_CRLSelector *)secondObject;

        /*
         * Since we know firstObject is a CRLSelector, if both references are
         * identical, they must be equal
         */
        if (firstCrlSelector == secondCrlSelector){
                *pResult = PKIX_TRUE;
                goto cleanup;
        }

        /*
         * If secondCRLSelector isn't a CRLSelector, we don't throw an error.
         * We simply return a Boolean result of FALSE
         */
        *pResult = PKIX_FALSE;
        PKIX_CHECK(PKIX_PL_Object_GetType
                    ((PKIX_PL_Object *)secondCrlSelector,
                    &secondType,
                    plContext),
                    "Could not get type of second argument");

        if (secondType != PKIX_CRLSELECTOR_TYPE) {
                goto cleanup;
        }

        /* Compare MatchCallback address */
        cmpResult = (firstCrlSelector->matchCallback ==
                    secondCrlSelector->matchCallback);

        if (cmpResult == PKIX_FALSE) {
                goto cleanup;
        }

        /* Compare Common CRL Selector Params */
        PKIX_EQUALS
                (firstCrlSelector->params,
                secondCrlSelector->params,
                &cmpResult,
                plContext,
                "pkix_ComCRLSelParams_Equals failed");


        if (cmpResult == PKIX_FALSE) {
                goto cleanup;
        }

        /* Compare Context */
        PKIX_EQUALS
                (firstCrlSelector->context,
                secondCrlSelector->context,
                &cmpResult,
                plContext,
                "pkix_ComCRLSelParams_Equals failed");

        *pResult = cmpResult;

cleanup:

        PKIX_RETURN(CRLSELECTOR);
}

/*
 * FUNCTION: pkix_CRLSelector_Duplicate
 * (see comments for PKIX_PL_Duplicate_Callback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_CRLSelector_Duplicate(
        PKIX_PL_Object *object,
        PKIX_PL_Object **pNewObject,
        void *plContext)
{
        PKIX_CRLSelector *old;
        PKIX_CRLSelector *new;

        PKIX_ENTER(CRLSELECTOR, "pkix_CRLSelector_Duplicate");
        PKIX_NULLCHECK_TWO(object, pNewObject);

        PKIX_CHECK(pkix_CheckType
                    (object, PKIX_CRLSELECTOR_TYPE, plContext),
                    "Object is not a CRLSelector");

        old = (PKIX_CRLSelector *)object;

        PKIX_CHECK(PKIX_PL_Object_Alloc
                    (PKIX_CRLSELECTOR_TYPE,
                    (PKIX_UInt32)(sizeof (PKIX_CRLSelector)),
                    (PKIX_PL_Object **)&new,
                    plContext),
                    "Create CRLSelector Duplicate Object failed");

        new->matchCallback = old->matchCallback;

        PKIX_DUPLICATE(old->params, &new->params, plContext,
                    "PKIX_PL_Object_Duplicate Params failed");

        PKIX_DUPLICATE(old->context, &new->context, plContext,
                "PKIX_PL_Object_Duplicate Context failed");

        *pNewObject = (PKIX_PL_Object *)new;

cleanup:

        if (PKIX_ERROR_RECEIVED){
                PKIX_DECREF(new);
        }

        PKIX_RETURN(CRLSELECTOR);
}

/*
 * FUNCTION: pkix_CRLSelector_DefaultMatch
 *
 * DESCRIPTION:
 *  This functions compares passing-in CRL's Issuer, date, CRL number
 *  with the corresponding parameter values set in CRLSelector's Params.
 *  When this CRL matches all the criteria set in Params, a NULL is returned.
 *  Otherwise, an PKIX_Error is returned.
 *
 * PARAMETERS
 *  "selector"
 *      Address of CRLSelector which is verified for a match
 *      Must be non-NULL.
 *  "crl"
 *      Address of the CRL object to be verified. Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 *
 * THREAD SAFETY:
 *  Conditionally Thread Safe
 *      (see Thread Safety Definitions in Programmer's Guide)
 *
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a List Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
static PKIX_Error *
pkix_CRLSelector_DefaultMatch(
        PKIX_CRLSelector *selector,
        PKIX_PL_CRL *crl,
        void *plContext)
{
        PKIX_ComCRLSelParams *params = NULL;
        PKIX_PL_X500Name *crlIssuerName = NULL;
        PKIX_PL_X500Name *issuerName = NULL;
        PKIX_List *selIssuerNames = NULL;
        PKIX_PL_Date *selDate = NULL;
        PKIX_Boolean result = PKIX_TRUE;
        PKIX_UInt32 numIssuers = 0;
        PKIX_Int32 i;
        PKIX_PL_BigInt *minCRLNumber = NULL;
        PKIX_PL_BigInt *maxCRLNumber = NULL;
        PKIX_PL_BigInt *crlNumber = NULL;

        PKIX_ENTER(CRLSELECTOR, "pkix_CRLSelector_DefaultMatch");
        PKIX_NULLCHECK_TWO(selector, crl);

        params = selector->params;

        /* No matching parameter provided, just a match */
        if (params == NULL) {
                goto cleanup;
        }

        PKIX_CHECK(PKIX_ComCRLSelParams_GetIssuerNames
                    (params, &selIssuerNames, plContext),
                    "PKIX_ComCRLSelParams_GetIssuerNames failed");

        /* Check for Issuers */
        if (selIssuerNames != NULL){

                result = PKIX_FALSE;

                PKIX_CHECK(PKIX_PL_CRL_GetIssuer
                            (crl, &crlIssuerName, plContext),
                            "PKIX_PL_CRL_GetIssuer failed");

                PKIX_CHECK(PKIX_List_GetLength
                            (selIssuerNames, &numIssuers, plContext),
                            "PKIX_List_GetLength failed");

                for (i = 0; i < numIssuers; i++){

                        PKIX_CHECK(PKIX_List_GetItem
                                    (selIssuerNames,
                                    i,
                                    (PKIX_PL_Object **)&issuerName,
                                    plContext),
                                    "PKIX_List_GetItem failed");

                        PKIX_CHECK(PKIX_PL_X500Name_Match
                                    (crlIssuerName,
                                    issuerName,
                                    &result,
                                    plContext),
                                    "PKIX_PL_X500Name_Match failed");

                        PKIX_DECREF(issuerName);

                        if (result == PKIX_TRUE) {
                                break;
                        }
                }

                if (result == PKIX_FALSE) {
                        PKIX_ERROR("Issuer Match Failed");
                }

        }

        PKIX_CHECK(PKIX_ComCRLSelParams_GetDateAndTime
                    (params, &selDate, plContext),
                    "PKIX_ComCRLSelParams_GetDateAndTime failed");

        /* Check for Date */
        if (selDate != NULL){

                result = PKIX_FALSE;

                PKIX_CHECK(PKIX_PL_CRL_VerifyUpdateTime
                            (crl, selDate, &result, plContext),
                            "pkix_pl_CRL_VerifyUpdateTime failed");

                if (result == PKIX_FALSE) {
                        PKIX_ERROR("DateAndTime match Failed");
                }

        }

        /* Check for CRL number in range */
        PKIX_CHECK(PKIX_PL_CRL_GetCRLNumber(crl, &crlNumber, plContext),
                    "PKIX_PL_CRL_GetCRLNumber failed");

        if (crlNumber != NULL) {
                result = PKIX_FALSE;

                PKIX_CHECK(PKIX_ComCRLSelParams_GetMinCRLNumber
                            (params, &minCRLNumber, plContext),
                            "PKIX_ComCRLSelParams_GetMinCRLNumber failed");

                if (minCRLNumber != NULL) {

                        PKIX_CHECK(PKIX_PL_Object_Compare
                                    ((PKIX_PL_Object *)minCRLNumber,
                                    (PKIX_PL_Object *)crlNumber,
                                    &result,
                                    plContext),
                                    "PKIX_PL_Object_Comparator failed");

                        if (result == 1) {
                                PKIX_ERROR("CRL MinNumber Range Match FAILED");
                        }
                }

                PKIX_CHECK(PKIX_ComCRLSelParams_GetMaxCRLNumber
                            (params, &maxCRLNumber, plContext),
                            "PKIX_ComCRLSelParams_GetMaxCRLNumber failed");

                if (maxCRLNumber != NULL) {

                        PKIX_CHECK(PKIX_PL_Object_Compare
                                    ((PKIX_PL_Object *)crlNumber,
                                    (PKIX_PL_Object *)maxCRLNumber,
                                    &result,
                                    plContext),
                                    "PKIX_PL_Object_Comparator failed");

                        if (result == 1) {
                                PKIX_ERROR("CRL MaxNumber Range Match FAILED");
                        }
                }
        }

cleanup:

        PKIX_DECREF(selIssuerNames);
        PKIX_DECREF(selDate);
        PKIX_DECREF(crlIssuerName);
        PKIX_DECREF(issuerName);
        PKIX_DECREF(crlNumber);
        PKIX_DECREF(minCRLNumber);
        PKIX_DECREF(maxCRLNumber);

        PKIX_RETURN(CRLSELECTOR);
}

/*
 * FUNCTION: pkix_CRLSelector_RegisterSelf
 * DESCRIPTION:
 *  Registers PKIX_CRLSELECTOR_TYPE and its related functions with
 *  systemClasses[]
 * THREAD SAFETY:
 *  Not Thread Safe - for performance and complexity reasons
 *
 *  Since this function is only called by PKIX_PL_Initialize, which should
 *  only be called once, it is acceptable that this function is not
 *  thread-safe.
 */
PKIX_Error *
pkix_CRLSelector_RegisterSelf(void *plContext)
{
        extern pkix_ClassTable_Entry systemClasses[PKIX_NUMTYPES];
        pkix_ClassTable_Entry entry;

        PKIX_ENTER(CRLSELECTOR, "pkix_CRLSelector_RegisterSelf");

        entry.description = "CRLSelector";
        entry.destructor = pkix_CRLSelector_Destroy;
        entry.equalsFunction = pkix_CRLSelector_Equals;
        entry.hashcodeFunction = pkix_CRLSelector_Hashcode;
        entry.toStringFunction = pkix_CRLSelector_ToString;
        entry.comparator = NULL;
        entry.duplicateFunction = pkix_CRLSelector_Duplicate;

        systemClasses[PKIX_CRLSELECTOR_TYPE] = entry;

cleanup:
        PKIX_RETURN(CRLSELECTOR);
}

/* --CRLSelector-Public-Functions---------------------------------------- */

/*
 * FUNCTION: PKIX_CRLSelector_Create (see comments in pkix_crlsel.h)
 */
PKIX_Error *
PKIX_CRLSelector_Create(
        PKIX_CRLSelector_MatchCallback callback,
        PKIX_PL_Object *crlSelectorContext,
        PKIX_CRLSelector **pSelector,
        void *plContext)
{
        PKIX_CRLSelector *selector = NULL;

        PKIX_ENTER(CRLSELECTOR, "PKIX_CRLSelector_Create");
        PKIX_NULLCHECK_ONE(pSelector);

        PKIX_CHECK(PKIX_PL_Object_Alloc
                    (PKIX_CRLSELECTOR_TYPE,
                    sizeof (PKIX_CRLSelector),
                    (PKIX_PL_Object **)&selector,
                    plContext),
                    "Could not create CRLSelector object");

        /*
         * if user specified a particular match callback, we use that one.
         * otherwise, we use the default match provided.
         */

        if (callback != NULL){
                selector->matchCallback = callback;
        } else {
                selector->matchCallback = pkix_CRLSelector_DefaultMatch;
        }

        /* initialize other fields */
        selector->params = NULL;

        PKIX_INCREF(crlSelectorContext);
        selector->context = crlSelectorContext;

        *pSelector = selector;

cleanup:

        if (PKIX_ERROR_RECEIVED){
                PKIX_DECREF(selector);
        }

        PKIX_RETURN(CRLSELECTOR);
}

/*
 * FUNCTION: PKIX_CRLSelector_GetMatchCallback (see comments in pkix_crlsel.h)
 */
PKIX_Error *
PKIX_CRLSelector_GetMatchCallback(
        PKIX_CRLSelector *selector,
        PKIX_CRLSelector_MatchCallback *pCallback,
        void *plContext)
{
        PKIX_ENTER(CRLSELECTOR, "PKIX_CRLSelector_GetMatchCallback");
        PKIX_NULLCHECK_TWO(selector, pCallback);

        *pCallback = selector->matchCallback;

cleanup:

        PKIX_RETURN(CRLSELECTOR);
}


/*
 * FUNCTION: PKIX_CRLSelector_GetCRLSelectorContext
 * (see comments in pkix_crlsel.h)
 */
PKIX_Error *
PKIX_CRLSelector_GetCRLSelectorContext(
        PKIX_CRLSelector *selector,
        void **pCrlSelectorContext,
        void *plContext)
{
        PKIX_ENTER(CRLSELECTOR, "PKIX_CRLSelector_GetCRLSelectorContext");
        PKIX_NULLCHECK_TWO(selector, pCrlSelectorContext);

        PKIX_INCREF(selector->context);

        *pCrlSelectorContext = selector->context;

cleanup:

        PKIX_RETURN(CRLSELECTOR);
}

/*
 * FUNCTION: PKIX_CRLSelector_GetCommonCRLSelectorParams
 * (see comments in pkix_crlsel.h)
 */
PKIX_Error *
PKIX_CRLSelector_GetCommonCRLSelectorParams(
        PKIX_CRLSelector *selector,
        PKIX_ComCRLSelParams **pParams,
        void *plContext)
{
        PKIX_ENTER(CRLSELECTOR, "PKIX_CRLSelector_GetCommonCRLSelectorParams");
        PKIX_NULLCHECK_TWO(selector, pParams);

        PKIX_INCREF(selector->params);

        *pParams = selector->params;

cleanup:

        PKIX_RETURN(CRLSELECTOR);
}

/*
 * FUNCTION: PKIX_CRLSelector_SetCommonCRLSelectorParams
 * (see comments in pkix_crlsel.h)
 */
PKIX_Error *
PKIX_CRLSelector_SetCommonCRLSelectorParams(
        PKIX_CRLSelector *selector,
        PKIX_ComCRLSelParams *params,
        void *plContext)
{
        PKIX_ENTER(CRLSELECTOR, "PKIX_CRLSelector_SetCommonCRLSelectorParams");
        PKIX_NULLCHECK_TWO(selector, params);

        PKIX_DECREF(selector->params);

        PKIX_INCREF(params);
        selector->params = params;

        PKIX_CHECK(PKIX_PL_Object_InvalidateCache
                    ((PKIX_PL_Object *)selector, plContext),
                    "PKIX_PL_Object_InvalidateCache failed");

cleanup:

        PKIX_RETURN(CRLSELECTOR);
}
