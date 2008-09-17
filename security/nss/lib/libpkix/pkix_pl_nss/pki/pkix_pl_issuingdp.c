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
 * pkix_pl_issuingdp.c
 *
 * IssuingDistributionPoint Object Functions Definitions
 *
 */

#include "pkix_pl_issuingdp.h"

/* --Private-IssuingDistributionPoint-Functions-------------------- */

/*
 * FUNCTION: pkix_pl_IssuingDistributionPoint_Create_Helper
 *
 * DESCRIPTION:
 *
 *  Helper function that populates items in IssuingDistributionPoint object
 *  "issuingDistPoint" with its NSS data from "nssIssuingDistPoint".
 *
 * PARAMETERS
 *  "nssIssuingDistPoint'
 *      Address of CERTCrlIssuingDistributionPoint whose data is used
 *      to create the object. Must be non-NULL.
 *  "issuingDistPoint"
 *      Address of the object for creation. Must be non-NULL.
 *  "plContext" - Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 *  Lock is acquired at higher-level.
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a DistributionPointName Error if the function fails in a
 *  non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
static PKIX_Error *
pkix_pl_IssuingDistributionPoint_Create_Helper(
        CERTCrlIssuingDistributionPoint *nssIssuingDistPoint,
        PKIX_PL_IssuingDistributionPoint *issuingDistPoint,
        void *plContext)
{
        PKIX_ENTER(ISSUINGDISTRIBUTIONPOINT,
                "pkix_pl_IssuingDistributionPoint_Create_Helper");
        PKIX_NULLCHECK_TWO(nssIssuingDistPoint, issuingDistPoint);

        if (nssIssuingDistPoint->onlyContainsUserCerts.data) {
                issuingDistPoint->onlyContainsUserCerts =
                    nssIssuingDistPoint->onlyContainsUserCerts.data[0] == 0xff;
        } else {
                issuingDistPoint->onlyContainsUserCerts = PKIX_FALSE;
        }

        if (nssIssuingDistPoint->onlyContainsCACerts.data) {
                issuingDistPoint->onlyContainsCACerts =
                    nssIssuingDistPoint->onlyContainsCACerts.data[0] == 0xff;
        } else {
                issuingDistPoint->onlyContainsCACerts = PKIX_FALSE;
        }

        if (nssIssuingDistPoint->onlySomeReasons.data) {
                PKIX_ISSUINGDISTRIBUTIONPOINT_DEBUG
                        ("\t\tCalling DER_GetUIntegerBits\n");
                issuingDistPoint->onlySomeReasons =
                    DER_GetUIntegerBits(&nssIssuingDistPoint->onlySomeReasons);
        } else {
                issuingDistPoint->onlySomeReasons = 0;
        }

        if (nssIssuingDistPoint->indirectCrl.data) {
                issuingDistPoint->indirectCrl =
                    nssIssuingDistPoint->indirectCrl.data[0] == 0xff;
        } else {
                issuingDistPoint->indirectCrl = PKIX_FALSE;
        }

        if (nssIssuingDistPoint->onlyContainsAttrCerts.data) {
                issuingDistPoint->onlyContainsAttrCerts =
                    nssIssuingDistPoint->onlyContainsAttrCerts.data[0] == 0xff;
        } else {
                issuingDistPoint->onlyContainsAttrCerts = PKIX_FALSE;
        }

cleanup:

        PKIX_RETURN(ISSUINGDISTRIBUTIONPOINT);
}

/*
 * FUNCTION: pkix_pl_IssuingDistributionPoint_Create
 *
 * DESCRIPTION:
 *  Create an IssuingDistributionPoint Object from its NSS data at
 *  "nssIssuingDistPoint" and stores the result in "pIssuingDistPoint".
 *
 * PARAMETERS
 *  "nssIssuingDistPoint'
 *      Address of CERTCrlIssuingDistributionPoint whose data is used
 *      to create the object. Must be non-NULL.
 *  "pIssuingDistPoint"
 *      Address of the object for creation. Must be non-NULL.
 *  "plContext" - Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 *  Lock is acquired at higher-level.
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a DistributionPointName Error if the function fails in a
 *  non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
pkix_pl_IssuingDistributionPoint_Create(
        CERTCrlIssuingDistributionPoint *nssIssuingDistPoint,
        PKIX_PL_IssuingDistributionPoint **pIssuingDistPoint,
        void *plContext)
{
        PKIX_PL_IssuingDistributionPoint *issuingDistPoint = NULL;

        PKIX_ENTER(ISSUINGDISTRIBUTIONPOINT,
                    "pkix_pl_IssuingDistributionPoint_Create");
        PKIX_NULLCHECK_TWO(nssIssuingDistPoint, pIssuingDistPoint);

        /* create a PKIX_PL_IssuingDistributionPoint object */
        PKIX_CHECK(PKIX_PL_Object_Alloc
                    (PKIX_ISSUINGDISTRIBUTIONPOINT_TYPE,
                    sizeof (PKIX_PL_IssuingDistributionPoint),
                    (PKIX_PL_Object **)&issuingDistPoint,
                    plContext),
                    PKIX_OBJECTALLOCFAILED);

        issuingDistPoint->nssIssuingDistPoint = nssIssuingDistPoint;
        issuingDistPoint->distPointName = NULL;

        PKIX_CHECK(pkix_pl_IssuingDistributionPoint_Create_Helper
                    (nssIssuingDistPoint, issuingDistPoint, plContext),
                    PKIX_ISSUINGDISTRIBUTIONPOINTCREATEHELPERfAILED);

        *pIssuingDistPoint = issuingDistPoint;

cleanup:

        PKIX_RETURN(ISSUINGDISTRIBUTIONPOINT);
}

/*
 * FUNCTION: pkix_pl_IssuingDistributionPoint_Destroy
 * (see comments for PKIX_PL_DestructorCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_pl_IssuingDistributionPoint_Destroy(
        PKIX_PL_Object *object,
        void *plContext)
{
        PKIX_PL_IssuingDistributionPoint *issuingDistPoint = NULL;

        PKIX_ENTER
                (ISSUINGDISTRIBUTIONPOINT,
                "pkix_pl_IssuingDistributionPoint_Destroy");
        PKIX_NULLCHECK_ONE(object);

        PKIX_CHECK(pkix_CheckType
                    (object, PKIX_ISSUINGDISTRIBUTIONPOINT_TYPE, plContext),
                    PKIX_OBJECTNOTISSUINGDISTRIBUTIONPOINT);

        issuingDistPoint = (PKIX_PL_IssuingDistributionPoint *) object;

        issuingDistPoint->nssIssuingDistPoint = NULL; /* freed from NSS CRL */
        issuingDistPoint->onlyContainsUserCerts = PKIX_FALSE;
        issuingDistPoint->onlyContainsCACerts = PKIX_FALSE;
        issuingDistPoint->onlySomeReasons = 0;
        issuingDistPoint->indirectCrl = PKIX_FALSE;
        issuingDistPoint->onlyContainsAttrCerts = PKIX_FALSE;

        PKIX_DECREF(issuingDistPoint->distPointName);

cleanup:

        PKIX_RETURN(ISSUINGDISTRIBUTIONPOINT);
}

/*
 * FUNCTION: pkix_pl_IssuingDistributionPoint_ToString_Helper
 * DESCRIPTION:
 *
 *  Helper function that creates a string representation of the
 *  IssuingDistributionPoint pointed to by "issuingDistPoint" and stores
 *  it at "pString".
 *
 * PARAMETERS
 *  "issuingDistPoint"
 *      Address of the object whose string representation is desired.
 *      Must be non-NULL.
 *  "pString"
 *      Address where string object will be stored. Must be non-NULL.
 *  "plContext" - Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a IssuingDistributionPoint Error if the function fails in a
 *  non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
pkix_pl_IssuingDistributionPoint_ToString_Helper(
        PKIX_PL_IssuingDistributionPoint *issuingDistPoint,
        PKIX_PL_String **pString,
        void *plContext)
{
        char *asciiFormat = NULL;
        PKIX_PL_String *issuingDistPointString = NULL;
        PKIX_PL_String *formatString = NULL;
        PKIX_PL_DistributionPointName *distPointName = NULL;
        PKIX_PL_String *distPointNameString = NULL;
        PKIX_Boolean onlyContainsUserCerts = PKIX_FALSE;
        PKIX_Boolean onlyContainsCACerts = PKIX_FALSE;
        PKIX_UInt32 onlySomeReasons = 0;
        PKIX_Boolean indirectCrl = PKIX_FALSE;
        PKIX_Boolean onlyContainsAttrCerts = PKIX_FALSE;

        PKIX_ENTER(ISSUINGDISTRIBUTIONPOINT,
                "pkix_pl_IssuingDistributionPoint_ToString_Helper");
        PKIX_NULLCHECK_TWO(issuingDistPoint, pString);


        asciiFormat =
                "[\n"
                "\tdistributionPointName: %s\n"
                "\tonlyContainsUserCerts: %d\n"
                "\tonlyContainsCACerts:   %d\n"
                "\tonlySomeReasons:     0x%x\n"
                "\tindirectCRL:           %d\n"
                "\tonlyContainsAttrCerts: %d ]\n";

        PKIX_CHECK(PKIX_PL_String_Create
                    (PKIX_ESCASCII,
                    asciiFormat,
                    0,
                    &formatString,
                    plContext),
                    PKIX_STRINGCREATEFAILED);

        /* Distribution Point Name */
        PKIX_CHECK(PKIX_PL_IssuingDistributionPoint_GetDistributionPointName
            (issuingDistPoint, &distPointName, plContext),
            PKIX_GETDISTRIBUTIONPOINTNAMEFAILED);

        PKIX_TOSTRING(distPointName, &distPointNameString, plContext,
            PKIX_OBJECTTOSTRINGFAILED);

        PKIX_CHECK(PKIX_PL_Sprintf
                    (&issuingDistPointString,
                    plContext,
                    formatString,
                    distPointNameString,
                    issuingDistPoint->onlyContainsUserCerts,
                    issuingDistPoint->onlyContainsCACerts,
                    issuingDistPoint->onlySomeReasons,
                    issuingDistPoint->indirectCrl,
                    issuingDistPoint->onlyContainsAttrCerts),
                    PKIX_SPRINTFFAILED);

        *pString = issuingDistPointString;

cleanup:

        PKIX_DECREF(formatString);
        PKIX_DECREF(distPointName);
        PKIX_DECREF(distPointNameString);

        PKIX_RETURN(ISSUINGDISTRIBUTIONPOINT);
}

/*
 * FUNCTION: pkix_pl_IssuingDistributionPoint_ToString
 * (see comments for PKIX_PL_ToStringCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_pl_IssuingDistributionPoint_ToString(
        PKIX_PL_Object *object,
        PKIX_PL_String **pString,
        void *plContext)
{
        PKIX_PL_String *issuingDpString = NULL;
        PKIX_PL_IssuingDistributionPoint *issuingDp = NULL;

        PKIX_ENTER(ISSUINGDISTRIBUTIONPOINT,
                    "pkix_pl_IssuingDistributionPoint_ToString");
        PKIX_NULLCHECK_TWO(object, pString);

        PKIX_CHECK(pkix_CheckType
                    (object, PKIX_ISSUINGDISTRIBUTIONPOINT_TYPE, plContext),
                    PKIX_OBJECTNOTISSUINGDISTRIBUTIONPOINT);

        issuingDp = (PKIX_PL_IssuingDistributionPoint *)object;

        PKIX_CHECK(pkix_pl_IssuingDistributionPoint_ToString_Helper
                    (issuingDp, &issuingDpString, plContext),
                    PKIX_ISSUINGDISTRIBUTIONPOINTTOSTRINGHELPERfAILED);
        *pString = issuingDpString;
cleanup:
        PKIX_RETURN(ISSUINGDISTRIBUTIONPOINT);
}

/*
 * FUNCTION: pkix_pl_IssuingDistributionPoint_RegisterSelf
 * DESCRIPTION:
 *  Registers PKIX_ISSUINGDISTRIBUTIONPOINT_TYPE and its related functions
 *  with systemClasses[]
 * THREAD SAFETY:
 *  Not Thread Safe - for performance and complexity reasons
 *
 *  Since this function is only called by PKIX_PL_Initialize, which should
 *  only be called once, it is acceptable that this function is not
 *  thread-safe.
 */
PKIX_Error *
pkix_pl_IssuingDistributionPoint_RegisterSelf(void *plContext)
{
        extern pkix_ClassTable_Entry systemClasses[PKIX_NUMTYPES];
        pkix_ClassTable_Entry entry;

        PKIX_ENTER(ISSUINGDISTRIBUTIONPOINT,
                    "pkix_pl_IssuingDistributionPoint_RegisterSelf");

        entry.description = "IssuingDistributionPoint";
        entry.destructor = pkix_pl_IssuingDistributionPoint_Destroy;
        entry.equalsFunction = NULL;
        entry.hashcodeFunction = NULL;
        entry.toStringFunction = pkix_pl_IssuingDistributionPoint_ToString;
        entry.comparator = NULL;
        entry.duplicateFunction = pkix_duplicateImmutable;

        systemClasses[PKIX_ISSUINGDISTRIBUTIONPOINT_TYPE] = entry;

cleanup:

        PKIX_RETURN(ISSUINGDISTRIBUTIONPOINT);
}

/* --Public-IssuingDistributionPoint-Functions--------------------------- */

/*
 * FUNCTION: PKIX_PL_IssuingDistributionPoint_GetDistributionPointName
 * (see comments in pkix_pl_pki.h)
 */
PKIX_Error *
PKIX_PL_IssuingDistributionPoint_GetDistributionPointName(
        PKIX_PL_IssuingDistributionPoint *issuingDistPoint,
        PKIX_PL_DistributionPointName **pDistPointName,
        void *plContext)
{
        CERTDistributionPointName *nssDistPointName;
        PKIX_PL_DistributionPointName *distPointName;
        CERTCrlIssuingDistributionPoint *nssIssuingDistPoint = NULL;

        PKIX_ENTER(ISSUINGDISTRIBUTIONPOINT,
                "PKIX_PL_IssuingDistributionPoint_GetDistributionPointName");

        PKIX_NULLCHECK_THREE
                (issuingDistPoint,
                pDistPointName,
                issuingDistPoint->nssIssuingDistPoint);

        nssIssuingDistPoint = issuingDistPoint->nssIssuingDistPoint;
        nssDistPointName = &nssIssuingDistPoint->distPointName;

        if (issuingDistPoint->distPointName == NULL) {

                PKIX_OBJECT_LOCK(issuingDistPoint);

                if (issuingDistPoint->distPointName == NULL) {

                        PKIX_CHECK(pkix_pl_DistributionPointName_Create
                                (nssDistPointName, &distPointName, plContext),
                                PKIX_DISTRIBUTIONPOINTNAMECREATEFAILED);

                        issuingDistPoint->distPointName = distPointName;

                }

                PKIX_OBJECT_UNLOCK(issuingDistPoint);

        }

        PKIX_INCREF(issuingDistPoint->distPointName);

        *pDistPointName = issuingDistPoint->distPointName;

cleanup:

        PKIX_RETURN(ISSUINGDISTRIBUTIONPOINT);
}

/*
 * FUNCTION: PKIX_PL_IssuingDistributionPoint_GetOnlyContainsUserCerts
 * (see comments in pkix_pl_pki.h)
 */
PKIX_Error *
PKIX_PL_IssuingDistributionPoint_GetOnlyContainsUserCerts(
        PKIX_PL_IssuingDistributionPoint *issuingDistPoint,
        PKIX_Boolean *pOnlyUserCerts,
        void *plContext)
{
        PKIX_ENTER(ISSUINGDISTRIBUTIONPOINT,
                "PKIX_PL_IssuingDistributionPoint_GetOnlyContainsUserCerts");

        PKIX_NULLCHECK_TWO(issuingDistPoint, pOnlyUserCerts);

        *pOnlyUserCerts = issuingDistPoint->onlyContainsUserCerts;

cleanup:

        PKIX_RETURN(ISSUINGDISTRIBUTIONPOINT);
}

/*
 * FUNCTION: PKIX_PL_IssuingDistributionPoint_GetOnlyContainsCACerts
 * (see comments in pkix_pl_pki.h)
 */
PKIX_Error *
PKIX_PL_IssuingDistributionPoint_GetOnlyContainsCACerts(
        PKIX_PL_IssuingDistributionPoint *issuingDistPoint,
        PKIX_Boolean *pOnlyCACerts,
        void *plContext)
{
        PKIX_ENTER(ISSUINGDISTRIBUTIONPOINT,
                "PKIX_PL_IssuingDistributionPoint_GetOnlyContainsCACerts");

        PKIX_NULLCHECK_TWO(issuingDistPoint, pOnlyCACerts);

        *pOnlyCACerts = issuingDistPoint->onlyContainsCACerts;

cleanup:

        PKIX_RETURN(ISSUINGDISTRIBUTIONPOINT);
}

/*
 * FUNCTION: PKIX_PL_IssuingDistributionPoint_GetOnlySomeReasons
 * (see comments in pkix_pl_pki.h)
 */
PKIX_Error *
PKIX_PL_IssuingDistributionPoint_GetOnlySomeReasons(
        PKIX_PL_IssuingDistributionPoint *issuingDistPoint,
        PKIX_UInt32 *pReasonFlags,
        void *plContext)
{
        PKIX_ENTER(ISSUINGDISTRIBUTIONPOINT,
                "PKIX_PL_IssuingDistributionPoint_GetOnlySomeReasons");

        PKIX_NULLCHECK_TWO(issuingDistPoint, pReasonFlags);

        *pReasonFlags = issuingDistPoint->onlySomeReasons;

cleanup:

        PKIX_RETURN(ISSUINGDISTRIBUTIONPOINT);
}

/*
 * FUNCTION: PKIX_PL_IssuingDistributionPoint_GetIndirectCRL
 * (see comments in pkix_pl_pki.h)
 */
PKIX_Error *
PKIX_PL_IssuingDistributionPoint_GetIndirectCRL(
        PKIX_PL_IssuingDistributionPoint *issuingDistPoint,
        PKIX_Boolean *pIndirectCrl,
        void *plContext)
{
        PKIX_ENTER(ISSUINGDISTRIBUTIONPOINT,
                "PKIX_PL_IssuingDistributionPoint_GetIndirectCRL");
        PKIX_NULLCHECK_TWO(issuingDistPoint, pIndirectCrl);

        *pIndirectCrl = issuingDistPoint->indirectCrl;

cleanup:

        PKIX_RETURN(ISSUINGDISTRIBUTIONPOINT);
}

/*
 * FUNCTION: PKIX_PL_IssuingDistributionPoint_GetOnlyContainsAttrCerts
 * (see comments in pkix_pl_pki.h)
 */
PKIX_Error *
PKIX_PL_IssuingDistributionPoint_GetOnlyContainsAttrCerts(
        PKIX_PL_IssuingDistributionPoint *issuingDistPoint,
        PKIX_Boolean *pOnlyAttrCerts,
        void *plContext)
{
        PKIX_ENTER(ISSUINGDISTRIBUTIONPOINT,
                "PKIX_PL_IssuingDistributionPoint_GetOnlyContainsAttrCerts");

        PKIX_NULLCHECK_TWO(issuingDistPoint, pOnlyAttrCerts);

        *pOnlyAttrCerts = issuingDistPoint->onlyContainsAttrCerts;
cleanup:

        PKIX_RETURN(ISSUINGDISTRIBUTIONPOINT);
}
