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
 * pkix_pl_certdp.c
 *
 * CertDistributionPoint Object Functions Definitions
 *
 */

#include "pkix_pl_certdp.h"

/* --Private-CertDistributionPoint-Functions----------------------------- */

/*
 * FUNCTION: pkix_pl_CertDistributionPoint_Destroy
 * (see comments for PKIX_PL_DestructorCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_pl_CertDistributionPoint_Destroy(
        PKIX_PL_Object *object,
        void *plContext)
{
        PKIX_PL_CertDistributionPoint *dp = NULL;

        PKIX_ENTER(CERTDISTRIBUTIONPOINT,
                    "pkix_pl_CertDistributionPoint_Destroy");
        PKIX_NULLCHECK_ONE(object);

        PKIX_CHECK(pkix_CheckType
                    (object, PKIX_CERTDISTRIBUTIONPOINT_TYPE, plContext),
                    PKIX_OBJECTNOTCERTDISTRIBUTIONPOINT);

        dp = (PKIX_PL_CertDistributionPoint *) object;

        dp->nssCrlDp = NULL; /* freed when NSS cert is freed */

        PKIX_DECREF(dp->dpName);
        PKIX_DECREF(dp->crlIssuerList);

cleanup:

        PKIX_RETURN(CERTDISTRIBUTIONPOINT);
}

/*
 * FUNCTION: pkix_pl_CertDistributionPoint_ToString_Helper
 * DESCRIPTION:
 *
 *  Helper function that creates a string representation of
 *  CertDistributionPoint and stores it at "pString".
 *
 * PARAMETERS
 *  "dp"
 *      Address of CertDistributionPoint whose string representation
 *      is desired. Must be non-NULL.
 *  "pString"
 *      Address where string pointer will be stored. Must be non-NULL.
 *  "plContext" - Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a CertDistributionPoint Error if the function fails in a
 *  non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
pkix_pl_CertDistributionPoint_ToString_Helper(
        PKIX_PL_CertDistributionPoint *dp,
        PKIX_PL_String **pString,
        void *plContext)
{
        char *asciiFormat = NULL;
        PKIX_PL_String *formatString = NULL;
        PKIX_PL_DistributionPointName *dpName = NULL;
        PKIX_PL_String *dpNameString = NULL;
        PKIX_List *crlIssuerList = NULL;
        PKIX_PL_String *crlIssuerListString = NULL;
        PKIX_PL_String *dpString = NULL;
        PKIX_UInt32 reasons = 0;

        PKIX_ENTER(CERTDISTRIBUTIONPOINT,
                    "pkix_pl_CertDistributionPoint_ToString_Helper");
        PKIX_NULLCHECK_TWO(dp, pString);

        asciiFormat =
                "[\n"
                "\tDistribPointName:%s\n"
                "\tReasons:         0x%x\n"
                "\tCRLIssuers:      %s\n"
                "\t]";

        PKIX_CHECK(PKIX_PL_String_Create
                    (PKIX_ESCASCII,
                    asciiFormat,
                    0,
                    &formatString,
                    plContext),
                    PKIX_STRINGCREATEFAILED);

        PKIX_CHECK(PKIX_PL_CertDistributionPoint_GetDistributionPointName
                    (dp, &dpName, plContext),
		    PKIX_GETDISTRIBUTIONPOINTNAMEFAILED);

        PKIX_TOSTRING(dpName, &dpNameString, plContext,
                    PKIX_DISTRIBUTIONPOINTNAMETOSTRINGFAILED);

        PKIX_CHECK(PKIX_PL_CertDistributionPoint_GetReasons
                    (dp, &reasons, plContext),
		    PKIX_CERTDISTRIBUTIONPOINTGETREASONSFAILED);

        PKIX_CHECK(PKIX_PL_CertDistributionPoint_GetCrlIssuerNames
                    (dp, &crlIssuerList, plContext),
		    PKIX_CERTDISTRIBUTIONPOINTGETCRLISSUERNAMESFAILED);

        PKIX_TOSTRING(crlIssuerList, &crlIssuerListString, plContext,
                    PKIX_LISTTOSTRINGFAILED);

        PKIX_CHECK(PKIX_PL_Sprintf
                    (&dpString,
                    plContext,
                    formatString,
                    dpNameString,
                    reasons,
                    crlIssuerListString),
                    PKIX_SPRINTFFAILED);

        *pString = dpString;

cleanup:

        PKIX_DECREF(formatString);
        PKIX_DECREF(dpName);
        PKIX_DECREF(dpNameString);
        PKIX_DECREF(crlIssuerList);
        PKIX_DECREF(crlIssuerListString);

        PKIX_RETURN(CERTDISTRIBUTIONPOINT);
}

/*
 * FUNCTION: pkix_pl_CertDistributionPoint_ToString
 * (see comments for PKIX_PL_ToStringCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_pl_CertDistributionPoint_ToString(
        PKIX_PL_Object *object,
        PKIX_PL_String **pString,
        void *plContext)
{
        PKIX_PL_String *dpString = NULL;
        PKIX_PL_CertDistributionPoint *dp = NULL;

        PKIX_ENTER(CERTDISTRIBUTIONPOINT,
                    "pkix_pl_CertDistributionPoint_ToString");
        PKIX_NULLCHECK_TWO(object, pString);

        PKIX_CHECK(pkix_CheckType
                    (object,
                    PKIX_CERTDISTRIBUTIONPOINT_TYPE,
                    plContext),
                    PKIX_OBJECTNOTCERTDISTRIBUTIONPOINT);

        dp = (PKIX_PL_CertDistributionPoint *)object;

        PKIX_CHECK(pkix_pl_CertDistributionPoint_ToString_Helper
                    (dp, &dpString, plContext),
                    PKIX_CERTDISTRIBUTIONPOINTTOSTRINGHELPERFAILED);

        *pString = dpString;

cleanup:

        PKIX_RETURN(CERTDISTRIBUTIONPOINT);
}

/*
 * FUNCTION: pkix_pl_CertDistributionPoint_RegisterSelf
 * DESCRIPTION:
 *
 *  Registers PKIX_CERTDISTRIBUTIONPOINT_TYPE and its related functions
 *  with systemClasses[]
 *
 * THREAD SAFETY:
 *  Not Thread Safe - for performance and complexity reasons
 *
 *  Since this function is only called by PKIX_PL_Initialize, which should
 *  only be called once, it is acceptable that this function is not
 *  thread-safe.
 */
PKIX_Error *
pkix_pl_CertDistributionPoint_RegisterSelf(void *plContext)
{
        extern pkix_ClassTable_Entry systemClasses[PKIX_NUMTYPES];
        pkix_ClassTable_Entry entry;

        PKIX_ENTER(CERTDISTRIBUTIONPOINT,
                    "pkix_pl_CertDistributionPoint_RegisterSelf");

        entry.description = "CertDistributionPoint";
        entry.destructor = pkix_pl_CertDistributionPoint_Destroy;
        entry.equalsFunction = NULL;
        entry.hashcodeFunction = NULL;
        entry.toStringFunction = pkix_pl_CertDistributionPoint_ToString;
        entry.comparator = NULL;
        entry.duplicateFunction = pkix_duplicateImmutable;

        systemClasses[PKIX_CERTDISTRIBUTIONPOINT_TYPE] = entry;

        PKIX_RETURN(CERTDISTRIBUTIONPOINT);
}

/*
 * FUNCTION: pkix_pl_CertDistributionPoint_Create
 * DESCRIPTION:
 *
 *  Creates a new CertDistributionPoint using the data at "nssDistPoint"
 *  and result at "pDistPoint".
 *
 * PARAMETERS
 *  "nssDistPoint"
 *      Address of CRLDistributionPoint that contains this object's data.
 *      Must be non-NULL.
 *  "pDistPoint"
 *      Address where object pointer will be stored. Must be non-NULL.
 *  "plContext" - Platform-specific context pointer.
 *
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 *
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
pkix_pl_CertDistributionPoint_Create(
        CRLDistributionPoint *nssDistPoint,
        PKIX_PL_CertDistributionPoint **pDistPoint,
        void *plContext)
{
        PKIX_PL_CertDistributionPoint *dp = NULL;

        PKIX_ENTER(CERTDISTRIBUTIONPOINT,
                    "pkix_pl_CertDistributionPoint_Create");
        PKIX_NULLCHECK_TWO(nssDistPoint, pDistPoint);

        PKIX_CHECK(PKIX_PL_Object_Alloc
                    (PKIX_CERTDISTRIBUTIONPOINT_TYPE,
                    sizeof (PKIX_PL_CertDistributionPoint),
                    (PKIX_PL_Object **)&dp,
                    plContext),
                    PKIX_CERTDISTRIBUTIONPOINTCREATEFAILED);

        dp->nssCrlDp = nssDistPoint;
        dp->dpName = NULL;
        dp->dpNameAbsent = PKIX_FALSE;
        dp->reasons = 0;
        dp->reasonsProcess = PKIX_FALSE;
        dp->crlIssuerList = NULL;

        *pDistPoint = dp;

cleanup:

        PKIX_RETURN(CERTDISTRIBUTIONPOINT);
}

/* --Public-CertDistributionPoint-Functions------------------------------- */

/*
 * FUNCTION: PKIX_PL_CertDistributionPoint_GetDistributionPointName
 * (see comments in pkix_pl_pki.h)
 */
PKIX_Error *
PKIX_PL_CertDistributionPoint_GetDistributionPointName(
        PKIX_PL_CertDistributionPoint *distPoint,
        PKIX_PL_DistributionPointName **pDistPointName,
        void *plContext)
{
        CRLDistributionPoint *nssCrlDp = NULL;
        PKIX_PL_DistributionPointName *dpName = NULL;
        CERTDistributionPointName nssDpName;

        PKIX_ENTER(CERTDISTRIBUTIONPOINT,
                    "PKIX_PL_CertDistributionPoint_GetDistributionPointName");
        PKIX_NULLCHECK_THREE(distPoint, pDistPointName, distPoint->nssCrlDp);

        nssCrlDp = distPoint->nssCrlDp;

        if (!distPoint->dpNameAbsent && distPoint->dpName == NULL) {

                /* There is data and not cached yet */

                PKIX_OBJECT_LOCK(distPoint);

                if (!distPoint->dpNameAbsent &&
                    distPoint->dpName == NULL) {

                    if (nssCrlDp->distPoint.fullName != NULL) {
                        nssDpName.distPointType = nssCrlDp->distPointType;
                        nssDpName.distPoint.fullName =
                                nssCrlDp->distPoint.fullName;

                        PKIX_CHECK(pkix_pl_DistributionPointName_Create
                                (&nssDpName, &dpName, plContext),
                                PKIX_DISTRIBUTIONPOINTNAMECREATEFAILED);

                        distPoint->dpName = dpName;
                    } else {
                        distPoint->dpNameAbsent = PKIX_TRUE;
                    }
                }
                PKIX_OBJECT_UNLOCK(distPoint);
        }

        PKIX_INCREF(distPoint->dpName);
        *pDistPointName = distPoint->dpName;

cleanup:
        PKIX_RETURN(CERTDISTRIBUTIONPOINT);
}

/*
 * FUNCTION: PKIX_PL_CertDistributionPoint_GetReasons
 * (see comments in pkix_pl_pki.h)
 */
PKIX_Error *
PKIX_PL_CertDistributionPoint_GetReasons(
        PKIX_PL_CertDistributionPoint *distPoint,
        PKIX_UInt32 *pReasonFlags,
        void *plContext)
{
        CRLDistributionPoint *nssCrlDp = NULL;

        PKIX_ENTER(CERTDISTRIBUTIONPOINT,
                    "PKIX_PL_CertDistributionPoint_GetReasons");
        PKIX_NULLCHECK_THREE(distPoint, pReasonFlags, distPoint->nssCrlDp);

        nssCrlDp = distPoint->nssCrlDp;

        if (!distPoint->reasonsProcess && distPoint->reasons == 0) {

                PKIX_OBJECT_LOCK(distPoint);
                if (!distPoint->reasonsProcess && distPoint->reasons == 0) {
                        distPoint->reasonsProcess = PKIX_TRUE;
                        PKIX_CERTDISTRIBUTIONPOINT_DEBUG
                                ("\t\tCalling DER_GetUIntegerBits\n");
                        distPoint->reasons =
                                DER_GetUIntegerBits(&nssCrlDp->reasons);
                }
                PKIX_OBJECT_UNLOCK(distPoint);
        }
        *pReasonFlags = distPoint->reasons;

cleanup:
        PKIX_RETURN(CERTDISTRIBUTIONPOINT);
}

/*
 * FUNCTION: PKIX_PL_CertDistributionPoint_GetCrlIssuerNames
 * (see comments in pkix_pl_pki.h)
 */
PKIX_Error *
PKIX_PL_CertDistributionPoint_GetCrlIssuerNames(
        PKIX_PL_CertDistributionPoint *distPoint,
        PKIX_List **pCrlIssuerNames, /* list of PKIX_PL_GeneralName */
        void *plContext)
{
        CRLDistributionPoint *nssCrlDp = NULL;
        CERTGeneralName *nssCrlIssuer = NULL;
        CERTGeneralName *nssCrlIssuerNext = NULL;
        PKIX_List *crlIssuerList = NULL;
        PKIX_PL_GeneralName *generalCrlName = NULL;

        PKIX_ENTER(CERTDISTRIBUTIONPOINT,
                    "PKIX_PL_CertDistributionPoint_GetCrlIssuerNames");
        PKIX_NULLCHECK_THREE(distPoint, pCrlIssuerNames, distPoint->nssCrlDp);

        if (distPoint->crlIssuerList == NULL) {

                PKIX_OBJECT_LOCK(distPoint);

                if (distPoint->crlIssuerList == NULL) {

                        nssCrlDp = distPoint->nssCrlDp;
                        nssCrlIssuer = nssCrlDp->crlIssuer;
                        nssCrlIssuerNext = nssCrlIssuer;

                        PKIX_CHECK(PKIX_List_Create(&crlIssuerList, plContext),
                                PKIX_LISTCREATEFAILED);

                        while (nssCrlIssuer) {

                            PKIX_CHECK(pkix_pl_GeneralName_Create
                                (nssCrlDp->crlIssuer,
                                &generalCrlName,
                                plContext),
                                PKIX_GENERALNAMECREATEFAILED);

                            PKIX_CHECK(PKIX_List_AppendItem
                                (crlIssuerList,
                                (PKIX_PL_Object *)generalCrlName,
                                plContext),
                                PKIX_LISTAPPENDITEMFAILED);

                            PKIX_DECREF(generalCrlName);

                            PKIX_CERTDISTRIBUTIONPOINT_DEBUG
                                ("\t\tCalling CERT_GetNextGeneralName.\n");
                            nssCrlIssuerNext =
                                    CERT_GetNextGeneralName(nssCrlIssuerNext);

                            if (nssCrlIssuer == nssCrlIssuerNext) {
                                /* XXX No test case for testing yet */
                                break;
                            }

                        }

                        distPoint->crlIssuerList = crlIssuerList;
                }

                PKIX_OBJECT_UNLOCK(distPoint);

        }

        PKIX_INCREF(distPoint->crlIssuerList);

        *pCrlIssuerNames = distPoint->crlIssuerList;

cleanup:

        if (PKIX_ERROR_RECEIVED){
                PKIX_DECREF(generalCrlName);
                PKIX_DECREF(crlIssuerList);
        }

        PKIX_RETURN(CERTDISTRIBUTIONPOINT);
}
