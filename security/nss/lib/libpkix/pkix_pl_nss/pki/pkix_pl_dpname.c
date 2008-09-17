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
 * pkix_pl_dpname.c
 *
 * DistributionPointName Object Functions Definitions
 *
 */

#include "pkix_pl_dpname.h"

/* --Private-DistributionPointName-Functions----------------------------- */

/*
 * FUNCTION: pkix_pl_DistributionPointName_Destroy
 * (see comments for PKIX_PL_DestructorCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_pl_DistributionPointName_Destroy(
        PKIX_PL_Object *object,
        void *plContext)
{
        PKIX_PL_DistributionPointName *dpName = NULL;

        PKIX_ENTER(DISTRIBUTIONPOINTNAME,
                "pkix_pl_DistributionPointName_Destroy");
        PKIX_NULLCHECK_ONE(object);

        PKIX_CHECK(pkix_CheckType
                (object, PKIX_DISTRIBUTIONPOINTNAME_TYPE, plContext),
                PKIX_OBJECTNOTDISTRIBUTIONPOINTNAME);

        dpName = (PKIX_PL_DistributionPointName *)object;
        /* nssFullNames (NSS data) is freed when Cert or CRL is freed */
        PKIX_DECREF(dpName->fullNameList);

cleanup:
        PKIX_RETURN(DISTRIBUTIONPOINTNAME);
}

/*
 * FUNCTION: pkix_pl_DistributionPointName_ToString_Helper
 * DESCRIPTION:
 *
 *  Helper function that creates a string representation of the object
 *  DistributionPointName pointed to by "dpName" and stores the return
 *  at "pString".
 *
 * PARAMETERS
 *  "dpName"
 *      Address of DistributionPointName whose string representation is
 *      desired. Must be non-NULL.
 *  "pString"
 *      Address where string object pointer will be stored. Must be non-NULL.
 *  "plContext" - Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a DistributionPointName Error if the function fails in a
 *  non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
pkix_pl_DistributionPointName_ToString_Helper(
        PKIX_PL_DistributionPointName *dpName,
        PKIX_PL_String **pString,
        void *plContext)
{
        char *asciiFormat = NULL;
        PKIX_PL_String *formatString = NULL;
        PKIX_List *fullNameList = NULL;
        PKIX_PL_String *fullNameListString = NULL;
        PKIX_PL_String *dpNamesString = NULL;

        PKIX_ENTER(DISTRIBUTIONPOINTNAME,
                    "pkix_pl_DistributionPointName_ToString_Helper");
        PKIX_NULLCHECK_TWO(dpName, pString);

        asciiFormat =
                "[\n"
                "\tFullName:        %s ]";

        PKIX_CHECK(PKIX_PL_String_Create
                (PKIX_ESCASCII,
                asciiFormat,
                0,
                &formatString,
                plContext),
                PKIX_STRINGCREATEFAILED);

        PKIX_CHECK(PKIX_PL_DistributionPointName_GetFullNames
                (dpName, &fullNameList, plContext),
                PKIX_DISTRIBUTIONPOINTNAMEGETFULLNAMESFAILED);

        PKIX_TOSTRING(fullNameList, &fullNameListString, plContext,
                    PKIX_LISTTOSTRINGFAILED);

        PKIX_CHECK(PKIX_PL_Sprintf
                (&dpNamesString,
                plContext,
                formatString,
                fullNameListString),
                PKIX_SPRINTFFAILED);

        *pString = dpNamesString;

cleanup:

        PKIX_DECREF(formatString);
        PKIX_DECREF(fullNameList);
        PKIX_DECREF(fullNameListString);

        PKIX_RETURN(DISTRIBUTIONPOINTNAME);
}

/*
 * FUNCTION: pkix_pl_DistributionPointName_ToString
 * (see comments for PKIX_PL_ToStringCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_pl_DistributionPointName_ToString(
        PKIX_PL_Object *object,
        PKIX_PL_String **pString,
        void *plContext)
{
        PKIX_PL_String *dpNameString = NULL;
        PKIX_PL_DistributionPointName *dpName = NULL;

        PKIX_ENTER(DISTRIBUTIONPOINTNAME,
                    "pkix_pl_DistributionPointName_ToString");
        PKIX_NULLCHECK_TWO(object, pString);

        PKIX_CHECK(pkix_CheckType
                    (object, PKIX_DISTRIBUTIONPOINTNAME_TYPE, plContext),
                    PKIX_OBJECTNOTDISTRIBUTIONPOINTNAME);

        dpName = (PKIX_PL_DistributionPointName *)object;

        PKIX_CHECK(pkix_pl_DistributionPointName_ToString_Helper
                    (dpName, &dpNameString, plContext),
                    PKIX_DISTRIBUTIONPOINTNAMETOSTRINGHELPERFAILED);

        *pString = dpNameString;

cleanup:

        PKIX_RETURN(DISTRIBUTIONPOINTNAME);
}

/*
 * FUNCTION: pkix_pl_DistributionPointName_RegisterSelf
 * DESCRIPTION:
 *  Registers PKIX_DISTRIBUTIONPOINTNAME_TYPE and its related functions with
 *  systemClasses[]
 * THREAD SAFETY:
 *  Not Thread Safe - for performance and complexity reasons
 *
 *  Since this function is only called by PKIX_PL_Initialize, which should
 *  only be called once, it is acceptable that this function is not
 *  thread-safe.
 */
PKIX_Error *
pkix_pl_DistributionPointName_RegisterSelf(void *plContext)
{
        extern pkix_ClassTable_Entry systemClasses[PKIX_NUMTYPES];
        pkix_ClassTable_Entry entry;

        PKIX_ENTER(DISTRIBUTIONPOINTNAME,
                    "pkix_pl_DistributionPointName_RegisterSelf");

        entry.description = "DistributionPointName";
        entry.destructor = pkix_pl_DistributionPointName_Destroy;
        entry.equalsFunction = NULL;
        entry.hashcodeFunction = NULL;
        entry.toStringFunction = pkix_pl_DistributionPointName_ToString;
        entry.comparator = NULL;
        entry.duplicateFunction = pkix_duplicateImmutable;

        systemClasses[PKIX_DISTRIBUTIONPOINTNAME_TYPE] = entry;

cleanup:

        PKIX_RETURN(DISTRIBUTIONPOINTNAME);
}

/*
 * FUNCTION: pkix_pl_DistributionPointName_Create
 *
 * DESCRIPTION:
 *  Creates a DistributionPointName from the data pointed to by
 *  "crlDistPointName", stores the result at "pDpName".
 *
 * PARAMETERS
 *  "crlDistPointName"
 *      Address of CERTDistributionPointName that contains this object's data.
 *      Must be non-NULL.
 *  "pDpName"
 *      Address where object pointer will be stored. Must be non-NULL.
 *  "plContext" - Platform-specific context pointer.
 *
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 *
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns an Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *pkix_pl_DistributionPointName_Create(
        CERTDistributionPointName *crlDistPointName,
        PKIX_PL_DistributionPointName **pDpName,
        void *plContext)
{
        PKIX_PL_DistributionPointName *dpName = NULL;

        PKIX_ENTER(DISTRIBUTIONPOINTNAME,
                    "pkix_pl_DistributionPointName_Create");
        PKIX_NULLCHECK_TWO(crlDistPointName, pDpName);

        PKIX_CHECK(PKIX_PL_Object_Alloc
                    (PKIX_DISTRIBUTIONPOINTNAME_TYPE,
                    sizeof (PKIX_PL_DistributionPointName),
                    (PKIX_PL_Object **)&dpName,
                    plContext),
                    PKIX_OBJECTALLOCFAILED);

        if (crlDistPointName->distPointType == generalName) {
                dpName->nssFullNames = crlDistPointName->distPoint.fullName;
        } else {
                /* relativeDistinguishedName is not supported */
                dpName->nssFullNames = NULL;
        }

        dpName->fullNameList = NULL;

        *pDpName = dpName;

cleanup:

        PKIX_RETURN(DISTRIBUTIONPOINTNAME);
}

/* --Public-DistributionPointName-Functions-------------------------------- */

/*
 * FUNCTION: PKIX_PL_DistributionPointName_GetFullNames
 * (see comments in pkix_pl_pki.h)
 */
PKIX_Error *
PKIX_PL_DistributionPointName_GetFullNames(
        PKIX_PL_DistributionPointName *dpName,
        PKIX_List **pDpFullNames, /* list of PKIX_PL_GeneralName */
        void *plContext)
{
        CERTGeneralName *fullName = NULL;
        CERTGeneralName *fullNameNext = NULL;
        PKIX_PL_GeneralName *generalName = NULL;
        PKIX_List *fullNameList = NULL;

        PKIX_ENTER(DISTRIBUTIONPOINTNAME,
                    "PKIX_PL_DistributionPointName_GetFullNames");
        PKIX_NULLCHECK_TWO(dpName, pDpFullNames);

        if (dpName->fullNameList == NULL) {

                PKIX_OBJECT_LOCK(dpName);

                if (dpName->fullNameList == NULL) {

                        fullName = dpName->nssFullNames;
                        fullNameNext = fullName;

                        PKIX_CHECK(PKIX_List_Create(&fullNameList, plContext),
                                    PKIX_LISTCREATEFAILED);

                        while (fullName) {

                                PKIX_CHECK(pkix_pl_GeneralName_Create
                                    (fullName, &generalName, plContext),
                                    PKIX_GENERALNAMECREATEFAILED);

                                PKIX_CHECK(PKIX_List_AppendItem
                                    (fullNameList,
                                    (PKIX_PL_Object *)generalName,
                                    plContext),
                                    PKIX_LISTAPPENDITEMFAILED);

                                PKIX_DECREF(generalName);

                                PKIX_DISTRIBUTIONPOINTNAME_DEBUG
                                ("\t\tCalling CERT_GetNextGeneralName.\n");

                                fullNameNext = CERT_GetNextGeneralName
                                    (fullNameNext);

                                if (fullName == fullNameNext) {
                                        break;
                                }
                        }
                        dpName->fullNameList = fullNameList;
                }
                PKIX_OBJECT_UNLOCK(dpName);
        }
        PKIX_INCREF(dpName->fullNameList);
        *pDpFullNames = dpName->fullNameList;

cleanup:
        PKIX_DECREF(generalName);
        if (PKIX_ERROR_RECEIVED){
                PKIX_DECREF(fullNameList);
        }
        PKIX_RETURN(DISTRIBUTIONPOINTNAME);
}
