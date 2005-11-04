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
 * pkix_pl_infoaccess.c
 *
 * InfoAccess Object Definitions
 *
 */

#include "pkix_pl_infoaccess.h"

/* XXX Following SEC_OID_PKIX defines should be merged in NSS */
#define SEC_OID_PKIX_CA_REPOSITORY     1003
#define SEC_OID_PKIX_TIMESTAMPING      1005
/* XXX Following OID defines hould be moved to NSS */
static const unsigned char siaTimeStampingOID[] = {0x2b, 0x06, 0x01, 0x05,
                                0x05, 0x07, 0x030, 0x03};
static const unsigned char siaCaRepositoryOID[] = {0x2b, 0x06, 0x01, 0x05,
                                0x05, 0x07, 0x030, 0x05};


/* --Private-InfoAccess-Functions----------------------------------*/

/*
 * FUNCTION: pkix_pl_InfoAccess_Destroy
 * (see comments for PKIX_PL_DestructorCallback in pkix_pl_pki.h)
 */
static PKIX_Error *
pkix_pl_InfoAccess_Destroy(
        PKIX_PL_Object *object,
        void *plContext)
{
        PKIX_PL_InfoAccess *infoAccess = NULL;

        PKIX_ENTER(INFOACCESS, "pkix_pl_InfoAccess_Destroy");
        PKIX_NULLCHECK_ONE(object);

        PKIX_CHECK(pkix_CheckType
                    (object, PKIX_INFOACCESS_TYPE, plContext),
                    "Object is not a InfoAccess");

        infoAccess = (PKIX_PL_InfoAccess *)object;

        PKIX_DECREF(infoAccess->location);

cleanup:

        PKIX_RETURN(INFOACCESS);
}

/*
 * FUNCTION: pkix_pl_InfoAccess_ToString
 * (see comments for PKIX_PL_ToStringCallback in pkix_pl_pki.h)
 */
static PKIX_Error *
pkix_pl_InfoAccess_ToString(
        PKIX_PL_Object *object,
        PKIX_PL_String **pString,
        void *plContext)
{
        PKIX_PL_InfoAccess *infoAccess;
        PKIX_PL_String *infoAccessString = NULL;
        char *asciiFormat = NULL;
        char *asciiMethod = NULL;
        PKIX_PL_String *formatString = NULL;
        PKIX_PL_String *methodString = NULL;
        PKIX_PL_String *locationString = NULL;

        PKIX_ENTER(INFOACCESS, "pkix_pl_InfoAccess_ToString");
        PKIX_NULLCHECK_TWO(object, pString);

        PKIX_CHECK(pkix_CheckType
                    (object, PKIX_INFOACCESS_TYPE, plContext),
                    "Object is not a InfoAccess");

        infoAccess = (PKIX_PL_InfoAccess *)object;

        asciiFormat =
                "["
                "method:%s, "
                "location:%s"
                "]";

        PKIX_CHECK(PKIX_PL_String_Create
                    (PKIX_ESCASCII,
                    asciiFormat,
                    0,
                    &formatString,
                    plContext),
                    "PKIX_PL_String_Create failed");

        switch(infoAccess->method) {
            case PKIX_INFOACCESS_CA_ISSUERS:
                    asciiMethod = "caIssuers";
                    break;
            case PKIX_INFOACCESS_OCSP:
                    asciiMethod = "ocsp";
                    break;
            case PKIX_INFOACCESS_TIMESTAMPING:
                    asciiMethod = "timestamping";
                    break;
            case PKIX_INFOACCESS_CA_REPOSITORY:
                    asciiMethod = "caRepository";
                    break;
            default:
                    asciiMethod = "unknown";
        }

        PKIX_CHECK(PKIX_PL_String_Create
                    (PKIX_ESCASCII,
                    asciiMethod,
                    0,
                    &methodString,
                    plContext),
                    "PKIX_PL_String_Create failed");

        PKIX_TOSTRING(infoAccess->location, &locationString, plContext,
                    "pkix_pl_GeneralName_ToString failed");

        PKIX_CHECK(PKIX_PL_Sprintf
                    (&infoAccessString,
                    plContext,
                    formatString,
                    methodString,
                    locationString),
                    "PKIX_PL_Sprintf failed");

        *pString = infoAccessString;

cleanup:

        PKIX_DECREF(formatString);
        PKIX_DECREF(methodString);
        PKIX_DECREF(locationString);

        PKIX_RETURN(INFOACCESS);
}

/*
 * FUNCTION: pkix_pl_InfoAccess_Hashcode
 * (see comments for PKIX_PL_HashcodeCallback in pkix_pl_pki.h)
 */
static PKIX_Error *
pkix_pl_InfoAccess_Hashcode(
        PKIX_PL_Object *object,
        PKIX_UInt32 *pHashcode,
        void *plContext)
{
        PKIX_PL_InfoAccess *infoAccess = NULL;
        SECItem *nssTime = NULL;
        PKIX_UInt32 infoAccessHash;

        PKIX_ENTER(INFOACCESS, "pkix_pl_InfoAccess_Hashcode");
        PKIX_NULLCHECK_TWO(object, pHashcode);

        PKIX_CHECK(pkix_CheckType
                    (object, PKIX_INFOACCESS_TYPE, plContext),
                    "Object is not a InfoAccess");

        infoAccess = (PKIX_PL_InfoAccess *)object;

        PKIX_HASHCODE(infoAccess->location, &infoAccessHash, plContext,
                    "PKIX_PL_Object_Hashcode failed");

        infoAccessHash += (infoAccess->method << 7);

        *pHashcode = infoAccessHash;

cleanup:

        PKIX_RETURN(INFOACCESS);

}

/*
 * FUNCTION: pkix_pl_InfoAccess_Equals
 * (see comments for PKIX_PL_Equals_Callback in pkix_pl_pki.h)
 */
static PKIX_Error *
pkix_pl_InfoAccess_Equals(
        PKIX_PL_Object *firstObject,
        PKIX_PL_Object *secondObject,
        PKIX_Boolean *pResult,
        void *plContext)
{
        PKIX_PL_InfoAccess *firstInfoAccess = NULL;
        PKIX_PL_InfoAccess *secondInfoAccess = NULL;
        PKIX_UInt32 secondType;
        PKIX_Boolean cmpResult;

        PKIX_ENTER(INFOACCESS, "pkix_pl_InfoAccess_Equals");
        PKIX_NULLCHECK_THREE(firstObject, secondObject, pResult);

        /* test that firstObject is a InfoAccess */
        PKIX_CHECK(pkix_CheckType
                    (firstObject, PKIX_INFOACCESS_TYPE, plContext),
                    "FirstObject argument is not a InfoAccess");

        /*
         * Since we know firstObject is a InfoAccess, if both references are
         * identical, they must be equal
         */
        if (firstObject == secondObject){
                *pResult = PKIX_TRUE;
                goto cleanup;
        }

        /*
         * If secondObject isn't a InfoAccess, we don't throw an error.
         * We simply return a Boolean result of FALSE
         */
        *pResult = PKIX_FALSE;
        PKIX_CHECK(PKIX_PL_Object_GetType
                    (secondObject, &secondType, plContext),
                    "Could not get type of second argument");
        if (secondType != PKIX_INFOACCESS_TYPE) goto cleanup;

        firstInfoAccess = (PKIX_PL_InfoAccess *)firstObject;
        secondInfoAccess = (PKIX_PL_InfoAccess *)secondObject;

        *pResult = PKIX_FALSE;

        if (firstInfoAccess->method != secondInfoAccess->method) {
                goto cleanup;
        }

        PKIX_EQUALS(firstInfoAccess, secondInfoAccess, &cmpResult, plContext,
                "PKIX_PL_Object_Equals failed");

        *pResult = cmpResult;

cleanup:

        PKIX_RETURN(INFOACCESS);
}

/*
 * FUNCTION: pkix_pl_InfoAccess_RegisterSelf
 * DESCRIPTION:
 *  Registers PKIX_INFOACCESS_TYPE and its related functions with systemClasses[]
 * THREAD SAFETY:
 *  Not Thread Safe - for performance and complexity reasons
 *
 *  Since this function is only called by PKIX_PL_Initialize, which should
 *  only be called once, it is acceptable that this function is not
 *  thread-safe.
 */
PKIX_Error *
pkix_pl_InfoAccess_RegisterSelf(void *plContext)
{
        extern pkix_ClassTable_Entry systemClasses[PKIX_NUMTYPES];
        pkix_ClassTable_Entry entry;

        PKIX_ENTER(INFOACCESS,
                "pkix_pl_InfoAccess_RegisterSelf");

        entry.description = "InfoAccess";
        entry.destructor = pkix_pl_InfoAccess_Destroy;
        entry.equalsFunction = pkix_pl_InfoAccess_Equals;
        entry.hashcodeFunction = pkix_pl_InfoAccess_Hashcode;
        entry.toStringFunction = pkix_pl_InfoAccess_ToString;
        entry.comparator = NULL;
        entry.duplicateFunction = pkix_duplicateImmutable;

        systemClasses[PKIX_INFOACCESS_TYPE] = entry;

        PKIX_RETURN(INFOACCESS);
}

/*
 * FUNCTION: pkix_pl_InfoAccess_CreateList
 * DESCRIPTION:
 *
 *  Based on data in CERTAuthInfoAccess array "nssInfoAccess", this function
 *  creates and returns a PKIX_List of PKIX_PL_InfoAccess at "pInfoAccessList".
 *
 * PARAMETERS
 *  "nssInfoAccess"
 *      The pointer array of CERTAuthInfoAccess that contains access data.
 *      May be NULL.
 *  "pInfoAccessList"
 *      Address where a list of PKIX_PL_InfoAccess is returned.
 *      Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
pkix_pl_InfoAccess_CreateList(
        CERTAuthInfoAccess **nssInfoAccess,
        PKIX_List **pInfoAccessList, /* of PKIX_PL_InfoAccess */
        void *plContext)
{
        PKIX_List *infoAccessList = NULL;
        PKIX_PL_InfoAccess *infoAccess = NULL;
        PKIX_PL_GeneralName *location = NULL;
        int i;

        PKIX_ENTER(INFOACCESS, "PKIX_PL_InfoAccess_CreateList");
        PKIX_NULLCHECK_ONE(pInfoAccessList);

        PKIX_CHECK(PKIX_List_Create(&infoAccessList, plContext),
                "PKIX_List_Create failed");

        *pInfoAccessList = infoAccessList;

        if (nssInfoAccess == NULL) {
                goto cleanup;
        }

        for (i = 0; nssInfoAccess[i] != NULL; i++) {

                if (nssInfoAccess[i]->location == NULL) {
                    continue;
                }

                PKIX_CHECK(PKIX_PL_Object_Alloc
                    (PKIX_INFOACCESS_TYPE,
                    sizeof (PKIX_PL_InfoAccess),
                    (PKIX_PL_Object **)&infoAccess,
                    plContext),
                    "Could not create InfoAccess object");

                PKIX_CHECK(pkix_pl_GeneralName_Create
                    (nssInfoAccess[i]->location, &location, plContext),
                    "PKIX_PL_GeneralName_Create failed");

                infoAccess->location = location;
                location = NULL;

                PKIX_CERT_DEBUG("\t\tCalling SECOID_FindOIDTag).\n");
                infoAccess->method = 
                    SECOID_FindOIDTag(&nssInfoAccess[i]->method);

                if (infoAccess->method == 0) {

                /* XXX
                 * This part of code is definitely hacking, need NSS decode
                 * support. We can reuse the CERT_DecodeAuthInfoAccessExtension
                 * since SIA and AIA are all the same type. However NSS need
                 * to add SIA, CaRepository, TimeStamping OID definitions and
                 * the numerical method, timeStamping and caRepository values.
                 *
                 * We assume now, since method is 0, implies the method for SIA
                 * was not decoded by CERT_DecodeAuthInfoAccessExtension()
                 * so we compare and put value in. This part should be taken
                 * out eventually if CERT_DecodeInfoAccessExtension (*renamed*)
                 * is doing the job.
                 */

                    PKIX_CERT_DEBUG("\t\tCalling PORT_Strncmp).\n");
                    if (PORT_Strncmp
                        ((char *)nssInfoAccess[i]->method.data,
                        (char *)siaTimeStampingOID,
                         nssInfoAccess[i]->method.len)
                        == 0) {
                            infoAccess->method = SEC_OID_PKIX_TIMESTAMPING;
                    } else if (PORT_Strncmp
                               ((char *)nssInfoAccess[i]->method.data,
                               (char *)siaCaRepositoryOID,
                               nssInfoAccess[i]->method.len)
                               == 0) {
                            infoAccess->method = SEC_OID_PKIX_CA_REPOSITORY;
                    }
                }

                /* Map NSS access method value into PKIX constant */
                switch(infoAccess->method) {
                    case SEC_OID_PKIX_CA_ISSUERS:
                        infoAccess->method = PKIX_INFOACCESS_CA_ISSUERS;
                        break;
                    case SEC_OID_PKIX_OCSP:
                        infoAccess->method = PKIX_INFOACCESS_OCSP;
                        break;
                    case SEC_OID_PKIX_TIMESTAMPING:
                        infoAccess->method = PKIX_INFOACCESS_TIMESTAMPING;
                        break;
                    case SEC_OID_PKIX_CA_REPOSITORY:
                        infoAccess->method = PKIX_INFOACCESS_CA_REPOSITORY;
                        break;
                   default:
                        break;
                }

                PKIX_CHECK(PKIX_List_AppendItem
                            (infoAccessList,
                            (PKIX_PL_Object *)infoAccess,
                            plContext),
                            "PKIX_List_AppendItem failed");
                PKIX_DECREF(infoAccess);
        }

        *pInfoAccessList = infoAccessList;

cleanup:

        PKIX_DECREF(infoAccess);
        PKIX_DECREF(location);

        PKIX_RETURN(INFOACCESS);
}

/* --Public-Functions------------------------------------------------------- */

/*
 * FUNCTION: PKIX_PL_InfoAccess_GetMethod (see comments in pkix_pl_pki.h)
 */
PKIX_Error *
PKIX_PL_InfoAccess_GetMethod(
        PKIX_PL_InfoAccess *infoAccess,
        PKIX_UInt32 *pMethod,
        void *plContext)
{
        PKIX_ENTER(INFOACCESS, "PKIX_PL_InfoAccess_GetMethod");
        PKIX_NULLCHECK_TWO(infoAccess, pMethod);

        *pMethod = infoAccess->method;

        PKIX_RETURN(INFOACCESS);
}

/*
 * FUNCTION: PKIX_PL_InfoAccess_GetLocation (see comments in pkix_pl_pki.h)
 */
PKIX_Error *
PKIX_PL_InfoAccess_GetLocation(
        PKIX_PL_InfoAccess *infoAccess,
        PKIX_PL_GeneralName **pLocation,
        void *plContext)
{
        PKIX_ENTER(INFOACCESS, "PKIX_PL_InfoAccess_GetLocation");
        PKIX_NULLCHECK_TWO(infoAccess, pLocation);

        PKIX_INCREF(infoAccess->location);

        *pLocation = infoAccess->location;

cleanup:

        PKIX_RETURN(INFOACCESS);
}
