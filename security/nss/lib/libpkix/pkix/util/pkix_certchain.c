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
 * pkix_certchain.c
 *
 * CertChain Object Functions
 *
 */

#include "pkix_certchain.h"

/* --Private-Functions-------------------------------------------- */

/*
 * FUNCTION: pkix_CertChain_Destroy
 * (see comments for PKIX_PL_DestructorCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_CertChain_Destroy(
        PKIX_PL_Object *object,
        void *plContext)
{
        PKIX_CertChain *chain = NULL;

        PKIX_ENTER(CERTCHAIN, "pkix_CertChain_Destroy");
        PKIX_NULLCHECK_ONE(object);

        /* Check that this object is a cert chain */
        PKIX_CHECK(pkix_CheckType(object, PKIX_CERTCHAIN_TYPE, plContext),
                    "Object is not a CertChain");

        chain = (PKIX_CertChain *)object;

        PKIX_DECREF(chain->certs);

cleanup:

        PKIX_RETURN(CERTCHAIN);
}

/*
 * FUNCTION: pkix_CertChain_Equals
 * (see comments for PKIX_PL_EqualsCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_CertChain_Equals(
        PKIX_PL_Object *first,
        PKIX_PL_Object *second,
        PKIX_Boolean *pResult,
        void *plContext)
{
        PKIX_UInt32 secondType;
        PKIX_Boolean cmpResult;
        PKIX_CertChain *firstChain = NULL;
        PKIX_CertChain *secondChain = NULL;
        PKIX_List *firstList = NULL;
        PKIX_List *secondList = NULL;

        PKIX_ENTER(CERTCHAIN, "pkix_CertChain_Equals");
        PKIX_NULLCHECK_THREE(first, second, pResult);

        PKIX_CHECK(pkix_CheckType(first, PKIX_CERTCHAIN_TYPE, plContext),
                    "First Argument is not a CertChain");

        PKIX_CHECK(PKIX_PL_Object_GetType(second, &secondType, plContext),
                    "Could not get type of second argument");

        *pResult = PKIX_FALSE;

        if (secondType != PKIX_CERTCHAIN_TYPE) goto cleanup;

        firstChain = (PKIX_CertChain *)first;
        secondChain = (PKIX_CertChain *)second;

        PKIX_CHECK(PKIX_PL_Object_Equals
                    ((PKIX_PL_Object *)firstChain->certs,
                    (PKIX_PL_Object *)secondChain->certs,
                    &cmpResult,
                    plContext),
                    "PKIX_PL_Object_Equals failed");

        *pResult = cmpResult;

cleanup:

        PKIX_DECREF(firstList);
        PKIX_DECREF(secondList);

        PKIX_RETURN(CERTCHAIN);
}

/*
 * FUNCTION: pkix_CertChain_Hashcode
 * (see comments for PKIX_PL_HashcodeCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_CertChain_Hashcode(
        PKIX_PL_Object *object,
        PKIX_UInt32 *pHashcode,
        void *plContext)
{
        PKIX_CertChain *chain = NULL;
        PKIX_List *certList = NULL;
        PKIX_PL_Object *element = NULL;
        PKIX_UInt32 hash = 0;
        PKIX_UInt32 tempHash = 0;

        PKIX_ENTER(CERTCHAIN, "pkix_CertChain_Hashcode");
        PKIX_NULLCHECK_TWO(object, pHashcode);

        PKIX_CHECK(pkix_CheckType(object, PKIX_CERTCHAIN_TYPE, plContext),
                    "Object is not a CertChain");

        chain = (PKIX_CertChain*)object;

        PKIX_CHECK(PKIX_PL_Object_Hashcode
                    ((PKIX_PL_Object *)chain->certs, &tempHash, plContext),
                    "PKIX_PL_Object_Hashcode failed");

        hash = 31 * hash + tempHash;

        *pHashcode = hash;

cleanup:

        PKIX_DECREF(certList);

        PKIX_RETURN(CERTCHAIN);
}

/*
 * FUNCTION: pkix_CertChain_ToString
 * (see comments for PKIX_PL_ToStringCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_CertChain_ToString(
        PKIX_PL_Object *object,
        PKIX_PL_String **pString,
        void *plContext)
{
        PKIX_CertChain *chain = NULL;
        PKIX_List *certList = NULL;
        PKIX_PL_String *chainString = NULL;

        PKIX_ENTER(CERTCHAIN, "pkix_CertChain_ToString");
        PKIX_NULLCHECK_TWO(object, pString);

        PKIX_CHECK(pkix_CheckType(object, PKIX_CERTCHAIN_TYPE, plContext),
                    "Object is not a CertChain");

        chain = (PKIX_CertChain*)object;

        PKIX_CHECK(PKIX_PL_Object_ToString
                    ((PKIX_PL_Object *)chain->certs, &chainString, plContext),
                    "PKIX_PL_Object_ToString failed");

        *pString = chainString;

cleanup:

        PKIX_DECREF(certList);

        PKIX_RETURN(CERTCHAIN);
}

/*
 * FUNCTION: pkix_CertChain_RegisterSelf
 * DESCRIPTION:
 *  Registers PKIX_CERTCHAIN_TYPE and its related functions with
 *  systemClasses[]
 * THREAD SAFETY:
 *  Not Thread Safe - for performance and complexity reasons
 *
 *  Since this function is only called by PKIX_PL_Initialize, which should
 *  only be called once, it is acceptable that this function is not
 *  thread-safe.
 */
PKIX_Error *
pkix_CertChain_RegisterSelf(void *plContext)
{
        extern pkix_ClassTable_Entry systemClasses[PKIX_NUMTYPES];
        pkix_ClassTable_Entry entry;

        PKIX_ENTER(CERTCHAIN, "pkix_CertChain_RegisterSelf");

        entry.description = "CertChain";
        entry.destructor = pkix_CertChain_Destroy;
        entry.equalsFunction = pkix_CertChain_Equals;
        entry.hashcodeFunction = pkix_CertChain_Hashcode;
        entry.toStringFunction = pkix_CertChain_ToString;
        entry.comparator = NULL;
        entry.duplicateFunction = pkix_duplicateImmutable;

        systemClasses[PKIX_CERTCHAIN_TYPE] = entry;

cleanup:

        PKIX_RETURN(CERTCHAIN);
}

/* --Public-Functions--------------------------------------------- */

/*
 * FUNCTION: PKIX_CertChain_Create (see comments in pkix_util.h)
 */
PKIX_Error *
PKIX_CertChain_Create(
        PKIX_List *certs,
        PKIX_CertChain **pChain,
        void *plContext)
{
        PKIX_CertChain *chain = NULL;

        PKIX_ENTER(CERTCHAIN, "PKIX_CertChain_Create");
        PKIX_NULLCHECK_TWO(pChain, certs);

        PKIX_CHECK(PKIX_PL_Object_Alloc
                    (PKIX_CERTCHAIN_TYPE,
                    sizeof (PKIX_CertChain),
                    (PKIX_PL_Object **)&chain,
                    plContext),
                    "Could not create CertChain object");


        /* initialize fields */
        PKIX_INCREF(certs);
        chain->certs = certs;

        PKIX_CHECK(PKIX_List_SetImmutable(chain->certs, plContext),
                    "PKIX_List_SetImmutable failed");

        *pChain = chain;

cleanup:

        if (PKIX_ERROR_RECEIVED){
                PKIX_DECREF(chain);
        }

        PKIX_RETURN(CERTCHAIN);
}


/*
 * FUNCTION: PKIX_CertChain_GetCertificates (see comments in pkix_util.h)
 */
PKIX_Error *
PKIX_CertChain_GetCertificates(
        PKIX_CertChain *chain,
        PKIX_List **pList,  /* list of PKIX_PL_Cert */
        void *plContext)
{
        PKIX_ENTER(CERTCHAIN, "PKIX_CertChain_GetCertificates");
        PKIX_NULLCHECK_TWO(chain, pList);

        PKIX_INCREF(chain->certs);

        *pList = chain->certs;

cleanup:

        PKIX_RETURN(CERTCHAIN);
}
