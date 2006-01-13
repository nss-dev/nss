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
 * pkix_ocspchecker.c
 *
 * OcspChecker Object Functions
 *
 */

#include "pkix_ocspchecker.h"

/* --Private-Functions-------------------------------------------- */

/*
 * FUNCTION: pkix_OcspChecker_Destroy
 *      (see comments for PKIX_PL_DestructorCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_OcspChecker_Destroy(
        PKIX_PL_Object *object,
        void *plContext)
{
        PKIX_OcspChecker *checker = NULL;

        PKIX_ENTER(OCSPCHECKER, "pkix_OcspChecker_Destroy");
        PKIX_NULLCHECK_ONE(object);

        /* Check that this object is a ocsp checker */
        PKIX_CHECK(pkix_CheckType
                    (object, PKIX_OCSPCHECKER_TYPE, plContext),
                    "Object is not an ocsp checker");

        checker = (PKIX_OcspChecker *)object;

        /* This is not yet a ref-counted object */
        /* PKIX_DECREF(checker->httpClient); */

cleanup:

        PKIX_RETURN(OCSPCHECKER);
}

/*
 * FUNCTION: pkix_OcspChecker_Duplicate
 * (see comments for PKIX_PL_DuplicateCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_OcspChecker_Duplicate(
        PKIX_PL_Object *object,
        PKIX_PL_Object **pNewObject,
        void *plContext)
{
        PKIX_OcspChecker *checker = NULL;
        PKIX_OcspChecker *checkerDuplicate = NULL;

        PKIX_ENTER(OCSPCHECKER, "pkix_OcspChecker_Duplicate");
        PKIX_NULLCHECK_TWO(object, pNewObject);

        PKIX_CHECK(pkix_CheckType
                    (object, PKIX_OCSPCHECKER_TYPE, plContext),
                    "Object is not a cert chain checker");

        checker = (PKIX_OcspChecker *)object;

        PKIX_CHECK(PKIX_OcspChecker_Create
                    (checker->checkCallback,
                     checker->http_uri,
                    &checkerDuplicate,
                    plContext),
                    "PKIX_OcspChecker_Create failed");


        /* This is not yet a ref-counted object */
        /* PKIX_INCREF(checker->httpClient); */
        checkerDuplicate->httpClient = checker->httpClient;

        *pNewObject = (PKIX_PL_Object *)checkerDuplicate;

cleanup:

        PKIX_RETURN(OCSPCHECKER);
}

/*
 * FUNCTION: pkix_OcspChecker_RegisterSelf
 * DESCRIPTION:
 *  Registers PKIX_OCSPCHECKER_TYPE and its related functions with
 *  systemClasses[]
 * THREAD SAFETY:
 *  Not Thread Safe - for performance and complexity reasons
 *
 *  Since this function is only called by PKIX_PL_Initialize, which should
 *  only be called once, it is acceptable that this function is not
 *  thread-safe.
 */
PKIX_Error *
pkix_OcspChecker_RegisterSelf(void *plContext)
{
        extern pkix_ClassTable_Entry systemClasses[PKIX_NUMTYPES];
        pkix_ClassTable_Entry entry;

        PKIX_ENTER(OCSPCHECKER, "pkix_OcspChecker_RegisterSelf");

        entry.description = "OcspChecker";
        entry.destructor = pkix_OcspChecker_Destroy;
        entry.equalsFunction = NULL;
        entry.hashcodeFunction = NULL;
        entry.toStringFunction = NULL;
        entry.comparator = NULL;
        entry.duplicateFunction = pkix_OcspChecker_Duplicate;

        systemClasses[PKIX_OCSPCHECKER_TYPE] = entry;

        PKIX_RETURN(OCSPCHECKER);
}

/* --Public-Functions--------------------------------------------- */


/*
 * FUNCTION: PKIX_OcspChecker_Create (see comments in pkix_checker.h)
 */
PKIX_Error *
PKIX_OcspChecker_Create(
    PKIX_RevocationChecker_RevCallback callback,
    char *http_uri,
    PKIX_OcspChecker **pChecker,
    void *plContext)
{
        PKIX_OcspChecker *checker = NULL;

        PKIX_ENTER(OCSPCHECKER, "PKIX_OcspChecker_Create");
        PKIX_NULLCHECK_ONE(pChecker);

        PKIX_CHECK(PKIX_PL_Object_Alloc
                    (PKIX_OCSPCHECKER_TYPE,
                    sizeof (PKIX_OcspChecker),
                    (PKIX_PL_Object **)&checker,
                    plContext),
                    "Could not create cert chain checker object");

        /* initialize fields */
        checker->checkCallback = callback;

        checker->http_uri = http_uri;

        /* create http client */

        *pChecker = checker;

cleanup:

        PKIX_RETURN(OCSPCHECKER);

}

/*
 * FUNCTION: PKIX_OcspChecker_GetCheckCallback
 *      (see comments in pkix_checker.h)
 */
PKIX_Error *
PKIX_OcspChecker_GetRevCallback(
        PKIX_OcspChecker *checker,
        PKIX_RevocationChecker_RevCallback *pCallback,
        void *plContext)
{
        PKIX_ENTER
                (OCSPCHECKER, "PKIX_OcspChecker_GetRevCallback");
        PKIX_NULLCHECK_TWO(checker, pCallback);

        *pCallback = checker->checkCallback;

        PKIX_RETURN(OCSPCHECKER);
}
