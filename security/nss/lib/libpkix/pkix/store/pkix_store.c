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
 * pkix_store.c
 *
 * CertStore Function Definitions
 *
 */

#include "pkix_store.h"

/* --CertStore-Private-Functions----------------------------------------- */

/*
 * FUNCTION: pkix_CertStore_Destroy
 * (see comments for PKIX_PL_DestructorCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_CertStore_Destroy(
        PKIX_PL_Object *object,
        void *plContext)
{
        PKIX_CertStore *certStore = NULL;

        PKIX_ENTER(CERTSTORE, "pkix_CertStore_Destroy");
        PKIX_NULLCHECK_ONE(object);

        /* Check that this object is a CertStore object */
        PKIX_CHECK(pkix_CheckType(object, PKIX_CERTSTORE_TYPE, plContext),
                    "Object is not a CertStore object");

        certStore = (PKIX_CertStore *)object;

        certStore->certCallback = NULL;
        certStore->crlCallback = NULL;

        PKIX_DECREF(certStore->certStoreContext);

cleanup:

        PKIX_RETURN(CERTSTORE);
}

/*
 * FUNCTION: pkix_CertStore_RegisterSelf
 * DESCRIPTION:
 *  Registers PKIX_CERTSTORE_TYPE and its related functions with
 *  systemClasses[]
 * THREAD SAFETY:
 *  Not Thread Safe - for performance and complexity reasons
 *
 *  Since this function is only called by PKIX_PL_Initialize, which should
 *  only be called once, it is acceptable that this function is not
 *  thread-safe.
 */
PKIX_Error *
pkix_CertStore_RegisterSelf(void *plContext)
{
        extern pkix_ClassTable_Entry systemClasses[PKIX_NUMTYPES];
        pkix_ClassTable_Entry entry;

        PKIX_ENTER(CERTSTORE, "pkix_CertStore_RegisterSelf");

        entry.description = "CertStore";
        entry.destructor = pkix_CertStore_Destroy;
        entry.equalsFunction = NULL;
        entry.hashcodeFunction = NULL;
        entry.toStringFunction = NULL;
        entry.comparator = NULL;
        entry.duplicateFunction = pkix_duplicateImmutable;

        systemClasses[PKIX_CERTSTORE_TYPE] = entry;

cleanup:

        PKIX_RETURN(CERTSTORE);
}

/* --CertStore-Public-Functions------------------------------------------ */

/*
 * FUNCTION: PKIX_CertStore_Create (see comments in pkix_certstore.h)
 */
PKIX_Error *
PKIX_CertStore_Create(
        PKIX_CertStore_CertCallback certCallback,
        PKIX_CertStore_CRLCallback crlCallback,
        PKIX_PL_Object *certStoreContext,
        PKIX_CertStore **pStore,
        void *plContext)
{
        PKIX_CertStore *certStore = NULL;
        PKIX_CRLSelector *crlSelector = NULL;

        PKIX_ENTER(CERTSTORE, "PKIX_CertStore_Create");
        PKIX_NULLCHECK_THREE(certCallback, crlCallback, pStore);

        PKIX_CHECK(PKIX_PL_Object_Alloc
                    (PKIX_CERTSTORE_TYPE,
                    sizeof (PKIX_CertStore),
                    (PKIX_PL_Object **)&certStore,
                    plContext),
                    "Could not create CertStore object");

        certStore->certCallback = certCallback;
        certStore->crlCallback = crlCallback;

        PKIX_INCREF(certStoreContext);
        certStore->certStoreContext = certStoreContext;

        *pStore = certStore;

cleanup:

        PKIX_RETURN(CERTSTORE);
}

/*
 * FUNCTION: PKIX_CertStore_GetCertCallback (see comments in pkix_certstore.h)
 */
PKIX_Error *
PKIX_CertStore_GetCertCallback(
        PKIX_CertStore *store,
        PKIX_CertStore_CertCallback *pCallback,
        void *plContext)
{
        PKIX_ENTER(CERTSTORE, "PKIX_CertStore_GetCertCallback");
        PKIX_NULLCHECK_TWO(store, pCallback);

        *pCallback = store->certCallback;

cleanup:

        PKIX_RETURN(CERTSTORE);
}

/*
 * FUNCTION: PKIX_CertStore_GetCRLCallback (see comments in pkix_certstore.h)
 */
PKIX_Error *
PKIX_CertStore_GetCRLCallback(
        PKIX_CertStore *store,
        PKIX_CertStore_CRLCallback *pCallback,
        void *plContext)
{
        PKIX_ENTER(CERTSTORE, "PKIX_CertStore_GetCRLCallback");
        PKIX_NULLCHECK_TWO(store, pCallback);

        *pCallback = store->crlCallback;

cleanup:

        PKIX_RETURN(CERTSTORE);
}

/*
 * FUNCTION: PKIX_CertStore_GetCertStoreContext
 * (see comments in pkix_certstore.h)
 */
PKIX_Error *
PKIX_CertStore_GetCertStoreContext(
        PKIX_CertStore *store,
        PKIX_PL_Object **pCertStoreContext,
        void *plContext)
{
        PKIX_ENTER(CERTSTORE, "PKIX_CertStore_GetCertStoreContext");
        PKIX_NULLCHECK_TWO(store, pCertStoreContext);

        PKIX_INCREF(store->certStoreContext);
        *pCertStoreContext = store->certStoreContext;

cleanup:

        PKIX_RETURN(CERTSTORE);
}
