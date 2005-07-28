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
 * pkix_pl_lifecycle.c
 *
 * Lifecycle Functions for the PKIX PL library.
 *
 */

#include "pkix_pl_lifecycle.h"

char *pkix_pl_PK11ConfigDir = NULL;
PKIX_Boolean pkix_pl_initialized = PKIX_FALSE;
pkix_ClassTable_Entry systemClasses[PKIX_NUMTYPES];
PRLock *classTableLock;

PKIX_PL_HashTable *cachedCrlSigTable = NULL;
PKIX_PL_HashTable *cachedCertSigTable = NULL;

/*
 * PKIX_PL_Initialize (see comments in pkix_pl_system.h)
 */
PKIX_Error *
PKIX_PL_Initialize(void *plContext){

        pkix_ClassTable_Entry nullEntry = {NULL};
        /* XXX currently using canned value for config dir; add to plContext */

        PKIX_ENTER(OBJECT, "PKIX_PL_Initialize");

        /*
         * This function can only be called once. If it has already been
         * called, we return a statically allocated error. Our technique works
         * most of the time, but may not work if multiple threads call this
         * function simultaneously. However, the function's documentation
         * makes it clear that this is prohibited, so it's not our
         * responsibility.
         */

        if (pkix_pl_initialized) return (PKIX_ALLOC_ERROR);


        /*  Initialize NSPR and NSS.  */
        PR_Init(PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 1);

        /* if using databases, use NSS_Init and not NSS_NoDB_Init */
        if (pkix_pl_PK11ConfigDir) {
                if (NSS_Init(pkix_pl_PK11ConfigDir) != SECSuccess) {
                        return (PKIX_ALLOC_ERROR);
                }
        } else {
                if (NSS_NoDB_Init(NULL) != 0){
                        return (PKIX_ALLOC_ERROR);
                }
        }

        PKIX_OBJECT_DEBUG("\tCalling PR_NewLock).\n");
        classTableLock = PR_NewLock();
        if (classTableLock == NULL) return (PKIX_ALLOC_ERROR);

        /* we don't need to register OBJECT */
        systemClasses[PKIX_OBJECT_TYPE] = nullEntry;

        /*
         * Register Error and String, since they will be needed if
         * there is a problem in registering any other type.
         */
        pkix_Error_RegisterSelf(plContext);
        (void) pkix_pl_String_RegisterSelf(plContext);


        /*
         * We register all other system types
         * (They don't need to be in order, but it's
         * easier to keep track of what types are registered
         * if we register them in the same order as their
         * numbers, defined in pkixt.h.
         */
        (void) pkix_pl_BigInt_RegisterSelf(plContext);
        (void) pkix_pl_ByteArray_RegisterSelf(plContext);
        /* already registered! pkix_Error_RegisterSelf(plContext); */
        (void) pkix_pl_HashTable_RegisterSelf(plContext);
        pkix_List_RegisterSelf(plContext);
        /* pkix_pl_Logger_RegisterSelf(plContext); */
        (void) pkix_pl_Mutex_RegisterSelf(plContext);
        (void) pkix_pl_OID_RegisterSelf(plContext);
        (void) pkix_pl_RWLock_RegisterSelf(plContext);
        /* already registered! pkix_pl_String_RegisterSelf(plContext); */

        pkix_pl_CertBasicConstraints_RegisterSelf(plContext);
        pkix_pl_Cert_RegisterSelf(plContext);
        pkix_CertChain_RegisterSelf(plContext);
        pkix_pl_CRL_RegisterSelf(plContext);
        pkix_pl_CRLEntry_RegisterSelf(plContext);
        pkix_pl_Date_RegisterSelf(plContext);
        pkix_pl_GeneralName_RegisterSelf(plContext);
        pkix_pl_CertNameConstraints_RegisterSelf(plContext);
        pkix_pl_PublicKey_RegisterSelf(plContext);
        pkix_pl_CollectionCertStoreContext_RegisterSelf(plContext);
        pkix_TrustAnchor_RegisterSelf(plContext);

        pkix_pl_X500Name_RegisterSelf(plContext);
        pkix_ProcessingParams_RegisterSelf(plContext);
        pkix_ValidateParams_RegisterSelf(plContext);
        pkix_ValidateResult_RegisterSelf(plContext);
        pkix_CertStore_RegisterSelf(plContext);
        pkix_CertChainChecker_RegisterSelf(plContext);
        pkix_RevocationChecker_RegisterSelf(plContext);
        pkix_CertSelector_RegisterSelf(plContext);

        pkix_ComCertSelParams_RegisterSelf(plContext);
        pkix_CRLSelector_RegisterSelf(plContext);
        pkix_ComCRLSelParams_RegisterSelf(plContext);
        pkix_pl_CertPolicyInfo_RegisterSelf(plContext);
        pkix_pl_CertPolicyQualifier_RegisterSelf(plContext);
        pkix_pl_CertPolicyMap_RegisterSelf(plContext);
        pkix_PolicyNode_RegisterSelf(plContext);
        pkix_TargetCertCheckerState_RegisterSelf(plContext);
        pkix_BasicConstraintsCheckerState_RegisterSelf(plContext);
        pkix_PolicyCheckerState_RegisterSelf(plContext);
        pkix_DefaultCRLCheckerState_RegisterSelf(plContext);
        pkix_SignatureCheckerState_RegisterSelf(plContext);
        pkix_BuildResult_RegisterSelf(plContext);
        pkix_BuildParams_RegisterSelf(plContext);
        pkix_ForwardBuilderState_RegisterSelf(plContext);
        pkix_NameConstraintsCheckerState_RegisterSelf(plContext);


        pkix_pl_initialized = PKIX_TRUE;

        PKIX_CHECK(PKIX_PL_HashTable_Create
                    (32,
                    &cachedCertSigTable,
                    plContext),
                    "PKIX_PL_HashTable_Create failed");

        PKIX_CHECK(PKIX_PL_HashTable_Create
                    (32,
                    &cachedCrlSigTable,
                    plContext),
                    "PKIX_PL_HashTable_Create failed");

cleanup:

        PKIX_RETURN(OBJECT);
}

/*
 * PKIX_PL_Shutdown (see comments in pkix_pl_system.h)
 */
PKIX_Error *
PKIX_PL_Shutdown(void *plContext)
{
        PKIX_UInt32 i = 0;

        PKIX_ENTER(OBJECT, "PKIX_PL_Shutdown");

        PKIX_DECREF(cachedCertSigTable);
        PKIX_DECREF(cachedCrlSigTable);

        if (!pkix_pl_initialized) return (PKIX_ALLOC_ERROR);

        NSS_Shutdown();

        pkix_pl_initialized = PKIX_FALSE;

cleanup:

        PKIX_RETURN(OBJECT);

}
