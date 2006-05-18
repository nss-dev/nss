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
 * test_ocspchecker.c
 *
 * Test OcspChecker function
 *
 */

#include "testutil.h"
#include "testutil_nss.h"

void *plContext = NULL;

void printUsage(void){
        (void) printf("\nUSAGE:\nOcspChecker TestName [ENE|EE] "
                    "<certStoreDirectory> <trustedCert> <targetCert>\n\n");
        (void) printf
                ("Validates a chain of certificates between "
                "<trustedCert> and <targetCert>\n"
                "using the certs and CRLs in <certStoreDirectory>. "
                "If ENE is specified,\n"
                "then an Error is Not Expected. "
                "If EE is specified, an Error is Expected.\n");
}

char *createFullPathName(
        char *dirName,
        char *certFile,
        void *plContext)
{
        PKIX_UInt32 certFileLen;
        PKIX_UInt32 dirNameLen;
        char *certPathName = NULL;

        PKIX_TEST_STD_VARS();

        certFileLen = PL_strlen(certFile);
        dirNameLen = PL_strlen(dirName);

        PKIX_TEST_EXPECT_NO_ERROR(PKIX_PL_Malloc
                (dirNameLen + certFileLen + 2,
                (void **)&certPathName,
                plContext));

        PL_strcpy(certPathName, dirName);
        PL_strcat(certPathName, "/");
        PL_strcat(certPathName, certFile);
        printf("certPathName = %s\n", certPathName);

cleanup:

        PKIX_TEST_RETURN();

        return (certPathName);
}

PKIX_Error *
testDefaultCertStore(PKIX_ValidateParams *valParams, char *crlDir)
{
        PKIX_PL_String *dirString = NULL;
        PKIX_CertStore *certStore = NULL;
        PKIX_ProcessingParams *procParams = NULL;
        PKIX_PL_Date *validity = NULL; 
        PKIX_List *revCheckers = NULL;
        PKIX_OcspChecker *ocspChecker = NULL;

        PKIX_TEST_STD_VARS();

        subTest("PKIX_PL_CollectionCertStoreContext_Create");

        /* Create CollectionCertStore */

        PKIX_TEST_EXPECT_NO_ERROR(PKIX_PL_String_Create
                (PKIX_ESCASCII, crlDir, 0, &dirString, plContext));

        PKIX_TEST_EXPECT_NO_ERROR(PKIX_PL_CollectionCertStore_Create
                (dirString, &certStore, plContext));

        /* Create CertStore */

        PKIX_TEST_EXPECT_NO_ERROR(PKIX_ValidateParams_GetProcessingParams
                (valParams, &procParams, plContext));

        subTest("PKIX_ProcessingParams_AddCertStore");
        PKIX_TEST_EXPECT_NO_ERROR(PKIX_ProcessingParams_AddCertStore
                (procParams, certStore, plContext));

        subTest("PKIX_ProcessingParams_SetRevocationEnabled");

        PKIX_TEST_EXPECT_NO_ERROR(PKIX_ProcessingParams_SetRevocationEnabled
                (procParams, PKIX_FALSE, plContext));

        /* create current Date */
        PKIX_TEST_EXPECT_NO_ERROR(pkix_pl_Date_CreateFromPRTime
                (PR_Now(), &validity, plContext));

        PKIX_TEST_EXPECT_NO_ERROR(PKIX_List_Create(&revCheckers, plContext));

        /* create revChecker */
        PKIX_TEST_EXPECT_NO_ERROR(PKIX_OcspChecker_Create
                (validity,
                NULL,        /* pwArg */
                NULL,        /* Use default responder */
                &ocspChecker,
                plContext));

        PKIX_TEST_EXPECT_NO_ERROR(PKIX_List_AppendItem
                (revCheckers, (PKIX_PL_Object *)ocspChecker, plContext));

        PKIX_TEST_EXPECT_NO_ERROR(PKIX_ProcessingParams_SetRevocationCheckers
                (procParams, revCheckers, plContext));

cleanup:

        PKIX_TEST_DECREF_AC(dirString);
        PKIX_TEST_DECREF_AC(procParams);
        PKIX_TEST_DECREF_AC(certStore);
        PKIX_TEST_DECREF_AC(revCheckers);
        PKIX_TEST_DECREF_AC(ocspChecker);

        PKIX_TEST_RETURN();

        return (0);
}

int main(int argc, char *argv[]){

        PKIX_ValidateParams *valParams = NULL;
        PKIX_ValidateResult *valResult = NULL;
        PKIX_UInt32 actualMinorVersion;
        PKIX_UInt32 j = 0;
        PKIX_UInt32 k = 0;
        PKIX_UInt32 chainLength = 0;
        PKIX_Boolean testValid = PKIX_TRUE;
        PKIX_Boolean useArenas = PKIX_FALSE;
        PKIX_List *chainCerts = NULL;
        PKIX_PL_Cert *dirCert = NULL;
        char *dirCertName = NULL;
        char *anchorCertName = NULL;
        char *dirName = NULL;
        char *databaseDir = NULL;

        PKIX_TEST_STD_VARS();

        if (argc < 5) {
                printUsage();
                return (0);
        }

        startTests("OcspChecker");

        useArenas = PKIX_TEST_ARENAS_ARG(argv[1]);

        databaseDir = argv[3+j];

        /* This must precede the call to PKIX_Initialize! */
        PKIX_TEST_EXPECT_NO_ERROR(PKIX_Initialize_SetConfigDir
            (PKIX_STORE_TYPE_PK11, databaseDir, plContext));

        PKIX_TEST_EXPECT_NO_ERROR(PKIX_Initialize
                (PKIX_TRUE, /* nssInitNeeded */
                useArenas,
                PKIX_MAJOR_VERSION,
                PKIX_MINOR_VERSION,
                PKIX_MINOR_VERSION,
                &actualMinorVersion,
                &plContext));

        /* ENE = expect no error; EE = expect error */
        if (PORT_Strcmp(argv[2+j], "ENE") == 0) {
                testValid = PKIX_TRUE;
        } else if (PORT_Strcmp(argv[2+j], "EE") == 0) {
                testValid = PKIX_FALSE;
        } else {
                printUsage();
                return (0);
        }

        subTest(argv[1+j]);

        dirName = databaseDir;

        chainLength = argc - j - 5;

        PKIX_TEST_EXPECT_NO_ERROR(PKIX_List_Create(&chainCerts, plContext));

        for (k = 0; k < chainLength; k++) {

                dirCert = createCert(dirName, argv[5+k+j], plContext);

                PKIX_TEST_EXPECT_NO_ERROR
                        (PKIX_List_AppendItem
                        (chainCerts, (PKIX_PL_Object *)dirCert, plContext));

                PKIX_TEST_DECREF_BC(dirCert);
        }

        valParams = createValidateParams
                (dirName,
                argv[4+j],
                NULL,
                NULL,
                NULL,
                PKIX_FALSE,
                PKIX_FALSE,
                PKIX_FALSE,
                PKIX_FALSE,
                chainCerts,
                plContext);

        testDefaultCertStore(valParams, dirName);

        if (testValid == PKIX_TRUE) {
                PKIX_TEST_EXPECT_NO_ERROR(PKIX_ValidateChain
                        (valParams, &valResult, plContext));
        } else {
                PKIX_TEST_EXPECT_ERROR(PKIX_ValidateChain
                        (valParams, &valResult, plContext));
        }


cleanup:

        PKIX_TEST_DECREF_AC(chainCerts);
        PKIX_TEST_DECREF_AC(valParams);
        PKIX_TEST_DECREF_AC(valResult);

        PKIX_Shutdown(plContext);

        PKIX_TEST_RETURN();

        endTests("OcspChecker");

        return (0);
}
