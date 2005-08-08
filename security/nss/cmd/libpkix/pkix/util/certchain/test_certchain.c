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
 * test_certchain.c
 *
 * Test CertChain Type
 *
 */

#include "testutil.h"
#include "testutil_nss.h"

void *plContext = NULL;

void createCertChains(
        char *goodInput,
        char *diffInput,
        PKIX_CertChain **goodObject,
        PKIX_CertChain **equalObject,
        PKIX_CertChain **diffObject)
{
        subTest("PKIX_CertChain_Create <goodObject>");
        *goodObject = createCertChain(goodInput, diffInput, plContext);

        subTest("PKIX_CertChain_Create <equalObject>");
        *equalObject = createCertChain(goodInput, diffInput, plContext);

        subTest("PKIX_CertChain_Create <diffObject>");
        *diffObject = createCertChain(diffInput, goodInput, plContext);

}

static void
testDestroy(void *goodObject, void *equalObject, void *diffObject)
{
        PKIX_TEST_STD_VARS();

        subTest("PKIX_CertChain_Destroy");

        PKIX_TEST_DECREF_BC(goodObject);
        PKIX_TEST_DECREF_BC(equalObject);
        PKIX_TEST_DECREF_BC(diffObject);

cleanup:

        PKIX_TEST_RETURN();

}

void testGetCertificates(
        PKIX_CertChain *goodObject,
        PKIX_CertChain *equalObject,
        PKIX_CertChain *diffObject)
{
        PKIX_List *goodList = NULL;
        PKIX_List *equalList = NULL;
        PKIX_List *diffList = NULL;

        PKIX_TEST_STD_VARS();

        subTest("PKIX_CertChain_GetCertificates");

        PKIX_TEST_EXPECT_NO_ERROR(PKIX_CertChain_GetCertificates
                                    (goodObject, &goodList, plContext));

        PKIX_TEST_EXPECT_NO_ERROR(PKIX_CertChain_GetCertificates
                                    (equalObject, &equalList, plContext));

        PKIX_TEST_EXPECT_NO_ERROR(PKIX_CertChain_GetCertificates
                                    (diffObject, &diffList, plContext));

cleanup:

        PKIX_TEST_DECREF_AC(goodList);
        PKIX_TEST_DECREF_AC(equalList);
        PKIX_TEST_DECREF_AC(diffList);
        PKIX_TEST_RETURN();

}

int main(int argc, char *argv[]) {

        PKIX_CertChain *goodObject = NULL;
        PKIX_CertChain *equalObject = NULL;
        PKIX_CertChain *diffObject = NULL;
        PKIX_UInt32 actualMinorVersion;

        PKIX_UInt32 j = 0;
        char *goodInput = "../../certs/yassir2yassir";
        char *diffInput = "../../certs/yassir2bcn";

        char *expectedAscii =
                "([\n"
                "\tVersion:         v3\n"
                "\tSerialNumber:    37bc65af\n"
                "\tIssuer:          CN=yassir,OU=bcn,OU=east,O=sun,C=us\n"
                "\tSubject:         CN=yassir,OU=bcn,OU=east,O=sun,C=us\n"
                "\tValidity: [From: Thu Aug 19 16:14:39 1999\n"
                "\t           To:   Fri Aug 18 16:14:39 2000]\n"
                "\tSubjectAltNames: (null)\n"
                "\tAuthorityKeyId:  (null)\n"
                "\tSubjectKeyId:    (null)\n"
                "\tSubjPubKeyAlgId: ANSI X9.57 DSA Signature\n"
                "\tCritExtOIDs:     (2.5.29.15, 2.5.29.19)\n"
                "\tExtKeyUsages:    (null)\n"
                "\tBasicConstraint: CA(0)\n"
                "\tCertPolicyInfo:  (null)\n"
                "\tPolicyMappings:  (null)\n"
                "\tExplicitPolicy:  -1\n"
                "\tInhibitMapping:  -1\n"
                "\tInhibitAnyPolicy:-1\n"
                "\tNameConstraints: (null)\n"
                "]\n"
                ", [\n"
                "\tVersion:         v3\n"
                "\tSerialNumber:    37bc66ec\n"
                "\tIssuer:          CN=yassir,OU=bcn,OU=east,O=sun,C=us\n"
                "\tSubject:         OU=bcn,OU=east,O=sun,C=us\n"
                "\tValidity: [From: Thu Aug 19 16:19:56 1999\n"
                "\t           To:   Fri Aug 18 16:19:56 2000]\n"
                "\tSubjectAltNames: (null)\n"
                "\tAuthorityKeyId:  (null)\n"
                "\tSubjectKeyId:    (null)\n"
                "\tSubjPubKeyAlgId: ANSI X9.57 DSA Signature\n"
                "\tCritExtOIDs:     (2.5.29.15, 2.5.29.19)\n"
                "\tExtKeyUsages:    (null)\n"
                "\tBasicConstraint: CA(0)\n"
                "\tCertPolicyInfo:  (null)\n"
                "\tPolicyMappings:  (null)\n"
                "\tExplicitPolicy:  -1\n"
                "\tInhibitMapping:  -1\n"
                "\tInhibitAnyPolicy:-1\n"
                "\tNameConstraints: (null)\n"
                "]\n"
                ")";

        PKIX_TEST_STD_VARS();

        startTests("CertChain");

        PKIX_TEST_EXPECT_NO_ERROR(PKIX_Initialize
                                    (PKIX_MAJOR_VERSION,
                                    PKIX_MINOR_VERSION,
                                    PKIX_MINOR_VERSION,
                                    &actualMinorVersion,
                                    plContext));

        PKIX_TEST_NSSCONTEXT_SETUP(0x10, argv[1], NULL, &plContext);

        createCertChains
                (goodInput, diffInput, &goodObject, &equalObject, &diffObject);

        PKIX_TEST_EQ_HASH_TOSTR_DUP
                (goodObject,
                equalObject,
                diffObject,
                expectedAscii,
                CertChain,
                PKIX_TRUE);

        testGetCertificates(goodObject, equalObject, diffObject);

        testDestroy(goodObject, equalObject, diffObject);

cleanup:

        PKIX_Shutdown(plContext);

        PKIX_TEST_RETURN();

        endTests("CertChain");

        return (0);
}
