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
 * testutil_nss.h
 *
 * NSS-specific utility functions for handling test errors
 *
 */

#ifndef _TESTUTIL_NSS_H
#define _TESTUTIL_NSS_H

#include "pkix_tools.h"
#include "plstr.h"
#include "prprf.h"
#include "prlong.h"
#include "secutil.h"
#include <stdio.h>
#include <ctype.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__STDC__)

#include "pkix_pl_generalname.h"

/* see source file for function documentation */

PKIX_PL_Cert *
createCert(
        char *certFileName,
        void *plContext);

PKIX_PL_CRL *
createCRL(
        char *inFileName,
        void *plContext);

PKIX_TrustAnchor *
createTrustAnchor(
        char *certFileName,
        PKIX_Boolean useCert,
        void *plContext);

PKIX_CertChain *
createCertChain(
        char *firstCertFileName,
        char *secondCertFileName,
        void *plContext);

PKIX_CertChain *
createCertChainPlus(
        char *certNames[],
        PKIX_PL_Cert *certs[],
        PKIX_UInt32 numCerts,
        void *plContext);

PKIX_PL_Date *
createDate(
        char *asciiDate,
        void *plContext);


PKIX_ProcessingParams *
createProcessingParams(
        char *firstAnchorFileName,
        char *secondAnchorFileName,
        char *dateAscii,
        PKIX_Boolean isCrlEnabled,
        void *plContext);

PKIX_ValidateParams *
createValidateParams(
        char *firstAnchorFileName,
        char *secondAnchorFileName,
        char *dateAscii,
        PKIX_List *initialPolicies, /* List of PKIX_PL_OID */
        PKIX_Boolean initialPolicyMappingInhibit,
        PKIX_Boolean initialAnyPolicyInhibit,
        PKIX_Boolean initialExplicitPolicy,
        PKIX_Boolean isCrlEnabled,
        PKIX_CertChain *chain,
        void *plContext);

PKIX_BuildParams *
createBuildParams(
        char *firstAnchorFileName,
        char *secondAnchorFileName,
        char *dateAscii,
        PKIX_List *initialPolicies, /* List of PKIX_PL_OID */
        PKIX_Boolean isCrlEnabled,
        void *plContext);

PKIX_ValidateResult *
createValidateResult(
        char *anchorFileName,
        char *pubKeyCertFileName,
        void *plContext);

PKIX_BuildResult *
createBuildResult(
        char *anchorFileName,
        char *pubKeyCertFileName,
        char *firstChainCertFileName,
        char *secondChainCertFileName,
        void *plContext);

PKIX_PL_GeneralName *
createGeneralName(
        PKIX_UInt32 nameType,
        char *asciiName,
        void *plContext);

#else /* __STDC__ */

#error No function declarations for non-ISO C yet

#endif /* __STDC__ */

#ifdef __cplusplus
}
#endif

#endif /* TESTUTIL_NSS_H */
