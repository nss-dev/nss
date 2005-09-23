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
 * pkix_build.h
 *
 * Header file for buildChain function
 *
 */

#ifndef _PKIX_BUILD_H
#define _PKIX_BUILD_H
#include "pkix_tools.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct PKIX_ForwardBuilderStateStruct PKIX_ForwardBuilderState;

typedef enum {
	BUILD_INITIAL,
	BUILD_IOPENDING,
	BUILD_COLLECTINGCERTS,
	BUILD_CHAINBUILDING
} BuildStatus;

typedef struct BuildConstantsStruct BuildConstants;

struct BuildConstantsStruct {
        PKIX_UInt32 numAnchors;
        PKIX_UInt32 numCertStores;
        PKIX_ProcessingParams *procParams;
        PKIX_PL_Date *testDate;
        PKIX_PL_Cert *targetCert;
        PKIX_PL_PublicKey *targetPubKey;
        PKIX_List *certStores;
        PKIX_List *anchors;
        PKIX_List *userCheckers;
        PKIX_CertChainChecker *crlChecker;
};

struct PKIX_ForwardBuilderStateStruct{
	BuildStatus status;
        PKIX_Int32 traversedCACerts;
        PKIX_UInt32 certStoreIndex;
        PKIX_UInt32 numCerts;
        PKIX_UInt32 certIndex;
        PKIX_Boolean dsaParamsNeeded;
        PKIX_Boolean revCheckDelayed;
	PKIX_Boolean canBeCached;
	PKIX_PL_Date *validityDate;
        PKIX_PL_Cert *prevCert;
	PKIX_PL_Cert *candidateCert;
        PKIX_List *traversedSubjNames;
	PKIX_List *trustChain;
	PKIX_List *candidateCerts;
	PKIX_CertSelector *certSel;
	PKIX_ForwardBuilderState *parentState;
};

/* --Private-Functions-------------------------------------------- */

PKIX_Error *
pkix_ForwardBuilderState_RegisterSelf(void *plContext);

#ifdef __cplusplus
}
#endif

#endif /* _PKIX_BUILD_H */
