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
 * pkix_pl_nsscontext.c
 *
 * NSSContext Function Definitions
 *
 */


#include "pkix_pl_nsscontext.h"

/* --Public-NSSContext-Functions--------------------------- */

/*
 * FUNCTION: PKIX_PL_NssContext_Create
 * (see comments in pkix_samples_modules.h)
 */
PKIX_Error *
PKIX_PL_NssContext_Create(
        PKIX_UInt32 certificateUsage,
        PKIX_Boolean useNssArena,
        void **pNssContext)
{
        PKIX_PL_NssContext *context = NULL;
        PRArenaPool *arena = NULL;
        void *plContext = NULL;

        PKIX_ENTER(CONTEXT, "PKIX_PL_NssContext_Create");
        PKIX_NULLCHECK_ONE(pNssContext);

        PKIX_CHECK(PKIX_PL_Malloc
                   (sizeof(PKIX_PL_NssContext), (void **)&context, NULL),
                   "PKIX_PL_Malloc failed");

        if (useNssArena == PKIX_TRUE) {
                PKIX_CONTEXT_DEBUG("\t\tCalling PORT_NewArena\n");
                arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
        }
        
        context->arena = arena;
        context->certificateUsage = (SECCertificateUsage)certificateUsage;

        *pNssContext = context;

cleanup:

        PKIX_RETURN(CONTEXT);
}


/*
 * FUNCTION: PKIX_PL_NssContext_Destroy
 * (see comments in pkix_samples_modules.h)
 */
PKIX_Error *
PKIX_PL_NssContext_Destroy(
        void *nssContext)
{
        void *plContext = NULL;
        PKIX_PL_NssContext *context = NULL;

        PKIX_ENTER(CONTEXT, "PKIX_PL_NssContext_Destroy");
        PKIX_NULLCHECK_ONE(nssContext);

        context = (PKIX_PL_NssContext*)nssContext;

        if (context->arena != NULL) {
                PKIX_CONTEXT_DEBUG("\t\tCalling PORT_FreeArena\n");
                PORT_FreeArena(context->arena, PKIX_FALSE);
        }

        PKIX_PL_Free(nssContext, NULL);

cleanup:

        PKIX_RETURN(CONTEXT);
}
