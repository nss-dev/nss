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
 * This file defines the public API for libpkix. These are the top-level
 * functions in the library. They perform the primary operations of this
 * library: building and validating chains of X.509 certificates.
 *
 */

#ifndef _PKIX_H
#define _PKIX_H

#include "pkixt.h"
#include "pkix_util.h"
#include "pkix_params.h"
#include "pkix_results.h"
#include "pkix_certstore.h"
#include "pkix_certsel.h"
#include "pkix_crlsel.h"
#include "pkix_checker.h"
#include "pkix_revchecker.h"
#include "pkix_pl_system.h"
#include "pkix_pl_pki.h"
#include "pkix_sample_modules.h"

#pragma ident "@(#)pkix.h       1.5     04/06/29 SMI"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__STDC__)

/* General
 *
 * Please refer to the libpkix Programmer's Guide for detailed information
 * about how to use the libpkix library. Certain key warnings and notices from
 * that document are repeated here for emphasis.
 *
 * All identifiers in this file (and all public identifiers defined in
 * libpkix) begin with "PKIX_". Private identifiers only intended for use
 * within the library begin with "pkix_".
 *
 * A function returns NULL upon success, and a PKIX_Error pointer upon failure.
 *
 * Unless otherwise noted, for all accessor (gettor) functions that return a
 * PKIX_PL_Object pointer, callers should assume that this pointer refers to a
 * shared object. Therefore, the caller should treat this shared object as
 * read-only and should not modify this shared object. When done using the
 * shared object, the caller should release the reference to the object by
 * using the PKIX_PL_Object_DecRef function.
 *
 * While a function is executing, if its arguments (or anything referred to by
 * its arguments) are modified, free'd, or destroyed, the function's behavior
 * is undefined.
 *
 */

/*
 * FUNCTION: PKIX_Initialize
 * DESCRIPTION:
 *
 * No PKIX_* types and functions should be used before this function is called
 * and returns successfully. This function should only be called once. If it
 * is called more than once, the behavior is undefined.
 *
 * This function initializes data structures critical to the operation of
 * libpkix. It also ensures that the API version (major.minor) desired by the
 * caller (the "desiredMajorVersion", "minDesiredMinorVersion", and
 * "maxDesiredMinorVersion") is compatible with the API version supported by
 * the library. As such, the library must support the "desiredMajorVersion"
 * of the API and must support a minor version that falls between
 * "minDesiredMinorVersion" and "maxDesiredMinorVersion", inclusive. If
 * compatibility exists, the function returns NULL and stores the library's
 * actual minor version at "pActualMinorVersion" (which may be greater than
 * "desiredMinorVersion"). If no compatibility exists, the function returns a
 * PKIX_Error pointer. If the caller wishes to specify that the largest
 * minor version available should be used, then maxDesiredMinorVersion should
 * be set to the macro PKIX_MAX_MINOR_VERSION (defined in pkixt.h).
 *
 * PARAMETERS:
 *  "desiredMajorVersion"
 *      The major version of the libpkix API the application wishes to use.
 *  "minDesiredMinorVersion"
 *      The minimum minor version of the libpkix API the application wishes
 *      to use.
 *  "maxDesiredMinorVersion"
 *      The maximum minor version of the libpkix API the application wishes
 *      to use.
 *  "pActualMinorVersion"
 *      Address where PKIX_UInt32 will be stored. Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Not Thread Safe
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns an Initialize Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
PKIX_Initialize(
        PKIX_UInt32 desiredMajorVersion,
        PKIX_UInt32 minDesiredMinorVersion,
        PKIX_UInt32 maxDesiredMinorVersion,
        PKIX_UInt32 *pActualMinorVersion,
        void *plContext);

/*
 * FUNCTION: PKIX_Shutdown
 * DESCRIPTION:
 *
 *  This function deallocates any memory used by libpkix and shuts down any
 *  ongoing operations. This function should only be called once. If it is
 *  called more than once, the behavior is undefined.
 *
 *  No PKIX_* types and functions should be used after this function is called
 *  and returns successfully.
 * PARAMETERS:
 *  "plContext" - Platform-specific context pointer.
 * THREAD SAFETY:
 *  Not Thread Safe
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
PKIX_Shutdown(void *plContext);

/*
 * FUNCTION: PKIX_ValidateChain
 * DESCRIPTION:
 *
 *  This function attempts to validate the CertChain that has been set in the
 *  ValidateParams pointed to by "params" using an RFC 3280-compliant
 *  algorithm. If successful, this function returns NULL and stores the
 *  ValidateResult at "pResult", which holds additional information, such as
 *  the policy tree and the target's public key. If unsuccessful, an Error is
 *  returned.
 *
 * PARAMETERS:
 *  "params"
 *      Address of ValidateParams used to validate CertChain. Must be non-NULL.
 *  "pResult"
 *      Address where object pointer will be stored. Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (See Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a Validate Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
PKIX_ValidateChain(
        PKIX_ValidateParams *params,
        PKIX_ValidateResult **pResult,
        void *plContext);

/*
 * FUNCTION: PKIX_BuildChain
 * DESCRIPTION:
 *
 *  This function attempts to build and validate a CertChain according to the
 *  parameters set in the BuildParams pointed to by "params" using an RFC
 *  3280-compliant validation algorithm. If successful, this function returns
 *  NULL and stores the BuildResult at "pResult", which holds the built
 *  CertChain, as well as additional information, such as the policy tree and
 *  the target's public key. If unsuccessful, an Error is returned.
 *
 * PARAMETERS:
 *  "params"
 *      Address of BuildParams used to build and validate CertChain.
 *      Must be non-NULL.
 *  "pResult"
 *      Address where object pointer will be stored. Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (See Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a Build Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
PKIX_BuildChain(
        PKIX_BuildParams *params,
        PKIX_BuildResult **pResult,
        void *plContext);

#else /* __STDC__ */

#error No function declarations for non-ISO C yet

#endif /* __STDC__ */

#ifdef __cplusplus
}
#endif

#endif /* _PKIX_H */
