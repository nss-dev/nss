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
 * This file defines functions associated with the PKIX_CertStore type.
 *
 */


#ifndef _PKIX_CERTSTORE_H
#define _PKIX_CERTSTORE_H

#include "pkixt.h"

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

/* PKIX_CertStore
 *
 * A PKIX_CertStore provides a standard way for the caller to retrieve
 * certificates and CRLs from a particular repository (or "store") of
 * certificates and CRLs, including LDAP directories, flat files, local
 * databases, etc. The CertCallback allows custom certificate retrieval logic
 * to be used while the CRLCallback allows custom CRL retrieval logic to be
 * used. Additionally, a CertStore can be initialized with a certStoreContext,
 * which is where the caller can specify configuration data such as the host
 * name of an LDAP server. Note that this certStoreContext must be an
 * Object (although any object type), allowing it to be reference-counted and
 * allowing it to provide the standard Object functions (Equals, Hashcode,
 * ToString, Compare, Duplicate).
 *
 * Once the caller has created the CertStore object, the caller then specifies
 * these CertStore objects in a ProcessingParams object and passes that object
 * to PKIX_ValidateChain or PKIX_BuildChain, which uses the objects to call the
 * user's callback functions as needed during the validation or building
 * process.
 */

/*
 * FUNCTION: PKIX_CertStore_CertCallback
 * DESCRIPTION:
 *
 *  This callback function retrieves from the CertStore pointed to by "store"
 *  all the certificates that match the CertSelector pointed to by "selector".
 *  It places these Certs in a List and stores a pointer to the List at
 *  "pCerts". If no certificates are found which match the CertSelector's
 *  criteria, this function stores an empty List at "pCerts".
 *
 *  Note that the List returned by this function is immutable.
 *
 * PARAMETERS:
 *  "store"
 *      Address of CertStore from which Certs are to be retrieved.
 *      Must be non-NULL.
 *  "selector"
 *      Address of CertSelector whose criteria must be satisfied.
 *      Must be non-NULL.
 *  "pCerts"
 *      Address where object pointer will be stored. Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe
 *
 *  Multiple threads must be able to safely call this function without
 *  worrying about conflicts, even if they're operating on the same object.
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a CertStore Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
typedef PKIX_Error *
(*PKIX_CertStore_CertCallback)(
        PKIX_CertStore *store,
        PKIX_CertSelector *selector,
        PKIX_List **pCerts,  /* list of PKIX_PL_Cert */
        void *plContext);

/*
 * FUNCTION: PKIX_CertStore_CRLCallback
 * DESCRIPTION:
 *
 *  This callback function retrieves from the CertStore pointed to by "store"
 *  all the CRLs that match the CRLSelector pointed to by "selector". It
 *  places these CRLs in a List and stores a pointer to the List at "pCRLs".
 *  If no CRLs are found which match the CRLSelector's criteria, this function
 *  stores an empty List at "pCRLs".
 *
 *  Note that the List returned by this function is immutable.
 *
 * PARAMETERS:
 *  "store"
 *      Address of CertStore from which CRLs are to be retrieved.
 *      Must be non-NULL.
 *  "selector"
 *      Address of CRLSelector whose criteria must be satisfied.
 *      Must be non-NULL.
 *  "pCrls"
 *      Address where object pointer will be stored. Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe
 *
 *  Multiple threads must be able to safely call this function without
 *  worrying about conflicts, even if they're operating on the same object.
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a CertStore Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
typedef PKIX_Error *
(*PKIX_CertStore_CRLCallback)(
        PKIX_CertStore *store,
        PKIX_CRLSelector *selector,
        PKIX_List **pCrls,  /* list of PKIX_PL_CRL */
        void *plContext);

/*
 * FUNCTION: PKIX_CertStore_Create
 * DESCRIPTION:
 *
 *  Creates a new CertStore and stores it at "pStore". The new CertStore uses
 *  the CertCallback pointed to by "certCallback" and the CRLCallback pointed
 *  to by "crlCallback" as its callback functions and uses the Object pointed
 *  to by "certStoreContext" as its context . Note that this certStoreContext
 *  must be an Object (although any object type), allowing it to be
 *  reference-counted and allowing it to provide the standard Object functions
 *  (Equals, Hashcode, ToString, Compare, Duplicate). Once created, a
 *  CertStore object is immutable, although the underlying repository can
 *  change. For example, a CertStore will often be a front-end for a database
 *  or directory. The contents of that directory can change after the
 *  CertStore object is created, but the CertStore object remains immutable.
 *
 * PARAMETERS:
 *  "certCallback"
 *      The CertCallback function to be used. Must be non-NULL.
 *  "crlCallback"
 *      The CRLCallback function to be used. Must be non-NULL.
 *  "certStoreContext"
 *      Address of Object representing the CertStore's context (if any).
 *  "pStore"
 *      Address where object pointer will be stored. Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a CertStore Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
PKIX_CertStore_Create(
        PKIX_CertStore_CertCallback certCallback,
        PKIX_CertStore_CRLCallback crlCallback,
        PKIX_PL_Object *certStoreContext,
        PKIX_CertStore **pStore,
        void *plContext);

/*
 * FUNCTION: PKIX_CertStore_GetCertCallback
 * DESCRIPTION:
 *
 *  Retrieves a pointer to "store's" Cert callback function and puts it in
 *  "pCallback".
 *
 * PARAMETERS:
 *  "store"
 *      The CertStore whose Cert callback is desired. Must be non-NULL.
 *  "pCallback"
 *      Address where Cert callback function pointer will be stored.
 *      Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a CertStore Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
PKIX_CertStore_GetCertCallback(
        PKIX_CertStore *store,
        PKIX_CertStore_CertCallback *pCallback,
        void *plContext);

/*
 * FUNCTION: PKIX_CertStore_GetCRLCallback
 * DESCRIPTION:
 *
 *  Retrieves a pointer to "store's" CRL callback function and puts it in
 *  "pCallback".
 *
 * PARAMETERS:
 *  "store"
 *      The CertStore whose CRL callback is desired. Must be non-NULL.
 *  "pCallback"
 *      Address where CRL callback function pointer will be stored.
 *      Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a CertStore Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
PKIX_CertStore_GetCRLCallback(
        PKIX_CertStore *store,
        PKIX_CertStore_CRLCallback *pCallback,
        void *plContext);

/*
 * FUNCTION: PKIX_CertStore_GetCertStoreContext
 * DESCRIPTION:
 *
 *  Retrieves a pointer to the Object representing the context (if any)
 *  of the CertStore pointed to by "store" and stores it at
 *  "pCertStoreContext".
 *
 * PARAMETERS:
 *  "store"
 *      Address of CertStore whose context is to be stored. Must be non-NULL.
 *  "pCertStoreContext"
 *      Address where object pointer will be stored. Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a CertStore Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
PKIX_CertStore_GetCertStoreContext(
        PKIX_CertStore *store,
        PKIX_PL_Object **pCertStoreContext,
        void *plContext);

#else /* __STDC__ */

#error No function declarations for non-ISO C yet

#endif /* __STDC__ */

#ifdef __cplusplus
}
#endif

#endif /* _PKIX_CERTSTORE_H */
