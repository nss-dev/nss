/* 
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 * 
 * The Original Code is the Netscape security libraries.
 * 
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation.  Portions created by Netscape are 
 * Copyright (C) 1994-2000 Netscape Communications Corporation.  All
 * Rights Reserved.
 * 
 * Contributor(s):
 * 
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU General Public License Version 2 or later (the
 * "GPL"), in which case the provisions of the GPL are applicable 
 * instead of those above.  If you wish to allow use of your 
 * version of this file only under the terms of the GPL and not to
 * allow others to use your version of this file under the MPL,
 * indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by
 * the GPL.  If you do not delete the provisions above, a recipient
 * may use your version of this file under either the MPL or the
 * GPL.
 */

#ifndef PKIXM_H
#define PKIXM_H

#ifdef DEBUG
static const char PKIXM_CVS_ID[] = "@(#) $Source$ $Revision$ $Date$ $Name$";
#endif /* DEBUG */

/*
 * pkixm.h
 *
 * This file contains the private type definitions for the 
 * PKIX part-1 objects.  Mostly, this file contains the actual 
 * structure definitions for the NSSPKIX types declared in nsspkixt.h.
 */

/* XXX */
#ifndef NSSBASE_H
#include "nssbase.h"
#endif /* NSSBASE_H */

#ifndef NSSASN1_H
#include "nssasn1.h"
#endif /* NSSASN1_H */

#ifndef PKIXTM_H
#include "pkixtm.h"
#endif /* PKIXTM_H */

#ifndef PKIX_H
#include "pkix.h"
#endif /* PKIX_H */

PR_BEGIN_EXTERN_C

NSS_EXTERN void
nssPKIXName_SetArena
(
  NSSPKIXName *name,
  NSSArena *arena
);

NSS_EXTERN void
nssPKIXExtension_SetArena
(
  NSSPKIXExtension *extension,
  NSSArena *arena
);

NSS_EXTERN void
nssPKIXExtensions_SetArena
(
  NSSPKIXExtensions *extensions,
  NSSArena *arena
);

NSS_EXTERN void
nssPKIXValidity_SetArena
(
  NSSPKIXValidity *validity,
  NSSArena *arena
);

NSS_EXTERN void
nssPKIXTime_SetArena
(
  NSSPKIXTime *time,
  NSSArena *arena
);

NSS_EXTERN void
nssPKIXTBSCertificate_SetArena
(
  NSSPKIXTBSCertificate *tbsCert,
  NSSArena *arena
);

NSS_EXTERN PRStatus
nssPKIXTBSCertificate_duplicate
(
  NSSPKIXTBSCertificate *tbsCert,
  NSSArena *arena,
  NSSPKIXTBSCertificate *copy
);

NSS_EXTERN void
nssPKIXCertificate_SetArena
(
  NSSPKIXCertificate *cert,
  NSSArena *arena
);

#ifdef nodef

/*
 * nss_pkix_Attribute_v_create
 *
 *
 * The error may be one of the following values:
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_INVALID_OID
 *  NSS_ERROR_INVALID_ITEM
 *
 * Return value:
 *  A valid pointer to an NSSPKIXAttribute upon success
 *  NULL upon failure.
 */

NSS_EXTERN NSSPKIXAttribute *
nss_pkix_Attribute_v_create
(
  NSSArena *arenaOpt,
  NSSPKIXAttributeType *typeOid,
  PRUint32 count,
  va_list ap
);


/*
 * nss_pkix_X520Name_DoUTF8
 *
 */

NSS_EXTERN PR_STATUS
nss_pkix_X520Name_DoUTF8
(
  NSSPKIXX520Name *name
);


/*
 * nss_pkix_X520CommonName_DoUTF8
 *
 */

NSS_EXTERN PR_STATUS
nss_pkix_X520CommonName_DoUTF8
(
  NSSPKIXX520CommonName *name
);

/*
 * nss_pkix_RDNSequence_v_create
 */

NSS_EXTERN NSSPKIXRDNSequence *
nss_pkix_RDNSequence_v_create
(
  NSSArena *arenaOpt,
  PRUint32 count,
  va_list ap
);

/*
 * nss_pkix_RDNSequence_Clear
 *
 * Wipes out cached data.
 */

NSS_EXTERN PRStatus
nss_pkix_RDNSequence_Clear
(
  NSSPKIXRDNSequence *rdnseq
);

#ifdef NSSDEBUG

NSS_EXTERN PRStatus
nss_pkix_RDNSequence_register
(
  NSSPKIXRDNSequence *rdnseq
);

NSS_EXTERN PRStatus
nss_pkix_RDNSequence_deregister
(
  NSSPKIXRDNSequence *rdnseq
);

#endif /* NSSDEBUG */

/*
 * nss_pkix_RelativeDistinguishedName_v_create
 *
 *
 * The error may be one of the following values:
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_INVALID_OID
 *  NSS_ERROR_INVALID_ITEM
 *
 * Return value:
 *  A valid pointer to an NSSPKIXRelativeDistinguishedName upon success
 *  NULL upon failure.
 */

NSS_EXTERN NSSPKIXRelativeDistinguishedName *
nss_pkix_RelativeDistinguishedName_V_Create
(
  NSSArena *arenaOpt,
  PRUint32 count,
  va_list ap
);

/*
 * nss_pkix_RelativeDistinguishedName_Clear
 *
 * Wipes out cached data.
 */

NSS_EXTERN PRStatus
nss_pkix_RelativeDistinguishedName_Clear
(
  NSSPKIXRelativeDistinguishedName *rdn
);

#ifdef NSSDEBUG

NSS_EXTERN PRStatus
nss_pkix_RelativeDistinguishedName_register
(
  NSSPKIXRelativeDistinguishedName *rdn
);

NSS_EXTERN PRStatus
nss_pkix_RelativeDistinguishedName_deregister
(
  NSSPKIXRelativeDistinguishedName *rdn
);

#endif /* NSSDEBUG */


#endif /* nodef */

PR_END_EXTERN_C

#endif /* PKIXM_H */
