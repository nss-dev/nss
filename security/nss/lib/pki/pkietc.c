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

#ifdef DEBUG
static const char CVS_ID[] = "@(#) $RCSfile$ $Revision$ $Date$ $Name$";
#endif /* DEBUG */

#ifndef DEV_H
#include "dev.h"
#endif /* DEV_H */

#ifndef PKIM_H
#include "pkim.h"
#endif /* PKIM_H */

struct nssSMIMEProfileStr
{
    nssPKIObject object;
    NSSCert *certificate;
    NSSASCII7 *email;
    NSSDER *subject;
    NSSItem *profileTime;
    NSSItem *profileData;
};

NSS_IMPLEMENT nssSMIMEProfile *
nssSMIMEProfile_Create (
  NSSCert *cert,
  NSSItem *profileTime,
  NSSItem *profileData
)
{
#if 0
    NSSArena *arena;
    nssSMIMEProfile *rvProfile;
    nssPKIObject *object;
    NSSTrustDomain *td = nssCert_GetTrustDomain(cert);
    NSSCryptoContext *cc = nssCert_GetCryptoContext(cert);
    arena = nssArena_Create();
    if (!arena) {
	return NULL;
    }
    object = nssPKIObject_Create(arena, NULL, td, cc);
    if (!object) {
	goto loser;
    }
    rvProfile = nss_ZNEW(arena, nssSMIMEProfile);
    if (!rvProfile) {
	goto loser;
    }
    rvProfile->object = *object;
    rvProfile->certificate = cert;
    rvProfile->email = nssUTF8_Duplicate(cert->email, arena);
    rvProfile->subject = nssItem_Duplicate(&cert->subject, arena, NULL);
    if (profileTime) {
	rvProfile->profileTime = nssItem_Duplicate(profileTime, arena, NULL);
    }
    if (profileData) {
	rvProfile->profileData = nssItem_Duplicate(profileData, arena, NULL);
    }
    return rvProfile;
loser:
    nssPKIObject_Destroy(object);
#endif
    return (nssSMIMEProfile *)NULL;
}

NSS_IMPLEMENT nssSMIMEProfile *
nssSMIMEProfile_AddRef (
  nssSMIMEProfile *profile
)
{
    if (profile) {
	nssPKIObject_AddRef(&profile->object);
    }
    return profile;
}

NSS_IMPLEMENT PRStatus
nssSMIMEProfile_Destroy (
  nssSMIMEProfile *profile
)
{
    if (profile) {
	(void)nssPKIObject_Destroy(&profile->object);
    }
    return PR_SUCCESS;
}

struct NSSCRLStr {
  nssPKIObject object;
  NSSDER encoding;
  NSSUTF8 *url;
  PRBool isKRL;
};

NSS_IMPLEMENT NSSCRL *
nssCRL_Create (
  nssPKIObject *object
)
{
    PRStatus status;
    NSSCRL *rvCRL;
    NSSArena *arena = object->arena;
    PR_ASSERT(object->instances != NULL && object->numInstances > 0);
    rvCRL = nss_ZNEW(arena, NSSCRL);
    if (!rvCRL) {
	return (NSSCRL *)NULL;
    }
    rvCRL->object = *object;
    /* XXX should choose instance based on some criteria */
    status = nssCryptokiCRL_GetAttributes(object->instances[0],
                                          arena,
                                          &rvCRL->encoding,
                                          &rvCRL->url,
                                          &rvCRL->isKRL);
    if (status != PR_SUCCESS) {
	return (NSSCRL *)NULL;
    }
    return rvCRL;
}

NSS_IMPLEMENT NSSCRL *
nssCRL_AddRef (
  NSSCRL *crl
)
{
    if (crl) {
	nssPKIObject_AddRef(&crl->object);
    }
    return crl;
}

NSS_IMPLEMENT PRStatus
nssCRL_Destroy (
  NSSCRL *crl
)
{
    if (crl) {
	(void)nssPKIObject_Destroy(&crl->object);
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT PRStatus
nssCRL_DeleteStoredObject (
  NSSCRL *crl,
  NSSCallback *uhh
)
{
    return nssPKIObject_DeleteStoredObject(&crl->object, uhh, PR_TRUE);
}

NSS_IMPLEMENT NSSDER *
nssCRL_GetEncoding (
  NSSCRL *crl
)
{
    if (crl->encoding.data != NULL && crl->encoding.size > 0) {
	return &crl->encoding;
    } else {
	return (NSSDER *)NULL;
    }
}

