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

#ifdef CERT_CACHE
#ifndef CERTCACHE_H
#include "certcache.h"
#endif /* CERTCACHE_H */
#endif /* CERT_CACHE */

struct NSSTrustDomainStr {
  PRInt32 refCount;
  NSSArena *arena;
  NSSCallback *callback;
  struct {
    nssSlotList *forCerts;
    nssSlotList *forCiphers;
    nssSlotList *forTrust;
  } slots;
#ifdef CERT_CACHE
  nssCertificateCache *cache;
#endif /* CERT_CACHE */
};

extern const NSSError NSS_ERROR_NOT_FOUND;

NSS_IMPLEMENT NSSTrustDomain *
NSSTrustDomain_Create
(
  NSSUTF8 *moduleOpt,
  NSSUTF8 *uriOpt,
  NSSUTF8 *opaqueOpt,
  void *reserved
)
{
    NSSArena *arena;
    NSSTrustDomain *rvTD;
    arena = NSSArena_Create();
    if(!arena) {
	return (NSSTrustDomain *)NULL;
    }
    rvTD = nss_ZNEW(arena, NSSTrustDomain);
    if (!rvTD) {
	goto loser;
    }
    rvTD->slots.forCerts = nssSlotList_Create(arena);
    if (!rvTD->slots.forCerts) {
	goto loser;
    }
    rvTD->slots.forCiphers = nssSlotList_Create(arena);
    if (!rvTD->slots.forCiphers) {
	goto loser;
    }
    rvTD->slots.forTrust = nssSlotList_Create(arena);
    if (!rvTD->slots.forTrust) {
	goto loser;
    }
#ifdef CERT_CACHE
    rvTD->cache = nssCertificateCache_Create();
    if (!rvTD->cache) {
	goto loser;
    }
#endif /* CERT_CACHE */
    rvTD->arena = arena;
    rvTD->refCount = 1;
#ifdef NSS_3_4_CODE
    rvTD->statusConfig = NULL;
#endif
    return rvTD;
loser:
    nssArena_Destroy(arena);
    return (NSSTrustDomain *)NULL;
}

NSS_IMPLEMENT PRStatus
NSSTrustDomain_Destroy
(
  NSSTrustDomain *td
)
{
    if (--td->refCount == 0) {
	nssSlotList_Destroy(td->slots.forCerts);
	nssSlotList_Destroy(td->slots.forCiphers);
	nssSlotList_Destroy(td->slots.forTrust);
#ifdef CERT_CACHE
	nssCertificateCache_Destroy(td->cache);
#endif /* CERT_CACHE */
	/* Destroy the trust domain */
	nssArena_Destroy(td->arena);
    }
    return PR_SUCCESS;
}

/* XXX */
NSS_IMPLEMENT NSSSlot **
nssTrustDomain_GetActiveSlots
(
  NSSTrustDomain *td,
  nssUpdateLevel *updateLevel
)
{
    /* XXX */
    *updateLevel = 1;
    return nssSlotList_GetSlots(td->slots.forCerts);
}

/* XXX */
static nssSession *
nssTrustDomain_GetSessionForToken
(
  NSSTrustDomain *td,
  NSSToken *token,
  PRBool readWrite
)
{
    nssSession *rvSession = NULL;
    NSSSlot *slot = nssToken_GetSlot(token);
    rvSession = nssSlot_CreateSession(slot, readWrite);
    nssSlot_Destroy(slot);
    return rvSession;
}

/* XXX */
#ifdef CERT_CACHE
static PRBool
nssTrustDomain_IsUpToDate
(
  NSSTrustDomain *td,
  nssUpdateLevel updateLevel
)
{
    return (updateLevel > 0);
}
#endif /* CERT_CACHE */

NSS_IMPLEMENT PRStatus
NSSTrustDomain_SetDefaultCallback
(
  NSSTrustDomain *td,
  NSSCallback *newCallback,
  NSSCallback **oldCallbackOpt
)
{
    if (oldCallbackOpt) {
	*oldCallbackOpt = td->callback;
    }
    td->callback = newCallback;
    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSCallback *
nssTrustDomain_GetDefaultCallback
(
  NSSTrustDomain *td,
  PRStatus *statusOpt
)
{
    if (statusOpt) {
	*statusOpt = PR_SUCCESS;
    }
    return td->callback;
}

NSS_IMPLEMENT NSSCallback *
NSSTrustDomain_GetDefaultCallback
(
  NSSTrustDomain *td,
  PRStatus *statusOpt
)
{
    return nssTrustDomain_GetDefaultCallback(td, statusOpt);
}

NSS_IMPLEMENT PRStatus
NSSTrustDomain_LoadModule
(
  NSSTrustDomain *td,
  NSSUTF8 *moduleOpt,
  NSSUTF8 *uriOpt,
  NSSUTF8 *opaqueOpt,
  void *reserved
)
{
    return PR_FAILURE;
}

NSS_IMPLEMENT PRStatus
NSSTrustDomain_AddModule
(
  NSSTrustDomain *td,
  NSSModule *module
)
{
    PRStatus status;
    PRUint32 order;
    /* XXX would be nice if order indicated whether or not to include it */
    order = nssModule_GetCertOrder(module);
    status = nssSlotList_AddModuleSlots(td->slots.forCerts, module, order);
    return PR_SUCCESS;
}

NSS_IMPLEMENT PRStatus
NSSTrustDomain_DisableToken
(
  NSSTrustDomain *td,
  NSSToken *token,
  NSSError why
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return PR_FAILURE;
}

NSS_IMPLEMENT PRStatus
NSSTrustDomain_EnableToken
(
  NSSTrustDomain *td,
  NSSToken *token
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return PR_FAILURE;
}

NSS_IMPLEMENT PRStatus
NSSTrustDomain_IsTokenEnabled
(
  NSSTrustDomain *td,
  NSSToken *token,
  NSSError *whyOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return PR_FAILURE;
}

NSS_IMPLEMENT NSSSlot *
NSSTrustDomain_FindSlotByName
(
  NSSTrustDomain *td,
  NSSUTF8 *slotName
)
{
    NSSSlot *slot = NULL;
    slot = nssSlotList_FindSlotByName(td->slots.forCerts, slotName);
    if (slot) {
	return slot;
    }
    slot = nssSlotList_FindSlotByName(td->slots.forCiphers, slotName);
    if (slot) {
	return slot;
    }
    slot = nssSlotList_FindSlotByName(td->slots.forTrust, slotName);
    return slot;
}

NSS_IMPLEMENT NSSToken *
nssTrustDomain_FindTokenByName
(
  NSSTrustDomain *td,
  NSSUTF8 *tokenName
)
{
    NSSToken *token = NULL;
    token = nssSlotList_FindTokenByName(td->slots.forCerts, tokenName);
    if (token) {
	return token;
    }
    token = nssSlotList_FindTokenByName(td->slots.forCiphers, tokenName);
    if (token) {
	return token;
    }
    token = nssSlotList_FindTokenByName(td->slots.forTrust, tokenName);
    return token;
}

NSS_IMPLEMENT NSSToken *
NSSTrustDomain_FindTokenByName
(
  NSSTrustDomain *td,
  NSSUTF8 *tokenName
)
{
    return nssTrustDomain_FindTokenByName(td, tokenName);
}

NSS_IMPLEMENT NSSToken *
NSSTrustDomain_FindTokenBySlotName
(
  NSSTrustDomain *td,
  NSSUTF8 *slotName
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSToken *
nssTrustDomain_FindTokenForAlgorithm
(
  NSSTrustDomain *td,
  const NSSAlgorithmAndParameters *ap
)
{
    return nssSlotList_GetBestTokenForAlgorithm(td->slots.forCerts, ap);
}

NSS_IMPLEMENT NSSToken *
NSSTrustDomain_FindTokenForAlgorithm
(
  NSSTrustDomain *td,
  NSSOID *algorithm
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSToken *
NSSTrustDomain_FindBestTokenForAlgorithms
(
  NSSTrustDomain *td,
  NSSOID *algorithms[], /* may be null-terminated */
  PRUint32 nAlgorithmsOpt /* limits the array if nonzero */
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT PRStatus
NSSTrustDomain_Login
(
  NSSTrustDomain *td,
  NSSCallback *uhhOpt
)
{
    PRStatus status;
    NSSSlot **slots = NULL;
    NSSSlot **slotp;
    nssUpdateLevel updateLevel;
    NSSCallback *uhh = uhhOpt ? uhhOpt : td->callback;
    /* obtain the current set of active slots in the trust domain */
    slots = nssTrustDomain_GetActiveSlots(td, &updateLevel);
    if (!slots) {
	return PR_SUCCESS;
    }
    /* iterate over the slots */
    status = PR_SUCCESS;
    for (slotp = slots; *slotp; slotp++) {
	if (nssSlot_Login(*slotp, uhh) != PR_SUCCESS) {
	    status = PR_FAILURE;
	}
    }
    nssSlotArray_Destroy(slots);
    return status;
}

NSS_IMPLEMENT PRStatus
NSSTrustDomain_Logout
(
  NSSTrustDomain *td
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return PR_FAILURE;
}

NSS_IMPLEMENT NSSCertificate *
NSSTrustDomain_ImportCertificate
(
  NSSTrustDomain *td,
  NSSCertificate *c,
  NSSToken *destinationOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCertificate *
nssTrustDomain_ImportEncodedCertificate
(
  NSSTrustDomain *td,
  NSSBER *ber,
  NSSToken *destinationOpt,
  NSSUTF8 *nicknameOpt
)
{
    PRStatus status;
    NSSCertificate *c = NULL;
    NSSToken *destination = destinationOpt; /* XXX */

    c = nssCertificate_Decode(ber);
    if (!c) {
	goto loser;
    }
    status = nssCertificate_CopyToToken(c, destination, nicknameOpt);
    if (status == PR_FAILURE) {
	goto loser;
    }
    return c;
loser:
    if (c) {
	nssCertificate_Destroy(c);
    }
    return (NSSCertificate *)NULL;
}

NSS_IMPLEMENT NSSCertificate *
NSSTrustDomain_ImportEncodedCertificate
(
  NSSTrustDomain *td,
  NSSBER *ber,
  NSSToken *destinationOpt,
  NSSUTF8 *nicknameOpt
)
{
    return nssTrustDomain_ImportEncodedCertificate(td, ber, destinationOpt,
                                                   nicknameOpt);
}

NSS_IMPLEMENT NSSCertificate **
NSSTrustDomain_ImportEncodedCertificateChain
(
  NSSTrustDomain *td,
  NSSBER *ber,
  NSSCertificate *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt,
  NSSToken *destinationOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSPrivateKey *
NSSTrustDomain_ImportEncodedPrivateKey
(
  NSSTrustDomain *td,
  NSSBER *ber,
  NSSItem *passwordOpt, /* NULL will cause a callback */
  NSSCallback *uhhOpt,
  NSSToken *destination
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSPublicKey *
NSSTrustDomain_ImportEncodedPublicKey
(
  NSSTrustDomain *td,
  NSSBER *ber,
  NSSToken *destinationOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCertificate **
nssTrustDomain_FindCertificatesByNickname
(
  NSSTrustDomain *td,
  NSSUTF8 *name,
  NSSCertificate *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
)
{
    PRStatus status;
    PRUint32 numRemaining;
    NSSToken *token = NULL;
    NSSSlot **slots = NULL;
    NSSSlot **slotp;
    NSSCertificate **rvCerts = NULL;
    nssPKIObjectCollection *collection = NULL;
    nssUpdateLevel updateLevel;
#ifdef CERT_CACHE
    /* see if this search is already cached */
    rvCerts = nssCertificateCache_FindCertificatesByNickname(td->cache,
                                                             name,
                                                             rvOpt,
                                                             maximumOpt,
                                                             arenaOpt,
                                                             &updateLevel);
    if (nssTrustDomain_IsUpToDate(td, updateLevel)) {
	/* The search was cached, and up-to-date with respect to token
	 * insertion/removal.  Thus, it is complete, and we can return
	 * the cached search.
	 */
	return rvCerts;
    }
#endif /* CERT_CACHE */
    /* initialize the collection of token certificates with the set of
     * cached certs (if any).
     */
    collection = nssCertificateCollection_Create(td, rvCerts);
    if (!collection) {
	return (NSSCertificate **)NULL;
    }
    nssCertificateArray_Destroy(rvCerts);
    /* obtain the current set of active slots in the trust domain */
    slots = nssTrustDomain_GetActiveSlots(td, &updateLevel);
    if (!slots) {
	goto loser;
    }
    /* iterate over the slots */
    numRemaining = maximumOpt;
    for (slotp = slots; *slotp; slotp++) {
	/* XXX
	 * If tokens have been added/removed, this search should be restricted
	 * to those tokens.  That is, this search should only have to look
	 * at inserted/removed tokens, the others are still up-to-date.
	 * Removal is easy -- the token will not be retrieved from the slot.
	 * Insertion implies there is a token here that has not been searched.
	 * The previous search, rvCerts, should indicate which tokens have
	 * been searched, they will not need to be searched again.
	 */
	token = nssSlot_GetToken(*slotp);
	if (token) {
	    nssSession *session;
	    nssCryptokiObject **instances;
	    nssTokenSearchType tokenOnly = nssTokenSearchType_TokenOnly;
	    session = nssTrustDomain_GetSessionForToken(td, token, PR_FALSE);
	    if (!session) {
		nssToken_Destroy(token);
		goto loser;
	    }
	    instances = nssToken_FindCertificatesByNickname(token,
	                                                    session,
	                                                    name,
	                                                    tokenOnly,
	                                                    numRemaining,
	                                                    &status);
	    nssToken_Destroy(token);
	    if (status != PR_SUCCESS) {
		goto loser;
	    }
	    if (instances) {
		status = nssPKIObjectCollection_AddInstances(collection, 
		                                             instances, 0);
		nss_ZFreeIf(instances);
		if (status != PR_SUCCESS) {
		    goto loser;
		}
		if (maximumOpt > 0) {
	            PRUint32 count;
	            count = nssPKIObjectCollection_Count(collection);
		    numRemaining = maximumOpt - count;
		    if (numRemaining == 0) break;
		}
	    }
	}
    }
    /* Grab the certs collected in the search. */
    rvCerts = nssPKIObjectCollection_GetCertificates(collection,
                                                     rvOpt, maximumOpt,
                                                     arenaOpt);
#ifdef CERT_CACHE
    /* Cache this search.  It is up-to-date w.r.t. the time when it grabbed
     * the slots to search.
     */
    status = nssCertificateCache_AddCertificatesForNickname(td->cache,
                                                            name,
                                                            rvCerts,
                                                            updateLevel);
#endif /* CERT_CACHE */
    nssPKIObjectCollection_Destroy(collection);
    nssSlotArray_Destroy(slots);
    return rvCerts;
loser:
    if (slots) {
	nssSlotArray_Destroy(slots);
    }
    if (collection) {
	nssPKIObjectCollection_Destroy(collection);
    }
    return (NSSCertificate **)NULL;
}

NSS_IMPLEMENT NSSCertificate **
NSSTrustDomain_FindCertificatesByNickname
(
  NSSTrustDomain *td,
  NSSUTF8 *name,
  NSSCertificate *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
)
{
    return nssTrustDomain_FindCertificatesByNickname(td,
                                                     name,
                                                     rvOpt,
                                                     maximumOpt,
                                                     arenaOpt);
}

NSS_IMPLEMENT NSSCertificate *
nssTrustDomain_FindBestCertificateByNickname
(
  NSSTrustDomain *td,
  NSSUTF8 *name,
  NSSTime time,
  NSSUsages usages,
  NSSPolicies *policiesOpt
)
{
    NSSCertificate **nicknameCerts;
    NSSCertificate *rvCert = NULL;
    nicknameCerts = nssTrustDomain_FindCertificatesByNickname(td, name,
                                                              NULL,
                                                              0,
                                                              NULL);
    if (nicknameCerts) {
	rvCert = nssCertificateArray_FindBestCertificate(nicknameCerts,
                                                         time,
                                                         usages,
                                                         policiesOpt);
	nssCertificateArray_Destroy(nicknameCerts);
    }
    return rvCert;
}

NSS_IMPLEMENT NSSCertificate *
NSSTrustDomain_FindBestCertificateByNickname
(
  NSSTrustDomain *td,
  NSSUTF8 *name,
  NSSTime time,
  NSSUsages usages,
  NSSPolicies *policiesOpt
)
{
    return nssTrustDomain_FindBestCertificateByNickname(td,
                                                        name,
                                                        time,
                                                        usages,
                                                        policiesOpt);
}

NSS_IMPLEMENT NSSCertificate **
nssTrustDomain_FindCertificatesBySubject
(
  NSSTrustDomain *td,
  NSSDER *subject,
  NSSCertificate *rvOpt[],
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    PRStatus status;
    PRUint32 numRemaining;
    NSSToken *token = NULL;
    NSSSlot **slots = NULL;
    NSSSlot **slotp;
    NSSCertificate **rvCerts = NULL;
    nssPKIObjectCollection *collection = NULL;
    nssUpdateLevel updateLevel;
#ifdef CERT_CACHE
    /* see if this search is already cached */
    rvCerts = nssCertificateCache_FindCertificatesBySubject(td->cache,
                                                            subject,
                                                            rvOpt,
                                                            maximumOpt,
                                                            arenaOpt,
                                                            &updateLevel);
    if (nssTrustDomain_IsUpToDate(td, updateLevel)) {
	return rvCerts;
    }
#endif /* CERT_CACHE */
    collection = nssCertificateCollection_Create(td, rvCerts);
    if (!collection) {
	return (NSSCertificate **)NULL;
    }
    nssCertificateArray_Destroy(rvCerts);
    slots = nssTrustDomain_GetActiveSlots(td, &updateLevel);
    if (!slots) {
	goto loser;
    }
    numRemaining = maximumOpt;
    for (slotp = slots; *slotp; slotp++) {
	token = nssSlot_GetToken(*slotp);
	if (token) {
	    nssSession *session;
	    nssCryptokiObject **instances;
	    nssTokenSearchType tokenOnly = nssTokenSearchType_TokenOnly;
	    session = nssTrustDomain_GetSessionForToken(td, token, PR_FALSE);
	    if (!session) {
		nssToken_Destroy(token);
		goto loser;
	    }
	    instances = nssToken_FindCertificatesBySubject(token,
	                                                   session,
	                                                   subject,
	                                                   tokenOnly,
	                                                   numRemaining,
	                                                   &status);
	    nssToken_Destroy(token);
	    if (status != PR_SUCCESS) {
		goto loser;
	    }
	    if (instances) {
		status = nssPKIObjectCollection_AddInstances(collection, 
		                                             instances, 0);
		nss_ZFreeIf(instances);
		if (status != PR_SUCCESS) {
		    goto loser;
		}
		if (maximumOpt > 0) {
		    PRUint32 count;
		    count = nssPKIObjectCollection_Count(collection);
		    numRemaining = maximumOpt - count;
		    if (numRemaining == 0) break;
		}
	    }
	}
    }
    rvCerts = nssPKIObjectCollection_GetCertificates(collection,
                                                     rvOpt, maximumOpt,
                                                     arenaOpt);
#ifdef CERT_CACHE
    status = nssCertificateCache_AddCertificatesForSubject(td->cache,
                                                           subject,
                                                           rvCerts,
                                                           updateLevel);
#endif /* CERT_CACHE */
    nssPKIObjectCollection_Destroy(collection);
    nssSlotArray_Destroy(slots);
    return rvCerts;
loser:
    if (slots) {
	nssSlotArray_Destroy(slots);
    }
    if (collection) {
	nssPKIObjectCollection_Destroy(collection);
    }
    return (NSSCertificate **)NULL;
}

NSS_IMPLEMENT NSSCertificate **
NSSTrustDomain_FindCertificatesBySubject
(
  NSSTrustDomain *td,
  NSSDER *subject,
  NSSCertificate *rvOpt[],
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    return nssTrustDomain_FindCertificatesBySubject(td, 
                                                    subject,
                                                    rvOpt,
                                                    maximumOpt,
                                                    arenaOpt);
}

NSS_IMPLEMENT NSSCertificate *
nssTrustDomain_FindBestCertificateBySubject
(
  NSSTrustDomain *td,
  NSSDER *subject,
  NSSTime time,
  NSSUsages usages,
  NSSPolicies *policiesOpt
)
{
    NSSCertificate **subjectCerts;
    NSSCertificate *rvCert = NULL;
    subjectCerts = nssTrustDomain_FindCertificatesBySubject(td, subject,
                                                            NULL,
                                                            0,
                                                            NULL);
    if (subjectCerts) {
	rvCert = nssCertificateArray_FindBestCertificate(subjectCerts,
                                                         time,
                                                         usages,
                                                         policiesOpt);
	nssCertificateArray_Destroy(subjectCerts);
    }
    return rvCert;
}

NSS_IMPLEMENT NSSCertificate *
NSSTrustDomain_FindBestCertificateBySubject
(
  NSSTrustDomain *td,
  NSSDER *subject,
  NSSTime time,
  NSSUsages usages,
  NSSPolicies *policiesOpt
)
{
    return nssTrustDomain_FindBestCertificateBySubject(td,
                                                       subject,
                                                       time,
                                                       usages,
                                                       policiesOpt);
}

NSS_IMPLEMENT NSSCertificate *
NSSTrustDomain_FindBestCertificateByNameComponents
(
  NSSTrustDomain *td,
  NSSUTF8 *nameComponents,
  NSSTime time,
  NSSUsage *usage,
  NSSPolicies *policiesOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCertificate **
NSSTrustDomain_FindCertificatesByNameComponents
(
  NSSTrustDomain *td,
  NSSUTF8 *nameComponents,
  NSSCertificate *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCertificate *
nssTrustDomain_FindCertificateByIssuerAndSerialNumber
(
  NSSTrustDomain *td,
  NSSDER *issuer,
  NSSDER *serial
)
{
    PRStatus status;
    NSSToken *token = NULL;
    NSSSlot **slots = NULL;
    NSSSlot **slotp;
    NSSCertificate *rvCert = NULL;
    nssPKIObjectCollection *collection = NULL;
    nssUpdateLevel updateLevel;
#ifdef CERT_CACHE
    /* see if this search is already cached */
    rvCert = nssCertificateCache_FindCertificateByIssuerAndSerialNumber(
                                                               td->cache,
                                                               issuer,
                                                               serial,
                                                               &updateLevel);
    if (nssTrustDomain_IsUpToDate(td, updateLevel)) {
	return rvCert;
    }
#endif /* CERT_CACHE */
    slots = nssTrustDomain_GetActiveSlots(td, &updateLevel);
    if (!slots) {
	goto loser;
    }
    for (slotp = slots; *slotp; slotp++) {
	token = nssSlot_GetToken(*slotp);
	if (token) {
	    nssSession *session;
	    nssCryptokiObject *instance;
	    nssTokenSearchType tokenOnly = nssTokenSearchType_TokenOnly;
	    session = nssTrustDomain_GetSessionForToken(td, token, PR_FALSE);
	    if (!session) {
		nssToken_Destroy(token);
		goto loser;
	    }
	    instance = nssToken_FindCertificateByIssuerAndSerialNumber(
	                                                            token,
	                                                            session,
	                                                            issuer,
	                                                            serial,
	                                                            tokenOnly,
	                                                            &status);
	    nssToken_Destroy(token);
	    if (status != PR_SUCCESS) {
		goto loser;
	    }
	    if (instance) {
		if (!collection) {
		    collection = nssCertificateCollection_Create(td, NULL);
		    if (!collection) {
			goto loser;
		    }
		}
		nssPKIObjectCollection_AddInstances(collection, 
		                                    &instance, 1);
	    }
	}
    }
    if (collection) {
	(void)nssPKIObjectCollection_GetCertificates(collection, 
	                                             &rvCert, 1, NULL);
	nssPKIObjectCollection_Destroy(collection);
	if (!rvCert) {
	    goto loser;
	}
    }
#ifdef CERT_CACHE
    status = nssCertificateCache_AddCertificate(td->cache, rvCert, 
                                                issuer, serial, updateLevel);
#endif /* CERT_CACHE */
    nssSlotArray_Destroy(slots);
    return rvCert;
loser:
    if (slots) {
	nssSlotArray_Destroy(slots);
    }
    return (NSSCertificate *)NULL;
}

NSS_IMPLEMENT NSSCertificate *
NSSTrustDomain_FindCertificateByIssuerAndSerialNumber
(
  NSSTrustDomain *td,
  NSSDER *issuer,
  NSSDER *serial
)
{
    return nssTrustDomain_FindCertificateByIssuerAndSerialNumber(td,
                                                                 issuer,
                                                                 serial);
}

NSS_IMPLEMENT NSSCertificate *
nssTrustDomain_FindCertificateByEncodedCertificate
(
  NSSTrustDomain *td,
  NSSBER *ber
)
{
    NSSCertificate *rvCert = NULL;
#if 0
    PRStatus status;
    NSSDER issuer = { 0 };
    NSSDER serial = { 0 };
    NSSArena *arena = nssArena_Create();
    if (!arena) {
	return (NSSCertificate *)NULL;
    }
    /* XXX this is not generic...  will any cert crack into issuer/serial? */
    status = nssPKIX509_GetIssuerAndSerialFromDER(ber, arena, &issuer, &serial);
    if (status != PR_SUCCESS) {
	goto finish;
    }
    rvCert = nssTrustDomain_FindCertificateByIssuerAndSerialNumber(td,
                                                                   &issuer,
                                                                   &serial);
finish:
    nssArena_Destroy(arena);
#endif
    return rvCert;
}

NSS_IMPLEMENT NSSCertificate *
NSSTrustDomain_FindCertificateByEncodedCertificate
(
  NSSTrustDomain *td,
  NSSBER *ber
)
{
    return nssTrustDomain_FindCertificateByEncodedCertificate(td, ber);
}

NSS_IMPLEMENT NSSCertificate **
nssTrustDomain_FindCertificatesByID
(
  NSSTrustDomain *td,
  NSSItem *id,
  NSSCertificate **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    PRStatus status;
    PRUint32 numRemaining;
    NSSToken *token = NULL;
    NSSSlot **slots = NULL;
    NSSSlot **slotp;
    NSSCertificate **rvCerts = NULL;
    nssPKIObjectCollection *collection = NULL;
    nssUpdateLevel updateLevel;
    collection = nssCertificateCollection_Create(td, rvCerts);
    if (!collection) {
	return (NSSCertificate **)NULL;
    }
    slots = nssTrustDomain_GetActiveSlots(td, &updateLevel);
    if (!slots) {
	goto loser;
    }
    numRemaining = maximumOpt;
    for (slotp = slots; *slotp; slotp++) {
	token = nssSlot_GetToken(*slotp);
	if (token) {
	    nssSession *session;
	    nssCryptokiObject **instances;
	    nssTokenSearchType tokenOnly = nssTokenSearchType_TokenOnly;
	    session = nssTrustDomain_GetSessionForToken(td, token, PR_FALSE);
	    if (!session) {
		nssToken_Destroy(token);
		goto loser;
	    }
	    instances = nssToken_FindCertificatesByID(token,
	                                              session,
	                                              id,
	                                              tokenOnly,
	                                              numRemaining,
	                                              &status);
	    nssToken_Destroy(token);
	    if (status != PR_SUCCESS) {
		goto loser;
	    }
	    if (instances) {
		status = nssPKIObjectCollection_AddInstances(collection, 
		                                             instances, 0);
		nss_ZFreeIf(instances);
		if (status != PR_SUCCESS) {
		    goto loser;
		}
		if (maximumOpt > 0) {
		    PRUint32 count;
		    count = nssPKIObjectCollection_Count(collection);
		    numRemaining = maximumOpt - count;
		    if (numRemaining == 0) break;
		}
	    }
	}
    }
    rvCerts = nssPKIObjectCollection_GetCertificates(collection,
                                                     rvOpt, maximumOpt,
                                                     arenaOpt);
    /* cache 'em? */
    nssPKIObjectCollection_Destroy(collection);
    nssSlotArray_Destroy(slots);
    return rvCerts;
loser:
    if (slots) {
	nssSlotArray_Destroy(slots);
    }
    if (collection) {
	nssPKIObjectCollection_Destroy(collection);
    }
    return (NSSCertificate **)NULL;
}

NSS_IMPLEMENT NSSCertificate *
NSSTrustDomain_FindBestCertificateByEmail
(
  NSSTrustDomain *td,
  NSSASCII7 *email,
  NSSTime time,
  NSSUsage *usage,
  NSSPolicies *policiesOpt
)
{
    return 0;
}

NSS_IMPLEMENT NSSCertificate **
NSSTrustDomain_FindCertificatesByEmail
(
  NSSTrustDomain *td,
  NSSASCII7 *email,
  NSSCertificate *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCertificate *
NSSTrustDomain_FindCertificateByOCSPHash
(
  NSSTrustDomain *td,
  NSSItem *hash
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCertificate *
NSSTrustDomain_FindBestUserCertificate
(
  NSSTrustDomain *td,
  NSSTime time,
  NSSUsage *usage,
  NSSPolicies *policiesOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCertificate **
NSSTrustDomain_FindUserCertificates
(
  NSSTrustDomain *td,
  NSSTime time,
  NSSUsage *usageOpt,
  NSSPolicies *policiesOpt,
  NSSCertificate **rvOpt,
  PRUint32 rvLimit, /* zero for no limit */
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCertificate *
NSSTrustDomain_FindBestUserCertificateForSSLClientAuth
(
  NSSTrustDomain *td,
  NSSUTF8 *sslHostOpt,
  NSSDER *rootCAsOpt[], /* null pointer for none */
  PRUint32 rootCAsMaxOpt, /* zero means list is null-terminated */
  const NSSAlgorithmAndParameters *apOpt,
  NSSPolicies *policiesOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCertificate **
NSSTrustDomain_FindUserCertificatesForSSLClientAuth
(
  NSSTrustDomain *td,
  NSSUTF8 *sslHostOpt,
  NSSDER *rootCAsOpt[], /* null pointer for none */
  PRUint32 rootCAsMaxOpt, /* zero means list is null-terminated */
  const NSSAlgorithmAndParameters *apOpt,
  NSSPolicies *policiesOpt,
  NSSCertificate **rvOpt,
  PRUint32 rvLimit, /* zero for no limit */
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCertificate *
NSSTrustDomain_FindBestUserCertificateForEmailSigning
(
  NSSTrustDomain *td,
  NSSASCII7 *signerOpt,
  NSSASCII7 *recipientOpt,
  /* anything more here? */
  const NSSAlgorithmAndParameters *apOpt,
  NSSPolicies *policiesOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCertificate **
NSSTrustDomain_FindUserCertificatesForEmailSigning
(
  NSSTrustDomain *td,
  NSSASCII7 *signerOpt,
  NSSASCII7 *recipientOpt,
  /* anything more here? */
  const NSSAlgorithmAndParameters *apOpt,
  NSSPolicies *policiesOpt,
  NSSCertificate **rvOpt,
  PRUint32 rvLimit, /* zero for no limit */
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

static PRStatus
collector(nssCryptokiObject *instance, void *arg)
{
    nssPKIObjectCollection *collection = (nssPKIObjectCollection *)arg;
    return nssPKIObjectCollection_AddInstanceAsObject(collection, instance);
}

NSS_IMPLEMENT PRStatus *
NSSTrustDomain_TraverseCertificates
(
  NSSTrustDomain *td,
  PRStatus (*callback)(NSSCertificate *c, void *arg),
  void *arg
)
{
    PRStatus status;
    NSSToken *token = NULL;
    NSSSlot **slots = NULL;
    NSSSlot **slotp;
    nssPKIObjectCollection *collection = NULL;
    nssPKIObjectCallback pkiCallback;
    nssUpdateLevel updateLevel;
    /* XXX cache ???  probably use query callback below */
    collection = nssCertificateCollection_Create(td, NULL);
    if (!collection) {
	return (PRStatus *)NULL;
    }
    /* obtain the current set of active slots in the trust domain */
    slots = nssTrustDomain_GetActiveSlots(td, &updateLevel);
    if (!slots) {
	goto loser;
    }
    /* iterate over the slots */
    for (slotp = slots; *slotp; slotp++) {
	/* get the token for the slot, if present */
	token = nssSlot_GetToken(*slotp);
	if (token) {
	    nssSession *session;
	    nssTokenSearchType tokenOnly = nssTokenSearchType_TokenOnly;
	    /* get a session for the token */
	    session = nssTrustDomain_GetSessionForToken(td, token, PR_FALSE);
	    if (!session) {
		nssToken_Destroy(token);
		goto loser;
	    }
	    /* perform the traversal */
	    status = nssToken_TraverseCertificates(token,
	                                           session,
	                                           tokenOnly,
	                                           collector,
	                                           collection);
	    nssToken_Destroy(token);
	    if (status != PR_SUCCESS) {
		goto loser;
	    }
	}
    }

    /* Traverse the collection */
    pkiCallback.func.cert = callback;
    pkiCallback.arg = arg;
    status = nssPKIObjectCollection_Traverse(collection, &pkiCallback);
    /* clean up */
    nssPKIObjectCollection_Destroy(collection);
    nssSlotArray_Destroy(slots);
    return NULL;
loser:
    if (slots) {
	nssSlotArray_Destroy(slots);
    }
    if (collection) {
	nssPKIObjectCollection_Destroy(collection);
    }
    return NULL;
}

NSS_IMPLEMENT NSSTrust *
nssTrustDomain_FindTrustForCertificate
(
  NSSTrustDomain *td,
  NSSCertificate *c
)
{
    PRStatus status;
    NSSSlot **slots;
    NSSSlot **slotp;
    NSSToken *token;
    NSSDER *encoding = nssCertificate_GetEncoding(c);
    NSSDER *issuer = nssCertificate_GetIssuer(c);
    NSSDER *serial = nssCertificate_GetSerialNumber(c);
    nssTokenSearchType tokenOnly = nssTokenSearchType_TokenOnly;
    nssCryptokiObject *to = NULL;
    nssPKIObject *pkio = NULL;
    NSSTrust *rvt = NULL;
    nssUpdateLevel updateLevel;
    slots = nssTrustDomain_GetActiveSlots(td, &updateLevel);
    if (!slots) {
	return (NSSTrust *)NULL;
    }
    for (slotp = slots; *slotp; slotp++) {
	token = nssSlot_GetToken(*slotp);
	if (token) {
	    to = nssToken_FindTrustForCertificate(token, NULL, 
	                                          encoding,
	                                          issuer,
	                                          serial,
	                                          tokenOnly);
	    if (to) {
		if (!pkio) {
		    pkio = nssPKIObject_Create(NULL, to, td, NULL);
		    if (!pkio) {
			goto loser;
		    }
		} else {
		    status = nssPKIObject_AddInstance(pkio, to);
		    if (status != PR_SUCCESS) {
			goto loser;
		    }
		}
	    }
	    nssToken_Destroy(token);
	}
    }
    if (pkio) {
	rvt = nssTrust_Create(pkio);
	if (!rvt) {
	    goto loser;
	}
    }
    nssSlotArray_Destroy(slots);
    return rvt;
loser:
    nssSlotArray_Destroy(slots);
    if (to) {
	nssCryptokiObject_Destroy(to);
    }
    if (pkio) {
	nssPKIObject_Destroy(pkio);
    }
    return (NSSTrust *)NULL;
}

NSS_IMPLEMENT NSSCRL **
nssTrustDomain_FindCRLsBySubject
(
  NSSTrustDomain *td,
  NSSDER *subject
)
{
    PRStatus status;
    NSSSlot **slots;
    NSSSlot **slotp;
    NSSToken *token;
    nssUpdateLevel updateLevel;
    nssPKIObjectCollection *collection;
    NSSCRL **rvCRLs = NULL;
    collection = nssCRLCollection_Create(td, NULL);
    if (!collection) {
	return (NSSCRL **)NULL;
    }
    slots = nssTrustDomain_GetActiveSlots(td, &updateLevel);
    if (!slots) {
	goto loser;
    }
    for (slotp = slots; *slotp; slotp++) {
	token = nssSlot_GetToken(*slotp);
	if (token) {
	    nssSession *session;
	    nssCryptokiObject **instances;
	    nssTokenSearchType tokenOnly = nssTokenSearchType_TokenOnly;
	    /* get a session for the token */
	    session = nssTrustDomain_GetSessionForToken(td, token, PR_FALSE);
	    if (!session) {
		nssToken_Destroy(token);
		goto loser;
	    }
	    /* perform the traversal */
	    instances = nssToken_FindCRLsBySubject(token, session, subject,
	                                           tokenOnly, 0, &status);
	    nssToken_Destroy(token);
	    if (status != PR_SUCCESS) {
		goto loser;
	    }
	    /* add the found CRL's to the collection */
	    status = nssPKIObjectCollection_AddInstances(collection, 
	                                                 instances, 0);
	    nss_ZFreeIf(instances);
	    if (status != PR_SUCCESS) {
		goto loser;
	    }
	}
    }
    rvCRLs = nssPKIObjectCollection_GetCRLs(collection, NULL, 0, NULL);
    nssPKIObjectCollection_Destroy(collection);
    nssSlotArray_Destroy(slots);
    return rvCRLs;
loser:
    nssPKIObjectCollection_Destroy(collection);
    nssSlotArray_Destroy(slots);
    return (NSSCRL **)NULL;
}

NSS_IMPLEMENT PRStatus
nssTrustDomain_GenerateKeyPair
(
  NSSTrustDomain *td,
  const NSSAlgorithmAndParameters *ap,
  NSSPublicKey **pbkOpt,
  NSSPrivateKey **pvkOpt,
  NSSUTF8 *nicknameOpt,
  NSSProperties properties,
  NSSOperations operations,
  NSSToken *destination,
  NSSCallback *uhhOpt
)
{
    PRStatus status;
    PRBool temporary;
    NSSToken *source;
    nssSession *session = NULL;
    nssCryptokiObject *bkey = NULL;
    nssCryptokiObject *vkey = NULL;
    nssPKIObject *pkio = NULL;
    NSSSlot *slot;

    if (nssToken_DoesAlgorithm(destination, ap)) {
	/* We can do the keygen on the destination token */
	source = nssToken_AddRef(destination);
	temporary = PR_FALSE;
    } else {
	/* We can't do the keygen on the destination token, find one
	 * that is capable of doing it, and create it there (as a
	 * temporary object)
	 */
	source = nssTrustDomain_FindTokenForAlgorithm(td, ap);
	if (!source) {
	    return PR_FAILURE;
	}
	temporary = PR_TRUE;
    }

    /* The key will be private, so login is required */
    slot = nssToken_GetSlot(destination);
    status = nssSlot_Login(slot, uhhOpt ? uhhOpt : td->callback);
    nssSlot_Destroy(slot);
    if (status == PR_FAILURE) {
	goto loser;
    }

    session = nssTrustDomain_GetSessionForToken(td, source, !temporary);
    if (!session) {
	goto loser;
    }

    status = nssToken_GenerateKeyPair(source, session, ap,
                                      !temporary, nicknameOpt, 
                                      properties, operations,
                                      &bkey, &vkey);
    if (status == PR_FAILURE) {
	goto loser;
    }

#if 0
    if (source != destination) {
	/* Have to move the keys to the destination, and destroy the sources */
	nssCryptokiObject *destbKey, *destvKey;
	nssSession *copySession;
	copySession = nssTrustDomain_GetSessionForToken(td, destination, 
	                                                PR_FALSE);
	if (!copySession) {
	    goto loser;
	}
	status = nssCryptokiKeyPair_Copy(bkey, vkey, session,
	                                 destination, copySession,
	                                 &destbKey, &destvKey,
	                                 PR_TRUE);
	nssCryptokiObject_DeleteStoredObject(bkey, session);
	nssCryptokiObject_DeleteStoredObject(vkey, session);
	bkey = vkey = NULL;
	nssSession_Destroy(copySession);
	if (status == PR_FAILURE) {
	    goto loser;
	}
	bkey = destbKey;
	vkey = destvKey;
    }
#endif

    if (pbkOpt) {
	pkio = nssPKIObject_Create(NULL, bkey, td, NULL);
	if (!pkio) {
	    goto loser;
	}
        *pbkOpt = nssPublicKey_Create(pkio);
	if (!*pbkOpt) {
	    nssPKIObject_Destroy(pkio);
	    goto loser;
	}
    } else {
	nssCryptokiObject_Destroy(bkey);
    }
    if (pvkOpt) {
	pkio = nssPKIObject_Create(NULL, vkey, td, NULL);
	if (!pkio) {
	    goto loser;
	}
        *pvkOpt = nssPrivateKey_Create(pkio);
	if (!*pvkOpt) {
	    nssPKIObject_Destroy(pkio);
	    goto loser;
	}
    } else {
	nssCryptokiObject_Destroy(vkey);
    }
    nssToken_Destroy(source);
    return PR_SUCCESS;

loser:
    if (session) {
	nssSession_Destroy(session);
    }
    if (bkey) {
	nssCryptokiObject_Destroy(bkey);
    }
    if (vkey) {
	nssCryptokiObject_Destroy(vkey);
    }
    nssToken_Destroy(source);
    return PR_FAILURE;
}

NSS_IMPLEMENT PRStatus
NSSTrustDomain_GenerateKeyPair
(
  NSSTrustDomain *td,
  const NSSAlgorithmAndParameters *ap,
  NSSPublicKey **pbkOpt,
  NSSPrivateKey **pvkOpt,
  NSSUTF8 *nicknameOpt,
  NSSProperties properties,
  NSSOperations operations,
  NSSToken *destination,
  NSSCallback *uhhOpt
)
{
    return nssTrustDomain_GenerateKeyPair(td, ap,
                                          pbkOpt, pvkOpt,
                                          nicknameOpt,
                                          properties, operations,
                                          destination, uhhOpt);
}

NSS_IMPLEMENT NSSToken *
nssTrustDomain_FindSourceToken
(
  NSSTrustDomain *td,
  const NSSAlgorithmAndParameters *ap,
  NSSToken *candidate
)
{
    NSSToken *source = NULL;
    if (nssToken_DoesAlgorithm(candidate, ap)) {
	/* We can do the math on the destination token */
	source = nssToken_AddRef(candidate);
    } else {
	/* We can't do the math on the destination token, find one
	 * that is capable of doing it
	 */
	source = nssTrustDomain_FindTokenForAlgorithm(td, ap);
    }
    return source;
}

NSS_IMPLEMENT NSSSymmetricKey *
nssTrustDomain_GenerateSymmetricKey
(
  NSSTrustDomain *td,
  const NSSAlgorithmAndParameters *ap,
  PRUint32 keysize,
  NSSToken *destination,
  NSSCallback *uhhOpt
)
{
    PRStatus status;
    PRBool temporary;
    NSSToken *source;
    nssSession *session = NULL;
    nssCryptokiObject *key = NULL;
    nssPKIObject *pkio = NULL;
    NSSSymmetricKey *rvKey = NULL;
    NSSSlot *slot;

    source = nssTrustDomain_FindSourceToken(td, ap, destination);
    if (!source) {
	return (NSSSymmetricKey *)NULL;
    }
    temporary = (source != destination); /* will we have to move it? */

    /* The key will be private, so login is required */
    slot = nssToken_GetSlot(destination);
    status = nssSlot_Login(slot, uhhOpt);
    nssSlot_Destroy(slot);
    if (status == PR_FAILURE) {
	goto loser;
    }

    session = nssTrustDomain_GetSessionForToken(td, source, temporary);
    if (!session) {
	goto loser;
    }

    /* XXX */
    key = nssToken_GenerateSymmetricKey(source, session, ap, keysize,
                                        NULL, !temporary, 0, 0);
    if (!key) {
	goto loser;
    }

    if (source != destination) {
	/* Have to move the key to the destination, and destroy the source */
	nssCryptokiObject *destKey;
	nssSession *copySession;
	copySession = nssTrustDomain_GetSessionForToken(td, destination, 
	                                                PR_TRUE);
	if (!copySession) {
	    goto loser;
	}
	destKey = nssCryptokiSymmetricKey_Copy(key, session,
	                                       destination, copySession,
	                                       PR_TRUE);
	nssCryptokiObject_DeleteStoredObject(key);
	key = NULL;
	nssSession_Destroy(copySession);
	if (!destKey) {
	    goto loser;
	}
	key = destKey;
    }

    pkio = nssPKIObject_Create(NULL, key, td, NULL);
    if (!pkio) {
	goto loser;
    }

    rvKey = nssSymmetricKey_Create(pkio);
    if (!rvKey) {
	goto loser;
    }
    nssToken_Destroy(source);
    return rvKey;

loser:
    if (session) {
	nssSession_Destroy(session);
    }
    if (key) {
	nssCryptokiObject_Destroy(key);
    }
    if (pkio) {
	nssPKIObject_Destroy(pkio);
    }
    nssToken_Destroy(source);
    return (NSSSymmetricKey *)NULL;
}

NSS_IMPLEMENT NSSSymmetricKey *
NSSTrustDomain_GenerateSymmetricKey
(
  NSSTrustDomain *td,
  const NSSAlgorithmAndParameters *ap,
  PRUint32 keysize,
  NSSToken *destination,
  NSSCallback *uhhOpt
)
{
    return nssTrustDomain_GenerateSymmetricKey(td, ap, keysize, 
                                               destination, uhhOpt);
}

NSS_IMPLEMENT NSSSymmetricKey *
NSSTrustDomain_GenerateSymmetricKeyFromPassword
(
  NSSTrustDomain *td,
  const NSSAlgorithmAndParameters *ap,
  NSSUTF8 *passwordOpt, /* if null, prompt */
  NSSToken *destinationOpt,
  NSSCallback *uhhOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSSymmetricKey *
NSSTrustDomain_FindSymmetricKeyByAlgorithmAndKeyID
(
  NSSTrustDomain *td,
  NSSOID *algorithm,
  NSSItem *keyID,
  NSSCallback *uhhOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT PRStatus *
NSSTrustDomain_TraversePrivateKeys
(
  NSSTrustDomain *td,
  PRStatus (*callback)(NSSPrivateKey *vk, void *arg),
  void *arg
)
{
    PRStatus status;
    NSSToken *token = NULL;
    NSSSlot **slots = NULL;
    NSSSlot **slotp;
    nssPKIObjectCollection *collection = NULL;
    nssPKIObjectCallback pkiCallback;
    nssUpdateLevel updateLevel;
    collection = nssPrivateKeyCollection_Create(td, NULL);
    if (!collection) {
	return (PRStatus *)NULL;
    }
    /* obtain the current set of active slots in the trust domain */
    slots = nssTrustDomain_GetActiveSlots(td, &updateLevel);
    if (!slots) {
	goto loser;
    }
    /* iterate over the slots */
    for (slotp = slots; *slotp; slotp++) {
	/* get the token for the slot, if present */
	token = nssSlot_GetToken(*slotp);
	if (token) {
	    nssSession *session;
	    nssCryptokiObject **instances;
	    nssTokenSearchType tokenOnly = nssTokenSearchType_TokenOnly;
	    /* get a session for the token */
	    session = nssTrustDomain_GetSessionForToken(td, token, PR_FALSE);
	    if (!session) {
		nssToken_Destroy(token);
		goto loser;
	    }
	    /* perform the traversal */
	    instances = nssToken_FindPrivateKeys(token,
	                                         session,
	                                         tokenOnly,
	                                         0, &status);
	    nssToken_Destroy(token);
	    status = nssPKIObjectCollection_AddInstances(collection, 
	                                                 instances, 0);
	    nss_ZFreeIf(instances);
	    if (status != PR_SUCCESS) {
		goto loser;
	    }
	}
	slotp++;
    }
    /* Traverse the collection */
    pkiCallback.func.pvkey = callback;
    pkiCallback.arg = arg;
    status = nssPKIObjectCollection_Traverse(collection, &pkiCallback);
    /* clean up */
    nssPKIObjectCollection_Destroy(collection);
    NSSSlotArray_Destroy(slots);
    return NULL;
loser:
    if (collection) {
	nssPKIObjectCollection_Destroy(collection);
    }
    if (slots) {
	NSSSlotArray_Destroy(slots);
    }
    return NULL;
}

NSS_IMPLEMENT NSSCryptoContext *
nssTrustDomain_CreateCryptoContext
(
  NSSTrustDomain *td,
  const NSSAlgorithmAndParameters *apOpt,
  NSSCallback *uhhOpt
)
{
    NSSCallback *uhh;
    if (uhhOpt) {
	uhh = uhhOpt;
    } else {
	uhh = td->callback;
    }
    return nssCryptoContext_Create(td, apOpt, uhh);
}

NSS_IMPLEMENT NSSCryptoContext *
NSSTrustDomain_CreateCryptoContext
(
  NSSTrustDomain *td,
  const NSSAlgorithmAndParameters *apOpt,
  NSSCallback *uhhOpt
)
{
    return nssTrustDomain_CreateCryptoContext(td, apOpt, uhhOpt);
}

NSS_IMPLEMENT NSSCryptoContext *
NSSTrustDomain_CreateCryptoContextForAlgorithm
(
  NSSTrustDomain *td,
  NSSOID *algorithm
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

