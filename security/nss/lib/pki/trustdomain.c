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

#ifndef PKI1_H
#include "pki1.h"
#endif /* PKI1_H */

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
  nssCertCache *cache;
#endif /* CERT_CACHE */
};


NSS_IMPLEMENT NSSTrustDomain *
NSSTrustDomain_Create (
  NSSUTF8 *moduleOpt,
  NSSUTF8 *uriOpt,
  NSSUTF8 *opaqueOpt,
  void *reserved
)
{
    NSSArena *arena;
    NSSTrustDomain *rvTD;
    arena = nssArena_Create();
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
    rvTD->cache = nssCertCache_Create();
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
NSSTrustDomain_Destroy (
  NSSTrustDomain *td
)
{
    if (--td->refCount == 0) {
	nssSlotList_Destroy(td->slots.forCerts);
	nssSlotList_Destroy(td->slots.forCiphers);
	nssSlotList_Destroy(td->slots.forTrust);
#ifdef CERT_CACHE
	nssCertCache_Destroy(td->cache);
#endif /* CERT_CACHE */
	/* Destroy the trust domain */
	nssArena_Destroy(td->arena);
    }
    return PR_SUCCESS;
}

/* XXX */
NSS_IMPLEMENT NSSSlot **
nssTrustDomain_GetActiveSlots (
  NSSTrustDomain *td,
  nssUpdateLevel *updateLevel
)
{
    /* XXX */
    *updateLevel = 1;
    return nssSlotList_GetSlots(td->slots.forCerts);
}

/* XXX */
NSS_IMPLEMENT nssSession *
nssTrustDomain_GetSessionForToken (
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
nssTrustDomain_IsUpToDate (
  NSSTrustDomain *td,
  nssUpdateLevel updateLevel
)
{
    return (updateLevel > 0);
}
#endif /* CERT_CACHE */

NSS_IMPLEMENT PRStatus
NSSTrustDomain_SetDefaultCallback (
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
nssTrustDomain_GetDefaultCallback (
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
NSSTrustDomain_GetDefaultCallback (
  NSSTrustDomain *td,
  PRStatus *statusOpt
)
{
    return nssTrustDomain_GetDefaultCallback(td, statusOpt);
}

NSS_IMPLEMENT PRStatus
NSSTrustDomain_LoadModule (
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
NSSTrustDomain_AddModule (
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
NSSTrustDomain_DisableToken (
  NSSTrustDomain *td,
  NSSToken *token,
  NSSError why
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return PR_FAILURE;
}

NSS_IMPLEMENT PRStatus
NSSTrustDomain_EnableToken (
  NSSTrustDomain *td,
  NSSToken *token
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return PR_FAILURE;
}

NSS_IMPLEMENT PRStatus
NSSTrustDomain_IsTokenEnabled (
  NSSTrustDomain *td,
  NSSToken *token,
  NSSError *whyOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return PR_FAILURE;
}

NSS_IMPLEMENT NSSSlot *
NSSTrustDomain_FindSlotByName (
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
nssTrustDomain_FindTokenByName (
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
NSSTrustDomain_FindTokenByName (
  NSSTrustDomain *td,
  NSSUTF8 *tokenName
)
{
    return nssTrustDomain_FindTokenByName(td, tokenName);
}

NSS_IMPLEMENT NSSToken *
NSSTrustDomain_FindTokenBySlotName (
  NSSTrustDomain *td,
  NSSUTF8 *slotName
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSToken *
nssTrustDomain_FindTokenForAlgorithm (
  NSSTrustDomain *td,
  NSSOIDTag alg
)
{
    return nssSlotList_GetBestTokenForAlgorithm(td->slots.forCerts, alg);
}

NSS_IMPLEMENT NSSToken *
NSSTrustDomain_FindTokenForAlgorithm (
  NSSTrustDomain *td,
  NSSOIDTag algorithm
)
{
    return nssTrustDomain_FindTokenForAlgorithm(td, algorithm);
}

NSS_IMPLEMENT NSSToken *
NSSTrustDomain_FindBestTokenForAlgorithms (
  NSSTrustDomain *td,
  NSSOIDTag *algorithms,
  PRUint32 nAlgorithmsOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSToken *
nssTrustDomain_FindTokenForAlgNParam (
  NSSTrustDomain *td,
  const NSSAlgNParam *ap
)
{
    return nssSlotList_GetBestTokenForAlgNParam(td->slots.forCerts, ap);
}

NSS_IMPLEMENT NSSToken *
NSSTrustDomain_FindTokenForAlgNParam (
  NSSTrustDomain *td,
  const NSSAlgNParam *ap
)
{
    return nssTrustDomain_FindTokenForAlgNParam(td, ap);
}

NSS_IMPLEMENT PRStatus
NSSTrustDomain_Login (
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
NSSTrustDomain_Logout (
  NSSTrustDomain *td
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return PR_FAILURE;
}

NSS_IMPLEMENT NSSCert *
NSSTrustDomain_ImportCert (
  NSSTrustDomain *td,
  NSSCert *c,
  NSSToken *destinationOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCert *
nssTrustDomain_ImportEncodedCert (
  NSSTrustDomain *td,
  NSSBER *ber,
  NSSUTF8 *nicknameOpt,
  NSSToken *destinationOpt
)
{
    PRStatus status;
    NSSCert *c = NULL;
    NSSToken *destination = destinationOpt; /* XXX */

    c = nssCert_Decode(ber);
    if (!c) {
	goto loser;
    }
    status = nssCert_CopyToToken(c, destination, nicknameOpt);
    if (status == PR_FAILURE) {
	goto loser;
    }
    return c;
loser:
    if (c) {
	nssCert_Destroy(c);
    }
    return (NSSCert *)NULL;
}

NSS_IMPLEMENT NSSCert *
NSSTrustDomain_ImportEncodedCert (
  NSSTrustDomain *td,
  NSSBER *ber,
  NSSUTF8 *nicknameOpt,
  NSSToken *destinationOpt
)
{
    return nssTrustDomain_ImportEncodedCert(td, ber, 
                                            nicknameOpt, destinationOpt);
}

NSS_IMPLEMENT NSSCertChain *
NSSTrustDomain_ImportEncodedCertChain (
  NSSTrustDomain *td,
  NSSBER *ber,
  NSSToken *destinationOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSPrivateKey *
nssTrustDomain_ImportEncodedPrivateKey (
  NSSTrustDomain *td,
  NSSBER *ber,
  NSSKeyPairType keyPairType,
  NSSOperations operations,
  NSSProperties properties,
  NSSUTF8 *passwordOpt,
  NSSCallback *uhhOpt,
  NSSToken *destination
)
{
    return nssPrivateKey_Decode(ber, keyPairType, 
                                operations, properties, 
                                passwordOpt, uhhOpt, destination, td, NULL);
}

NSS_IMPLEMENT NSSPrivateKey *
NSSTrustDomain_ImportEncodedPrivateKey (
  NSSTrustDomain *td,
  NSSBER *ber,
  NSSKeyPairType keyPairType,
  NSSOperations operations,
  NSSProperties properties,
  NSSUTF8 *passwordOpt,
  NSSCallback *uhhOpt,
  NSSToken *destination
)
{
    return nssTrustDomain_ImportEncodedPrivateKey(td, ber, keyPairType,
                                                  operations, properties, 
                                                  passwordOpt, uhhOpt, 
                                                  destination);
}

NSS_IMPLEMENT NSSPublicKey *
NSSTrustDomain_ImportEncodedPublicKey (
  NSSTrustDomain *td,
  NSSBER *ber,
  NSSToken *destinationOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCert **
nssTrustDomain_FindCertsByNickname (
  NSSTrustDomain *td,
  NSSUTF8 *name,
  NSSCert *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
)
{
    PRStatus status;
    PRUint32 numRemaining;
    NSSToken *token = NULL;
    NSSSlot **slots = NULL;
    NSSSlot **slotp;
    NSSCert **rvCerts = NULL;
    nssPKIObjectCollection *collection = NULL;
    nssUpdateLevel updateLevel;
#ifdef CERT_CACHE
    /* see if this search is already cached */
    rvCerts = nssCertCache_FindCertsByNickname(td->cache,
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
    collection = nssCertCollection_Create(td, rvCerts);
    if (!collection) {
	return (NSSCert **)NULL;
    }
    nssCertArray_Destroy(rvCerts);
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
	    instances = nssToken_FindCertsByNickname(token,
	                                                    session,
	                                                    name,
	                                                    tokenOnly,
	                                                    numRemaining,
	                                                    &status);
	    nssToken_Destroy(token);
	    nssSession_Destroy(session);
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
    rvCerts = nssPKIObjectCollection_GetCerts(collection,
                                                     rvOpt, maximumOpt,
                                                     arenaOpt);
#ifdef CERT_CACHE
    /* Cache this search.  It is up-to-date w.r.t. the time when it grabbed
     * the slots to search.
     */
    status = nssCertCache_AddCertsForNickname(td->cache,
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
    return (NSSCert **)NULL;
}

NSS_IMPLEMENT NSSCert **
NSSTrustDomain_FindCertsByNickname (
  NSSTrustDomain *td,
  NSSUTF8 *name,
  NSSCert *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
)
{
    return nssTrustDomain_FindCertsByNickname(td,
                                                     name,
                                                     rvOpt,
                                                     maximumOpt,
                                                     arenaOpt);
}

NSS_IMPLEMENT NSSCert *
nssTrustDomain_FindBestCertByNickname (
  NSSTrustDomain *td,
  NSSUTF8 *name,
  NSSTime time,
  NSSUsages *usagesOpt,
  NSSPolicies *policiesOpt
)
{
    NSSCert **nicknameCerts;
    NSSCert *rvCert = NULL;
    nicknameCerts = nssTrustDomain_FindCertsByNickname(td, name,
                                                              NULL,
                                                              0,
                                                              NULL);
    if (nicknameCerts) {
	rvCert = nssCertArray_FindBestCert(nicknameCerts,
                                                         time,
                                                         usagesOpt,
                                                         policiesOpt);
	nssCertArray_Destroy(nicknameCerts);
    }
    return rvCert;
}

NSS_IMPLEMENT NSSCert *
NSSTrustDomain_FindBestCertByNickname (
  NSSTrustDomain *td,
  NSSUTF8 *name,
  NSSTime time,
  NSSUsages *usagesOpt,
  NSSPolicies *policiesOpt
)
{
    return nssTrustDomain_FindBestCertByNickname(td,
                                                        name,
                                                        time,
                                                        usagesOpt,
                                                        policiesOpt);
}

NSS_IMPLEMENT NSSCert **
nssTrustDomain_FindCertsBySubject (
  NSSTrustDomain *td,
  NSSDER *subject,
  NSSCert *rvOpt[],
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    PRStatus status;
    PRUint32 numRemaining;
    NSSToken *token = NULL;
    NSSSlot **slots = NULL;
    NSSSlot **slotp;
    NSSCert **rvCerts = NULL;
    nssPKIObjectCollection *collection = NULL;
    nssUpdateLevel updateLevel;
#ifdef CERT_CACHE
    /* see if this search is already cached */
    rvCerts = nssCertCache_FindCertsBySubject(td->cache,
                                                            subject,
                                                            rvOpt,
                                                            maximumOpt,
                                                            arenaOpt,
                                                            &updateLevel);
    if (nssTrustDomain_IsUpToDate(td, updateLevel)) {
	return rvCerts;
    }
#endif /* CERT_CACHE */
    collection = nssCertCollection_Create(td, rvCerts);
    if (!collection) {
	return (NSSCert **)NULL;
    }
    nssCertArray_Destroy(rvCerts);
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
	    instances = nssToken_FindCertsBySubject(token,
	                                                   session,
	                                                   subject,
	                                                   tokenOnly,
	                                                   numRemaining,
	                                                   &status);
	    nssToken_Destroy(token);
	    nssSession_Destroy(session);
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
    rvCerts = nssPKIObjectCollection_GetCerts(collection,
                                                     rvOpt, maximumOpt,
                                                     arenaOpt);
#ifdef CERT_CACHE
    status = nssCertCache_AddCertsForSubject(td->cache,
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
    return (NSSCert **)NULL;
}

NSS_IMPLEMENT NSSCert **
NSSTrustDomain_FindCertsBySubject (
  NSSTrustDomain *td,
  NSSDER *subject,
  NSSCert *rvOpt[],
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    return nssTrustDomain_FindCertsBySubject(td, 
                                                    subject,
                                                    rvOpt,
                                                    maximumOpt,
                                                    arenaOpt);
}

NSS_IMPLEMENT NSSCert *
nssTrustDomain_FindBestCertBySubject (
  NSSTrustDomain *td,
  NSSDER *subject,
  NSSTime time,
  NSSUsages *usagesOpt,
  NSSPolicies *policiesOpt
)
{
    NSSCert **subjectCerts;
    NSSCert *rvCert = NULL;
    subjectCerts = nssTrustDomain_FindCertsBySubject(td, subject,
                                                            NULL,
                                                            0,
                                                            NULL);
    if (subjectCerts) {
	rvCert = nssCertArray_FindBestCert(subjectCerts,
                                                         time,
                                                         usagesOpt,
                                                         policiesOpt);
	nssCertArray_Destroy(subjectCerts);
    }
    return rvCert;
}

NSS_IMPLEMENT NSSCert *
NSSTrustDomain_FindBestCertBySubject (
  NSSTrustDomain *td,
  NSSDER *subject,
  NSSTime time,
  NSSUsages *usagesOpt,
  NSSPolicies *policiesOpt
)
{
    return nssTrustDomain_FindBestCertBySubject(td,
                                                       subject,
                                                       time,
                                                       usagesOpt,
                                                       policiesOpt);
}

NSS_IMPLEMENT NSSCert *
NSSTrustDomain_FindBestCertByNameComponents (
  NSSTrustDomain *td,
  NSSUTF8 *nameComponents,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCert **
NSSTrustDomain_FindCertsByNameComponents (
  NSSTrustDomain *td,
  NSSUTF8 *nameComponents,
  NSSCert *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCert *
nssTrustDomain_FindCertByIssuerAndSerialNumber (
  NSSTrustDomain *td,
  NSSDER *issuer,
  NSSDER *serial
)
{
    PRStatus status;
    NSSToken *token = NULL;
    NSSSlot **slots = NULL;
    NSSSlot **slotp;
    NSSCert *rvCert = NULL;
    nssPKIObjectCollection *collection = NULL;
    nssUpdateLevel updateLevel;
#ifdef CERT_CACHE
    /* see if this search is already cached */
    rvCert = nssCertCache_FindCertByIssuerAndSerialNumber(
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
	    instance = nssToken_FindCertByIssuerAndSerialNumber(
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
		    collection = nssCertCollection_Create(td, NULL);
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
	(void)nssPKIObjectCollection_GetCerts(collection, 
	                                             &rvCert, 1, NULL);
	nssPKIObjectCollection_Destroy(collection);
	if (!rvCert) {
	    goto loser;
	}
    }
#ifdef CERT_CACHE
    status = nssCertCache_AddCert(td->cache, rvCert, 
                                                issuer, serial, updateLevel);
#endif /* CERT_CACHE */
    nssSlotArray_Destroy(slots);
    return rvCert;
loser:
    if (slots) {
	nssSlotArray_Destroy(slots);
    }
    return (NSSCert *)NULL;
}

NSS_IMPLEMENT NSSCert *
NSSTrustDomain_FindCertByIssuerAndSerialNumber (
  NSSTrustDomain *td,
  NSSDER *issuer,
  NSSDER *serial
)
{
    return nssTrustDomain_FindCertByIssuerAndSerialNumber(td,
                                                                 issuer,
                                                                 serial);
}

NSS_IMPLEMENT NSSCert *
nssTrustDomain_FindCertByEncodedCert (
  NSSTrustDomain *td,
  NSSBER *ber
)
{
    NSSCert *rvCert = NULL;
#if 0
    PRStatus status;
    NSSDER issuer = { 0 };
    NSSDER serial = { 0 };
    NSSArena *arena = nssArena_Create();
    if (!arena) {
	return (NSSCert *)NULL;
    }
    /* XXX this is not generic...  will any cert crack into issuer/serial? */
    status = nssPKIX509_GetIssuerAndSerialFromDER(ber, arena, &issuer, &serial);
    if (status != PR_SUCCESS) {
	goto finish;
    }
    rvCert = nssTrustDomain_FindCertByIssuerAndSerialNumber(td,
                                                                   &issuer,
                                                                   &serial);
finish:
    nssArena_Destroy(arena);
#endif
    return rvCert;
}

NSS_IMPLEMENT NSSCert *
NSSTrustDomain_FindCertByEncodedCert (
  NSSTrustDomain *td,
  NSSBER *ber
)
{
    return nssTrustDomain_FindCertByEncodedCert(td, ber);
}

NSS_IMPLEMENT NSSCert **
nssTrustDomain_FindCertsByID (
  NSSTrustDomain *td,
  NSSItem *id,
  NSSCert **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    PRStatus status;
    PRUint32 numRemaining;
    NSSToken *token = NULL;
    NSSSlot **slots = NULL;
    NSSSlot **slotp;
    NSSCert **rvCerts = NULL;
    nssPKIObjectCollection *collection = NULL;
    nssUpdateLevel updateLevel;
    collection = nssCertCollection_Create(td, rvCerts);
    if (!collection) {
	return (NSSCert **)NULL;
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
	    instances = nssToken_FindCertsByID(token,
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
    rvCerts = nssPKIObjectCollection_GetCerts(collection,
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
    return (NSSCert **)NULL;
}

NSS_IMPLEMENT NSSCert *
NSSTrustDomain_FindBestCertByEmail (
  NSSTrustDomain *td,
  NSSASCII7 *email,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt
)
{
    return 0;
}

NSS_IMPLEMENT NSSCert **
nssTrustDomain_FindCertsByEmail (
  NSSTrustDomain *td,
  NSSASCII7 *email,
  NSSCert *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCert **
NSSTrustDomain_FindCertsByEmail (
  NSSTrustDomain *td,
  NSSASCII7 *email,
  NSSCert *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
)
{
    return nssTrustDomain_FindCertsByEmail(td, email, rvOpt,
                                                  maximumOpt, arenaOpt);
}

NSS_IMPLEMENT NSSCert *
NSSTrustDomain_FindCertByOCSPHash (
  NSSTrustDomain *td,
  NSSItem *hash
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

/* XXX don't keep this */
struct stuff_str {
  NSSCert **rv;
  PRUint32 rvCount;
  PRUint32 rvSize;
  PRUint32 rvLimit;
  NSSArena *arenaOpt;
};

static PRStatus
get_user(NSSCert *c, void *arg)
{
    struct stuff_str *stuff = (struct stuff_str *)arg;
    if (nssCert_IsPrivateKeyAvailable(c, NULL, NULL)) {
	if (stuff->rvSize == 0) {
	    stuff->rvSize = 2;
	    stuff->rv = nss_ZNEWARRAY(stuff->arenaOpt, NSSCert *,
	                              stuff->rvSize + 1);
	    if (!stuff->rv) return PR_FAILURE;
	} else if (stuff->rvCount == stuff->rvSize && stuff->rvLimit == 0) {
	    stuff->rvSize *= 2;
	    stuff->rv = nss_ZREALLOCARRAY(stuff->rv, NSSCert *,
	                                  stuff->rvSize + 1);
	    if (!stuff->rv) return PR_FAILURE;
	} else {
	    return PR_SUCCESS;
	}
	stuff->rv[stuff->rvCount++] = nssCert_AddRef(c);
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSCert **
nssTrustDomain_FindUserCerts (
  NSSTrustDomain *td,
  NSSCert **rvOpt,
  PRUint32 rvLimit,
  NSSArena *arenaOpt
)
{
    PRStatus *status;
    /* XXX need something more efficient */
    struct stuff_str stuff;
    stuff.rv = rvOpt;
    stuff.rvCount = 0;
    stuff.rvSize = rvOpt ? rvLimit : 0;
    stuff.rvLimit = rvLimit;
    stuff.arenaOpt = arenaOpt;
    status = nssTrustDomain_TraverseCerts(td, get_user, &stuff);
    if (status && *status == PR_FAILURE) {
	nssCertArray_Destroy(stuff.rv);
	stuff.rv = NULL;
    }
    return stuff.rv;
}

NSS_IMPLEMENT NSSCert **
NSSTrustDomain_FindUserCerts (
  NSSTrustDomain *td,
  NSSCert **rvOpt,
  PRUint32 rvLimit,
  NSSArena *arenaOpt
)
{
    return nssTrustDomain_FindUserCerts(td, rvOpt, rvLimit, arenaOpt);
}

NSS_IMPLEMENT NSSCert *
nssTrustDomain_FindBestUserCert (
  NSSTrustDomain *td,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt
)
{
    NSSCert **userCerts;
    NSSCert *rvCert;

    userCerts = nssTrustDomain_FindUserCerts(td, NULL, 0, NULL);
    if (!userCerts) {
	return (NSSCert *)NULL;
    }
    rvCert = nssCertArray_FindBestCert(userCerts, time, usages, policiesOpt);
    nssCertArray_Destroy(userCerts);
    return rvCert;
}

NSS_IMPLEMENT NSSCert *
NSSTrustDomain_FindBestUserCert (
  NSSTrustDomain *td,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt
)
{
    return nssTrustDomain_FindBestUserCert(td, time, usages, policiesOpt);
}

NSS_IMPLEMENT NSSCert *
nssTrustDomain_FindBestUserCertForSSLClientAuth (
  NSSTrustDomain *td,
  NSSUTF8 *sslHostOpt,
  NSSDER **rootCAsOpt,
  PRUint32 rootCAsMaxOpt,
  const NSSAlgNParam *apOpt,
  NSSPolicies *policiesOpt
)
{
    NSSCert **userCerts;
    NSSCert *rvCert = NULL;
    NSSCert **c;
    NSSUsages clientCA = { NSSUsage_SSLClient, 0 };

    userCerts = nssTrustDomain_FindUserCerts(td, NULL, 0, NULL);
    if (!userCerts) {
	return (NSSCert *)NULL;
    }
    for (c = userCerts; *c; c++) {
	if (!nssCert_IsValidAtTime(*c, NSSTime_Now(), NULL)) {
	    continue;
	}
	if (rootCAsOpt &&
	    !nssCert_HasCANameInChain(*c, rootCAsOpt, rootCAsMaxOpt,
	                              NSSTime_Now(), &clientCA, NULL)) 
	{
	    continue;
	}
	/* XXX ... */
	if (PR_TRUE) { /* everything passed */
	    rvCert = nssCert_AddRef(*c);
	    break;
	}
    }
    nssCertArray_Destroy(userCerts);
    return rvCert;
}

NSS_IMPLEMENT NSSCert *
NSSTrustDomain_FindBestUserCertForSSLClientAuth (
  NSSTrustDomain *td,
  NSSUTF8 *sslHostOpt,
  NSSDER **rootCAsOpt,
  PRUint32 rootCAsMaxOpt,
  const NSSAlgNParam *apOpt,
  NSSPolicies *policiesOpt
)
{
    return nssTrustDomain_FindBestUserCertForSSLClientAuth(td, sslHostOpt,
                                                           rootCAsOpt,
                                                           rootCAsMaxOpt,
                                                           apOpt,
                                                           policiesOpt);
}

NSS_IMPLEMENT NSSCert **
NSSTrustDomain_FindUserCertsForSSLClientAuth (
  NSSTrustDomain *td,
  NSSUTF8 *sslHostOpt,
  NSSDER *rootCAsOpt[], /* null pointer for none */
  PRUint32 rootCAsMaxOpt, /* zero means list is null-terminated */
  const NSSAlgNParam *apOpt,
  NSSPolicies *policiesOpt,
  NSSCert **rvOpt,
  PRUint32 rvLimit, /* zero for no limit */
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCert *
NSSTrustDomain_FindBestUserCertForEmailSigning (
  NSSTrustDomain *td,
  NSSASCII7 *signerOpt,
  NSSASCII7 *recipientOpt,
  /* anything more here? */
  const NSSAlgNParam *apOpt,
  NSSPolicies *policiesOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCert **
NSSTrustDomain_FindUserCertsForEmailSigning (
  NSSTrustDomain *td,
  NSSASCII7 *signerOpt,
  NSSASCII7 *recipientOpt,
  /* anything more here? */
  const NSSAlgNParam *apOpt,
  NSSPolicies *policiesOpt,
  NSSCert **rvOpt,
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
nssTrustDomain_TraverseCerts (
  NSSTrustDomain *td,
  PRStatus (*callback)(NSSCert *c, void *arg),
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
    collection = nssCertCollection_Create(td, NULL);
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
	    status = nssToken_TraverseCerts(token,
	                                           session,
	                                           tokenOnly,
	                                           collector,
	                                           collection);
	    nssToken_Destroy(token);
	    nssSession_Destroy(session);
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

NSS_IMPLEMENT PRStatus *
NSSTrustDomain_TraverseCerts (
  NSSTrustDomain *td,
  PRStatus (*callback)(NSSCert *c, void *arg),
  void *arg
)
{
    return nssTrustDomain_TraverseCerts(td, callback, arg);
}

NSS_IMPLEMENT nssTrust *
nssTrustDomain_FindTrustForCert (
  NSSTrustDomain *td,
  NSSCert *c
)
{
    PRStatus status;
    NSSSlot **slots;
    NSSSlot **slotp;
    NSSToken *token;
    NSSDER *encoding = nssCert_GetEncoding(c);
    NSSDER *issuer = nssCert_GetIssuer(c);
    NSSDER *serial = nssCert_GetSerialNumber(c);
    nssTokenSearchType tokenOnly = nssTokenSearchType_TokenOnly;
    nssCryptokiObject *to = NULL;
    nssPKIObject *pkio = NULL;
    nssTrust *rvt = NULL;
    nssUpdateLevel updateLevel;
    slots = nssTrustDomain_GetActiveSlots(td, &updateLevel);
    if (!slots) {
	return (nssTrust *)NULL;
    }
    for (slotp = slots; *slotp; slotp++) {
	token = nssSlot_GetToken(*slotp);
	if (token) {
		/* XXX */
	    nssSession *session = nssToken_CreateSession(token, PR_FALSE);
	    if (!session) {
		continue;
	    }
	    to = nssToken_FindTrustForCert(token, session, 
	                                          encoding,
	                                          issuer,
	                                          serial,
	                                          tokenOnly);
	    nssSession_Destroy(session);
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
    return (nssTrust *)NULL;
}

NSS_IMPLEMENT NSSCRL **
nssTrustDomain_FindCRLsBySubject (
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
nssTrustDomain_GenerateKeyPair (
  NSSTrustDomain *td,
  const NSSAlgNParam *ap,
  NSSPublicKey **pbkOpt,
  NSSPrivateKey **pvkOpt,
  NSSUTF8 *nicknameOpt,
  NSSProperties properties,
  NSSOperations operations,
  NSSToken *destination,
  NSSCallback *uhhOpt
)
{
    nssPKIObjectCreator creator;

    creator.td = td;
    creator.vd = NULL;
    creator.destination = destination;
    creator.session = NULL; /* allow it to create one */
    creator.persistent = PR_TRUE;
    creator.ap = ap;
    creator.uhh = uhhOpt ? uhhOpt : td->callback;
    creator.nickname = nicknameOpt;
    creator.properties = properties;
    creator.operations = operations;
    return nssPKIObjectCreator_GenerateKeyPair(&creator, pbkOpt, pvkOpt);
}

NSS_IMPLEMENT PRStatus
NSSTrustDomain_GenerateKeyPair (
  NSSTrustDomain *td,
  const NSSAlgNParam *ap,
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
nssTrustDomain_FindSourceToken (
  NSSTrustDomain *td,
  const NSSAlgNParam *ap,
  NSSToken *candidate
)
{
    NSSToken *source = NULL;
    if (nssToken_DoesAlgNParam(candidate, ap)) {
	/* We can do the math on the destination token */
	source = nssToken_AddRef(candidate);
    } else {
	/* We can't do the math on the destination token, find one
	 * that is capable of doing it
	 */
	source = nssTrustDomain_FindTokenForAlgNParam(td, ap);
    }
    return source;
}

NSS_IMPLEMENT NSSSymKey *
nssTrustDomain_GenerateSymKey (
  NSSTrustDomain *td,
  const NSSAlgNParam *ap,
  PRUint32 keysize,
  NSSToken *destination,
  NSSCallback *uhhOpt
)
{
    nssPKIObjectCreator creator;

    creator.td = td;
    creator.vd = NULL;
    creator.destination = destination;
    creator.session = NULL; /* allow it to create one */
    creator.persistent = PR_TRUE;
    creator.ap = ap;
    creator.uhh = uhhOpt ? uhhOpt : td->callback;
    creator.nickname = NULL /*nicknameOpt*/;
    creator.properties = 0 /*properties*/;
    creator.operations = 0 /*operations*/;
    return nssPKIObjectCreator_GenerateSymKey(&creator, keysize);
}

NSS_IMPLEMENT NSSSymKey *
NSSTrustDomain_GenerateSymKey (
  NSSTrustDomain *td,
  const NSSAlgNParam *ap,
  PRUint32 keysize,
  NSSToken *destination,
  NSSCallback *uhhOpt
)
{
    return nssTrustDomain_GenerateSymKey(td, ap, keysize, 
                                               destination, uhhOpt);
}

NSS_IMPLEMENT NSSSymKey *
NSSTrustDomain_GenerateSymKeyFromPassword (
  NSSTrustDomain *td,
  const NSSAlgNParam *ap,
  NSSUTF8 *passwordOpt, /* if null, prompt */
  NSSToken *destinationOpt,
  NSSCallback *uhhOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSSymKey *
NSSTrustDomain_FindSymKeyByAlgorithmAndKeyID (
  NSSTrustDomain *td,
  NSSOIDTag algorithm,
  NSSItem *keyID,
  NSSCallback *uhhOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT PRStatus *
NSSTrustDomain_TraversePrivateKeys (
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

NSS_IMPLEMENT NSSVolatileDomain *
nssTrustDomain_CreateVolatileDomain (
  NSSTrustDomain *td,
  NSSCallback *uhhOpt
)
{
    return nssVolatileDomain_Create(td, uhhOpt);
}

NSS_IMPLEMENT NSSVolatileDomain *
NSSTrustDomain_CreateVolatileDomain (
  NSSTrustDomain *td,
  NSSCallback *uhhOpt
)
{
    return nssTrustDomain_CreateVolatileDomain(td, uhhOpt);
}

NSS_IMPLEMENT NSSCryptoContext *
nssTrustDomain_CreateCryptoContext (
  NSSTrustDomain *td,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhhOpt
)
{
    NSSCallback *uhh;
    if (uhhOpt) {
	uhh = uhhOpt;
    } else {
	uhh = td->callback;
    }
    return nssCryptoContext_Create(td, NULL, apOpt, uhh);
}

NSS_IMPLEMENT NSSCryptoContext *
NSSTrustDomain_CreateCryptoContext (
  NSSTrustDomain *td,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhhOpt
)
{
    return nssTrustDomain_CreateCryptoContext(td, apOpt, uhhOpt);
}

NSS_IMPLEMENT NSSCryptoContext *
NSSTrustDomain_CreateCryptoContextForAlgorithm (
  NSSTrustDomain *td,
  NSSOIDTag algorithm
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

