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

struct NSSTrustDomainStr {
  PRInt32 refCount;
  NSSArena *arena;
  NSSCallback *callback;
  struct {
    nssSlotList *forCerts;
    nssSlotList *forCiphers;
    nssSlotList *forTrust;
  } slots;
  nssPKIObjectTable *objectTable;
  nssTokenStore *tokenStore;
  nssPKIDatabase *pkidb;
};


NSS_IMPLEMENT NSSTrustDomain *
nssTrustDomain_Create (
  NSSUTF8 *dbPath,
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
    rvTD->objectTable = nssPKIObjectTable_Create(arena);
    if (!rvTD->objectTable) {
	goto loser;
    }
    rvTD->tokenStore = nssTokenStore_Create(rvTD, NULL);
    if (!rvTD->tokenStore) {
	goto loser;
    }
    rvTD->pkidb = nssPKIDatabase_Open(rvTD, dbPath, 0);
    if (!rvTD->pkidb) {
	goto loser;
    }
    rvTD->arena = arena;
    rvTD->refCount = 1;
    return rvTD;
loser:
    if (rvTD->objectTable) {
	nssPKIObjectTable_Destroy(rvTD->objectTable);
    }
    if (rvTD->tokenStore) {
	nssTokenStore_Destroy(rvTD->tokenStore);
    }
    if (rvTD->pkidb) {
	nssPKIDatabase_Close(rvTD->pkidb);
    }
    nssArena_Destroy(arena);
    return (NSSTrustDomain *)NULL;
}

NSS_IMPLEMENT NSSTrustDomain *
NSSTrustDomain_Create (
  NSSUTF8 *dbPath,
  NSSUTF8 *uriOpt,
  NSSUTF8 *opaqueOpt,
  void *reserved
)
{
    return nssTrustDomain_Create(dbPath, uriOpt, opaqueOpt, reserved);
}

NSS_IMPLEMENT PRStatus
nssTrustDomain_Destroy (
  NSSTrustDomain *td
)
{
    if (--td->refCount == 0) {
	nssSlotList_Destroy(td->slots.forCerts);
	nssSlotList_Destroy(td->slots.forCiphers);
	nssSlotList_Destroy(td->slots.forTrust);
	nssPKIObjectTable_Destroy(td->objectTable);
	nssTokenStore_Destroy(td->tokenStore);
	nssPKIDatabase_Close(td->pkidb);
	/* Destroy the trust domain */
	nssArena_Destroy(td->arena);
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT PRStatus
NSSTrustDomain_Destroy (
  NSSTrustDomain *td
)
{
    return nssTrustDomain_Destroy(td);
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

NSS_IMPLEMENT nssPKIObjectTable *
nssTrustDomain_GetObjectTable (
  NSSTrustDomain *td
)
{
    return td->objectTable;
}

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
nssTrustDomain_AddModule (
  NSSTrustDomain *td,
  NSSModule *module
)
{
    PRStatus status;
    PRUint32 order;
    /* XXX would be nice if order indicated whether or not to include it */
    order = nssModule_GetCertOrder(module);
    status = nssSlotList_AddModuleSlots(td->slots.forCerts, module, order);
    {
	/* XXX ugh */
	NSSSlot **slots, **sp;
	NSSToken *token;
	slots = nssModule_GetSlots(module);
	for (sp = slots; *sp; sp++) {
	    token = nssSlot_GetToken(*sp);
	    status |= nssTokenStore_AddToken(td->tokenStore, token);
	    nssToken_Destroy(token);
	}
	nssSlotArray_Destroy(slots);
    }
    return status;
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
nssTrustDomain_Login (
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
NSSTrustDomain_Login (
  NSSTrustDomain *td,
  NSSCallback *uhhOpt
)
{
    return nssTrustDomain_Login(td, uhhOpt);
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
    NSSItem nickIt;

    nickIt.data = nicknameOpt;
    nickIt.size = nicknameOpt ? nssUTF8_Length(nicknameOpt, NULL) : 0;

    c = nssCert_Decode(ber, &nickIt, NULL, td, NULL);
    if (!c) {
	goto loser;
    }
    if (destinationOpt) { /* ja vohl? */
	status = nssTokenStore_ImportCert(td->tokenStore, c, 
	                                  nicknameOpt, destination);
    } else {
	status = nssPKIDatabase_ImportCert(td->pkidb, c, nicknameOpt, NULL);
    }
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

/* XXX do all token certs need to by synched with db certs first? */
NSS_IMPLEMENT NSSCert **
nssTrustDomain_FindCertsByNickname (
  NSSTrustDomain *td,
  NSSUTF8 *name,
  NSSCert **rvOpt,
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
)
{
    NSSCert **rvCerts, **dbCerts;
    /* Locate all token certs */
    rvCerts = nssTokenStore_FindCertsByNickname(td->tokenStore, name, 
                                                rvOpt, maximumOpt, arenaOpt);
    if (rvOpt || maximumOpt > 0) {
	PRIntn count = nssObjectArray_Count((void **)rvCerts);
	maximumOpt -= count;
	if (maximumOpt == 0) return rvCerts;
	if (rvOpt) rvOpt += count;
    }
    dbCerts = nssPKIDatabase_FindCertsByNickname(td->pkidb, name,
                                                 rvOpt, maximumOpt, arenaOpt);
    if (!rvOpt) {
	rvCerts = nssCertArray_Join(rvCerts, dbCerts);
    }
    return rvCerts;
}

NSS_IMPLEMENT NSSCert **
NSSTrustDomain_FindCertsByNickname (
  NSSTrustDomain *td,
  NSSUTF8 *name,
  NSSCert **rvOpt,
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
)
{
    return nssTrustDomain_FindCertsByNickname(td, name,
                                              rvOpt, maximumOpt, arenaOpt);
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
                                           time, usagesOpt, policiesOpt);
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
    return nssTrustDomain_FindBestCertByNickname(td, name,
                                                 time, usagesOpt, policiesOpt);
}

NSS_IMPLEMENT NSSCert **
nssTrustDomain_FindCertsBySubject (
  NSSTrustDomain *td,
  NSSDER *subject,
  NSSCert **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    NSSCert **rvCerts, **dbCerts;
    rvCerts = nssTokenStore_FindCertsBySubject(td->tokenStore, subject, 
                                               rvOpt, maximumOpt, arenaOpt);
    if (rvOpt || maximumOpt > 0) {
	PRIntn count = nssObjectArray_Count((void **)rvCerts);
	maximumOpt -= count;
	if (maximumOpt == 0) return rvCerts;
	if (rvOpt) rvOpt += count;
    }
    dbCerts = nssPKIDatabase_FindCertsBySubject(td->pkidb, subject,
                                                rvOpt, maximumOpt, arenaOpt);
    if (!rvOpt) {
	rvCerts = nssCertArray_Join(rvCerts, dbCerts);
    }
    return rvCerts;
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
    return nssTrustDomain_FindCertsBySubject(td, subject,
                                             rvOpt, maximumOpt, arenaOpt);
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
                                                     NULL, 0, NULL);
    if (subjectCerts) {
	rvCert = nssCertArray_FindBestCert(subjectCerts,
                                           time, usagesOpt, policiesOpt);
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
    return nssTrustDomain_FindBestCertBySubject(td, subject,
                                                time, usagesOpt, policiesOpt);
}

NSS_IMPLEMENT NSSCert *
nssTrustDomain_FindCertByIssuerAndSerialNumber (
  NSSTrustDomain *td,
  NSSDER *issuer,
  NSSDER *serial
)
{
    NSSCert *rvCert = NULL;
    rvCert = nssTokenStore_FindCertByIssuerAndSerialNumber(td->tokenStore,
                                                           issuer,
                                                           serial);
    if (!rvCert) {
	rvCert = nssPKIDatabase_FindCertByIssuerAndSerialNumber(td->pkidb,
                                                                issuer,
                                                                serial);
    }
    return rvCert;
}

NSS_IMPLEMENT NSSCert *
NSSTrustDomain_FindCertByIssuerAndSerialNumber (
  NSSTrustDomain *td,
  NSSDER *issuer,
  NSSDER *serial
)
{
    return nssTrustDomain_FindCertByIssuerAndSerialNumber(td, issuer, serial);
}

NSS_IMPLEMENT NSSCert *
nssTrustDomain_FindCertByEncodedCert (
  NSSTrustDomain *td,
  NSSBER *ber
)
{
    NSSCert *rvCert = NULL;
    rvCert = nssTokenStore_FindCertByEncodedCert(td->tokenStore, ber);
    if (!rvCert) {
	rvCert = nssPKIDatabase_FindCertByEncodedCert(td->pkidb, ber);
    }
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
    NSSCert **rvCerts = NULL;
    rvCerts = nssTokenStore_FindCertsByID(td->tokenStore, id, 
                                          rvOpt, maximumOpt, arenaOpt);
    /* XXX bother with db? */
    return rvCerts;
}

NSS_IMPLEMENT NSSCert **
nssTrustDomain_FindCertsByEmail (
  NSSTrustDomain *td,
  NSSASCII7 *email,
  NSSCert **rvOpt,
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
)
{
    NSSCert **rvCerts, **dbCerts;
    rvCerts = nssTokenStore_FindCertsByEmail(td->tokenStore, email, 
                                             rvOpt, maximumOpt, arenaOpt);
    if (rvOpt || maximumOpt > 0) {
	PRIntn count = nssObjectArray_Count((void **)rvCerts);
	maximumOpt -= count;
	if (maximumOpt == 0) return rvCerts;
	if (rvOpt) rvOpt += count;
    }
    dbCerts = nssPKIDatabase_FindCertsByEmail(td->pkidb, email,
                                              rvOpt, maximumOpt, arenaOpt);
    if (!rvOpt) {
	rvCerts = nssCertArray_Join(rvCerts, dbCerts);
    }
    return rvCerts;
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
NSSTrustDomain_FindBestCertByEmail (
  NSSTrustDomain *td,
  NSSASCII7 *email,
  NSSTime time,
  NSSUsages *usagesOpt,
  NSSPolicies *policiesOpt
)
{
    NSSCert **emailCerts;
    NSSCert *rvCert = NULL;
    emailCerts = nssTrustDomain_FindCertsByEmail(td, email,
                                                 NULL, 0, NULL);
    if (emailCerts) {
	rvCert = nssCertArray_FindBestCert(emailCerts,
                                           time, usagesOpt, policiesOpt);
	nssCertArray_Destroy(emailCerts);
    }
    return rvCert;
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
    PRStatus status;
    /* XXX need something more efficient */
    struct stuff_str stuff;
    stuff.rv = rvOpt;
    stuff.rvCount = 0;
    stuff.rvSize = rvOpt ? rvLimit : 0;
    stuff.rvLimit = rvLimit;
    stuff.arenaOpt = arenaOpt;
    status = nssTokenStore_TraverseCerts(td->tokenStore, get_user, &stuff);
    if (status == PR_FAILURE) {
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

struct token_cert_filter_str {
  PRStatus (*callback)(NSSCert *c, void *arg);
  void *arg;
};

static PRStatus 
filter_out_token_certs(NSSCert *c, void *arg)
{
    struct token_cert_filter_str *cbarg = (struct token_cert_filter_str *)arg;
    if (nssCert_CountInstances(c) == 0) {
	return cbarg->callback(c, cbarg->arg);
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT PRStatus *
nssTrustDomain_TraverseCerts (
  NSSTrustDomain *td,
  PRStatus (*callback)(NSSCert *c, void *arg),
  void *arg
)
{
    PRStatus status;
    /* XXX this is mighty ugly */
    struct token_cert_filter_str cbarg;
    cbarg.callback = callback;
    cbarg.arg = arg;
    status = nssTokenStore_TraverseCerts(td->tokenStore, callback, arg);
    nssPKIDatabase_TraverseCerts(td->pkidb, filter_out_token_certs, &cbarg);
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

NSS_IMPLEMENT NSSCRL **
nssTrustDomain_FindCRLsBySubject (
  NSSTrustDomain *td,
  NSSDER *subject
)
{
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

NSS_IMPLEMENT NSSPublicKey *
nssTrustDomain_FindPublicKeyByID (
  NSSTrustDomain *td,
  NSSItem *keyID
)
{
    return nssTokenStore_FindPublicKeyByID(td->tokenStore, keyID);
}

NSS_IMPLEMENT NSSPrivateKey *
nssTrustDomain_FindPrivateKeyByID (
  NSSTrustDomain *td,
  NSSItem *keyID
)
{
    return nssTokenStore_FindPrivateKeyByID(td->tokenStore, keyID);
}

NSS_IMPLEMENT PRStatus *
nssTrustDomain_TraversePrivateKeys (
  NSSTrustDomain *td,
  PRStatus (*callback)(NSSPrivateKey *vk, void *arg),
  void *arg
)
{
    return nssTokenStore_TraversePrivateKeys(td->tokenStore, callback, arg);
}

NSS_IMPLEMENT PRStatus *
NSSTrustDomain_TraversePrivateKeys (
  NSSTrustDomain *td,
  PRStatus (*callback)(NSSPrivateKey *vk, void *arg),
  void *arg
)
{
    return nssTrustDomain_TraversePrivateKeys(td, callback, arg);
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

NSS_IMPLEMENT PRStatus
nssTrustDomain_SetCertTrust (
  NSSTrustDomain *td,
  NSSCert *c,
  nssTrust *trust
)
{
    return nssPKIDatabase_SetCertTrust(td->pkidb, c, trust);
}

