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

#ifndef NSSCKEPV_H
#include "nssckepv.h"
#endif /* NSSCKEPV_H */

#ifndef DEVM_H
#include "devm.h"
#endif /* DEVM_H */

#ifndef CKHELPER_H
#include "ckhelper.h"
#endif /* CKHELPER_H */

/* The number of object handles to grab during each call to C_FindObjects */
#define OBJECT_STACK_SIZE 16

struct NSSTokenStr
{
  struct nssDeviceBaseStr base;
  NSSSlot *slot;  /* Peer */
  CK_TOKEN_INFO info;
  CK_MECHANISM_TYPE_PTR mechanisms;
  CK_ULONG numMechanisms;
  nssSession *defaultSession;
  nssTokenObjectCache *cache;
};

NSS_IMPLEMENT NSSToken *
nssToken_Create
(
  CK_SLOT_ID slotID,
  NSSSlot *peer
)
{
    NSSArena *arena;
    NSSToken *rvToken;
    nssSession *session = NULL;
    NSSUTF8 *tokenName = NULL;
    PRUint32 length;
    PRBool readWrite;
    CK_RV ckrv;
    void *epv = nssSlot_GetCryptokiEPV(peer);
    arena = NSSArena_Create();
    if(!arena) {
	return (NSSToken *)NULL;
    }
    rvToken = nss_ZNEW(arena, NSSToken);
    if (!rvToken) {
	goto loser;
    }
    /* Get token information */
    ckrv = CKAPI(epv)->C_GetTokenInfo(slotID, &rvToken->info);
    if (ckrv != CKR_OK) {
	/* set an error here, eh? */
	goto loser;
    }
    /* Grab the slot description from the PKCS#11 fixed-length buffer */
    length = nssPKCS11String_Length(rvToken->info.label, 
                                    sizeof(rvToken->info.label));
    if (length > 0) {
	tokenName = nssUTF8_Create(arena, nssStringType_UTF8String, 
	                           (void *)rvToken->info.label, length);
	if (!tokenName) {
	    goto loser;
	}
    }
    /* Open a default session handle for the token. */
    if (rvToken->info.ulMaxSessionCount == 1) {
	/* if the token can only handle one session, it must be RW. */
	readWrite = PR_TRUE;
    } else {
	readWrite = PR_FALSE;
    }
    session = nssSlot_CreateSession(peer, readWrite);
    if (session == NULL) {
	goto loser;
    }
    /* TODO: seed the RNG here */
    rvToken->base.arena = arena;
    rvToken->base.refCount = 1;
    rvToken->base.name = tokenName;
    rvToken->base.lock = PZ_NewLock(nssNSSILockOther); /* XXX */
    if (!rvToken->base.lock) {
	goto loser;
    }
    rvToken->slot = peer; /* slot owns ref to token */
    ckrv = CKAPI(epv)->C_GetMechanismList(slotID, NULL, 
                                          &rvToken->numMechanisms);
    if (ckrv != CKR_OK) {
	goto loser;
    }
    if (rvToken->numMechanisms > 0) {
	rvToken->mechanisms = nss_ZNEWARRAY(arena, CK_MECHANISM_TYPE,
	                                    rvToken->numMechanisms);
	if (!rvToken->mechanisms) {
	    goto loser;
	}
	ckrv = CKAPI(epv)->C_GetMechanismList(slotID, rvToken->mechanisms,
	                                      &rvToken->numMechanisms);
	if (ckrv != CKR_OK) {
	    goto loser;
	}
    }
    rvToken->defaultSession = session;
    if (nssSlot_IsHardware(peer)) {
	rvToken->cache = nssTokenObjectCache_Create(rvToken, 
	                                            PR_TRUE, PR_TRUE, PR_TRUE);
	if (!rvToken->cache) {
	    nssSlot_Destroy(peer);
	    goto loser;
	}
    }
    return rvToken;
loser:
    if (session) {
	nssSession_Destroy(session);
    }
    nssArena_Destroy(arena);
    return (NSSToken *)NULL;
}

NSS_IMPLEMENT PRStatus
nssToken_Destroy
(
  NSSToken *tok
)
{
    if (tok) {
	PR_AtomicDecrement(&tok->base.refCount);
	if (tok->base.refCount == 0) {
	    nssSession_Destroy(tok->defaultSession);
	    PZ_DestroyLock(tok->base.lock);
	    nssTokenObjectCache_Destroy(tok->cache);
	    return nssArena_Destroy(tok->base.arena);
	}
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT void
nssToken_Remove
(
  NSSToken *tok
)
{
    nssTokenObjectCache_Clear(tok->cache);
}

NSS_IMPLEMENT void
NSSToken_Destroy
(
  NSSToken *tok
)
{
    (void)nssToken_Destroy(tok);
}

NSS_IMPLEMENT NSSToken *
nssToken_AddRef
(
  NSSToken *tok
)
{
    PR_AtomicIncrement(&tok->base.refCount);
    return tok;
}

NSS_IMPLEMENT PRStatus
NSSToken_GetInfo
(
  NSSToken *token,
  NSSTokenInfo *tokenInfo
)
{
    tokenInfo->name = token->base.name;
#if 0
    tokenInfo->manufacturerID = token->manufacturerID;
    tokenInfo->model = token->model;
    tokenInfo->serialNumber = token->serialNumber;
#endif
    tokenInfo->sessions.maximum = token->info.ulMaxSessionCount;
    tokenInfo->sessions.active = token->info.ulSessionCount;
    tokenInfo->readWriteSessions.maximum = token->info.ulMaxRwSessionCount;
    tokenInfo->readWriteSessions.active = token->info.ulRwSessionCount;
    tokenInfo->pinRange.maximum = token->info.ulMaxPinLen;
    tokenInfo->pinRange.minimum = token->info.ulMinPinLen;
    tokenInfo->publicMemory.total = token->info.ulTotalPublicMemory;
    tokenInfo->publicMemory.free = token->info.ulFreePublicMemory;
    tokenInfo->privateMemory.total = token->info.ulTotalPrivateMemory;
    tokenInfo->privateMemory.free = token->info.ulFreePrivateMemory;
    tokenInfo->hardwareVersion.major = token->info.hardwareVersion.major;
    tokenInfo->hardwareVersion.minor = token->info.hardwareVersion.minor;
    tokenInfo->firmwareVersion.major = token->info.firmwareVersion.major;
    tokenInfo->firmwareVersion.minor = token->info.firmwareVersion.minor;
    tokenInfo->hasRNG = token->info.flags & CKF_RNG;
    tokenInfo->isWriteProtected = token->info.flags & CKF_WRITE_PROTECTED;
    tokenInfo->isLoginRequired = token->info.flags & CKF_LOGIN_REQUIRED;
    tokenInfo->isPINInitialized = token->info.flags & 
                                                  CKF_USER_PIN_INITIALIZED;
    tokenInfo->hasClock = token->info.flags & CKF_CLOCK_ON_TOKEN;
    tokenInfo->hasProtectedAuthPath = token->info.flags & 
                                         CKF_PROTECTED_AUTHENTICATION_PATH;
    tokenInfo->supportsDualCrypto = token->info.flags & 
                                                CKF_DUAL_CRYPTO_OPERATIONS;
    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSSlot *
nssToken_GetSlot
(
  NSSToken *tok
)
{
    return nssSlot_AddRef(tok->slot);
}

NSS_IMPLEMENT NSSSlot *
NSSToken_GetSlot
(
  NSSToken *tok
)
{
    return nssToken_GetSlot(tok);
}

NSS_IMPLEMENT NSSModule *
nssToken_GetModule
(
  NSSToken *token
)
{
    return nssSlot_GetModule(token->slot);
}

NSS_IMPLEMENT void *
nssToken_GetCryptokiEPV
(
  NSSToken *token
)
{
    return nssSlot_GetCryptokiEPV(token->slot);
}

NSS_IMPLEMENT nssSession *
nssToken_GetDefaultSession
(
  NSSToken *token
)
{
    return token->defaultSession;
}

NSS_IMPLEMENT NSSUTF8 *
nssToken_GetName
(
  NSSToken *tok
)
{
    return tok->base.name;
}

NSS_IMPLEMENT NSSUTF8 *
NSSToken_GetName
(
  NSSToken *token
)
{
    return nssToken_GetName(token);
}

NSS_IMPLEMENT nssTokenObjectCache *
nssToken_GetObjectCache
(
  NSSToken *token
)
{
    return token->cache;
}

NSS_IMPLEMENT PRBool
nssToken_DoesAlgorithm
(
  NSSToken *token,
  const NSSAlgorithmAndParameters *ap
)
{
    CK_ULONG ul;
    CK_MECHANISM_PTR pMech = nssAlgorithmAndParameters_GetMechanism(ap);
    for (ul = 0; ul < token->numMechanisms; ul++) {
	if (pMech->mechanism == token->mechanisms[ul]) {
	    return PR_TRUE;
	}
    }
    return PR_FALSE;
}

NSS_IMPLEMENT nssSession *
nssToken_CreateSession
(
  NSSToken *token,
  PRBool readWrite
)
{
    return nssSlot_CreateSession(token->slot, readWrite);
}

NSS_IMPLEMENT PRBool
nssToken_IsLoginRequired
(
  NSSToken *token
)
{
    return (token->info.flags & CKF_LOGIN_REQUIRED);
}

NSS_IMPLEMENT PRBool
nssToken_NeedsPINInitialization
(
  NSSToken *token
)
{
    return (!(token->info.flags & CKF_USER_PIN_INITIALIZED));
}

static nssCryptokiObject *
import_object
(
  NSSToken *tok,
  nssSession *session,
  CK_ATTRIBUTE_PTR objectTemplate,
  CK_ULONG otsize
)
{
    CK_RV ckrv;
    CK_OBJECT_HANDLE handle;
    nssCryptokiObject *object = NULL;
    void *epv = nssToken_GetCryptokiEPV(tok);

    PR_ASSERT(session); /* XXX for now, should remove later */
    PR_ASSERT(session->isRW);

    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_CreateObject(session->handle, 
                                      objectTemplate, otsize,
                                      &handle);
    nssSession_ExitMonitor(session);
    if (ckrv == CKR_OK) {
	object = nssCryptokiObject_Create(tok, session, handle);
    }
    return object;
}

static nssCryptokiObject **
create_objects_from_handles
(
  NSSToken *tok,
  nssSession *session,
  CK_OBJECT_HANDLE *handles,
  PRUint32 numH
)
{
    nssCryptokiObject **objects;
    objects = nss_ZNEWARRAY(NULL, nssCryptokiObject *, numH + 1);
    if (objects) {
	PRInt32 i;
	for (i=0; i<(PRInt32)numH; i++) {
	    objects[i] = nssCryptokiObject_Create(tok, session, handles[i]);
	    if (!objects[i]) {
		for (--i; i>0; --i) {
		    nssCryptokiObject_Destroy(objects[i]);
		}
		return (nssCryptokiObject **)NULL;
	    }
	}
    }
    return objects;
}

static nssCryptokiObject **
find_objects
(
  NSSToken *tok,
  nssSession *session,
  CK_ATTRIBUTE_PTR obj_template,
  CK_ULONG otsize,
  PRUint32 maximumOpt,
  PRStatus *statusOpt
)
{
    CK_RV ckrv;
    CK_ULONG count;
    CK_OBJECT_HANDLE *objectHandles;
    CK_OBJECT_HANDLE staticObjects[OBJECT_STACK_SIZE];
    PRUint32 arraySize, numHandles;
    void *epv = nssToken_GetCryptokiEPV(tok);
    nssCryptokiObject **objects;

    PR_ASSERT(session); /* XXX remove later */

    /* the arena is only for the array of object handles */
    if (maximumOpt > 0) {
	arraySize = maximumOpt;
    } else {
	arraySize = OBJECT_STACK_SIZE;
    }
    numHandles = 0;
    if (arraySize <= OBJECT_STACK_SIZE) {
	objectHandles = staticObjects;
    } else {
	objectHandles = nss_ZNEWARRAY(NULL, CK_OBJECT_HANDLE, arraySize);
    }
    if (!objectHandles) {
	goto loser;
    }
    nssSession_EnterMonitor(session); /* ==== session lock === */
    /* Initialize the find with the template */
    ckrv = CKAPI(epv)->C_FindObjectsInit(session->handle, 
                                         obj_template, otsize);
    if (ckrv != CKR_OK) {
	nssSession_ExitMonitor(session);
	goto loser;
    }
    while (PR_TRUE) {
	/* Issue the find for up to arraySize - numHandles objects */
	ckrv = CKAPI(epv)->C_FindObjects(session->handle, 
	                                 objectHandles + numHandles, 
	                                 arraySize - numHandles, 
	                                 &count);
	if (ckrv != CKR_OK) {
	    nssSession_ExitMonitor(session);
	    goto loser;
	}
	/* bump the number of found objects */
	numHandles += count;
	if (maximumOpt > 0 || numHandles < arraySize) {
	    /* When a maximum is provided, the search is done all at once,
	     * so the search is finished.  If the number returned was less 
	     * than the number sought, the search is finished.
	     */
	    break;
	}
	/* the array is filled, double it and continue */
	arraySize *= 2;
	if (objectHandles == staticObjects) {
	    objectHandles = nss_ZNEWARRAY(NULL,CK_OBJECT_HANDLE, arraySize);
	    if (objectHandles) {
		nsslibc_memcpy(objectHandles, staticObjects, 
			       OBJECT_STACK_SIZE * sizeof(objectHandles[1]));
	    }
	} else {
	    objectHandles = nss_ZREALLOCARRAY(objectHandles, 
	                                  CK_OBJECT_HANDLE, 
	                                  arraySize);
	}
	if (!objectHandles) {
	    nssSession_ExitMonitor(session);
	    goto loser;
	}
    }
    ckrv = CKAPI(epv)->C_FindObjectsFinal(session->handle);
    nssSession_ExitMonitor(session); /* ==== end session lock === */
    if (ckrv != CKR_OK) {
	goto loser;
    }
    if (numHandles > 0) {
	objects = create_objects_from_handles(tok, session,
	                                      objectHandles, numHandles);
    } else {
	objects = NULL;
    }
    if (objectHandles && objectHandles != staticObjects) {
	nss_ZFreeIf(objectHandles);
    }
    if (statusOpt) *statusOpt = PR_SUCCESS;
    return objects;
loser:
    if (objectHandles && objectHandles != staticObjects) {
	nss_ZFreeIf(objectHandles);
    }
    if (statusOpt) *statusOpt = PR_FAILURE;
    return (nssCryptokiObject **)NULL;
}

static nssCryptokiObject **
find_objects_by_template
(
  NSSToken *token,
  nssSession *session,
  CK_ATTRIBUTE_PTR obj_template,
  CK_ULONG otsize,
  PRUint32 maximumOpt,
  PRStatus *statusOpt
)
{
    CK_OBJECT_CLASS objclass;
    nssCryptokiObject **objects = NULL;
    PRUint32 i;
    for (i=0; i<otsize; i++) {
	if (obj_template[i].type == CKA_CLASS) {
	    objclass = *(CK_OBJECT_CLASS *)obj_template[i].pValue;
	    break;
	}
    }
    PR_ASSERT(i < otsize);
    /* If these objects are being cached, try looking there first */
    if (token->cache && 
        nssTokenObjectCache_HaveObjectClass(token->cache, objclass)) 
    {
	PRStatus status;
	objects = nssTokenObjectCache_FindObjectsByTemplate(token->cache,
	                                                    objclass,
	                                                    obj_template,
	                                                    otsize,
	                                                    maximumOpt,
	                                                    &status);
	if (status == PR_SUCCESS) {
	    if (statusOpt) *statusOpt = status;
	    return objects;
	}
    }
    /* Either they are not cached, or cache failed; look on token. */
    objects = find_objects(token, session, 
                           obj_template, otsize, 
                           maximumOpt, statusOpt);
    return objects;
}

NSS_IMPLEMENT nssCryptokiObject *
nssToken_ImportCertificate
(
  NSSToken *tok,
  nssSession *session,
  NSSCertificateType certType,
  NSSItem *id,
  NSSUTF8 *nickname,
  NSSDER *encoding,
  NSSDER *issuer,
  NSSDER *subject,
  NSSDER *serial,
  NSSASCII7 *email,
  PRBool asTokenObject
)
{
    CK_CERTIFICATE_TYPE cert_type;
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE cert_tmpl[10];
    CK_ULONG ctsize;
    nssTokenSearchType searchType;
    nssCryptokiObject *rvObject = NULL;

    if (certType == NSSCertificateType_PKIX) {
	cert_type = CKC_X_509;
    } else {
	return (nssCryptokiObject *)NULL;
    }
    NSS_CK_TEMPLATE_START(cert_tmpl, attr, ctsize);
    if (asTokenObject) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
	searchType = nssTokenSearchType_TokenOnly;
    } else {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_false);
	searchType = nssTokenSearchType_SessionOnly;
    }
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_CLASS,            &g_ck_class_cert);
    NSS_CK_SET_ATTRIBUTE_VAR( attr, CKA_CERTIFICATE_TYPE,  cert_type);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_ID,                id);
    NSS_CK_SET_ATTRIBUTE_UTF8(attr, CKA_LABEL,             nickname);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_VALUE,             encoding);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_ISSUER,            issuer);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_SUBJECT,           subject);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_SERIAL_NUMBER,     serial);
    if (email) {
	NSS_CK_SET_ATTRIBUTE_UTF8(attr, CKA_NETSCAPE_EMAIL,    email);
    }
    NSS_CK_TEMPLATE_FINISH(cert_tmpl, attr, ctsize);
    /* see if the cert is already there */
    rvObject = nssToken_FindCertificateByIssuerAndSerialNumber(tok,
                                                               session,
                                                               issuer,
                                                               serial,
                                                               searchType,
                                                               NULL);
    if (rvObject) {
	/* according to PKCS#11, label, ID, issuer, and serial number 
	 * may change after the object has been created.  For PKIX, the
	 * last two attributes can't change, so for now we'll only worry
	 * about the first two.
	 */
	NSS_CK_TEMPLATE_START(cert_tmpl, attr, ctsize);
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_ID,    id);
	NSS_CK_SET_ATTRIBUTE_UTF8(attr, CKA_LABEL, nickname);
	NSS_CK_TEMPLATE_FINISH(cert_tmpl, attr, ctsize);
	/* reset the mutable attributes on the token */
	nssCKObject_SetAttributes(rvObject->handle, 
	                          cert_tmpl, ctsize,
	                          session, tok->slot);
	if (!rvObject->label && nickname) {
	    rvObject->label = nssUTF8_Duplicate(nickname, NULL);
	}
    } else {
	/* Import the certificate onto the token */
	rvObject = import_object(tok, session, cert_tmpl, ctsize);
    }
    if (rvObject && tok->cache) {
	/* The cache will overwrite the attributes if the object already
	 * exists.
	 */
	nssTokenObjectCache_ImportObject(tok->cache, rvObject,
	                                 CKO_CERTIFICATE,
	                                 cert_tmpl, ctsize);
    }
    return rvObject;
}

/* traverse all certificates - this should only happen if the token
 * has been marked as "traversable"
 */
NSS_IMPLEMENT nssCryptokiObject **
nssToken_FindCertificates
(
  NSSToken *token,
  nssSession *session,
  nssTokenSearchType searchType,
  PRUint32 maximumOpt,
  PRStatus *statusOpt
)
{
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE cert_template[2];
    CK_ULONG ctsize;
    nssCryptokiObject **objects;
    NSS_CK_TEMPLATE_START(cert_template, attr, ctsize);
    /* Set the search to token/session only if provided */
    if (searchType == nssTokenSearchType_SessionOnly) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_false);
    } else if (searchType == nssTokenSearchType_TokenOnly ||
               searchType == nssTokenSearchType_TokenForced) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
    }
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_CLASS, &g_ck_class_cert);
    NSS_CK_TEMPLATE_FINISH(cert_template, attr, ctsize);

    if (searchType == nssTokenSearchType_TokenForced) {
	objects = find_objects(token, session,
	                       cert_template, ctsize,
	                       maximumOpt, statusOpt);
    } else {
	objects = find_objects_by_template(token, session,
	                                   cert_template, ctsize,
	                                   maximumOpt, statusOpt);
    }
    return objects;
}

NSS_IMPLEMENT nssCryptokiObject **
nssToken_FindCertificatesBySubject
(
  NSSToken *token,
  nssSession *session,
  NSSDER *subject,
  nssTokenSearchType searchType,
  PRUint32 maximumOpt,
  PRStatus *statusOpt
)
{
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE subj_template[3];
    CK_ULONG stsize;
    nssCryptokiObject **objects;
    NSS_CK_TEMPLATE_START(subj_template, attr, stsize);
    /* Set the search to token/session only if provided */
    if (searchType == nssTokenSearchType_SessionOnly) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_false);
    } else if (searchType == nssTokenSearchType_TokenOnly) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
    }
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_CLASS, &g_ck_class_cert);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_SUBJECT, subject);
    NSS_CK_TEMPLATE_FINISH(subj_template, attr, stsize);
    /* now locate the token certs matching this template */
    objects = find_objects_by_template(token, session,
                                       subj_template, stsize,
                                       maximumOpt, statusOpt);
    return objects;
}

NSS_IMPLEMENT nssCryptokiObject **
nssToken_FindCertificatesByNickname
(
  NSSToken *token,
  nssSession *session,
  NSSUTF8 *name,
  nssTokenSearchType searchType,
  PRUint32 maximumOpt,
  PRStatus *statusOpt
)
{
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE nick_template[3];
    CK_ULONG ntsize;
    nssCryptokiObject **objects;
    NSS_CK_TEMPLATE_START(nick_template, attr, ntsize);
    NSS_CK_SET_ATTRIBUTE_UTF8(attr, CKA_LABEL, name);
    /* Set the search to token/session only if provided */
    if (searchType == nssTokenSearchType_SessionOnly) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_false);
    } else if (searchType == nssTokenSearchType_TokenOnly) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
    }
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_CLASS, &g_ck_class_cert);
    NSS_CK_TEMPLATE_FINISH(nick_template, attr, ntsize);
    /* now locate the token certs matching this template */
    objects = find_objects_by_template(token, session,
                                       nick_template, ntsize, 
                                       maximumOpt, statusOpt);
    if (!objects) {
	/* This is to workaround the fact that PKCS#11 doesn't specify
	 * whether the '\0' should be included.  XXX Is that still true?
	 * im - this is not needed by the current softoken.  However, I'm 
	 * leaving it in until I have surveyed more tokens to see if it needed.
	 * well, its needed by the builtin token...
	 */
	nick_template[0].ulValueLen++;
	objects = find_objects_by_template(token, session,
	                                   nick_template, ntsize, 
	                                   maximumOpt, statusOpt);
    }
    return objects;
}

/* XXX
 * This function *does not* use the token object cache, because not even
 * the softoken will return a value for CKA_NETSCAPE_EMAIL from a call
 * to GetAttributes.  The softoken does allow searches with that attribute,
 * it just won't return a value for it.
 */
NSS_IMPLEMENT nssCryptokiObject **
nssToken_FindCertificatesByEmail
(
  NSSToken *token,
  nssSession *session,
  NSSASCII7 *email,
  nssTokenSearchType searchType,
  PRUint32 maximumOpt,
  PRStatus *statusOpt
)
{
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE email_template[3];
    CK_ULONG etsize;
    nssCryptokiObject **objects;
    NSS_CK_TEMPLATE_START(email_template, attr, etsize);
    NSS_CK_SET_ATTRIBUTE_UTF8(attr, CKA_NETSCAPE_EMAIL, email);
    /* Set the search to token/session only if provided */
    if (searchType == nssTokenSearchType_SessionOnly) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_false);
    } else if (searchType == nssTokenSearchType_TokenOnly) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
    }
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_CLASS, &g_ck_class_cert);
    NSS_CK_TEMPLATE_FINISH(email_template, attr, etsize);
    /* now locate the token certs matching this template */
    objects = find_objects(token, session,
                           email_template, etsize,
                           maximumOpt, statusOpt);
    if (!objects) {
	/* This is to workaround the fact that PKCS#11 doesn't specify
	 * whether the '\0' should be included.  XXX Is that still true?
	 * im - this is not needed by the current softoken.  However, I'm 
	 * leaving it in until I have surveyed more tokens to see if it needed.
	 * well, its needed by the builtin token...
	 */
	email_template[0].ulValueLen++;
	objects = find_objects(token, session,
	                       email_template, etsize,
	                       maximumOpt, statusOpt);
    }
    return objects;
}

NSS_IMPLEMENT nssCryptokiObject **
nssToken_FindCertificatesByID
(
  NSSToken *token,
  nssSession *session,
  NSSItem *id,
  nssTokenSearchType searchType,
  PRUint32 maximumOpt,
  PRStatus *statusOpt
)
{
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE id_template[3];
    CK_ULONG idtsize;
    nssCryptokiObject **objects;
    NSS_CK_TEMPLATE_START(id_template, attr, idtsize);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_ID, id);
    /* Set the search to token/session only if provided */
    if (searchType == nssTokenSearchType_SessionOnly) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_false);
    } else if (searchType == nssTokenSearchType_TokenOnly) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
    }
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_CLASS, &g_ck_class_cert);
    NSS_CK_TEMPLATE_FINISH(id_template, attr, idtsize);
    /* now locate the token certs matching this template */
    objects = find_objects_by_template(token, session,
                                       id_template, idtsize,
                                       maximumOpt, statusOpt);
    return objects;
}

/*
 * decode the serial item and return our result.
 * NOTE serialDecode's data is really stored in serial. Don't free it.
 */
static PRStatus
nssToken_decodeSerialItem(NSSItem *serial, NSSItem *serialDecode)
{
    unsigned char *data = (unsigned char *)serial->data;
    int data_left, data_len, index;

    if ((serial->size >= 3) && (data[0] == 0x2)) {
	/* remove the der encoding of the serial number before generating the
	 * key.. */
	data_left = serial->size-2;
	data_len = data[1];
	index = 2;

	/* extended length ? (not very likely for a serial number) */
	if (data_len & 0x80) {
	    int len_count = data_len & 0x7f;

	    data_len = 0;
	    data_left -= len_count;
	    if (data_left > 0) {
		while (len_count --) {
		    data_len = (data_len << 8) | data[index++];
		}
	    } 
	}
	/* XXX leaving any leading zeros on the serial number for backwards
	 * compatibility
	 */
	/* not a valid der, must be just an unlucky serial number value */
	if (data_len == data_left) {
	    serialDecode->size = data_len;
	    serialDecode->data = &data[index];
	    return PR_SUCCESS;
	}
    }
    return PR_FAILURE;
}

NSS_IMPLEMENT nssCryptokiObject *
nssToken_FindCertificateByIssuerAndSerialNumber
(
  NSSToken *token,
  nssSession *session,
  NSSDER *issuer,
  NSSDER *serial,
  nssTokenSearchType searchType,
  PRStatus *statusOpt
)
{
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE_PTR serialAttr;
    CK_ATTRIBUTE cert_template[4];
    CK_ULONG ctsize;
    nssCryptokiObject **objects;
    nssCryptokiObject *rvObject = NULL;
    NSS_CK_TEMPLATE_START(cert_template, attr, ctsize);
    /* Set the search to token/session only if provided */
    if (searchType == nssTokenSearchType_SessionOnly) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_false);
    } else if ((searchType == nssTokenSearchType_TokenOnly) ||
               (searchType == nssTokenSearchType_TokenForced)) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
    }
    /* Set the unique id */
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_CLASS,         &g_ck_class_cert);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_ISSUER,         issuer);
    serialAttr = attr;
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_SERIAL_NUMBER,  serial);
    NSS_CK_TEMPLATE_FINISH(cert_template, attr, ctsize);
    /* get the object handle */
    if (searchType == nssTokenSearchType_TokenForced) {
	objects = find_objects(token, session,
	                       cert_template, ctsize,
	                       1, statusOpt);
    } else {
	objects = find_objects_by_template(token, session,
                                       cert_template, ctsize,
                                       1, statusOpt);
    }
    if (objects) {
	rvObject = objects[0];
	nss_ZFreeIf(objects);
    }

    /*
     * NSS used to incorrectly store serial numbers in their decoded form.
     * because of this old tokens have decoded serial numbers.
     */
    if (!objects) {
	NSSItem serialDecode;
	PRStatus status;

	status = nssToken_decodeSerialItem(serial, &serialDecode);
	if (status != PR_SUCCESS) {
	    return NULL;
	}
    	NSS_CK_SET_ATTRIBUTE_ITEM(serialAttr,CKA_SERIAL_NUMBER,&serialDecode);
	if (searchType == nssTokenSearchType_TokenForced) {
	    objects = find_objects(token, session,
	                       cert_template, ctsize,
	                       1, statusOpt);
	} else {
	    objects = find_objects_by_template(token, session,
                                       cert_template, ctsize,
                                       1, statusOpt);
	}
	if (objects) {
	    rvObject = objects[0];
	    nss_ZFreeIf(objects);
	}
    }
    return rvObject;
}

NSS_IMPLEMENT nssCryptokiObject *
nssToken_FindCertificateByEncodedCertificate
(
  NSSToken *token,
  nssSession *session,
  NSSBER *encodedCertificate,
  nssTokenSearchType searchType,
  PRStatus *statusOpt
)
{
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE cert_template[3];
    CK_ULONG ctsize;
    nssCryptokiObject **objects;
    nssCryptokiObject *rvObject = NULL;
    NSS_CK_TEMPLATE_START(cert_template, attr, ctsize);
    /* Set the search to token/session only if provided */
    if (searchType == nssTokenSearchType_SessionOnly) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_false);
    } else if (searchType == nssTokenSearchType_TokenOnly) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
    }
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_CLASS, &g_ck_class_cert);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_VALUE, encodedCertificate);
    NSS_CK_TEMPLATE_FINISH(cert_template, attr, ctsize);
    /* get the object handle */
    objects = find_objects_by_template(token, session,
                                       cert_template, ctsize,
                                       1, statusOpt);
    if (objects) {
	rvObject = objects[0];
	nss_ZFreeIf(objects);
    }
    return rvObject;
}

NSS_IMPLEMENT nssCryptokiObject **
nssToken_FindPrivateKeys
(
  NSSToken *token,
  nssSession *session,
  nssTokenSearchType searchType,
  PRUint32 maximumOpt,
  PRStatus *statusOpt
)
{
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE key_template[2];
    CK_ULONG ktsize;
    nssCryptokiObject **objects;

    NSS_CK_TEMPLATE_START(key_template, attr, ktsize);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_CLASS, &g_ck_class_privkey);
    if (searchType == nssTokenSearchType_SessionOnly) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_false);
    } else if (searchType == nssTokenSearchType_TokenOnly) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
    }
    NSS_CK_TEMPLATE_FINISH(key_template, attr, ktsize);

    objects = find_objects_by_template(token, session,
                                       key_template, ktsize, 
                                       maximumOpt, statusOpt);
    return objects;
}

/* XXX ?there are no session cert objects, so only search token objects */
NSS_IMPLEMENT nssCryptokiObject *
nssToken_FindPrivateKeyByID
(
  NSSToken *token,
  nssSession *session,
  NSSItem *keyID
)
{
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE key_template[3];
    CK_ULONG ktsize;
    nssCryptokiObject **objects;
    nssCryptokiObject *rvKey = NULL;

    NSS_CK_TEMPLATE_START(key_template, attr, ktsize);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_CLASS, &g_ck_class_privkey);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_ID, keyID);
    NSS_CK_TEMPLATE_FINISH(key_template, attr, ktsize);

    objects = find_objects_by_template(token, session,
                                       key_template, ktsize, 
                                       1, NULL);
    if (objects) {
	rvKey = objects[0];
	nss_ZFreeIf(objects);
    }
    return rvKey;
}

/* XXX ?there are no session cert objects, so only search token objects */
NSS_IMPLEMENT nssCryptokiObject *
nssToken_FindPublicKeyByID
(
  NSSToken *token,
  nssSession *session,
  NSSItem *keyID
)
{
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE key_template[3];
    CK_ULONG ktsize;
    nssCryptokiObject **objects;
    nssCryptokiObject *rvKey = NULL;

    NSS_CK_TEMPLATE_START(key_template, attr, ktsize);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_CLASS, &g_ck_class_pubkey);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_ID, keyID);
    NSS_CK_TEMPLATE_FINISH(key_template, attr, ktsize);

    objects = find_objects_by_template(token, session,
                                       key_template, ktsize, 
                                       1, NULL);
    if (objects) {
	rvKey = objects[0];
	nss_ZFreeIf(objects);
    }
    return rvKey;
}

static void
sha1_hash(NSSItem *input, NSSItem *output)
{
#ifdef NSS_3_4_CODE
    PK11SlotInfo *internal = PK11_GetInternalSlot();
    NSSToken *token = PK11Slot_GetNSSToken(internal);
#else
    NSSToken *token = nss_GetDefaultCryptoToken();
#endif
    (void)nssToken_Digest(token, token->defaultSession,
                          NSSAlgorithmAndParameters_SHA1,
                          input, output, NULL);
#ifdef NSS_3_4_CODE
    PK11_FreeSlot(token->pk11slot);
#endif
}

static void
md5_hash(NSSItem *input, NSSItem *output)
{
#ifdef NSS_3_4_CODE
    PK11SlotInfo *internal = PK11_GetInternalSlot();
    NSSToken *token = PK11Slot_GetNSSToken(internal);
#else
    NSSToken *token = nss_GetDefaultCryptoToken();
#endif
    (void)nssToken_Digest(token, token->defaultSession,
                          NSSAlgorithmAndParameters_MD5,
                          input, output, NULL);
#ifdef NSS_3_4_CODE
    PK11_FreeSlot(token->pk11slot);
#endif
}

static CK_TRUST
get_ck_trust
(
  nssTrustLevel nssTrust
)
{
    CK_TRUST t;
    switch (nssTrust) {
    case nssTrustLevel_Unknown: t = CKT_NETSCAPE_TRUST_UNKNOWN; break;
    case nssTrustLevel_NotTrusted: t = CKT_NETSCAPE_UNTRUSTED; break;
    case nssTrustLevel_TrustedDelegator: t = CKT_NETSCAPE_TRUSTED_DELEGATOR; 
	break;
    case nssTrustLevel_ValidDelegator: t = CKT_NETSCAPE_VALID_DELEGATOR; break;
    case nssTrustLevel_Trusted: t = CKT_NETSCAPE_TRUSTED; break;
    case nssTrustLevel_Valid: t = CKT_NETSCAPE_VALID; break;
    }
    return t;
}
 
NSS_IMPLEMENT nssCryptokiObject *
nssToken_ImportTrust
(
  NSSToken *tok,
  nssSession *session,
  NSSDER *certEncoding,
  NSSDER *certIssuer,
  NSSDER *certSerial,
  nssTrustLevel serverAuth,
  nssTrustLevel clientAuth,
  nssTrustLevel codeSigning,
  nssTrustLevel emailProtection,
  PRBool asTokenObject
)
{
    nssCryptokiObject *object;
    CK_OBJECT_CLASS tobjc = CKO_NETSCAPE_TRUST;
    CK_TRUST ckSA, ckCA, ckCS, ckEP;
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE trust_tmpl[10];
    CK_ULONG tsize;
    PRUint8 sha1[20]; /* this is cheating... */
    PRUint8 md5[16];
    NSSItem sha1_result, md5_result;
    sha1_result.data = sha1; sha1_result.size = sizeof sha1;
    md5_result.data = md5; md5_result.size = sizeof md5;
    sha1_hash(certEncoding, &sha1_result);
    md5_hash(certEncoding, &md5_result);
    ckSA = get_ck_trust(serverAuth);
    ckCA = get_ck_trust(clientAuth);
    ckCS = get_ck_trust(codeSigning);
    ckEP = get_ck_trust(emailProtection);
    NSS_CK_TEMPLATE_START(trust_tmpl, attr, tsize);
    if (asTokenObject) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
    } else {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_false);
    }
    NSS_CK_SET_ATTRIBUTE_VAR( attr, CKA_CLASS,           tobjc);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_ISSUER,          certIssuer);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_SERIAL_NUMBER,   certSerial);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_CERT_SHA1_HASH, &sha1_result);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_CERT_MD5_HASH,  &md5_result);
    /* now set the trust values */
    NSS_CK_SET_ATTRIBUTE_VAR(attr, CKA_TRUST_SERVER_AUTH,      ckSA);
    NSS_CK_SET_ATTRIBUTE_VAR(attr, CKA_TRUST_CLIENT_AUTH,      ckCA);
    NSS_CK_SET_ATTRIBUTE_VAR(attr, CKA_TRUST_CODE_SIGNING,     ckCS);
    NSS_CK_SET_ATTRIBUTE_VAR(attr, CKA_TRUST_EMAIL_PROTECTION, ckEP);
    NSS_CK_TEMPLATE_FINISH(trust_tmpl, attr, tsize);
    /* import the trust object onto the token */
    object = import_object(tok, session, trust_tmpl, tsize);
    if (object && tok->cache) {
	nssTokenObjectCache_ImportObject(tok->cache, object, tobjc,
	                                 trust_tmpl, tsize);
    }
    return object;
}

NSS_IMPLEMENT nssCryptokiObject **
nssToken_FindTrustObjects
(
  NSSToken *token,
  nssSession *session,
  nssTokenSearchType searchType,
  PRUint32 maximumOpt,
  PRStatus *statusOpt
)
{
    CK_OBJECT_CLASS tobjc = CKO_NETSCAPE_TRUST;
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE tobj_template[2];
    CK_ULONG tobj_size;
    nssCryptokiObject **objects;

    NSS_CK_TEMPLATE_START(tobj_template, attr, tobj_size);
    if (searchType == nssTokenSearchType_SessionOnly) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_false);
    } else if (searchType == nssTokenSearchType_TokenOnly ||
               searchType == nssTokenSearchType_TokenForced) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
    }
    NSS_CK_SET_ATTRIBUTE_VAR( attr, CKA_CLASS, tobjc);
    NSS_CK_TEMPLATE_FINISH(tobj_template, attr, tobj_size);

    if (searchType == nssTokenSearchType_TokenForced) {
	objects = find_objects(token, session,
	                       tobj_template, tobj_size,
	                       maximumOpt, statusOpt);
    } else {
	objects = find_objects_by_template(token, session,
	                                   tobj_template, tobj_size,
	                                   maximumOpt, statusOpt);
    }
    return objects;
}

NSS_IMPLEMENT nssCryptokiObject *
nssToken_FindTrustForCertificate
(
  NSSToken *token,
  nssSession *session,
  NSSDER *certEncoding,
  NSSDER *certIssuer,
  NSSDER *certSerial,
  nssTokenSearchType searchType
)
{
    CK_OBJECT_CLASS tobjc = CKO_NETSCAPE_TRUST;
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE tobj_template[5];
    CK_ULONG tobj_size;
    nssCryptokiObject *object, **objects;

    NSS_CK_TEMPLATE_START(tobj_template, attr, tobj_size);
    if (searchType == nssTokenSearchType_SessionOnly) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_false);
    } else if (searchType == nssTokenSearchType_TokenOnly) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
    }
    NSS_CK_SET_ATTRIBUTE_VAR( attr, CKA_CLASS,          tobjc);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_ISSUER,         certIssuer);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_SERIAL_NUMBER , certSerial);
    NSS_CK_TEMPLATE_FINISH(tobj_template, attr, tobj_size);
    object = NULL;
    objects = find_objects_by_template(token, session,
                                       tobj_template, tobj_size,
                                       1, NULL);
    if (objects) {
	object = objects[0];
	nss_ZFreeIf(objects);
    }
    return object;
}
 
NSS_IMPLEMENT nssCryptokiObject *
nssToken_ImportCRL
(
  NSSToken *token,
  nssSession *session,
  NSSDER *subject,
  NSSDER *encoding,
  PRBool isKRL,
  NSSUTF8 *url,
  PRBool asTokenObject
)
{
    nssCryptokiObject *object;
    CK_OBJECT_CLASS crlobjc = CKO_NETSCAPE_CRL;
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE crl_tmpl[6];
    CK_ULONG crlsize;

    NSS_CK_TEMPLATE_START(crl_tmpl, attr, crlsize);
    if (asTokenObject) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
    } else {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_false);
    }
    NSS_CK_SET_ATTRIBUTE_VAR( attr, CKA_CLASS,        crlobjc);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_SUBJECT,      subject);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_VALUE,        encoding);
    NSS_CK_SET_ATTRIBUTE_UTF8(attr, CKA_NETSCAPE_URL, url);
    if (isKRL) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_NETSCAPE_KRL, &g_ck_true);
    } else {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_NETSCAPE_KRL, &g_ck_false);
    }
    NSS_CK_TEMPLATE_FINISH(crl_tmpl, attr, crlsize);

    /* import the crl object onto the token */
    object = import_object(token, session, crl_tmpl, crlsize);
    if (object && token->cache) {
	nssTokenObjectCache_ImportObject(token->cache, object, crlobjc,
	                                 crl_tmpl, crlsize);
    }
    return object;
}

NSS_IMPLEMENT nssCryptokiObject **
nssToken_FindCRLs
(
  NSSToken *token,
  nssSession *session,
  nssTokenSearchType searchType,
  PRUint32 maximumOpt,
  PRStatus *statusOpt
)
{
    CK_OBJECT_CLASS crlobjc = CKO_NETSCAPE_CRL;
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE crlobj_template[2];
    CK_ULONG crlobj_size;
    nssCryptokiObject **objects;

    NSS_CK_TEMPLATE_START(crlobj_template, attr, crlobj_size);
    if (searchType == nssTokenSearchType_SessionOnly) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_false);
    } else if (searchType == nssTokenSearchType_TokenOnly ||
               searchType == nssTokenSearchType_TokenForced) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
    }
    NSS_CK_SET_ATTRIBUTE_VAR( attr, CKA_CLASS, crlobjc);
    NSS_CK_TEMPLATE_FINISH(crlobj_template, attr, crlobj_size);

    if (searchType == nssTokenSearchType_TokenForced) {
	objects = find_objects(token, session,
	                       crlobj_template, crlobj_size,
	                       maximumOpt, statusOpt);
    } else {
	objects = find_objects_by_template(token, session,
	                                   crlobj_template, crlobj_size,
	                                   maximumOpt, statusOpt);
    }
    return objects;
}

NSS_IMPLEMENT nssCryptokiObject **
nssToken_FindCRLsBySubject
(
  NSSToken *token,
  nssSession *session,
  NSSDER *subject,
  nssTokenSearchType searchType,
  PRUint32 maximumOpt,
  PRStatus *statusOpt
)
{
    CK_OBJECT_CLASS crlobjc = CKO_NETSCAPE_CRL;
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE crlobj_template[3];
    CK_ULONG crlobj_size;
    nssCryptokiObject **objects;

    NSS_CK_TEMPLATE_START(crlobj_template, attr, crlobj_size);
    if (searchType == nssTokenSearchType_SessionOnly) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_false);
    } else if (searchType == nssTokenSearchType_TokenOnly ||
               searchType == nssTokenSearchType_TokenForced) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
    }
    NSS_CK_SET_ATTRIBUTE_VAR( attr, CKA_CLASS, crlobjc);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_SUBJECT, subject);
    NSS_CK_TEMPLATE_FINISH(crlobj_template, attr, crlobj_size);

    objects = find_objects_by_template(token, session,
                                       crlobj_template, crlobj_size,
                                       maximumOpt, statusOpt);
    return objects;
}

#define PUBLIC_KEY_PROPS_MASK \
    (NSSProperties_PRIVATE | NSSProperties_READ_ONLY)

#define PUBLIC_KEY_OPS_MASK \
    (NSSOperations_DERIVE | NSSOperations_ENCRYPT        | \
     NSSOperations_VERIFY | NSSOperations_VERIFY_RECOVER | \
     NSSOperations_WRAP)

#define PRIVATE_KEY_PROPS_MASK \
    (NSSProperties_PRIVATE   | NSSProperties_READ_ONLY   | \
     NSSProperties_SENSITIVE | NSSProperties_EXTRACTABLE)

#define PRIVATE_KEY_OPS_MASK \
    (NSSOperations_DERIVE | NSSOperations_DECRYPT      | \
     NSSOperations_SIGN   | NSSOperations_SIGN_RECOVER | \
     NSSOperations_UNWRAP)

NSS_IMPLEMENT PRStatus
nssToken_GenerateKeyPair
(
  NSSToken *token,
  nssSession *session,
  const NSSAlgorithmAndParameters *ap,
  PRBool asTokenObjects,
  const NSSUTF8 *labelOpt,
  NSSProperties properties,
  NSSOperations operations,
  nssCryptokiObject **publicKey,
  nssCryptokiObject **privateKey
)
{
    CK_RV ckrv;
    CK_MECHANISM_PTR mechanism;
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE bk_template[11];
    CK_ATTRIBUTE vk_template[11];
    CK_ULONG btsize, vtsize;
    CK_OBJECT_HANDLE bkeyh, vkeyh;
    void *epv = nssToken_GetCryptokiEPV(token);

    mechanism = nssAlgorithmAndParameters_GetMechanism(ap);

    /*
     * Construct the public key template
     */
    NSS_CK_TEMPLATE_START(bk_template, attr, btsize);
    if (asTokenObjects) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
    } else {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_false);
    }
    if (labelOpt) {
	NSS_CK_SET_ATTRIBUTE_UTF8(attr, CKA_LABEL, labelOpt);
    }
    if (properties) {
	PRUint32 bkProps = operations & PUBLIC_KEY_PROPS_MASK;
	attr += nssCKTemplate_SetPropertyAttributes(attr,
	                                            attr - bk_template,
                                                    bkProps);
    }
    if (operations) {
	PRUint32 bkOps = operations & PUBLIC_KEY_OPS_MASK;
	attr += nssCKTemplate_SetOperationAttributes(attr, 
	                                             attr - bk_template,
	                                             bkOps);
    }
    /* Set algorithm-dependent values in the template */
    attr += nssAlgorithmAndParameters_SetTemplateValues(ap, attr,
                                                        bk_template - attr);
    NSS_CK_TEMPLATE_FINISH(bk_template, attr, btsize);

    /*
     * Construct the private key template
     */
    NSS_CK_TEMPLATE_START(vk_template, attr, vtsize);
    if (asTokenObjects) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_PRIVATE, &g_ck_true);
    } else {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_false);
    }
    if (labelOpt) {
	NSS_CK_SET_ATTRIBUTE_UTF8(attr, CKA_LABEL, labelOpt);
    }
    if (properties) {
	PRUint32 vkProps = operations & PRIVATE_KEY_PROPS_MASK;
	attr += nssCKTemplate_SetPropertyAttributes(attr,
	                                            attr - vk_template,
                                                    vkProps);
    }
    if (operations) {
	PRUint32 vkOps = operations & PRIVATE_KEY_OPS_MASK;
	attr += nssCKTemplate_SetOperationAttributes(attr, 
	                                             attr - vk_template,
	                                             vkOps);
    }
#if 0
    /* XXX */
    if (mechanism->mechanism == CKM_DH_PKCS_KEY_PAIR_GEN) {
	nssDHParameters *dhp = nssAlgorithmAndParameters_GetDHParams(ap);
	NSS_CK_SET_ATTRIBUTE_VAR(attr, CKA_VALUE_BITS, dhp->valueBits);
    }
#endif
    NSS_CK_TEMPLATE_FINISH(vk_template, attr, vtsize);

    ckrv = CKAPI(epv)->C_GenerateKeyPair(session->handle, mechanism, 
                                         bk_template, btsize,
                                         vk_template, vtsize,
                                         &bkeyh, &vkeyh);
    if (ckrv != CKR_OK) {
	return PR_FAILURE;
    }

    *publicKey = nssCryptokiObject_Create(token, session, bkeyh);
    if (!*publicKey) {
	/*nssCKObject_Delete(session->handle, bkeyh);*/
	/*nssCKObject_Delete(session->handle, vkeyh);*/
	return PR_FAILURE;
    }

    *privateKey = nssCryptokiObject_Create(token, session, vkeyh);
    if (!*privateKey) {
	/*nssCKObject_Delete(session->handle, bkeyh);*/
	/*nssCKObject_Delete(session->handle, vkeyh);*/
	nssCryptokiObject_Destroy(*publicKey);
	return PR_FAILURE;
    }

    return PR_SUCCESS;
}

NSS_IMPLEMENT nssCryptokiObject *
nssToken_GenerateSymmetricKey
(
  NSSToken *token,
  nssSession *session,
  const NSSAlgorithmAndParameters *ap,
  PRUint32 keysize,
  const NSSUTF8 *labelOpt,
  PRBool asTokenObject,
  NSSOperations operations,
  NSSProperties properties
)
{
    CK_RV ckrv;
    CK_MECHANISM_PTR mechanism;
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE keyTemplate[17];
    CK_ULONG tsize;
    CK_OBJECT_HANDLE keyh;
    void *epv = nssToken_GetCryptokiEPV(token);
    nssCryptokiObject *key;

    /* Set up the symmetric key's template */
    NSS_CK_TEMPLATE_START(keyTemplate, attr, tsize);
    if (asTokenObject) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
    } else {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_false);
    }
    if (labelOpt) {
	NSS_CK_SET_ATTRIBUTE_UTF8(attr, CKA_LABEL, labelOpt);
    }
    if (operations) {
	attr += nssCKTemplate_SetOperationAttributes(attr, 
	                                             attr - keyTemplate,
	                                             operations);
    }
    if (properties) {
	attr += nssCKTemplate_SetPropertyAttributes(attr,
	                                            attr - keyTemplate,
                                                    properties);
    }
    if (keysize > 0) {
	NSS_CK_SET_ATTRIBUTE_VAR(attr, CKA_VALUE_LEN, keysize);
    }
    NSS_CK_TEMPLATE_FINISH(keyTemplate, attr, tsize);

    /* Generate the key */
    mechanism = nssAlgorithmAndParameters_GetMechanism(ap);

    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_GenerateKey(session->handle, mechanism, 
                                     keyTemplate, tsize, &keyh);
    nssSession_ExitMonitor(session);

    if (ckrv == CKR_OK) {
	key = nssCryptokiObject_Create(token, session, keyh);
    }
    return key;
}

static NSSItem * 
prepare_output_buffer(NSSArena *arenaOpt, NSSItem *rvOpt, 
                      CK_ULONG bufLen, PRBool *freeit)
{
    if (rvOpt) {
	*freeit = PR_FALSE;
	if (rvOpt->size > 0 && rvOpt->size < bufLen) {
	    return (NSSItem *)NULL;
	}
    } else {
	*freeit = (arenaOpt == NULL);
	rvOpt = nss_ZNEW(arenaOpt, NSSItem);
	if (!rvOpt) {
	    return (NSSItem *)NULL;
	}
    }
    rvOpt->data = nss_ZAlloc(arenaOpt, bufLen);
    rvOpt->size = bufLen;
    return rvOpt;
}

NSS_IMPLEMENT nssCryptokiObject *
nssToken_UnwrapKey
(
  NSSToken *token,
  nssSession *session,
  const NSSAlgorithmAndParameters *ap,
  nssCryptokiObject *wrappingKey,
  NSSItem *wrappedKey,
  PRBool asTokenObject,
  NSSOperations operations,
  NSSProperties properties
)
{
    CK_RV ckrv;
    CK_MECHANISM_PTR mechanism;
    CK_OBJECT_HANDLE keyH;
    CK_ATTRIBUTE keyTemplate[14];
    CK_ATTRIBUTE_PTR attr = keyTemplate;
    CK_ULONG ktSize;
    nssCryptokiObject *unwrappedKey = NULL;
    void *epv = nssToken_GetCryptokiEPV(token);

    mechanism = nssAlgorithmAndParameters_GetMechanism(ap);

    /* set up the key template */
    NSS_CK_TEMPLATE_START(keyTemplate, attr, ktSize);
    if (asTokenObject) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
    } else {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_false);
    }
    if (operations) {
	attr += nssCKTemplate_SetOperationAttributes(attr, 
	                                             keyTemplate - attr,
	                                             operations);
    }

    if (properties) {
	attr += nssCKTemplate_SetPropertyAttributes(attr,
	                                            keyTemplate - attr,
                                                    properties);
    }
    NSS_CK_TEMPLATE_FINISH(keyTemplate, attr, ktSize);
    /* Unwrap it */
    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_UnwrapKey(session->handle, mechanism,
                                   wrappingKey->handle,
                                   (CK_BYTE_PTR)wrappedKey->data,
                                   (CK_ULONG)wrappedKey->size,
                                   keyTemplate, ktSize, &keyH);
    nssSession_ExitMonitor(session);
    if (ckrv == CKR_OK) {
	unwrappedKey = nssCryptokiObject_Create(token, session, keyH);
    }
    return unwrappedKey;
}

NSS_IMPLEMENT NSSItem *
nssToken_WrapKey
(
  NSSToken *token,
  nssSession *session,
  const NSSAlgorithmAndParameters *ap,
  nssCryptokiObject *wrappingKey,
  nssCryptokiObject *targetKey,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    CK_RV ckrv;
    CK_ULONG wrapLen;
    CK_MECHANISM_PTR mechanism;
    void *epv = nssToken_GetCryptokiEPV(token);
    nssArenaMark *mark = NULL;
    PRBool freeit;

    mechanism = nssAlgorithmAndParameters_GetMechanism(ap);

    nssSession_EnterMonitor(session);
    /* Get the length of the output buffer */
    ckrv = CKAPI(epv)->C_WrapKey(session->handle, mechanism,
                                 wrappingKey->handle, targetKey->handle,
                                 NULL, &wrapLen);
    if (ckrv != CKR_OK) {
	goto loser;
    }
    /* Set up the output buffer */
    if (arenaOpt) {
	mark = nssArena_Mark(arenaOpt);
    }
    rvOpt = prepare_output_buffer(arenaOpt, rvOpt, wrapLen, &freeit);
    if (!rvOpt) {
	goto loser;
    }
    /* Wrap it */
    ckrv = CKAPI(epv)->C_WrapKey(session->handle, mechanism,
                                 wrappingKey->handle, targetKey->handle,
                                 (CK_BYTE_PTR)rvOpt->data,
                                 (CK_ULONG_PTR)&rvOpt->size);
    nssSession_ExitMonitor(session);
    if (ckrv != CKR_OK) {
	goto loser;
    }
    if (mark) {
	nssArena_Unmark(arenaOpt, mark);
    }
    return rvOpt;
loser:
    nssSession_ExitMonitor(session);
    if (mark) {
	nssArena_Release(arenaOpt, mark);
    } else {
	if (freeit) {
	    nssItem_Destroy(rvOpt);
	}
    }
    return (NSSItem *)NULL;
}

NSS_IMPLEMENT nssCryptokiObject *
nssToken_DeriveKey
(
  NSSToken *token,
  nssSession *session,
  const NSSAlgorithmAndParameters *ap,
  nssCryptokiObject *baseKey,
  PRBool asTokenObject,
  NSSOperations operations,
  NSSProperties properties
)
{
    CK_RV ckrv;
    CK_MECHANISM_PTR mechanism;
    CK_OBJECT_HANDLE keyH;
    CK_ATTRIBUTE keyTemplate[14];
    CK_ATTRIBUTE_PTR attr = keyTemplate;
    CK_ULONG ktSize;
    nssCryptokiObject *derivedKey = NULL;
    void *epv = nssToken_GetCryptokiEPV(token);

    mechanism = nssAlgorithmAndParameters_GetMechanism(ap);

    /* set up the key template */
    NSS_CK_TEMPLATE_START(keyTemplate, attr, ktSize);
    if (asTokenObject) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
    } else {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_false);
    }
    if (operations) {
	attr += nssCKTemplate_SetOperationAttributes(attr, 
	                                             keyTemplate - attr,
	                                             operations);
    }

    if (properties) {
	attr += nssCKTemplate_SetPropertyAttributes(attr,
	                                            keyTemplate - attr,
                                                    properties);
    }
    NSS_CK_TEMPLATE_FINISH(keyTemplate, attr, ktSize);
    /* ready to do the derivation */
    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_DeriveKey(session->handle, mechanism,
                                   baseKey->handle,
                                   keyTemplate, ktSize, &keyH);
    nssSession_ExitMonitor(session);
    if (ckrv == CKR_OK) {
	derivedKey = nssCryptokiObject_Create(token, session, keyH);
    }
    return derivedKey;
}

NSS_IMPLEMENT NSSItem *
nssToken_Encrypt
(
  NSSToken *tok,
  nssSession *session,
  const NSSAlgorithmAndParameters *ap,
  nssCryptokiObject *key,
  NSSItem *data,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    CK_RV ckrv;
    CK_ULONG bufLen;
    CK_MECHANISM_PTR mechanism;
    void *epv = nssToken_GetCryptokiEPV(tok);
    nssArenaMark *mark = NULL;
    PRBool freeit;

    mechanism = nssAlgorithmAndParameters_GetMechanism(ap);

    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_EncryptInit(session->handle, mechanism, key->handle);
    if (ckrv != CKR_OK) {
	goto loser;
    }
    /* Get the length of the output buffer */
    ckrv = CKAPI(epv)->C_Encrypt(session->handle, 
                                 (CK_BYTE_PTR)data->data, 
                                 (CK_ULONG)data->size,
                                 NULL, &bufLen);
    if (ckrv != CKR_OK) {
	goto loser;
    }
    /* Set up the output buffer */
    if (arenaOpt) {
	mark = nssArena_Mark(arenaOpt);
    }
    rvOpt = prepare_output_buffer(arenaOpt, rvOpt, bufLen, &freeit);
    if (!rvOpt) {
	goto loser;
    }
    /* Do the single-part encryption */
    ckrv = CKAPI(epv)->C_Encrypt(session->handle, 
                                (CK_BYTE_PTR)data->data, 
                                (CK_ULONG)data->size,
                                (CK_BYTE_PTR)rvOpt->data,
                                (CK_ULONG_PTR)&rvOpt->size);
    nssSession_ExitMonitor(session);
    if (ckrv != CKR_OK) {
	goto loser;
    }
    if (mark) {
	nssArena_Unmark(arenaOpt, mark);
    }
    return rvOpt;
loser:
    nssSession_ExitMonitor(session);
    if (mark) {
	nssArena_Release(arenaOpt, mark);
    } else {
	if (freeit) {
	    nssItem_Destroy(rvOpt);
	}
    }
    return (NSSItem *)NULL;
}

NSS_IMPLEMENT PRStatus
nssToken_BeginEncrypt
(
  NSSToken *token,
  nssSession *session,
  const NSSAlgorithmAndParameters *ap,
  nssCryptokiObject *key
)
{
    CK_RV ckrv;
    CK_MECHANISM_PTR mechanism;
    void *epv = nssToken_GetCryptokiEPV(token);

    mechanism = nssAlgorithmAndParameters_GetMechanism(ap);
    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_EncryptInit(session->handle, mechanism, key->handle);
    nssSession_ExitMonitor(session);
    return (ckrv == CKR_OK) ? PR_SUCCESS : PR_FAILURE;
}

NSS_IMPLEMENT NSSItem *
nssToken_ContinueEncrypt
(
  NSSToken *token,
  nssSession *session,
  NSSItem *data,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    CK_RV ckrv;
    CK_ULONG bufLen;
    PRBool freeit;
    void *epv = nssToken_GetCryptokiEPV(token);

    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_EncryptUpdate(session->handle, 
                                       (CK_BYTE_PTR)data->data, 
                                       (CK_ULONG)data->size,
                                       NULL, &bufLen);
    if (ckrv != CKR_OK) {
	nssSession_ExitMonitor(session);
	return (NSSItem *)NULL;
    }
    rvOpt = prepare_output_buffer(arenaOpt, rvOpt, bufLen, &freeit);
    if (!rvOpt) {
	nssSession_ExitMonitor(session);
	return (NSSItem *)NULL;
    }
    ckrv = CKAPI(epv)->C_EncryptUpdate(session->handle, 
                                       (CK_BYTE_PTR)data->data, 
                                       (CK_ULONG)data->size,
                                       (CK_BYTE_PTR)rvOpt->data, 
                                       (CK_ULONG_PTR)&rvOpt->size);
    if (ckrv != CKR_OK) {
	if (freeit) {
	    nssItem_Destroy(rvOpt);
	}
	rvOpt = NULL;
    }
    nssSession_ExitMonitor(session);
    return rvOpt;
}

NSS_IMPLEMENT NSSItem *
nssToken_FinishEncrypt
(
  NSSToken *token,
  nssSession *session,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    CK_RV ckrv;
    CK_ULONG bufLen;
    PRBool freeit;
    void *epv = nssToken_GetCryptokiEPV(token);

    nssSession_EnterMonitor(session);
    /* Get the length */
    ckrv = CKAPI(epv)->C_EncryptFinal(session->handle, NULL, &bufLen);
    if (ckrv != CKR_OK || bufLen == 0) {
	nssSession_ExitMonitor(session);
	return (NSSItem *)NULL;
    }
    rvOpt = prepare_output_buffer(arenaOpt, rvOpt, bufLen, &freeit);
    if (!rvOpt) {
	nssSession_ExitMonitor(session);
	return (NSSItem *)NULL;
    }
    /* Get the encrypted result */
    ckrv = CKAPI(epv)->C_EncryptFinal(session->handle, 
                                      (CK_BYTE_PTR)rvOpt->data, 
                                      (CK_ULONG_PTR)&rvOpt->size);
    nssSession_ExitMonitor(session);
    if (ckrv != CKR_OK) {
	if (freeit) {
	    nssItem_Destroy(rvOpt);
	}
	return (NSSItem *)NULL;
    }
    return rvOpt;
}

NSS_IMPLEMENT NSSItem *
nssToken_Decrypt
(
  NSSToken *tok,
  nssSession *session,
  const NSSAlgorithmAndParameters *ap,
  nssCryptokiObject *key,
  NSSItem *data,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    CK_RV ckrv;
    CK_ULONG bufLen;
    CK_MECHANISM_PTR mechanism;
    void *epv = nssToken_GetCryptokiEPV(tok);
    nssArenaMark *mark = NULL;
    PRBool freeit;

    mechanism = nssAlgorithmAndParameters_GetMechanism(ap);

    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_DecryptInit(session->handle, mechanism, key->handle);
    if (ckrv != CKR_OK) {
	goto loser;
    }
    /* Get the length of the output buffer */
    ckrv = CKAPI(epv)->C_Decrypt(session->handle, 
                                 (CK_BYTE_PTR)data->data, 
                                 (CK_ULONG)data->size,
                                 NULL, &bufLen);
    if (ckrv != CKR_OK) {
	goto loser;
    }
    /* Set up the output buffer */
    if (arenaOpt) {
	mark = nssArena_Mark(arenaOpt);
    }
    rvOpt = prepare_output_buffer(arenaOpt, rvOpt, bufLen, &freeit);
    if (!rvOpt) {
	goto loser;
    }
    /* Do the single-part decryption */
    ckrv = CKAPI(epv)->C_Decrypt(session->handle, 
                                (CK_BYTE_PTR)data->data, 
                                (CK_ULONG)data->size,
                                (CK_BYTE_PTR)rvOpt->data,
                                (CK_ULONG_PTR)&rvOpt->size);
    nssSession_ExitMonitor(session);
    if (ckrv != CKR_OK) {
	goto loser;
    }
    if (mark) {
	nssArena_Unmark(arenaOpt, mark);
    }
    return rvOpt;
loser:
    nssSession_ExitMonitor(session);
    if (mark) {
	nssArena_Release(arenaOpt, mark);
    } else {
	if (freeit) {
	    nssItem_Destroy(rvOpt);
	}
    }
    return (NSSItem *)NULL;
}

NSS_IMPLEMENT PRStatus
nssToken_BeginDecrypt
(
  NSSToken *token,
  nssSession *session,
  const NSSAlgorithmAndParameters *ap,
  nssCryptokiObject *key
)
{
    CK_RV ckrv;
    CK_MECHANISM_PTR mechanism;
    void *epv = nssToken_GetCryptokiEPV(token);

    mechanism = nssAlgorithmAndParameters_GetMechanism(ap);
    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_DecryptInit(session->handle, mechanism, key->handle);
    nssSession_ExitMonitor(session);
    return (ckrv == CKR_OK) ? PR_SUCCESS : PR_FAILURE;
}

NSS_IMPLEMENT NSSItem *
nssToken_ContinueDecrypt
(
  NSSToken *token,
  nssSession *session,
  NSSItem *data,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    CK_RV ckrv;
    CK_ULONG bufLen;
    PRBool freeit;
    void *epv = nssToken_GetCryptokiEPV(token);

    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_DecryptUpdate(session->handle, 
                                       (CK_BYTE_PTR)data->data, 
                                       (CK_ULONG)data->size,
                                       NULL, &bufLen);
    if (ckrv != CKR_OK) {
	nssSession_ExitMonitor(session);
	return (NSSItem *)NULL;
    }
    rvOpt = prepare_output_buffer(arenaOpt, rvOpt, bufLen, &freeit);
    if (!rvOpt) {
	nssSession_ExitMonitor(session);
	return (NSSItem *)NULL;
    }
    ckrv = CKAPI(epv)->C_DecryptUpdate(session->handle, 
                                       (CK_BYTE_PTR)data->data, 
                                       (CK_ULONG)data->size,
                                       (CK_BYTE_PTR)rvOpt->data, 
                                       (CK_ULONG_PTR)&rvOpt->size);
    if (ckrv != CKR_OK) {
	if (freeit) {
	    nssItem_Destroy(rvOpt);
	}
	rvOpt = NULL;
    }
    nssSession_ExitMonitor(session);
    return rvOpt;
}

NSS_IMPLEMENT NSSItem *
nssToken_FinishDecrypt
(
  NSSToken *token,
  nssSession *session,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    CK_RV ckrv;
    CK_ULONG bufLen;
    PRBool freeit;
    void *epv = nssToken_GetCryptokiEPV(token);

    nssSession_EnterMonitor(session);
    /* Get the length */
    ckrv = CKAPI(epv)->C_DecryptFinal(session->handle, NULL, &bufLen);
    if (ckrv != CKR_OK || bufLen == 0) {
	nssSession_ExitMonitor(session);
	return (NSSItem *)NULL;
    }
    rvOpt = prepare_output_buffer(arenaOpt, rvOpt, bufLen, &freeit);
    if (!rvOpt) {
	nssSession_ExitMonitor(session);
	return (NSSItem *)NULL;
    }
    /* Get the decrypted result */
    ckrv = CKAPI(epv)->C_DecryptFinal(session->handle, 
                                      (CK_BYTE_PTR)rvOpt->data, 
                                      (CK_ULONG_PTR)&rvOpt->size);
    nssSession_ExitMonitor(session);
    if (ckrv != CKR_OK) {
	if (freeit) {
	    nssItem_Destroy(rvOpt);
	}
	return (NSSItem *)NULL;
    }
    return rvOpt;
}

NSS_IMPLEMENT NSSItem *
nssToken_Sign
(
  NSSToken *token,
  nssSession *session,
  const NSSAlgorithmAndParameters *ap,
  nssCryptokiObject *key,
  NSSItem *data,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    CK_RV ckrv;
    CK_ULONG sigLen;
    CK_MECHANISM_PTR mechanism;
    void *epv = nssToken_GetCryptokiEPV(token);
    nssArenaMark *mark = NULL;
    PRBool freeit;

    mechanism = nssAlgorithmAndParameters_GetMechanism(ap);

    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_SignInit(session->handle, mechanism, key->handle);
    if (ckrv != CKR_OK) {
	goto loser;
    }
    /* Get the length of the output buffer */
    ckrv = CKAPI(epv)->C_Sign(session->handle, 
                              (CK_BYTE_PTR)data->data, 
                              (CK_ULONG)data->size,
                              NULL, &sigLen);
    if (ckrv != CKR_OK) {
	goto loser;
    }
    /* Set up the output buffer */
    if (arenaOpt) {
	mark = nssArena_Mark(arenaOpt);
    }
    rvOpt = prepare_output_buffer(arenaOpt, rvOpt, sigLen, &freeit);
    if (!rvOpt) {
	goto loser;
    }
    /* Do the single-part signature */
    ckrv = CKAPI(epv)->C_Sign(session->handle, 
                              (CK_BYTE_PTR)data->data, 
                              (CK_ULONG)data->size,
                              (CK_BYTE_PTR)rvOpt->data,
                              (CK_ULONG_PTR)&rvOpt->size);
    nssSession_ExitMonitor(session);
    if (ckrv != CKR_OK) {
	goto loser;
    }
    if (mark) {
	nssArena_Unmark(arenaOpt, mark);
    }
    return rvOpt;
loser:
    nssSession_ExitMonitor(session);
    if (mark) {
	nssArena_Release(arenaOpt, mark);
    } else {
	if (freeit) {
	    nssItem_Destroy(rvOpt);
	}
    }
    return (NSSItem *)NULL;
}

NSS_IMPLEMENT PRStatus
nssToken_BeginSign
(
  NSSToken *token,
  nssSession *session,
  const NSSAlgorithmAndParameters *ap,
  nssCryptokiObject *key
)
{
    CK_RV ckrv;
    CK_MECHANISM_PTR mechanism;
    void *epv = nssToken_GetCryptokiEPV(token);

    mechanism = nssAlgorithmAndParameters_GetMechanism(ap);
    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_SignInit(session->handle, mechanism, key->handle);
    nssSession_ExitMonitor(session);
    return (ckrv == CKR_OK) ? PR_SUCCESS : PR_FAILURE;
}

NSS_IMPLEMENT PRStatus
nssToken_ContinueSign
(
  NSSToken *token,
  nssSession *session,
  NSSItem *data
)
{
    CK_RV ckrv;
    void *epv = nssToken_GetCryptokiEPV(token);

    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_SignUpdate(session->handle, 
                                    (CK_BYTE_PTR)data->data, 
                                    (CK_ULONG)data->size);
    nssSession_ExitMonitor(session);
    return (ckrv == CKR_OK) ? PR_SUCCESS : PR_FAILURE;
}

NSS_IMPLEMENT NSSItem *
nssToken_FinishSign
(
  NSSToken *tok,
  nssSession *session,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    CK_RV ckrv;
    CK_ULONG sigLen;
    PRBool freeit;
    void *epv = nssToken_GetCryptokiEPV(tok);

    nssSession_EnterMonitor(session);
    /* Get the length */
    ckrv = CKAPI(epv)->C_SignFinal(session->handle, NULL, &sigLen);
    if (ckrv != CKR_OK || sigLen == 0) {
	nssSession_ExitMonitor(session);
	return (NSSItem *)NULL;
    }
    rvOpt = prepare_output_buffer(arenaOpt, rvOpt, sigLen, &freeit);
    if (!rvOpt) {
	nssSession_ExitMonitor(session);
	return (NSSItem *)NULL;
    }
    /* Get the signature */
    ckrv = CKAPI(epv)->C_SignFinal(session->handle, 
                                   (CK_BYTE_PTR)rvOpt->data, 
                                   (CK_ULONG_PTR)&rvOpt->size);
    nssSession_ExitMonitor(session);
    if (ckrv != CKR_OK) {
	if (freeit) {
	    nssItem_Destroy(rvOpt);
	}
	return (NSSItem *)NULL;
    }
    return rvOpt;
}

NSS_IMPLEMENT NSSItem *
nssToken_SignRecover
(
  NSSToken *tok,
  nssSession *session,
  const NSSAlgorithmAndParameters *ap,
  nssCryptokiObject *key,
  NSSItem *data,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    CK_RV ckrv;
    CK_ULONG bufLen;
    CK_MECHANISM_PTR mechanism;
    void *epv = nssToken_GetCryptokiEPV(tok);
    nssArenaMark *mark = NULL;
    PRBool freeit;

    mechanism = nssAlgorithmAndParameters_GetMechanism(ap);

    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_SignRecoverInit(session->handle, mechanism, 
                                         key->handle);
    if (ckrv != CKR_OK) {
	goto loser;
    }
    /* Get the length of the output buffer */
    ckrv = CKAPI(epv)->C_SignRecover(session->handle, 
                                     (CK_BYTE_PTR)data->data, 
                                     (CK_ULONG)data->size,
                                     NULL, &bufLen);
    if (ckrv != CKR_OK) {
	goto loser;
    }
    /* Set up the output buffer */
    if (arenaOpt) {
	mark = nssArena_Mark(arenaOpt);
    }
    rvOpt = prepare_output_buffer(arenaOpt, rvOpt, bufLen, &freeit);
    if (!rvOpt) {
	goto loser;
    }
    /* Do the single-part signature with recovery */
    ckrv = CKAPI(epv)->C_SignRecover(session->handle, 
                                     (CK_BYTE_PTR)data->data, 
                                     (CK_ULONG)data->size,
                                     (CK_BYTE_PTR)rvOpt->data,
                                     (CK_ULONG_PTR)&rvOpt->size);
    nssSession_ExitMonitor(session);
    if (ckrv != CKR_OK) {
	goto loser;
    }
    if (mark) {
	nssArena_Unmark(arenaOpt, mark);
    }
    return rvOpt;
loser:
    nssSession_ExitMonitor(session);
    if (mark) {
	nssArena_Release(arenaOpt, mark);
    } else {
	if (freeit) {
	    nssItem_Destroy(rvOpt);
	}
    }
    return (NSSItem *)NULL;
}

NSS_IMPLEMENT PRStatus
nssToken_Verify
(
  NSSToken *token,
  nssSession *session,
  const NSSAlgorithmAndParameters *ap,
  nssCryptokiObject *key,
  NSSItem *data,
  NSSItem *signature
)
{
    CK_RV ckrv;
    CK_MECHANISM_PTR mechanism;
    void *epv = nssToken_GetCryptokiEPV(token);

    mechanism = nssAlgorithmAndParameters_GetMechanism(ap);

    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_VerifyInit(session->handle, mechanism, key->handle);
    if (ckrv != CKR_OK) {
	return PR_FAILURE;
    }
    /* Do the single-part verification */
    ckrv = CKAPI(epv)->C_Verify(session->handle, 
                                (CK_BYTE_PTR)data->data, 
                                (CK_ULONG)data->size,
                                (CK_BYTE_PTR)signature->data,
                                (CK_ULONG)signature->size);
    nssSession_ExitMonitor(session);
    if (ckrv != CKR_OK) {
	if (ckrv == CKR_SIGNATURE_INVALID) {
	    /* the verification failed */
	    nss_SetError(NSS_ERROR_INVALID_SIGNATURE);
	} else if (ckrv == CKR_SIGNATURE_LEN_RANGE) {
	    /* signature->len is invalid, which is more like bad input
	     * than an invalid signature
	     */
	    nss_SetError(NSS_ERROR_INVALID_DATA);
	} else {
	    nss_SetError(NSS_ERROR_TOKEN_FAILURE);
	}
	return PR_FAILURE;
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT PRStatus
nssToken_BeginVerify
(
  NSSToken *token,
  nssSession *session,
  const NSSAlgorithmAndParameters *ap,
  nssCryptokiObject *key
)
{
    CK_RV ckrv;
    CK_MECHANISM_PTR mechanism;
    void *epv = nssToken_GetCryptokiEPV(token);

    mechanism = nssAlgorithmAndParameters_GetMechanism(ap);
    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_VerifyInit(session->handle, mechanism, key->handle);
    nssSession_ExitMonitor(session);
    return (ckrv == CKR_OK) ? PR_SUCCESS : PR_FAILURE;
}

NSS_IMPLEMENT PRStatus
nssToken_ContinueVerify
(
  NSSToken *token,
  nssSession *session,
  NSSItem *data
)
{
    CK_RV ckrv;
    void *epv = nssToken_GetCryptokiEPV(token);

    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_VerifyUpdate(session->handle, 
                                      (CK_BYTE_PTR)data->data, 
                                      (CK_ULONG)data->size);
    nssSession_ExitMonitor(session);
    return (ckrv == CKR_OK) ? PR_SUCCESS : PR_FAILURE;
}

NSS_IMPLEMENT PRStatus
nssToken_FinishVerify
(
  NSSToken *tok,
  nssSession *session,
  NSSItem *signature
)
{
    CK_RV ckrv;
    void *epv = nssToken_GetCryptokiEPV(tok);

    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_VerifyFinal(session->handle, 
                                     (CK_BYTE_PTR)signature->data, 
                                     (CK_ULONG)signature->size);
    nssSession_ExitMonitor(session);
    if (ckrv != CKR_OK) {
	if (ckrv == CKR_SIGNATURE_INVALID) {
	    /* the verification failed */
	    nss_SetError(NSS_ERROR_INVALID_SIGNATURE);
	} else if (ckrv == CKR_SIGNATURE_LEN_RANGE) {
	    /* signature->len is invalid, which is more like bad input
	     * than an invalid signature
	     */
	    nss_SetError(NSS_ERROR_INVALID_DATA);
	} else {
	    nss_SetError(NSS_ERROR_TOKEN_FAILURE);
	}
	return PR_FAILURE;
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSItem *
nssToken_VerifyRecover
(
  NSSToken *tok,
  nssSession *session,
  const NSSAlgorithmAndParameters *ap,
  nssCryptokiObject *key,
  NSSItem *signature,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    CK_RV ckrv;
    CK_ULONG bufLen;
    CK_MECHANISM_PTR mechanism;
    void *epv = nssToken_GetCryptokiEPV(tok);
    nssArenaMark *mark = NULL;
    PRBool freeit;

    mechanism = nssAlgorithmAndParameters_GetMechanism(ap);

    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_VerifyRecoverInit(session->handle, mechanism, 
                                           key->handle);
    if (ckrv != CKR_OK) {
	goto loser;
    }
    /* Get the length of the output buffer */
    ckrv = CKAPI(epv)->C_VerifyRecover(session->handle, 
                                       (CK_BYTE_PTR)signature->data, 
                                       (CK_ULONG)signature->size,
                                       NULL, &bufLen);
    if (ckrv != CKR_OK) {
	goto loser;
    }
    /* Set up the output buffer */
    if (arenaOpt) {
	mark = nssArena_Mark(arenaOpt);
    }
    rvOpt = prepare_output_buffer(arenaOpt, rvOpt, bufLen, &freeit);
    if (!rvOpt) {
	goto loser;
    }
    /* Do the single-part verification with recovery */
    ckrv = CKAPI(epv)->C_VerifyRecover(session->handle, 
                                       (CK_BYTE_PTR)signature->data, 
                                       (CK_ULONG)signature->size,
                                       (CK_BYTE_PTR)rvOpt->data,
                                       (CK_ULONG_PTR)&rvOpt->size);
    nssSession_ExitMonitor(session);
    if (ckrv != CKR_OK) {
	goto loser;
    }
    if (mark) {
	nssArena_Unmark(arenaOpt, mark);
    }
    return rvOpt;
loser:
    nssSession_ExitMonitor(session);
    if (mark) {
	nssArena_Release(arenaOpt, mark);
    } else {
	if (freeit) {
	    nssItem_Destroy(rvOpt);
	}
    }
    return (NSSItem *)NULL;
}

NSS_IMPLEMENT NSSItem *
nssToken_Digest
(
  NSSToken *tok,
  nssSession *session,
  const NSSAlgorithmAndParameters *ap,
  NSSItem *data,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    CK_RV ckrv;
    CK_ULONG digestLen;
    CK_MECHANISM_PTR mechanism;
    void *epv = nssToken_GetCryptokiEPV(tok);
    nssArenaMark *mark = NULL;
    PRBool freeit;

    mechanism = nssAlgorithmAndParameters_GetMechanism(ap);

    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_DigestInit(session->handle, mechanism);
    if (ckrv != CKR_OK) {
	goto loser;
    }
    /* Get the length of the output buffer */
    ckrv = CKAPI(epv)->C_Digest(session->handle, 
                                (CK_BYTE_PTR)data->data, 
                                (CK_ULONG)data->size,
                                NULL, &digestLen);
    if (ckrv != CKR_OK) {
	goto loser;
    }
    /* Set up the output buffer */
    if (arenaOpt) {
	mark = nssArena_Mark(arenaOpt);
    }
    rvOpt = prepare_output_buffer(arenaOpt, rvOpt, digestLen, &freeit);
    if (!rvOpt) {
	goto loser;
    }
    /* Do the single-part digest */
    ckrv = CKAPI(epv)->C_Digest(session->handle, 
                                (CK_BYTE_PTR)data->data, 
                                (CK_ULONG)data->size,
                                (CK_BYTE_PTR)rvOpt->data,
                                (CK_ULONG_PTR)&rvOpt->size);
    nssSession_ExitMonitor(session);
    if (ckrv != CKR_OK) {
	goto loser;
    }
    if (mark) {
	nssArena_Unmark(arenaOpt, mark);
    }
    return rvOpt;
loser:
    nssSession_ExitMonitor(session);
    if (mark) {
	nssArena_Release(arenaOpt, mark);
    } else {
	if (freeit) {
	    nssItem_Destroy(rvOpt);
	}
    }
    return (NSSItem *)NULL;
}

NSS_IMPLEMENT PRStatus
nssToken_BeginDigest
(
  NSSToken *tok,
  nssSession *session,
  const NSSAlgorithmAndParameters *ap
)
{
    CK_RV ckrv;
    CK_MECHANISM_PTR mechanism;
    void *epv = nssToken_GetCryptokiEPV(tok);

    mechanism = nssAlgorithmAndParameters_GetMechanism(ap);
    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_DigestInit(session->handle, mechanism);
    nssSession_ExitMonitor(session);
    return (ckrv == CKR_OK) ? PR_SUCCESS : PR_FAILURE;
}

NSS_IMPLEMENT PRStatus
nssToken_ContinueDigest
(
  NSSToken *tok,
  nssSession *session,
  NSSItem *item
)
{
    CK_RV ckrv;
    void *epv = nssToken_GetCryptokiEPV(tok);

    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_DigestUpdate(session->handle, 
                                      (CK_BYTE_PTR)item->data, 
                                      (CK_ULONG)item->size);
    nssSession_ExitMonitor(session);
    return (ckrv == CKR_OK) ? PR_SUCCESS : PR_FAILURE;
}

NSS_IMPLEMENT NSSItem *
nssToken_FinishDigest
(
  NSSToken *tok,
  nssSession *session,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    CK_RV ckrv;
    CK_ULONG digestLen;
    PRBool freeit;
    void *epv = nssToken_GetCryptokiEPV(tok);

    nssSession_EnterMonitor(session);
    /* Get the length */
    ckrv = CKAPI(epv)->C_DigestFinal(session->handle, NULL, &digestLen);
    if (ckrv != CKR_OK || digestLen == 0) {
	nssSession_ExitMonitor(session);
	return (NSSItem *)NULL;
    }
    rvOpt = prepare_output_buffer(arenaOpt, rvOpt, digestLen, &freeit);
    if (!rvOpt) {
	nssSession_ExitMonitor(session);
	return (NSSItem *)NULL;
    }
    /* Get the digest */
    ckrv = CKAPI(epv)->C_DigestFinal(session->handle, 
                                     (CK_BYTE_PTR)rvOpt->data, 
                                     (CK_ULONG_PTR)&rvOpt->size);
    nssSession_ExitMonitor(session);
    if (ckrv != CKR_OK) {
	if (freeit) {
	    nssItem_Destroy(rvOpt);
	}
	return (NSSItem *)NULL;
    }
    return rvOpt;
}

/* Sigh.  The methods to find objects declared above cause problems with
 * the low-level object cache in the softoken -- the objects are found in 
 * toto, then one wave of GetAttributes is done, then another.  Having a 
 * large number of objects causes the cache to be thrashed, as the objects 
 * are gone before there's any chance to ask for their attributes.
 * So, for now, bringing back traversal methods for certs.  This way all of 
 * the cert's attributes can be grabbed immediately after finding it,
 * increasing the likelihood that the cache takes care of it.
 */
NSS_IMPLEMENT PRStatus
nssToken_TraverseCertificates
(
  NSSToken *token,
  nssSession *session,
  nssTokenSearchType searchType,
  PRStatus (* callback)(nssCryptokiObject *instance, void *arg),
  void *arg
)
{
    CK_RV ckrv;
    CK_ULONG count;
    CK_OBJECT_HANDLE *objectHandles;
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE cert_template[2];
    CK_ULONG ctsize;
    NSSArena *arena;
    PRStatus status;
    PRUint32 arraySize, numHandles;
    nssCryptokiObject **objects;
    void *epv = nssToken_GetCryptokiEPV(token);

    /* template for all certs */
    NSS_CK_TEMPLATE_START(cert_template, attr, ctsize);
    if (searchType == nssTokenSearchType_SessionOnly) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_false);
    } else if (searchType == nssTokenSearchType_TokenOnly ||
               searchType == nssTokenSearchType_TokenForced) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
    }
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_CLASS, &g_ck_class_cert);
    NSS_CK_TEMPLATE_FINISH(cert_template, attr, ctsize);

    /* the arena is only for the array of object handles */
    arena = nssArena_Create();
    if (!arena) {
	return PR_FAILURE;
    }
    arraySize = OBJECT_STACK_SIZE;
    numHandles = 0;
    objectHandles = nss_ZNEWARRAY(arena, CK_OBJECT_HANDLE, arraySize);
    if (!objectHandles) {
	goto loser;
    }
    nssSession_EnterMonitor(session); /* ==== session lock === */
    /* Initialize the find with the template */
    ckrv = CKAPI(epv)->C_FindObjectsInit(session->handle, 
                                         cert_template, ctsize);
    if (ckrv != CKR_OK) {
	nssSession_ExitMonitor(session);
	goto loser;
    }
    while (PR_TRUE) {
	/* Issue the find for up to arraySize - numHandles objects */
	ckrv = CKAPI(epv)->C_FindObjects(session->handle, 
	                                 objectHandles + numHandles, 
	                                 arraySize - numHandles, 
	                                 &count);
	if (ckrv != CKR_OK) {
	    nssSession_ExitMonitor(session);
	    goto loser;
	}
	/* bump the number of found objects */
	numHandles += count;
	if (numHandles < arraySize) {
	    break;
	}
	/* the array is filled, double it and continue */
	arraySize *= 2;
	objectHandles = nss_ZREALLOCARRAY(objectHandles, 
	                                  CK_OBJECT_HANDLE, 
	                                  arraySize);
	if (!objectHandles) {
	    nssSession_ExitMonitor(session);
	    goto loser;
	}
    }
    ckrv = CKAPI(epv)->C_FindObjectsFinal(session->handle);
    nssSession_ExitMonitor(session); /* ==== end session lock === */
    if (ckrv != CKR_OK) {
	goto loser;
    }
    if (numHandles > 0) {
	objects = create_objects_from_handles(token, session,
	                                      objectHandles, numHandles);
	if (objects) {
	    nssCryptokiObject **op;
	    for (op = objects; *op; op++) {
		status = (*callback)(*op, arg);
	    }
	    nss_ZFreeIf(objects);
	}
    }
    nssArena_Destroy(arena);
    return PR_SUCCESS;
loser:
    nssArena_Destroy(arena);
    return PR_FAILURE;
}

