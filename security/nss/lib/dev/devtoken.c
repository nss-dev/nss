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

#ifndef PKI1_H
#include "pki1.h"
#endif /* PKI1_H */

/* The number of object handles to grab during each call to C_FindObjects */
#define OBJECT_STACK_SIZE 16

#ifndef BITS_PER_BYTE
#define BITS_PER_BYTE 8
#endif

struct NSSTokenStr
{
  struct nssDeviceBaseStr base;
  NSSSlot *slot;  /* Peer */
  CK_SLOT_ID slotID;
  CK_TOKEN_INFO info;
  CK_MECHANISM_TYPE_PTR mechanisms;
  CK_ULONG numMechanisms;
  nssSession *defaultSession;
};

NSS_IMPLEMENT NSSToken *
nssToken_Create (
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
    arena = nssArena_Create();
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
    rvToken->slotID = slotID;
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
    return rvToken;
loser:
    if (session) {
	nssSession_Destroy(session);
    }
    nssArena_Destroy(arena);
    return (NSSToken *)NULL;
}

NSS_IMPLEMENT PRStatus
nssToken_Destroy (
  NSSToken *tok
)
{
    if (tok) {
	PR_AtomicDecrement(&tok->base.refCount);
	if (tok->base.refCount == 0) {
	    nssSession_Destroy(tok->defaultSession);
	    PZ_DestroyLock(tok->base.lock);
	    return nssArena_Destroy(tok->base.arena);
	}
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT void
nssToken_Remove (
  NSSToken *tok
)
{
    return;
}

NSS_IMPLEMENT void
NSSToken_Destroy (
  NSSToken *tok
)
{
    (void)nssToken_Destroy(tok);
}

NSS_IMPLEMENT NSSToken *
nssToken_AddRef (
  NSSToken *tok
)
{
    PR_AtomicIncrement(&tok->base.refCount);
    return tok;
}

NSS_IMPLEMENT PRStatus
NSSToken_GetInfo (
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
nssToken_GetSlot (
  NSSToken *tok
)
{
    return nssSlot_AddRef(tok->slot);
}

NSS_IMPLEMENT NSSSlot *
NSSToken_GetSlot (
  NSSToken *tok
)
{
    return nssToken_GetSlot(tok);
}

NSS_IMPLEMENT NSSModule *
nssToken_GetModule (
  NSSToken *token
)
{
    return nssSlot_GetModule(token->slot);
}

NSS_IMPLEMENT void *
nssToken_GetCryptokiEPV (
  NSSToken *token
)
{
    return nssSlot_GetCryptokiEPV(token->slot);
}

NSS_IMPLEMENT nssSession *
nssToken_GetDefaultSession (
  NSSToken *token
)
{
    return token->defaultSession;
}

static PRStatus
update_info(NSSToken *token)
{
    CK_RV ckrv;
    void *epv = nssToken_GetCryptokiEPV(token);
    /* Get token information */
    ckrv = CKAPI(epv)->C_GetTokenInfo(token->slotID, &token->info);
    if (ckrv != CKR_OK) {
	return PR_FAILURE;
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSUTF8 *
nssToken_GetName (
  NSSToken *tok
)
{
    return tok->base.name;
}

NSS_IMPLEMENT NSSUTF8 *
NSSToken_GetName (
  NSSToken *token
)
{
    return nssToken_GetName(token);
}

NSS_IMPLEMENT PRBool
nssToken_IsReadOnly (
  NSSToken *token
)
{
    return (token->info.flags & CKF_WRITE_PROTECTED);
}

NSS_IMPLEMENT PRBool
nssToken_DoesAlgorithm (
  NSSToken *token,
  NSSOIDTag alg
)
{
    CK_ULONG ul;
    NSSOID *oid = nssOID_CreateFromTag(alg);

    for (ul = 0; ul < token->numMechanisms; ul++) {
	if (oid->mechanism == token->mechanisms[ul]) {
	    return PR_TRUE;
	}
    }
    return PR_FALSE;
}

NSS_IMPLEMENT PRBool
nssToken_DoesAlgNParam (
  NSSToken *token,
  const NSSAlgNParam *ap
)
{
    CK_ULONG ul;
    CK_MECHANISM_PTR pMech = nssAlgNParam_GetMechanism(ap);

    for (ul = 0; ul < token->numMechanisms; ul++) {
	if (pMech->mechanism == token->mechanisms[ul]) {
	    return PR_TRUE;
	}
    }
    return PR_FALSE;
}

NSS_IMPLEMENT nssSession *
nssToken_CreateSession (
  NSSToken *token,
  PRBool readWrite
)
{
    return nssSlot_CreateSession(token->slot, readWrite);
}

NSS_IMPLEMENT PRBool
nssToken_HasSessionLimit (
  NSSToken *token
)
{
    return (token->info.ulMaxSessionCount != CK_EFFECTIVELY_INFINITE);
}

NSS_IMPLEMENT PRBool
nssToken_IsLoginRequired (
  NSSToken *token
)
{
    return (token->info.flags & CKF_LOGIN_REQUIRED);
}

NSS_IMPLEMENT PRBool
nssToken_NeedsPINInitialization (
  NSSToken *token
)
{
    (void)update_info(token);
    return (!(token->info.flags & CKF_USER_PIN_INITIALIZED));
}

static nssCryptokiObject *
import_object (
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
create_objects_from_handles (
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
find_objects_by_template (
  NSSToken *token,
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
    void *epv = nssToken_GetCryptokiEPV(token);
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
	objects = create_objects_from_handles(token, session,
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

NSS_IMPLEMENT nssCryptokiObject *
nssToken_ImportCert (
  NSSToken *tok,
  nssSession *session,
  NSSCertType certType,
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
    nssCryptokiObject *rvObject = NULL, **objs;

    if (certType == NSSCertType_PKIX) {
	cert_type = CKC_X_509;
    } else {
	return (nssCryptokiObject *)NULL;
    }
    NSS_CK_TEMPLATE_START(cert_tmpl, attr, ctsize);
    if (asTokenObject) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
    } else {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_false);
    }
    /* required attributes */
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_CLASS,            &g_ck_class_cert);
    NSS_CK_SET_ATTRIBUTE_VAR( attr, CKA_CERTIFICATE_TYPE,  cert_type);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_VALUE,             encoding);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_ISSUER,            issuer);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_SUBJECT,           subject);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_SERIAL_NUMBER,     serial);
    /* optional attributes */
    if (id) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_ID, id);
    }
    if (nickname) {
	NSS_CK_SET_ATTRIBUTE_UTF8(attr, CKA_LABEL, nickname);
    }
    if (email) {
	NSS_CK_SET_ATTRIBUTE_UTF8(attr, CKA_NETSCAPE_EMAIL,    email);
    }
    NSS_CK_TEMPLATE_FINISH(cert_tmpl, attr, ctsize);
    /* see if the cert is already there */
    objs = find_objects_by_template(tok, session, cert_tmpl, ctsize, 1, NULL);
    if (objs) {
	rvObject = objs[0];
	nss_ZFreeIf(objs);
    }
    if (rvObject && (id || nickname)) {
	/* according to PKCS#11, label, ID, issuer, and serial number 
	 * may change after the object has been created.  For PKIX, the
	 * last two attributes can't change, so for now we'll only worry
	 * about the first two.
	 */
	NSS_CK_TEMPLATE_START(cert_tmpl, attr, ctsize);
	if (id) {
	    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_ID, id);
	}
	if (nickname) {
	    NSS_CK_SET_ATTRIBUTE_UTF8(attr, CKA_LABEL, nickname);
	}
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
    return rvObject;
}

/* traverse all certificates - this should only happen if the token
 * has been marked as "traversable"
 */
NSS_IMPLEMENT nssCryptokiObject **
nssToken_FindCerts (
  NSSToken *token,
  nssSession *session,
  PRUint32 maximumOpt,
  PRStatus *statusOpt
)
{
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE cert_template[2];
    CK_ULONG ctsize;

    NSS_CK_TEMPLATE_START(cert_template, attr, ctsize);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_CLASS, &g_ck_class_cert);
    NSS_CK_TEMPLATE_FINISH(cert_template, attr, ctsize);

    return find_objects_by_template(token, session,
                                    cert_template, ctsize,
                                    maximumOpt, statusOpt);
}

NSS_IMPLEMENT nssCryptokiObject *
nssToken_ImportPublicKey (
  NSSToken *token,
  nssSession *session,
  NSSPublicKeyInfo *bki,
  PRBool asTokenObject
)
{
    CK_OBJECT_CLASS bkclass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE ckKeyType;
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE bktemplate[6];
    CK_ULONG bktsize;

    NSS_CK_TEMPLATE_START(bktemplate, attr, bktsize);
    /* token or session object */
    if (asTokenObject) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
    } else {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_false);
    }
    /* public key */
    NSS_CK_SET_ATTRIBUTE_VAR(attr, CKA_CLASS, bkclass);
    /* key-specific attributes */
    switch (bki->kind) {
    case NSSKeyPairType_RSA:
	ckKeyType = CKK_RSA;
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_MODULUS, &bki->u.rsa.modulus);
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_PUBLIC_EXPONENT, 
	                                        &bki->u.rsa.publicExponent);
	break;
#if 0
    case NSSKeyPairType_DSA:
	ckKeyType = CKK_DSA;
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_PRIME, &bki->u.dsa.params.prime);
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_SUBPRIME, 
	                                        &bki->u.dsa.params.subPrime);
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_BASE,  &bki->u.dsa.params.base);
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_VALUE, &bki->u.dsa.publicValue);
	break;
#endif
    default:
	PR_ASSERT(0); /* XXX under construction */
	return NULL;
    }
    /* key type */
    NSS_CK_SET_ATTRIBUTE_VAR(attr, CKA_KEY_TYPE, ckKeyType);
    NSS_CK_TEMPLATE_FINISH(bktemplate, attr, bktsize);

    return import_object(token, session, bktemplate, bktsize);
}

NSS_IMPLEMENT nssCryptokiObject **
nssToken_FindPublicKeys (
  NSSToken *token,
  nssSession *session,
  PRUint32 maximumOpt,
  PRStatus *statusOpt
)
{
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE key_template[2];
    CK_ULONG ktsize;
    nssCryptokiObject **objects;

    NSS_CK_TEMPLATE_START(key_template, attr, ktsize);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_CLASS, &g_ck_class_pubkey);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
    NSS_CK_TEMPLATE_FINISH(key_template, attr, ktsize);

    objects = find_objects_by_template(token, session,
                                       key_template, ktsize, 
                                       maximumOpt, statusOpt);
    return objects;
}

NSS_IMPLEMENT nssCryptokiObject **
nssToken_FindPrivateKeys (
  NSSToken *token,
  nssSession *session,
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
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
    NSS_CK_TEMPLATE_FINISH(key_template, attr, ktsize);

    objects = find_objects_by_template(token, session,
                                       key_template, ktsize, 
                                       maximumOpt, statusOpt);
    return objects;
}

NSS_IMPLEMENT PRStatus
nssToken_SeedRandom (
  NSSToken *token,
  NSSItem *seed
)
{
    CK_RV ckrv;
    void *epv = nssToken_GetCryptokiEPV(token);
    nssSession *session = token->defaultSession;

    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_SeedRandom(session->handle, seed->data, seed->size);
    nssSession_ExitMonitor(session);
    if (ckrv != CKR_OK) {
	if (ckrv == CKR_RANDOM_SEED_NOT_SUPPORTED ||
	    ckrv == CKR_RANDOM_NO_RNG) 
	{
	    nss_SetError(NSS_ERROR_INVALID_DEVICE);
	} else {
	    nss_SetGenericDeviceError(ckrv);
	}
	return PR_FAILURE;
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT PRUint8 *
nssToken_GenerateRandom (
  NSSToken *token,
  PRUint8 *rvOpt,
  PRUint32 numBytes,
  NSSArena *arenaOpt
)
{
    CK_RV ckrv;
    void *epv = nssToken_GetCryptokiEPV(token);
    nssSession *session = token->defaultSession;

    if (!rvOpt) {
	rvOpt = nss_ZAlloc(arenaOpt, numBytes);
	if (!rvOpt) {
	    return (PRUint8 *)NULL;
	}
    }
    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_GenerateRandom(session->handle, rvOpt, numBytes);
    nssSession_ExitMonitor(session);
    if (ckrv != CKR_OK) {
	if (ckrv == CKR_RANDOM_NO_RNG) {
	    nss_SetError(NSS_ERROR_INVALID_DEVICE);
	} else {
	    nss_SetGenericDeviceError(ckrv);
	}
	return (PRUint8 *)NULL;
    }
    return rvOpt;
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
nssToken_GenerateKeyPair (
  NSSToken *token,
  nssSession *session,
  const NSSAlgNParam *ap,
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
    PRUint32 numLeft;
    PRUint32 numBK = sizeof(bk_template) / sizeof(bk_template[0]);
    PRUint32 numVK = sizeof(vk_template) / sizeof(vk_template[0]);

    mechanism = nssAlgNParam_GetMechanism(ap);

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
	numLeft = numBK - (attr - bk_template);
	attr += nssCKTemplate_SetPropertyAttributes(attr, numLeft, bkProps);
    }
    if (operations) {
	PRUint32 bkOps = operations & PUBLIC_KEY_OPS_MASK;
	numLeft = numBK - (attr - bk_template);
	attr += nssCKTemplate_SetOperationAttributes(attr, numLeft, bkOps);
    }
    /* Set algorithm-dependent values in the template */
    numLeft = numBK - (attr - bk_template);
    attr += nssAlgNParam_SetTemplateValues(ap, attr, numLeft);
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
	numLeft = numVK - (attr - vk_template);
	attr += nssCKTemplate_SetPropertyAttributes(attr, numLeft, vkProps);
    }
    if (operations) {
	PRUint32 vkOps = operations & PRIVATE_KEY_OPS_MASK;
	numLeft = numVK - (attr - vk_template);
	attr += nssCKTemplate_SetOperationAttributes(attr, numLeft, vkOps);
    }
#if 0
    /* XXX */
    if (mechanism->mechanism == CKM_DH_PKCS_KEY_PAIR_GEN) {
	nssDHParameters *dhp = nssAlgNParam_GetDHParams(ap);
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
nssToken_GenerateSymKey (
  NSSToken *token,
  nssSession *session,
  const NSSAlgNParam *ap,
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
    nssCryptokiObject *key = NULL;
    PRUint32 numLeft;
    PRUint32 numkt = sizeof(keyTemplate) / sizeof(keyTemplate[0]);

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
	numLeft = numkt - (attr - keyTemplate);
	attr += nssCKTemplate_SetOperationAttributes(attr, numLeft,
	                                             operations);
    }
    if (properties) {
	numLeft = numkt - (attr - keyTemplate);
	attr += nssCKTemplate_SetPropertyAttributes(attr, numLeft,
                                                    properties);
    }
    if (keysize > 0) {
	keysize /= BITS_PER_BYTE;
	NSS_CK_SET_ATTRIBUTE_VAR(attr, CKA_VALUE_LEN, keysize);
    }
    NSS_CK_TEMPLATE_FINISH(keyTemplate, attr, tsize);

    /* Generate the key */
    mechanism = nssAlgNParam_GetMechanism(ap);

    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_GenerateKey(session->handle, mechanism, 
                                     keyTemplate, tsize, &keyh);
    nssSession_ExitMonitor(session);

    if (ckrv == CKR_OK) {
	key = nssCryptokiObject_Create(token, session, keyh);
    }
    return key;
}

NSS_IMPLEMENT nssCryptokiObject *
nssToken_ImportRawSymKey (
  NSSToken *token,
  nssSession *session,
  NSSItem *keyData,
  NSSSymKeyType symKeyType,
  PRBool asTokenObject,
  const NSSUTF8 *labelOpt,
  NSSOperations operations,
  NSSProperties properties
)
{
    CK_RV ckrv;
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE keyTemplate[17];
    CK_ULONG tsize;
    CK_OBJECT_HANDLE keyh;
    void *epv = nssToken_GetCryptokiEPV(token);
    nssCryptokiObject *key = NULL;
    PRUint32 numLeft;
    PRUint32 numkt = sizeof(keyTemplate) / sizeof(keyTemplate[0]);
    CK_KEY_TYPE ckKeyType;

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
	numLeft = numkt - (attr - keyTemplate);
	attr += nssCKTemplate_SetOperationAttributes(attr, numLeft,
	                                             operations);
    }
    if (properties) {
	numLeft = numkt - (attr - keyTemplate);
	attr += nssCKTemplate_SetPropertyAttributes(attr, numLeft,
                                                    properties);
    }
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_VALUE, keyData);
    ckKeyType = nssCK_GetSymKeyType(symKeyType);
    NSS_CK_SET_ATTRIBUTE_VAR(attr, CKA_KEY_TYPE, ckKeyType);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_CLASS, &g_ck_class_symkey);
    NSS_CK_TEMPLATE_FINISH(keyTemplate, attr, tsize);

    /* Import the key */
    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_CreateObject(session->handle, keyTemplate, tsize, 
                                      &keyh);
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
    if (!rvOpt) {
	*freeit = (arenaOpt == NULL);
	rvOpt = nss_ZNEW(arenaOpt, NSSItem);
	if (!rvOpt) {
	    return (NSSItem *)NULL;
	}
    } else {
	*freeit = PR_FALSE;
	if (rvOpt->size > 0) {
	    PR_ASSERT(rvOpt->data != NULL);
	    if (rvOpt->size < bufLen || !rvOpt->data) {
		/* set invalid len error */
		return (NSSItem *)NULL;
	    }
	}
    }
    if (!rvOpt->data) {
	/* XXX freeit ain't workin here */
	rvOpt->data = nss_ZAlloc(arenaOpt, bufLen);
    }
    rvOpt->size = bufLen;
    return rvOpt;
}

static nssCryptokiObject *
unwrap_key (
  NSSToken *token,
  nssSession *session,
  const NSSAlgNParam *ap,
  nssCryptokiObject *wrappingKey,
  NSSItem *wrappedKey,
  PRBool asTokenObject,
  NSSOperations operations,
  NSSProperties properties,
  CK_OBJECT_CLASS keyClass,
  CK_KEY_TYPE keyType
)
{
    CK_RV ckrv;
    CK_MECHANISM_PTR mechanism;
    CK_OBJECT_HANDLE keyH;
    CK_ATTRIBUTE keyTemplate[16];
    CK_ATTRIBUTE_PTR attr = keyTemplate;
    CK_ULONG ktSize;
    nssCryptokiObject *unwrappedKey = NULL;
    void *epv = nssToken_GetCryptokiEPV(token);
    PRUint32 numLeft;
    PRUint32 numkt = sizeof(keyTemplate) / sizeof(keyTemplate[0]);

    mechanism = nssAlgNParam_GetMechanism(ap);

    /* set up the key template */
    NSS_CK_TEMPLATE_START(keyTemplate, attr, ktSize);
    if (asTokenObject) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
    } else {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_false);
    }
    NSS_CK_SET_ATTRIBUTE_VAR(attr, CKA_CLASS, keyClass);
    NSS_CK_SET_ATTRIBUTE_VAR(attr, CKA_KEY_TYPE, keyType);
    if (operations) {
	numLeft = numkt - (attr - keyTemplate);
	attr += nssCKTemplate_SetOperationAttributes(attr, numLeft,
	                                             operations);
    }

    if (properties) {
	numLeft = numkt - (attr - keyTemplate);
	attr += nssCKTemplate_SetPropertyAttributes(attr, numLeft,
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

NSS_IMPLEMENT nssCryptokiObject *
nssToken_UnwrapPrivateKey (
  NSSToken *token,
  nssSession *session,
  const NSSAlgNParam *ap,
  nssCryptokiObject *wrappingKey,
  NSSItem *wrappedKey,
  PRBool asTokenObject,
  NSSOperations operations,
  NSSProperties properties,
  NSSKeyPairType privKeyType
)
{
    CK_KEY_TYPE keyType = nssCK_GetKeyPairType(privKeyType);
    return unwrap_key(token, session, ap, wrappingKey, wrappedKey,
                      asTokenObject, operations, properties,
                      CKO_PRIVATE_KEY, keyType);
}

NSS_IMPLEMENT nssCryptokiObject *
nssToken_UnwrapSymKey (
  NSSToken *token,
  nssSession *session,
  const NSSAlgNParam *ap,
  nssCryptokiObject *wrappingKey,
  NSSItem *wrappedKey,
  PRBool asTokenObject,
  NSSOperations operations,
  NSSProperties properties,
  NSSSymKeyType symKeyType
)
{
    CK_KEY_TYPE keyType = nssCK_GetSymKeyType(symKeyType);
    return unwrap_key(token, session, ap, wrappingKey, wrappedKey,
                      asTokenObject, operations, properties,
                      CKO_SECRET_KEY, keyType);
}

NSS_IMPLEMENT NSSItem *
nssToken_WrapKey (
  NSSToken *token,
  nssSession *session,
  const NSSAlgNParam *ap,
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
    PRBool freeit = PR_FALSE;

    mechanism = nssAlgNParam_GetMechanism(ap);

    nssSession_EnterMonitor(session);
    /* Get the length of the output buffer */
#ifdef SOFTOKEN_CANT_GIVE_WRAP_LEN_BUG
/* NSS 3.X guessed the wrap len from the pubkey size, what about the
 * implicit PKCS#8 encoding done on pubkeys?
 */
    ckrv = CKAPI(epv)->C_WrapKey(session->handle, mechanism,
                                 wrappingKey->handle, targetKey->handle,
                                 NULL, &wrapLen);
    if (ckrv != CKR_OK) {
	goto loser;
    }
#else
    wrapLen = 8192; /* XXX this will boink out at > 8k keys */
#endif
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
nssToken_DeriveKey (
  NSSToken *token,
  nssSession *session,
  const NSSAlgNParam *ap,
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
    PRUint32 numLeft;
    PRUint32 numkt = sizeof(keyTemplate) / sizeof(keyTemplate[0]);

    mechanism = nssAlgNParam_GetMechanism(ap);

    /* set up the key template */
    NSS_CK_TEMPLATE_START(keyTemplate, attr, ktSize);
    if (asTokenObject) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true);
    } else {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_false);
    }
    if (operations) {
	numLeft = numkt - (attr - keyTemplate);
	attr += nssCKTemplate_SetOperationAttributes(attr, 
	                                             keyTemplate - attr,
	                                             operations);
    }

    if (properties) {
	numLeft = numkt - (attr - keyTemplate);
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

NSS_IMPLEMENT PRStatus
nssToken_DeriveSSLSessionKeys (
  NSSToken *token,
  nssSession *session,
  const NSSAlgNParam *ap,
  nssCryptokiObject *masterSecret,
  PRUint32 keySize,
  NSSSymKeyType keyType,
  nssCryptokiObject **rvSessionKeys /* [4] */
)
{
    CK_RV ckrv;
    CK_MECHANISM_PTR mechanism;
    CK_OBJECT_HANDLE keyH;
    CK_ATTRIBUTE keyTemplate[4];
    CK_ATTRIBUTE_PTR attr = keyTemplate;
    CK_KEY_TYPE ckKeyType = nssCK_GetSymKeyType(keyType);
    CK_ULONG ktSize;
    void *epv = nssToken_GetCryptokiEPV(token);
    PRUint32 i, keyNum;

    mechanism = nssAlgNParam_GetMechanism(ap);

    /* set up the key template */
    NSS_CK_TEMPLATE_START(keyTemplate, attr, ktSize);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_false);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_CLASS, &g_ck_class_symkey);
    NSS_CK_SET_ATTRIBUTE_VAR( attr, CKA_KEY_TYPE, ckKeyType);
    NSS_CK_SET_ATTRIBUTE_VAR( attr, CKA_VALUE_LEN, keySize);
    /* XXX set any defaults, or allow token to do it? */
    NSS_CK_TEMPLATE_FINISH(keyTemplate, attr, ktSize);
    /* ready to do the derivation */
    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_DeriveKey(session->handle, mechanism,
                                   masterSecret->handle,
                                   keyTemplate, ktSize, &keyH);
    nssSession_ExitMonitor(session);
    if (ckrv == CKR_OK) {
	CK_SSL3_KEY_MAT_PARAMS *kmp;
	CK_SSL3_KEY_MAT_OUT_PTR kmo;

	kmp = (CK_SSL3_KEY_MAT_PARAMS *)mechanism->pParameter;
	kmo = kmp->pReturnedKeyMaterial;
	/* XXX all in the same session? */
	keyNum = 0;
	rvSessionKeys[0] = nssCryptokiObject_Create(token, session, 
	                                            kmo->hClientMacSecret);
	if (!rvSessionKeys[0]) {
	    return PR_FAILURE;
	}
	keyNum++;
	rvSessionKeys[1] = nssCryptokiObject_Create(token, session, 
	                                            kmo->hServerMacSecret);
	if (!rvSessionKeys[1]) {
	    for (i=0; i<keyNum; i++) 
		nssCryptokiObject_Destroy(rvSessionKeys[i]);
	    return PR_FAILURE;
	}
	keyNum++;
	rvSessionKeys[2] = nssCryptokiObject_Create(token, session, 
	                                            kmo->hClientKey);
	if (!rvSessionKeys[2]) {
	    for (i=0; i<keyNum; i++) 
		nssCryptokiObject_Destroy(rvSessionKeys[i]);
	    return PR_FAILURE;
	}
	keyNum++;
	rvSessionKeys[3] = nssCryptokiObject_Create(token, session, 
	                                            kmo->hServerKey);
	if (!rvSessionKeys[3]) {
	    for (i=0; i<keyNum; i++) 
		nssCryptokiObject_Destroy(rvSessionKeys[i]);
	    return PR_FAILURE;
	}
	keyNum++;
	return PR_SUCCESS;
    }
    return PR_FAILURE;
}

NSS_IMPLEMENT NSSItem *
nssToken_Encrypt (
  NSSToken *tok,
  nssSession *session,
  const NSSAlgNParam *ap,
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
    PRBool freeit = PR_FALSE;

    mechanism = nssAlgNParam_GetMechanism(ap);

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
nssToken_BeginEncrypt (
  NSSToken *token,
  nssSession *session,
  const NSSAlgNParam *ap,
  nssCryptokiObject *key
)
{
    CK_RV ckrv;
    CK_MECHANISM_PTR mechanism;
    void *epv = nssToken_GetCryptokiEPV(token);

    mechanism = nssAlgNParam_GetMechanism(ap);
    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_EncryptInit(session->handle, mechanism, key->handle);
    nssSession_ExitMonitor(session);
    return (ckrv == CKR_OK) ? PR_SUCCESS : PR_FAILURE;
}

NSS_IMPLEMENT NSSItem *
nssToken_ContinueEncrypt (
  NSSToken *token,
  nssSession *session,
  NSSItem *data,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    CK_RV ckrv;
    PRBool freeit = PR_FALSE;
    void *epv = nssToken_GetCryptokiEPV(token);

    nssSession_EnterMonitor(session);
#ifdef SOFTOKEN_WONT_RETURN_LEN_HERE
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
#endif /* SOFTOKEN_WONT_RETURN_LEN_HERE */
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
nssToken_FinishEncrypt (
  NSSToken *token,
  nssSession *session,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    CK_RV ckrv;
    CK_ULONG bufLen;
    PRBool freeit = PR_FALSE;
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
nssToken_Decrypt (
  NSSToken *tok,
  nssSession *session,
  const NSSAlgNParam *ap,
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
    PRBool freeit = PR_FALSE;

    mechanism = nssAlgNParam_GetMechanism(ap);

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
nssToken_BeginDecrypt (
  NSSToken *token,
  nssSession *session,
  const NSSAlgNParam *ap,
  nssCryptokiObject *key
)
{
    CK_RV ckrv;
    CK_MECHANISM_PTR mechanism;
    void *epv = nssToken_GetCryptokiEPV(token);

    mechanism = nssAlgNParam_GetMechanism(ap);
    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_DecryptInit(session->handle, mechanism, key->handle);
    nssSession_ExitMonitor(session);
    return (ckrv == CKR_OK) ? PR_SUCCESS : PR_FAILURE;
}

NSS_IMPLEMENT NSSItem *
nssToken_ContinueDecrypt (
  NSSToken *token,
  nssSession *session,
  NSSItem *data,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    CK_RV ckrv;
    PRBool freeit = PR_FALSE;
    void *epv = nssToken_GetCryptokiEPV(token);

    nssSession_EnterMonitor(session);
#ifdef SOFTOKEN_WONT_RETURN_LEN_HERE
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
#endif /* SOFTOKEN_WONT_RETURN_LEN_HERE */
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
nssToken_FinishDecrypt (
  NSSToken *token,
  nssSession *session,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    CK_RV ckrv;
    CK_ULONG bufLen;
    PRBool freeit = PR_FALSE;
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
nssToken_Sign (
  NSSToken *token,
  nssSession *session,
  const NSSAlgNParam *ap,
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
    PRBool freeit = PR_FALSE;

    mechanism = nssAlgNParam_GetMechanism(ap);

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
nssToken_BeginSign (
  NSSToken *token,
  nssSession *session,
  const NSSAlgNParam *ap,
  nssCryptokiObject *key
)
{
    CK_RV ckrv;
    CK_MECHANISM_PTR mechanism;
    void *epv = nssToken_GetCryptokiEPV(token);

    mechanism = nssAlgNParam_GetMechanism(ap);
    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_SignInit(session->handle, mechanism, key->handle);
    nssSession_ExitMonitor(session);
    return (ckrv == CKR_OK) ? PR_SUCCESS : PR_FAILURE;
}

NSS_IMPLEMENT PRStatus
nssToken_ContinueSign (
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
nssToken_FinishSign (
  NSSToken *tok,
  nssSession *session,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    CK_RV ckrv;
    CK_ULONG sigLen;
    PRBool freeit = PR_FALSE;
    void *epv = nssToken_GetCryptokiEPV(tok);

    nssSession_EnterMonitor(session);
    /* Get the length */
#ifndef SOFTOKEN_WONT_DO_LENGTH_FOR_TLS_PRF
    if (rvOpt && rvOpt->size > 0) goto do_sign;
#endif /* SOFTOKEN_WONT_DO_LENGTH_FOR_TLS_PRF */
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
#ifndef SOFTOKEN_WONT_DO_LENGTH_FOR_TLS_PRF
do_sign:
#endif /* SOFTOKEN_WONT_DO_LENGTH_FOR_TLS_PRF */
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
nssToken_SignRecover (
  NSSToken *tok,
  nssSession *session,
  const NSSAlgNParam *ap,
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
    PRBool freeit = PR_FALSE;

    mechanism = nssAlgNParam_GetMechanism(ap);

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
nssToken_Verify (
  NSSToken *token,
  nssSession *session,
  const NSSAlgNParam *ap,
  nssCryptokiObject *key,
  NSSItem *data,
  NSSItem *signature
)
{
    CK_RV ckrv;
    CK_MECHANISM_PTR mechanism;
    void *epv = nssToken_GetCryptokiEPV(token);

    mechanism = nssAlgNParam_GetMechanism(ap);

    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_VerifyInit(session->handle, mechanism, key->handle);
    if (ckrv != CKR_OK) {
	return PR_FAILURE;
    }
    /* Do the single-part verification */
#ifndef SOFTOKEN_SINGLE_PART_VERIFY_BUG
    if (mechanism->mechanism != CKM_RSA_PKCS) {
    /* XXX the softoken does not do single-part verification correctly,
     *     it fails to hash the data before signing
     *     but that's ok when no ongoing hash is involved, and (at least
     *     CKM_RSA_PKCS) doing it multi-part doesn't work either...
     */
    ckrv = CKAPI(epv)->C_VerifyUpdate(session->handle, 
                                      (CK_BYTE_PTR)data->data, 
                                      (CK_ULONG)data->size);
    if (ckrv == CKR_OK) {
	ckrv = CKAPI(epv)->C_VerifyFinal(session->handle, 
	                                 (CK_BYTE_PTR)signature->data, 
	                                 (CK_ULONG)signature->size);
    }
    } else {
    ckrv = CKAPI(epv)->C_Verify(session->handle, 
                                (CK_BYTE_PTR)data->data, 
                                (CK_ULONG)data->size,
                                (CK_BYTE_PTR)signature->data,
                                (CK_ULONG)signature->size);
    }
#endif /* SOFTOKEN_SINGLE_PART_VERIFY_BUG */
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
	    nss_SetGenericDeviceError(ckrv);
	}
	return PR_FAILURE;
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT PRStatus
nssToken_BeginVerify (
  NSSToken *token,
  nssSession *session,
  const NSSAlgNParam *ap,
  nssCryptokiObject *key
)
{
    CK_RV ckrv;
    CK_MECHANISM_PTR mechanism;
    void *epv = nssToken_GetCryptokiEPV(token);

    mechanism = nssAlgNParam_GetMechanism(ap);
    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_VerifyInit(session->handle, mechanism, key->handle);
    nssSession_ExitMonitor(session);
    return (ckrv == CKR_OK) ? PR_SUCCESS : PR_FAILURE;
}

NSS_IMPLEMENT PRStatus
nssToken_ContinueVerify (
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
nssToken_FinishVerify (
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
	    nss_SetGenericDeviceError(ckrv);
	}
	return PR_FAILURE;
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSItem *
nssToken_VerifyRecover (
  NSSToken *tok,
  nssSession *session,
  const NSSAlgNParam *ap,
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
    PRBool freeit = PR_FALSE;

    mechanism = nssAlgNParam_GetMechanism(ap);

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
nssToken_Digest (
  NSSToken *tok,
  nssSession *session,
  const NSSAlgNParam *ap,
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
    PRBool freeit = PR_FALSE;

    mechanism = nssAlgNParam_GetMechanism(ap);

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

/* XXX move this */
NSS_IMPLEMENT PRStatus
nssCK_MapCKRVToNSSError
(
  CK_RV ckrv
)
{
    NSSError e;
    if (ckrv == CKR_OK) return PR_SUCCESS;
    switch (ckrv) {
    case CKR_OPERATION_ACTIVE: e = NSS_ERROR_SESSION_IN_USE; break;
    default:                   e = NSS_ERROR_DEVICE_ERROR;
    }
    nss_SetError(e);
    return PR_FAILURE;
}

NSS_IMPLEMENT PRStatus
nssToken_BeginDigest (
  NSSToken *tok,
  nssSession *session,
  const NSSAlgNParam *ap
)
{
    CK_RV ckrv;
    CK_MECHANISM_PTR mechanism;
    void *epv = nssToken_GetCryptokiEPV(tok);

    mechanism = nssAlgNParam_GetMechanism(ap);
    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_DigestInit(session->handle, mechanism);
    nssSession_ExitMonitor(session);
    return nssCK_MapCKRVToNSSError(ckrv);
}

NSS_IMPLEMENT PRStatus
nssToken_ContinueDigest (
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

NSS_IMPLEMENT PRStatus
nssToken_DigestKey (
  NSSToken *tok,
  nssSession *session,
  nssCryptokiObject *key
)
{
    CK_RV ckrv;
    void *epv = nssToken_GetCryptokiEPV(tok);

    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_DigestKey(session->handle, key->handle);
    nssSession_ExitMonitor(session);
    return (ckrv == CKR_OK) ? PR_SUCCESS : PR_FAILURE;
}

NSS_IMPLEMENT NSSItem *
nssToken_FinishDigest (
  NSSToken *tok,
  nssSession *session,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    CK_RV ckrv;
    CK_ULONG digestLen;
    PRBool freeit = PR_FALSE;
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

