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


struct NSSSymKeyStr
{
  nssPKIObject object;
  NSSSymKeyType kind;
  PRUint32 length; /* XXX 64-bit... */
  NSSOperations operations;
};

NSS_IMPLEMENT NSSSymKey *
nssSymKey_CreateFromInstance (
  nssCryptokiObject *instance,
  NSSTrustDomain *td,
  NSSVolatileDomain *vdOpt
)
{
    PRStatus status;
    nssPKIObject *pkio;
    NSSSymKey *rvKey = NULL;

    rvKey = nssPKIObject_CREATE(td, instance, NSSSymKey);
    if (!rvKey) {
	return (NSSSymKey *)NULL;
    }
    pkio = &rvKey->object;
    status = nssCryptokiSymKey_GetAttributes(instance, pkio->arena,
                                             &rvKey->kind,
                                             &rvKey->length,
                                             &rvKey->operations);
    if (status != PR_SUCCESS) {
	goto loser;
    }
    pkio->objectType = pkiObjectType_SymKey;
    pkio->numIDs = 0; /* XXX */
    /* XXX not adding to table w/o uid... */
    if (rvKey && vdOpt) {
	status = nssVolatileDomain_ImportSymKey(vdOpt, rvKey);
	if (status == PR_FAILURE) {
	    goto loser;
	}
    }
    return rvKey;
loser:
    nssSymKey_Destroy(rvKey);
    return (NSSSymKey *)NULL;
}

NSS_IMPLEMENT NSSSymKey *
nssSymKey_AddRef (
  NSSSymKey *mk
)
{
    if (mk) {
	nssPKIObject_AddRef(&mk->object);
    }
    return mk;
}

NSS_IMPLEMENT PRStatus
nssSymKey_Destroy (
  NSSSymKey *mk
)
{
    return nssPKIObject_Destroy(&mk->object);
}

NSS_IMPLEMENT PRStatus
NSSSymKey_Destroy (
  NSSSymKey *mk
)
{
    nssSymKey_Destroy(mk);
    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSToken **
nssSymKey_GetTokens (
  NSSSymKey *mk,
  NSSToken **rvOpt,
  PRUint32 rvMaxOpt,
  PRStatus *statusOpt
)
{
    return nssPKIObject_GetTokens(&mk->object, rvOpt, rvMaxOpt, statusOpt);
}

NSS_IMPLEMENT NSSToken **
NSSSymKey_GetTokens (
  NSSSymKey *mk,
  NSSToken **rvOpt,
  PRUint32 rvMaxOpt,
  PRStatus *statusOpt
)
{
    return nssSymKey_GetTokens(mk, rvOpt, rvMaxOpt, statusOpt);
}

NSS_IMPLEMENT nssCryptokiObject *
nssSymKey_GetInstance (
  NSSSymKey *mk,
  NSSToken *token
)
{
    return nssPKIObject_GetInstance(&mk->object, token);
}

NSS_IMPLEMENT nssCryptokiObject *
nssSymKey_FindInstanceForAlgorithm (
  NSSSymKey *mk,
  const NSSAlgNParam *ap
)
{
    nssCryptokiObject *instance;
    instance = nssPKIObject_FindInstanceForAlgorithm(&mk->object, ap);
    /* XXX here for now... make it apply for all searches... */
    if (!instance) {
	NSSToken *token;
	token = nssTrustDomain_FindTokenForAlgNParam(mk->object.td, ap);
	if (token) {
	    instance = nssSymKey_CopyToToken(mk, token, PR_FALSE);
	    nssToken_Destroy(token);
	}
    }
    return instance;
}

NSS_IMPLEMENT PRBool
nssSymKey_HasInstanceOnToken (
  NSSSymKey *mk,
  NSSToken *token
)
{
    return nssPKIObject_HasInstanceOnToken(&mk->object, token);
}

NSS_IMPLEMENT PRStatus
nssSymKey_DeleteStoredObject (
  NSSSymKey *mk,
  NSSCallback *uhh
)
{
    return nssPKIObject_DeleteStoredObject(&mk->object, uhh, PR_TRUE);
}

NSS_IMPLEMENT PRStatus
NSSSymKey_DeleteStoredObject (
  NSSSymKey *mk,
  NSSCallback *uhh
)
{
    return nssSymKey_DeleteStoredObject(mk, uhh);
}

/* XXX should take session as arg?  crypto contexts copy instances in
 * their own session?
 */
NSS_IMPLEMENT nssCryptokiObject *
nssSymKey_CopyToToken (
  NSSSymKey *mk,
  NSSToken *destination,
  PRBool asPersistentObject
)
{
    /* XXX this could get complicated... might have to wrap the key, etc. */
    nssSession *session;
    nssCryptokiObject *mko;

    session = nssToken_CreateSession(destination, asPersistentObject);
    if (!session) {
	return (nssCryptokiObject *)NULL;
    }
    /* XXX kind of a hack to peek into first instance like this */
    mko = nssCryptokiSymKey_Copy(mk->object.instances[0],
                                       mk->object.instances[0]->session,
                                       destination, session,
                                       asPersistentObject);
    nssSession_Destroy(session);
    if (mko) {
	if (nssPKIObject_AddInstance(&mk->object, mko) == PR_FAILURE) {
	    nssCryptokiObject_Destroy(mko);
	    mko = NULL;
	} else {
	    /* XXX */
	    mko = nssCryptokiObject_Clone(mko);
	}
    }
    return mko;
}

NSS_IMPLEMENT PRUint32
nssSymKey_GetKeyLength (
  NSSSymKey *mk
)
{
    return mk->length;
}

NSS_IMPLEMENT PRUint32
NSSSymKey_GetKeyLength (
  NSSSymKey *mk
)
{
    return nssSymKey_GetKeyLength(mk);
}

#ifndef BPB
#define BPB 8
#endif

NSS_IMPLEMENT PRUint32
NSSSymKey_GetKeyStrength (
  NSSSymKey *mk
)
{
    /* XXX look these up */
    switch (mk->kind) {
    case NSSSymKeyType_DES:       return 56;
    case NSSSymKeyType_TripleDES: return 112; /* IIRC */
    case NSSSymKeyType_RC2:       return -1; /* need eff. len. */
    case NSSSymKeyType_RC4:       return mk->length * BPB;
    case NSSSymKeyType_AES:       return mk->length * BPB;
    default: return -1;
    }
}

NSS_IMPLEMENT PRStatus
NSSSymKey_IsStillPresent (
  NSSSymKey *mk
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return PR_FAILURE;
}

NSS_IMPLEMENT void
nssSymKey_SetVolatileDomain (
  NSSSymKey *mk,
  NSSVolatileDomain *vd
)
{
    nssPKIObject_SetVolatileDomain(&mk->object, vd);
}

NSS_IMPLEMENT NSSTrustDomain *
nssSymKey_GetTrustDomain (
  NSSSymKey *mk,
  PRStatus *statusOpt
)
{
    return nssPKIObject_GetTrustDomain(&mk->object, statusOpt);
}

NSS_IMPLEMENT NSSTrustDomain *
NSSSymKey_GetTrustDomain (
  NSSSymKey *mk,
  PRStatus *statusOpt
)
{
    return nssSymKey_GetTrustDomain(mk, statusOpt);
}

NSS_IMPLEMENT NSSVolatileDomain **
nssSymKey_GetVolatileDomains (
  NSSSymKey *mk,
  NSSVolatileDomain **vdsOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt,
  PRStatus *statusOpt
)
{
    return nssPKIObject_GetVolatileDomains(&mk->object, vdsOpt,
                                           maximumOpt, arenaOpt, statusOpt);
}

NSS_IMPLEMENT NSSToken *
NSSSymKey_GetToken (
  NSSSymKey *mk,
  PRStatus *statusOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSSlot *
NSSSymKey_GetSlot (
  NSSSymKey *mk,
  PRStatus *statusOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSModule *
NSSSymKey_GetModule (
  NSSSymKey *mk,
  PRStatus *statusOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSItem *
nssSymKey_Encrypt (
  NSSSymKey *mk,
  const NSSAlgNParam *ap,
  NSSItem *data,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nssSession *session;
    nssCryptokiObject **op, **objects;
    NSSItem *rvIt = NULL;

    /* XXX in cipher order */
    objects = nssPKIObject_GetInstances(&mk->object);
    for (op = objects; *op; op++) {
	session = nssToken_CreateSession((*op)->token, PR_FALSE);
	if (!session) {
	    break;
	}
	rvIt = nssToken_Encrypt((*op)->token, session, ap, *op, 
	                        data, rvOpt, arenaOpt);
	nssSession_Destroy(session);
	if (rvIt) {
	    break;
	} /* XXX some errors should cause us to break out of the loop here */
    }
    nssCryptokiObjectArray_Destroy(objects);
    return rvIt;
}

NSS_IMPLEMENT NSSItem *
NSSSymKey_Encrypt (
  NSSSymKey *mk,
  const NSSAlgNParam *ap,
  NSSItem *data,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssSymKey_Encrypt(mk, ap, data, uhh, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
nssSymKey_Decrypt (
  NSSSymKey *mk,
  const NSSAlgNParam *ap,
  NSSItem *encryptedData,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nssSession *session;
    nssCryptokiObject **op, **objects;
    NSSItem *rvIt = NULL;

    /* XXX in cipher order */
    objects = nssPKIObject_GetInstances(&mk->object);
    for (op = objects; *op; op++) {
	session = nssToken_CreateSession((*op)->token, PR_FALSE);
	if (!session) {
	    break;
	}
	rvIt = nssToken_Decrypt((*op)->token, session, ap, *op, 
	                        encryptedData, rvOpt, arenaOpt);
	nssSession_Destroy(session);
	if (rvIt) {
	    break;
	} /* XXX some errors should cause us to break out of the loop here */
    }
    nssCryptokiObjectArray_Destroy(objects);
    return rvIt;
}

NSS_IMPLEMENT NSSItem *
NSSSymKey_Decrypt (
  NSSSymKey *mk,
  const NSSAlgNParam *ap,
  NSSItem *encryptedData,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssSymKey_Decrypt(mk, ap, encryptedData, 
                                   uhh, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
nssSymKey_Sign (
  NSSSymKey *mk,
  const NSSAlgNParam *ap,
  NSSItem *data,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nssSession *session;
    nssCryptokiObject **op, **objects;
    NSSItem *rvIt = NULL;

    /* XXX in cipher order */
    objects = nssPKIObject_GetInstances(&mk->object);
    for (op = objects; *op; op++) {
	session = nssToken_CreateSession((*op)->token, PR_FALSE);
	if (!session) {
	    break;
	}
	rvIt = nssToken_Sign((*op)->token, session, ap, *op, 
	                     data, rvOpt, arenaOpt);
	nssSession_Destroy(session);
	if (rvIt) {
	    break;
	} /* XXX some errors should cause us to break out of the loop here */
    }
    nssCryptokiObjectArray_Destroy(objects);
    return rvIt;
}

NSS_IMPLEMENT NSSItem *
NSSSymKey_Sign (
  NSSSymKey *mk,
  const NSSAlgNParam *ap,
  NSSItem *data,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssSymKey_Sign(mk, ap, data, uhh, rvOpt, arenaOpt);
}

NSS_IMPLEMENT PRStatus
nssSymKey_Verify (
  NSSSymKey *mk,
  const NSSAlgNParam *ap,
  NSSItem *data,
  NSSItem *signature,
  NSSCallback *uhh
)
{
    nssSession *session;
    nssCryptokiObject **op, **objects;
    PRStatus status;

    /* XXX in cipher order */
    objects = nssPKIObject_GetInstances(&mk->object);
    for (op = objects; *op; op++) {
	session = nssToken_CreateSession((*op)->token, PR_FALSE);
	if (!session) {
	    break;
	}
	status = nssToken_Verify((*op)->token, session, ap, *op, 
	                         data, signature);
	nssSession_Destroy(session);
	if (status == PR_SUCCESS) {
	    break;
	} else {
	    NSSError e = NSS_GetError();
	    if (e == NSS_ERROR_INVALID_SIGNATURE ||
	        e == NSS_ERROR_INVALID_DATA)
	    {
		break;
	    }
	    /* otherwise, a token failure, so try other tokens */
	}
    }
    nssCryptokiObjectArray_Destroy(objects);
    return status;
}

NSS_IMPLEMENT PRStatus
NSSSymKey_Verify (
  NSSSymKey *mk,
  const NSSAlgNParam *ap,
  NSSItem *data,
  NSSItem *signature,
  NSSCallback *uhh
)
{
    return nssSymKey_Verify(mk, ap, data, signature, uhh);
}

NSS_IMPLEMENT NSSItem *
NSSSymKey_WrapSymKey (
  NSSSymKey *wrappingKey,
  const NSSAlgNParam *ap,
  NSSSymKey *keyToWrap,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSItem *
NSSSymKey_WrapPrivateKey (
  NSSSymKey *wrappingKey,
  const NSSAlgNParam *ap,
  NSSPrivateKey *keyToWrap,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSSymKey *
NSSSymKey_UnwrapSymKey (
  NSSSymKey *wrappingKey,
  const NSSAlgNParam *ap,
  NSSItem *wrappedKey,
  NSSSymKeyType targetSymKeyType,
  PRUint32 keySizeOpt,
  NSSOperations operations,
  NSSCallback *uhh
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSPrivateKey *
NSSSymKey_UnwrapPrivateKey (
  NSSSymKey *wrappingKey,
  const NSSAlgNParam *ap,
  NSSItem *wrappedKey,
  NSSUTF8 *labelOpt,
  NSSItem *keyIDOpt,
  PRBool persistant,
  PRBool sensitive,
  NSSToken *destinationOpt,
  NSSCallback *uhh
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSSymKey *
nssSymKey_DeriveSymKey (
  NSSSymKey *originalKey,
  const NSSAlgNParam *ap,
  NSSSymKeyType target,
  PRUint32 keySizeOpt,
  NSSOperations operations,
  NSSProperties properties,
  NSSToken *destinationOpt,
  NSSVolatileDomain *vdOpt,
  NSSCallback *uhhOpt
)
{
    nssCryptokiObject *mko, *rvo;
    NSSSymKey *rvKey = NULL;
    NSSTrustDomain *td = nssSymKey_GetTrustDomain(originalKey, NULL);

    mko = nssSymKey_FindInstanceForAlgorithm(originalKey, ap);
    if (!mko) {
	return (NSSSymKey *)NULL;
    }

    /* XXX use domains */
    rvo = nssToken_DeriveKey(mko->token, mko->session, ap, mko, 
                             PR_FALSE, operations, properties);
    if (rvo) {
	rvKey = nssSymKey_CreateFromInstance(rvo, td, vdOpt);
	if (!rvKey) {
	    nssCryptokiObject_Destroy(rvo);
	}
    }

    nssCryptokiObject_Destroy(mko);
    return rvKey;
}

NSS_IMPLEMENT NSSSymKey *
NSSSymKey_DeriveSymKey (
  NSSSymKey *originalKey,
  const NSSAlgNParam *ap,
  NSSSymKeyType target,
  PRUint32 keySizeOpt,
  NSSOperations operations,
  NSSProperties properties,
  NSSToken *destinationOpt,
  NSSVolatileDomain *vdOpt,
  NSSCallback *uhhOpt
)
{
    return nssSymKey_DeriveSymKey(originalKey, ap, target,
                                  keySizeOpt, operations, properties,
                                  destinationOpt, vdOpt, uhhOpt);
}

NSS_IMPLEMENT NSSCryptoContext *
nssSymKey_CreateCryptoContext (
  NSSSymKey *mk,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhh
)
{
    NSSCryptoContext *cc;
    cc = nssCryptoContext_CreateForSymKey(mk, apOpt, uhh);
    return cc;
}

NSS_IMPLEMENT NSSCryptoContext *
NSSSymKey_CreateCryptoContext (
  NSSSymKey *mk,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhh
)
{
    return nssSymKey_CreateCryptoContext(mk, apOpt, uhh);
}

NSS_IMPLEMENT PRStatus
nssSymKey_DeriveSSLSessionKeys (
  NSSSymKey *masterSecret,
  const NSSAlgNParam *ap,
  PRUint32 keySize,
  NSSSymKeyType keyType,
  NSSSymKey **rvSessionKeys /* [4] */
)
{
    nssCryptokiObject *mso; /* only one instance of master secret */
    nssCryptokiObject *skeys[4];
    NSSTrustDomain *td = masterSecret->object.td;
    NSSVolatileDomain *vd;
    PRStatus status;
    PRIntn i;

    nssSymKey_GetVolatileDomains(masterSecret, &vd, 1, NULL, &status);
    if (status == PR_FAILURE) {
	return PR_FAILURE;
    }

    mso = masterSecret->object.instances[0];
    status = nssToken_DeriveSSLSessionKeys(mso->token, mso->session, 
                                           ap, mso, keySize, keyType,
                                           skeys);
    if (status == PR_FAILURE) {
	return PR_FAILURE;
    }
    for (i=0; i<4; i++) {
	rvSessionKeys[i] = nssSymKey_CreateFromInstance(skeys[i], td, vd);
	if (!rvSessionKeys[i]) break;
    }
    if (i < 4) {
	nssCryptokiObject_Destroy(skeys[i]);
	for (--i; i>=0; --i) {
	    nssSymKey_Destroy(rvSessionKeys[i]);
	}
	status = PR_FAILURE;
    }
    return status;
}

