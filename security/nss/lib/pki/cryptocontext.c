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

typedef enum {
  no_object = 0,
  a_cert,
  a_symkey,
  a_pubkey,
  a_privkey
} pki_object_type;

struct NSSCryptoContextStr
{
#if 0
  PRInt32 refCount;
#endif
  /* these are set when the context is created */
  NSSArena *arena;
  NSSTrustDomain *td;
  NSSVolatileDomain *vd;
  NSSCallback *callback; /* this can be changed or overriden */
  /* these are set when the context is used for an operation */
  NSSToken *token;
  nssSession *session;
  NSSAlgNParam *ap; /* this can be overriden */
  nssCryptokiObject *key; /* key used for crypto */
  nssCryptokiObject *bkey; /* public key of user cert */
  union {
    NSSSymKey *mkey;
    NSSPublicKey *bkey;
    NSSPrivateKey *vkey;
    NSSCert *cert;
  } u; /* the distinguished object */
  pki_object_type which;
};

struct NSSCryptoContextMarkStr
{
  NSSArena *arena;
  NSSItem state;
};

NSS_IMPLEMENT NSSCryptoContext *
nssCryptoContext_Create (
  NSSTrustDomain *td,
  NSSVolatileDomain *vdOpt,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhhOpt
)
{
    NSSArena *arena;
    NSSCryptoContext *rvCC;
    arena = NSSArena_Create();
    if (!arena) {
	return (NSSCryptoContext *)NULL;
    }
    rvCC = nss_ZNEW(arena, NSSCryptoContext);
    if (!rvCC) {
	nssArena_Destroy(arena);
	return (NSSCryptoContext *)NULL;
    }
    rvCC->td = td;
    rvCC->arena = arena;
    if (apOpt) {
	rvCC->ap = nssAlgNParam_Clone(apOpt, rvCC->arena);
	if (!rvCC->ap) {
	    nssArena_Destroy(arena);
	    return (NSSCryptoContext *)NULL;
	}
    }
    return rvCC;
}

NSS_IMPLEMENT NSSCryptoContext *
nssCryptoContext_CreateForSymKey (
  NSSSymKey *mkey,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhhOpt
)
{
    NSSCryptoContext *rvCC;
    NSSTrustDomain *td = nssPKIObject_GetTrustDomain(PKIOBJECT(mkey));
    /* XXX multiple vds? */
    NSSVolatileDomain *vd;
    nssPKIObject_GetVolatileDomains(PKIOBJECT(mkey), &vd, 1, NULL, NULL);

    rvCC = nssCryptoContext_Create(td, vd, apOpt, uhhOpt);
    if (rvCC) {
	rvCC->which = a_symkey;
	rvCC->u.mkey = nssSymKey_AddRef(mkey);
    }
    nssVolatileDomain_Destroy(vd);
    return rvCC;
}

NSS_IMPLEMENT NSSCryptoContext *
nssCryptoContext_CreateForPrivateKey (
  NSSPrivateKey *vkey,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhhOpt
)
{
    NSSCryptoContext *rvCC;
    NSSTrustDomain *td = nssPKIObject_GetTrustDomain(PKIOBJECT(vkey));
    /* XXX multiple vds? */
    NSSVolatileDomain *vd;
    nssPKIObject_GetVolatileDomains(PKIOBJECT(vkey), &vd, 1, NULL, NULL);

    rvCC = nssCryptoContext_Create(td, vd, apOpt, uhhOpt);
    if (rvCC) {
	rvCC->which = a_privkey;
	rvCC->u.vkey = nssPrivateKey_AddRef(vkey);
    }
    return rvCC;
}

NSS_IMPLEMENT PRStatus
nssCryptoContext_Destroy (
  NSSCryptoContext *cc
)
{
    PRStatus status = PR_SUCCESS;
    switch (cc->which) {
    case a_cert:    nssCert_Destroy(cc->u.cert);       break;
    case a_pubkey:  nssPublicKey_Destroy(cc->u.bkey);  break;
    case a_privkey: nssPrivateKey_Destroy(cc->u.vkey); break;
    case a_symkey:  nssSymKey_Destroy(cc->u.mkey);     break;
    default: break;
    }
    if (cc->key) {
	nssCryptokiObject_Destroy(cc->key);
    }
    if (cc->bkey) {
	nssCryptokiObject_Destroy(cc->bkey);
    }
    if (cc->token) {
	status |= nssToken_Destroy(cc->token);
    }
    if (cc->session) {
	status |= nssSession_Destroy(cc->session);
    }
    status |= nssArena_Destroy(cc->arena);
    return status;
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_Destroy (
  NSSCryptoContext *cc
)
{
    if (!cc) {
	return PR_SUCCESS;
    }
    return nssCryptoContext_Destroy(cc);
}

NSS_IMPLEMENT PRStatus
nssCryptoContext_SetDefaultCallback (
  NSSCryptoContext *cc,
  NSSCallback *newCallback,
  NSSCallback **oldCallbackOpt
)
{
    if (oldCallbackOpt) {
	*oldCallbackOpt = cc->callback;
    }
    cc->callback = newCallback;
    return PR_SUCCESS;
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_SetDefaultCallback (
  NSSCryptoContext *cc,
  NSSCallback *newCallback,
  NSSCallback **oldCallbackOpt
)
{
    return nssCryptoContext_SetDefaultCallback(cc, 
                                               newCallback, 
                                               oldCallbackOpt);
}

NSS_IMPLEMENT NSSCallback *
nssCryptoContext_GetDefaultCallback (
  NSSCryptoContext *cc,
  PRStatus *statusOpt
)
{
    if (statusOpt) {
	*statusOpt = PR_SUCCESS;
    }
    return cc->callback;
}

NSS_IMPLEMENT NSSCallback *
NSSCryptoContext_GetDefaultCallback (
  NSSCryptoContext *cc,
  PRStatus *statusOpt
)
{
    return nssCryptoContext_GetDefaultCallback(cc, statusOpt);
}

NSS_IMPLEMENT NSSTrustDomain *
nssCryptoContext_GetTrustDomain (
  NSSCryptoContext *cc
)
{
    return cc->td; /* XXX */
}

NSS_IMPLEMENT NSSTrustDomain *
NSSCryptoContext_GetTrustDomain (
  NSSCryptoContext *cc
)
{
    return nssCryptoContext_GetTrustDomain(cc);
}

static PRStatus
prepare_context_for_operation (
  NSSCryptoContext *cc,
  const NSSAlgNParam *ap
)
{
    if (cc->token) {
	/* check that the token can do the operation */
	if (!nssToken_DoesAlgNParam(cc->token, ap)) 
	{
	    /*nss_SetError(NSS_ERROR_NO_TOKEN_FOR_OPERATION);*/
	    goto loser;
	}
    } else {
	/* Set the token where the operation will take place */
	cc->token = nssTrustDomain_FindTokenForAlgNParam(cc->td, ap);
	if (!cc->token) {
	    /*nss_SetError(NSS_ERROR_NO_TOKEN_FOR_OPERATION);*/
	    goto loser;
	}
    }
    /* Obtain a session for the operation */
    if (!cc->session) {
	cc->session = nssToken_CreateSession(cc->token, PR_FALSE);
	if (!cc->session) {
	    goto loser;
	}
    }
    return PR_SUCCESS;
loser:
    nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
    return PR_FAILURE;
}

static PRStatus
prepare_context_key (
  NSSCryptoContext *cc,
  nssPKIObject *key,
  nssCryptokiObject **keyo,
  const NSSAlgNParam *ap
)
{
    PRStatus status;
    if (cc->token) {
	/* context already has a token set */
	if (nssToken_DoesAlgNParam(cc->token, ap)) {
	    /* and the token can do the operation */
	    if (!*keyo) {
		/* get a key instance from it */
		*keyo = nssPKIObject_GetInstance(key, cc->token);
	    } /* else we already have a key instance */
	} else {
	    /* the token can't do the math, so this context won't work */
	    goto loser;
	}
    } else {
	/* find an instance of the key that will do the operation */
	*keyo = nssPKIObject_FindInstanceForAlgorithm(key, cc->ap, PR_TRUE);
	if (*keyo) {
	    /* okay, now we know what token to use */
	    cc->token = nssToken_AddRef(cc->key->token);
	} else {
	    /* find any token in the trust domain that can */
	    cc->token = nssTrustDomain_FindTokenForAlgNParam(cc->td, ap);
	    if (!cc->token) {
		/*nss_SetError(NSS_ERROR_NO_TOKEN_FOR_OPERATION);*/
		goto loser;
	    }
	}
    }
    /* the token has been set, so if we didn't find a key instance on
     * the token, copy it there as a temp (session) object
     */
    if (!*keyo) {
	    /* XXX uh, get the session first */
	status = nssPKIObject_CopyToToken(key, cc->token, NULL, PR_FALSE,
	                                 NULL, keyo);
	if (status == PR_FAILURE) {
	    goto loser;
	}
    }
    /* Obtain a session for the operation */
    if (!cc->session) {
	cc->session = nssToken_CreateSession(cc->token, PR_FALSE);
	if (!cc->session) {
	    goto loser;
	}
    }
    return PR_SUCCESS;
loser:
    nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
    return PR_FAILURE;
}

static PRStatus
prepare_context_symmetric_key (
  NSSCryptoContext *cc,
  const NSSAlgNParam *ap
)
{
    return prepare_context_key(cc, PKIOBJECT(cc->u.mkey), &cc->key, ap);
}

static PRStatus
prepare_context_private_key (
  NSSCryptoContext *cc,
  const NSSAlgNParam *ap
)
{
    PRStatus status;
    NSSPrivateKey *vkey = NULL;
    if (cc->which == a_cert) {
	/* try to get the key from the cert */
	vkey = nssCert_FindPrivateKey(cc->u.cert, cc->callback);
	if (!vkey) {
	    return PR_FAILURE;
	}
    } else {
	vkey = nssPrivateKey_AddRef(cc->u.vkey);
    }
    status = prepare_context_key(cc, PKIOBJECT(vkey), &cc->key, ap);
    nssPrivateKey_Destroy(vkey);
    return status;
}

static PRStatus
prepare_context_public_key (
  NSSCryptoContext *cc,
  const NSSAlgNParam *ap
)
{
    PRStatus status;
    NSSPublicKey *bkey = NULL;
    /* when the dist. object is a cert, both keys may be available,
     * so public key is stored separately
     */
    nssCryptokiObject **bkp = (cc->which == a_cert) ? &cc->bkey : &cc->key;
    if (cc->which == a_cert) {
	/* try to get the key from the cert */
	bkey = nssCert_GetPublicKey(cc->u.cert);
	if (!bkey) {
	    return PR_FAILURE;
	}
    } else {
	bkey = nssPublicKey_AddRef(cc->u.bkey);
    }
    status = prepare_context_key(cc, PKIOBJECT(bkey), bkp, ap);
    nssPublicKey_Destroy(bkey);
    return status;
}

NSS_IMPLEMENT NSSItem *
nssCryptoContext_Encrypt (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nssCryptokiObject *key;
    const NSSAlgNParam *ap = apOpt ? apOpt : cc->ap;
    if (!ap) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSItem *)NULL;
    }
    if (cc->which == a_cert || cc->which == a_pubkey) {
	if (prepare_context_public_key(cc, ap) == PR_FAILURE) {
	    return (NSSItem *)NULL;
	}
	key = (cc->which == a_cert) ? cc->bkey : cc->key;
    } else if (cc->which == a_symkey) {
	if (prepare_context_symmetric_key(cc, ap) == PR_FAILURE) {
	    return (NSSItem *)NULL;
	}
	key = cc->key;
    }
    return nssToken_Encrypt(cc->token, cc->session, ap, key,
                            data, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
NSSCryptoContext_Encrypt (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    if (cc->which != a_symkey) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSItem *)NULL;
    }
    return nssCryptoContext_Encrypt(cc, apOpt, data, 
                                    uhhOpt, rvOpt, arenaOpt);
}

NSS_IMPLEMENT PRStatus
nssCryptoContext_BeginEncrypt (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhhOpt
)
{
    nssCryptokiObject *key;
    const NSSAlgNParam *ap = apOpt ? apOpt : cc->ap;
    if (!ap) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return PR_FAILURE;
    }
    if (cc->which == a_cert || cc->which == a_pubkey) {
	if (prepare_context_public_key(cc, ap) == PR_FAILURE) {
	    return PR_FAILURE;
	}
	key = (cc->which == a_cert) ? cc->bkey : cc->key;
    } else if (cc->which == a_symkey) {
	if (prepare_context_symmetric_key(cc, ap) == PR_FAILURE) {
	    return PR_FAILURE;
	}
	key = cc->key;
    }
    return nssToken_BeginEncrypt(cc->token, cc->session, ap, key);
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_BeginEncrypt (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhhOpt
)
{
    if (cc->which != a_symkey) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return PR_FAILURE;
    }
    return nssCryptoContext_BeginEncrypt(cc, apOpt, uhhOpt);
}

NSS_IMPLEMENT NSSItem *
nssCryptoContext_ContinueEncrypt (
  NSSCryptoContext *cc,
  NSSItem *data,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssToken_ContinueEncrypt(cc->token, cc->session, 
                                    data, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
NSSCryptoContext_ContinueEncrypt (
  NSSCryptoContext *cc,
  NSSItem *data,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    PR_ASSERT(cc->session);
    return nssCryptoContext_ContinueEncrypt(cc, data, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
nssCryptoContext_FinishEncrypt (
  NSSCryptoContext *cc,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssToken_FinishEncrypt(cc->token, cc->session, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
NSSCryptoContext_FinishEncrypt (
  NSSCryptoContext *cc,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    PR_ASSERT(cc->session);
    return nssCryptoContext_FinishEncrypt(cc, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
nssCryptoContext_Decrypt (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSItem *encryptedData,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    const NSSAlgNParam *ap = apOpt ? apOpt : cc->ap;
    if (!ap) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSItem *)NULL;
    }
    if (cc->which == a_cert || cc->which == a_privkey) {
	if (prepare_context_private_key(cc, ap) == PR_FAILURE) {
	    return (NSSItem *)NULL;
	}
    } else if (cc->which == a_symkey) {
	if (prepare_context_symmetric_key(cc, ap) == PR_FAILURE) {
	    return (NSSItem *)NULL;
	}
    }
    return nssToken_Decrypt(cc->token, cc->session, ap, cc->key,
                            encryptedData, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
NSSCryptoContext_Decrypt (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSItem *encryptedData,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    if (cc->which != a_symkey) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSItem *)NULL;
    }
    return nssCryptoContext_Decrypt(cc, apOpt, encryptedData, 
                                    uhhOpt, rvOpt, arenaOpt);
}

NSS_IMPLEMENT PRStatus
nssCryptoContext_BeginDecrypt (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhhOpt
)
{
    const NSSAlgNParam *ap = apOpt ? apOpt : cc->ap;
    if (!ap) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return PR_FAILURE;
    }
    if (cc->which == a_cert || cc->which == a_privkey) {
	if (prepare_context_private_key(cc, ap) == PR_FAILURE) {
	    return PR_FAILURE;
	}
    } else if (cc->which == a_symkey) {
	if (prepare_context_symmetric_key(cc, ap) == PR_FAILURE) {
	    return PR_FAILURE;
	}
    }
    return nssToken_BeginDecrypt(cc->token, cc->session, ap, cc->key);
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_BeginDecrypt (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhhOpt
)
{
    if (cc->which != a_symkey) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return PR_FAILURE;
    }
    return nssCryptoContext_BeginDecrypt(cc, apOpt, uhhOpt);
}

NSS_IMPLEMENT NSSItem *
nssCryptoContext_ContinueDecrypt (
  NSSCryptoContext *cc,
  NSSItem *data,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssToken_ContinueDecrypt(cc->token, cc->session, 
                                    data, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
NSSCryptoContext_ContinueDecrypt (
  NSSCryptoContext *cc,
  NSSItem *data,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    PR_ASSERT(cc->session);
    return nssCryptoContext_ContinueDecrypt(cc, data, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
nssCryptoContext_FinishDecrypt (
  NSSCryptoContext *cc,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssToken_FinishDecrypt(cc->token, cc->session, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
NSSCryptoContext_FinishDecrypt (
  NSSCryptoContext *cc,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    PR_ASSERT(cc->session);
    return nssCryptoContext_FinishDecrypt(cc, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
nssCryptoContext_Sign (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    const NSSAlgNParam *ap = apOpt ? apOpt : cc->ap;
    if (!ap) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSItem *)NULL;
    }
    if (cc->which == a_symkey) {
	if (prepare_context_symmetric_key(cc, ap) == PR_FAILURE)
	    return (NSSItem *)NULL;
    } else {
	if (prepare_context_private_key(cc, ap) == PR_FAILURE)
	    return (NSSItem *)NULL;
    }
    return nssToken_Sign(cc->token, cc->session, ap, cc->key,
                         data, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
NSSCryptoContext_Sign (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    PR_ASSERT(cc->which == a_symkey || 
              cc->which == a_privkey || 
              cc->which == a_cert);
    if (cc->which != a_symkey && 
	cc->which != a_privkey && cc->which != a_cert) 
    {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSItem *)NULL;
    }
    return nssCryptoContext_Sign(cc, apOpt, data, uhhOpt, rvOpt, arenaOpt);
}

NSS_IMPLEMENT PRStatus
nssCryptoContext_BeginSign (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhhOpt
)
{
    const NSSAlgNParam *ap = apOpt ? apOpt : cc->ap;
    if (!ap) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return PR_FAILURE;
    }
    if (cc->which == a_symkey) {
	if (prepare_context_symmetric_key(cc, ap) == PR_FAILURE)
	    return PR_FAILURE;
    } else {
	if (prepare_context_private_key(cc, ap) == PR_FAILURE)
	    return PR_FAILURE;
    }
    return nssToken_BeginSign(cc->token, cc->session, ap, cc->key);
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_BeginSign (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhhOpt
)
{
    PR_ASSERT(cc->which == a_symkey || 
              cc->which == a_privkey || 
              cc->which == a_cert);
    if (cc->which != a_symkey && 
	cc->which != a_privkey && cc->which != a_cert) 
    {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return PR_FAILURE;
    }
    return nssCryptoContext_BeginSign(cc, apOpt, uhhOpt);
}

NSS_IMPLEMENT PRStatus
nssCryptoContext_ContinueSign (
  NSSCryptoContext *cc,
  NSSItem *data
)
{
    return nssToken_ContinueSign(cc->token, cc->session, data);
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_ContinueSign (
  NSSCryptoContext *cc,
  NSSItem *data
)
{
    PR_ASSERT(cc->session);
    return nssCryptoContext_ContinueSign(cc, data);
}

NSS_IMPLEMENT NSSItem *
nssCryptoContext_FinishSign (
  NSSCryptoContext *cc,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssToken_FinishSign(cc->token, cc->session, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
NSSCryptoContext_FinishSign (
  NSSCryptoContext *cc,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    PR_ASSERT(cc->session);
    return nssCryptoContext_FinishSign(cc, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
nssCryptoContext_SignRecover (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    const NSSAlgNParam *ap = apOpt ? apOpt : cc->ap;
    if (!ap) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSItem *)NULL;
    }
    if (prepare_context_private_key(cc, ap) == PR_FAILURE) {
	return (NSSItem *)NULL;
    }
    return nssToken_SignRecover(cc->token, cc->session, ap, cc->key,
                                data, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
NSSCryptoContext_SignRecover (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    PR_ASSERT(cc->which == a_privkey || cc->which == a_cert);
    if (cc->which != a_privkey && cc->which != a_cert) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSItem *)NULL;
    }
    return nssCryptoContext_SignRecover(cc, apOpt, data, 
                                        uhhOpt, rvOpt, arenaOpt);
}

#if 0
NSS_IMPLEMENT NSSSymKey *
nssCryptoContext_UnwrapSymKey (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSItem *wrappedKey,
  NSSCallback *uhhOpt,
  NSSOperations operations,
  NSSProperties properties
)
{
    const NSSAlgNParam *ap = apOpt ? apOpt : cc->ap;
    if (!ap) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSSymKey *)NULL;
    }
    /* set up the private key */
    if (prepare_context_private_key(cc, ap) == PR_FAILURE) {
	return (NSSSymKey *)NULL;
    }
    /* do the unwrap */
    cc->mko = nssToken_UnwrapKey(cc->token, cc->session, ap, cc->vko,
                                 wrappedKey, PR_FALSE, 
                                 operations, properties);
    /* create a new symkey */
    if (cc->mko) {
	nssPKIObject *pkio;
	pkio = nssPKIObject_Create(NULL, cc->mko, cc->td, cc);
	if (!pkio) {
	    goto loser;
	}
	cc->mk = nssSymKey_Create(pkio);
	if (!cc->mk) {
	    nssPKIObject_Destroy(pkio);
	    goto loser;
	}
	return nssSymKey_AddRef(cc->mk);
    }
loser:
    if (cc->mko) {
	nssCryptokiObject_Destroy(cc->mko);
	cc->mko = NULL;
    }
    nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
    return (NSSSymKey *)NULL;
}

NSS_IMPLEMENT NSSSymKey *
NSSCryptoContext_UnwrapSymKey (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSItem *wrappedKey,
  NSSCallback *uhhOpt,
  NSSOperations operations,
  NSSProperties properties
)
{
    if (!cc->vk && !cc->cert) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSSymKey *)NULL;
    }
    return nssCryptoContext_UnwrapSymKey(cc, apOpt, 
                                               wrappedKey, uhhOpt, 
                                               operations, properties);
}
#endif

NSS_IMPLEMENT PRStatus
nssCryptoContext_Verify (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSItem *signature,
  NSSCallback *uhhOpt
)
{
    nssCryptokiObject *key;
    const NSSAlgNParam *ap = apOpt ? apOpt : cc->ap;
    if (!ap) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return PR_FAILURE;
    }
    if (cc->which == a_symkey) {
	if (prepare_context_symmetric_key(cc, ap) == PR_FAILURE)
	    return PR_FAILURE;
    } else {
	if (prepare_context_public_key(cc, ap) == PR_FAILURE)
	    return PR_FAILURE;
    }
    key = (cc->which == a_cert) ? cc->bkey : cc->key;
    return nssToken_Verify(cc->token, cc->session, ap, key,
                           data, signature);
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_Verify (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSItem *signature,
  NSSCallback *uhhOpt
)
{
    PR_ASSERT(cc->which == a_symkey || 
              cc->which == a_pubkey || 
              cc->which == a_cert);
    if (cc->which != a_symkey && 
        cc->which != a_pubkey && cc->which != a_cert) 
    {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return PR_FAILURE;
    }
    return nssCryptoContext_Verify(cc, apOpt, data, signature, uhhOpt);
}

NSS_IMPLEMENT PRStatus
nssCryptoContext_BeginVerify (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhhOpt
)
{
    nssCryptokiObject *key;
    const NSSAlgNParam *ap = apOpt ? apOpt : cc->ap;
    if (!ap) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return PR_FAILURE;
    }
    if (cc->which == a_symkey) {
	if (prepare_context_symmetric_key(cc, ap) == PR_FAILURE)
	    return PR_FAILURE;
    } else {
	if (prepare_context_public_key(cc, ap) == PR_FAILURE)
	    return PR_FAILURE;
    }
    key = (cc->which == a_cert) ? cc->bkey : cc->key;
    return nssToken_BeginVerify(cc->token, cc->session, ap, key);
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_BeginVerify (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhhOpt
)
{
    PR_ASSERT(cc->which == a_symkey || 
              cc->which == a_pubkey || 
              cc->which == a_cert);
    if (cc->which != a_symkey && 
        cc->which != a_pubkey && cc->which != a_cert) 
    {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return PR_FAILURE;
    }
    return nssCryptoContext_BeginVerify(cc, apOpt, uhhOpt);
}

NSS_IMPLEMENT PRStatus
nssCryptoContext_ContinueVerify (
  NSSCryptoContext *cc,
  NSSItem *data
)
{
    return nssToken_ContinueVerify(cc->token, cc->session, data);
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_ContinueVerify (
  NSSCryptoContext *cc,
  NSSItem *data
)
{
    PR_ASSERT(cc->session);
    return nssCryptoContext_ContinueVerify(cc, data);
}

NSS_IMPLEMENT PRStatus
nssCryptoContext_FinishVerify (
  NSSCryptoContext *cc,
  NSSItem *signature
)
{
    return nssToken_FinishVerify(cc->token, cc->session, signature);
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_FinishVerify (
  NSSCryptoContext *cc,
  NSSItem *signature
)
{
    PR_ASSERT(cc->session);
    return nssCryptoContext_FinishVerify(cc, signature);
}

NSS_IMPLEMENT NSSItem *
nssCryptoContext_VerifyRecover (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSItem *signature,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nssCryptokiObject *key;
    const NSSAlgNParam *ap = apOpt ? apOpt : cc->ap;
    if (!ap) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSItem *)NULL;
    }
    if (prepare_context_private_key(cc, ap) == PR_FAILURE) {
	return (NSSItem *)NULL;
    }
    key = (cc->which == a_cert) ? cc->bkey : cc->key;
    return nssToken_VerifyRecover(cc->token, cc->session, ap, key,
                                  signature, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
NSSCryptoContext_VerifyRecover (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSItem *signature,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    PR_ASSERT(cc->which == a_pubkey || cc->which == a_cert);
    if (cc->which != a_pubkey && cc->which != a_cert) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSItem *)NULL;
    }
    return nssCryptoContext_VerifyRecover(cc, apOpt, signature, 
                                          uhhOpt, rvOpt, arenaOpt);
}

#if 0
NSS_IMPLEMENT NSSItem *
nssCryptoContext_WrapSymKey (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSSymKey *keyToWrap,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    const NSSAlgNParam *ap = apOpt ? apOpt : cc->ap;
    if (!ap || cc->mk) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSItem *)NULL;
    }
    /* set the context's symkey to the key to wrap */
    cc->mk = nssSymKey_AddRef(keyToWrap);
    /* initialize the context with the symkey first */
    if (prepare_context_symmetric_key(cc, ap) == PR_FAILURE) {
	/* didn't find a token that could do the operation */
	return (NSSItem *)NULL;
    }
    /* now try to initialize with the public key */
    if (prepare_context_public_key(cc, ap) == PR_FAILURE) {
	/* most likely failed trying to move the pubkey */
	return (NSSItem *)NULL;
    }
    /* do the wrap on the token */
    return nssToken_WrapKey(cc->token, cc->session, ap, cc->bko,
                            cc->mko, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
NSSCryptoContext_WrapSymKey (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSSymKey *keyToWrap,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    if (!cc->vk && !cc->cert) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSItem *)NULL;
    }
    return nssCryptoContext_WrapSymKey(cc, apOpt, keyToWrap,
                                             uhhOpt, rvOpt, arenaOpt);
}
#endif

NSS_IMPLEMENT NSSItem *
nssCryptoContext_Digest (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    const NSSAlgNParam *ap = apOpt ? apOpt : cc->ap;
    if (!ap) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSItem *)NULL;
    }
    if (prepare_context_for_operation(cc, ap) == PR_FAILURE) {
	return (NSSItem *)NULL;
    }
    return nssToken_Digest(cc->token, cc->session, ap, 
                           data, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
NSSCryptoContext_Digest (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSItem *data,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssCryptoContext_Digest(cc, apOpt, data, 
                                   uhhOpt, rvOpt, arenaOpt);
}

NSS_IMPLEMENT PRStatus
nssCryptoContext_BeginDigest (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhhOpt
)
{
    PRStatus status;
    const NSSAlgNParam *ap = apOpt ? apOpt : cc->ap;
    if (!ap) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return PR_FAILURE;
    }
    if (prepare_context_for_operation(cc, ap) == PR_FAILURE) {
	return PR_FAILURE;
    }
    status = nssToken_BeginDigest(cc->token, cc->session, ap);
    if (status == PR_FAILURE) {
	NSSError e = NSS_GetError();
	/* XXX the old code handled this...  SSL calls InitState
         *     then HandleHandshake successively, both of which call
	 *     BeginDigest...  perhaps change there, not here?
	 */
	if (e == NSS_ERROR_SESSION_IN_USE) {
	    /* XXX ugly */
	    unsigned char digbuf[64];
	    NSSItem dig; dig.data = digbuf; dig.size = sizeof(digbuf);
	    if (nssToken_FinishDigest(cc->token, cc->session, &dig, NULL) 
	         != NULL)
	    {
		nss_SetError(NSS_ERROR_NO_ERROR);
		return nssToken_BeginDigest(cc->token, cc->session, ap);
	    }
	}
    }
    return status;
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_BeginDigest (
  NSSCryptoContext *cc,
  const NSSAlgNParam *apOpt,
  NSSCallback *uhhOpt
)
{
    return nssCryptoContext_BeginDigest(cc, apOpt, uhhOpt);
}

NSS_IMPLEMENT PRStatus
nssCryptoContext_ContinueDigest (
  NSSCryptoContext *cc,
  NSSItem *item
)
{
    return nssToken_ContinueDigest(cc->token, cc->session, item);
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_ContinueDigest (
  NSSCryptoContext *cc,
  NSSItem *item
)
{
    PR_ASSERT(cc->session);
    return nssCryptoContext_ContinueDigest(cc, item);
}

NSS_IMPLEMENT PRStatus
nssCryptoContext_DigestKey (
  NSSCryptoContext *cc,
  NSSSymKey *mkOpt
)
{
    PRStatus status;
    nssCryptokiObject *mko;
    if (mkOpt) {
	/* The context is being asked to digest a key that may not be
	 * within its scope.  Copy the key if needed.
	 */
	mko = nssPKIObject_GetInstance(PKIOBJECT(mkOpt), cc->token);
	if (!mko) {
	    status = nssPKIObject_CopyToToken(PKIOBJECT(mkOpt), cc->token, 
	                                                cc->session, PR_FALSE,
	                                                NULL, &mko);
	    if (status == PR_FAILURE) {
		return PR_FAILURE;
	    }
	}
    } else {
	if (cc->which != a_symkey) {
	    nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	    return PR_FAILURE;
	}
	mko = cc->key;
    }
    status = nssToken_DigestKey(cc->token, cc->session, mko);
    if (mkOpt) nssCryptokiObject_Destroy(mko);
    return status;
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_DigestKey (
  NSSCryptoContext *cc,
  NSSSymKey *mkOpt
)
{
    return nssCryptoContext_DigestKey(cc, mkOpt);
}

NSS_IMPLEMENT NSSItem *
nssCryptoContext_FinishDigest (
  NSSCryptoContext *cc,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssToken_FinishDigest(cc->token, cc->session, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
NSSCryptoContext_FinishDigest (
  NSSCryptoContext *cc,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    PR_ASSERT(cc->session);
    return nssCryptoContext_FinishDigest(cc, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSCryptoContext *
nssCryptoContext_Clone (
  NSSCryptoContext *cc
)
{
    NSSCryptoContext *rvCC;
    rvCC = nssCryptoContext_Create(cc->td, cc->vd, cc->ap, cc->callback);
    if (!rvCC) {
	return (NSSCryptoContext *)NULL;
    }
    if (cc->token) {
	rvCC->token = nssToken_AddRef(cc->token);
    }
    if (cc->session) {
	rvCC->session = nssSession_Clone(cc->session);
    }
    rvCC->which = cc->which;
    switch (cc->which) {
    case a_cert:    rvCC->u.cert = nssCert_AddRef(cc->u.cert);       break;
    case a_symkey:  rvCC->u.mkey = nssSymKey_AddRef(cc->u.mkey);     break;
    case a_pubkey:  rvCC->u.bkey = nssPublicKey_AddRef(cc->u.bkey);  break;
    case a_privkey: rvCC->u.vkey = nssPrivateKey_AddRef(cc->u.vkey); break;
    default: break;
    }
    /* XXX key, bkey */
    return rvCC;
}

NSS_IMPLEMENT NSSCryptoContext *
NSSCryptoContext_Clone (
  NSSCryptoContext *cc
)
{
    return nssCryptoContext_Clone(cc);
}

NSS_IMPLEMENT NSSCryptoContextMark *
nssCryptoContext_Mark (
  NSSCryptoContext *cc
)
{
    PRStatus status;
    NSSArena *arena;
    NSSCryptoContextMark *rvMark;

    if (!cc->session) {
	/* correct? */
	return (NSSCryptoContextMark *)NULL;
    }

    arena = nssArena_Create();
    if (!arena) {
	return (NSSCryptoContextMark *)NULL;
    }
    rvMark = nss_ZNEW(arena, NSSCryptoContextMark);
    if (!rvMark) {
	nssArena_Destroy(arena);
	return (NSSCryptoContextMark *)NULL;
    }
    rvMark->arena = arena;

    status = nssSession_Save(cc->session, &rvMark->state, arena);
    if (status == PR_FAILURE) {
	nssArena_Destroy(arena);
	return (NSSCryptoContextMark *)NULL;
    }

    return rvMark;
}

NSS_IMPLEMENT NSSCryptoContextMark *
NSSCryptoContext_Mark (
  NSSCryptoContext *cc
)
{
    return nssCryptoContext_Mark(cc);
}

/* unmark means keep the changes, so just free the mark */
NSS_IMPLEMENT PRStatus
nssCryptoContext_Unmark (
  NSSCryptoContext *cc,
  NSSCryptoContextMark *mark
)
{
    return nssArena_Destroy(mark->arena);
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_Unmark (
  NSSCryptoContext *cc,
  NSSCryptoContextMark *mark
)
{
    return nssCryptoContext_Unmark(cc, mark);
} 

/* release means throw away the changes and go back to the mark's state */
NSS_IMPLEMENT PRStatus
nssCryptoContext_Release (
  NSSCryptoContext *cc,
  NSSCryptoContextMark *mark
)
{
    PRStatus status;
    if (!cc->session) {
	/* correct? create new session? */
	return PR_FAILURE;
    }
    status = nssSession_Restore(cc->session, &mark->state);
    nssArena_Destroy(mark->arena);
    return status;
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_Release (
  NSSCryptoContext *cc,
  NSSCryptoContextMark *mark
)
{
    return nssCryptoContext_Release(cc, mark);
}

