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

#ifndef PKISTORE_H
#include "pkistore.h"
#endif /* PKISTORE_H */

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
  NSSCallback *callback; /* this can be changed or overriden */
  /* these are set when the context is used for an operation */
  NSSToken *token;
  nssSession *session;
  NSSAlgorithmAndParameters *ap; /* this can be overriden */
  nssCryptokiObject *key; /* key used for crypto */
  nssCryptokiObject *bkey; /* public key of user cert */
  union {
    NSSSymmetricKey *mkey;
    NSSPublicKey *bkey;
    NSSPrivateKey *vkey;
    NSSCertificate *cert;
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
  const NSSAlgorithmAndParameters *apOpt,
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
	rvCC->ap = nssAlgorithmAndParameters_Clone(apOpt, rvCC->arena);
	if (!rvCC->ap) {
	    nssArena_Destroy(arena);
	    return (NSSCryptoContext *)NULL;
	}
    }
    return rvCC;
}

NSS_IMPLEMENT NSSCryptoContext *
nssCryptoContext_CreateForSymmetricKey (
  NSSSymmetricKey *mkey,
  const NSSAlgorithmAndParameters *apOpt,
  NSSCallback *uhhOpt
)
{
    NSSCryptoContext *rvCC;
    NSSTrustDomain *td = nssSymmetricKey_GetTrustDomain(mkey, NULL);

    rvCC = nssCryptoContext_Create(td, apOpt, uhhOpt);
    if (rvCC) {
	rvCC->which = a_symkey;
	rvCC->u.mkey = nssSymmetricKey_AddRef(mkey);
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
    case a_cert: nssCertificate_Destroy(cc->u.cert); break;
    case a_pubkey: nssPublicKey_Destroy(cc->u.bkey); break;
    case a_privkey: nssPrivateKey_Destroy(cc->u.vkey); break;
    case a_symkey: nssSymmetricKey_Destroy(cc->u.mkey); break;
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
  const NSSAlgorithmAndParameters *ap
)
{
    if (cc->token) {
	/* check that the token can do the operation */
	if (!nssToken_DoesAlgorithm(cc->token, ap)) {
	    /*nss_SetError(NSS_ERROR_NO_TOKEN_FOR_OPERATION);*/
	    goto loser;
	}
    } else {
	/* Set the token where the operation will take place */
	cc->token = nssTrustDomain_FindTokenForAlgorithmAndParameters(cc->td, 
	                                                              ap);
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
prepare_context_symmetric_key (
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *ap
)
{
    if (cc->token) {
	/* context already has a token set */
	if (nssToken_DoesAlgorithm(cc->token, ap)) {
	    /* and the token can do the operation */
	    if (!cc->key) {
		/* get a key instance from it */
		cc->key = nssSymmetricKey_GetInstance(cc->u.mkey, cc->token);
	    } /* else we already have a key instance */
	} else {
	    /* the token can't do the math, so this context won't work */
	    goto loser;
	}
    } else {
	/* find an instance of the key that will do the operation */
	cc->key = nssSymmetricKey_FindInstanceForAlgorithm(cc->u.mkey, cc->ap);
	if (cc->key) {
	    /* okay, now we know what token to use */
	    cc->token = nssToken_AddRef(cc->key->token);
	} else {
	    /* find any token in the trust domain that can */
	    cc->token = nssTrustDomain_FindTokenForAlgorithmAndParameters(cc->td, ap);
	    if (!cc->token) {
		/*nss_SetError(NSS_ERROR_NO_TOKEN_FOR_OPERATION);*/
		goto loser;
	    }
	}
    }
    /* the token has been set, so if we didn't find a key instance on
     * the token, copy it there
     */
    if (!cc->key) {
	cc->key = nssSymmetricKey_CopyToToken(cc->u.mkey, cc->token);
	if (!cc->key) {
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
prepare_context_private_key (
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *ap
)
{
    NSSPrivateKey *vkey = NULL;
    if (cc->which == a_cert) {
	/* try to get the key from the cert */
	vkey = nssCertificate_FindPrivateKey(cc->u.cert, cc->callback);
	if (!vkey) {
	    goto loser;
	}
    } else {
	vkey = nssPrivateKey_AddRef(cc->u.vkey);
    }
    if (cc->token) {
	/* context already has a token set */
	if (nssToken_DoesAlgorithm(cc->token, ap)) {
	    /* and the token can do the operation */
	    if (!cc->key) {
		/* get a key instance from it */
		cc->key = nssPrivateKey_GetInstance(vkey, cc->token);
	    } /* else we already have a key instance for the token */
	} else {
	    /* the token can't do the math, so this context won't work */
	    goto loser;
	}
    } else {
	/* find an instance of the key that will do the operation */
	cc->key = nssPrivateKey_FindInstanceForAlgorithm(vkey, cc->ap);
	if (cc->key) {
	    /* okay, now we know what token to use */
	    cc->token = nssToken_AddRef(cc->key->token);
	} else {
	    /* find any token in the trust domain that can */
	    cc->token = nssTrustDomain_FindTokenForAlgorithmAndParameters(cc->td, ap);
	    if (!cc->token) {
		/*nss_SetError(NSS_ERROR_NO_TOKEN_FOR_OPERATION);*/
		goto loser;
	    }
	}
    }
    /* the token has been set, so if we didn't find a key instance on
     * the token, copy it there
     */
    if (!cc->key) {
	cc->key = nssPrivateKey_CopyToToken(vkey, cc->token);
	if (!cc->key) {
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
    if (vkey) {
	nssPrivateKey_Destroy(vkey);
    }
    return PR_SUCCESS;
loser:
    if (vkey) {
	nssPrivateKey_Destroy(vkey);
    }
    nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
    return PR_FAILURE;
}

static PRStatus
prepare_context_public_key (
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *ap
)
{
    /* when the dist. object is a cert, both keys may be available,
     * so public key is stored separately
     */
    nssCryptokiObject **bkp = (cc->which == a_cert) ? &cc->bkey : &cc->key;
    NSSPublicKey *bkey = NULL;
    if (cc->which == a_cert) {
	/* try to get the key from the cert */
	bkey = nssCertificate_GetPublicKey(cc->u.cert);
	if (!bkey) {
	    goto loser;
	}
    } else {
	bkey = nssPublicKey_AddRef(cc->u.bkey);
    }
    if (cc->token) {
	/* context already has a token set */
	if (nssToken_DoesAlgorithm(cc->token, ap)) {
	    /* and the token can do the operation */
	    if (!*bkp) {
		/* get a key instance from it */
		*bkp = nssPublicKey_GetInstance(bkey, cc->token);
	    } /* else we already have a key instance for the token */
	} else {
	    /* the token can't do the math, so this context won't work */
	    goto loser;
	}
    } else {
	/* find an instance of the key that will do the operation */
	*bkp = nssPublicKey_FindInstanceForAlgorithm(bkey, cc->ap);
	if (*bkp) {
	    /* okay, now we know what token to use */
	    cc->token = nssToken_AddRef(cc->key->token);
	} else {
	    /* find any token in the trust domain that can */
	    cc->token = nssTrustDomain_FindTokenForAlgorithmAndParameters(cc->td, ap);
	    if (!cc->token) {
		/*nss_SetError(NSS_ERROR_NO_TOKEN_FOR_OPERATION);*/
		goto loser;
	    }
	}
    }
    /* the token has been set, so if we didn't find a key instance on
     * the token, copy it there
     */
    if (!*bkp) {
	*bkp = nssPublicKey_CopyToToken(bkey, cc->token);
	if (!*bkp) {
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
    if (bkey) {
	nssPublicKey_Destroy(bkey);
    }
    return PR_SUCCESS;
loser:
    if (bkey) {
	nssPublicKey_Destroy(bkey);
    }
    nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
    return PR_FAILURE;
}

NSS_IMPLEMENT NSSItem *
nssCryptoContext_Encrypt (
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *data,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nssCryptokiObject *key;
    const NSSAlgorithmAndParameters *ap = apOpt ? apOpt : cc->ap;
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
  const NSSAlgorithmAndParameters *apOpt,
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
  const NSSAlgorithmAndParameters *apOpt,
  NSSCallback *uhhOpt
)
{
    nssCryptokiObject *key;
    const NSSAlgorithmAndParameters *ap = apOpt ? apOpt : cc->ap;
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
  const NSSAlgorithmAndParameters *apOpt,
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
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *encryptedData,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    const NSSAlgorithmAndParameters *ap = apOpt ? apOpt : cc->ap;
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
  const NSSAlgorithmAndParameters *apOpt,
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
  const NSSAlgorithmAndParameters *apOpt,
  NSSCallback *uhhOpt
)
{
    const NSSAlgorithmAndParameters *ap = apOpt ? apOpt : cc->ap;
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
  const NSSAlgorithmAndParameters *apOpt,
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
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *data,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    const NSSAlgorithmAndParameters *ap = apOpt ? apOpt : cc->ap;
    if (!ap) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSItem *)NULL;
    }
    if (prepare_context_private_key(cc, ap) == PR_FAILURE) {
	return (NSSItem *)NULL;
    }
    return nssToken_Sign(cc->token, cc->session, ap, cc->key,
                         data, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
NSSCryptoContext_Sign (
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
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
    return nssCryptoContext_Sign(cc, apOpt, data, uhhOpt, rvOpt, arenaOpt);
}

NSS_IMPLEMENT PRStatus
nssCryptoContext_BeginSign (
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSCallback *uhhOpt
)
{
    const NSSAlgorithmAndParameters *ap = apOpt ? apOpt : cc->ap;
    if (!ap) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return PR_FAILURE;
    }
    if (prepare_context_private_key(cc, ap) == PR_FAILURE) {
	return PR_FAILURE;
    }
    return nssToken_BeginSign(cc->token, cc->session, ap, cc->key);
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_BeginSign (
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSCallback *uhhOpt
)
{
    PR_ASSERT(cc->which == a_privkey || cc->which == a_cert);
    if (cc->which != a_privkey && cc->which != a_cert) {
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
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *data,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    const NSSAlgorithmAndParameters *ap = apOpt ? apOpt : cc->ap;
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
  const NSSAlgorithmAndParameters *apOpt,
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
NSS_IMPLEMENT NSSSymmetricKey *
nssCryptoContext_UnwrapSymmetricKey (
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *wrappedKey,
  NSSCallback *uhhOpt,
  NSSOperations operations,
  NSSProperties properties
)
{
    const NSSAlgorithmAndParameters *ap = apOpt ? apOpt : cc->ap;
    if (!ap) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSSymmetricKey *)NULL;
    }
    /* set up the private key */
    if (prepare_context_private_key(cc, ap) == PR_FAILURE) {
	return (NSSSymmetricKey *)NULL;
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
	cc->mk = nssSymmetricKey_Create(pkio);
	if (!cc->mk) {
	    nssPKIObject_Destroy(pkio);
	    goto loser;
	}
	return nssSymmetricKey_AddRef(cc->mk);
    }
loser:
    if (cc->mko) {
	nssCryptokiObject_Destroy(cc->mko);
	cc->mko = NULL;
    }
    nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
    return (NSSSymmetricKey *)NULL;
}

NSS_IMPLEMENT NSSSymmetricKey *
NSSCryptoContext_UnwrapSymmetricKey (
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *wrappedKey,
  NSSCallback *uhhOpt,
  NSSOperations operations,
  NSSProperties properties
)
{
    if (!cc->vk && !cc->cert) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSSymmetricKey *)NULL;
    }
    return nssCryptoContext_UnwrapSymmetricKey(cc, apOpt, 
                                               wrappedKey, uhhOpt, 
                                               operations, properties);
}
#endif

NSS_IMPLEMENT PRStatus
nssCryptoContext_Verify (
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *data,
  NSSItem *signature,
  NSSCallback *uhhOpt
)
{
    nssCryptokiObject *key;
    const NSSAlgorithmAndParameters *ap = apOpt ? apOpt : cc->ap;
    if (!ap) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return PR_FAILURE;
    }
    if (prepare_context_public_key(cc, ap) == PR_FAILURE) {
	return PR_FAILURE;
    }
    key = (cc->which == a_cert) ? cc->bkey : cc->key;
    return nssToken_Verify(cc->token, cc->session, ap, key,
                           data, signature);
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_Verify (
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *data,
  NSSItem *signature,
  NSSCallback *uhhOpt
)
{
    PR_ASSERT(cc->which == a_pubkey || cc->which == a_cert);
    if (cc->which != a_pubkey && cc->which != a_cert) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return PR_FAILURE;
    }
    return nssCryptoContext_Verify(cc, apOpt, data, signature, uhhOpt);
}

NSS_IMPLEMENT PRStatus
nssCryptoContext_BeginVerify (
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSCallback *uhhOpt
)
{
    nssCryptokiObject *key;
    const NSSAlgorithmAndParameters *ap = apOpt ? apOpt : cc->ap;
    if (!ap) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return PR_FAILURE;
    }
    if (prepare_context_private_key(cc, ap) == PR_FAILURE) {
	return PR_FAILURE;
    }
    key = (cc->which == a_cert) ? cc->bkey : cc->key;
    return nssToken_BeginVerify(cc->token, cc->session, ap, key);
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_BeginVerify (
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSCallback *uhhOpt
)
{
    PR_ASSERT(cc->which == a_pubkey || cc->which == a_cert);
    if (cc->which != a_pubkey && cc->which != a_cert) {
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
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *signature,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nssCryptokiObject *key;
    const NSSAlgorithmAndParameters *ap = apOpt ? apOpt : cc->ap;
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
  const NSSAlgorithmAndParameters *apOpt,
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
nssCryptoContext_WrapSymmetricKey (
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSSymmetricKey *keyToWrap,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    const NSSAlgorithmAndParameters *ap = apOpt ? apOpt : cc->ap;
    if (!ap || cc->mk) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSItem *)NULL;
    }
    /* set the context's symkey to the key to wrap */
    cc->mk = nssSymmetricKey_AddRef(keyToWrap);
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
NSSCryptoContext_WrapSymmetricKey (
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSSymmetricKey *keyToWrap,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    if (!cc->vk && !cc->cert) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSItem *)NULL;
    }
    return nssCryptoContext_WrapSymmetricKey(cc, apOpt, keyToWrap,
                                             uhhOpt, rvOpt, arenaOpt);
}
#endif

NSS_IMPLEMENT NSSItem *
nssCryptoContext_Digest (
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *data,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    const NSSAlgorithmAndParameters *ap = apOpt ? apOpt : cc->ap;
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
  const NSSAlgorithmAndParameters *apOpt,
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
  const NSSAlgorithmAndParameters *apOpt,
  NSSCallback *uhhOpt
)
{
    const NSSAlgorithmAndParameters *ap = apOpt ? apOpt : cc->ap;
    if (!ap) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return PR_FAILURE;
    }
    if (prepare_context_for_operation(cc, apOpt) == PR_FAILURE) {
	return PR_FAILURE;
    }
    return nssToken_BeginDigest(cc->token, cc->session, ap);
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_BeginDigest (
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
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
NSSCryptoContext_Clone (
  NSSCryptoContext *cc
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

