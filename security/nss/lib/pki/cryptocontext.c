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

struct NSSCryptoContextStr
{
#if 0
  PRInt32 refCount;
#endif
  NSSArena *arena;
  NSSTrustDomain *td;
  nssCertificateStore *certStore;
  NSSCallback *callback;
  NSSToken *token;
  nssSession *session;
  NSSAlgorithmAndParameters *ap;
  NSSSymmetricKey *mk;
  nssCryptokiObject *mko;
  NSSPrivateKey *vk;
  nssCryptokiObject *vko;
  NSSPublicKey *bk;
  nssCryptokiObject *bko;
  NSSCertificate *cert;
};

extern const NSSError NSS_ERROR_NOT_FOUND;

NSS_IMPLEMENT NSSCryptoContext *
nssCryptoContext_Create
(
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
nssCryptoContext_CreateForSymmetricKey
(
  NSSSymmetricKey *mk,
  const NSSAlgorithmAndParameters *apOpt,
  NSSCallback *uhh
)
{
    NSSCryptoContext *rvCC = NULL;
    NSSTrustDomain *td;

    td = nssSymmetricKey_GetTrustDomain(mk, NULL);
    if (!td) {
	/* nss_SetError(NSS_ERROR_INVALID_SYMKEY); */
	return (NSSCryptoContext *)NULL;
    }

    rvCC = nssCryptoContext_Create(td, apOpt, uhh);
    rvCC->mk = nssSymmetricKey_AddRef(mk);

    return rvCC;
}

NSS_IMPLEMENT PRStatus
nssCryptoContext_Destroy
(
  NSSCryptoContext *cc
)
{
    PRStatus status = PR_SUCCESS;
    if (cc->mk) {
	status |= nssSymmetricKey_Destroy(cc->mk);
	if (cc->mko) {
	    nssCryptokiObject_Destroy(cc->mko);
	}
    }
    if (cc->bk) {
	status |= nssPublicKey_Destroy(cc->bk);
	if (cc->bko) {
	    nssCryptokiObject_Destroy(cc->bko);
	}
    }
    if (cc->vk) {
	status |= nssPrivateKey_Destroy(cc->vk);
	if (cc->vko) {
	    nssCryptokiObject_Destroy(cc->vko);
	}
    }
    if (cc->cert) {
	status |= nssCertificate_Destroy(cc->cert);
    }
    if (cc->token) {
	status |= nssToken_Destroy(cc->token);
    }
    if (cc->session) {
	status |= nssSession_Destroy(cc->session);
    }
    if (cc->certStore) {
	nssCertificateStore_Destroy(cc->certStore);
    }
    status |= nssArena_Destroy(cc->arena);
    return status;
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_Destroy
(
  NSSCryptoContext *cc
)
{
    if (!cc) {
	return PR_SUCCESS;
    }
    return nssCryptoContext_Destroy(cc);
}

NSS_IMPLEMENT PRStatus
nssCryptoContext_SetDefaultCallback
(
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
NSSCryptoContext_SetDefaultCallback
(
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
nssCryptoContext_GetDefaultCallback
(
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
NSSCryptoContext_GetDefaultCallback
(
  NSSCryptoContext *cc,
  PRStatus *statusOpt
)
{
    return nssCryptoContext_GetDefaultCallback(cc, statusOpt);
}

NSS_IMPLEMENT NSSTrustDomain *
nssCryptoContext_GetTrustDomain
(
  NSSCryptoContext *cc
)
{
    return cc->td; /* XXX */
}

NSS_IMPLEMENT NSSTrustDomain *
NSSCryptoContext_GetTrustDomain
(
  NSSCryptoContext *cc
)
{
    return nssCryptoContext_GetTrustDomain(cc);
}

NSS_IMPLEMENT PRStatus
nssCryptoContext_ImportCertificate
(
  NSSCryptoContext *cc,
  NSSCertificate *c
)
{
    PRStatus nssrv;
    if (!cc->certStore) {
	cc->certStore = nssCertificateStore_Create(cc->arena);
	if (!cc->certStore) {
	    return PR_FAILURE;
	}
    }
    nssrv = nssCertificateStore_Add(cc->certStore, c);
    if (nssrv == PR_SUCCESS) {
	nssCertificate_SetCryptoContext(cc);
	cc->cert = nssCertificate_AddRef(c);
    }
    return nssrv;
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_ImportCertificate
(
  NSSCryptoContext *cc,
  NSSCertificate *c
)
{
    return nssCryptoContext_ImportCertificate(cc, c);
}

NSS_IMPLEMENT NSSCertificate *
NSSCryptoContext_ImportPKIXCertificate
(
  NSSCryptoContext *cc,
  struct NSSPKIXCertificateStr *pc
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCertificate *
NSSCryptoContext_ImportEncodedCertificate
(
  NSSCryptoContext *cc,
  NSSBER *ber
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_ImportEncodedPKIXCertificateChain
(
  NSSCryptoContext *cc,
  NSSBER *ber
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return PR_FAILURE;
}

NSS_IMPLEMENT PRStatus
nssCryptoContext_ImportTrust
(
  NSSCryptoContext *cc,
  NSSTrust *trust
)
{
    PRStatus nssrv;
    if (!cc->certStore) {
	cc->certStore = nssCertificateStore_Create(cc->arena);
	if (!cc->certStore) {
	    return PR_FAILURE;
	}
    }
    nssrv = nssCertificateStore_AddTrust(cc->certStore, trust);
#if 0
    if (nssrv == PR_SUCCESS) {
	trust->object.cryptoContext = cc;
    }
#endif
    return nssrv;
}

NSS_IMPLEMENT PRStatus
nssCryptoContext_ImportSMIMEProfile
(
  NSSCryptoContext *cc,
  nssSMIMEProfile *profile
)
{
    PRStatus nssrv;
    if (!cc->certStore) {
	cc->certStore = nssCertificateStore_Create(cc->arena);
	if (!cc->certStore) {
	    return PR_FAILURE;
	}
    }
    nssrv = nssCertificateStore_AddSMIMEProfile(cc->certStore, profile);
#if 0
    if (nssrv == PR_SUCCESS) {
	profile->object.cryptoContext = cc;
    }
#endif
    return nssrv;
}

NSS_IMPLEMENT NSSCertificate *
NSSCryptoContext_FindBestCertificateByNickname
(
  NSSCryptoContext *cc,
  NSSUTF8 *name,
  NSSTime *timeOpt, /* NULL for "now" */
  NSSUsage *usage,
  NSSPolicies *policiesOpt /* NULL for none */
)
{
    NSSCertificate **certs;
    NSSCertificate *rvCert = NULL;
    if (!cc->certStore) {
	return NULL;
    }
    certs = nssCertificateStore_FindCertificatesByNickname(cc->certStore,
                                                           name,
                                                           NULL, 0, NULL);
    if (certs) {
	rvCert = nssCertificateArray_FindBestCertificate(certs,
	                                                 timeOpt,
	                                                 usage,
	                                                 policiesOpt);
	nssCertificateArray_Destroy(certs);
    }
    return rvCert;
}

NSS_IMPLEMENT NSSCertificate **
NSSCryptoContext_FindCertificatesByNickname
(
  NSSCryptoContext *cc,
  NSSUTF8 *name,
  NSSCertificate *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
)
{
    NSSCertificate **rvCerts;
    if (!cc->certStore) {
	return NULL;
    }
    rvCerts = nssCertificateStore_FindCertificatesByNickname(cc->certStore,
                                                             name,
                                                             rvOpt,
                                                             maximumOpt,
                                                             arenaOpt);
    return rvCerts;
}

NSS_IMPLEMENT NSSCertificate *
NSSCryptoContext_FindCertificateByIssuerAndSerialNumber
(
  NSSCryptoContext *cc,
  NSSDER *issuer,
  NSSDER *serialNumber
)
{
    if (!cc->certStore) {
	return NULL;
    }
    return nssCertificateStore_FindCertificateByIssuerAndSerialNumber(
                                                               cc->certStore,
                                                               issuer,
                                                               serialNumber);
}

NSS_IMPLEMENT NSSCertificate *
NSSCryptoContext_FindBestCertificateBySubject
(
  NSSCryptoContext *cc,
  NSSDER *subject,
  NSSTime *timeOpt,
  NSSUsage *usage,
  NSSPolicies *policiesOpt
)
{
    NSSCertificate **certs;
    NSSCertificate *rvCert = NULL;
    if (!cc->certStore) {
	return NULL;
    }
    certs = nssCertificateStore_FindCertificatesBySubject(cc->certStore,
                                                          subject,
                                                          NULL, 0, NULL);
    if (certs) {
	rvCert = nssCertificateArray_FindBestCertificate(certs,
	                                                 timeOpt,
	                                                 usage,
	                                                 policiesOpt);
	nssCertificateArray_Destroy(certs);
    }
    return rvCert;
}

NSS_IMPLEMENT NSSCertificate **
nssCryptoContext_FindCertificatesBySubject
(
  NSSCryptoContext *cc,
  NSSDER *subject,
  NSSCertificate *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
)
{
    NSSCertificate **rvCerts;
    if (!cc->certStore) {
	return NULL;
    }
    rvCerts = nssCertificateStore_FindCertificatesBySubject(cc->certStore,
                                                            subject,
                                                            rvOpt,
                                                            maximumOpt,
                                                            arenaOpt);
    return rvCerts;
}

NSS_IMPLEMENT NSSCertificate **
NSSCryptoContext_FindCertificatesBySubject
(
  NSSCryptoContext *cc,
  NSSDER *subject,
  NSSCertificate *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
)
{
    return nssCryptoContext_FindCertificatesBySubject(cc, subject,
                                                      rvOpt, maximumOpt,
                                                      arenaOpt);
}

NSS_IMPLEMENT NSSCertificate *
NSSCryptoContext_FindBestCertificateByNameComponents
(
  NSSCryptoContext *cc,
  NSSUTF8 *nameComponents,
  NSSTime *timeOpt,
  NSSUsage *usage,
  NSSPolicies *policiesOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCertificate **
NSSCryptoContext_FindCertificatesByNameComponents
(
  NSSCryptoContext *cc,
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
NSSCryptoContext_FindCertificateByEncodedCertificate
(
  NSSCryptoContext *cc,
  NSSBER *encodedCertificate
)
{
    if (!cc->certStore) {
	return NULL;
    }
    return nssCertificateStore_FindCertificateByEncodedCertificate(
                                                           cc->certStore,
                                                           encodedCertificate);
}

NSS_IMPLEMENT NSSCertificate *
NSSCryptoContext_FindBestCertificateByEmail
(
  NSSCryptoContext *cc,
  NSSASCII7 *email,
  NSSTime *timeOpt,
  NSSUsage *usage,
  NSSPolicies *policiesOpt
)
{
    NSSCertificate **certs;
    NSSCertificate *rvCert = NULL;
    if (!cc->certStore) {
	return NULL;
    }
    certs = nssCertificateStore_FindCertificatesByEmail(cc->certStore,
                                                        email,
                                                        NULL, 0, NULL);
    if (certs) {
	rvCert = nssCertificateArray_FindBestCertificate(certs,
	                                                 timeOpt,
	                                                 usage,
	                                                 policiesOpt);
	nssCertificateArray_Destroy(certs);
    }
    return rvCert;
}

NSS_IMPLEMENT NSSCertificate **
NSSCryptoContext_FindCertificatesByEmail
(
  NSSCryptoContext *cc,
  NSSASCII7 *email,
  NSSCertificate *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
)
{
    NSSCertificate **rvCerts;
    if (!cc->certStore) {
	return NULL;
    }
    rvCerts = nssCertificateStore_FindCertificatesByEmail(cc->certStore,
                                                          email,
                                                          rvOpt,
                                                          maximumOpt,
                                                          arenaOpt);
    return rvCerts;
}

NSS_IMPLEMENT NSSCertificate *
NSSCryptoContext_FindCertificateByOCSPHash
(
  NSSCryptoContext *cc,
  NSSItem *hash
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCertificate *
NSSCryptoContext_FindBestUserCertificate
(
  NSSCryptoContext *cc,
  NSSTime *timeOpt,
  NSSUsage *usage,
  NSSPolicies *policiesOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCertificate **
NSSCryptoContext_FindUserCertificates
(
  NSSCryptoContext *cc,
  NSSTime *timeOpt,
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
NSSCryptoContext_FindBestUserCertificateForSSLClientAuth
(
  NSSCryptoContext *cc,
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
NSSCryptoContext_FindUserCertificatesForSSLClientAuth
(
  NSSCryptoContext *cc,
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
NSSCryptoContext_FindBestUserCertificateForEmailSigning
(
  NSSCryptoContext *cc,
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

NSS_IMPLEMENT NSSCertificate *
NSSCryptoContext_FindUserCertificatesForEmailSigning
(
  NSSCryptoContext *cc,
  NSSASCII7 *signerOpt, /* fgmr or a more general name? */
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

NSS_IMPLEMENT NSSTrust *
nssCryptoContext_FindTrustForCertificate
(
  NSSCryptoContext *cc,
  NSSCertificate *cert
)
{
    if (!cc->certStore) {
	return NULL;
    }
    return nssCertificateStore_FindTrustForCertificate(cc->certStore, cert);
}

NSS_IMPLEMENT nssSMIMEProfile *
nssCryptoContext_FindSMIMEProfileForCertificate
(
  NSSCryptoContext *cc,
  NSSCertificate *cert
)
{
    if (!cc->certStore) {
	return NULL;
    }
    return nssCertificateStore_FindSMIMEProfileForCertificate(cc->certStore, 
                                                              cert);
}

static PRStatus
prepare_context_for_operation
(
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
	cc->token = nssTrustDomain_FindTokenForAlgorithm(cc->td, ap);
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
prepare_context_symmetric_key
(
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *ap
)
{
    if (cc->token) {
	/* context already has a token set */
	if (nssToken_DoesAlgorithm(cc->token, ap)) {
	    /* and the token can do the operation */
	    if (!cc->mko) {
		/* get a key instance from it */
		cc->mko = nssSymmetricKey_GetInstance(cc->mk, cc->token);
	    } /* else we already have a key instance */
	} else {
	    /* the token can't do the math, so this context won't work */
	    goto loser;
	}
    } else {
	/* find an instance of the key that will do the operation */
	cc->mko = nssSymmetricKey_FindInstanceForAlgorithm(cc->mk, cc->ap);
	if (cc->mko) {
	    /* okay, now we know what token to use */
	    cc->token = nssToken_AddRef(cc->mko->token);
	} else {
	    /* find any token in the trust domain that can */
	    cc->token = nssTrustDomain_FindTokenForAlgorithm(cc->td, ap);
	    if (!cc->token) {
		/*nss_SetError(NSS_ERROR_NO_TOKEN_FOR_OPERATION);*/
		goto loser;
	    }
	}
    }
    /* the token has been set, so if we didn't find a key instance on
     * the token, copy it there
     */
    if (!cc->mko) {
	cc->mko = nssSymmetricKey_Copy(cc->mk, cc->token);
	if (!cc->mko) {
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
prepare_context_private_key
(
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *ap
)
{
    if (!cc->vk) {
	/* try to get the key from the cert (if present) */
	if (cc->cert) {
	    cc->vk = nssCertificate_FindPrivateKey(cc->cert, cc->callback);
	}
	if (!cc->vk) {
	    goto loser;
	}
    }
    if (cc->token) {
	/* context already has a token set */
	if (nssToken_DoesAlgorithm(cc->token, ap)) {
	    /* and the token can do the operation */
	    if (!cc->vko) {
		/* get a key instance from it */
		cc->vko = nssPrivateKey_GetInstance(cc->vk, cc->token);
	    } /* else we already have a key instance for the token */
	} else {
	    /* the token can't do the math, so this context won't work */
	    goto loser;
	}
    } else {
	/* find an instance of the key that will do the operation */
	cc->vko = nssPrivateKey_FindInstanceForAlgorithm(cc->vk, cc->ap);
	if (cc->vko) {
	    /* okay, now we know what token to use */
	    cc->token = nssToken_AddRef(cc->vko->token);
	} else {
	    /* find any token in the trust domain that can */
	    cc->token = nssTrustDomain_FindTokenForAlgorithm(cc->td, ap);
	    if (!cc->token) {
		/*nss_SetError(NSS_ERROR_NO_TOKEN_FOR_OPERATION);*/
		goto loser;
	    }
	}
    }
    /* the token has been set, so if we didn't find a key instance on
     * the token, copy it there
     */
    if (!cc->vko) {
	cc->vko = nssPrivateKey_Copy(cc->vk, cc->token);
	if (!cc->vko) {
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
prepare_context_public_key
(
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *ap
)
{
    if (!cc->bk) {
	/* try to get the key from the cert (if present) */
	if (cc->cert) {
	    cc->bk = nssCertificate_GetPublicKey(cc->cert);
	}
	if (!cc->bk) {
	    goto loser;
	}
    }
    if (cc->token) {
	/* context already has a token set */
	if (nssToken_DoesAlgorithm(cc->token, ap)) {
	    /* and the token can do the operation */
	    if (!cc->bko) {
		/* get a key instance from it */
		cc->bko = nssPublicKey_GetInstance(cc->bk, cc->token);
	    } /* else we already have a key instance for the token */
	} else {
	    /* the token can't do the math, so this context won't work */
	    goto loser;
	}
    } else {
	/* find an instance of the key that will do the operation */
	cc->bko = nssPublicKey_FindInstanceForAlgorithm(cc->bk, cc->ap);
	if (cc->bko) {
	    /* okay, now we know what token to use */
	    cc->token = nssToken_AddRef(cc->bko->token);
	} else {
	    /* find any token in the trust domain that can */
	    cc->token = nssTrustDomain_FindTokenForAlgorithm(cc->td, ap);
	    if (!cc->token) {
		/*nss_SetError(NSS_ERROR_NO_TOKEN_FOR_OPERATION);*/
		goto loser;
	    }
	}
    }
    /* the token has been set, so if we didn't find a key instance on
     * the token, copy it there
     */
    if (!cc->bko) {
	cc->bko = nssPublicKey_Copy(cc->bk, cc->token);
	if (!cc->bko) {
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

NSS_IMPLEMENT PRStatus
nssCryptoContext_GenerateKeyPair
(
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *ap,
  NSSPrivateKey **pvkOpt,
  NSSPublicKey **pbkOpt,
  PRBool privateKeyIsSensitive,
  NSSToken *destination,
  NSSCallback *uhhOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return PR_FAILURE;
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_GenerateKeyPair
(
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *ap,
  NSSPrivateKey **pvkOpt,
  NSSPublicKey **pbkOpt,
  PRBool privateKeyIsSensitive,
  NSSToken *destination,
  NSSCallback *uhhOpt
)
{
    return nssCryptoContext_GenerateKeyPair(cc, ap, pvkOpt, pbkOpt,
                                            privateKeyIsSensitive,
                                            destination, uhhOpt);
}

NSS_IMPLEMENT NSSSymmetricKey *
nssCryptoContext_GenerateSymmetricKey
(
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *ap,
  PRUint32 keysize,
  NSSToken *destination,
  NSSCallback *uhhOpt
)
{
    NSSToken *source = NULL;
    nssCryptokiObject *key = NULL;
    nssPKIObject *pkio = NULL;
    NSSSymmetricKey *symKey = NULL;
    nssSession *session = NULL;

    source = nssTrustDomain_FindSourceToken(cc->td, ap, destination);
    if (!source) {
	return (NSSSymmetricKey *)NULL;
    }

    session = nssToken_CreateSession(source, PR_FALSE);
    if (!session) {
	goto loser;
    }

    key = nssToken_GenerateSymmetricKey(source, session, ap, keysize,
                                        NULL, PR_FALSE, 0, 0);
    if (!key) {
	goto loser;
    }


    pkio = nssPKIObject_Create(NULL, key, cc->td, cc);
    if (!pkio) {
	goto loser;
    }

    symKey = nssSymmetricKey_Create(pkio);
    if (!symKey) {
	goto loser;
    }

    /* XXX need to think about how this changes state */
    cc->mk = nssSymmetricKey_AddRef(symKey);
    cc->mko = nssCryptokiObject_Clone(key);
    cc->token = nssToken_AddRef(destination);
    cc->session = session;

    nssToken_Destroy(source);
    return symKey;
loser:
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
NSSCryptoContext_GenerateSymmetricKey
(
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *ap,
  PRUint32 keysize,
  NSSToken *destination,
  NSSCallback *uhhOpt
)
{
    return nssCryptoContext_GenerateSymmetricKey(cc, ap, keysize,
                                                 destination, uhhOpt);
}

NSS_IMPLEMENT NSSSymmetricKey *
NSSCryptoContext_GenerateSymmetricKeyFromPassword
(
  NSSCryptoContext *cc,
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
NSSCryptoContext_FindSymmetricKeyByAlgorithmAndKeyID
(
  NSSCryptoContext *cc,
  NSSOID *algorithm,
  NSSItem *keyID,
  NSSCallback *uhhOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSItem *
nssCryptoContext_Encrypt
(
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
    if (prepare_context_symmetric_key(cc, ap) == PR_FAILURE) {
	return (NSSItem *)NULL;
    }
    return nssToken_Encrypt(cc->token, cc->session, ap, cc->mko,
                            data, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
NSSCryptoContext_Encrypt
(
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *data,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    if (!cc->mk) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSItem *)NULL;
    }
    return nssCryptoContext_Encrypt(cc, apOpt, data, 
                                    uhhOpt, rvOpt, arenaOpt);
}

NSS_IMPLEMENT PRStatus
nssCryptoContext_BeginEncrypt
(
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
    if (prepare_context_symmetric_key(cc, ap) == PR_FAILURE) {
	return PR_FAILURE;
    }
    return nssToken_BeginEncrypt(cc->token, cc->session, ap, cc->mko);
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_BeginEncrypt
(
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSCallback *uhhOpt
)
{
    if (!cc->mk) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return PR_FAILURE;
    }
    return nssCryptoContext_BeginEncrypt(cc, apOpt, uhhOpt);
}

NSS_IMPLEMENT NSSItem *
nssCryptoContext_ContinueEncrypt
(
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
NSSCryptoContext_ContinueEncrypt
(
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
nssCryptoContext_FinishEncrypt
(
  NSSCryptoContext *cc,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssToken_FinishEncrypt(cc->token, cc->session, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
NSSCryptoContext_FinishEncrypt
(
  NSSCryptoContext *cc,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    PR_ASSERT(cc->session);
    return nssCryptoContext_FinishEncrypt(cc, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
nssCryptoContext_Decrypt
(
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
    if (prepare_context_symmetric_key(cc, ap) == PR_FAILURE) {
	return (NSSItem *)NULL;
    }
    return nssToken_Decrypt(cc->token, cc->session, ap, cc->mko,
                            encryptedData, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
NSSCryptoContext_Decrypt
(
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *encryptedData,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    if (!cc->mk) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSItem *)NULL;
    }
    return nssCryptoContext_Decrypt(cc, apOpt, encryptedData, 
                                    uhhOpt, rvOpt, arenaOpt);
}

NSS_IMPLEMENT PRStatus
nssCryptoContext_BeginDecrypt
(
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
    if (prepare_context_symmetric_key(cc, ap) == PR_FAILURE) {
	return PR_FAILURE;
    }
    return nssToken_BeginDecrypt(cc->token, cc->session, ap, cc->mko);
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_BeginDecrypt
(
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSCallback *uhhOpt
)
{
    if (!cc->mk) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return PR_FAILURE;
    }
    return nssCryptoContext_BeginDecrypt(cc, apOpt, uhhOpt);
}

NSS_IMPLEMENT NSSItem *
nssCryptoContext_ContinueDecrypt
(
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
NSSCryptoContext_ContinueDecrypt
(
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
nssCryptoContext_FinishDecrypt
(
  NSSCryptoContext *cc,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssToken_FinishDecrypt(cc->token, cc->session, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
NSSCryptoContext_FinishDecrypt
(
  NSSCryptoContext *cc,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    PR_ASSERT(cc->session);
    return nssCryptoContext_FinishDecrypt(cc, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
nssCryptoContext_Sign
(
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
    return nssToken_Sign(cc->token, cc->session, ap, cc->vko,
                         data, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
NSSCryptoContext_Sign
(
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *data,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    if (!cc->vk && !cc->cert) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSItem *)NULL;
    }
    return nssCryptoContext_Sign(cc, apOpt, data, uhhOpt, rvOpt, arenaOpt);
}

NSS_IMPLEMENT PRStatus
nssCryptoContext_BeginSign
(
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
    return nssToken_BeginSign(cc->token, cc->session, ap, cc->vko);
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_BeginSign
(
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSCallback *uhhOpt
)
{
    if (!cc->vk && !cc->cert) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return PR_FAILURE;
    }
    return nssCryptoContext_BeginSign(cc, apOpt, uhhOpt);
}

NSS_IMPLEMENT PRStatus
nssCryptoContext_ContinueSign
(
  NSSCryptoContext *cc,
  NSSItem *data
)
{
    return nssToken_ContinueSign(cc->token, cc->session, data);
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_ContinueSign
(
  NSSCryptoContext *cc,
  NSSItem *data
)
{
    PR_ASSERT(cc->session);
    return nssCryptoContext_ContinueSign(cc, data);
}

NSS_IMPLEMENT NSSItem *
nssCryptoContext_FinishSign
(
  NSSCryptoContext *cc,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssToken_FinishSign(cc->token, cc->session, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
NSSCryptoContext_FinishSign
(
  NSSCryptoContext *cc,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    PR_ASSERT(cc->session);
    return nssCryptoContext_FinishSign(cc, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
nssCryptoContext_SignRecover
(
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
    return nssToken_SignRecover(cc->token, cc->session, ap, cc->vko,
                                data, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
NSSCryptoContext_SignRecover
(
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *data,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    if (!cc->vk && !cc->cert) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSItem *)NULL;
    }
    return nssCryptoContext_SignRecover(cc, apOpt, data, 
                                        uhhOpt, rvOpt, arenaOpt);
}

#if 0
NSS_IMPLEMENT PRStatus
nssCryptoContext_BeginSignRecover
(
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSCallback *uhhOpt
)
{
    if (prepare_context_object_for_operation(cc, apOpt) == PR_FAILURE) {
	return PR_FAILURE;
    }
    return nssToken_BeginSignRecover(cc->token, cc->session, 
                                     cc->ap, cc->object);
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_BeginSignRecover
(
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSCallback *uhhOpt
)
{
    if (cc->which != context_has_private_key ||
        cc->which != context_has_keypair) 
    {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return PR_FAILURE;
    }
    return nssCryptoContext_BeginSignRecover(cc, apOpt, uhhOpt);
}

NSS_IMPLEMENT NSSItem *
nssCryptoContext_ContinueSignRecover
(
  NSSCryptoContext *cc,
  NSSItem *data,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssToken_ContinueSignRecover(cc->token, cc->session, 
                                        data, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
NSSCryptoContext_ContinueSignRecover
(
  NSSCryptoContext *cc,
  NSSItem *data,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    PR_ASSERT(cc->session);
    return nssCryptoContext_ContinueSignRecover(cc, data, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
nssCryptoContext_FinishSignRecover
(
  NSSCryptoContext *cc,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssToken_FinishSignRecover(cc->token, cc->session, 
                                      rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
NSSCryptoContext_FinishSignRecover
(
  NSSCryptoContext *cc,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    PR_ASSERT(cc->session);
    return nssCryptoContext_FinishSignRecover(cc, rvOpt, arenaOpt);
}
#endif

NSS_IMPLEMENT NSSSymmetricKey *
nssCryptoContext_UnwrapSymmetricKey
(
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
NSSCryptoContext_UnwrapSymmetricKey
(
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

NSS_IMPLEMENT NSSSymmetricKey *
NSSCryptoContext_DeriveSymmetricKey
(
  NSSCryptoContext *cc,
  NSSPublicKey *bk,
  const NSSAlgorithmAndParameters *apOpt,
  NSSOID *target,
  PRUint32 keySizeOpt, /* zero for best allowed */
  NSSOperations operations,
  NSSCallback *uhhOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT PRStatus
nssCryptoContext_Verify
(
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *data,
  NSSItem *signature,
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
    return nssToken_Verify(cc->token, cc->session, ap, cc->bko,
                           data, signature);
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_Verify
(
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *data,
  NSSItem *signature,
  NSSCallback *uhhOpt
)
{
    if (!cc->bk && !cc->cert) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return PR_FAILURE;
    }
    return nssCryptoContext_Verify(cc, apOpt, data, signature, uhhOpt);
}

NSS_IMPLEMENT PRStatus
nssCryptoContext_BeginVerify
(
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
    return nssToken_BeginVerify(cc->token, cc->session, ap, cc->bko);
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_BeginVerify
(
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSCallback *uhhOpt
)
{
    if (!cc->bk && !cc->cert) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return PR_FAILURE;
    }
    return nssCryptoContext_BeginVerify(cc, apOpt, uhhOpt);
}

NSS_IMPLEMENT PRStatus
nssCryptoContext_ContinueVerify
(
  NSSCryptoContext *cc,
  NSSItem *data
)
{
    return nssToken_ContinueVerify(cc->token, cc->session, data);
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_ContinueVerify
(
  NSSCryptoContext *cc,
  NSSItem *data
)
{
    PR_ASSERT(cc->session);
    return nssCryptoContext_ContinueVerify(cc, data);
}

NSS_IMPLEMENT PRStatus
nssCryptoContext_FinishVerify
(
  NSSCryptoContext *cc,
  NSSItem *signature
)
{
    return nssToken_FinishVerify(cc->token, cc->session, signature);
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_FinishVerify
(
  NSSCryptoContext *cc,
  NSSItem *signature
)
{
    PR_ASSERT(cc->session);
    return nssCryptoContext_FinishVerify(cc, signature);
}

NSS_IMPLEMENT NSSItem *
nssCryptoContext_VerifyRecover
(
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *signature,
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
    return nssToken_VerifyRecover(cc->token, cc->session, ap, cc->bko,
                                  signature, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
NSSCryptoContext_VerifyRecover
(
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *signature,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    if (!cc->bk && !cc->cert) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSItem *)NULL;
    }
    return nssCryptoContext_VerifyRecover(cc, apOpt, signature, 
                                          uhhOpt, rvOpt, arenaOpt);
}

#if 0
NSS_IMPLEMENT PRStatus
NSSCryptoContext_BeginVerifyRecover
(
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSCallback *uhhOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return PR_FAILURE;
}

NSS_IMPLEMENT NSSItem *
NSSCryptoContext_ContinueVerifyRecover
(
  NSSCryptoContext *cc,
  NSSItem *data,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSItem *
NSSCryptoContext_FinishVerifyRecover
(
  NSSCryptoContext *cc,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}
#endif

NSS_IMPLEMENT NSSItem *
nssCryptoContext_WrapSymmetricKey
(
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
NSSCryptoContext_WrapSymmetricKey
(
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

NSS_IMPLEMENT NSSItem *
nssCryptoContext_Digest
(
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
NSSCryptoContext_Digest
(
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
nssCryptoContext_BeginDigest
(
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
NSSCryptoContext_BeginDigest
(
  NSSCryptoContext *cc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSCallback *uhhOpt
)
{
    return nssCryptoContext_BeginDigest(cc, apOpt, uhhOpt);
}

NSS_IMPLEMENT PRStatus
nssCryptoContext_ContinueDigest
(
  NSSCryptoContext *cc,
  NSSItem *item
)
{
    return nssToken_ContinueDigest(cc->token, cc->session, item);
}

NSS_IMPLEMENT PRStatus
NSSCryptoContext_ContinueDigest
(
  NSSCryptoContext *cc,
  NSSItem *item
)
{
    PR_ASSERT(cc->session);
    return nssCryptoContext_ContinueDigest(cc, item);
}

NSS_IMPLEMENT NSSItem *
nssCryptoContext_FinishDigest
(
  NSSCryptoContext *cc,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssToken_FinishDigest(cc->token, cc->session, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
NSSCryptoContext_FinishDigest
(
  NSSCryptoContext *cc,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    PR_ASSERT(cc->session);
    return nssCryptoContext_FinishDigest(cc, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSCryptoContext *
NSSCryptoContext_Clone
(
  NSSCryptoContext *cc
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

