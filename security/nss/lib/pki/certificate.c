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

#ifndef BASE_H
#include "base.h"
#endif /* BASE_H */

#ifndef DEV_H
#include "dev.h"
#endif /* DEV_H */

#ifndef PKIM_H
#include "pkim.h"
#endif /* PKIM_H */

#include "nsst.h"

typedef struct 
{
  void *data;
  NSSCertificateMethods *methods;
  PRBool haveValidity;
  NSSTime notBefore;
  NSSTime notAfter;
  PRBool haveUsages;
  NSSUsages usages;
  NSSPolicies *policies;
}
nssCertDecoding;

struct NSSCertificateStr
{
  nssPKIObject object;
  NSSCertificateType kind;
  NSSItem id;
  NSSBER encoding;
  NSSDER issuer;
  NSSDER subject;
  NSSDER serial;
  NSSASCII7 *email;
  nssCertDecoding decoding;
};


NSS_EXTERN NSSCertificateMethods *
nss_GetMethodsForType
(
  NSSCertificateType certType
);

/* Creates a certificate from a base object */
NSS_IMPLEMENT NSSCertificate *
nssCertificate_Create
(
  nssPKIObject *object
)
{
    PRStatus status;
    NSSCertificate *rvCert;
    /* mark? */
    NSSArena *arena = object->arena;
    PR_ASSERT(object->instances != NULL && object->numInstances > 0);
    rvCert = nss_ZNEW(arena, NSSCertificate);
    if (!rvCert) {
	return (NSSCertificate *)NULL;
    }
    rvCert->object = *object;
    /* XXX should choose instance based on some criteria */
    status = nssCryptokiCertificate_GetAttributes(object->instances[0],
                                                  arena,
                                                  &rvCert->kind,
                                                  &rvCert->id,
                                                  &rvCert->encoding,
                                                  &rvCert->issuer,
                                                  &rvCert->serial,
                                                  &rvCert->subject,
                                                  &rvCert->email);
    if (status != PR_SUCCESS) {
	return (NSSCertificate *)NULL;
    }
    /* all certs need an encoding value */
    if (rvCert->encoding.data == NULL) {
	return (NSSCertificate *)NULL;
    }
    rvCert->decoding.methods = nss_GetMethodsForType(rvCert->kind);
    if (!rvCert->decoding.methods) {
	return (NSSCertificate *)NULL;
    }
    return rvCert;
}

NSS_IMPLEMENT NSSCertificate *
nssCertificate_Decode
(
  NSSBER *ber
)
{
    NSSArena *arena;
    NSSCertificate *rvCert;
    NSSCertificateMethods *decoder;
    void *decoding;
    NSSItem *it;

    /* create the PKIObject */
    arena = nssArena_Create();
    if (!arena) {
	return (NSSCertificate *)NULL;
    }
    rvCert = nss_ZNEW(arena, NSSCertificate);
    if (!rvCert) {
	goto loser;
    }
    rvCert->object.arena = arena;
    rvCert->object.refCount = 1;
    rvCert->object.lock = PZ_NewLock(nssILockOther);
    if (!rvCert->object.lock) {
	goto loser;
    }
    /* try to decode it */
    decoder = nss_GetMethodsForType(NSSCertificateType_PKIX);
    decoding = decoder->decode(arena, ber);
    if (decoding) {
	/* it's a PKIX cert */
	rvCert->decoding.methods = decoder;
	rvCert->decoding.data = decoding;
	rvCert->kind = NSSCertificateType_PKIX;
    } else {
	goto loser;
    }
    /* copy the BER encoding */
    it = nssItem_Duplicate(ber, arena, &rvCert->encoding);
    if (!it) {
	goto loser;
    }
    /* obtain the issuer from the decoding */
    it = decoder->getIssuer(decoding);
    if (!it) {
	goto loser;
    }
    rvCert->issuer = *it;
    /* obtain the serial number from the decoding */
    it = decoder->getSerialNumber(decoding);
    if (!it) {
	goto loser;
    }
    rvCert->serial = *it;
    /* obtain the subject from the decoding */
    it = decoder->getSubject(decoding);
    if (!it) {
	goto loser;
    }
    rvCert->subject = *it;
    /* obtain the email address from the decoding */
    rvCert->email = decoder->getEmailAddress(decoding);
    return rvCert;
loser:
    nssArena_Destroy(arena);
    return (NSSCertificate *)NULL;
}

/* XXX */
NSS_IMPLEMENT NSSCertificate *
nssCertificate_CreateIndexCert
(
  NSSDER *issuer,
  NSSDER *serial
)
{
    NSSCertificate *c = nss_ZNEW(NULL, NSSCertificate);
    if (c) {
	c->issuer = *issuer;
	c->serial = *serial;
    }
    return c;
}

NSS_IMPLEMENT NSSCertificate *
nssCertificate_AddRef
(
  NSSCertificate *c
)
{
    if (c) {
	nssPKIObject_AddRef(&c->object);
    }
    return c;
}

NSS_IMPLEMENT PRStatus
nssCertificate_Destroy
(
  NSSCertificate *c
)
{
    PRBool destroyed;
    if (c) {
	void *dc = c->decoding.data;
	NSSCertificateMethods *methods = c->decoding.methods;
	destroyed = nssPKIObject_Destroy(&c->object);
	if (destroyed) {
	    if (dc) {
		methods->destroy(dc);
	    }
	}
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT PRStatus
NSSCertificate_Destroy
(
  NSSCertificate *c
)
{
    return nssCertificate_Destroy(c);
}

NSS_IMPLEMENT PRUint32
nssCertificate_Hash
(
  NSSCertificate *c
)
{
    int i;
    PRUint32 h = 0;
    for (i=0; i<c->issuer.size; i++)
	h = (h >> 28) ^ (h << 4) ^ ((unsigned char *)c->issuer.data)[i];
    for (i=0; i<c->serial.size; i++)
	h = (h >> 28) ^ (h << 4) ^ ((unsigned char *)c->serial.data)[i];
    return h;
}

NSS_IMPLEMENT NSSDER *
nssCertificate_GetEncoding
(
  NSSCertificate *c
)
{
    if (c->encoding.size > 0 && c->encoding.data) {
	return &c->encoding;
    } else {
	return (NSSDER *)NULL;
    }
}

NSS_IMPLEMENT NSSDER *
nssCertificate_GetIssuer
(
  NSSCertificate *c
)
{
    if (c->issuer.size > 0 && c->issuer.data) {
	return &c->issuer;
    } else {
	return (NSSDER *)NULL;
    }
}

NSS_IMPLEMENT NSSDER *
nssCertificate_GetSerialNumber
(
  NSSCertificate *c
)
{
    if (c->serial.size > 0 && c->serial.data) {
	return &c->serial;
    } else {
	return (NSSDER *)NULL;
    }
}

NSS_IMPLEMENT NSSDER *
nssCertificate_GetSubject
(
  NSSCertificate *c
)
{
    if (c->subject.size > 0 && c->subject.data) {
	return &c->subject;
    } else {
	return (NSSDER *)NULL;
    }
}

NSS_IMPLEMENT NSSUTF8 *
nssCertificate_GetNickname
(
  NSSCertificate *c,
  NSSToken *tokenOpt
)
{
    return nssPKIObject_GetNicknameForToken(&c->object, tokenOpt);
}

NSS_IMPLEMENT NSSToken *
nssCertificate_GetWriteToken
(
  NSSCertificate *c,
  nssSession **rvSessionOpt
)
{
    return nssPKIObject_GetWriteToken(&c->object, rvSessionOpt);
}

NSS_IMPLEMENT NSSUTF8 *
NSSCertificate_GetNickname
(
  NSSCertificate *c,
  NSSToken *tokenOpt
)
{
    return nssCertificate_GetNickname(c, tokenOpt);
}

NSS_IMPLEMENT NSSASCII7 *
nssCertificate_GetEmailAddress
(
  NSSCertificate *c
)
{
    return c->email;
}

static nssCertDecoding *
nssCertificate_GetDecoding
(
  NSSCertificate *c
)
{
    if (!c->decoding.data) {
	c->decoding.data = c->decoding.methods->decode(NULL, &c->encoding);
    }
    return &c->decoding;
}

NSS_IMPLEMENT void *
NSSCertificate_GetDecoding
(
  NSSCertificate *c
)
{
    nssCertDecoding *dc;

    dc = nssCertificate_GetDecoding(c);
    if (dc) {
	return dc->data;
    }
    return (void *)NULL;
}

NSS_EXTERN NSSCertificateType
NSSCertificate_GetType
(
  NSSCertificate *c
)
{
    return c->kind;
}

NSS_IMPLEMENT NSSUsages *
nssCertificate_GetUsages
(
  NSSCertificate *c,
  PRStatus *statusOpt
)
{
    PRStatus status;
    nssCertDecoding *dc = nssCertificate_GetDecoding(c);
    if (statusOpt) *statusOpt = PR_SUCCESS;
    if (dc) {
	if (!dc->haveUsages) {
	    status = dc->methods->getUsages(dc->data, &dc->usages);
	    if (statusOpt) *statusOpt = status;
	}
    } else {
	if (statusOpt) *statusOpt = PR_FAILURE;
	return 0; /* XXX */
    }
    return &dc->usages;
}

static PRStatus
get_validity_period(nssCertDecoding *dc)
{
    if (!dc->haveValidity) {
	return dc->methods->getValidityPeriod(dc->data, 
	                                      &dc->notBefore, 
	                                      &dc->notAfter);
    }
    return PR_SUCCESS;
}

/* XXX */
NSS_IMPLEMENT PRBool
nssCertificate_IsValidAtTime
(
  NSSCertificate *c,
  NSSTime time,
  PRStatus *statusOpt
)
{
    PRStatus status;
    nssCertDecoding *dc = nssCertificate_GetDecoding(c);
    if (statusOpt) *statusOpt = PR_FAILURE;
    if (dc) {
	status = get_validity_period(dc);
	if (status == PR_FAILURE) {
	    return PR_FALSE;
	}
	if (statusOpt) *statusOpt = PR_SUCCESS;
	if (nssTime_WithinRange(time, dc->notBefore, dc->notAfter)) {
	    return PR_TRUE;
	}
    }
    return PR_FALSE;
}

/* XXX */
/* note this isn't the same as CERT_IsNewer, but doesn't intend to be */
NSS_IMPLEMENT PRBool
nssCertificate_IsNewer
(
  NSSCertificate *c1,
  NSSCertificate *c2,
  PRStatus *statusOpt
)
{
    nssCertDecoding *dc1 = nssCertificate_GetDecoding(c1);
    nssCertDecoding *dc2 = nssCertificate_GetDecoding(c2);
    if (statusOpt) *statusOpt = PR_SUCCESS;
    /* get the times from the decoding */
    if (get_validity_period(dc1) == PR_FAILURE) {
	if (statusOpt) *statusOpt = PR_FAILURE;
	return PR_FALSE;
    }
    if (get_validity_period(dc2) == PR_FAILURE) {
	if (statusOpt) *statusOpt = PR_FAILURE;
	return PR_FALSE;
    }
    return nssTime_IsAfter(dc1->notBefore, dc2->notBefore);
}

NSS_IMPLEMENT PRBool
nssCertificate_IssuerAndSerialEqual
(
  NSSCertificate *c1,
  NSSCertificate *c2
)
{
    return (nssItem_Equal(&c1->issuer, &c2->issuer, NULL) &&
            nssItem_Equal(&c1->serial, &c2->serial, NULL));
}

NSS_IMPLEMENT void
nssCertificate_SetCryptoContext
(
  NSSCertificate *c,
  NSSCryptoContext *cc
)
{
    c->object.cryptoContext = cc;
}

NSS_IMPLEMENT NSSCryptoContext *
nssCertificate_GetCryptoContext
(
  NSSCertificate *c
)
{
    return c->object.cryptoContext;
}

NSS_IMPLEMENT NSSTrustDomain *
nssCertificate_GetTrustDomain
(
  NSSCertificate *c
)
{
    return c->object.trustDomain;
}

NSS_IMPLEMENT NSSTrustDomain *
NSSCertificate_GetTrustDomain
(
  NSSCertificate *c
)
{
    return nssCertificate_GetTrustDomain(c);
}

NSS_IMPLEMENT NSSToken **
nssCertificate_GetTokens
(
  NSSCertificate *c,
  PRStatus *statusOpt
)
{
    return nssPKIObject_GetTokens(&c->object, statusOpt);
}

NSS_IMPLEMENT NSSToken **
NSSCertificate_GetTokens
(
  NSSCertificate *c,
  PRStatus *statusOpt
)
{
    return nssCertificate_GetTokens(c, statusOpt);
}

NSS_IMPLEMENT NSSSlot *
NSSCertificate_GetSlot
(
  NSSCertificate *c,
  PRStatus *statusOpt
)
{
    return (NSSSlot *)NULL;
}

NSS_IMPLEMENT NSSModule *
NSSCertificate_GetModule
(
  NSSCertificate *c,
  PRStatus *statusOpt
)
{
    return (NSSModule *)NULL;
}

NSS_IMPLEMENT nssCryptokiObject *
nssCertificate_FindInstanceForAlgorithm
(
  NSSCertificate *c,
  NSSAlgorithmAndParameters *ap
)
{
    return nssPKIObject_FindInstanceForAlgorithm(&c->object, ap);
}

NSS_IMPLEMENT PRStatus
nssCertificate_DeleteStoredObject
(
  NSSCertificate *c,
  NSSCallback *uhh
)
{
    return nssPKIObject_DeleteStoredObject(&c->object, uhh, PR_TRUE);
}

NSS_IMPLEMENT PRStatus
NSSCertificate_DeleteStoredObject
(
  NSSCertificate *c,
  NSSCallback *uhh
)
{
    return nssPKIObject_DeleteStoredObject(&c->object, uhh, PR_TRUE);
}

NSS_IMPLEMENT PRStatus
nssCertificate_CopyToToken
(
  NSSCertificate *c,
  NSSToken *token,
  NSSUTF8 *nicknameOpt
)
{
    PRStatus status;
    nssCryptokiObject *instance;
    nssSession *rwSession;

    rwSession = nssToken_CreateSession(token, PR_TRUE);
    if (!rwSession) {
	return PR_FAILURE;
    }
    instance = nssToken_ImportCertificate(token, rwSession,
                                          c->kind, NULL, nicknameOpt,
                                          &c->encoding, &c->issuer, 
                                          &c->subject, &c->serial,
                                          c->email, PR_TRUE);
    if (!instance) {
	goto loser;
    }
    status = nssPKIObject_AddInstance(&c->object, instance);
    if (status == PR_FAILURE) {
	goto loser;
    }
    nssSession_Destroy(rwSession);
    return PR_SUCCESS;
loser:
    nssSession_Destroy(rwSession);
    return PR_FAILURE;
}

static NSSUsage
get_trusted_usage
(
  NSSCertificate *c,
  PRBool asCA,
  PRStatus *status
)
{
    nssTrust *trust;
    nssTrustLevel checkLevel;
    NSSUsage usage = 0;

    *status = PR_SUCCESS;
    checkLevel = asCA ? nssTrustLevel_TrustedDelegator :
                        nssTrustLevel_Trusted;
    /* XXX needs to be cached with cert */
    trust = nssTrustDomain_FindTrustForCertificate(c->object.trustDomain, c);
    if (!trust) {
	if (NSS_GetError() == NSS_ERROR_NO_ERROR) {
	    *status = PR_SUCCESS;
	} else {
	    *status = PR_FAILURE;
	}
	return 0;
    }
    if (trust->clientAuth == checkLevel) {
	usage |= NSSUsage_SSLClient;
    }
    if (trust->serverAuth == checkLevel) {
	usage |= NSSUsage_SSLServer;
    }
    if (trust->emailProtection == checkLevel) {
	usage |= NSSUsage_EmailSigner | NSSUsage_EmailRecipient;
    }
    if (trust->codeSigning == checkLevel) {
	usage |= NSSUsage_CodeSigner;
    }
    nssTrust_Destroy(trust);
    /* XXX should check user cert */
    return usage;
}

static PRStatus
validate_and_discover_trust
(
  NSSCertificate *c,
  NSSTime time,
  NSSUsage usage,
  NSSPolicies *policiesOpt,
  PRBool asCA,
  PRBool *trusted
)
{
    PRStatus status;
    NSSUsage trustedUsage;
    NSSUsages *certUsages;
    PRBool valid;

    *trusted = PR_FALSE;

    /* First verify the time is within the cert's validity period */
    if (!nssCertificate_IsValidAtTime(c, time, &status)) {
	if (status == PR_SUCCESS) {
	    /* The function was successful, so we own the error */
	    nss_SetError(NSS_ERROR_CERTIFICATE_NOT_VALID_AT_TIME);
	} /* else the function failed and owns the error */
	return PR_FAILURE;
    }

    /* See if the cert is trusted, overrides cert's usage */
    trustedUsage = get_trusted_usage(c, asCA, &status);
    if (trustedUsage && (trustedUsage & usage) == usage) {
	*trusted = PR_TRUE;
	return PR_SUCCESS;
    }

    /* Verify the cert is capable of the desired set of usages */
    certUsages = nssCertificate_GetUsages(c, &status);
    if (status == PR_FAILURE) {
	return PR_FAILURE;
    }
    if (asCA) {
	valid = ((certUsages->ca & usage) == usage);
    } else {
	valid = ((certUsages->peer & usage) == usage);
    }
    if (!valid) {
	nss_SetError(NSS_ERROR_CERTIFICATE_USAGE_INSUFFICIENT);
	return PR_FAILURE;
    }

    return status;
}

static PRStatus
validate_chain_link
(
  NSSCertificate *subjectCert,
  NSSCertificate *issuerCert,
  void **vData
)
{
    PRStatus status;
    nssCertDecoding *dcs;

    dcs = nssCertificate_GetDecoding(subjectCert);
    if (!dcs) {
	return PR_FAILURE;
    }

    if (!*vData) {
	*vData = dcs->methods->startChainValidation();
#if 0
	if (!*vData) {
	    return PR_FAILURE;
	}
#endif
    }

    status = dcs->methods->validateChainLink(dcs->data, issuerCert, *vData);

#if 0
    if (*finished) {
	dcs->methods->freeChainValidationData(*vData);
	*vData = NULL;
    }
#endif
    return status;
}

#if 0
static PRBool
cert_in_chain_revoked
(
  NSSCertificate **chain,
  PRStatus *status
)
{
    NSSCertificate **cp;
    nssCRL *crl;
    for (cp = chain; *cp; cp++) {
	crl = nssTrustDomain_FindCRLBySubject(td, subject);
	if (crl) {
	    status = nssCRL_FindCertificate(*cp);
	}
    }
    /* If OCSP is enabled, check revocation status of the cert */
    if (NSS_IsOCSPEnabled()) {
	nssOCSPResponder *responder = get_ocsp_responder(chain[0]);
	if (responder) {
	    status = nssOCSPResponder_CheckStatus(responder, chain[0]);
	}
    }
}
#endif

NSS_IMPLEMENT PRStatus
nssCertificate_Validate
(
  NSSCertificate *c,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt
)
{
    PRStatus status;
    PRBool asCA;
    PRBool trusted = PR_FALSE;
    PRBool atRoot = PR_FALSE;
    NSSCertificate **cp, **chain;
    NSSCertificate *subjectCert = NULL;
    NSSCertificate *issuerCert = NULL;
    NSSUsage usage;
    void *vData = NULL;

    /* Build the chain (this cert will be first) */
    chain = nssCertificate_BuildChain(c, time, usages, policiesOpt,
                                      NULL, 0, NULL, &status);
    if (status == PR_FAILURE) {
	return PR_FAILURE;
    }
    /* XXX restrict to ca || peer for now */
    if (usages->ca) {
	usage = usages->ca;
	asCA = PR_TRUE;
    } else {
	usage = usages->peer;
	asCA = PR_FALSE;
    }
    /* Validate the chain */
    subjectCert = chain[0];
    for (cp = chain + 1; !atRoot; cp++) {
	if (*cp) {
	    issuerCert = *cp;
	} else {
	    atRoot = PR_TRUE;
	}
	status = validate_and_discover_trust(subjectCert,
	                                     time, usage, policiesOpt,
	                                     asCA, &trusted);
	if (status == PR_FAILURE) {
	    goto done;
	}
	if (trusted) {
	    if (subjectCert == chain[0]) {
		/* The cert we are validating is explicitly trusted */
		goto done;
	    } else {
		/* Some cert in the chain is explicitly trusted, still
		 * need to check OCSP and/or CRL's
		 */
		goto check_revocation;
	    }
	}
	if (atRoot) {
	    break;
	}
	status = validate_chain_link(subjectCert, issuerCert, &vData);
	if (status == PR_FAILURE) {
	    goto done;
	}
	asCA = PR_TRUE;
	subjectCert = issuerCert;
    }

check_revocation:
    if (!trusted) {
	/* the last cert checked in the chain must be trusted */
	nss_SetError(NSS_ERROR_CERTIFICATE_HAS_NO_TRUSTED_ISSUER);
	status = PR_FAILURE;
    }
#if 0
    if (cert_in_chain_revoked(chain, &status)) {
	if (status == PR_SUCCESS) {
	    /* The status check succeeded, set the error */
	    nss_SetError(NSS_ERROR_CERTIFICATE_REVOKED);
	}
    }
#endif

done:
    nssCertificateArray_Destroy(chain);
    return status;
}

NSS_IMPLEMENT PRStatus
NSSCertificate_Validate
(
  NSSCertificate *c,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt
)
{
    return nssCertificate_Validate(c, time, usages, policiesOpt);
}

#if 0
struct NSSValidationErrorStr
{
  NSSCertificate *c;
  NSSUsage usage;
  NSSError error;
  PRUint32 level;
};
#endif

NSS_IMPLEMENT void ** /* void *[] */
NSSCertificate_ValidateCompletely
(
  NSSCertificate *c,
  NSSTime time, /* NULL for "now" */
  NSSUsages *usages,
  NSSPolicies *policiesOpt, /* NULL for none */
  void **rvOpt, /* NULL for allocate */
  PRUint32 rvLimit, /* zero for no limit */
  NSSArena *arenaOpt /* NULL for heap */
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT PRStatus
NSSCertificate_ValidateAndDiscoverUsagesAndPolicies
(
  NSSCertificate *c,
  NSSTime **notBeforeOutOpt,
  NSSTime **notAfterOutOpt,
  void *allowedUsages,
  void *disallowedUsages,
  void *allowedPolicies,
  void *disallowedPolicies,
  /* more args.. work on this fgmr */
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return PR_FAILURE;
}

NSS_IMPLEMENT NSSUsages *
nssCertificate_GetTrustedUsages
(
  NSSCertificate *c,
  NSSUsages *usagesOpt
)
{
    PRStatus status;
    PRBool freeIt = PR_FALSE;
    if (!usagesOpt) {
	usagesOpt = nss_ZNEW(NULL, NSSUsages);
	if (!usagesOpt) {
	    return (NSSUsages *)NULL;
	}
	freeIt = PR_TRUE;
    }
    usagesOpt->ca = get_trusted_usage(c, PR_TRUE, &status);
    if (status == PR_FAILURE) {
	if (freeIt) nss_ZFreeIf(usagesOpt);
	return (NSSUsages *)NULL;
    }
    usagesOpt->peer = get_trusted_usage(c, PR_FALSE, &status);
    if (status == PR_FAILURE) {
	if (freeIt) nss_ZFreeIf(usagesOpt);
	return (NSSUsages *)NULL;
    }
    return usagesOpt;
}

NSS_IMPLEMENT NSSUsages *
NSSCertificate_GetTrustedUsages
(
  NSSCertificate *c,
  NSSUsages *usagesOpt
)
{
    return nssCertificate_GetTrustedUsages(c, usagesOpt);
}

NSS_IMPLEMENT PRBool
nssCertificate_IsTrustedForUsages
(
  NSSCertificate *c,
  NSSUsages *usages,
  PRStatus *statusOpt
)
{
    NSSUsages certUsages;
    if (nssCertificate_GetTrustedUsages(c, &certUsages) == NULL) {
	if (statusOpt) *statusOpt = PR_FAILURE;
	return PR_FALSE;
    }
    return nssUsages_Match(usages, &certUsages);
}

static void
set_trust_for_usage
(
  NSSUsage usage,
  nssTrust *trust,
  nssTrustLevel setLevel
)
{
    if (usage & NSSUsage_SSLClient) {
	trust->clientAuth = setLevel;
    }
    if (usage & NSSUsage_SSLServer) {
	trust->serverAuth = setLevel;
    }
    if (usage & (NSSUsage_EmailSigner | NSSUsage_EmailRecipient)) {
	trust->emailProtection = setLevel;
    }
    if (usage & NSSUsage_CodeSigner) {
	trust->codeSigning = setLevel;
    }
}

/* XXX move */
NSS_IMPLEMENT NSSToken *
nssTrust_GetWriteToken
(
  nssTrust *t,
  nssSession **rvSessionOpt
)
{
    return nssPKIObject_GetWriteToken(&t->object, rvSessionOpt);
}

/* XXX move */
NSS_IMPLEMENT void
nssTrust_Clear
(
  nssTrust *trust
)
{
    trust->clientAuth = nssTrustLevel_NotTrusted;
    trust->serverAuth = nssTrustLevel_NotTrusted;
    trust->emailProtection = nssTrustLevel_NotTrusted;
    trust->codeSigning = nssTrustLevel_NotTrusted;
}

/* XXX move */
NSS_IMPLEMENT nssTrust *
nssTrust_CreateNull
(
  NSSTrustDomain *td
)
{
    nssPKIObject *pkio;
    nssTrust *trust = NULL;
    pkio = nssPKIObject_Create(NULL, NULL, td, NULL);
    if (pkio) {
	trust = nss_ZNEW(pkio->arena, nssTrust);
	if (trust) {
	    trust->object = *pkio;
	    nssTrust_Clear(trust);
	} else {
	    nssPKIObject_Destroy(pkio);
	}
    }
    return trust;
}

NSS_IMPLEMENT PRStatus
nssCertificate_SetTrustedUsages
(
  NSSCertificate *c,
  NSSUsages *usages
)
{
    PRStatus status;
    nssTrust *trust;
    NSSToken *token;
    nssSession *session;
    nssCryptokiObject *instance;

    /* XXX needs to be cached with cert */
    trust = nssTrustDomain_FindTrustForCertificate(c->object.trustDomain, c);
    if (trust) {
	token = nssTrust_GetWriteToken(trust, &session);
	nssTrust_Clear(trust);
    } else {
	if (NSS_GetError() != NSS_ERROR_NO_ERROR) {
	    return PR_FAILURE;
	}
	/* XXX something better */
	/* create a new trust object */
	trust = nssTrust_CreateNull(c->object.trustDomain);
	if (!trust) {
	    return PR_FAILURE;
	}
	token = nssCertificate_GetWriteToken(c, &session);
	if (!token) {
	    /* XXX should extract from trust domain */
	    PR_ASSERT(0);
	    return PR_FAILURE;
	}
    }
    /* set the new trust values */
    set_trust_for_usage(usages->ca, trust, nssTrustLevel_TrustedDelegator);
    set_trust_for_usage(usages->peer, trust, nssTrustLevel_Trusted);
    /* import (set) the trust values on the token */
    instance = nssToken_ImportTrust(token, session, &c->encoding,
                                    &c->issuer, &c->serial,
                                    trust->serverAuth,
                                    trust->clientAuth,
                                    trust->codeSigning,
                                    trust->emailProtection,
                                    PR_TRUE);
    /* clean up */
    nssSession_Destroy(session);
    nssToken_Destroy(token);
    if (instance) {
	nssCryptokiObject_Destroy(instance);
	status = PR_SUCCESS;
    } else {
	status = PR_FAILURE;
    }
    nssTrust_Destroy(trust);
    return status;
}

NSS_IMPLEMENT PRStatus
NSSCertificate_SetTrustedUsages
(
  NSSCertificate *c,
  NSSUsages *usages
)
{
    return nssCertificate_SetTrustedUsages(c, usages);
}

NSS_IMPLEMENT NSSDER *
nssCertificate_Encode
(
  NSSCertificate *c,
  NSSDER *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssItem_Duplicate((NSSItem *)&c->encoding, arenaOpt, rvOpt);
}

NSS_IMPLEMENT NSSDER *
NSSCertificate_Encode
(
  NSSCertificate *c,
  NSSDER *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssCertificate_Encode(c, rvOpt, arenaOpt);
}

static NSSCertificate *
filter_subject_certs_for_id
(
  NSSCertificate **subjectCerts, 
  void *id
)
{
    NSSCertificate **si;
    NSSCertificate *rvCert = NULL;
    /* walk the subject certs */
    for (si = subjectCerts; *si; si++) {
	nssCertDecoding *dcp = nssCertificate_GetDecoding(*si);
	if (dcp->methods->isMyIdentifier(dcp->data, id)) {
	    /* this cert has the correct identifier */
	    rvCert = nssCertificate_AddRef(*si);
	    break;
	}
    }
    return rvCert;
}

static NSSCertificate *
find_cert_issuer
(
  NSSCertificate *c,
  NSSTime time,
  NSSUsages *usagesOpt,
  NSSPolicies *policiesOpt
)
{
    NSSArena *arena;
    NSSCertificate **certs = NULL;
    NSSCertificate **ccIssuers = NULL;
    NSSCertificate **tdIssuers = NULL;
    NSSCertificate *issuer = NULL;
    NSSTrustDomain *td;
    NSSCryptoContext *cc;
    cc = c->object.cryptoContext; /* NSSCertificate_GetCryptoContext(c); */
    td = nssCertificate_GetTrustDomain(c);
    arena = nssArena_Create();
    if (!arena) {
	return (NSSCertificate *)NULL;
    }
    if (cc) {
	ccIssuers = nssCryptoContext_FindCertificatesBySubject(cc,
	                                                       &c->issuer,
	                                                       NULL,
	                                                       0,
	                                                       arena);
    }
    tdIssuers = nssTrustDomain_FindCertificatesBySubject(td,
                                                         &c->issuer,
                                                         NULL,
                                                         0,
                                                         arena);
    certs = nssCertificateArray_Join(ccIssuers, tdIssuers);
    if (certs) {
	nssCertDecoding *dc = NULL;
	void *issuerID = NULL;
	dc = nssCertificate_GetDecoding(c);
	if (dc) {
	    issuerID = dc->methods->getIssuerIdentifier(dc->data);
	}
	if (issuerID) {
	    issuer = filter_subject_certs_for_id(certs, issuerID);
	    dc->methods->freeIdentifier(issuerID);
	} else {
	    issuer = nssCertificateArray_FindBestCertificate(certs,
	                                                     time,
	                                                     usagesOpt,
	                                                     policiesOpt);
	}
	nssCertificateArray_Destroy(certs);
    }
    nssArena_Destroy(arena);
    return issuer;
}

/* XXX review based on CERT_FindCertIssuer
 * this function is not using the authCertIssuer field as a fallback
 * if authority key id does not exist
 */
NSS_IMPLEMENT NSSCertificate **
nssCertificate_BuildChain
(
  NSSCertificate *c,
  NSSTime time,
  NSSUsages *usagesOpt,
  NSSPolicies *policiesOpt,
  NSSCertificate **rvOpt,
  PRUint32 rvLimit,
  NSSArena *arenaOpt,
  PRStatus *statusOpt
)
{
    PRStatus status;
    NSSCertificate **rvChain;
    NSSTrustDomain *td;
    nssPKIObjectCollection *collection;
    NSSUsages usages = { 0 };

    td = NSSCertificate_GetTrustDomain(c);
    if (statusOpt) *statusOpt = PR_SUCCESS;

    /* initialize the collection with the current cert */
    collection = nssCertificateCollection_Create(td, NULL);
    if (!collection) {
	if (statusOpt) *statusOpt = PR_FAILURE;
	return (NSSCertificate **)NULL;
    }
    nssPKIObjectCollection_AddObject(collection, (nssPKIObject *)c);
    if (rvLimit == 1) {
	goto finish;
    }
    /* going from peer to CA */
    if (usagesOpt) {
	usages.ca = usagesOpt->peer;
	usagesOpt = &usages;
    }
    /* walk the chain */
    while (!nssItem_Equal(&c->subject, &c->issuer, &status)) {
	c = find_cert_issuer(c, time, usagesOpt, policiesOpt);
	if (c) {
	    nssPKIObjectCollection_AddObject(collection, (nssPKIObject *)c);
	    nssCertificate_Destroy(c); /* collection has it */
	    if (rvLimit > 0 &&
	        nssPKIObjectCollection_Count(collection) == rvLimit) 
	    {
		break;
	    }
	} else {
	    nss_SetError(NSS_ERROR_CERTIFICATE_ISSUER_NOT_FOUND);
	    if (statusOpt) *statusOpt = PR_FAILURE;
	    break;
	}
    }
finish:
    rvChain = nssPKIObjectCollection_GetCertificates(collection, 
                                                     rvOpt, 
                                                     rvLimit, 
                                                     arenaOpt);
    nssPKIObjectCollection_Destroy(collection);
    return rvChain;
}

NSS_IMPLEMENT NSSCertificate **
NSSCertificate_BuildChain
(
  NSSCertificate *c,
  NSSTime time,
  NSSUsages *usagesOpt,
  NSSPolicies *policiesOpt,
  NSSCertificate **rvOpt,
  PRUint32 rvLimit, /* zero for no limit */
  NSSArena *arenaOpt,
  PRStatus *statusOpt
)
{
    return nssCertificate_BuildChain(c, time, usagesOpt, policiesOpt,
                                     rvOpt, rvLimit, arenaOpt, statusOpt);
}

NSS_IMPLEMENT NSSItem *
NSSCertificate_Encrypt
(
  NSSCertificate *c,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *data,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT PRStatus
NSSCertificate_Verify
(
  NSSCertificate *c,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *data,
  NSSItem *signature,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt,
  NSSCallback *uhh
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return PR_FAILURE;
}

NSS_IMPLEMENT NSSItem *
NSSCertificate_VerifyRecover
(
  NSSCertificate *c,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *signature,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSItem *
NSSCertificate_WrapSymmetricKey
(
  NSSCertificate *c,
  const NSSAlgorithmAndParameters *apOpt,
  NSSSymmetricKey *keyToWrap,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCryptoContext *
NSSCertificate_CreateCryptoContext
(
  NSSCertificate *c,
  const NSSAlgorithmAndParameters *apOpt,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt,
  NSSCallback *uhh  
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSPublicKey *
nssCertificate_GetPublicKey
(
  NSSCertificate *c
)
{
    PRStatus status;
    NSSToken **tokens, **tp;
    nssCryptokiObject *instance;
    NSSTrustDomain *td = nssCertificate_GetTrustDomain(c);
    tokens = nssPKIObject_GetTokens(&c->object, &status);
    if (!tokens) {
	return (NSSPublicKey *)NULL; /* actually, should defer to crypto context */
    }
    for (tp = tokens; *tp; tp++) {
	/* XXX need to iterate over cert instances to have session */
	nssSession *session = nssToken_CreateSession(*tp, PR_FALSE);
	if (!session) {
	    break;
	}
	instance = nssToken_FindPublicKeyByID(*tp, session, &c->id);
	nssSession_Destroy(session);
	if (instance) {
	    break;
	}
    }
    /* also search on other tokens? */
    nssTokenArray_Destroy(tokens);
    if (instance) {
	nssPKIObject *pkio;
	NSSPublicKey *bk = NULL;
	pkio = nssPKIObject_Create(NULL, instance, td, /* XXX cc */ NULL);
	if (!pkio) {
	    nssCryptokiObject_Destroy(instance);
	    return (NSSPublicKey *)NULL;
	}
	bk = nssPublicKey_Create(pkio);
	if (!bk) {
	    nssPKIObject_Destroy(pkio);
	    return (NSSPublicKey *)NULL;
	}
	return bk;
    } else {
	NSSOID *keyAlg;
	NSSBitString keyBits;
	nssCertDecoding *dc = nssCertificate_GetDecoding(c);

	status = dc->methods->getPublicKeyInfo(dc->data, &keyAlg, &keyBits);
	if (status == PR_SUCCESS) {
	    return nssPublicKey_CreateFromInfo(td, NULL, keyAlg, &keyBits);
	}
    }
    return (NSSPublicKey *)NULL;
}

NSS_IMPLEMENT NSSPublicKey *
NSSCertificate_GetPublicKey
(
  NSSCertificate *c
)
{
    return nssCertificate_GetPublicKey(c);
}

NSS_IMPLEMENT NSSPrivateKey *
nssCertificate_FindPrivateKey
(
  NSSCertificate *c,
  NSSCallback *uhh
)
{
    PRStatus status;
    NSSToken **tokens, **tp;
    nssCryptokiObject *instance;
    NSSTrustDomain *td = nssCertificate_GetTrustDomain(c);

    tokens = nssPKIObject_GetTokens(&c->object, &status);
    if (!tokens) {
	return PR_FALSE; /* actually, should defer to crypto context */
    }
    for (tp = tokens; *tp; tp++) {
	NSSSlot *slot = nssToken_GetSlot(*tp);
	NSSCallback *pwcb = uhh ? 
	                    uhh : 
	                    nssTrustDomain_GetDefaultCallback(td, NULL);
	status = nssSlot_Login(slot, pwcb);
	nssSlot_Destroy(slot);
	if (status != PR_SUCCESS) {
	    break;
	}
	/* XXX need to iterate over cert instances to have session */
	{
	    nssSession *session = nssToken_CreateSession(*tp, PR_FALSE);
	    instance = nssToken_FindPrivateKeyByID(*tp, session, &c->id);
	    nssSession_Destroy(session);
	    if (instance) {
		break;
	    }
	}
    }
    /* also search on other tokens? */
    nssTokenArray_Destroy(tokens);
    if (instance) {
	nssPKIObject *pkio;
	NSSPrivateKey *vk = NULL;
	pkio = nssPKIObject_Create(NULL, instance, td, /* XXX cc */ NULL);
	if (!pkio) {
	    nssCryptokiObject_Destroy(instance);
	    return (NSSPrivateKey *)NULL;
	}
	vk = nssPrivateKey_Create(pkio);
	if (!vk) {
	    nssPKIObject_Destroy(pkio);
	    return (NSSPrivateKey *)NULL;
	}
	return vk;
    }
    return (NSSPrivateKey *)NULL;
}

NSS_IMPLEMENT NSSPrivateKey *
NSSCertificate_FindPrivateKey
(
  NSSCertificate *c,
  NSSCallback *uhh
)
{
    return nssCertificate_FindPrivateKey(c, uhh);
}

NSS_IMPLEMENT PRBool
nssCertificate_IsPrivateKeyAvailable
(
  NSSCertificate *c,
  NSSCallback *uhh,
  PRStatus *statusOpt
)
{
    /* this works with the softoken, does it work everywhere?  */
    return (c->id.size > 0);
}

NSS_IMPLEMENT PRBool
NSSCertificate_IsPrivateKeyAvailable
(
  NSSCertificate *c,
  NSSCallback *uhh,
  PRStatus *statusOpt
)
{
    return nssCertificate_IsPrivateKeyAvailable(c, uhh, statusOpt);
}

NSS_IMPLEMENT PRBool
NSSUserCertificate_IsStillPresent
(
  NSSUserCertificate *uc,
  PRStatus *statusOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return PR_FALSE;
}

NSS_IMPLEMENT NSSItem *
NSSUserCertificate_Decrypt
(
  NSSUserCertificate *uc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *data,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSItem *
NSSUserCertificate_Sign
(
  NSSUserCertificate *uc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *data,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSItem *
NSSUserCertificate_SignRecover
(
  NSSUserCertificate *uc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *data,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSSymmetricKey *
NSSUserCertificate_UnwrapSymmetricKey
(
  NSSUserCertificate *uc,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *wrappedKey,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSSymmetricKey *
NSSUserCertificate_DeriveSymmetricKey
(
  NSSUserCertificate *uc, /* provides private key */
  NSSCertificate *c, /* provides public key */
  const NSSAlgorithmAndParameters *apOpt,
  NSSOID *target,
  PRUint32 keySizeOpt, /* zero for best allowed */
  NSSOperations operations,
  NSSCallback *uhh
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT nssTrust *
nssTrust_Create
(
  nssPKIObject *object
)
{
    PRStatus status;
    PRUint32 i;
    PRUint32 lastTrustOrder, myTrustOrder;
    NSSModule *module;
    nssTrust *rvt;
    nssCryptokiObject *instance;
    nssTrustLevel serverAuth, clientAuth, codeSigning, emailProtection;
    lastTrustOrder = 1<<16; /* just make it big */
    PR_ASSERT(object->instances != NULL && object->numInstances > 0);
    rvt = nss_ZNEW(object->arena, nssTrust);
    if (!rvt) {
	return (nssTrust *)NULL;
    }
    rvt->object = *object;
    /* trust has to peek into the base object members */
    PZ_Lock(object->lock);
    for (i=0; i<object->numInstances; i++) {
	/* get the trust order from the token's module */
	instance = object->instances[i];
	module = nssToken_GetModule(instance->token);
	myTrustOrder = nssModule_GetTrustOrder(module);
	nssModule_Destroy(module);
	/* get the trust values from this token */
	status = nssCryptokiTrust_GetAttributes(instance,
	                                        &serverAuth,
	                                        &clientAuth,
	                                        &codeSigning,
	                                        &emailProtection);
	if (status != PR_SUCCESS) {
	    PZ_Unlock(object->lock);
	    return (nssTrust *)NULL;
	}
	if (rvt->serverAuth == nssTrustLevel_Unknown ||
	    myTrustOrder < lastTrustOrder) 
	{
	    rvt->serverAuth = serverAuth;
	}
	if (rvt->clientAuth == nssTrustLevel_Unknown ||
	    myTrustOrder < lastTrustOrder) 
	{
	    rvt->clientAuth = clientAuth;
	}
	if (rvt->emailProtection == nssTrustLevel_Unknown ||
	    myTrustOrder < lastTrustOrder) 
	{
	    rvt->emailProtection = emailProtection;
	}
	if (rvt->codeSigning == nssTrustLevel_Unknown ||
	    myTrustOrder < lastTrustOrder) 
	{
	    rvt->codeSigning = codeSigning;
	}
	lastTrustOrder = myTrustOrder;
    }
    PZ_Unlock(object->lock);
    return rvt;
}

NSS_IMPLEMENT nssTrust *
nssTrust_AddRef
(
  nssTrust *trust
)
{
    if (trust) {
	nssPKIObject_AddRef(&trust->object);
    }
    return trust;
}

NSS_IMPLEMENT PRStatus
nssTrust_Destroy
(
  nssTrust *trust
)
{
    if (trust) {
	(void)nssPKIObject_Destroy(&trust->object);
    }
    return PR_SUCCESS;
}

struct nssSMIMEProfileStr
{
    nssPKIObject object;
    NSSCertificate *certificate;
    NSSASCII7 *email;
    NSSDER *subject;
    NSSItem *profileTime;
    NSSItem *profileData;
};

NSS_IMPLEMENT nssSMIMEProfile *
nssSMIMEProfile_Create
(
  NSSCertificate *cert,
  NSSItem *profileTime,
  NSSItem *profileData
)
{
    NSSArena *arena;
    nssSMIMEProfile *rvProfile;
    nssPKIObject *object;
    NSSTrustDomain *td = nssCertificate_GetTrustDomain(cert);
    NSSCryptoContext *cc = nssCertificate_GetCryptoContext(cert);
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
    return (nssSMIMEProfile *)NULL;
}

NSS_IMPLEMENT nssSMIMEProfile *
nssSMIMEProfile_AddRef
(
  nssSMIMEProfile *profile
)
{
    if (profile) {
	nssPKIObject_AddRef(&profile->object);
    }
    return profile;
}

NSS_IMPLEMENT PRStatus
nssSMIMEProfile_Destroy
(
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
nssCRL_Create
(
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
nssCRL_AddRef
(
  NSSCRL *crl
)
{
    if (crl) {
	nssPKIObject_AddRef(&crl->object);
    }
    return crl;
}

NSS_IMPLEMENT PRStatus
nssCRL_Destroy
(
  NSSCRL *crl
)
{
    if (crl) {
	(void)nssPKIObject_Destroy(&crl->object);
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT PRStatus
nssCRL_DeleteStoredObject
(
  NSSCRL *crl,
  NSSCallback *uhh
)
{
    return nssPKIObject_DeleteStoredObject(&crl->object, uhh, PR_TRUE);
}

NSS_IMPLEMENT NSSDER *
nssCRL_GetEncoding
(
  NSSCRL *crl
)
{
    if (crl->encoding.data != NULL && crl->encoding.size > 0) {
	return &crl->encoding;
    } else {
	return (NSSDER *)NULL;
    }
}
