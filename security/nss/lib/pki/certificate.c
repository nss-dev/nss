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

extern const NSSError NSS_ERROR_NOT_FOUND;

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

NSS_IMPLEMENT NSSUsages
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
    return dc->usages;
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
    nssCertDecoding *dc1, *dc2;
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

#if 0
NSS_IMPLEMENT PRBool
nssCertificate_IsValidAtTime
(
  NSSCertificate *c,
  NSSTime *time,
  PRStatus *statusOpt
)
{
    PRStatus status = PR_FAILURE;
    nssDecodedCertificate *dc;

    dc = nssCertificate_GetDecoding(c);
    if (!dc) {
	if (statusOpt) *statusOpt = PR_FAILURE;
	return PR_FALSE;
    }

    /* Get the validity period from the decoded certificate */
    if (!dc->haveValidityPeriod) {
	/* First time it has been asked for, go and get it from the
	 * certificate handler
	 */
	status = dc->GetValidTimes(dc->cert, &dc->notBefore, &dc->notAfter);
	if (status != PR_SUCCESS) {
	    if (statusOpt) *statusOpt = PR_FAILURE;
	    return PR_FALSE;
	}
	dc->haveValidityPeriod = PR_TRUE;
    }

    return nssTime_WithinRange(time, dc->notBefore, dc->notAfter);
}

NSS_IMPLEMENT PRBool
nssCertificate_IsCapableOfUsage
(
  NSSCertificate *c,
  NSSUsage *usage,
  PRStatus *statusOpt
)
{
    PRStatus status = PR_FAILURE;
    nssDecodedCertificate *dc;

    dc = nssCertificate_GetDecoding(c);
    if (!dc) {
	if (statusOpt) *statusOpt = PR_FAILURE;
	return PR_FALSE;
    }

    /* Get the set of usages from the decoded certificate */
    if (!dc->haveUsages) {
	/* First time they have been asked for, go and get them from the
	 * certificate handler
	 */
	status = dc->GetUsages(dc->cert, &dc->usages);
	if (status != PR_SUCCESS) {
	    if (statusOpt) *statusOpt = PR_FAILURE;
	    return PR_FALSE;
	}
	dc->haveUsages = PR_TRUE;
    }

    return (usage & dc->usages) ? PR_TRUE : PR_FALSE;
}

static PRStatus
validate_and_discover_trust
(
  NSSCertificate *c,
  NSSTime *time,
  NSSUsage *usage,
  NSSPolicies *policiesOpt,
  PRBool *trusted
)
{
    PRStatus status;

    *trusted = PR_FALSE;

    /* First verify the time is within the cert's validity period */
    if (!nssCertificate_IsValidAtTime(c, timeOpt, &status)) {
	if (status == PR_SUCCESS) {
	    /* The function was successful, so we own the error */
	    nss_SetError(NSS_ERROR_CERTIFICATE_NOT_VALID_AT_TIME);
	} /* else the function failed and owns the error */
	return PR_FAILURE;
    }

    /* Verify the cert is capable of the desired usage */
    if (!nssCertificate_IsCapableOfUsage(c, usage, &status)) {
	if (status == PR_SUCCESS) {
	    /* The function was successful, so we own the error */
	    nss_SetError(NSS_ERROR_CERTIFICATE_INSUFFICIENT_USAGE);
	} /* else the function failed and owns the error */
	return PR_FAILURE;
    }

    /* See if the cert is trusted */
    if (nssCertificate_IsTrustedForUsage(c, usage, &status)) {
	*trusted = PR_TRUE;
    }

    return status;
}

static PRStatus
validate_chain_link
(
  NSSCertificate *subjectCert,
  NSSCertificate *issuerCert,
  void **vData,
  PRBool *finished
)
{
    PRStatus status;
    nssCertDecoding *dcs, *dci;

    *finished = PR_FALSE;
    if (nssCertificate_Equal(subjectCert, issuerCert)) {
	*finished = PR_TRUE;
    }

    dcs = nssCertificate_GetDecoding(subjectCert);
    if (!dc) {
	return PR_FAILURE;
    }

    dci = nssCertificate_GetDecoding(issuerCert);
    if (!dc) {
	return PR_FAILURE;
    }

    if (!*vData) {
	*vData = dc->StartChainValidation();
	if (!*vData) {
	    return PR_FAILURE;
	}
    }

    status = dc->ValidateChainLink(dcs->cert, dci->cert, *vData);

    if (*finished) {
	dc->FreeChainValidationData(*vData);
	*vData = NULL;
    }
}

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
    if (NSS_GetIsOCSPEnabled() == PR_TRUE) {
	nssOCSPResponder *responder = get_ocsp_responder(chain[0]);
	if (responder) {
	    status = nssOCSPResponder_CheckStatus(responder, chain[0]));
	}
    }
}

NSS_IMPLEMENT PRStatus
nssCertificate_Validate
(
  NSSCertificate *c,
  NSSTime *timeOpt,
  NSSUsage *usage,
  NSSPolicies *policiesOpt
)
{
    PRStatus status;
    PRBool trusted;
    NSSCertificate **cp, **chain;
    NSSCertificate *subjectCert = NULL;
    NSSCertificate *issuerCert = NULL;
    void *vData = NULL;

    if (!timeOpt) {
	timeOpt = NSSTime_Now();
    }

    /* Build the chain (this cert will be first) */
    chain = nssCertificate_BuildChain(c, timeOpt, usage, policiesOpt,
                                      NULL, 0, NULL, &status);
    if (status == PR_FAILURE) {
	return PR_FAILURE;
    }

    /* Validate the chain */
    for (cp = chain; *cp; cp++) {
	subjectCert = *cp;
	status = validate_and_discover_trust(subjectCert,
	                                     timeOpt, usage, policiesOpt,
	                                     &trusted);
	if (status == PR_FAILURE) {
	    goto done;
	}
	if (trusted) {
	    if (issuerCert == NULL) {
		/* The cert we are validating is explicitly trusted */
		goto done;
	    } else {
		/* Some cert in the chain is explicitly trusted, still
		 * need to check OCSP and/or CRL's
		 */
		goto check_revocation;
	    }
	}
	if (issuerCert) {
	    status = validate_chain_link(subjectCert, issuerCert, 
	                                 &vData, &finished);
	    if (status == PR_FAILURE) {
		goto done;
	    }
	}
	if (finished) {
	    break;
	}
	usage = nssUsage_GetRequiredCAUsage(usage);
	issuerCert = subjectCert;
    }

check_revocation:
    if (cert_in_chain_revoked(chain, &status)) {
	if (status == PR_SUCCESS) {
	    /* The status check succeeded, set the error */
	    nss_SetError(NSS_ERROR_CERTIFICATE_REVOKED);
	}
    }

done:
    nssCertificateArray_Destroy(chain);
    return status;
}
#endif

NSS_IMPLEMENT PRStatus
NSSCertificate_Validate
(
  NSSCertificate *c,
  NSSTime *timeOpt,
  NSSUsage *usage,
  NSSPolicies *policiesOpt
)
{
    /*return nssCertificate_Validate(c, timeOpt, usage, policiesOpt);*/
return PR_FAILURE;
}

NSS_IMPLEMENT void ** /* void *[] */
NSSCertificate_ValidateCompletely
(
  NSSCertificate *c,
  NSSTime *timeOpt, /* NULL for "now" */
  NSSUsage *usage,
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
  NSSTime *timeOpt,
  NSSUsages usages,
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
#ifdef NSS_3_4_CODE
    if (!td) {
	td = STAN_GetDefaultTrustDomain();
    }
#endif
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
	                                                     timeOpt,
	                                                     usages,
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
  NSSTime *timeOpt,
  NSSUsages usages,
  NSSPolicies *policiesOpt,
  NSSCertificate **rvOpt,
  PRUint32 rvLimit,
  NSSArena *arenaOpt,
  PRStatus *statusOpt
)
{
    PRStatus status;
    NSSCertificate **rvChain;
#ifdef NSS_3_4_CODE
    NSSCertificate *cp;
#endif
    NSSTrustDomain *td;
    nssPKIObjectCollection *collection;
    td = NSSCertificate_GetTrustDomain(c);
#ifdef NSS_3_4_CODE
    if (!td) {
	td = STAN_GetDefaultTrustDomain();
    }
#endif
    if (statusOpt) *statusOpt = PR_SUCCESS;
    collection = nssCertificateCollection_Create(td, NULL);
    if (!collection) {
	if (statusOpt) *statusOpt = PR_FAILURE;
	return (NSSCertificate **)NULL;
    }
    nssPKIObjectCollection_AddObject(collection, (nssPKIObject *)c);
    if (rvLimit == 1) {
	goto finish;
    }
    while (!nssItem_Equal(&c->subject, &c->issuer, &status)) {
	c = find_cert_issuer(c, timeOpt, usages, policiesOpt);
#ifdef NSS_3_4_CODE
	if (!c) {
	    PRBool tmpca = usage->nss3lookingForCA;
	    usage->nss3lookingForCA = PR_TRUE;
	    c = find_cert_issuer(c, timeOpt, usages, policiesOpt);
	    if (!c && !usage->anyUsage) {
		usage->anyUsage = PR_TRUE;
		c = find_cert_issuer(c, timeOpt, usages, policiesOpt);
		usage->anyUsage = PR_FALSE;
	    }
	    usage->nss3lookingForCA = tmpca;
	}
#endif /* NSS_3_4_CODE */
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
  NSSTime *timeOpt,
  NSSUsages usages,
  NSSPolicies *policiesOpt,
  NSSCertificate **rvOpt,
  PRUint32 rvLimit, /* zero for no limit */
  NSSArena *arenaOpt,
  PRStatus *statusOpt
)
{
    return nssCertificate_BuildChain(c, timeOpt, usages, policiesOpt,
                                     rvOpt, rvLimit, arenaOpt, statusOpt);
}

NSS_IMPLEMENT NSSItem *
NSSCertificate_Encrypt
(
  NSSCertificate *c,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *data,
  NSSTime *timeOpt,
  NSSUsage *usage,
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
  NSSTime *timeOpt,
  NSSUsage *usage,
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
  NSSTime *timeOpt,
  NSSUsage *usage,
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
  NSSTime *timeOpt,
  NSSUsage *usage,
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
  NSSTime *timeOpt,
  NSSUsage *usage,
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
	instance = nssToken_FindPublicKeyByID(*tp, NULL, &c->id);
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
	    if (instance) {
		nssCryptokiObject_Destroy(instance);
		break;
	    }
	    nssSession_Destroy(session);
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
    NSSPrivateKey *vk;
    vk = nssCertificate_FindPrivateKey(c, uhh);
    if (!vk) {
	if (statusOpt) {
	    *statusOpt = PR_FAILURE;
	}
	return PR_FALSE;
    }
    nssPrivateKey_Destroy(vk);
    return PR_TRUE;
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
  NSSTime *timeOpt,
  NSSUsage *usage,
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
  NSSTime *timeOpt,
  NSSUsage *usage,
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
  NSSTime *timeOpt,
  NSSUsage *usage,
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
  NSSTime *timeOpt,
  NSSUsage *usage,
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

struct NSSTrustStr 
{
    nssPKIObject object;
    NSSCertificate *certificate;
    nssTrustLevel serverAuth;
    nssTrustLevel clientAuth;
    nssTrustLevel emailProtection;
    nssTrustLevel codeSigning;
};

NSS_IMPLEMENT NSSTrust *
nssTrust_Create
(
  nssPKIObject *object
)
{
    PRStatus status;
    PRUint32 i;
    PRUint32 lastTrustOrder, myTrustOrder;
    NSSModule *module;
    NSSTrust *rvt;
    nssCryptokiObject *instance;
    nssTrustLevel serverAuth, clientAuth, codeSigning, emailProtection;
    lastTrustOrder = 1<<16; /* just make it big */
    PR_ASSERT(object->instances != NULL && object->numInstances > 0);
    rvt = nss_ZNEW(object->arena, NSSTrust);
    if (!rvt) {
	return (NSSTrust *)NULL;
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
	    return (NSSTrust *)NULL;
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

NSS_IMPLEMENT NSSTrust *
nssTrust_AddRef
(
  NSSTrust *trust
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
  NSSTrust *trust
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
