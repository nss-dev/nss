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
  NSSCertMethods *methods;
  PRBool haveValidity;
  NSSTime notBefore;
  NSSTime notAfter;
  PRBool haveUsages;
  NSSUsages usages;
  NSSPolicies *policies;
}
nssCertDecoding;

struct NSSCertStr
{
  nssPKIObject object;
  NSSCertType kind;
  NSSItem id;
  NSSBER encoding;
  NSSDER issuer;
  NSSDER subject;
  NSSDER serial;
  NSSASCII7 *email;
  NSSPublicKey *bk; /* for ephemeral decoded pubkeys */
  nssTrust trust;
  nssCertDecoding decoding;
};


NSS_EXTERN NSSCertMethods *
nss_GetMethodsForType (
  NSSCertType certType
);

NSS_IMPLEMENT NSSCert *
nssCert_CreateFromInstance (
  nssCryptokiObject *instance,
  NSSTrustDomain *td,
  NSSVolatileDomain *vdOpt
)
{
    PRStatus status;
    nssPKIObject *pkio;
    NSSCert *rvCert = NULL;
    nssPKIObjectTable *objectTable = nssTrustDomain_GetObjectTable(td);

    rvCert = nssPKIObject_CREATE(td, instance, NSSCert);
    if (!rvCert) {
	return (NSSCert *)NULL;
    }
    pkio = &rvCert->object;
    status = nssCryptokiCert_GetAttributes(instance, pkio->arena,
                                           &rvCert->kind,
                                           &rvCert->id,
                                           &rvCert->encoding,
                                           &rvCert->issuer,
                                           &rvCert->serial,
                                           &rvCert->subject);
    if (status != PR_SUCCESS) {
	goto loser;
    }
    pkio->objectType = pkiObjectType_Cert;
    pkio->numIDs = 2;
    pkio->uid[0] = &rvCert->issuer;
    pkio->uid[1] = &rvCert->serial;
    rvCert = (NSSCert *)nssPKIObjectTable_Add(objectTable, pkio);
    if (!rvCert) {
	rvCert = (NSSCert *)pkio;
	goto loser;
    } else if ((nssPKIObject *)rvCert != pkio) {
	nssCert_Destroy((NSSCert *)pkio);
    }
    rvCert->decoding.methods = nss_GetMethodsForType(rvCert->kind);
    if (!rvCert->decoding.methods) {
	goto loser;
    }
    if (rvCert && vdOpt) {
	status = nssVolatileDomain_ImportCert(vdOpt, rvCert);
	if (status == PR_FAILURE) {
	    goto loser;
	}
    }
    /* token certs trusted by default */
    rvCert->trust.trustedUsages.ca = rvCert->trust.trustedUsages.peer = ~0;
    /* XXX or check trust here by looking at db? */
    return rvCert;
loser:
    nssCert_Destroy(rvCert);
    return (NSSCert *)NULL;
}

NSS_IMPLEMENT NSSCert *
nssCert_Decode (
  NSSBER *ber,
  NSSItem *nicknameOpt,
  nssTrust *trustOpt,
  NSSTrustDomain *td,
  NSSVolatileDomain *vdOpt
)
{
    nssPKIObject *pkio;
    NSSCert *rvCert;
    NSSCertMethods *decoder;
    void *decoding;
    NSSItem *it;
    nssPKIObjectTable *objectTable = nssTrustDomain_GetObjectTable(td);

    rvCert = nssPKIObject_CREATE(td, NULL, NSSCert);
    if (!rvCert) {
	return (NSSCert *)NULL;
    }
    pkio = &rvCert->object;
    /* try to decode it */
    decoder = nss_GetMethodsForType(NSSCertType_PKIX);
    if (!decoder) {
	/* nss_SetError(UNKNOWN_CERT_TYPE); */
	goto loser;
    }
    decoding = decoder->decode(pkio->arena, ber);
    if (decoding) {
	/* it's a PKIX cert */
	rvCert->decoding.methods = decoder;
	rvCert->decoding.data = decoding;
	rvCert->kind = NSSCertType_PKIX;
    } else {
	goto loser;
    }
    /* copy the BER encoding */
    it = nssItem_Duplicate(ber, pkio->arena, &rvCert->encoding);
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
    /* set the nickname to the supplied one */
    if (nicknameOpt) {
	pkio->nickname = nssUTF8_Create(pkio->arena, nssStringType_UTF8String,
	                                nicknameOpt->data, nicknameOpt->size);
    }
    if (trustOpt) {
	rvCert->trust = *trustOpt;
    }
    pkio->objectType = pkiObjectType_Cert;
    pkio->numIDs = 2;
    pkio->uid[0] = &rvCert->issuer;
    pkio->uid[1] = &rvCert->serial;
    rvCert = (NSSCert *)nssPKIObjectTable_Add(objectTable, pkio);
    if (!rvCert) {
	rvCert = (NSSCert *)pkio;
	goto loser;
    } else if ((nssPKIObject *)rvCert != pkio) {
	nssCert_Destroy((NSSCert *)pkio);
    }
    return rvCert;
loser:
    nssCert_Destroy(rvCert);
    return (NSSCert *)NULL;
}

/* XXX */
NSS_IMPLEMENT NSSCert *
nssCert_CreateIndexCert (
  NSSDER *issuer,
  NSSDER *serial
)
{
    NSSCert *c = nss_ZNEW(NULL, NSSCert);
    if (c) {
	c->issuer = *issuer;
	c->serial = *serial;
    }
    return c;
}

NSS_IMPLEMENT NSSCert *
nssCert_AddRef (
  NSSCert *c
)
{
    if (c) {
	nssPKIObject_AddRef(&c->object);
    }
    return c;
}

NSS_IMPLEMENT PRStatus
nssCert_Destroy (
  NSSCert *c
)
{
    PRBool destroyed;
    if (c) {
	void *dc = c->decoding.data;
	NSSCertMethods *methods = c->decoding.methods;
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
nssCert_RemoveInstanceForToken (
  NSSCert *c,
  NSSToken *token
)
{
    return nssPKIObject_RemoveInstanceForToken(&c->object, token);
}

NSS_IMPLEMENT PRBool
nssCert_HasInstanceOnToken (
  NSSCert *c,
  NSSToken *token
)
{
    return nssPKIObject_HasInstanceOnToken(&c->object, token);
}

NSS_IMPLEMENT PRIntn
nssCert_CountInstances (
  NSSCert *c
)
{
    return nssPKIObject_CountInstances(&c->object);
}

NSS_IMPLEMENT PRStatus
NSSCert_Destroy (
  NSSCert *c
)
{
    return nssCert_Destroy(c);
}

NSS_IMPLEMENT PRUint32
nssCert_Hash (
  NSSCert *c
)
{
    PRUint32 i;
    PRUint32 h = 0;
    for (i=0; i<c->issuer.size; i++)
	h = (h >> 28) ^ (h << 4) ^ ((unsigned char *)c->issuer.data)[i];
    for (i=0; i<c->serial.size; i++)
	h = (h >> 28) ^ (h << 4) ^ ((unsigned char *)c->serial.data)[i];
    return h;
}

NSS_IMPLEMENT NSSDER *
nssCert_GetEncoding (
  NSSCert *c
)
{
    if (c->encoding.size > 0 && c->encoding.data) {
	return &c->encoding;
    } else {
	return (NSSDER *)NULL;
    }
}

NSS_IMPLEMENT NSSDER *
nssCert_GetIssuer (
  NSSCert *c
)
{
    if (c->issuer.size > 0 && c->issuer.data) {
	return &c->issuer;
    } else {
	return (NSSDER *)NULL;
    }
}

NSS_IMPLEMENT NSSDER *
NSSCert_GetIssuer (
  NSSCert *c
)
{
    return nssCert_GetIssuer(c);
}

NSS_IMPLEMENT NSSDER *
nssCert_GetSerialNumber (
  NSSCert *c
)
{
    if (c->serial.size > 0 && c->serial.data) {
	return &c->serial;
    } else {
	return (NSSDER *)NULL;
    }
}

NSS_IMPLEMENT NSSDER *
NSSCert_GetSerialNumber (
  NSSCert *c
)
{
    return nssCert_GetSerialNumber(c);
}

NSS_IMPLEMENT NSSDER *
nssCert_GetSubject (
  NSSCert *c
)
{
    if (c->subject.size > 0 && c->subject.data) {
	return &c->subject;
    } else {
	return (NSSDER *)NULL;
    }
}

NSS_IMPLEMENT NSSItem *
nssCert_GetID (
  NSSCert *c
)
{
    if (c->id.size > 0 && c->id.data) {
	return &c->id;
    } else {
	return (NSSItem *)NULL;
    }
}

NSS_IMPLEMENT PRStatus
nssCert_SetNickname (
  NSSCert *c,
  NSSToken *tokenOpt,
  NSSUTF8 *nickname
)
{
    return nssPKIObject_SetNickname(&c->object, tokenOpt, nickname);
}

NSS_IMPLEMENT NSSUTF8 *
nssCert_GetNickname (
  NSSCert *c,
  NSSToken *tokenOpt
)
{
    return nssPKIObject_GetNickname(&c->object, tokenOpt);
}

NSS_IMPLEMENT NSSUTF8 *
NSSCert_GetNickname (
  NSSCert *c,
  NSSToken *tokenOpt
)
{
    return nssCert_GetNickname(c, tokenOpt);
}

NSS_IMPLEMENT NSSASCII7 *
nssCert_GetEmailAddress (
  NSSCert *c
)
{
    return c->email;
}

NSS_IMPLEMENT NSSUTF8 **
nssCert_GetNames (
  NSSCert *c,
  NSSUTF8 **rvOpt,
  PRUint32 rvMaxOpt,
  NSSArena *arenaOpt
)
{
    /* XXX need to go out to plugin for this */
    if (!rvOpt) {
	rvOpt = nss_ZNEWARRAY(arenaOpt, NSSUTF8 *, 2);
    }
    rvOpt[0] = nssUTF8_Duplicate("<not implemented>", arenaOpt);
    if (rvMaxOpt > 1) rvOpt[1] = NULL;
    return rvOpt;
}

NSS_IMPLEMENT NSSUTF8 **
NSSCert_GetNames (
  NSSCert *c,
  NSSUTF8 **rvOpt,
  PRUint32 rvMaxOpt,
  NSSArena *arenaOpt
)
{
    return nssCert_GetNames(c, rvOpt, rvMaxOpt, arenaOpt);
}

NSS_IMPLEMENT NSSUTF8 **
nssCert_GetIssuerNames (
  NSSCert *c,
  NSSUTF8 **rvOpt,
  PRUint32 rvMaxOpt,
  NSSArena *arenaOpt
)
{
    /* XXX need to go out to plugin for this */
    if (!rvOpt) {
	rvOpt = nss_ZNEWARRAY(arenaOpt, NSSUTF8 *, 2);
    }
    rvOpt[0] = nssUTF8_Duplicate("<not implemented>", arenaOpt);
    if (rvMaxOpt > 1) rvOpt[1] = NULL;
    return rvOpt;
}

NSS_IMPLEMENT NSSUTF8 **
NSSCert_GetIssuerNames (
  NSSCert *c,
  NSSUTF8 **rvOpt,
  PRUint32 rvMaxOpt,
  NSSArena *arenaOpt
)
{
    return nssCert_GetIssuerNames(c, rvOpt, rvMaxOpt, arenaOpt);
}

static nssCertDecoding *
nssCert_GetDecoding (
  NSSCert *c
)
{
    if (!c->decoding.data) {
	c->decoding.data = c->decoding.methods->decode(NULL, &c->encoding);
    }
    return &c->decoding;
}

NSS_IMPLEMENT void *
NSSCert_GetDecoding (
  NSSCert *c
)
{
    nssCertDecoding *dc;

    dc = nssCert_GetDecoding(c);
    if (dc) {
	return dc->data;
    }
    return (void *)NULL;
}

NSS_EXTERN NSSCertType
NSSCert_GetType (
  NSSCert *c
)
{
    return c->kind;
}

NSS_EXTERN NSSKeyPairType
nssCert_GetKeyType (
  NSSCert *c
)
{
    NSSKeyPairType keyType = NSSKeyPairType_Unknown;
    NSSPublicKey *bk = nssCert_GetPublicKey(c);

    if (bk) {
	keyType = nssPublicKey_GetKeyType(bk);
	nssPublicKey_Destroy(bk);
    }
    return keyType;
}

NSS_EXTERN NSSKeyPairType
NSSCert_GetKeyType (
  NSSCert *c
)
{
    return nssCert_GetKeyType(c);
}

NSS_IMPLEMENT NSSUsages *
nssCert_GetUsages (
  NSSCert *c,
  PRStatus *statusOpt
)
{
    PRStatus status;
    nssCertDecoding *dc = nssCert_GetDecoding(c);
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
nssCert_IsValidAtTime (
  NSSCert *c,
  NSSTime time,
  PRStatus *statusOpt
)
{
    PRStatus status;
    nssCertDecoding *dc = nssCert_GetDecoding(c);
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
nssCert_IsNewer (
  NSSCert *c1,
  NSSCert *c2,
  PRStatus *statusOpt
)
{
    nssCertDecoding *dc1 = nssCert_GetDecoding(c1);
    nssCertDecoding *dc2 = nssCert_GetDecoding(c2);
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
nssCert_IssuerAndSerialEqual (
  NSSCert *c1,
  NSSCert *c2
)
{
    return (nssItem_Equal(&c1->issuer, &c2->issuer, NULL) &&
            nssItem_Equal(&c1->serial, &c2->serial, NULL));
}

NSS_IMPLEMENT PRBool
nssCert_HasCANameInChain (
  NSSCert *c,
  NSSDER **rootCAs,
  PRUint32 rootCAsMaxOpt,
  NSSTime time,
  const NSSUsages *usages,
  NSSPolicies *policiesOpt
)
{
    NSSDER **caName;
    NSSCert **chain;
    NSSCert **cert;
    PRUint32 i;
    PRBool foundIt = PR_FALSE;

    chain = nssCert_BuildChain(c, time, usages, policiesOpt, 
                               NULL, 0, NULL, NULL);
    if (!chain) {
	return PR_FALSE;
    }
    /* XXX maybe in this case it is more appropriate to build the chain
     * one-at-a-time?  I don't think this is much of a hit
     */
    for (cert = chain; *cert; cert++) {
	for (caName = rootCAs, i=0; 
	     *caName && (rootCAsMaxOpt == 0 || i < rootCAsMaxOpt);
	     caName++, i++)
	{
	    if (NSSItem_Equal(&(*cert)->issuer, *caName, NULL)) {
		foundIt = PR_TRUE;
		break;
	    }
	}
    }
    nssCertArray_Destroy(chain);
    return foundIt;
}

NSS_IMPLEMENT void
nssCert_SetVolatileDomain (
  NSSCert *c,
  NSSVolatileDomain *vd
)
{
    nssPKIObject_SetVolatileDomain(&c->object, vd);
}

NSS_IMPLEMENT NSSVolatileDomain **
nssCert_GetVolatileDomains(
  NSSCert *c,
  NSSVolatileDomain **vdsOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt,
  PRStatus *statusOpt
)
{
    return nssPKIObject_GetVolatileDomains(&c->object, vdsOpt,
                                           maximumOpt, arenaOpt, statusOpt);
}

NSS_IMPLEMENT NSSTrustDomain *
nssCert_GetTrustDomain (
  NSSCert *c
)
{
    return c->object.td;
}

NSS_IMPLEMENT NSSTrustDomain *
NSSCert_GetTrustDomain (
  NSSCert *c
)
{
    return nssCert_GetTrustDomain(c);
}

NSS_IMPLEMENT NSSToken **
nssCert_GetTokens (
  NSSCert *c,
  NSSToken **rvOpt,
  PRUint32 rvMaxOpt,
  PRStatus *statusOpt
)
{
    return nssPKIObject_GetTokens(&c->object, rvOpt, rvMaxOpt, statusOpt);
}

NSS_IMPLEMENT NSSToken **
NSSCert_GetTokens (
  NSSCert *c,
  NSSToken **rvOpt,
  PRUint32 rvMaxOpt,
  PRStatus *statusOpt
)
{
    return nssCert_GetTokens(c, rvOpt, rvMaxOpt, statusOpt);
}

NSS_IMPLEMENT NSSSlot *
NSSCert_GetSlot (
  NSSCert *c,
  PRStatus *statusOpt
)
{
    return (NSSSlot *)NULL;
}

NSS_IMPLEMENT NSSModule *
NSSCert_GetModule (
  NSSCert *c,
  PRStatus *statusOpt
)
{
    return (NSSModule *)NULL;
}

NSS_IMPLEMENT nssCryptokiObject *
nssCert_FindInstanceForAlgorithm (
  NSSCert *c,
  NSSAlgNParam *ap
)
{
    return nssPKIObject_FindInstanceForAlgorithm(&c->object, ap);
}

NSS_IMPLEMENT PRStatus
nssCert_DeleteStoredObject (
  NSSCert *c,
  NSSCallback *uhh
)
{
    return nssPKIObject_DeleteStoredObject(&c->object, uhh, PR_TRUE);
}

NSS_IMPLEMENT PRStatus
NSSCert_DeleteStoredObject (
  NSSCert *c,
  NSSCallback *uhh
)
{
    return nssCert_DeleteStoredObject(c, uhh);
}

NSS_IMPLEMENT PRStatus
nssCert_CopyToToken (
  NSSCert *c,
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
    instance = nssToken_ImportCert(token, rwSession,
                                   c->kind, NULL, nicknameOpt,
                                   &c->encoding, &c->issuer, 
                                   &c->subject, &c->serial,
                                   c->email, PR_TRUE);
    nssSession_Destroy(rwSession);
    if (!instance) {
	return PR_FAILURE;
    }
    status = nssPKIObject_AddInstance(&c->object, instance);
    if (status == PR_FAILURE) {
	return PR_FAILURE;
    }
    return PR_SUCCESS;
}

static PRStatus
validate_and_discover_trust (
  NSSCert *c,
  NSSTime time,
  NSSUsage usage,
  NSSPolicies *policiesOpt,
  PRBool asCA,
  PRBool *trusted
)
{
    PRStatus status;
    NSSUsages *certUsages;
    PRBool valid;

    *trusted = PR_FALSE;

    /* First verify the time is within the cert's validity period */
    if (!nssCert_IsValidAtTime(c, time, &status)) {
	if (status == PR_SUCCESS) {
	    /* The function was successful, so we own the error */
	    nss_SetError(NSS_ERROR_CERTIFICATE_NOT_VALID_AT_TIME);
	} /* else the function failed and owns the error */
	return PR_FAILURE;
    }

    /* See if the cert is trusted, overrides cert's usage */
    if ((asCA && c->trust.trustedUsages.ca & usage) ||
        c->trust.trustedUsages.peer & usage) 
    {
	*trusted = PR_TRUE;
	return PR_SUCCESS;
    }

    /* Verify the cert is capable of the desired set of usages */
    certUsages = nssCert_GetUsages(c, &status);
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
validate_chain_link (
  NSSCert *subjectCert,
  NSSCert *issuerCert,
  void **vData
)
{
    PRStatus status;
    nssCertDecoding *dcs;

    dcs = nssCert_GetDecoding(subjectCert);
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
cert_in_chain_revoked (
  NSSCert **chain,
  PRStatus *status
)
{
    NSSCert **cp;
    nssCRL *crl;
    for (cp = chain; *cp; cp++) {
	crl = nssTrustDomain_FindCRLBySubject(td, subject);
	if (crl) {
	    status = nssCRL_FindCert(*cp);
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
nssCert_Validate (
  NSSCert *c,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt
)
{
    PRStatus status;
    PRBool asCA;
    PRBool trusted = PR_FALSE;
    PRBool atRoot = PR_FALSE;
    NSSCert **cp, **chain;
    NSSCert *subjectCert = NULL;
    NSSCert *issuerCert = NULL;
    NSSUsage usage;
    void *vData = NULL;

    /* Build the chain (this cert will be first) */
    chain = nssCert_BuildChain(c, time, usages, policiesOpt,
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
    nssCertArray_Destroy(chain);
    return status;
}

NSS_IMPLEMENT PRStatus
NSSCert_Validate (
  NSSCert *c,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt
)
{
    return nssCert_Validate(c, time, usages, policiesOpt);
}

#if 0
struct NSSValidationErrorStr
{
  NSSCert *c;
  NSSUsage usage;
  NSSError error;
  PRUint32 level;
};
#endif

NSS_IMPLEMENT void ** /* void *[] */
NSSCert_ValidateCompletely (
  NSSCert *c,
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
NSSCert_ValidateAndDiscoverUsagesAndPolicies (
  NSSCert *c,
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
nssCert_GetTrustedUsages (
  NSSCert *c,
  NSSUsages *usagesOpt
)
{
    PRBool freeIt = PR_FALSE;
    if (!usagesOpt) {
	usagesOpt = nss_ZNEW(NULL, NSSUsages);
	if (!usagesOpt) {
	    return (NSSUsages *)NULL;
	}
	freeIt = PR_TRUE;
    }
    *usagesOpt = c->trust.trustedUsages;
    return usagesOpt;
}

NSS_IMPLEMENT NSSUsages *
NSSCert_GetTrustedUsages (
  NSSCert *c,
  NSSUsages *usagesOpt
)
{
    return nssCert_GetTrustedUsages(c, usagesOpt);
}

NSS_IMPLEMENT PRBool
nssCert_IsTrustedForUsages (
  NSSCert *c,
  NSSUsages *usages,
  PRStatus *statusOpt
)
{
    if (c->trust.trustedUsages.ca == usages->ca &&
        c->trust.trustedUsages.peer == usages->peer)
    {
	return PR_TRUE;
    } else {
	return PR_FALSE;
    }
}

NSS_IMPLEMENT PRStatus
nssCert_SetTrustedUsages (
  NSSCert *c,
  NSSUsages *usages
)
{
    NSSTrustDomain *td;
    if (c->trust.trustedUsages.ca == usages->ca &&
        c->trust.trustedUsages.peer == usages->peer) 
    {
	/* already set to desired value */
	return PR_SUCCESS;
    }
    /* XXX lock here? */
    /* set the new trusted usages */
    c->trust.trustedUsages = *usages;
    /* clear the not trusted usages of all bits from the new trust */
    c->trust.notTrustedUsages.ca &= usages->ca;
    c->trust.notTrustedUsages.peer &= usages->peer;
    /* reflect the change in the db */
    td = nssCert_GetTrustDomain(c);
    return nssTrustDomain_SetCertTrust(td, c, &c->trust);
}

NSS_IMPLEMENT PRStatus
NSSCert_SetTrustedUsages (
  NSSCert *c,
  NSSUsages *usages
)
{
    return nssCert_SetTrustedUsages(c, usages);
}

NSS_IMPLEMENT NSSDER *
nssCert_Encode (
  NSSCert *c,
  NSSDER *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssItem_Duplicate((NSSItem *)&c->encoding, arenaOpt, rvOpt);
}

NSS_IMPLEMENT NSSDER *
NSSCert_Encode (
  NSSCert *c,
  NSSDER *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssCert_Encode(c, rvOpt, arenaOpt);
}

static NSSCert *
filter_subject_certs_for_id (
  NSSCert **subjectCerts, 
  void *id
)
{
    NSSCert **si;
    NSSCert *rvCert = NULL;
    /* walk the subject certs */
    for (si = subjectCerts; *si; si++) {
	nssCertDecoding *dcp = nssCert_GetDecoding(*si);
	if (dcp->methods->isMyIdentifier(dcp->data, id)) {
	    /* this cert has the correct identifier */
	    rvCert = nssCert_AddRef(*si);
	    break;
	}
    }
    return rvCert;
}

static NSSCert *
find_cert_issuer (
  NSSCert *c,
  NSSTime time,
  const NSSUsages *usagesOpt,
  NSSPolicies *policiesOpt
)
{
    NSSCert **issuers = NULL;
    NSSCert *issuer = NULL;
    NSSTrustDomain *td;
    NSSVolatileDomain *vd;
    /* XXX what to do with multiple vds? */
    nssCert_GetVolatileDomains(c, &vd, 1, NULL, NULL);
    td = nssCert_GetTrustDomain(c);
    if (vd) {
	issuers = nssVolatileDomain_FindCertsBySubject(vd, &c->issuer,
	                                               NULL, 0, NULL);
	nssVolatileDomain_Destroy(vd);
    } else {
	issuers = nssTrustDomain_FindCertsBySubject(td, &c->issuer,
                                                    NULL, 0, NULL);
    }
    if (issuers) {
	nssCertDecoding *dc = NULL;
	void *issuerID = NULL;
	dc = nssCert_GetDecoding(c);
	if (dc) {
	    issuerID = dc->methods->getIssuerIdentifier(dc->data);
	}
	if (issuerID) {
	    issuer = filter_subject_certs_for_id(issuers, issuerID);
	    dc->methods->freeIdentifier(issuerID);
	} else {
	    issuer = nssCertArray_FindBestCert(issuers, time,
	                                       usagesOpt, policiesOpt);
	}
	nssCertArray_Destroy(issuers);
    }
    return issuer;
}

/* XXX review based on CERT_FindCertIssuer
 * this function is not using the authCertIssuer field as a fallback
 * if authority key id does not exist
 */
NSS_IMPLEMENT NSSCert **
nssCert_BuildChain (
  NSSCert *c,
  NSSTime time,
  const NSSUsages *usagesOpt,
  NSSPolicies *policiesOpt,
  NSSCert **rvOpt,
  PRUint32 rvLimit,
  NSSArena *arenaOpt,
  PRStatus *statusOpt
)
{
    PRStatus status;
    PRUint32 i, size;
    NSSCert **rvChain;
    NSSTrustDomain *td;
    NSSUsages usages = { 0 };

    td = NSSCert_GetTrustDomain(c);
    if (statusOpt) *statusOpt = PR_SUCCESS;

    if (rvLimit) {
	size = rvLimit;
    } else {
	size = 4;
    }
    rvChain = nss_ZNEWARRAY(arenaOpt, NSSCert *, size + 1);
    if (!rvChain) {
	if (statusOpt) *statusOpt = PR_FAILURE;
	return (NSSCert **)NULL;
    }
    i = 0; /* begin the chain with the cert passed in */
    rvChain[i++] = nssCert_AddRef(c);
    /* going from peer to CA */
    if (usagesOpt) {
	usages.ca = usagesOpt->peer;
	usagesOpt = &usages;
    }
    /* walk the chain */
    while (!nssItem_Equal(&c->subject, &c->issuer, &status)) {
	c = find_cert_issuer(c, time, usagesOpt, policiesOpt);
	if (c) {
	    rvChain[i++] = c;
	    if (rvLimit > 0 && i == rvLimit) {
		/* reached the limit of certs asked for */
		break;
	    }
	    if (i == size) {
		/* unlimited search, but array is full */
		NSSCert **test;
		size *= 2;
		test = nss_ZREALLOCARRAY(rvChain, NSSCert *, size + 1);
		if (!test) {
		    nssCertArray_Destroy(rvChain);
		    if (statusOpt) *statusOpt = PR_FAILURE;
		    return (NSSCert **)NULL;
		}
		rvChain = test;
	    }
	} else {
	    nss_SetError(NSS_ERROR_CERTIFICATE_ISSUER_NOT_FOUND);
	    if (statusOpt) *statusOpt = PR_FAILURE;
	    break;
	}
    }
    return rvChain;
}

NSS_IMPLEMENT NSSCert **
NSSCert_BuildChain (
  NSSCert *c,
  NSSTime time,
  const NSSUsages *usagesOpt,
  NSSPolicies *policiesOpt,
  NSSCert **rvOpt,
  PRUint32 rvLimit, /* zero for no limit */
  NSSArena *arenaOpt,
  PRStatus *statusOpt
)
{
    return nssCert_BuildChain(c, time, usagesOpt, policiesOpt,
                              rvOpt, rvLimit, arenaOpt, statusOpt);
}

NSS_IMPLEMENT NSSItem *
NSSCert_Encrypt (
  NSSCert *c,
  const NSSAlgNParam *apOpt,
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
NSSCert_Verify (
  NSSCert *c,
  const NSSAlgNParam *apOpt,
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
NSSCert_VerifyRecover (
  NSSCert *c,
  const NSSAlgNParam *apOpt,
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
nssCert_WrapSymKey (
  NSSCert *c,
  const NSSAlgNParam *ap,
  NSSSymKey *keyToWrap,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    NSSPublicKey *pubKey;
    NSSItem *wrap;

    /* XXX do some validation */

    pubKey = nssCert_GetPublicKey(c);
    if (!pubKey) {
	return (NSSItem *)NULL;
    }

    wrap = nssPublicKey_WrapSymKey(pubKey, ap, keyToWrap,
                                   uhh, rvOpt, arenaOpt);
    nssPublicKey_Destroy(pubKey);
    return wrap;
}

NSS_IMPLEMENT NSSItem *
NSSCert_WrapSymKey (
  NSSCert *c,
  const NSSAlgNParam *ap,
  NSSSymKey *keyToWrap,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt,
  NSSCallback *uhh,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    return nssCert_WrapSymKey(c, ap, keyToWrap,
                              time, usages, policiesOpt,
                              uhh, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSCryptoContext *
NSSCert_CreateCryptoContext (
  NSSCert *c,
  const NSSAlgNParam *apOpt,
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
nssCert_GetPublicKey (
  NSSCert *c
)
{
    PRStatus status;
    NSSTrustDomain *td = nssCert_GetTrustDomain(c);
    NSSVolatileDomain *vd;
    /* XXX multiple vds? */
    nssCert_GetVolatileDomains(c, &vd, 1, NULL, NULL);

    if (!c->bk && c->id.size > 0) {
	/* first try looking for a persistent object */
	c->bk = nssTrustDomain_FindPublicKeyByID(td, &c->id);
    }
    if (!c->bk) {
	NSSOIDTag keyAlg;
	NSSBitString keyBits;
	nssCertDecoding *dc = nssCert_GetDecoding(c);
	/* create an ephemeral pubkey object, either in the cert's
	 * volatile domain (if it exists), or as a standalone object
	 * that will be destroyed with the cert
	 */
	status = dc->methods->getPublicKeyInfo(dc->data, &keyAlg, &keyBits);
	if (status == PR_SUCCESS) {
	    c->bk = nssPublicKey_CreateFromInfo(td, vd, keyAlg, &keyBits);
	}
    }
    nssVolatileDomain_Destroy(vd);
    if (c->bk) {
	return nssPublicKey_AddRef(c->bk);
    }
    return (NSSPublicKey *)NULL;
}

NSS_IMPLEMENT NSSPublicKey *
NSSCert_GetPublicKey (
  NSSCert *c
)
{
    return nssCert_GetPublicKey(c);
}

NSS_IMPLEMENT NSSPrivateKey *
nssCert_FindPrivateKey (
  NSSCert *c,
  NSSCallback *uhh
)
{
    NSSTrustDomain *td = nssCert_GetTrustDomain(c);
    if (c->id.size > 0) {
	return nssTrustDomain_FindPrivateKeyByID(td, &c->id);
    } else {
	return (NSSPrivateKey *)NULL;
    }
}

NSS_IMPLEMENT NSSPrivateKey *
NSSCert_FindPrivateKey (
  NSSCert *c,
  NSSCallback *uhh
)
{
    return nssCert_FindPrivateKey(c, uhh);
}

NSS_IMPLEMENT PRBool
nssCert_IsPrivateKeyAvailable (
  NSSCert *c,
  NSSCallback *uhh,
  PRStatus *statusOpt
)
{
    NSSPrivateKey *vk;
    /* XXX would be nice to "ping" the tokens w/o actually building the key */
    vk = nssCert_FindPrivateKey(c, uhh);
    if (vk) {
	nssPrivateKey_Destroy(vk);
	return PR_TRUE;
    } else {
	return PR_FALSE;
    }
}

NSS_IMPLEMENT PRBool
NSSCert_IsPrivateKeyAvailable (
  NSSCert *c,
  NSSCallback *uhh,
  PRStatus *statusOpt
)
{
    return nssCert_IsPrivateKeyAvailable(c, uhh, statusOpt);
}

NSS_IMPLEMENT PRBool
NSSUserCert_IsStillPresent (
  NSSUserCert *uc,
  PRStatus *statusOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return PR_FALSE;
}

NSS_IMPLEMENT NSSItem *
NSSUserCert_Decrypt (
  NSSUserCert *uc,
  const NSSAlgNParam *apOpt,
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
NSSUserCert_Sign (
  NSSUserCert *uc,
  const NSSAlgNParam *apOpt,
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
NSSUserCert_SignRecover (
  NSSUserCert *uc,
  const NSSAlgNParam *apOpt,
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

NSS_IMPLEMENT NSSSymKey *
NSSUserCert_UnwrapSymKey (
  NSSUserCert *uc,
  const NSSAlgNParam *apOpt,
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

NSS_IMPLEMENT NSSSymKey *
NSSUserCert_DeriveSymKey (
  NSSUserCert *uc, /* provides private key */
  NSSCert *c, /* provides public key */
  const NSSAlgNParam *apOpt,
  NSSSymKeyType targetSymKeyType,
  PRUint32 keySizeOpt, /* zero for best allowed */
  NSSOperations operations,
  NSSCallback *uhh
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

