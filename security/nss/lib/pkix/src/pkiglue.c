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
static const char CVS_ID[] = "@(#) $Source$ $Revision$ $Date$ $Name$";
#endif /* DEBUG */

#ifndef NSSDEV_H
#include "nssdev.h"
#endif /* NSSDEV_H */

#ifndef NSSASN1_H
#include "nssasn1.h"
#endif /* NSSASN1_H */

#ifndef PKI_H
#include "pki.h"
#endif /* PKI_H */

#ifndef PKIX_H
#include "pkix.h"
#endif /* PKIX_H */

#include "nss.h"

static void *
pkix_Decode (
  NSSArena *arenaOpt,
  NSSBER *encoding
)
{
    NSSPKIXCertificate *pkixCert;

    nss_HoldErrorStack();

    pkixCert = nssPKIXCertificate_Decode(arenaOpt, encoding);

    nss_ResumeErrorStack();

    return (void *)pkixCert;
}

static NSSBER *
pkix_GetSubject (
  void *cert
)
{
    NSSPKIXCertificate *pkixCert = (NSSPKIXCertificate *)cert;
    NSSPKIXTBSCertificate *tbsCert;
    NSSPKIXName *subject;
    NSSBER *subjectBER = NULL;

    nss_HoldErrorStack();

    /*
     * cert->tbsCert
     */
    tbsCert = nssPKIXCertificate_GetTBSCertificate(pkixCert);
    if (!tbsCert) {
	goto finish;
    }
    /*
     * tbsCert->subject
     */
    subject = nssPKIXTBSCertificate_GetSubject(tbsCert);
    if (!subject) {
	goto finish;
    }
    /*
     * subject->der
     */
    subjectBER = nssPKIXName_Encode(subject);

finish:
    nss_ResumeErrorStack();
    return subjectBER;
}

static NSSBER *
pkix_GetIssuer (
  void *cert
)
{
    NSSPKIXCertificate *pkixCert = (NSSPKIXCertificate *)cert;
    NSSPKIXTBSCertificate *tbsCert;
    NSSPKIXName *issuer;
    NSSBER *issuerBER = NULL;

    nss_HoldErrorStack();

    /*
     * cert->tbsCert
     */
    tbsCert = nssPKIXCertificate_GetTBSCertificate(pkixCert);
    if (!tbsCert) {
	goto finish;
    }
    /*
     * tbsCert->issuer
     */
    issuer = nssPKIXTBSCertificate_GetIssuer(tbsCert);
    if (!issuer) {
	goto finish;
    }
    /*
     * issuer->der
     */
    issuerBER = nssPKIXName_Encode(issuer);

finish:
    nss_ResumeErrorStack();
    return issuerBER;
}

static NSSBER *
pkix_GetSerialNumber (
  void *cert
)
{
    NSSPKIXCertificate *pkixCert = (NSSPKIXCertificate *)cert;
    NSSPKIXTBSCertificate *tbsCert;
    NSSBER *snBER;

    nss_HoldErrorStack();

    /*
     * cert->tbsCert
     */
    tbsCert = nssPKIXCertificate_GetTBSCertificate(pkixCert);
    if (!tbsCert) {
	goto finish;
    }
    /*
     * tbsCert->serialNumber
     */
    snBER = nssPKIXTBSCertificate_GetSerialNumber(tbsCert);

finish:
    nss_ResumeErrorStack();
    return snBER;
}

static NSSASCII7 *
pkix_GetEmailAddress (
  void *cert
)
{
    return NULL;
}

static PRStatus
pkix_GetValidityPeriod (
  void *cert,
  NSSTime *notBefore, 
  NSSTime *notAfter
)
{
    PRStatus status;
    NSSPKIXCertificate *pkixCert = (NSSPKIXCertificate *)cert;
    NSSPKIXTBSCertificate *tbsCert;
    NSSPKIXValidity *validity;
    NSSPKIXTime *pkixTime;

    nss_HoldErrorStack();

    /*
     * cert->tbsCert
     */
    tbsCert = nssPKIXCertificate_GetTBSCertificate(pkixCert);
    if (!tbsCert) {
	goto loser;
    }
    /*
     * tbsCert->validity
     */
    validity = nssPKIXTBSCertificate_GetValidity(tbsCert);
    if (!validity) {
	goto loser;
    }
    /*
     * validity->notBefore
     */
    pkixTime = nssPKIXValidity_GetNotBefore(validity);
    if (!pkixTime) {
	goto loser;
    }
    *notBefore = nssPKIXTime_GetTime(pkixTime, &status);
    if (status == PR_FAILURE) {
	goto loser;
    }
    /*
     * validity->notAfter
     */
    pkixTime = nssPKIXValidity_GetNotAfter(validity);
    if (!pkixTime) {
	goto loser;
    }
    *notAfter = nssPKIXTime_GetTime(pkixTime, &status);
    if (status == PR_FAILURE) {
	goto loser;
    }

    nss_ResumeErrorStack();
    return PR_SUCCESS;
loser:
    nss_ResumeErrorStack();
    return PR_FAILURE;
}

/*
 * restrict the set of usages based on the value of the key usage
 * extension
 */
static void
get_usages_from_key_usage (
  NSSPKIXKeyUsage *keyUsage,
  NSSUsages *usages
)
{
    NSSPKIXKeyUsageValue ku;
    ku = nssPKIXKeyUsage_GetValue(keyUsage);

    if ((ku & NSSPKIXKeyUsage_DigitalSignature) == 0) {
	usages->peer &= ~(NSSUsage_EmailSigner |
	                  NSSUsage_CodeSigner |
	                  NSSUsage_StatusResponder);
    }
    if ((ku & (NSSPKIXKeyUsage_DigitalSignature |
               NSSPKIXKeyUsage_KeyAgreement)) == 0)
    {
	/* XXX add key type as parameter */
	usages->peer &= ~NSSUsage_SSLClient;
    }
#if 0
    if ((ku & NSSPKIXKeyUsage_NonRepudiation) == 0) {
    }
#endif
    if ((ku & (NSSPKIXKeyUsage_KeyEncipherment |
               NSSPKIXKeyUsage_KeyAgreement)) == 0) 
    {
	/* XXX ku_key_agreement_or_encipherment */
	/* XXX add key type as parameter */
	usages->peer &= ~(NSSUsage_SSLServer | NSSUsage_EmailRecipient);
    }
#if 0
    if ((ku & NSSPKIXKeyUsage_DataEncipherment) == 0) {
    }
#endif
    if ((ku & NSSPKIXKeyUsage_KeyCertSign) == 0) {
	usages->ca = 0;
    }
    if ((ku & NSSPKIXKeyUsage_CRLSign) == 0) {
	usages->peer &= ~NSSUsage_CRLSigner;
    }
#if 0
    if ((ku & NSSPKIXKeyUsage_EncipherOnly) == 0) {
    }
    if ((ku & NSSPKIXKeyUsage_DecipherOnly) == 0) {
    }
#endif
}

/*
 * restrict the set of usages based on the value of the basic constraints
 * extension
 */
static void
get_usages_from_basic_constraints (
  NSSPKIXBasicConstraints *basicConstraints,
  NSSUsages *usages
)
{
    if (!nssPKIXBasicConstraints_IsCA(basicConstraints)) {
	usages->ca = 0;
    }
}

#if 0
/*
 * restrict the set of usages based on the value of the extended key usage
 * extension
 */
static void
get_usages_from_ext_key_usage (
  NSSPKIXExtendedKeyUsage *extKeyUsage,
  NSSUsages *usages
)
{
}
#endif

/*
 * restrict the set of usages based on the value of the netscape cert type
 * extension
 */
static void
get_usages_from_ns_cert_type (
  NSSPKIXnetscapeCertType *nsCertType,
  NSSUsages *usages
)
{
    NSSPKIXnetscapeCertTypeValue nsct;
    nsct = nssPKIXnetscapeCertType_GetValue(nsCertType);
    if ((nsct & NSSPKIXnetscapeCertType_SSLClient) == 0) {
	usages->peer &= ~NSSUsage_SSLClient;
    }
    if ((nsct & NSSPKIXnetscapeCertType_SSLServer) == 0) {
	usages->peer &= ~NSSUsage_SSLServer;
    }
    if ((nsct & NSSPKIXnetscapeCertType_SSLCA) == 0) {
	usages->ca &= ~(NSSUsage_SSLClient | NSSUsage_SSLServer);
    }
    if ((nsct & NSSPKIXnetscapeCertType_Email) == 0) {
	usages->peer &= ~(NSSUsage_EmailSigner | NSSUsage_EmailRecipient);
    }
    if ((nsct & NSSPKIXnetscapeCertType_EmailCA) == 0) {
	usages->ca &= ~(NSSUsage_EmailSigner | NSSUsage_EmailRecipient);
    }
    if ((nsct & NSSPKIXnetscapeCertType_ObjectSigning) == 0) {
	usages->peer &= ~NSSUsage_CodeSigner;
    }
    if ((nsct & NSSPKIXnetscapeCertType_ObjectSigningCA) == 0) {
	usages->ca &= ~NSSUsage_CodeSigner;
    }
}

static PRStatus
pkix_GetUsages (
  void *cert,
  NSSUsages *rvUsages
)
{
    NSSPKIXCertificate *pkixCert = (NSSPKIXCertificate *)cert;
    NSSPKIXTBSCertificate *tbsCert;
    NSSPKIXExtensions *extensions;
    NSSPKIXBasicConstraints *basicConstraints;
    NSSPKIXKeyUsage *keyUsage;
    NSSPKIXnetscapeCertType *nsCertType;
    NSSUsages usages;

    nss_HoldErrorStack();

    /* start with everything */
    usages.ca = NSSUsage_All;
    usages.peer = NSSUsage_All;
    /*
     * cert->tbsCert
     */
    tbsCert = nssPKIXCertificate_GetTBSCertificate(pkixCert);
    if (!tbsCert) {
	goto loser;
    }
    /*
     * tbsCert->extensions
     */
    extensions = nssPKIXTBSCertificate_GetExtensions(tbsCert);
    if (!extensions) {
	goto loser;
    }
    /*
     * extensions[keyUsage]
     */
    keyUsage = nssPKIXExtensions_GetKeyUsage(extensions);
    if (keyUsage) {
	get_usages_from_key_usage(keyUsage, &usages);
    }
    /*
     * extensions[basicConstraints]
     */
    basicConstraints = nssPKIXExtensions_GetBasicConstraints(extensions);
    if (basicConstraints) {
	get_usages_from_basic_constraints(basicConstraints, &usages);
    }
    /*
     * extensions[nsCertType]
     */
    nsCertType = nssPKIXExtensions_GetNetscapeCertType(extensions);
    if (nsCertType) {
	get_usages_from_ns_cert_type(nsCertType, &usages);
    }
    *rvUsages = usages;

    nss_ResumeErrorStack();
    return PR_SUCCESS;
loser:
    nss_ResumeErrorStack();
    return PR_FAILURE;
}

static NSSPolicies *
pkix_GetPolicies (
  void *cert
)
{
    return NULL;
}

static PRStatus
pkix_GetPublicKeyInfo (
  void *cert,
  NSSOID **keyType,
  NSSBitString *keyData
)
{
    NSSPKIXCertificate *pkixCert = (NSSPKIXCertificate *)cert;
    NSSPKIXTBSCertificate *tbsCert;
    NSSPKIXSubjectPublicKeyInfo *spki;
    NSSPKIXAlgorithmIdentifier *algID;
    NSSBitString *spk;

    nss_HoldErrorStack();

    /*
     * cert->tbsCert
     */
    tbsCert = nssPKIXCertificate_GetTBSCertificate(pkixCert);
    if (!tbsCert) {
	goto loser;
    }
    /*
     * tbsCert->subjectPublicKeyInfo
     */
    spki = nssPKIXTBSCertificate_GetSubjectPublicKeyInfo(tbsCert);
    if (!spki) {
	goto loser;
    }
    /*
     * subjectPublicKeyInfo->algorithm
     */
    algID = nssPKIXSubjectPublicKeyInfo_GetAlgorithm(spki);
    if (!algID) {
	goto loser;
    }
    /*
     * algorithm->algorithm (OID)
     */
    *keyType = nssPKIXAlgorithmIdentifier_GetAlgorithm(algID);
    if (!*keyType) {
	goto loser;
    }
    /* XXX parameters ? */
    /*
     * subjectPublicKeyInfo->subjectPublicKey
     */
    spk = nssPKIXSubjectPublicKeyInfo_GetSubjectPublicKey(spki);
    if (!spk) {
	goto loser;
    }
    *keyData = *spk;

    nss_ResumeErrorStack();
    return PR_SUCCESS;
loser:
    nss_ResumeErrorStack();
    return PR_FAILURE;
}

struct pkix_issuer_id_str {
  NSSArena *arena;
  NSSPKIXAuthorityKeyIdentifier *authKeyID;
};

static void *
pkix_GetIssuerIdentifier (
  void *cert
)
{
    NSSArena *arena = NULL;
    NSSPKIXTBSCertificate *tbsCert;
    NSSPKIXExtensions *extns;
    NSSPKIXCertificate *pkixCert = (NSSPKIXCertificate *)cert;
    NSSPKIXAuthorityKeyIdentifier *authKeyID;
    struct pkix_issuer_id_str *issuer_id = NULL;

    nss_HoldErrorStack();

    /*
     * cert->tbsCert
     */
    tbsCert = nssPKIXCertificate_GetTBSCertificate(pkixCert);
    if (!tbsCert) {
	goto loser;
    }
    /*
     * tbsCert->extensions
     */
    extns = nssPKIXTBSCertificate_GetExtensions(tbsCert);
    if (!extns) {
	if (NSS_GetError() == NSS_ERROR_INVALID_BER) {
	    goto loser;
	} else {
	    /* no extensions */
	    nss_ResumeErrorStack();
	    return (void *)NULL;
	}
    }

    /*
     * extensions[authorityKeyIdentifier]
     */
    authKeyID = nssPKIXExtensions_GetAuthorityKeyIdentifier(extns);
    if (!authKeyID) {
	if (NSS_GetError() == NSS_ERROR_INVALID_BER) {
	    goto loser;
	} else {
	    /* authKeyID extension not present XXX should check code */
	    nss_ResumeErrorStack();
	    return (void *)NULL;
	}
    }

    arena = NSSArena_Create();
    if (!arena) {
	goto loser;
    }

    issuer_id = nss_ZNEW(arena, struct pkix_issuer_id_str);
    if (!issuer_id) {
	goto loser;
    }

    issuer_id->arena = arena;
    issuer_id->authKeyID = nssPKIXAuthorityKeyIdentifier_Duplicate(authKeyID,
                                                                   arena);

    nss_ResumeErrorStack();
    return (void *)issuer_id;
loser:
    if (arena) {
	NSSArena_Destroy(arena);
    }
    nss_ResumeErrorStack();
    return (void *)NULL;
}

static PRBool
pkix_IsMyIdentifier (
  void *cert,
  void *id
)
{
    NSSPKIXTBSCertificate *tbsCert;
    NSSPKIXExtensions *extns;
    NSSPKIXCertificate *pkixCert = (NSSPKIXCertificate *)cert;
    NSSPKIXKeyIdentifier *skID, *akID;
    struct pkix_issuer_id_str *iid = (struct pkix_issuer_id *)id;

    nss_HoldErrorStack();

    /*
     * cert->tbsCert
     */
    tbsCert = nssPKIXCertificate_GetTBSCertificate(pkixCert);
    if (!tbsCert) {
	goto loser;
    }
    /*
     * tbsCert->extensions
     */
    extns = nssPKIXTBSCertificate_GetExtensions(tbsCert);
    if (!extns) {
	if (NSS_GetError() == NSS_ERROR_INVALID_BER) {
	    goto loser;
	} else {
	    nss_ResumeErrorStack();
	    return (void *)NULL;
	}
    }
    /*
     * extensions[subjectKeyIdentifier]
     */
    skID = nssPKIXExtensions_GetSubjectKeyIdentifier(extns);
    if (!skID) {
	if (NSS_GetError() == NSS_ERROR_INVALID_BER) {
	    goto loser;
	}
    }

    akID = nssPKIXAuthorityKeyIdentifier_GetKeyIdentifier(iid->authKeyID);
    if (akID) {
	return NSSItem_Equal(skID, akID, NULL);
    }
    /* XXX under construction */
loser:
    nss_ResumeErrorStack();
    return PR_FALSE;
}

static void 
pkix_FreeIdentifier (
  void *id
)
{
    struct pkix_issuer_id_str *iid = (struct pkix_issuer_id *)id;

    nss_HoldErrorStack();
    NSSArena_Destroy(iid->arena);
    nss_ResumeErrorStack();
}

struct nss_pkix_validation_data_str 
{
  PRInt32 pathLen;
};

static void *
pkix_StartChainValidation (
  void
)
{
    struct nss_pkix_validation_data_str *validationData;

    validationData = nss_ZNEW(NULL, struct nss_pkix_validation_data_str);
    if (!validationData) {
	return NULL;
    }

    return (void *)validationData;
}

/* XXX */
#define NSSPKIXBasicConstraints_UNLIMITED_PATH_CONSTRAINT -2

static PRStatus
check_basic_constraints (
  NSSPKIXCertificate *cert,
  struct nss_pkix_validation_data_str *validationData
)
{
    NSSPKIXTBSCertificate *tbsCert;
    NSSPKIXExtensions *extensions;
    NSSPKIXBasicConstraints *bc;

    /*
     * cert->tbsCert
     */
    tbsCert = nssPKIXCertificate_GetTBSCertificate(cert);
    if (!tbsCert) {
	return PR_FAILURE;
    }
    /*
     * tbsCert->extensions
     */
    extensions = nssPKIXTBSCertificate_GetExtensions(tbsCert);
    if (!extensions) {
	if (NSS_GetError() == NSS_ERROR_INVALID_BER) {
	    return PR_FAILURE;
	} else {
	    goto done;
	}
    }
    /*
     * extensions[basicConstraints]
     */
    bc = nssPKIXExtensions_GetBasicConstraints(extensions);
    if (bc) {
	PRInt32 plc;
	if (!nssPKIXBasicConstraints_IsCA(bc)) {
	    nss_SetError(NSS_ERROR_INVALID_CERTIFICATE);
	    return PR_FAILURE;
	}
	plc = nssPKIXBasicConstraints_GetPathLengthConstraint(bc);
	if (plc != NSSPKIXBasicConstraints_UNLIMITED_PATH_CONSTRAINT &&
	    plc <= validationData->pathLen) 
	{
	    nss_SetError(NSS_ERROR_CERTIFICATE_EXCEEDED_PATH_LENGTH_CONSTRAINT);
	    return PR_FAILURE;
	}
    }
done:
    validationData->pathLen++;
    return PR_SUCCESS;
}

static PRStatus
verify_signature (
  NSSPKIXCertificate *cert,
  NSSPKIXCertificate *issuerCert,
  NSSCertificate *issuer
)
{
    PRStatus status;
    NSSBitString *sig;
    NSSPKIXAlgorithmIdentifier *sigAlg;
    NSSPKIXTBSCertificate *tbsCert;
    NSSDER *tbsDER;
    NSSPublicKey *verifyKey;
    NSSAlgorithmAndParameters *ap;
    NSSOID *alg;
    NSSItem *params;

    sigAlg = nssPKIXCertificate_GetSignatureAlgorithm(cert);
    if (!sigAlg) {
	return PR_FAILURE;
    }
    alg = nssPKIXAlgorithmIdentifier_GetAlgorithm(sigAlg);
    /* XXX */
    /* there are trailing bytes in the algid of certs generated by
     * NSS... what are they?  3.X ignores them, uses NULL params
     */
#if 0
    params = nssPKIXAlgorithmIdentifier_GetParameters(sigAlg);
#else
    params = NULL;
#endif

    sig = nssPKIXCertificate_GetSignature(cert);
    if (!sig) {
	return PR_FAILURE;
    }

    tbsCert = nssPKIXCertificate_GetTBSCertificate(cert);
    if (!tbsCert) {
	return PR_FAILURE;
    }

    /* XXX */
    tbsDER = nssPKIXTBSCertificate_Encode(tbsCert, NSSASN1DER, 0, 0);
    if (!tbsDER) {
	return PR_FAILURE;
    }

    verifyKey = NSSCertificate_GetPublicKey(issuer);
    if (!verifyKey) {
	return PR_FAILURE;
    }

    ap = NSSOID_CreateAlgorithmAndParameters(alg, params);
    if (!ap) {
	NSSPublicKey_Destroy(verifyKey);
	return PR_FAILURE;
    }

    NSSASN1_ConvertBitString(sig);

    status = NSSPublicKey_Verify(verifyKey, ap, tbsDER, sig, NULL);

    NSSAlgorithmAndParameters_Destroy(ap);
    NSSPublicKey_Destroy(verifyKey);
    
    return status;
}

static PRStatus
pkix_ValidateChainLink (
  void *cert,
  NSSCertificate *issuer,
  void *vData
)
{
    PRStatus status;
    NSSPKIXCertificate *pkixCert = (NSSPKIXCertificate *)cert;
    NSSPKIXCertificate *pkixIssuer;
    struct nss_pkix_validation_data_str *validationData = 
      (struct nss_pkix_validation_data_str *)vData;

    nss_HoldErrorStack();

    pkixIssuer = (NSSPKIXCertificate *)NSSCertificate_GetDecoding(issuer);
    if (!pkixIssuer) {
	goto loser;
    }

    /*
     * Check the Basic Constraints extension of the issuer against
     * the current path length
     */
    status = check_basic_constraints(pkixIssuer, validationData);
    if (status == PR_FAILURE) {
	goto loser;
    }

    /* Check the Name Constraints extension against the name */
    /* XXX */

    /*
     * Verify the signature
     */
    status = verify_signature(pkixCert, pkixIssuer, issuer);

    nss_ResumeErrorStack();
    return status;
loser:
    nss_ResumeErrorStack();
    return PR_FAILURE;
}

static void
pkix_FreeChainValidationData (
  void *vData
)
{
}

static void
pkix_Destroy (
  void *cert
)
{
    NSSPKIXCertificate *pkixCert = (NSSPKIXCertificate *)cert;

    nss_HoldErrorStack();

    nssPKIXCertificate_Destroy(pkixCert);

    nss_ResumeErrorStack();
}

NSSCertificateMethods g_pkix_methods;

NSS_IMPLEMENT PRStatus
NSS_EnablePKIXCertificates (
  void
)
{
    g_pkix_methods.decode = pkix_Decode;
    g_pkix_methods.getSubject = pkix_GetSubject;
    g_pkix_methods.getIssuer = pkix_GetIssuer;
    g_pkix_methods.getSerialNumber = pkix_GetSerialNumber;
    g_pkix_methods.getEmailAddress = pkix_GetEmailAddress;
    g_pkix_methods.getValidityPeriod = pkix_GetValidityPeriod;
    g_pkix_methods.getUsages = pkix_GetUsages;
    g_pkix_methods.getPolicies = pkix_GetPolicies;
    g_pkix_methods.getIssuerIdentifier = pkix_GetIssuerIdentifier;
    g_pkix_methods.getPublicKeyInfo = pkix_GetPublicKeyInfo;
    g_pkix_methods.isMyIdentifier = pkix_IsMyIdentifier;
    g_pkix_methods.freeIdentifier = pkix_FreeIdentifier;
    g_pkix_methods.startChainValidation = pkix_StartChainValidation;
    g_pkix_methods.validateChainLink = pkix_ValidateChainLink;
    g_pkix_methods.freeChainValidationData = pkix_FreeChainValidationData;
    g_pkix_methods.destroy = pkix_Destroy;

    return NSS_SetDefaultCertificateHandler(NSSCertificateType_PKIX, 
                                            &g_pkix_methods);
}
