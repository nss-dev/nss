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

#ifndef PKI_H
#include "pki.h"
#endif /* PKI_H */

#ifndef PKIX_H
#include "pkix.h"
#endif /* PKIX_H */

#include "nss.h"

static void *
pkix_Decode
(
  NSSArena *arenaOpt,
  NSSBER *encoding
)
{
    NSSPKIXCertificate *pkixCert;
    pkixCert = nssPKIXCertificate_Decode(arenaOpt, encoding);
    if (!pkixCert) {
	return (void *)NULL;
    }
    return (void *)pkixCert;
}

static NSSBER *
pkix_GetSubject
(
  void *cert
)
{
    NSSPKIXCertificate *pkixCert = (NSSPKIXCertificate *)cert;
    NSSPKIXTBSCertificate *tbsCert;
    NSSPKIXName *subject;
    /*
     * cert->tbsCert
     */
    tbsCert = nssPKIXCertificate_GetTBSCertificate(pkixCert);
    if (!tbsCert) {
	return (NSSBER *)NULL;
    }
    /*
     * tbsCert->subject
     */
    subject = nssPKIXTBSCertificate_GetSubject(tbsCert);
    if (!subject) {
	return (NSSBER *)NULL;
    }
    /*
     * subject->der
     */
    return nssPKIXName_Encode(subject);
}

static NSSBER *
pkix_GetIssuer
(
  void *cert
)
{
    NSSPKIXCertificate *pkixCert = (NSSPKIXCertificate *)cert;
    NSSPKIXTBSCertificate *tbsCert;
    NSSPKIXName *issuer;
    /*
     * cert->tbsCert
     */
    tbsCert = nssPKIXCertificate_GetTBSCertificate(pkixCert);
    if (!tbsCert) {
	return (NSSBER *)NULL;
    }
    /*
     * tbsCert->issuer
     */
    issuer = nssPKIXTBSCertificate_GetIssuer(tbsCert);
    if (!issuer) {
	return (NSSBER *)NULL;
    }
    /*
     * issuer->der
     */
    return nssPKIXName_Encode(issuer);
}

static NSSBER *
pkix_GetSerialNumber
(
  void *cert
)
{
    NSSPKIXCertificate *pkixCert = (NSSPKIXCertificate *)cert;
    NSSPKIXTBSCertificate *tbsCert;
    /*
     * cert->tbsCert
     */
    tbsCert = nssPKIXCertificate_GetTBSCertificate(pkixCert);
    if (!tbsCert) {
	return (NSSBER *)NULL;
    }
    /*
     * tbsCert->serialNumber
     */
    return nssPKIXTBSCertificate_GetSerialNumber(tbsCert);
}

static NSSASCII7 *
pkix_GetEmailAddress
(
  void *cert
)
{
    return NULL;
}

#if 0
struct nss_pkix_issuer_id_str {
};
#endif

static void *
pkix_GetIssuerIdentifier
(
  void *cert
)
{
    return NULL;
}

static PRBool
pkix_IsMyIdentifier
(
  void *cert,
  void *id
)
{
    return PR_FALSE;
}

static void 
pkix_FreeIdentifier
(
  void *id
)
{
}

static PRStatus
pkix_GetValidityPeriod
(
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
    /*
     * cert->tbsCert
     */
    tbsCert = nssPKIXCertificate_GetTBSCertificate(pkixCert);
    if (!tbsCert) {
	return PR_FAILURE;
    }
    /*
     * tbsCert->validity
     */
    validity = nssPKIXTBSCertificate_GetValidity(tbsCert);
    if (!validity) {
	return PR_FAILURE;
    }
    /*
     * validity->notBefore
     */
    pkixTime = nssPKIXValidity_GetNotBefore(validity);
    if (!pkixTime) {
	return PR_FAILURE;
    }
    *notBefore = nssPKIXTime_GetTime(pkixTime, &status);
    if (status == PR_FAILURE) {
	return PR_FAILURE;
    }
    /*
     * validity->notAfter
     */
    pkixTime = nssPKIXValidity_GetNotAfter(validity);
    if (!pkixTime) {
	return PR_FAILURE;
    }
    *notAfter = nssPKIXTime_GetTime(pkixTime, &status);
    if (status == PR_FAILURE) {
	return PR_FAILURE;
    }
    return PR_SUCCESS;
}

/*
 * restrict the set of usages based on the value of the key usage
 * extension
 */
static void
get_usages_from_key_usage
(
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
	usages->peer &= ~(NSSUsage_SSLServer | NSSUsage_EmailRecipient);
    }
#if 0
    if ((ku & NSSPKIXKeyUsage_DataEncipherment) == 0) {
    }
#endif
    if ((ku & NSSPKIXKeyUsage_KeyCertSign) == 0) {
	usages->ca = 0;
    }
#if 0
    if ((ku & NSSPKIXKeyUsage_CRLSign) == 0) {
    }
    if ((ku & NSSPKIXKeyUsage_EncipherOnly) == 0) {
    }
    if ((ku & NSSPKIXKeyUsage_DecipherOnly) == 0) {
    }
#endif
    /* XXX ssl step-up */
}

/*
 * restrict the set of usages based on the value of the basic constraints
 * extension
 */
static void
get_usages_from_basic_constraints
(
  NSSPKIXBasicConstraints *basicConstraints,
  NSSUsages *usages
)
{
    if (!nssPKIXBasicConstraints_IsCA(basicConstraints)) {
	usages->ca = 0;
    }
}

/*
 * restrict the set of usages based on the value of the netscape cert type
 * extension
 */
static void
get_usages_from_ns_cert_type
(
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
    /* XXX ssl step-up */
}

static PRStatus
pkix_GetUsages
(
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

    /* start with everything */
    usages.ca = NSSUsage_All;
    usages.peer = NSSUsage_All;
    /*
     * cert->tbsCert
     */
    tbsCert = nssPKIXCertificate_GetTBSCertificate(pkixCert);
    if (!tbsCert) {
	return PR_FAILURE;
    }
    /*
     * tbsCert->extensions
     */
    extensions = nssPKIXTBSCertificate_GetExtensions(tbsCert);
    if (!extensions) {
	return PR_FAILURE;
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
    return PR_SUCCESS;
}

static NSSPolicies *
pkix_GetPolicies
(
  void *cert
)
{
    return NULL;
}

#if 0
struct nss_pkix_validation_data_str {
};
#endif

static void *
pkix_StartChainValidation
(
)
{
    return NULL;
}

static PRStatus
pkix_ValidateChainLink
(
  void *cert,
  void *issuer,
  void *vData
)
{
#if 0
    NSSPKIXCertificate *pkixCert = (NSSPKIXCertificate *)cert;
    NSSPKIXCertificate *pkixIssuer = (NSSPKIXCertificate *)issuer;
    struct nss_pkix_validation_data_str *validationData = 
      (struct nss_pkix_validation_data_str *)vData;

    /*
     * Check the Basic Constraints extension.
     */
    /*
     * extensions[basicConstraints]
     */
    basicConstraints = nssPKIXExtensions_GetBasicConstraints(extensions);
    if (basicConstraints) {
    }

    /*
     * Verify the signature.
     */
    sig = NSSPKIXCertificate_GetSignature(cert);

    sigAlg = get_signature_algorithm_from_pkix_cert(cert);

    tbsCert = NSSPKIXCertificate_GetTBSCertificate(cert);

    tbsDER = NSSPKIXTBSCertificate_Encode(tbsCert);

    signingCert = NSSPKIXCertificate_GetNSSCertificate(issuer);

    verifyKey = NSSCertificate_GetPublicKey(signingCert);

    status = NSSPublicKey_Verify(verifyKey, sigAlg, tbsDER, sig, NULL);

    NSSPublicKey_Destroy(verifyKey);
    
    NSSCertificate_Destroy(signingCert);
#endif
    return PR_SUCCESS;

}

static void
pkix_FreeChainValidationData
(
  void *vData
)
{
}

static void
pkix_Destroy
(
  void *cert
)
{
    NSSPKIXCertificate *pkixCert = (NSSPKIXCertificate *)cert;
    NSSPKIXCertificate_Destroy(pkixCert);
}

NSSCertificateMethods g_pkix_methods;

NSS_IMPLEMENT PRStatus
NSS_EnablePKIXCertificates
(
  void
)
{
    g_pkix_methods.decode = pkix_Decode;
    g_pkix_methods.getSubject = pkix_GetSubject;
    g_pkix_methods.getIssuer = pkix_GetIssuer;
    g_pkix_methods.getSerialNumber = pkix_GetSerialNumber;
    g_pkix_methods.getEmailAddress = pkix_GetEmailAddress;
    g_pkix_methods.getIssuerIdentifier = pkix_GetIssuerIdentifier;
    g_pkix_methods.isMyIdentifier = pkix_IsMyIdentifier;
    g_pkix_methods.freeIdentifier = pkix_FreeIdentifier;
    g_pkix_methods.getValidityPeriod = pkix_GetValidityPeriod;
    g_pkix_methods.getUsages = pkix_GetUsages;
    g_pkix_methods.getPolicies = pkix_GetPolicies;
    g_pkix_methods.startChainValidation = pkix_StartChainValidation;
    g_pkix_methods.validateChainLink = pkix_ValidateChainLink;
    g_pkix_methods.freeChainValidationData = pkix_FreeChainValidationData;
    g_pkix_methods.destroy = pkix_Destroy;

    return NSS_SetDefaultCertificateHandler(NSSCertificateType_PKIX, 
                                            &g_pkix_methods);
}
