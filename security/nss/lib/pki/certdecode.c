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

#ifndef PKIM_H
#include "pkim.h"
#endif /* PKIM_H */

#ifndef ASN1_H
#include "asn1.h"
#endif /* ASN1_H */

/* XXX temporary stuff for cracking X509 parts */

static const nssASN1Template skip_template[] = {
  { nssASN1_SKIP }
};

typedef struct {
  NSSDER data;
} 
someSignedData;

typedef struct {
  NSSDER issuer;
  NSSDER serial;
}
anIssuerAndSN;

static const nssASN1Template s_x509_signed_data_template[] = {
  { nssASN1_SEQUENCE, 0, NULL, sizeof(someSignedData) },
  { nssASN1_ANY, offsetof(someSignedData, data) },
  { nssASN1_SKIP_REST },
  { 0 }
};

static const nssASN1Template s_x509_issuer_serial_template[] = {
  { nssASN1_SEQUENCE, 0, NULL, sizeof(NSSDER) },
  { nssASN1_EXPLICIT | nssASN1_OPTIONAL | nssASN1_CONSTRUCTED |
    nssASN1_CONTEXT_SPECIFIC | 0, 0, skip_template }, /* version */
  { nssASN1_ANY, offsetof(anIssuerAndSN, serial) },
  { nssASN1_SKIP },
  { nssASN1_ANY, offsetof(anIssuerAndSN, issuer) },
  { nssASN1_SKIP_REST },
  { 0 }
};

NSS_IMPLEMENT PRStatus
nssPKIX509_GetIssuerAndSerialFromDER
(
  NSSDER *encoding,
  NSSArena *arenaOpt,
  NSSDER *issuer,
  NSSDER *serial
)
{
    PRStatus status;
    someSignedData signedData;
    anIssuerAndSN issuerAndSN;
    memset(&signedData, 0, sizeof(signedData));
    memset(&issuerAndSN, 0, sizeof(issuerAndSN));
    status = nssASN1_DecodeBER(NULL, &signedData, 
                               s_x509_signed_data_template, encoding);
    if (status != PR_SUCCESS) {
	return status;
    }
    status = nssASN1_DecodeBER(arenaOpt, &issuerAndSN, 
                               s_x509_issuer_serial_template, 
                               &signedData.data);
    nss_ZFreeIf(signedData.data.data);
    *issuer = issuerAndSN.issuer;
    *serial = issuerAndSN.serial;
    return status;
}

typedef struct {
  NSSItem version;
  NSSDER issuer;
  NSSDER serial;
  NSSDER subject;
}
quickX509Cert;

#if 0
static const nssASN1Template s_x509_quick_template[] = {
  { nssASN1_SEQUENCE, 0, NULL, sizeof(quickX509Cert) },
  { nssASN1_EXPLICIT | nssASN1_OPTIONAL | nssASN1_CONSTRUCTED |
    nssASN1_CONTEXT_SPECIFIC | 0, offsetof(quickX509Cert, version), 
    nssASN1Template_Integer }, /* version */
  { nssASN1_ANY, offsetof(quickX509Cert, serial) },
  { nssASN1_SKIP }, /* sig */
  { nssASN1_ANY, offsetof(quickX509Cert, issuer) },
  { nssASN1_SKIP }, /* validity */
  { nssASN1_ANY, offsetof(quickX509Cert, subject) },
  { nssASN1_SKIP_REST },
  { 0 }
};
#endif

#ifdef NSS_3_4_CODE
/* This is defined in nss3hack.c */
NSS_EXTERN nssDecodedCert *
nssDecodedPKIXCertificate_Create
(
  NSSArena *arenaOpt,
  NSSDER *encoding
);

NSS_IMPLEMENT PRStatus
nssDecodedPKIXCertificate_Destroy
(
  nssDecodedCert *dc
);
#else /* NSS_4_0_CODE */
/* This is where 4.0 PKIX code will handle the decoding */
static nssDecodedCert *
nssDecodedPKIXCertificate_Create
(
  NSSArena *arenaOpt, /* XXX should remove */
  NSSDER *encoding
)
{
    NSSArena *arena;
    nssDecodedCert *rvDC = NULL;
    quickX509Cert *quickCert;
return rvDC;
    arena = nssArena_Create();
    if (!arena) {
	return (nssDecodedCert *)NULL;
    }
    rvDC = nss_ZNEW(arena, nssDecodedCert);
    if (!rvDC) {
	goto loser;
    }
    quickCert = nss_ZNEW(arena, quickX509Cert);
    if (!quickCert) {
	goto loser;
    }
    rvDC->type = NSSCertificateType_PKIX;
    rvDC->data = quickCert;
    return rvDC;
loser:
    nssArena_Destroy(arena);
    return (nssDecodedCert *)NULL;
}

static PRStatus
nssDecodedPKIXCertificate_Destroy
(
  nssDecodedCert *dc
)
{
    return PR_FAILURE;
}
#endif /* not NSS_3_4_CODE */

NSS_IMPLEMENT nssDecodedCert *
nssDecodedCert_Create
(
  NSSArena *arenaOpt,
  NSSDER *encoding,
  NSSCertificateType type
)
{
    nssDecodedCert *rvDC = NULL;
    switch(type) {
    case NSSCertificateType_PKIX:
	rvDC = nssDecodedPKIXCertificate_Create(arenaOpt, encoding);
	break;
    default:
#if 0
	nss_SetError(NSS_ERROR_INVALID_ARGUMENT);
#endif
	return (nssDecodedCert *)NULL;
    }
    return rvDC;
}

NSS_IMPLEMENT PRStatus
nssDecodedCert_Destroy
(
  nssDecodedCert *dc
)
{
    if (!dc) {
	return PR_FAILURE;
    }
    switch(dc->type) {
    case NSSCertificateType_PKIX:
	return nssDecodedPKIXCertificate_Destroy(dc);
    default:
#if 0
	nss_SetError(NSS_ERROR_INVALID_ARGUMENT);
#endif
	break;
    }
    return PR_FAILURE;
}

