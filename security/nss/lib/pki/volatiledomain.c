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

struct object_array_str
{
  void **array;
  PRUint32 count;
  PRUint32 size;
};

#define DEFAULT_ARRAY_SIZE 4
#define DEFAULT_RETURN_ARRAY 4

struct NSSVolatileDomainStr
{
#if 0
  PRInt32 refCount;
#endif
  NSSArena *arena;
  NSSTrustDomain *td;
  NSSCallback *callback;

  PZLock *objectLock;
  struct object_array_str certs;
  struct object_array_str bkeys;
  struct object_array_str vkeys;
  struct object_array_str mkeys;
};

NSS_IMPLEMENT NSSVolatileDomain *
nssVolatileDomain_Create (
  NSSTrustDomain *td,
  NSSCallback *uhhOpt
)
{
    NSSArena *arena;
    NSSVolatileDomain *rvVD;
    arena = NSSArena_Create();
    if (!arena) {
	return (NSSVolatileDomain *)NULL;
    }
    rvVD = nss_ZNEW(arena, NSSVolatileDomain);
    if (!rvVD) {
	nssArena_Destroy(arena);
	return (NSSVolatileDomain *)NULL;
    }
    rvVD->objectLock = PZ_NewLock(nssILockOther); /* XXX */
    if (!rvVD->objectLock) {
	nssArena_Destroy(arena);
	return (NSSVolatileDomain *)NULL;
    }
    rvVD->td = td;
    rvVD->arena = arena;
    if (uhhOpt) {
	rvVD->callback = uhhOpt;
    }
    return rvVD;
}

NSS_IMPLEMENT PRStatus
nssVolatileDomain_Destroy (
  NSSVolatileDomain *vd
)
{
    PRStatus status = PR_SUCCESS;
    PZ_DestroyLock(vd->objectLock);
    nssCertificateArray_Destroy((NSSCertificate **)vd->certs.array);
    nssPublicKeyArray_Destroy((NSSPublicKey **)vd->bkeys.array);
    nssPrivateKeyArray_Destroy((NSSPrivateKey **)vd->vkeys.array);
    nssSymmetricKeyArray_Destroy((NSSSymmetricKey **)vd->mkeys.array);
    status |= nssArena_Destroy(vd->arena);
    return status;
}

NSS_IMPLEMENT PRStatus
NSSVolatileDomain_Destroy (
  NSSVolatileDomain *vd
)
{
    if (!vd) {
	return PR_SUCCESS;
    }
    return nssVolatileDomain_Destroy(vd);
}

NSS_IMPLEMENT PRStatus
nssVolatileDomain_SetDefaultCallback (
  NSSVolatileDomain *vd,
  NSSCallback *newCallback,
  NSSCallback **oldCallbackOpt
)
{
    if (oldCallbackOpt) {
	*oldCallbackOpt = vd->callback;
    }
    vd->callback = newCallback;
    return PR_SUCCESS;
}

NSS_IMPLEMENT PRStatus
NSSVolatileDomain_SetDefaultCallback (
  NSSVolatileDomain *vd,
  NSSCallback *newCallback,
  NSSCallback **oldCallbackOpt
)
{
    return nssVolatileDomain_SetDefaultCallback(vd, 
                                                newCallback, 
                                                oldCallbackOpt);
}

NSS_IMPLEMENT NSSCallback *
nssVolatileDomain_GetDefaultCallback (
  NSSVolatileDomain *vd,
  PRStatus *statusOpt
)
{
    if (statusOpt) {
	*statusOpt = PR_SUCCESS;
    }
    return vd->callback;
}

NSS_IMPLEMENT NSSCallback *
NSSVolatileDomain_GetDefaultCallback (
  NSSVolatileDomain *vd,
  PRStatus *statusOpt
)
{
    return nssVolatileDomain_GetDefaultCallback(vd, statusOpt);
}

NSS_IMPLEMENT NSSTrustDomain *
nssVolatileDomain_GetTrustDomain (
  NSSVolatileDomain *vd
)
{
    return vd->td; /* XXX */
}

NSS_IMPLEMENT NSSTrustDomain *
NSSVolatileDomain_GetTrustDomain (
  NSSVolatileDomain *vd
)
{
    return nssVolatileDomain_GetTrustDomain(vd);
}

NSS_IMPLEMENT PRStatus
nssVolatileDomain_ImportCertificate (
  NSSVolatileDomain *vd,
  NSSCertificate *c
)
{
    PZ_Lock(vd->objectLock);
    if (vd->certs.count == vd->certs.size) {
	if (vd->certs.size == 0) {
	    /* need to alloc new array */
	    vd->certs.array = (void **)nss_ZNEWARRAY(vd->arena, 
	                                             NSSCertificate *, 
	                                             DEFAULT_ARRAY_SIZE);
	} else {
	    /* array is full, realloc */
	    vd->certs.size *= 2;
	    vd->certs.array = (void **)nss_ZREALLOCARRAY(vd->certs.array, 
	                                                 NSSCertificate *, 
	                                                 vd->certs.size);
	}
	if (!vd->certs.array) {
	    PZ_Unlock(vd->objectLock);
	    return PR_FAILURE;
	}
    }
    vd->certs.array[vd->certs.count++] = (void *)nssCertificate_AddRef(c);
    PZ_Unlock(vd->objectLock);
    nssCertificate_SetVolatileDomain(c, vd);
    return PR_SUCCESS;
}

NSS_IMPLEMENT PRStatus
NSSVolatileDomain_ImportCertificate (
  NSSVolatileDomain *vd,
  NSSCertificate *c
)
{
    return nssVolatileDomain_ImportCertificate(vd, c);
}

NSS_IMPLEMENT NSSCertificate *
nssVolatileDomain_ImportEncodedCertificate (
  NSSVolatileDomain *vd,
  NSSBER *ber,
  NSSUTF8 *nickOpt
)
{
    NSSCertificate *c;

    c = nssCertificate_Decode(ber);
    if (!c) {
	return (NSSCertificate *)NULL;
    }
    if (nickOpt) {
	nssCertificate_SetNickname(c, NULL, nickOpt);
    }
    if (nssVolatileDomain_ImportCertificate(vd, c) == PR_FAILURE) {
	nssCertificate_Destroy(c);
	return (NSSCertificate *)NULL;
    }
    return c;
}

NSS_IMPLEMENT NSSCertificate *
NSSVolatileDomain_ImportEncodedCertificate (
  NSSVolatileDomain *vd,
  NSSBER *ber,
  NSSUTF8 *nickOpt
)
{
    return nssVolatileDomain_ImportEncodedCertificate(vd, ber, nickOpt);
}

NSS_IMPLEMENT PRStatus
NSSVolatileDomain_ImportEncodedCertificateChain (
  NSSVolatileDomain *vd,
  NSSBER *ber,
  NSSCertificateType certType
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return PR_FAILURE;
}

#if 0
NSS_IMPLEMENT PRStatus
nssVolatileDomain_ImportSMIMEProfile (
  NSSVolatileDomain *vd,
  nssSMIMEProfile *profile
)
{
    PRStatus nssrv;
    if (!vd->certStore) {
	vd->certStore = nssCertificateStore_Create(vd->arena);
	if (!vd->certStore) {
	    return PR_FAILURE;
	}
    }
    nssrv = nssCertificateStore_AddSMIMEProfile(vd->certStore, profile);
#if 0
    if (nssrv == PR_SUCCESS) {
	profile->object.cryptoContext = vd;
    }
#endif
    return nssrv;
}
#endif

struct cert_array_str {
  NSSCertificate **array;
  PRUint32 count;
  PRUint32 size;
  PRBool grow;
  NSSArena *arenaOpt;
  nssArenaMark *mark;
};

#define INIT_CERT_ARRAY(cert_array, rvOpt, maxOpt, arenaOpt) \
    (cert_array)->array = rvOpt;                             \
    (cert_array)->count = 0;                                 \
    (cert_array)->size  = maxOpt;                            \
    (cert_array)->grow = maxOpt ? PR_FALSE : PR_TRUE;        \
    (cert_array)->arenaOpt = arenaOpt;                       \
    (cert_array)->mark = NULL;

static PRStatus
add_to_cert_array(struct cert_array_str *car, NSSCertificate *c)
{
    if (!car->array) {
	if (car->arenaOpt) {
	    car->mark = nssArena_Mark(car->arenaOpt);
	    if (!car->mark) {
		return PR_FAILURE;
	    }
	}
	if (!car->size) {
	    car->size = DEFAULT_RETURN_ARRAY;
	}
	car->array = nss_ZNEWARRAY(car->arenaOpt, NSSCertificate *, 
	                           car->size + 1);
    } else if (car->count == car->size) {
	if (!car->grow) {
	    return PR_FAILURE; /* this will terminate the loop */
	}
	car->size *= 2;
	car->array = nss_ZREALLOCARRAY(car->array, NSSCertificate *, 
	                               car->size + 1);
    }
    if (!car->array) {
	return PR_FAILURE;
    }
    car->array[car->count++] = nssCertificate_AddRef(c);
    return PR_SUCCESS;
}

static NSSCertificate **
finish_cert_array(struct cert_array_str *car, PRStatus status,
                  NSSCertificate **tdCerts)
{
    if (status == PR_FAILURE) {
	if (!car->grow) {
	   /* this just means we were supplied an array that we filled,
	    * not actually a failure
	    */
	    return car->array;
	} else if (car->mark) {
	    nssArena_Release(car->arenaOpt, car->mark);
	} else {
	    nss_ZFreeIf(car->array);
	}
	car->array = NULL;
    } else if (car->mark) {
	if (tdCerts) {
	    car->array = nssCertificateArray_Join(car->array, tdCerts);
	}
	nssArena_Unmark(car->arenaOpt, car->mark);
    }

    return car->array;
}

NSS_IMPLEMENT NSSCertificate **
nssVolatileDomain_FindCertificatesByNickname (
  NSSVolatileDomain *vd,
  NSSUTF8 *name,
  NSSCertificate **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    PRStatus status;
    PRUint32 i;
    NSSCertificate **certs, **tdCerts;
    NSSUTF8 *cNick;
    struct cert_array_str cert_array;

    INIT_CERT_ARRAY(&cert_array, rvOpt, maximumOpt, arenaOpt);

    PZ_Lock(vd->objectLock);
    certs = (NSSCertificate **)vd->certs.array;
    for (i=0; i<vd->certs.count; i++) {
	cNick = nssCertificate_GetNickname(certs[i], NULL);
	if (nssUTF8_Equal(name, cNick, NULL)) { 
	    status = add_to_cert_array(&cert_array, certs[i]);
	    if (status == PR_FAILURE) {
		break;
	    }
	}
    }
    PZ_Unlock(vd->objectLock);

    tdCerts = nssTrustDomain_FindCertificatesByNickname(vd->td, name, 
                                   rvOpt ? rvOpt + cert_array.count : NULL,
                                   maximumOpt - cert_array.count, arenaOpt);

    return finish_cert_array(&cert_array, status, tdCerts);
}

NSS_IMPLEMENT NSSCertificate **
NSSVolatileDomain_FindCertificatesByNickname (
  NSSVolatileDomain *vd,
  NSSUTF8 *name,
  NSSCertificate *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
)
{
    return nssVolatileDomain_FindCertificatesByNickname(vd, name, rvOpt,
                                                        maximumOpt, arenaOpt);
}

NSS_IMPLEMENT NSSCertificate *
nssVolatileDomain_FindBestCertificateByNickname (
  NSSVolatileDomain *vd,
  NSSUTF8 *name,
  NSSTime time, /* NULL for "now" */
  NSSUsages *usages,
  NSSPolicies *policiesOpt /* NULL for none */
)
{
    NSSCertificate **certs;
    NSSCertificate *rvCert = NULL;

    /* search the volatile (and trust) domain by nickname */
    certs = nssVolatileDomain_FindCertificatesByNickname(vd, name, 
                                                         NULL, 0, NULL);
    if (certs) {
	/* find the best one */
	rvCert = nssCertificateArray_FindBestCertificate(certs, time, 
	                                                 usages, policiesOpt);
	nssCertificateArray_Destroy(certs);
    }
    return rvCert;
}

NSS_IMPLEMENT NSSCertificate *
NSSVolatileDomain_FindBestCertificateByNickname (
  NSSVolatileDomain *vd,
  NSSUTF8 *name,
  NSSTime time, /* NULL for "now" */
  NSSUsages *usages,
  NSSPolicies *policiesOpt /* NULL for none */
)
{
    return nssVolatileDomain_FindBestCertificateByNickname(vd, name,
                                                           time, usages,
                                                           policiesOpt);
}

NSS_IMPLEMENT NSSCertificate *
nssVolatileDomain_FindCertificateByIssuerAndSerialNumber (
  NSSVolatileDomain *vd,
  NSSDER *issuer,
  NSSDER *serial
)
{
    PRUint32 i;
    NSSCertificate **certs;
    NSSDER *cIssuer, *cSerial;
    NSSCertificate *rvCert = NULL;

    PZ_Lock(vd->objectLock);
    certs = (NSSCertificate **)vd->certs.array;
    for (i=0; i<vd->certs.count; i++) {
	cIssuer = nssCertificate_GetIssuer(certs[i]);
	cSerial = nssCertificate_GetSerialNumber(certs[i]);
	if (nssItem_Equal(cIssuer, issuer, NULL) &&
	    nssItem_Equal(cSerial, serial, NULL)) 
	{
	    rvCert = nssCertificate_AddRef(certs[i]);
	    break;
	}
    }
    PZ_Unlock(vd->objectLock);
    if (!rvCert) {
	rvCert = nssTrustDomain_FindCertificateByIssuerAndSerialNumber(vd->td,
	                                                      issuer, serial);
    }
    return rvCert;
}

NSS_IMPLEMENT NSSCertificate *
NSSVolatileDomain_FindCertificateByIssuerAndSerialNumber (
  NSSVolatileDomain *vd,
  NSSDER *issuer,
  NSSDER *serial
)
{
    return nssVolatileDomain_FindCertificateByIssuerAndSerialNumber(vd,
                                                                    issuer,
                                                                    serial);
}

NSS_IMPLEMENT NSSCertificate **
nssVolatileDomain_FindCertificatesBySubject (
  NSSVolatileDomain *vd,
  NSSDER *subject,
  NSSCertificate *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
)
{
    PRStatus status;
    PRUint32 i;
    NSSCertificate **certs, **tdCerts;
    NSSDER *certSubject;
    struct cert_array_str cert_array;

    INIT_CERT_ARRAY(&cert_array, rvOpt, maximumOpt, arenaOpt);

    PZ_Lock(vd->objectLock);
    certs = (NSSCertificate **)vd->certs.array;
    for (i=0; i<vd->certs.count; i++) {
	certSubject = nssCertificate_GetSubject(certs[i]);
	if (nssItem_Equal(certSubject, subject, NULL)) {
	    status = add_to_cert_array(&cert_array, certs[i]);
	    if (status == PR_FAILURE) {
		break;
	    }
	}
    }
    PZ_Unlock(vd->objectLock);

    tdCerts = nssTrustDomain_FindCertificatesBySubject(vd->td, subject, 
                                   rvOpt ? rvOpt + cert_array.count : NULL,
                                   maximumOpt - cert_array.count, arenaOpt);

    return finish_cert_array(&cert_array, status, tdCerts);
}

NSS_IMPLEMENT NSSCertificate **
NSSVolatileDomain_FindCertificatesBySubject (
  NSSVolatileDomain *vd,
  NSSDER *subject,
  NSSCertificate *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
)
{
    return nssVolatileDomain_FindCertificatesBySubject(vd, subject,
                                                      rvOpt, maximumOpt,
                                                      arenaOpt);
}

NSS_IMPLEMENT NSSCertificate *
nssVolatileDomain_FindBestCertificateBySubject (
  NSSVolatileDomain *vd,
  NSSDER *subject,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt
)
{
    NSSCertificate **certs;
    NSSCertificate *rvCert = NULL;

    /* search the volatile (and trust) domain by subject */
    certs = nssVolatileDomain_FindCertificatesBySubject(vd, subject, 
                                                          NULL, 0, NULL);
    if (certs) {
	/* find the best one */
	rvCert = nssCertificateArray_FindBestCertificate(certs, time, 
	                                                 usages, policiesOpt);
	nssCertificateArray_Destroy(certs);
    }
    return rvCert;
}

NSS_IMPLEMENT NSSCertificate *
NSSVolatileDomain_FindBestCertificateBySubject (
  NSSVolatileDomain *vd,
  NSSDER *subject,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt
)
{
    return nssVolatileDomain_FindBestCertificateBySubject(vd, subject,
                                                time, usages, policiesOpt);
}

NSS_IMPLEMENT NSSCertificate *
nssVolatileDomain_FindCertificateByEncodedCertificate (
  NSSVolatileDomain *vd,
  NSSBER *encodedCert
)
{
    PRUint32 i;
    NSSBER *certEnc;
    NSSCertificate **certs;
    NSSCertificate *rvCert = NULL;

    PZ_Lock(vd->objectLock);
    certs = (NSSCertificate **)vd->certs.array;
    for (i=0; i<vd->certs.count; i++) {
	certEnc = nssCertificate_GetEncoding(certs[i]);
	if (nssItem_Equal(certEnc, encodedCert, NULL)) {
	    rvCert = nssCertificate_AddRef(certs[i]);
	    break;
	}
    }
    PZ_Unlock(vd->objectLock);
    if (!rvCert) {
	rvCert = nssTrustDomain_FindCertificateByEncodedCertificate(vd->td,
	                                                      encodedCert);
    }
    return rvCert;
}

NSS_IMPLEMENT NSSCertificate *
NSSVolatileDomain_FindCertificateByEncodedCertificate (
  NSSVolatileDomain *vd,
  NSSBER *encodedCert
)
{
    return nssVolatileDomain_FindCertificateByEncodedCertificate(vd,
                                                          encodedCert);
}

NSS_IMPLEMENT NSSCertificate **
nssVolatileDomain_FindCertificatesByEmail (
  NSSVolatileDomain *vd,
  NSSASCII7 *email,
  NSSCertificate *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
)
{
    PRStatus status;
    PRUint32 i;
    NSSCertificate **certs, **tdCerts;
    NSSASCII7 *cEmail;
    struct cert_array_str cert_array;

    INIT_CERT_ARRAY(&cert_array, rvOpt, maximumOpt, arenaOpt);

    PZ_Lock(vd->objectLock);
    certs = (NSSCertificate **)vd->certs.array;
    for (i=0; i<vd->certs.count; i++) {
	cEmail = nssCertificate_GetEmailAddress(certs[i]);
	if (nssUTF8_Equal(cEmail, email, NULL)) {
	    status = add_to_cert_array(&cert_array, certs[i]);
	    if (status == PR_FAILURE) {
		break;
	    }
	}
    }
    PZ_Unlock(vd->objectLock);

    tdCerts = nssTrustDomain_FindCertificatesByEmail(vd->td, email, 
                                   rvOpt ? rvOpt + cert_array.count : NULL,
                                   maximumOpt - cert_array.count, arenaOpt);

    return finish_cert_array(&cert_array, status, tdCerts);
}

NSS_IMPLEMENT NSSCertificate **
NSSVolatileDomain_FindCertificatesByEmail (
  NSSVolatileDomain *vd,
  NSSASCII7 *email,
  NSSCertificate *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
)
{
    return nssVolatileDomain_FindCertificatesByEmail(vd, email, rvOpt,
                                                     maximumOpt, arenaOpt);
}

NSS_IMPLEMENT NSSCertificate *
nssVolatileDomain_FindBestCertificateByEmail (
  NSSVolatileDomain *vd,
  NSSASCII7 *email,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt
)
{
    NSSCertificate **certs;
    NSSCertificate *rvCert = NULL;

    /* search the volatile domain by email */
    certs = nssVolatileDomain_FindCertificatesByEmail(vd, email, 
                                                      NULL, 0, NULL);
    if (certs) {
	/* find the best one */
	rvCert = nssCertificateArray_FindBestCertificate(certs, time, 
	                                                 usages, policiesOpt);
	nssCertificateArray_Destroy(certs);
    }
    return rvCert;
}

NSS_IMPLEMENT NSSCertificate *
NSSVolatileDomain_FindBestCertificateByEmail (
  NSSVolatileDomain *vd,
  NSSASCII7 *email,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt
)
{
    return nssVolatileDomain_FindBestCertificateByEmail(vd, email,
                                              time, usages, policiesOpt);
}

NSS_IMPLEMENT NSSCertificate *
NSSVolatileDomain_FindBestUserCertificate (
  NSSVolatileDomain *vd,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCertificate **
NSSVolatileDomain_FindUserCertificates (
  NSSVolatileDomain *vd,
  NSSTime time,
  NSSUsages *usagesOpt,
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
NSSVolatileDomain_FindBestUserCertificateForSSLClientAuth (
  NSSVolatileDomain *vd,
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
NSSVolatileDomain_FindUserCertificatesForSSLClientAuth (
  NSSVolatileDomain *vd,
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
NSSVolatileDomain_FindBestUserCertificateForEmailSigning (
  NSSVolatileDomain *vd,
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
NSSVolatileDomain_FindUserCertificatesForEmailSigning (
  NSSVolatileDomain *vd,
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

NSS_IMPLEMENT PRStatus
nssVolatileDomain_GenerateKeyPair (
  NSSVolatileDomain *vd,
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
NSSVolatileDomain_GenerateKeyPair (
  NSSVolatileDomain *vd,
  const NSSAlgorithmAndParameters *ap,
  NSSPrivateKey **pvkOpt,
  NSSPublicKey **pbkOpt,
  PRBool privateKeyIsSensitive,
  NSSToken *destination,
  NSSCallback *uhhOpt
)
{
    return nssVolatileDomain_GenerateKeyPair(vd, ap, pvkOpt, pbkOpt,
                                            privateKeyIsSensitive,
                                            destination, uhhOpt);
}

NSS_IMPLEMENT NSSSymmetricKey *
nssVolatileDomain_GenerateSymmetricKey (
  NSSVolatileDomain *vd,
  const NSSAlgorithmAndParameters *ap,
  PRUint32 keysize,
  const NSSUTF8 *labelOpt,
  NSSOperations operations,
  NSSProperties properties,
  NSSToken *destination,
  NSSCallback *uhhOpt
)
{
    NSSToken *source;
    nssCryptokiObject *key;
    nssSession *session;

    source = nssTrustDomain_FindSourceToken(vd->td, ap, destination);
    if (!source) {
	return (NSSSymmetricKey *)NULL;
    }

    /* XXX should volatile domain keep hash of tokens? */
    session = nssToken_CreateSession(source, PR_FALSE);
    if (!session) {
	nssToken_Destroy(source);
	return (NSSSymmetricKey *)NULL;
    }

    key = nssToken_GenerateSymmetricKey(source, session, ap, keysize,
                                        labelOpt, PR_FALSE, 
                                        operations, properties);
    nssSession_Destroy(session);
    nssToken_Destroy(source);
    if (!key) {
	return (NSSSymmetricKey *)NULL;
    }

    return nssSymmetricKey_CreateFromInstance(key, vd->td, vd);
}

NSS_IMPLEMENT NSSSymmetricKey *
NSSVolatileDomain_GenerateSymmetricKey (
  NSSVolatileDomain *vd,
  const NSSAlgorithmAndParameters *ap,
  PRUint32 keysize,
  const NSSUTF8 *labelOpt,
  NSSOperations operations,
  NSSProperties properties,
  NSSToken *destination,
  NSSCallback *uhhOpt
)
{
    return nssVolatileDomain_GenerateSymmetricKey(vd, ap, keysize,
                                                 labelOpt, 
                                                 operations, properties,
                                                 destination, uhhOpt);
}

NSS_IMPLEMENT NSSSymmetricKey *
NSSVolatileDomain_GenerateSymmetricKeyFromPassword (
  NSSVolatileDomain *vd,
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
NSSVolatileDomain_FindSymmetricKeyByAlgorithmAndKeyID (
  NSSVolatileDomain *vd,
  NSSOID *algorithm,
  NSSItem *keyID,
  NSSCallback *uhhOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

#if 0
NSS_IMPLEMENT NSSSymmetricKey *
nssVolatileDomain_UnwrapSymmetricKey (
  NSSVolatileDomain *vd,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *wrappedKey,
  NSSCallback *uhhOpt,
  NSSOperations operations,
  NSSProperties properties
)
{
    const NSSAlgorithmAndParameters *ap = apOpt ? apOpt : vd->ap;
    if (!ap) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSSymmetricKey *)NULL;
    }
    /* set up the private key */
    if (prepare_context_private_key(vd, ap) == PR_FAILURE) {
	return (NSSSymmetricKey *)NULL;
    }
    /* do the unwrap */
    vd->mko = nssToken_UnwrapKey(vd->token, vd->session, ap, vd->vko,
                                 wrappedKey, PR_FALSE, 
                                 operations, properties);
    /* create a new symkey */
    if (vd->mko) {
	nssPKIObject *pkio;
	pkio = nssPKIObject_Create(NULL, vd->mko, vd->td, vd);
	if (!pkio) {
	    goto loser;
	}
	vd->mk = nssSymmetricKey_Create(pkio);
	if (!vd->mk) {
	    nssPKIObject_Destroy(pkio);
	    goto loser;
	}
	return nssSymmetricKey_AddRef(vd->mk);
    }
loser:
    if (vd->mko) {
	nssCryptokiObject_Destroy(vd->mko);
	vd->mko = NULL;
    }
    nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
    return (NSSSymmetricKey *)NULL;
}

NSS_IMPLEMENT NSSSymmetricKey *
NSSVolatileDomain_UnwrapSymmetricKey (
  NSSVolatileDomain *vd,
  const NSSAlgorithmAndParameters *apOpt,
  NSSItem *wrappedKey,
  NSSCallback *uhhOpt,
  NSSOperations operations,
  NSSProperties properties
)
{
    if (!vd->vk && !vd->cert) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSSymmetricKey *)NULL;
    }
    return nssVolatileDomain_UnwrapSymmetricKey(vd, apOpt, 
                                               wrappedKey, uhhOpt, 
                                               operations, properties);
}
#endif

NSS_IMPLEMENT NSSSymmetricKey *
NSSVolatileDomain_DeriveSymmetricKey (
  NSSVolatileDomain *vd,
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

#if 0
NSS_IMPLEMENT NSSItem *
nssVolatileDomain_WrapSymmetricKey (
  NSSVolatileDomain *vd,
  const NSSAlgorithmAndParameters *apOpt,
  NSSSymmetricKey *keyToWrap,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    const NSSAlgorithmAndParameters *ap = apOpt ? apOpt : vd->ap;
    if (!ap || vd->mk) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSItem *)NULL;
    }
    /* set the context's symkey to the key to wrap */
    vd->mk = nssSymmetricKey_AddRef(keyToWrap);
    /* initialize the context with the symkey first */
    if (prepare_context_symmetric_key(vd, ap) == PR_FAILURE) {
	/* didn't find a token that could do the operation */
	return (NSSItem *)NULL;
    }
    /* now try to initialize with the public key */
    if (prepare_context_public_key(vd, ap) == PR_FAILURE) {
	/* most likely failed trying to move the pubkey */
	return (NSSItem *)NULL;
    }
    /* do the wrap on the token */
    return nssToken_WrapKey(vd->token, vd->session, ap, vd->bko,
                            vd->mko, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSItem *
NSSVolatileDomain_WrapSymmetricKey (
  NSSVolatileDomain *vd,
  const NSSAlgorithmAndParameters *apOpt,
  NSSSymmetricKey *keyToWrap,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    if (!vd->vk && !vd->cert) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSItem *)NULL;
    }
    return nssVolatileDomain_WrapSymmetricKey(vd, apOpt, keyToWrap,
                                             uhhOpt, rvOpt, arenaOpt);
}
#endif

