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

#include "pki1.h" /* XXX */
#include "oiddata.h"

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

  nssTokenSessionHash *tokenSessionHash;

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
    rvVD->tokenSessionHash = nssTokenSessionHash_Create();
    if (!rvVD->tokenSessionHash) {
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
    nssTokenSessionHash_Destroy(vd->tokenSessionHash);
    nssCertArray_Destroy((NSSCert **)vd->certs.array);
    nssPublicKeyArray_Destroy((NSSPublicKey **)vd->bkeys.array);
    nssPrivateKeyArray_Destroy((NSSPrivateKey **)vd->vkeys.array);
    nssSymKeyArray_Destroy((NSSSymKey **)vd->mkeys.array);
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
nssVolatileDomain_ImportCert (
  NSSVolatileDomain *vd,
  NSSCert *c
)
{
    PZ_Lock(vd->objectLock);
    if (vd->certs.count == vd->certs.size) {
	if (vd->certs.size == 0) {
	    /* need to alloc new array */
	    vd->certs.array = (void **)nss_ZNEWARRAY(vd->arena, 
	                                             NSSCert *, 
	                                             DEFAULT_ARRAY_SIZE);
	} else {
	    /* array is full, realloc */
	    vd->certs.size *= 2;
	    vd->certs.array = (void **)nss_ZREALLOCARRAY(vd->certs.array, 
	                                                 NSSCert *, 
	                                                 vd->certs.size);
	}
	if (!vd->certs.array) {
	    PZ_Unlock(vd->objectLock);
	    return PR_FAILURE;
	}
    }
    vd->certs.array[vd->certs.count++] = (void *)nssCert_AddRef(c);
    PZ_Unlock(vd->objectLock);
    nssCert_SetVolatileDomain(c, vd);
    return PR_SUCCESS;
}

NSS_IMPLEMENT PRStatus
NSSVolatileDomain_ImportCert (
  NSSVolatileDomain *vd,
  NSSCert *c
)
{
    return nssVolatileDomain_ImportCert(vd, c);
}

NSS_IMPLEMENT NSSCert *
nssVolatileDomain_ImportEncodedCert (
  NSSVolatileDomain *vd,
  NSSBER *ber,
  NSSUTF8 *nickOpt
)
{
    NSSCert *c;

    c = nssCert_Decode(ber);
    if (!c) {
	return (NSSCert *)NULL;
    }
    if (nickOpt) {
	nssCert_SetNickname(c, NULL, nickOpt);
    }
    if (nssVolatileDomain_ImportCert(vd, c) == PR_FAILURE) {
	nssCert_Destroy(c);
	return (NSSCert *)NULL;
    }
    return c;
}

NSS_IMPLEMENT NSSCert *
NSSVolatileDomain_ImportEncodedCert (
  NSSVolatileDomain *vd,
  NSSBER *ber,
  NSSUTF8 *nickOpt
)
{
    return nssVolatileDomain_ImportEncodedCert(vd, ber, nickOpt);
}

NSS_IMPLEMENT PRStatus
NSSVolatileDomain_ImportEncodedCertChain (
  NSSVolatileDomain *vd,
  NSSBER *ber,
  NSSCertType certType
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return PR_FAILURE;
}

NSS_IMPLEMENT NSSPrivateKey *
nssVolatileDomain_ImportEncodedPrivateKey (
  NSSVolatileDomain *vd,
  NSSBER *ber,
  NSSOID *keyPairAlg,
  NSSOperations operations,
  NSSProperties properties,
  NSSUTF8 *passwordOpt,
  NSSCallback *uhhOpt,
  NSSToken *destination
)
{
    return nssPrivateKey_Decode(ber, keyPairAlg, 
                                operations, properties, 
                                passwordOpt, uhhOpt, destination, 
                                vd->td, vd);
}

NSS_IMPLEMENT NSSPrivateKey *
NSSVolatileDomain_ImportEncodedPrivateKey (
  NSSVolatileDomain *vd,
  NSSBER *ber,
  NSSOID *keyPairAlg,
  NSSOperations operations,
  NSSProperties properties,
  NSSUTF8 *passwordOpt,
  NSSCallback *uhhOpt,
  NSSToken *destination
)
{
    return nssVolatileDomain_ImportEncodedPrivateKey(vd, ber, keyPairAlg,
                                                     operations,
                                                     properties,
                                                     passwordOpt, uhhOpt,
                                                     destination);
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
	vd->certStore = nssCertStore_Create(vd->arena);
	if (!vd->certStore) {
	    return PR_FAILURE;
	}
    }
    nssrv = nssCertStore_AddSMIMEProfile(vd->certStore, profile);
#if 0
    if (nssrv == PR_SUCCESS) {
	profile->object.cryptoContext = vd;
    }
#endif
    return nssrv;
}
#endif

struct cert_array_str {
  NSSCert **array;
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
add_to_cert_array(struct cert_array_str *car, NSSCert *c)
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
	car->array = nss_ZNEWARRAY(car->arenaOpt, NSSCert *, 
	                           car->size + 1);
    } else if (car->count == car->size) {
	if (!car->grow) {
	    return PR_FAILURE; /* this will terminate the loop */
	}
	car->size *= 2;
	car->array = nss_ZREALLOCARRAY(car->array, NSSCert *, 
	                               car->size + 1);
    }
    if (!car->array) {
	return PR_FAILURE;
    }
    car->array[car->count++] = nssCert_AddRef(c);
    return PR_SUCCESS;
}

static NSSCert **
finish_cert_array(struct cert_array_str *car, PRStatus status,
                  NSSCert **tdCerts)
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
	    car->array = nssCertArray_Join(car->array, tdCerts);
	}
	nssArena_Unmark(car->arenaOpt, car->mark);
    }

    return car->array;
}

NSS_IMPLEMENT NSSCert **
nssVolatileDomain_FindCertsByNickname (
  NSSVolatileDomain *vd,
  NSSUTF8 *name,
  NSSCert **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    PRStatus status;
    PRUint32 i;
    NSSCert **certs, **tdCerts;
    NSSUTF8 *cNick;
    struct cert_array_str cert_array;

    INIT_CERT_ARRAY(&cert_array, rvOpt, maximumOpt, arenaOpt);

    PZ_Lock(vd->objectLock);
    certs = (NSSCert **)vd->certs.array;
    for (i=0; i<vd->certs.count; i++) {
	cNick = nssCert_GetNickname(certs[i], NULL);
	if (nssUTF8_Equal(name, cNick, NULL)) { 
	    status = add_to_cert_array(&cert_array, certs[i]);
	    if (status == PR_FAILURE) {
		break;
	    }
	}
    }
    PZ_Unlock(vd->objectLock);

    tdCerts = nssTrustDomain_FindCertsByNickname(vd->td, name, 
                                   rvOpt ? rvOpt + cert_array.count : NULL,
                                   maximumOpt - cert_array.count, arenaOpt);

    return finish_cert_array(&cert_array, status, tdCerts);
}

NSS_IMPLEMENT NSSCert **
NSSVolatileDomain_FindCertsByNickname (
  NSSVolatileDomain *vd,
  NSSUTF8 *name,
  NSSCert *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
)
{
    return nssVolatileDomain_FindCertsByNickname(vd, name, rvOpt,
                                                        maximumOpt, arenaOpt);
}

NSS_IMPLEMENT NSSCert *
nssVolatileDomain_FindBestCertByNickname (
  NSSVolatileDomain *vd,
  NSSUTF8 *name,
  NSSTime time, /* NULL for "now" */
  NSSUsages *usages,
  NSSPolicies *policiesOpt /* NULL for none */
)
{
    NSSCert **certs;
    NSSCert *rvCert = NULL;

    /* search the volatile (and trust) domain by nickname */
    certs = nssVolatileDomain_FindCertsByNickname(vd, name, 
                                                         NULL, 0, NULL);
    if (certs) {
	/* find the best one */
	rvCert = nssCertArray_FindBestCert(certs, time, 
	                                                 usages, policiesOpt);
	nssCertArray_Destroy(certs);
    }
    return rvCert;
}

NSS_IMPLEMENT NSSCert *
NSSVolatileDomain_FindBestCertByNickname (
  NSSVolatileDomain *vd,
  NSSUTF8 *name,
  NSSTime time, /* NULL for "now" */
  NSSUsages *usages,
  NSSPolicies *policiesOpt /* NULL for none */
)
{
    return nssVolatileDomain_FindBestCertByNickname(vd, name,
                                                           time, usages,
                                                           policiesOpt);
}

NSS_IMPLEMENT NSSCert *
nssVolatileDomain_FindCertByIssuerAndSerialNumber (
  NSSVolatileDomain *vd,
  NSSDER *issuer,
  NSSDER *serial
)
{
    PRUint32 i;
    NSSCert **certs;
    NSSDER *cIssuer, *cSerial;
    NSSCert *rvCert = NULL;

    PZ_Lock(vd->objectLock);
    certs = (NSSCert **)vd->certs.array;
    for (i=0; i<vd->certs.count; i++) {
	cIssuer = nssCert_GetIssuer(certs[i]);
	cSerial = nssCert_GetSerialNumber(certs[i]);
	if (nssItem_Equal(cIssuer, issuer, NULL) &&
	    nssItem_Equal(cSerial, serial, NULL)) 
	{
	    rvCert = nssCert_AddRef(certs[i]);
	    break;
	}
    }
    PZ_Unlock(vd->objectLock);
    if (!rvCert) {
	rvCert = nssTrustDomain_FindCertByIssuerAndSerialNumber(vd->td,
	                                                      issuer, serial);
    }
    return rvCert;
}

NSS_IMPLEMENT NSSCert *
NSSVolatileDomain_FindCertByIssuerAndSerialNumber (
  NSSVolatileDomain *vd,
  NSSDER *issuer,
  NSSDER *serial
)
{
    return nssVolatileDomain_FindCertByIssuerAndSerialNumber(vd,
                                                                    issuer,
                                                                    serial);
}

NSS_IMPLEMENT NSSCert **
nssVolatileDomain_FindCertsBySubject (
  NSSVolatileDomain *vd,
  NSSDER *subject,
  NSSCert *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
)
{
    PRStatus status;
    PRUint32 i;
    NSSCert **certs, **tdCerts;
    NSSDER *certSubject;
    struct cert_array_str cert_array;

    INIT_CERT_ARRAY(&cert_array, rvOpt, maximumOpt, arenaOpt);

    PZ_Lock(vd->objectLock);
    certs = (NSSCert **)vd->certs.array;
    for (i=0; i<vd->certs.count; i++) {
	certSubject = nssCert_GetSubject(certs[i]);
	if (nssItem_Equal(certSubject, subject, NULL)) {
	    status = add_to_cert_array(&cert_array, certs[i]);
	    if (status == PR_FAILURE) {
		break;
	    }
	}
    }
    PZ_Unlock(vd->objectLock);

    tdCerts = nssTrustDomain_FindCertsBySubject(vd->td, subject, 
                                   rvOpt ? rvOpt + cert_array.count : NULL,
                                   maximumOpt - cert_array.count, arenaOpt);

    return finish_cert_array(&cert_array, status, tdCerts);
}

NSS_IMPLEMENT NSSCert **
NSSVolatileDomain_FindCertsBySubject (
  NSSVolatileDomain *vd,
  NSSDER *subject,
  NSSCert *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
)
{
    return nssVolatileDomain_FindCertsBySubject(vd, subject,
                                                      rvOpt, maximumOpt,
                                                      arenaOpt);
}

NSS_IMPLEMENT NSSCert *
nssVolatileDomain_FindBestCertBySubject (
  NSSVolatileDomain *vd,
  NSSDER *subject,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt
)
{
    NSSCert **certs;
    NSSCert *rvCert = NULL;

    /* search the volatile (and trust) domain by subject */
    certs = nssVolatileDomain_FindCertsBySubject(vd, subject, 
                                                          NULL, 0, NULL);
    if (certs) {
	/* find the best one */
	rvCert = nssCertArray_FindBestCert(certs, time, 
	                                                 usages, policiesOpt);
	nssCertArray_Destroy(certs);
    }
    return rvCert;
}

NSS_IMPLEMENT NSSCert *
NSSVolatileDomain_FindBestCertBySubject (
  NSSVolatileDomain *vd,
  NSSDER *subject,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt
)
{
    return nssVolatileDomain_FindBestCertBySubject(vd, subject,
                                                time, usages, policiesOpt);
}

NSS_IMPLEMENT NSSCert *
nssVolatileDomain_FindCertByEncodedCert (
  NSSVolatileDomain *vd,
  NSSBER *encodedCert
)
{
    PRUint32 i;
    NSSBER *certEnc;
    NSSCert **certs;
    NSSCert *rvCert = NULL;

    PZ_Lock(vd->objectLock);
    certs = (NSSCert **)vd->certs.array;
    for (i=0; i<vd->certs.count; i++) {
	certEnc = nssCert_GetEncoding(certs[i]);
	if (nssItem_Equal(certEnc, encodedCert, NULL)) {
	    rvCert = nssCert_AddRef(certs[i]);
	    break;
	}
    }
    PZ_Unlock(vd->objectLock);
    if (!rvCert) {
	rvCert = nssTrustDomain_FindCertByEncodedCert(vd->td,
	                                                      encodedCert);
    }
    return rvCert;
}

NSS_IMPLEMENT NSSCert *
NSSVolatileDomain_FindCertByEncodedCert (
  NSSVolatileDomain *vd,
  NSSBER *encodedCert
)
{
    return nssVolatileDomain_FindCertByEncodedCert(vd,
                                                          encodedCert);
}

NSS_IMPLEMENT NSSCert **
nssVolatileDomain_FindCertsByEmail (
  NSSVolatileDomain *vd,
  NSSASCII7 *email,
  NSSCert *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
)
{
    PRStatus status;
    PRUint32 i;
    NSSCert **certs, **tdCerts;
    NSSASCII7 *cEmail;
    struct cert_array_str cert_array;

    INIT_CERT_ARRAY(&cert_array, rvOpt, maximumOpt, arenaOpt);

    PZ_Lock(vd->objectLock);
    certs = (NSSCert **)vd->certs.array;
    for (i=0; i<vd->certs.count; i++) {
	cEmail = nssCert_GetEmailAddress(certs[i]);
	if (nssUTF8_Equal(cEmail, email, NULL)) {
	    status = add_to_cert_array(&cert_array, certs[i]);
	    if (status == PR_FAILURE) {
		break;
	    }
	}
    }
    PZ_Unlock(vd->objectLock);

    tdCerts = nssTrustDomain_FindCertsByEmail(vd->td, email, 
                                   rvOpt ? rvOpt + cert_array.count : NULL,
                                   maximumOpt - cert_array.count, arenaOpt);

    return finish_cert_array(&cert_array, status, tdCerts);
}

NSS_IMPLEMENT NSSCert **
NSSVolatileDomain_FindCertsByEmail (
  NSSVolatileDomain *vd,
  NSSASCII7 *email,
  NSSCert *rvOpt[],
  PRUint32 maximumOpt, /* 0 for no max */
  NSSArena *arenaOpt
)
{
    return nssVolatileDomain_FindCertsByEmail(vd, email, rvOpt,
                                                     maximumOpt, arenaOpt);
}

NSS_IMPLEMENT NSSCert *
nssVolatileDomain_FindBestCertByEmail (
  NSSVolatileDomain *vd,
  NSSASCII7 *email,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt
)
{
    NSSCert **certs;
    NSSCert *rvCert = NULL;

    /* search the volatile domain by email */
    certs = nssVolatileDomain_FindCertsByEmail(vd, email, 
                                                      NULL, 0, NULL);
    if (certs) {
	/* find the best one */
	rvCert = nssCertArray_FindBestCert(certs, time, 
	                                                 usages, policiesOpt);
	nssCertArray_Destroy(certs);
    }
    return rvCert;
}

NSS_IMPLEMENT NSSCert *
NSSVolatileDomain_FindBestCertByEmail (
  NSSVolatileDomain *vd,
  NSSASCII7 *email,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt
)
{
    return nssVolatileDomain_FindBestCertByEmail(vd, email,
                                              time, usages, policiesOpt);
}

NSS_IMPLEMENT NSSCert *
NSSVolatileDomain_FindBestUserCert (
  NSSVolatileDomain *vd,
  NSSTime time,
  NSSUsages *usages,
  NSSPolicies *policiesOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCert **
NSSVolatileDomain_FindUserCerts (
  NSSVolatileDomain *vd,
  NSSTime time,
  NSSUsages *usagesOpt,
  NSSPolicies *policiesOpt,
  NSSCert **rvOpt,
  PRUint32 rvLimit, /* zero for no limit */
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCert *
NSSVolatileDomain_FindBestUserCertForSSLClientAuth (
  NSSVolatileDomain *vd,
  NSSUTF8 *sslHostOpt,
  NSSDER *rootCAsOpt[], /* null pointer for none */
  PRUint32 rootCAsMaxOpt, /* zero means list is null-terminated */
  const NSSAlgNParam *apOpt,
  NSSPolicies *policiesOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCert **
NSSVolatileDomain_FindUserCertsForSSLClientAuth (
  NSSVolatileDomain *vd,
  NSSUTF8 *sslHostOpt,
  NSSDER *rootCAsOpt[], /* null pointer for none */
  PRUint32 rootCAsMaxOpt, /* zero means list is null-terminated */
  const NSSAlgNParam *apOpt,
  NSSPolicies *policiesOpt,
  NSSCert **rvOpt,
  PRUint32 rvLimit, /* zero for no limit */
  NSSArena *arenaOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCert *
NSSVolatileDomain_FindBestUserCertForEmailSigning (
  NSSVolatileDomain *vd,
  NSSASCII7 *signerOpt,
  NSSASCII7 *recipientOpt,
  /* anything more here? */
  const NSSAlgNParam *apOpt,
  NSSPolicies *policiesOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSCert *
NSSVolatileDomain_FindUserCertsForEmailSigning (
  NSSVolatileDomain *vd,
  NSSASCII7 *signerOpt, /* fgmr or a more general name? */
  NSSASCII7 *recipientOpt,
  /* anything more here? */
  const NSSAlgNParam *apOpt,
  NSSPolicies *policiesOpt,
  NSSCert **rvOpt,
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
  const NSSAlgNParam *ap,
  NSSPrivateKey **pvkOpt,
  NSSPublicKey **pbkOpt,
  PRBool privateKeyIsSensitive,
  NSSToken *destination,
  NSSCallback *uhhOpt
)
{
    nssPKIObjectCreator creator;

    creator.td = vd->td;
    creator.vd = vd;
    creator.destination = destination;
    creator.session = nssTokenSessionHash_GetSession(vd->tokenSessionHash,
                                                     destination, PR_FALSE);
    if (!creator.session) {
	return PR_FAILURE;
    }
    creator.persistent = PR_FALSE;
    creator.ap = ap;
    creator.uhh = uhhOpt ? uhhOpt : vd->callback;
    creator.nickname = NULL /*nicknameOpt*/;
    creator.properties = 0 /*properties*/;
    creator.operations = 0 /*operations*/;
    return nssPKIObjectCreator_GenerateKeyPair(&creator, pbkOpt, pvkOpt);
}

NSS_IMPLEMENT PRStatus
NSSVolatileDomain_GenerateKeyPair (
  NSSVolatileDomain *vd,
  const NSSAlgNParam *ap,
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

NSS_IMPLEMENT NSSSymKey *
nssVolatileDomain_GenerateSymKey (
  NSSVolatileDomain *vd,
  const NSSAlgNParam *ap,
  PRUint32 keysize,
  const NSSUTF8 *nicknameOpt,
  NSSOperations operations,
  NSSProperties properties,
  NSSToken *destination,
  NSSCallback *uhhOpt
)
{
    nssPKIObjectCreator creator;

    creator.td = vd->td;
    creator.vd = vd;
    creator.destination = destination;
    creator.session = nssTokenSessionHash_GetSession(vd->tokenSessionHash,
                                                     destination, PR_FALSE);
    if (!creator.session) {
	return (NSSSymKey *)NULL;
    }
    creator.persistent = PR_FALSE;
    creator.ap = ap;
    creator.uhh = uhhOpt ? uhhOpt : vd->callback;
    creator.nickname = nicknameOpt;
    creator.properties = properties;
    creator.operations = operations;
    return nssPKIObjectCreator_GenerateSymKey(&creator, keysize);
}

NSS_IMPLEMENT NSSSymKey *
NSSVolatileDomain_GenerateSymKey (
  NSSVolatileDomain *vd,
  const NSSAlgNParam *ap,
  PRUint32 keysize,
  const NSSUTF8 *labelOpt,
  NSSOperations operations,
  NSSProperties properties,
  NSSToken *destination,
  NSSCallback *uhhOpt
)
{
    return nssVolatileDomain_GenerateSymKey(vd, ap, keysize,
                                                 labelOpt, 
                                                 operations, properties,
                                                 destination, uhhOpt);
}

NSS_IMPLEMENT NSSSymKey *
NSSVolatileDomain_GenerateSymKeyFromPassword (
  NSSVolatileDomain *vd,
  const NSSAlgNParam *ap,
  NSSUTF8 *passwordOpt, /* if null, prompt */
  NSSToken *destinationOpt,
  NSSCallback *uhhOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

NSS_IMPLEMENT NSSSymKey *
NSSVolatileDomain_FindSymKeyByAlgorithmAndKeyID (
  NSSVolatileDomain *vd,
  NSSOID *algorithm,
  NSSItem *keyID,
  NSSCallback *uhhOpt
)
{
    nss_SetError(NSS_ERROR_NOT_FOUND);
    return NULL;
}

/* XXX at a lower layer, or with OID? */
static NSSSymKeyType
get_sym_key_type(const NSSOID *symKeyAlg)
{
    switch (nssOID_GetTag(symKeyAlg)) {
    case NSS_OID_DES_ECB:
    case NSS_OID_DES_CBC:
    case NSS_OID_DES_MAC:
	return NSSSymKeyType_DES;
    case NSS_OID_DES_EDE3_CBC:
	return NSSSymKeyType_TripleDES;
    case NSS_OID_RC2_CBC:
	return NSSSymKeyType_RC2;
    case NSS_OID_RC4:
	return NSSSymKeyType_RC4;
    default:
	return NSSSymKeyType_Unknown;
    }
}

NSS_IMPLEMENT NSSSymKey *
nssVolatileDomain_UnwrapSymKey (
  NSSVolatileDomain *vd,
  const NSSAlgNParam *ap,
  NSSPrivateKey *wrapKey,
  NSSItem *wrappedKey,
  const NSSOID *targetKeyAlg,
  NSSCallback *uhhOpt,
  NSSOperations operations,
  NSSProperties properties
)
{
    nssCryptokiObject *vko, *mko;
    NSSSymKey *mkey = NULL;
    NSSSymKeyType keyType = get_sym_key_type(targetKeyAlg);

    /* find a token to do it on */
    vko = nssPrivateKey_FindInstanceForAlgorithm(wrapKey, ap);
    if (!vko) {
	return (NSSSymKey *)NULL;
    }
    /* do the unwrap for a session object */
    mko = nssToken_UnwrapSymKey(vko->token, vko->session, ap, vko,
                                      wrappedKey, PR_FALSE, 
                                      operations, properties, keyType);
    /* done with the private key */
    nssCryptokiObject_Destroy(vko);
    /* create a new symkey in the volatile domain */
    if (mko) {
	mkey = nssSymKey_CreateFromInstance(mko, vd->td, vd);
	if (!mkey) {
	    nssCryptokiObject_Destroy(mko);
	}
    }
    return mkey;
}

NSS_IMPLEMENT NSSSymKey *
NSSVolatileDomain_UnwrapSymKey (
  NSSVolatileDomain *vd,
  const NSSAlgNParam *ap,
  NSSPrivateKey *wrapKey,
  NSSItem *wrappedKey,
  const NSSOID *targetKeyAlg,
  NSSCallback *uhhOpt,
  NSSOperations operations,
  NSSProperties properties
)
{
    return nssVolatileDomain_UnwrapSymKey(vd, ap, wrapKey,
                                                wrappedKey, targetKeyAlg,
                                                uhhOpt, operations, 
                                                properties);
}

NSS_IMPLEMENT NSSSymKey *
NSSVolatileDomain_DeriveSymKey (
  NSSVolatileDomain *vd,
  NSSPublicKey *bk,
  const NSSAlgNParam *apOpt,
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
nssVolatileDomain_WrapSymKey (
  NSSVolatileDomain *vd,
  const NSSAlgNParam *apOpt,
  NSSSymKey *keyToWrap,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    const NSSAlgNParam *ap = apOpt ? apOpt : vd->ap;
    if (!ap || vd->mk) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSItem *)NULL;
    }
    /* set the context's symkey to the key to wrap */
    vd->mk = nssSymKey_AddRef(keyToWrap);
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
NSSVolatileDomain_WrapSymKey (
  NSSVolatileDomain *vd,
  const NSSAlgNParam *apOpt,
  NSSSymKey *keyToWrap,
  NSSCallback *uhhOpt,
  NSSItem *rvOpt,
  NSSArena *arenaOpt
)
{
    if (!vd->vk && !vd->cert) {
	nss_SetError(NSS_ERROR_INVALID_CRYPTO_CONTEXT);
	return (NSSItem *)NULL;
    }
    return nssVolatileDomain_WrapSymKey(vd, apOpt, keyToWrap,
                                             uhhOpt, rvOpt, arenaOpt);
}
#endif

