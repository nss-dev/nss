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

#ifndef PKIM_H
#include "pkim.h"
#endif /* PKIM_H */

#ifndef PKISTORE_H
#include "pkistore.h"
#endif /* PKISTORE_H */

/* taking from certificate implementation... move to pkim.h? */
NSS_EXTERN PRUint32
nssCertificate_Hash
(
  NSSCertificate *c
);

NSS_EXTERN NSSCertificate *
nssCertificate_CreateIndexCert
(
  NSSDER *issuer,
  NSSDER *serial
);

/* 
 * Certificate Store
 *
 * This differs from the cache in that it is a true storage facility.  Items
 * stay in until they are explicitly removed.  It is only used by crypto
 * contexts at this time, but may be more generally useful...
 *
 */

struct nssCertificateStoreStr 
{
    PRBool i_allocated_arena;
    NSSArena *arena;
    PZLock *lock;
    nssHash *subject;
    nssHash *issuer_and_serial;
};

typedef struct certificate_hash_entry_str certificate_hash_entry;

struct certificate_hash_entry_str
{
    NSSCertificate *cert;
    NSSTrust *trust;
    nssSMIMEProfile *profile;
};

#if 0
/* XXX This a common function that should be moved out, possibly an
 *     nssSubjectCertificateList should be created?
 */
/* sort the subject list from newest to oldest */
static PRIntn subject_list_sort(void *v1, void *v2)
{
    NSSCertificate *c1 = (NSSCertificate *)v1;
    NSSCertificate *c2 = (NSSCertificate *)v2;
    nssDecodedCert *dc1 = nssCertificate_GetDecoding(c1);
    nssDecodedCert *dc2 = nssCertificate_GetDecoding(c2);
    if (dc1->isNewerThan(dc1, dc2)) {
	return -1;
    } else {
	return 1;
    }
}
#endif

struct subject_list_node_str
{
    PRCList link;
    NSSCertificate *cert;
};

struct subject_hash_entry_str
{
    PRCList head;
    PRUint32 count;
    NSSDER *subject;
};

typedef struct subject_hash_entry_str subject_hash_entry;

static subject_hash_entry *
subject_hash_entry_create
(
  NSSDER *subject
)
{
    subject_hash_entry *rvEntry;
    rvEntry = nss_ZNEW(NULL, subject_hash_entry);
    if (rvEntry) {
	PR_INIT_CLIST(&rvEntry->head);
    }
    rvEntry->subject = nssItem_Duplicate(subject, NULL, NULL);
    return rvEntry;
}

static void
subject_hash_entry_destroy
(
  subject_hash_entry *entry
)
{
    nss_ZFreeIf(entry->subject);
    nss_ZFreeIf(entry);
}

static PRStatus
subject_hash_entry_add
(
  subject_hash_entry *entry,
  NSSCertificate *cert
)
{
    struct subject_list_node_str *node;
    PRCList *link = PR_NEXT_LINK(&entry->head);
    /* XXX sort by validity */
    while (link != &entry->head) {
	node = (struct subject_list_node_str *)link;
	if (nssCertificate_IssuerAndSerialEqual(cert, node->cert)) {
	    /* cert already in */
	    return PR_FAILURE;
	}
	link = PR_NEXT_LINK(link);
    }
    node = nss_ZNEW(NULL, struct subject_list_node_str);
    if (!node) {
	return PR_FAILURE;
    }
    PR_INIT_CLIST(&node->link);
    node->cert = cert;
    PR_INSERT_AFTER(&node->link, link);
    entry->count++;
    return PR_SUCCESS;
}

static void
subject_hash_entry_remove
(
  subject_hash_entry *entry,
  NSSCertificate *cert
)
{
    struct subject_list_node_str *node;
    PRCList *link = PR_NEXT_LINK(&entry->head);
    /* XXX sort by validity */
    while (link != &entry->head) {
	node = (struct subject_list_node_str *)link;
	if (node->cert == cert) {
	    PR_REMOVE_LINK(link);
	    entry->count--;
	    break;
	}
	link = PR_NEXT_LINK(link);
    }
}

static void
get_subject_entry_certs
(
  subject_hash_entry *entry, 
  NSSCertificate **array, 
  PRUint32 count
)
{
    PRUint32 i = 0;
    struct subject_list_node_str *node;
    PRCList *link = PR_NEXT_LINK(&entry->head);
    while (link != &entry->head && i < count) {
	node = (struct subject_list_node_str *)link;
	array[i++] = nssCertificate_AddRef(node->cert);
	link = PR_NEXT_LINK(link);
    }
}

NSS_IMPLEMENT nssCertificateStore *
nssCertificateStore_Create
(
  NSSArena *arenaOpt
)
{
    NSSArena *arena;
    nssCertificateStore *store;
    PRBool i_allocated_arena;
    if (arenaOpt) {
	arena = arenaOpt;
	i_allocated_arena = PR_FALSE;
    } else {
	arena = nssArena_Create();
	if (!arena) {
	    return NULL;
	}
	i_allocated_arena = PR_TRUE;
    }
    store = nss_ZNEW(arena, nssCertificateStore);
    if (!store) {
	goto loser;
    }
    store->lock = PZ_NewLock(nssILockOther); /* XXX */
    if (!store->lock) {
	goto loser;
    }
    /* Create the issuer/serial --> {cert, trust, S/MIME profile } hash */
    store->issuer_and_serial = nssHash_CreateCertificate(arena, 0);
    if (!store->issuer_and_serial) {
	goto loser;
    }
    /* Create the subject DER --> subject list hash */
    store->subject = nssHash_CreateItem(arena, 0);
    if (!store->subject) {
	goto loser;
    }
    store->arena = arena;
    store->i_allocated_arena = i_allocated_arena;
    return store;
loser:
    if (store) {
	if (store->lock) {
	    PZ_DestroyLock(store->lock);
	}
	if (store->issuer_and_serial) {
	    nssHash_Destroy(store->issuer_and_serial);
	}
	if (store->subject) {
	    nssHash_Destroy(store->subject);
	}
    }
    if (i_allocated_arena) {
	nssArena_Destroy(arena);
    }
    return NULL;
}

NSS_IMPLEMENT void
nssCertificateStore_Destroy
(
  nssCertificateStore *store
)
{
    PZ_DestroyLock(store->lock);
    nssHash_Destroy(store->issuer_and_serial);
    nssHash_Destroy(store->subject);
    if (store->i_allocated_arena) {
	nssArena_Destroy(store->arena);
    } else {
	nss_ZFreeIf(store);
    }
}

static PRStatus
add_certificate_entry
(
  nssCertificateStore *store,
  NSSCertificate *cert
)
{
    PRStatus status;
    certificate_hash_entry *entry;
    entry = nss_ZNEW(NULL, certificate_hash_entry);
    if (!entry) {
	return PR_FAILURE;
    }
    entry->cert = cert;
    status = nssHash_Add(store->issuer_and_serial, cert, entry);
    if (status != PR_SUCCESS) {
	nss_ZFreeIf(entry);
    }
    return status;
}

static PRStatus
add_subject_entry
(
  nssCertificateStore *store,
  NSSCertificate *cert
)
{
    PRStatus status;
    subject_hash_entry *entry;
    NSSDER *subject = nssCertificate_GetSubject(cert);
    entry = (subject_hash_entry *)nssHash_Lookup(store->subject, subject);
    if (entry) {
	/* The subject is already in, add this cert to the list */
	status = subject_hash_entry_add(entry, cert);
    } else {
	/* Create a new subject list for the subject */
	entry = subject_hash_entry_create(subject);
	if (!entry) {
	    return PR_FAILURE;
	}
	/* Add the cert entry to this list of subjects */
	status = subject_hash_entry_add(entry, cert);
	if (status != PR_SUCCESS) {
	    return status;
	}
	/* Add the subject list to the cache */
	status = nssHash_Add(store->subject, subject, entry);
    }
    return status;
}

/* declared below */
static void
remove_certificate_entry
(
  nssCertificateStore *store,
  NSSCertificate *cert
);

NSS_IMPLEMENT PRStatus
nssCertificateStore_Add
(
  nssCertificateStore *store,
  NSSCertificate *cert
)
{
    PRStatus status;
    PZ_Lock(store->lock);
    if (nssHash_Exists(store->issuer_and_serial, cert)) {
	PZ_Unlock(store->lock);
	return PR_SUCCESS;
    }
    status = add_certificate_entry(store, cert);
    if (status == PR_SUCCESS) {
	status = add_subject_entry(store, cert);
	if (status == PR_SUCCESS) {
	    nssCertificate_AddRef(cert); /* obtain a reference for the store */
	} else {
	    remove_certificate_entry(store, cert);
	}
    }
    PZ_Unlock(store->lock);
    return status;
}

static void
remove_certificate_entry
(
  nssCertificateStore *store,
  NSSCertificate *cert
)
{
    certificate_hash_entry *entry;
    entry = (certificate_hash_entry *)
                             nssHash_Lookup(store->issuer_and_serial, cert);
    if (entry) {
	nssHash_Remove(store->issuer_and_serial, cert);
	if (entry->trust) {
	    nssTrust_Destroy(entry->trust);
	}
	if (entry->profile) {
	    nssSMIMEProfile_Destroy(entry->profile);
	}
	nss_ZFreeIf(entry);
    }
}

static void
remove_subject_entry
(
  nssCertificateStore *store,
  NSSCertificate *cert
)
{
    subject_hash_entry *entry;
    NSSDER *subject = nssCertificate_GetSubject(cert);
    /* Get the subject list for the cert's subject */
    entry = (subject_hash_entry *)nssHash_Lookup(store->subject, subject);
    if (entry) {
	/* Remove the cert from the subject hash */
	subject_hash_entry_remove(entry, cert);
	if (entry->count == 0) {
	    nssHash_Remove(store->subject, subject);
	    subject_hash_entry_destroy(entry);
	}
    }
}

NSS_IMPLEMENT void
nssCertificateStore_Remove
(
  nssCertificateStore *store,
  NSSCertificate *cert
)
{
    certificate_hash_entry *entry;
    PZ_Lock(store->lock);
    entry = (certificate_hash_entry *)
                              nssHash_Lookup(store->issuer_and_serial, cert);
    if (entry && entry->cert == cert) {
	remove_certificate_entry(store, cert);
	remove_subject_entry(store, cert);
	NSSCertificate_Destroy(cert); /* release the store's reference */
    }
    PZ_Unlock(store->lock);
}

static NSSCertificate **
get_certs_from_entry
(
  subject_hash_entry *entry,
  NSSCertificate *rvOpt[],
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    PRUint32 count;
    NSSCertificate **rvArray = NULL;
    if (entry->count == 0) {
	return (NSSCertificate **)NULL;
    }
    if (maximumOpt > 0) {
	count = PR_MIN(maximumOpt, entry->count);
    }
    if (rvOpt) {
	rvArray = rvOpt;
    } else {
	rvArray = nss_ZNEWARRAY(arenaOpt, NSSCertificate *, count + 1);
    }
    if (rvArray) {
	get_subject_entry_certs(entry, rvArray, count);
    }
    return rvArray;
}

NSS_IMPLEMENT NSSCertificate **
nssCertificateStore_FindCertificatesBySubject
(
  nssCertificateStore *store,
  NSSDER *subject,
  NSSCertificate *rvOpt[],
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    NSSCertificate **rvArray = NULL;
    subject_hash_entry *entry;
    PZ_Lock(store->lock);
    entry = (subject_hash_entry *)nssHash_Lookup(store->subject, subject);
    if (entry) {
	rvArray = get_certs_from_entry(entry, rvOpt, maximumOpt, arenaOpt);
    }
    PZ_Unlock(store->lock);
    return rvArray;
}

/* Because only subject indexing is implemented, all other lookups require
 * full traversal (unfortunately, PLHashTable doesn't allow you to exit
 * early from the enumeration).  The assumptions are that 1) lookups by 
 * fields other than subject will be rare, and 2) the hash will not have
 * a large number of entries.  These assumptions will be tested.
 *
 * XXX
 * For NSS 3.4, it is worth consideration to do all forms of indexing,
 * because the only crypto context is global and persistent.
 */

struct nickname_template_str
{
    NSSUTF8 *nickname;
    subject_hash_entry *entry;
};

static void match_nickname(const void *k, void *v, void *a)
{
    PRStatus status;
    NSSUTF8 *nickname;
    struct nickname_template_str *nt = (struct nickname_template_str *)a;
    subject_hash_entry *entry = (subject_hash_entry *)v;
    struct subject_list_node_str *node;
    node = (struct subject_list_node_str *)PR_NEXT_LINK(&entry->head);
    nickname = nssCertificate_GetNickname(node->cert, NULL);
    if (status == PR_SUCCESS && nickname &&
         nssUTF8_Equal(nickname, nt->nickname, &status)) 
    {
	nt->entry = entry;
    }
}

/*
 * Find all cached certs with this label.
 */
NSS_IMPLEMENT NSSCertificate **
nssCertificateStore_FindCertificatesByNickname
(
  nssCertificateStore *store,
  NSSUTF8 *nickname,
  NSSCertificate *rvOpt[],
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    NSSCertificate **rvArray = NULL;
    struct nickname_template_str nt;
    nt.nickname = nickname;
    nt.entry = NULL;
    PZ_Lock(store->lock);
    nssHash_Iterate(store->subject, match_nickname, &nt);
    if (nt.entry) {
	rvArray = get_certs_from_entry(nt.entry, rvOpt, maximumOpt, arenaOpt);
    }
    PZ_Unlock(store->lock);
    return rvArray;
}

struct email_template_str
{
    NSSASCII7 *email;
    NSSArena *arena;
    PRUint32 maximum;
    NSSCertificate **certs;
    PRUint32 numCerts;
};

static void match_email(const void *k, void *v, void *a)
{
    PRStatus status;
    NSSASCII7 *email;
    struct email_template_str *et = (struct email_template_str *)a;
    subject_hash_entry *entry = (subject_hash_entry *)v;
    struct subject_list_node_str *node;
    node = (struct subject_list_node_str *)PR_NEXT_LINK(&entry->head);
    email = nssCertificate_GetEmailAddress(node->cert);
    if (nssUTF8_Equal(email, et->email, &status)) {
	PRUint32 i, count = entry->count;
	if (et->numCerts == 0 && !et->certs) {
	    /* First encounter with matching certs, and need to allocate
	     * an array for them
	     */
	    et->certs = nss_ZNEWARRAY(et->arena, NSSCertificate *, count + 1);
	} else if (et->maximum == 0 && et->certs) {
	    /* Already have matching certs, need to realloc */
	    et->certs = nss_ZREALLOCARRAY(et->certs, 
	                                  NSSCertificate *, 
	                                  et->numCerts + count + 1);
	}
	if (!et->certs) {
	    /* XXX */
	    return;
	}
	if (et->maximum > 0 && et->numCerts + count > et->maximum) {
	    /* would exceed the maximum allowed */
	    count = et->maximum - et->numCerts;
	}
	for (i=0; i<count; i++) {
	    et->certs[et->numCerts++] = nssCertificate_AddRef(node->cert);
	}
    }
}

/*
 * Find all cached certs with this email address.
 */
NSS_IMPLEMENT NSSCertificate **
nssCertificateStore_FindCertificatesByEmail
(
  nssCertificateStore *store,
  NSSASCII7 *email,
  NSSCertificate *rvOpt[],
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    struct email_template_str et;
    et.email = email;
    et.certs = rvOpt;
    et.maximum = maximumOpt;
    et.arena = arenaOpt;
    et.numCerts = 0;
    PZ_Lock(store->lock);
    nssHash_Iterate(store->subject, match_email, &et);
    PZ_Unlock(store->lock);
    return et.certs;
}

NSS_IMPLEMENT NSSCertificate *
nssCertificateStore_FindCertificateByIssuerAndSerialNumber
(
  nssCertificateStore *store,
  NSSDER *issuer,
  NSSDER *serial
)
{
    certificate_hash_entry *entry;
    NSSCertificate *index;
    NSSCertificate *rvCert = NULL;
    index = nssCertificate_CreateIndexCert(issuer, serial);
    PZ_Lock(store->lock);
    entry = (certificate_hash_entry *)
                           nssHash_Lookup(store->issuer_and_serial, &index);
    if (entry) {
	rvCert = nssCertificate_AddRef(entry->cert);
    }
    PZ_Unlock(store->lock);
    nss_ZFreeIf(index);
    return rvCert;
}

#ifdef NSS_3_4_CODE
static PRStatus
issuer_and_serial_from_encoding
(
  NSSBER *encoding, 
  NSSDER *issuer, 
  NSSDER *serial
)
{
    SECItem derCert, derIssuer, derSerial;
    SECStatus secrv;
    derCert.data = (unsigned char *)encoding->data;
    derCert.len = encoding->size;
    secrv = CERT_IssuerNameFromDERCert(&derCert, &derIssuer);
    if (secrv != SECSuccess) {
	return PR_FAILURE;
    }
    secrv = CERT_SerialNumberFromDERCert(&derCert, &derSerial);
    if (secrv != SECSuccess) {
	PORT_Free(derIssuer.data);
	return PR_FAILURE;
    }
    issuer->data = derIssuer.data;
    issuer->size = derIssuer.len;
    serial->data = derSerial.data;
    serial->size = derSerial.len;
    return PR_SUCCESS;
}
#endif

NSS_IMPLEMENT NSSCertificate *
nssCertificateStore_FindCertificateByEncodedCertificate
(
  nssCertificateStore *store,
  NSSDER *encoding
)
{
    PRStatus status = PR_FAILURE;
    NSSDER issuer, serial;
    NSSCertificate *rvCert = NULL;
#ifdef NSS_3_4_CODE
    status = issuer_and_serial_from_encoding(encoding, &issuer, &serial);
#endif
    if (status != PR_SUCCESS) {
	return NULL;
    }
    rvCert = nssCertificateStore_FindCertificateByIssuerAndSerialNumber(store, 
                                                                     &issuer, 
                                                                     &serial);
#ifdef NSS_3_4_CODE
    PORT_Free(issuer.data);
    PORT_Free(serial.data);
#endif
    return rvCert;
}

NSS_EXTERN PRStatus
nssCertificateStore_AddTrust
(
  nssCertificateStore *store,
  NSSTrust *trust
)
{
#if 0
    NSSCertificate *cert;
    certificate_hash_entry *entry;
    cert = trust->certificate;
    PZ_Lock(store->lock);
    entry = (certificate_hash_entry *)
                              nssHash_Lookup(store->issuer_and_serial, cert);
    if (entry) {
	entry->trust = nssTrust_AddRef(trust);
    }
    PZ_Unlock(store->lock);
    return (entry) ? PR_SUCCESS : PR_FAILURE;
#endif
    return PR_FAILURE;
}

NSS_IMPLEMENT NSSTrust *
nssCertificateStore_FindTrustForCertificate
(
  nssCertificateStore *store,
  NSSCertificate *cert
)
{
    certificate_hash_entry *entry;
    NSSTrust *rvTrust = NULL;
    PZ_Lock(store->lock);
    entry = (certificate_hash_entry *)
                              nssHash_Lookup(store->issuer_and_serial, cert);
    if (entry && entry->trust) {
	rvTrust = nssTrust_AddRef(entry->trust);
    }
    PZ_Unlock(store->lock);
    return rvTrust;
}

NSS_EXTERN PRStatus
nssCertificateStore_AddSMIMEProfile
(
  nssCertificateStore *store,
  nssSMIMEProfile *profile
)
{
#if 0
    NSSCertificate *cert;
    certificate_hash_entry *entry;
    cert = profile->certificate;
    PZ_Lock(store->lock);
    entry = (certificate_hash_entry *)
                              nssHash_Lookup(store->issuer_and_serial, cert);
    if (entry) {
	entry->profile = nssSMIMEProfile_AddRef(profile);
    }
    PZ_Unlock(store->lock);
    return (entry) ? PR_SUCCESS : PR_FAILURE;
#endif
    return PR_FAILURE;
}

NSS_IMPLEMENT nssSMIMEProfile *
nssCertificateStore_FindSMIMEProfileForCertificate
(
  nssCertificateStore *store,
  NSSCertificate *cert
)
{
    certificate_hash_entry *entry;
    nssSMIMEProfile *rvProfile = NULL;
    PZ_Lock(store->lock);
    entry = (certificate_hash_entry *)
                              nssHash_Lookup(store->issuer_and_serial, cert);
    if (entry && entry->profile) {
	rvProfile = nssSMIMEProfile_AddRef(entry->profile);
    }
    PZ_Unlock(store->lock);
    return rvProfile;
}

static PLHashNumber
nss_certificate_hash(const void *c)
{
    return (PLHashNumber)nssCertificate_Hash((NSSCertificate *)c);
}

static int
nss_compare_certs(const void *v1, const void *v2)
{
    return nssCertificate_IssuerAndSerialEqual((NSSCertificate *)v1,
                                               (NSSCertificate *)v2);
}

NSS_IMPLEMENT nssHash *
nssHash_CreateCertificate
(
  NSSArena *arenaOpt,
  PRUint32 numBuckets
)
{
    return nssHash_Create(arenaOpt, 
                          numBuckets, 
                          nss_certificate_hash, 
                          nss_compare_certs, 
                          PL_CompareValues);
}

NSS_IMPLEMENT void
nssCertificateStore_DumpStoreInfo
(
  nssCertificateStore *store,
  void (* cert_dump_iter)(const void *, void *, void *),
  void *arg
)
{
    PZ_Lock(store->lock);
    nssHash_Iterate(store->issuer_and_serial, cert_dump_iter, arg);
    PZ_Unlock(store->lock);
}

