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

/* taking from certificate implementation... move to pkim.h? */
NSS_EXTERN PRUint32
nssCert_Hash (
  NSSCert *c
);

NSS_EXTERN NSSCert *
nssCert_CreateIndexCert (
  NSSDER *issuer,
  NSSDER *serial
);

/* 
 * Cert Store
 *
 */

struct nssCertStoreStr 
{
    PRBool i_allocated_arena;
    NSSArena *arena;
    PZLock *lock;
    nssHash *subject;
    nssHash *issuer_and_serial;
};

#if 0
/* XXX This a common function that should be moved out, possibly an
 *     nssSubjectCertList should be created?
 */
/* sort the subject list from newest to oldest */
static PRIntn subject_list_sort(void *v1, void *v2)
{
    NSSCert *c1 = (NSSCert *)v1;
    NSSCert *c2 = (NSSCert *)v2;
    nssDecodedCert *dc1 = nssCert_GetDecoding(c1);
    nssDecodedCert *dc2 = nssCert_GetDecoding(c2);
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
    NSSCert *cert;
};

struct subject_hash_entry_str
{
    PRCList head;
    PRUint32 count;
    NSSDER *subject;
};

typedef struct subject_hash_entry_str subject_hash_entry;

static subject_hash_entry *
subject_hash_entry_create (
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
subject_hash_entry_destroy (
  subject_hash_entry *entry
)
{
    nss_ZFreeIf(entry->subject);
    nss_ZFreeIf(entry);
}

static PRStatus
subject_hash_entry_add (
  subject_hash_entry *entry,
  NSSCert *cert
)
{
    struct subject_list_node_str *node;
    PRCList *link = PR_NEXT_LINK(&entry->head);
    /* XXX sort by validity */
    while (link != &entry->head) {
	node = (struct subject_list_node_str *)link;
	if (nssCert_IssuerAndSerialEqual(cert, node->cert)) {
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
subject_hash_entry_remove (
  subject_hash_entry *entry,
  NSSCert *cert
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
get_subject_entry_certs (
  subject_hash_entry *entry, 
  NSSCert **array, 
  PRUint32 count
)
{
    PRUint32 i = 0;
    struct subject_list_node_str *node;
    PRCList *link = PR_NEXT_LINK(&entry->head);
    while (link != &entry->head && i < count) {
	node = (struct subject_list_node_str *)link;
	array[i++] = nssCert_AddRef(node->cert);
	link = PR_NEXT_LINK(link);
    }
}

static nssCertStore *
nssCertStore_Create (
  NSSArena *arenaOpt
)
{
    NSSArena *arena;
    nssCertStore *store;
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
    store = nss_ZNEW(arena, nssCertStore);
    if (!store) {
	goto loser;
    }
    store->lock = PZ_NewLock(nssILockOther); /* XXX */
    if (!store->lock) {
	goto loser;
    }
    /* Create the issuer/serial --> {cert, trust, S/MIME profile } hash */
    store->issuer_and_serial = nssHash_CreateCert(arena, 0);
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

static void
nssCertStore_Destroy (
  nssCertStore *store
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
add_subject_entry (
  nssCertStore *store,
  NSSCert *cert
)
{
    PRStatus status;
    subject_hash_entry *entry;
    NSSDER *subject = nssCert_GetSubject(cert);
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

static PRStatus
nssCertStore_AddCert (
  nssCertStore *store,
  NSSCert *cert
)
{
    PRStatus status;
    PZ_Lock(store->lock);
    if (nssHash_Exists(store->issuer_and_serial, cert)) {
	PZ_Unlock(store->lock);
	return PR_SUCCESS;
    }
    status = nssHash_Add(store->issuer_and_serial, cert, cert);
    if (status == PR_SUCCESS) {
	status = add_subject_entry(store, cert);
	if (status == PR_SUCCESS) {
	    nssCert_AddRef(cert); /* obtain a reference for the store */
	} else {
	    nssHash_Remove(store->issuer_and_serial, cert);
	}
    }
    PZ_Unlock(store->lock);
    return status;
}

static void
remove_subject_entry (
  nssCertStore *store,
  NSSCert *cert
)
{
    subject_hash_entry *entry;
    NSSDER *subject = nssCert_GetSubject(cert);
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

static void
nssCertStore_RemoveCert (
  nssCertStore *store,
  NSSCert *cert
)
{
    NSSCert *entry;
    PZ_Lock(store->lock);
    entry = nssHash_Lookup(store->issuer_and_serial, cert);
    if (entry) {
	nssHash_Remove(store->issuer_and_serial, entry);
	remove_subject_entry(store, entry);
	nssCert_Destroy(entry); /* release the store's reference */
    }
    PZ_Unlock(store->lock);
}

static NSSCert **
get_certs_from_entry (
  subject_hash_entry *entry,
  NSSCert *rvOpt[],
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    PRUint32 count;
    NSSCert **rvArray = NULL;
    if (entry->count == 0) {
	return (NSSCert **)NULL;
    }
    if (maximumOpt > 0) {
	count = PR_MIN(maximumOpt, entry->count);
    } else {
	count = entry->count;
    }
    if (rvOpt) {
	rvArray = rvOpt;
    } else {
	rvArray = nss_ZNEWARRAY(arenaOpt, NSSCert *, count + 1);
    }
    if (rvArray) {
	get_subject_entry_certs(entry, rvArray, count);
    }
    return rvArray;
}

static NSSCert **
nssCertStore_FindCertsBySubject (
  nssCertStore *store,
  NSSBER *subject,
  NSSCert **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    NSSCert **rvArray = NULL;
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
    NSSUTF8 *nickname;
    struct nickname_template_str *nt = (struct nickname_template_str *)a;
    subject_hash_entry *entry = (subject_hash_entry *)v;
    struct subject_list_node_str *node;
    node = (struct subject_list_node_str *)PR_NEXT_LINK(&entry->head);
    nickname = nssCert_GetNickname(node->cert, NULL);
    if (nickname && nssUTF8_Equal(nickname, nt->nickname, NULL))
    {
	nt->entry = entry;
    }
}

/*
 * Find all cached certs with this label.
 */
static NSSCert **
nssCertStore_FindCertsByNickname (
  nssCertStore *store,
  NSSUTF8 *nickname,
  NSSCert *rvOpt[],
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    NSSCert **rvArray = NULL;
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
    NSSCert **certs;
    PRUint32 numCerts;
};

static void match_email(const void *k, void *v, void *a)
{
    NSSASCII7 *email;
    struct email_template_str *et = (struct email_template_str *)a;
    subject_hash_entry *entry = (subject_hash_entry *)v;
    struct subject_list_node_str *node;
    node = (struct subject_list_node_str *)PR_NEXT_LINK(&entry->head);
    email = nssCert_GetEmailAddress(node->cert);
    if (nssUTF8_Equal(email, et->email, NULL)) {
	PRUint32 i, count = entry->count;
	if (et->numCerts == 0 && !et->certs) {
	    /* First encounter with matching certs, and need to allocate
	     * an array for them
	     */
	    et->certs = nss_ZNEWARRAY(et->arena, NSSCert *, count + 1);
	} else if (et->maximum == 0 && et->certs) {
	    /* Already have matching certs, need to realloc */
	    et->certs = nss_ZREALLOCARRAY(et->certs, 
	                                  NSSCert *, 
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
	    et->certs[et->numCerts++] = nssCert_AddRef(node->cert);
	}
    }
}

/*
 * Find all cached certs with this email address.
 */
static NSSCert **
nssCertStore_FindCertsByEmail (
  nssCertStore *store,
  NSSASCII7 *email,
  NSSCert *rvOpt[],
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

static NSSCert *
nssCertStore_FindCertByIssuerAndSerialNumber (
  nssCertStore *store,
  NSSDER *issuer,
  NSSDER *serial
)
{
    NSSCert *index;
    NSSCert *rvCert = NULL;
    index = nssCert_CreateIndexCert(issuer, serial);
    PZ_Lock(store->lock);
    rvCert = (NSSCert *)nssHash_Lookup(store->issuer_and_serial, index);
    if (rvCert) nssCert_AddRef(rvCert);
    PZ_Unlock(store->lock);
    nss_ZFreeIf(index);
    return rvCert;
}

struct encoding_template_str
{
  NSSCert *cert;
  NSSBER *ber;
};

static void match_encoding(const void *k, void *v, void *a)
{
    NSSCert *c = (NSSCert *)v;
    struct encoding_template_str *et = (struct encoding_template_str *)a;
    NSSBER *ber = nssCert_GetEncoding(c);
    if (nssItem_Equal(ber, et->ber, NULL))
	et->cert = nssCert_AddRef(c);
}

static NSSCert *
nssCertStore_FindCertByEncodedCert (
  nssCertStore *store,
  NSSDER *encoding
)
{
    struct encoding_template_str et;
    et.ber = encoding;
    PZ_Lock(store->lock);
    /* XXX should be faster */
    nssHash_Iterate(store->issuer_and_serial, match_encoding, &et);
    PZ_Unlock(store->lock);
    return et.cert;
}

struct id_template_str
{
  NSSItem *id;
  NSSArena *arena;
  PRUint32 maximum;
  NSSCert **certs;
  PRUint32 numCerts;
};

static void match_id(const void *k, void *v, void *a)
{
    NSSItem *id;
    struct id_template_str *idt = (struct id_template_str *)a;
    NSSCert *c = (NSSCert *)v;
    id = nssCert_GetID(c);
    if (nssItem_Equal(id, idt->id, NULL)) {
	if (idt->numCerts == 0 && !idt->certs) {
	    /* First encounter with matching certs, and need to allocate
	     * an array for them
	     */
	    idt->certs = nss_ZNEWARRAY(idt->arena, NSSCert *, 2);
	} else if (idt->maximum == 0 && idt->certs) {
	    /* Already have matching certs, need to realloc */
	    idt->certs = nss_ZREALLOCARRAY(idt->certs, 
	                                   NSSCert *, 
	                                   idt->numCerts + 1);
	}
	if (!idt->certs) {
	    /* XXX */
	    return;
	}
	if (idt->maximum == 0 || idt->numCerts + 1 < idt->maximum) {
	    idt->certs[idt->numCerts++] = nssCert_AddRef(c);
	}
    }
}

NSS_IMPLEMENT NSSCert **
nssCertStore_FindCertsByID (
  nssCertStore *store,
  NSSItem *id,
  NSSCert **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    struct id_template_str idt;
    idt.id = id;
    idt.arena = arenaOpt;
    idt.maximum = maximumOpt;
    idt.certs = NULL;
    PZ_Lock(store->lock);
    nssHash_Iterate(store->issuer_and_serial, match_id, &idt);
    PZ_Unlock(store->lock);
    return idt.certs;
}

struct cert_cb_str {
  PRStatus (*callback)(NSSCert *c, void *arg);
  void *arg;
};

static void do_cert_callback(const void *k, void *v, void *a)
{
    struct cert_cb_str *cb = (struct cert_cb_str *)a;
    (void)cb->callback((NSSCert*)v, cb->arg);
}

static PRStatus
nssCertStore_TraverseCerts (
  nssCertStore *store,
  PRStatus (*callback)(NSSCert *c, void *arg),
  void *arg
)
{
    struct cert_cb_str cb;
    cb.callback = callback;
    cb.arg = arg;
    nssHash_Iterate(store->issuer_and_serial, do_cert_callback, &cb);
    return PR_SUCCESS; /* XXX */
}

static PLHashNumber
nss_certificate_hash(const void *c)
{
    return (PLHashNumber)nssCert_Hash((NSSCert *)c);
}

static int
nss_compare_certs(const void *v1, const void *v2)
{
    return nssCert_IssuerAndSerialEqual((NSSCert *)v1, (NSSCert *)v2);
}

NSS_IMPLEMENT nssHash *
nssHash_CreateCert (
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

/*
 * A store consisting of a token and all of its (visible) 
 * _persistent_ objects.
 */
struct nssTokenObjectStoreStr
{
  NSSToken *token;
  NSSSlot *slot;
  nssSession *session;
  PRBool isFriendly;
  PZLock *lock;           /* protects everything below */
  NSSCert **certs;        /* token certs               */
  PRBool wasLoggedIn;     /* token was authenticated last time
                           * we accessed it
			   */
  PRBool wasPresent;      /* token was inserted last time
                           * we accessed it
			   */
  PRBool disabled;        /* token is disabled, ignore it */
  NSSError error;         /* remember any error that occured */
};
typedef struct nssTokenObjectStoreStr nssTokenObjectStore;

struct nssTokenStoreStr
{
  NSSTrustDomain *td;
  nssCertStore *certs;
  PZLock *lock; /* protects the arena, array, and counter */
  NSSArena *arena;
  nssTokenObjectStore **tokens;
  PRUint32 numTokens;
};

static void
unload_token_certs(nssTokenObjectStore *objectStore, nssTokenStore *store)
{
    NSSCert **cp;
    if (objectStore->certs) {
	/* notify the cert objects that the token is removed */
	for (cp = objectStore->certs; *cp; cp++) {
	    nssCert_RemoveInstanceForToken(*cp, objectStore->token);
	    if (nssCert_CountInstances(*cp) == 0) {
		/* the cert now has no token instances, remove it from
		 * the token store
		 */
		nssTokenStore_RemoveCert(store, *cp);
	    }
	}
	/* clear the array of token certs */
	nssCertArray_Destroy(objectStore->certs);
	objectStore->certs = NULL;
    }
}

static PRStatus
load_token_certs(nssTokenObjectStore *objectStore, nssTokenStore *store)
{
    PRStatus status;
    nssCryptokiObject **tokenCerts;
    NSSCert **cp;

    if (objectStore->certs) {
	/* clear the existing array of token certs */
	nssCertArray_Destroy(objectStore->certs);
	objectStore->certs = NULL;
    }
    /* find all peristent cert instances (PKCS #11 "token objects")
     * on the token
     */
    tokenCerts = nssToken_FindCerts(objectStore->token, objectStore->session,
                                    nssTokenSearchType_TokenOnly, 0, &status);
    if (status == PR_FAILURE) {
	return PR_FAILURE;
    }
    if (tokenCerts) {
	objectStore->certs = nssCertArray_CreateFromInstances(tokenCerts,
	                                                      store->td, 
	                                                      NULL, NULL);
	if (!objectStore->certs) {
	    nssCryptokiObjectArray_Destroy(tokenCerts);
	    return PR_FAILURE;
	}
	for (cp = objectStore->certs; *cp; cp++) {
	    status = nssCertStore_AddCert(store->certs, *cp);
	    if (status == PR_FAILURE) {
		unload_token_certs(objectStore, store);
	    }
	}
    }
    return PR_SUCCESS;
}

static nssTokenObjectStore *
create_token_object_store(nssTokenStore *store, NSSToken *token)
{
    nssTokenObjectStore *rvObjectStore;

    /* XXX mark it */
    rvObjectStore = nss_ZNEW(store->arena, nssTokenObjectStore);
    if (!rvObjectStore) {
	return (nssTokenObjectStore *)NULL;
    }
    rvObjectStore->session = nssToken_CreateSession(token, PR_FALSE);
    if (!rvObjectStore->session) {
	return (nssTokenObjectStore *)NULL;
    }
    rvObjectStore->lock = PZ_NewLock(nssILockOther);
    if (!rvObjectStore->lock) {
	nssSession_Destroy(rvObjectStore->session);
	return (nssTokenObjectStore *)NULL;
    }
    rvObjectStore->token = nssToken_AddRef(token);
    rvObjectStore->slot = nssToken_GetSlot(token);
    rvObjectStore->isFriendly = nssSlot_IsFriendly(rvObjectStore->slot);
    if (load_token_certs(rvObjectStore, store) == PR_SUCCESS) {
	rvObjectStore->wasPresent = PR_TRUE;
    } else {
	NSSError e = NSS_GetError();
	if (e == NSS_ERROR_DEVICE_REMOVED) {
	    rvObjectStore->wasPresent = PR_FALSE;
	} else if (e == NSS_ERROR_LOGIN_REQUIRED) {
	    rvObjectStore->wasLoggedIn = PR_FALSE;
	} else {
	    rvObjectStore->error = e;
	}
    }
    return rvObjectStore;
}

static void
destroy_token_object_store(nssTokenObjectStore *objectStore, 
                           nssTokenStore *store)
{
    (void)unload_token_certs(objectStore, store);
    PZ_DestroyLock(objectStore->lock);
    nssSession_Destroy(objectStore->session);
}

static void
refresh_token_object_store(nssTokenObjectStore *objectStore, 
                           nssTokenStore *store)
{
    PRStatus status = PR_SUCCESS;
    PRBool isLoggedIn, isPresent;
    NSSError e = NSS_ERROR_NO_ERROR;

    /* get the current status of the token */
    isPresent = nssSlot_IsTokenPresent(objectStore->slot);
    isLoggedIn = nssSlot_IsLoggedIn(objectStore->slot);

    /* check against the previous status */
    PZ_Lock(objectStore->lock);
    if (!isPresent) {
	if (objectStore->wasPresent) {
	    /* token has been removed since the last search */
	    unload_token_certs(objectStore, store);
	} /* else it wasn't present before, so do nothing */
    } else if (!objectStore->wasPresent) {
	/* token has been inserted since the last search */
	if (objectStore->isFriendly || isLoggedIn) {
	    /* and it is either friendly or authenticated, so certs should
	     * be available
	     */
	    status = load_token_certs(objectStore, store);
	}
    } else if (!isLoggedIn) {
	/* token is present but not authenticated */
	if (!objectStore->isFriendly && objectStore->wasLoggedIn) {
	    /* it is not friendly, and was previously authenticated, so
	     * we have private objects that need to be unloaded
	     */
	    unload_token_certs(objectStore, store);
	} /* else it wasn't authenticated before, so do nothing */
    } else if (!objectStore->isFriendly && !objectStore->wasLoggedIn) {
	/* token is present and authenticated, load private objects */
	status = load_token_certs(objectStore, store);
    }
    if (status == PR_FAILURE) {
	e = NSS_GetError();
	if (e == NSS_ERROR_DEVICE_REMOVED) {
	    /* this can occur when we attempted to load objects, but
	     * during the load the device was removed.  Unload and
	     * move on.
	     */
	    unload_token_certs(objectStore, store);
	    e = NSS_ERROR_NO_ERROR; /* override the error */
	}
    }
    objectStore->wasPresent = isPresent;
    objectStore->wasLoggedIn = isLoggedIn;
    objectStore->error = e;
    PZ_Unlock(objectStore->lock);
}

static nssTokenObjectStore **
get_token_object_stores(nssTokenStore *store)
{
    nssTokenObjectStore **objectStores;
    PZ_Lock(store->lock);
    objectStores = nss_ZNEWARRAY(NULL, nssTokenObjectStore *, 
                                 store->numTokens + 1);
    if (objectStores)
	nsslibc_memcpy(objectStores, store->tokens,
	               store->numTokens * sizeof(nssTokenObjectStore *));
    PZ_Unlock(store->lock);
    return objectStores;
}

static nssTokenObjectStore *
find_store_for_token(nssTokenStore *store, NSSToken *token)
{
    PRUint32 i;
    nssTokenObjectStore *objectStore;

    PZ_Lock(store->lock);
    for (i=0; i<store->numTokens; i++) {
	if (store->tokens[i]->token == token) {
	    objectStore = store->tokens[i];
	    break;
	}
    }
    PZ_Unlock(store->lock);
    if (!objectStore) {
	nss_SetError(NSS_ERROR_DEVICE_NOT_FOUND);
    }
    return objectStore;
}

NSS_IMPLEMENT PRStatus
nssTokenStore_AddToken (
  nssTokenStore *store,
  NSSToken *token
)
{
    PRStatus status = PR_SUCCESS;
    PZ_Lock(store->lock);
    if (store->numTokens == 0) {
	store->tokens = nss_ZNEWARRAY(NULL, 
	                              nssTokenObjectStore *, 
                                      store->numTokens + 1);
    } else {
	store->tokens = nss_ZREALLOCARRAY(store->tokens, 
	                                  nssTokenObjectStore *, 
                                          store->numTokens + 1);
    }
    if (store->tokens) {
	store->tokens[store->numTokens] = create_token_object_store(store, 
	                                                            token);
	if (!store->tokens[store->numTokens]) {
	    status = PR_FAILURE;
	} else {
	    store->numTokens++;
	}
    } else  {
	status = PR_FAILURE;
    }
    PZ_Unlock(store->lock);
    return status;
}

NSS_IMPLEMENT nssTokenStore *
nssTokenStore_Create (
  NSSTrustDomain *td,
  NSSToken **tokens
)
{
    NSSArena *arena;
    PRUint32 i;
    nssTokenStore *rvStore = NULL;

    arena = nssArena_Create();
    if (!arena) {
	return (nssTokenStore *)NULL;
    }
    rvStore = nss_ZNEW(arena, nssTokenStore);
    if (!rvStore) {
	goto loser;
    }
    rvStore->lock = PZ_NewLock(nssILockOther);
    if (!rvStore->lock) {
	goto loser;
    }
    rvStore->certs = nssCertStore_Create(arena);
    if (!rvStore->certs) {
	goto loser;
    }
    rvStore->arena = arena;
    rvStore->td = td; /* XXX addref? */
    if (tokens) {
	for (; tokens[rvStore->numTokens]; rvStore->numTokens++);
	rvStore->tokens = nss_ZNEWARRAY(arena, nssTokenObjectStore *, 
	                                rvStore->numTokens);
	if (!rvStore->tokens) {
	    goto loser;
	}
	for (i=0; i<rvStore->numTokens; i++) {
	    rvStore->tokens[i] = create_token_object_store(rvStore, tokens[i]);
	    if (!rvStore->tokens[i]) {
		goto loser;
	    }
	}
    }
    return rvStore;
loser:
    if (rvStore->lock) {
	PZ_DestroyLock(rvStore->lock);
    }
    if (rvStore->certs) {
	nssCertStore_Destroy(rvStore->certs);
    }
    for (i=0; i<rvStore->numTokens && rvStore->tokens[i]; i++) {
	destroy_token_object_store(rvStore->tokens[i], rvStore);
    }
    nssArena_Destroy(arena);
    return (nssTokenStore *)NULL;
}

NSS_IMPLEMENT void
nssTokenStore_Destroy (
  nssTokenStore *store
)
{
    PRUint32 i;
    for (i=0; i<store->numTokens; i++) {
	destroy_token_object_store(store->tokens[i], store);
    }
    nssCertStore_Destroy(store->certs);
    nssArena_Destroy(store->arena);
}

NSS_IMPLEMENT PRStatus
nssTokenStore_EnableToken (
  nssTokenStore *store,
  NSSToken *token
)
{
    PRStatus status = PR_FAILURE;
    nssTokenObjectStore *objectStore;

    objectStore = find_store_for_token(store, token);
    if (objectStore) {
	PZ_Lock(objectStore->lock);
	load_token_certs(objectStore, store);
	objectStore->disabled = PR_FALSE;
	PZ_Unlock(objectStore->lock);
	status = PR_SUCCESS;
    }
    return status;
}

NSS_IMPLEMENT PRStatus
nssTokenStore_DisableToken (
  nssTokenStore *store,
  NSSToken *token
)
{
    PRStatus status = PR_FAILURE;
    nssTokenObjectStore *objectStore;

    objectStore = find_store_for_token(store, token);
    if (objectStore) {
	PZ_Lock(objectStore->lock);
	unload_token_certs(objectStore, store);
	objectStore->disabled = PR_TRUE;
	PZ_Unlock(objectStore->lock);
	status = PR_SUCCESS;
    }
    return status;
}

NSS_IMPLEMENT void
nssTokenStore_Refresh (
  nssTokenStore *store
)
{
    nssTokenObjectStore **objectStores, **osp;

    objectStores = get_token_object_stores(store);
    if (!objectStores) {
	return;
    }
    for (osp = objectStores; *osp; osp++) {
	refresh_token_object_store(*osp, store);
    }
    nss_ZFreeIf(objectStores);
}

NSS_IMPLEMENT PRStatus
nssTokenStore_ImportCert (
  nssTokenStore *store,
  NSSCert *cert,
  NSSUTF8 *nicknameOpt,
  NSSToken *destination
)
{
    PRUint32 i;
    PRStatus status;
    nssTokenObjectStore *objectStore;

    objectStore = find_store_for_token(store, destination);
    if (!objectStore) {
	return PR_FAILURE;
    }
    /* refresh the token */
    refresh_token_object_store(objectStore, store);
    /* see if it's already there */
    if (nssCert_HasInstanceOnToken(cert, destination)) {
	return PR_SUCCESS;
    }
    /* copy it onto the token and add it to the store */
    status = nssCert_CopyToToken(cert, destination, nicknameOpt);
    if (status == PR_SUCCESS) {
	status = nssCertStore_AddCert(store->certs, cert);
	if (status == PR_FAILURE) {
	    /* the store is inconsistent */
	    nss_SetError(NSS_ERROR_INTERNAL_ERROR);
	    PZ_Lock(store->tokens[i]->lock);
	    /* force a reset of the token before the next access by
	     * pretending like it was removed
	     */
	    store->tokens[i]->wasPresent = PR_FALSE;
	    unload_token_certs(store->tokens[i], store);
	    PZ_Unlock(store->tokens[i]->lock);
	    return PR_FAILURE;
	}
	return PR_SUCCESS;
    } else {
	return PR_FAILURE;
    }
}

NSS_IMPLEMENT void
nssTokenStore_RemoveCert (
  nssTokenStore *store,
  NSSCert *cert
)
{
    (void)nssCertStore_RemoveCert(store->certs, cert);
}

NSS_IMPLEMENT NSSCert **
nssTokenStore_FindCertsByNickname (
  nssTokenStore *store,
  NSSUTF8 *name,
  NSSCert **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    nssTokenStore_Refresh(store);
    return nssCertStore_FindCertsByNickname(store->certs, name, 
                                            rvOpt, maximumOpt, arenaOpt);
}

NSS_IMPLEMENT NSSCert **
nssTokenStore_FindCertsBySubject (
  nssTokenStore *store,
  NSSBER *subject,
  NSSCert **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    nssTokenStore_Refresh(store);
    return nssCertStore_FindCertsBySubject(store->certs, subject, 
                                           rvOpt, maximumOpt, arenaOpt);
}

NSS_IMPLEMENT NSSCert **
nssTokenStore_FindCertsByEmail (
  nssTokenStore *store,
  NSSASCII7 *email,
  NSSCert **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    nssTokenStore_Refresh(store);
    return nssCertStore_FindCertsByEmail(store->certs, email, 
                                         rvOpt, maximumOpt, arenaOpt);
}

NSS_IMPLEMENT NSSCert *
nssTokenStore_FindCertByIssuerAndSerialNumber (
  nssTokenStore *store,
  NSSBER *issuer,
  NSSBER *serial
)
{
    nssTokenStore_Refresh(store);
    return nssCertStore_FindCertByIssuerAndSerialNumber(store->certs,
                                                        issuer, serial);
}

NSS_IMPLEMENT NSSCert *
nssTokenStore_FindCertByEncodedCert (
  nssTokenStore *store,
  NSSBER *ber
)
{
    nssTokenStore_Refresh(store);
    return nssCertStore_FindCertByEncodedCert(store->certs, ber);
}

NSS_IMPLEMENT NSSCert **
nssTokenStore_FindCertsByID (
  nssTokenStore *store,
  NSSItem *id,
  NSSCert **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    nssTokenStore_Refresh(store);
    return nssCertStore_FindCertsByID(store->certs, id,
                                      rvOpt, maximumOpt, arenaOpt);
}

NSS_IMPLEMENT PRStatus
nssTokenStore_TraverseCerts (
  nssTokenStore *store,
  PRStatus (*callback)(NSSCert *c, void *arg),
  void *arg
)
{
    nssTokenStore_Refresh(store);
    return nssCertStore_TraverseCerts(store->certs, callback, arg);
}

