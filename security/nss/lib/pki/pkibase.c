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

NSS_IMPLEMENT nssPKIObject *
nssPKIObject_Create (
  NSSArena *arenaOpt,
  nssCryptokiObject *instanceOpt,
  NSSTrustDomain *td,
  NSSVolatileDomain *vdOpt /* XXX remove */
)
{
    NSSArena *arena;
    nssArenaMark *mark = NULL;
    nssPKIObject *object;
    if (arenaOpt) {
	arena = arenaOpt;
	mark = nssArena_Mark(arena);
    } else {
	arena = nssArena_Create();
	if (!arena) {
	    return (nssPKIObject *)NULL;
	}
    }
    object = nss_ZNEW(arena, nssPKIObject);
    if (!object) {
	goto loser;
    }
    object->arena = arena;
    object->td = td; /* XXX */
    object->lock = PZ_NewLock(nssILockOther);
    if (!object->lock) {
	goto loser;
    }
    if (instanceOpt) {
	if (nssPKIObject_AddInstance(object, instanceOpt) != PR_SUCCESS) {
	    goto loser;
	}
    }
    PR_AtomicIncrement(&object->refCount);
    if (mark) {
	nssArena_Unmark(arena, mark);
    }
    return object;
loser:
    if (mark) {
	nssArena_Release(arena, mark);
    } else {
	nssArena_Destroy(arena);
    }
    return (nssPKIObject *)NULL;
}

NSS_IMPLEMENT PRBool
nssPKIObject_Destroy (
  nssPKIObject *object
)
{
    PRUint32 i;
    PR_ASSERT(object->refCount > 0);
    PR_AtomicDecrement(&object->refCount);
    if (object->refCount == 0) {
	for (i=0; i<object->numInstances; i++) {
	    nssCryptokiObject_Destroy(object->instances[i]);
	}
	/*nssVolatileDomain_Destroy(object->vd);*/
	PZ_DestroyLock(object->lock);
	nssArena_Destroy(object->arena);
	return PR_TRUE;
    }
    return PR_FALSE;
}

NSS_IMPLEMENT nssPKIObject *
nssPKIObject_AddRef (
  nssPKIObject *object
)
{
    PR_AtomicIncrement(&object->refCount);
    return object;
}

NSS_IMPLEMENT PRStatus
nssPKIObject_AddInstance (
  nssPKIObject *object,
  nssCryptokiObject *instance
)
{
    PZ_Lock(object->lock);
    if (object->numInstances == 0) {
	object->instances = nss_ZNEWARRAY(object->arena,
	                                  nssCryptokiObject *,
	                                  object->numInstances + 1);
    } else {
	PRUint32 i;
	for (i=0; i<object->numInstances; i++) {
	    if (nssCryptokiObject_Equal(object->instances[i], instance)) {
		PZ_Unlock(object->lock);
		/* Object already has the instance */
		if (instance->label) {
		    if (!object->instances[i]->label ||
		        !nssUTF8_Equal(instance->label,
		                       object->instances[i]->label, NULL))
		    {
			/* Either the old instance did not have a label,
			 * or the label has changed.
			 */
			nss_ZFreeIf(object->instances[i]->label);
			object->instances[i]->label = instance->label;
			instance->label = NULL;
		    }
		} else if (object->instances[i]->label) {
		    /* The old label was removed */
		    nss_ZFreeIf(object->instances[i]->label);
		    object->instances[i]->label = NULL;
		}
		nssCryptokiObject_Destroy(instance);
		return PR_SUCCESS;
	    }
	}
	object->instances = nss_ZREALLOCARRAY(object->instances,
	                                      nssCryptokiObject *,
	                                      object->numInstances + 1);
    }
    if (!object->instances) {
	PZ_Unlock(object->lock);
	return PR_FAILURE;
    }
    object->instances[object->numInstances++] = instance;
    PZ_Unlock(object->lock);
    return PR_SUCCESS;
}

NSS_IMPLEMENT PRBool
nssPKIObject_HasInstance (
  nssPKIObject *object,
  nssCryptokiObject *instance
)
{
    PRUint32 i;
    PRBool hasIt = PR_FALSE;;
    PZ_Lock(object->lock);
    for (i=0; i<object->numInstances; i++) {
	if (nssCryptokiObject_Equal(object->instances[i], instance)) {
	    hasIt = PR_TRUE;
	    break;
	}
    }
    PZ_Unlock(object->lock);
    return hasIt;
}

NSS_IMPLEMENT PRBool
nssPKIObject_HasInstanceOnToken (
  nssPKIObject *object,
  NSSToken *token
)
{
    PRUint32 i;
    PRBool hasIt = PR_FALSE;;
    PZ_Lock(object->lock);
    for (i=0; i<object->numInstances; i++) {
	if (object->instances[i]->token == token) {
	    hasIt = PR_TRUE;
	    break;
	}
    }
    PZ_Unlock(object->lock);
    return hasIt;
}

NSS_IMPLEMENT PRIntn
nssPKIObject_CountInstances (
  nssPKIObject *object
)
{
    PRIntn count;
    PZ_Lock(object->lock);
    count = object->numInstances;
    PZ_Unlock(object->lock);
    return count;
}

NSS_IMPLEMENT PRStatus
nssPKIObject_RemoveInstanceForToken (
  nssPKIObject *object,
  NSSToken *token
)
{
    PRUint32 i;
    nssCryptokiObject *instanceToRemove = NULL;
    PZ_Lock(object->lock);
    if (object->numInstances == 0) {
	PZ_Unlock(object->lock);
	return PR_SUCCESS;
    }
    for (i=0; i<object->numInstances; i++) {
	if (object->instances[i]->token == token) {
	    instanceToRemove = object->instances[i];
	    object->instances[i] = object->instances[object->numInstances-1];
	    object->instances[object->numInstances-1] = NULL;
	    break;
	}
    }
    if (--object->numInstances > 0) {
	object->instances = nss_ZREALLOCARRAY(object->instances,
	                                      nssCryptokiObject *,
	                                      object->numInstances);
	if (!object->instances) {
	    PZ_Unlock(object->lock);
	    return PR_FAILURE;
	}
    } else {
	nss_ZFreeIf(object->instances);
    }
    nssCryptokiObject_Destroy(instanceToRemove);
    PZ_Unlock(object->lock);
    return PR_SUCCESS;
}

/* this needs more thought on what will happen when there are multiple
 * instances
 */
NSS_IMPLEMENT PRStatus
nssPKIObject_DeleteStoredObject (
  nssPKIObject *object,
  NSSCallback *uhh,
  PRBool isFriendly
)
{
    PRUint32 i, numNotDestroyed;
    PRStatus status = PR_SUCCESS;
    NSSTrustDomain *td = object->td;
    NSSCallback *pwcb = uhh ?  /* is this optional? */
                        uhh : 
                        nssTrustDomain_GetDefaultCallback(td, NULL);
    numNotDestroyed = 0;
    PZ_Lock(object->lock);
    for (i=0; i<object->numInstances; i++) {
	nssCryptokiObject *instance = object->instances[i];
	NSSSlot *slot = nssToken_GetSlot(instance->token);
	/* If both the operation and the slot are friendly, login is
	 * not required.  If either or both are not friendly, it is
	 * required. XXX session objects?
	 */
	if (!(isFriendly && nssSlot_IsFriendly(slot))) {
	    status = nssSlot_Login(slot, pwcb);
	    nssSlot_Destroy(slot);
	    if (status == PR_FAILURE) {
		return PR_FAILURE;
	    }
	}
	/* this function will destroy the instance if successful */
	status = nssCryptokiObject_DeleteStoredObject(instance);
	/* XXX this should be fixed to understand read-only tokens,
	 * for now, to handle the builtins, just make the attempt.
	 */
	object->instances[i] = NULL;
	if (status == PR_FAILURE) {
	    object->instances[numNotDestroyed++] = instance;
	}
    }
    if (numNotDestroyed == 0) {
	nss_ZFreeIf(object->instances);
	object->numInstances = 0;
    } else {
	object->numInstances = numNotDestroyed;
    }
    PZ_Unlock(object->lock);
    return status;
}

NSS_IMPLEMENT NSSToken **
nssPKIObject_GetTokens (
  nssPKIObject *object,
  NSSToken **rvOpt,
  PRUint32 rvMaxOpt,
  PRStatus *statusOpt
)
{
    NSSToken **tokens = NULL;
    PZ_Lock(object->lock);
    if (object->numInstances > 0) {
	if (rvMaxOpt) {
	    rvMaxOpt = PR_MIN(rvMaxOpt, object->numInstances);
	} else {
	    rvMaxOpt = object->numInstances;
	}
	if (rvOpt) {
	    tokens = rvOpt;
	} else {
	    tokens = nss_ZNEWARRAY(NULL, NSSToken *, 
	                           object->numInstances + 1);
	}
	if (tokens) {
	    PRUint32 i;
	    for (i=0; i<rvMaxOpt; i++) {
		tokens[i] = nssToken_AddRef(object->instances[i]->token);
	    }
	}
    }
    PZ_Unlock(object->lock);
    /* until more logic here */
    if (statusOpt) 
	*statusOpt = tokens ? PR_SUCCESS : PR_FAILURE;
    return tokens;
}

NSS_EXTERN PRStatus
nssPKIObject_SetNickname (
  nssPKIObject *object,
  NSSToken *tokenOpt,
  NSSUTF8 *nickname
)
{
    PRUint32 i;
    PRStatus status;
    PZ_Lock(object->lock);
    if (object->vd) {
	object->tempName = nssUTF8_Duplicate(nickname, object->arena);
	status = object->tempName ? PR_SUCCESS : PR_FAILURE;
    } else  {
	nssCryptokiObject *instance = NULL;
	if (tokenOpt) {
	    for (i=0; i<object->numInstances; i++) {
		if (object->instances[i]->token == tokenOpt) {
		    instance = object->instances[i];
		    break;
		}
	    }
	} else {
	    instance = object->instances[0];
	}
	if (instance) {
	    status = nssCryptokiObject_SetLabel(instance, nickname);
	} else {
	    status = PR_FAILURE;
	}
    }
    PZ_Unlock(object->lock);
    return status;
}

NSS_IMPLEMENT NSSUTF8 *
nssPKIObject_GetNickname (
  nssPKIObject *object,
  NSSToken *tokenOpt
)
{
    PRUint32 i;
    NSSUTF8 *nickname = NULL;
    PZ_Lock(object->lock);
    if (object->vd) {
	return object->tempName;
    } else {
	for (i=0; i<object->numInstances; i++) {
	    if ((!tokenOpt && object->instances[i]->label) ||
	        (object->instances[i]->token == tokenOpt)) 
	    {
		/* XXX should be copy? safe as long as caller has reference */
		nickname = object->instances[i]->label; 
		break;
	    }
	}
    }
    PZ_Unlock(object->lock);
    return nickname;
}

NSS_IMPLEMENT nssCryptokiObject **
nssPKIObject_GetInstances (
  nssPKIObject *object
)
{
    nssCryptokiObject **instances = NULL;
    PRUint32 i;
    if (object->numInstances == 0) {
	return (nssCryptokiObject **)NULL;
    }
    PZ_Lock(object->lock);
    instances = nss_ZNEWARRAY(NULL, nssCryptokiObject *, 
                              object->numInstances + 1);
    if (instances) {
	for (i=0; i<object->numInstances; i++) {
	    instances[i] = nssCryptokiObject_Clone(object->instances[i]);
	}
    }
    PZ_Unlock(object->lock);
    return instances;
}

NSS_IMPLEMENT nssCryptokiObject *
nssPKIObject_GetInstance (
  nssPKIObject *object,
  NSSToken *token
)
{
    nssCryptokiObject *instance = NULL;
    PRUint32 i;
    PZ_Lock(object->lock);
    for (i=0; i<object->numInstances; i++) {
	if (object->instances[i]->token == token) {
	    instance = nssCryptokiObject_Clone(object->instances[i]);
	    break;
	}
    }
    PZ_Unlock(object->lock);
    return instance;
}

NSS_IMPLEMENT nssCryptokiObject *
nssPKIObject_FindInstanceForAlgorithm (
  nssPKIObject *object,
  const NSSAlgNParam *ap
)
{
    nssCryptokiObject *instance = NULL;
    PRUint32 i;
    PZ_Lock(object->lock);
    for (i=0; i<object->numInstances; i++) {
	if (nssToken_DoesAlgNParam(object->instances[i]->token, ap)) {
	    instance = nssCryptokiObject_Clone(object->instances[i]);
	    break;
	}
    }
    PZ_Unlock(object->lock);
    return instance;
}

NSS_IMPLEMENT PRBool
nssPKIObject_IsOnToken (
  nssPKIObject *object,
  NSSToken *token
)
{
    PRUint32 i;
    PRBool foundIt = PR_FALSE;
    PZ_Lock(object->lock);
    for (i=0; i<object->numInstances; i++) {
	if (object->instances[i]->token == token) {
	    foundIt = PR_TRUE;
	    break;
	}
    }
    PZ_Unlock(object->lock);
    return foundIt;
}

NSS_IMPLEMENT NSSTrustDomain *
nssPKIObject_GetTrustDomain (
  nssPKIObject *object,
  PRStatus *statusOpt
)
{
    if (statusOpt) {
	*statusOpt = PR_SUCCESS;
    }
    return object->td;
}

NSS_IMPLEMENT NSSVolatileDomain *
nssPKIObject_GetVolatileDomain (
  nssPKIObject *object,
  PRStatus *statusOpt
)
{
    if (statusOpt) {
	*statusOpt = PR_SUCCESS;
    }
    return nssVolatileDomain_AddRef(object->vd);
}

NSS_IMPLEMENT NSSToken *
nssPKIObject_GetWriteToken (
  nssPKIObject *object,
  nssSession **rvSessionOpt
)
{
    PRUint32 i;
    NSSToken *token = NULL;
    nssCryptokiObject *instance;
    *rvSessionOpt = NULL;
    PZ_Lock(object->lock);
    for (i=0; i<object->numInstances; i++) {
	instance = object->instances[i];
	if (!nssToken_IsReadOnly(instance->token)) {
	    token = nssToken_AddRef(instance->token);
	    if (rvSessionOpt && nssSession_IsReadWrite(instance->session)) 
	    {
		*rvSessionOpt = nssSession_AddRef(instance->session);
	    }
	    break;
	}
    }
    PZ_Unlock(object->lock);
    if (token && rvSessionOpt && !*rvSessionOpt) {
	*rvSessionOpt = nssToken_CreateSession(token, PR_TRUE);
	if (!*rvSessionOpt) {
	    nssToken_Destroy(token);
	    token = NULL;
	}
    }
    return token;
}

NSS_IMPLEMENT NSSCert **
nssCertArray_CreateFromInstances (
  nssCryptokiObject **instances,
  NSSTrustDomain *td,
  NSSVolatileDomain *vdOpt,
  NSSArena *arenaOpt
)
{
    PRIntn i, count;
    nssCryptokiObject **ip;
    NSSCert **rvCerts;

    for (ip = instances, count = 0; *ip; ip++, count++);
    rvCerts = nss_ZNEWARRAY(arenaOpt, NSSCert *, count + 1);
    if (!rvCerts) {
	return (NSSCert **)NULL;
    }
    for (i = 0; i < count; i++) {
	rvCerts[i] = nssCert_CreateFromInstance(instances[i], td, 
	                                        vdOpt, NULL);
	if (!rvCerts[i]) {
	    nssCertArray_Destroy(rvCerts); /* it's NULL-terminated */
	    return (NSSCert **)NULL;
	}
    }
    return rvCerts;
}

NSS_IMPLEMENT void
nssCertArray_Destroy (
  NSSCert **certs
)
{
    if (certs) {
	NSSCert **certp;
	for (certp = certs; *certp; certp++) {
	    nssCert_Destroy(*certp);
	}
	nss_ZFreeIf(certs);
    }
}

NSS_IMPLEMENT void
NSSCertArray_Destroy (
  NSSCert **certs
)
{
    nssCertArray_Destroy(certs);
}

NSS_IMPLEMENT NSSCert **
nssCertArray_Duplicate (
  NSSCert **certs,
  NSSArena *arenaOpt
)
{
    PRUint32 i, n;
    NSSCert **c, **rvCerts;

    for (c = certs, n = 0; *c; c++, n++);
    rvCerts = nss_ZNEWARRAY(arenaOpt, NSSCert *, n + 1);
    if (!rvCerts) {
	return (NSSCert **)NULL;
    }
    for (i = 0; i < n; i++) {
	rvCerts[i] = nssCert_AddRef(certs[i]);
    }
    return rvCerts;
}

NSS_IMPLEMENT NSSCert **
nssCertArray_Join (
  NSSCert **certs1,
  NSSCert **certs2
)
{
    if (certs1 && certs2) {
	NSSCert **certs, **cp;
	PRUint32 count = 0;
	PRUint32 count1 = 0;
	cp = certs1;
	while (*cp++) count1++;
	count = count1;
	cp = certs2;
	while (*cp++) count++;
	certs = nss_ZREALLOCARRAY(certs1, NSSCert *, count + 1);
	if (!certs) {
	    nss_ZFreeIf(certs1);
	    nss_ZFreeIf(certs2);
	    return (NSSCert **)NULL;
	}
	for (cp = certs2; *cp; cp++, count1++) {
	    certs[count1] = *cp;
	}
	nss_ZFreeIf(certs2);
	return certs;
    } else if (certs1) {
	return certs1;
    } else {
	return certs2;
    }
}

NSS_IMPLEMENT NSSCert * 
nssCertArray_FindBestCert (
  NSSCert **certs, 
  NSSTime time,
  const NSSUsages *usagesOpt,
  NSSPolicies *policiesOpt
)
{
    PRStatus status;
    NSSCert *bestCert = NULL;
    if (!certs) {
	return (NSSCert *)NULL;
    }
    for (; *certs; certs++) {
	NSSCert *c = *certs;
	NSSUsages *certUsages = nssCert_GetUsages(c, &status);
	if (status == PR_FAILURE) {
	    return (NSSCert *)NULL;
	}
	if (!bestCert) {
	    /* take the first cert with matching usage (if provided) */
	    if (!usagesOpt || nssUsages_Match(usagesOpt, certUsages)) {
		bestCert = nssCert_AddRef(c);
	    }
	    continue;
	} else {
	    /* already have a cert for this usage, if this cert doesn't have
	     * the correct usage, continue
	     * if ths cert does match usage, defer to time/policies
	     */
	    if (usagesOpt && !nssUsages_Match(usagesOpt, certUsages)) {
		continue;
	    }
	}
	/* time */
	if (nssCert_IsValidAtTime(bestCert, time, &status)) {
	    /* The current best cert is valid at time */
	    if (!nssCert_IsValidAtTime(c, time, &status)) {
		/* If the new cert isn't valid at time, it's not better */
		continue;
	    }
	} else {
	    if (status == PR_FAILURE) {
		return (NSSCert *)NULL;
	    }
	    /* The current best cert is not valid at time */
	    if (nssCert_IsValidAtTime(c, time, NULL)) {
		/* If the new cert is valid at time, it's better */
		nssCert_Destroy(bestCert);
		bestCert = nssCert_AddRef(c);
	    }
	}
	/* either they are both valid at time, or neither valid; 
	 * take the newer one
	 */
	if (nssCert_IsNewer(c, bestCert, &status)) {
	    nssCert_Destroy(bestCert);
	    bestCert = nssCert_AddRef(c);
	} else if (status == PR_FAILURE) {
	    return (NSSCert *)NULL;
	}
	/* policies */
	/* XXX later -- defer to policies */
    }
    return bestCert;
}

NSS_IMPLEMENT PRStatus
nssCertArray_Traverse (
  NSSCert **certs,
  PRStatus (* callback)(NSSCert *c, void *arg),
  void *arg
)
{
    PRStatus status = PR_SUCCESS;
    if (certs) {
	NSSCert **certp;
	for (certp = certs; *certp; certp++) {
	    status = (*callback)(*certp, arg);
	    if (status != PR_SUCCESS) {
		break;
	    }
	}
    }
    return status;
}


NSS_IMPLEMENT void
nssCRLArray_Destroy (
  NSSCRL **crls
)
{
    if (crls) {
	NSSCRL **crlp;
	for (crlp = crls; *crlp; crlp++) {
	    nssCRL_Destroy(*crlp);
	}
	nss_ZFreeIf(crls);
    }
}

NSS_IMPLEMENT void
nssSymKeyArray_Destroy (
  NSSSymKey **mkeys
)
{
    if (mkeys) {
	NSSSymKey **mkp;
	for (mkp = mkeys; *mkp; mkp++) {
	    nssSymKey_Destroy(*mkp);
	}
    }
    nss_ZFreeIf(mkeys);
}

NSS_IMPLEMENT void
nssPrivateKeyArray_Destroy (
  NSSPrivateKey **vkeys
)
{
    if (vkeys) {
	NSSPrivateKey **vkp;
	for (vkp = vkeys; *vkp; vkp++) {
	    nssPrivateKey_Destroy(*vkp);
	}
    }
    nss_ZFreeIf(vkeys);
}

NSS_IMPLEMENT void
nssPublicKeyArray_Destroy (
  NSSPublicKey **bkeys
)
{
    if (bkeys) {
	NSSPublicKey **bkp;
	for (bkp = bkeys; *bkp; bkp++) {
	    nssPublicKey_Destroy(*bkp);
	}
    }
    nss_ZFreeIf(bkeys);
}

NSS_IMPLEMENT PRBool
nssUsages_Match (
  const NSSUsages *usages,
  const NSSUsages *testUsages
)
{
   return (((usages->ca & testUsages->ca) == usages->ca) &&
           ((usages->peer & testUsages->peer) == usages->peer));
}

/*
 * Object collections
 */

typedef enum
{
  pkiObjectType_Cert = 0,
  pkiObjectType_CRL = 1,
  pkiObjectType_PrivateKey = 2,
  pkiObjectType_PublicKey = 3
} pkiObjectType;

/* Each object is defined by a set of items that uniquely identify it.
 * Here are the uid sets:
 *
 * NSSCert ==>  { issuer, serial }
 * NSSPrivateKey
 *         (RSA) ==> { modulus, public exponent }
 *
 */
#define MAX_ITEMS_FOR_UID 2

/* pkiObjectCollectionNode
 *
 * A node in the collection is the set of unique identifiers for a single
 * object, along with either the actual object or a proto-object.
 */
typedef struct
{
  PRCList link;
  PRBool haveObject;
  nssPKIObject *object;
  NSSItem uid[MAX_ITEMS_FOR_UID];
} 
pkiObjectCollectionNode;

/* nssPKIObjectCollection
 *
 * The collection is the set of all objects, plus the interfaces needed
 * to manage the objects.
 *
 */
struct nssPKIObjectCollectionStr
{
  NSSArena *arena;
  NSSTrustDomain *td;
  PRCList head; /* list of pkiObjectCollectionNode's */
  PRUint32 size;
  pkiObjectType objectType;
  void           (*      destroyObject)(nssPKIObject *o);
  PRStatus       (*   getUIDFromObject)(nssPKIObject *o, NSSItem *uid);
  PRStatus       (* getUIDFromInstance)(nssCryptokiObject *co, NSSItem *uid, 
                                        NSSArena *arena);
  nssPKIObject * (*       createObject)(nssPKIObject *o);
};

static nssPKIObjectCollection *
nssPKIObjectCollection_Create (
  NSSTrustDomain *td
)
{
    NSSArena *arena;
    nssPKIObjectCollection *rvCollection = NULL;
    arena = nssArena_Create();
    if (!arena) {
	return (nssPKIObjectCollection *)NULL;
    }
    rvCollection = nss_ZNEW(arena, nssPKIObjectCollection);
    if (!rvCollection) {
	goto loser;
    }
    PR_INIT_CLIST(&rvCollection->head);
    rvCollection->arena = arena;
    rvCollection->td = td; /* XXX */
    return rvCollection;
loser:
    nssArena_Destroy(arena);
    return (nssPKIObjectCollection *)NULL;
}

NSS_IMPLEMENT void
nssPKIObjectCollection_Destroy (
  nssPKIObjectCollection *collection
)
{
    if (collection) {
	PRCList *link;
	pkiObjectCollectionNode *node;
	/* first destroy any objects in the collection */
	link = PR_NEXT_LINK(&collection->head);
	while (link != &collection->head) {
	    node = (pkiObjectCollectionNode *)link;
	    if (node->haveObject) {
		(*collection->destroyObject)(node->object);
	    } else {
		nssPKIObject_Destroy(node->object);
	    }
	    link = PR_NEXT_LINK(link);
	}
	/* then destroy it */
	nssArena_Destroy(collection->arena);
    }
}

NSS_IMPLEMENT PRUint32
nssPKIObjectCollection_Count (
  nssPKIObjectCollection *collection
)
{
    return collection->size;
}

NSS_IMPLEMENT PRStatus
nssPKIObjectCollection_AddObject (
  nssPKIObjectCollection *collection,
  nssPKIObject *object
)
{
    pkiObjectCollectionNode *node;
    node = nss_ZNEW(collection->arena, pkiObjectCollectionNode);
    if (!node) {
	return PR_FAILURE;
    }
    node->haveObject = PR_TRUE;
    node->object = nssPKIObject_AddRef(object);
    (*collection->getUIDFromObject)(object, node->uid);
    PR_INIT_CLIST(&node->link);
    PR_INSERT_BEFORE(&node->link, &collection->head);
    collection->size++;
    return PR_SUCCESS;
}

static pkiObjectCollectionNode *
find_instance_in_collection (
  nssPKIObjectCollection *collection,
  nssCryptokiObject *instance
)
{
    PRCList *link;
    pkiObjectCollectionNode *node;
    link = PR_NEXT_LINK(&collection->head);
    while (link != &collection->head) {
	node = (pkiObjectCollectionNode *)link;
	if (nssPKIObject_HasInstance(node->object, instance)) {
	    return node;
	}
	link = PR_NEXT_LINK(link);
    }
    return (pkiObjectCollectionNode *)NULL;
}

static pkiObjectCollectionNode *
find_object_in_collection (
  nssPKIObjectCollection *collection,
  NSSItem *uid
)
{
    PRUint32 i;
    PRStatus status;
    PRCList *link;
    pkiObjectCollectionNode *node;
    link = PR_NEXT_LINK(&collection->head);
    while (link != &collection->head) {
	node = (pkiObjectCollectionNode *)link;
	for (i=0; i<MAX_ITEMS_FOR_UID; i++) {
	    if (!nssItem_Equal(&node->uid[i], &uid[i], &status)) {
		break;
	    }
	}
	if (i == MAX_ITEMS_FOR_UID) {
	    return node;
	}
	link = PR_NEXT_LINK(link);
    }
    return (pkiObjectCollectionNode *)NULL;
}

static pkiObjectCollectionNode *
add_object_instance (
  nssPKIObjectCollection *collection,
  nssCryptokiObject *instance
)
{
    PRUint32 i;
    PRStatus status;
    pkiObjectCollectionNode *node;
    nssArenaMark *mark = NULL;
    NSSItem uid[MAX_ITEMS_FOR_UID];
    nsslibc_memset(uid, 0, sizeof uid);
    /* The list is traversed twice, first (here) looking to match the
     * { token, handle } tuple, and if that is not found, below a search
     * for unique identifier is done.  Here, a match means this exact object
     * instance is already in the collection, and we have nothing to do.
     */
    node = find_instance_in_collection(collection, instance);
    if (node) {
	/* The collection is assumed to take over the instance.  Since we
	 * are not using it, it must be destroyed.
	 */
	nssCryptokiObject_Destroy(instance);
	return node;
    }
    mark = nssArena_Mark(collection->arena);
    if (!mark) {
	goto loser;
    }
    status = (*collection->getUIDFromInstance)(instance, uid, 
                                               collection->arena);
    if (status != PR_SUCCESS) {
	goto loser;
    }
    /* Search for unique identifier.  A match here means the object exists 
     * in the collection, but does not have this instance, so the instance 
     * needs to be added.
     */
    node = find_object_in_collection(collection, uid);
    if (node) {
	/* This is a object with multiple instances */
	status = nssPKIObject_AddInstance(node->object, instance);
    } else {
	/* This is a completely new object.  Create a node for it. */
	node = nss_ZNEW(collection->arena, pkiObjectCollectionNode);
	if (!node) {
	    goto loser;
	}
	node->object = nssPKIObject_Create(NULL, instance, 
	                                   collection->td, NULL);
	if (!node->object) {
	    goto loser;
	}
	for (i=0; i<MAX_ITEMS_FOR_UID; i++) {
	    node->uid[i] = uid[i];
	}
	node->haveObject = PR_FALSE;
	PR_INIT_CLIST(&node->link);
	PR_INSERT_BEFORE(&node->link, &collection->head);
	collection->size++;
	status = PR_SUCCESS;
    }
    nssArena_Unmark(collection->arena, mark);
    return node;
loser:
    if (mark) {
	nssArena_Release(collection->arena, mark);
    }
    nssCryptokiObject_Destroy(instance);
    return (pkiObjectCollectionNode *)NULL;
}

NSS_IMPLEMENT PRStatus
nssPKIObjectCollection_AddInstances (
  nssPKIObjectCollection *collection,
  nssCryptokiObject **instances,
  PRUint32 numInstances
)
{
    PRStatus status = PR_SUCCESS;
    PRUint32 i = 0;
    pkiObjectCollectionNode *node;
    if (instances) {
	for (; *instances; instances++, i++) {
	    if (numInstances > 0 && i == numInstances) {
		break;
	    }
	    node = add_object_instance(collection, *instances);
	    if (node == NULL) {
		goto loser;
	    }
	}
    }
    return status;
loser:
    /* free the remaining instances */
    for (; *instances; instances++, i++) {
	if (numInstances > 0 && i == numInstances) {
	    break;
	}
	nssCryptokiObject_Destroy(*instances);
    }
    return PR_FAILURE;
}

static void
nssPKIObjectCollection_RemoveNode (
   nssPKIObjectCollection *collection,
   pkiObjectCollectionNode *node
)
{
    PR_REMOVE_LINK(&node->link); 
    collection->size--;
}

static PRStatus
nssPKIObjectCollection_GetObjects (
  nssPKIObjectCollection *collection,
  nssPKIObject **rvObjects,
  PRUint32 rvSize
)
{
    PRUint32 i = 0;
    PRCList *link = PR_NEXT_LINK(&collection->head);
    pkiObjectCollectionNode *node;
    while ((i < rvSize) && (link != &collection->head)) {
	node = (pkiObjectCollectionNode *)link;
	if (!node->haveObject) {
	    /* Convert the proto-object to an object */
	    node->object = (*collection->createObject)(node->object);
	    if (!node->object) {
		link = PR_NEXT_LINK(link);
		/*remove bogus object from list*/
		nssPKIObjectCollection_RemoveNode(collection,node);
		continue;
	    }
	    node->haveObject = PR_TRUE;
	}
	rvObjects[i++] = nssPKIObject_AddRef(node->object);
	link = PR_NEXT_LINK(link);
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT PRStatus
nssPKIObjectCollection_Traverse (
  nssPKIObjectCollection *collection,
  nssPKIObjectCallback *callback
)
{
    PRStatus status;
    PRCList *link = PR_NEXT_LINK(&collection->head);
    pkiObjectCollectionNode *node;
    while (link != &collection->head) {
	node = (pkiObjectCollectionNode *)link;
	if (!node->haveObject) {
	    node->object = (*collection->createObject)(node->object);
	    if (!node->object) {
		link = PR_NEXT_LINK(link);
		/*remove bogus object from list*/
		nssPKIObjectCollection_RemoveNode(collection,node);
		continue;
	    }
	    node->haveObject = PR_TRUE;
	}
	switch (collection->objectType) {
	case pkiObjectType_Cert: 
	    status = (*callback->func.cert)((NSSCert *)node->object, 
	                                    callback->arg);
	    break;
	case pkiObjectType_CRL: 
	    status = (*callback->func.crl)((NSSCRL *)node->object, 
	                                   callback->arg);
	    break;
	case pkiObjectType_PrivateKey: 
	    status = (*callback->func.pvkey)((NSSPrivateKey *)node->object, 
	                                     callback->arg);
	    break;
	case pkiObjectType_PublicKey: 
	    status = (*callback->func.pbkey)((NSSPublicKey *)node->object, 
	                                     callback->arg);
	    break;
	}
	link = PR_NEXT_LINK(link);
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT PRStatus
nssPKIObjectCollection_AddInstanceAsObject (
  nssPKIObjectCollection *collection,
  nssCryptokiObject *instance
)
{
    pkiObjectCollectionNode *node;
    node = add_object_instance(collection, instance);
    if (node == NULL) {
	return PR_FAILURE;
    }
    if (!node->haveObject) {
	node->object = (*collection->createObject)(node->object);
	if (!node->object) {
	    /*remove bogus object from list*/
	    nssPKIObjectCollection_RemoveNode(collection,node);
	    return PR_FAILURE;
	}
	node->haveObject = PR_TRUE;
    }
    return PR_SUCCESS;
}

/*
 * Cert collections
 */

static void
cert_destroyObject(nssPKIObject *o)
{
    NSSCert *c = (NSSCert *)o;
    nssCert_Destroy(c);
}

static PRStatus
cert_getUIDFromObject(nssPKIObject *o, NSSItem *uid)
{
    NSSCert *c = (NSSCert *)o;
    NSSDER *issuer, *serial;
    issuer = nssCert_GetIssuer(c);
    serial = nssCert_GetSerialNumber(c);
    uid[0] = *issuer;
    uid[1] = *serial;
    return PR_SUCCESS;
}

static PRStatus
cert_getUIDFromInstance(nssCryptokiObject *instance, NSSItem *uid, 
                        NSSArena *arena)
{
    return nssCryptokiCert_GetAttributes(instance,
                                                arena, /* arena    */
                                                NULL,  /* type     */
                                                NULL,  /* id       */
                                                NULL,  /* encoding */
                                                &uid[0], /* issuer */
                                                &uid[1], /* serial */
                                                NULL,  /* subject  */
                                                NULL); /* email    */
}

static nssPKIObject *
cert_createObject(nssPKIObject *o)
{
    NSSCert *cert;
    cert = nssCert_Create(o);
    return (nssPKIObject *)cert;
}

NSS_IMPLEMENT nssPKIObjectCollection *
nssCertCollection_Create (
  NSSTrustDomain *td,
  NSSCert **certsOpt
)
{
    PRStatus status;
    nssPKIObjectCollection *collection;
    collection = nssPKIObjectCollection_Create(td);
    collection->objectType = pkiObjectType_Cert;
    collection->destroyObject = cert_destroyObject;
    collection->getUIDFromObject = cert_getUIDFromObject;
    collection->getUIDFromInstance = cert_getUIDFromInstance;
    collection->createObject = cert_createObject;
    if (certsOpt) {
	for (; *certsOpt; certsOpt++) {
	    nssPKIObject *object = (nssPKIObject *)(*certsOpt);
	    status = nssPKIObjectCollection_AddObject(collection, object);
	}
    }
    return collection;
}

NSS_IMPLEMENT NSSCert **
nssPKIObjectCollection_GetCerts (
  nssPKIObjectCollection *collection,
  NSSCert **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    PRStatus status;
    PRUint32 rvSize;
    PRBool allocated = PR_FALSE;
    if (collection->size == 0) {
	return (NSSCert **)NULL;
    }
    if (maximumOpt == 0) {
	rvSize = collection->size;
    } else {
	rvSize = PR_MIN(collection->size, maximumOpt);
    }
    if (!rvOpt) {
	rvOpt = nss_ZNEWARRAY(arenaOpt, NSSCert *, rvSize + 1);
	if (!rvOpt) {
	    return (NSSCert **)NULL;
	}
	allocated = PR_TRUE;
    }
    status = nssPKIObjectCollection_GetObjects(collection, 
                                               (nssPKIObject **)rvOpt, 
                                               rvSize);
    if (status != PR_SUCCESS) {
	if (allocated) {
	    nss_ZFreeIf(rvOpt);
	}
	return (NSSCert **)NULL;
    }
    return rvOpt;
}

/*
 * CRL/KRL collections
 */

static void
crl_destroyObject(nssPKIObject *o)
{
    NSSCRL *crl = (NSSCRL *)o;
    nssCRL_Destroy(crl);
}

static PRStatus
crl_getUIDFromObject(nssPKIObject *o, NSSItem *uid)
{
    NSSCRL *crl = (NSSCRL *)o;
    NSSDER *encoding;
    encoding = nssCRL_GetEncoding(crl);
    uid[0] = *encoding;
    uid[1].data = NULL; uid[1].size = 0;
    return PR_SUCCESS;
}

static PRStatus
crl_getUIDFromInstance(nssCryptokiObject *instance, NSSItem *uid, 
                       NSSArena *arena)
{
    return nssCryptokiCRL_GetAttributes(instance,
                                        arena,   /* arena    */
                                        &uid[0], /* encoding */
                                        NULL,    /* url      */
                                        NULL);   /* isKRL    */
}

static nssPKIObject *
crl_createObject(nssPKIObject *o)
{
    return (nssPKIObject *)nssCRL_Create(o);
}

NSS_IMPLEMENT nssPKIObjectCollection *
nssCRLCollection_Create (
  NSSTrustDomain *td,
  NSSCRL **crlsOpt
)
{
    PRStatus status;
    nssPKIObjectCollection *collection;
    collection = nssPKIObjectCollection_Create(td);
    collection->objectType = pkiObjectType_CRL;
    collection->destroyObject = crl_destroyObject;
    collection->getUIDFromObject = crl_getUIDFromObject;
    collection->getUIDFromInstance = crl_getUIDFromInstance;
    collection->createObject = crl_createObject;
    if (crlsOpt) {
	for (; *crlsOpt; crlsOpt++) {
	    nssPKIObject *object = (nssPKIObject *)(*crlsOpt);
	    status = nssPKIObjectCollection_AddObject(collection, object);
	}
    }
    return collection;
}

NSS_IMPLEMENT NSSCRL **
nssPKIObjectCollection_GetCRLs (
  nssPKIObjectCollection *collection,
  NSSCRL **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    PRStatus status;
    PRUint32 rvSize;
    PRBool allocated = PR_FALSE;
    if (collection->size == 0) {
	return (NSSCRL **)NULL;
    }
    if (maximumOpt == 0) {
	rvSize = collection->size;
    } else {
	rvSize = PR_MIN(collection->size, maximumOpt);
    }
    if (!rvOpt) {
	rvOpt = nss_ZNEWARRAY(arenaOpt, NSSCRL *, rvSize + 1);
	if (!rvOpt) {
	    return (NSSCRL **)NULL;
	}
	allocated = PR_TRUE;
    }
    status = nssPKIObjectCollection_GetObjects(collection, 
                                               (nssPKIObject **)rvOpt, 
                                               rvSize);
    if (status != PR_SUCCESS) {
	if (allocated) {
	    nss_ZFreeIf(rvOpt);
	}
	return (NSSCRL **)NULL;
    }
    return rvOpt;
}

/*
 * PrivateKey collections
 */

static void
privkey_destroyObject(nssPKIObject *o)
{
    NSSPrivateKey *pvk = (NSSPrivateKey *)o;
    nssPrivateKey_Destroy(pvk);
}

static PRStatus
privkey_getUIDFromObject(nssPKIObject *o, NSSItem *uid)
{
    NSSPrivateKey *pvk = (NSSPrivateKey *)o;
    NSSItem *id;
    id = nssPrivateKey_GetID(pvk);
    uid[0] = *id;
    return PR_SUCCESS;
}

static PRStatus
privkey_getUIDFromInstance(nssCryptokiObject *instance, NSSItem *uid, 
                           NSSArena *arena)
{
    return nssCryptokiPrivateKey_GetAttributes(instance,
                                               arena,
                                               NULL, /* type */
                                               &uid[0]);
}

static nssPKIObject *
privkey_createObject(nssPKIObject *o)
{
    NSSPrivateKey *pvk;
    pvk = nssPrivateKey_Create(o);
    return (nssPKIObject *)pvk;
}

NSS_IMPLEMENT nssPKIObjectCollection *
nssPrivateKeyCollection_Create (
  NSSTrustDomain *td,
  NSSPrivateKey **pvkOpt
)
{
    PRStatus status;
    nssPKIObjectCollection *collection;
    collection = nssPKIObjectCollection_Create(td);
    collection->objectType = pkiObjectType_PrivateKey;
    collection->destroyObject = privkey_destroyObject;
    collection->getUIDFromObject = privkey_getUIDFromObject;
    collection->getUIDFromInstance = privkey_getUIDFromInstance;
    collection->createObject = privkey_createObject;
    if (pvkOpt) {
	for (; *pvkOpt; pvkOpt++) {
	    nssPKIObject *o = (nssPKIObject *)(*pvkOpt);
	    status = nssPKIObjectCollection_AddObject(collection, o);
	}
    }
    return collection;
}

NSS_IMPLEMENT NSSPrivateKey **
nssPKIObjectCollection_GetPrivateKeys (
  nssPKIObjectCollection *collection,
  NSSPrivateKey **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    PRStatus status;
    PRUint32 rvSize;
    PRBool allocated = PR_FALSE;
    if (collection->size == 0) {
	return (NSSPrivateKey **)NULL;
    }
    if (maximumOpt == 0) {
	rvSize = collection->size;
    } else {
	rvSize = PR_MIN(collection->size, maximumOpt);
    }
    if (!rvOpt) {
	rvOpt = nss_ZNEWARRAY(arenaOpt, NSSPrivateKey *, rvSize + 1);
	if (!rvOpt) {
	    return (NSSPrivateKey **)NULL;
	}
	allocated = PR_TRUE;
    }
    status = nssPKIObjectCollection_GetObjects(collection, 
                                               (nssPKIObject **)rvOpt, 
                                               rvSize);
    if (status != PR_SUCCESS) {
	if (allocated) {
	    nss_ZFreeIf(rvOpt);
	}
	return (NSSPrivateKey **)NULL;
    }
    return rvOpt;
}

/*
 * PublicKey collections
 */

static void
pubkey_destroyObject(nssPKIObject *o)
{
    NSSPublicKey *pubk = (NSSPublicKey *)o;
    nssPublicKey_Destroy(pubk);
}

static PRStatus
pubkey_getUIDFromObject(nssPKIObject *o, NSSItem *uid)
{
    NSSPublicKey *pubk = (NSSPublicKey *)o;
    NSSItem *id;
    id = nssPublicKey_GetID(pubk);
    uid[0] = *id;
    return PR_SUCCESS;
}

static PRStatus
pubkey_getUIDFromInstance(nssCryptokiObject *instance, NSSItem *uid, 
                          NSSArena *arena)
{
    return nssCryptokiPublicKey_GetAttributes(instance,
                                              arena,
                                              NULL, /* type */
                                              &uid[0]);
}

static nssPKIObject *
pubkey_createObject(nssPKIObject *o)
{
    NSSPublicKey *pubk;
    pubk = nssPublicKey_Create(o);
    return (nssPKIObject *)pubk;
}

NSS_IMPLEMENT nssPKIObjectCollection *
nssPublicKeyCollection_Create (
  NSSTrustDomain *td,
  NSSPublicKey **pubkOpt
)
{
    PRStatus status;
    nssPKIObjectCollection *collection;
    collection = nssPKIObjectCollection_Create(td);
    collection->objectType = pkiObjectType_PublicKey;
    collection->destroyObject = pubkey_destroyObject;
    collection->getUIDFromObject = pubkey_getUIDFromObject;
    collection->getUIDFromInstance = pubkey_getUIDFromInstance;
    collection->createObject = pubkey_createObject;
    if (pubkOpt) {
	for (; *pubkOpt; pubkOpt++) {
	    nssPKIObject *o = (nssPKIObject *)(*pubkOpt);
	    status = nssPKIObjectCollection_AddObject(collection, o);
	}
    }
    return collection;
}

NSS_IMPLEMENT NSSPublicKey **
nssPKIObjectCollection_GetPublicKeys (
  nssPKIObjectCollection *collection,
  NSSPublicKey **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    PRStatus status;
    PRUint32 rvSize;
    PRBool allocated = PR_FALSE;
    if (collection->size == 0) {
	return (NSSPublicKey **)NULL;
    }
    if (maximumOpt == 0) {
	rvSize = collection->size;
    } else {
	rvSize = PR_MIN(collection->size, maximumOpt);
    }
    if (!rvOpt) {
	rvOpt = nss_ZNEWARRAY(arenaOpt, NSSPublicKey *, rvSize + 1);
	if (!rvOpt) {
	    return (NSSPublicKey **)NULL;
	}
	allocated = PR_TRUE;
    }
    status = nssPKIObjectCollection_GetObjects(collection, 
                                               (nssPKIObject **)rvOpt, 
                                               rvSize);
    if (status != PR_SUCCESS) {
	if (allocated) {
	    nss_ZFreeIf(rvOpt);
	}
	return (NSSPublicKey **)NULL;
    }
    return rvOpt;
}

NSS_IMPLEMENT PRStatus
nssPKIObjectCreator_GenerateKeyPair (
  nssPKIObjectCreator *creator,
  NSSPublicKey **pbkOpt,
  NSSPrivateKey **pvkOpt
)
{
    PRStatus status;
    PRBool temporary;
    NSSToken *source;
    nssSession *session = NULL;
    nssCryptokiObject *bkey = NULL;
    nssCryptokiObject *vkey = NULL;
    NSSSlot *slot;

    /* search the trust domain for a usable token for the keygen */
    source = nssTrustDomain_FindSourceToken(creator->td, 
                                            creator->ap, 
                                            creator->destination);
    if (!source) {
	return PR_FAILURE;
    }
    /* If we want a persistent object but the destination token can't
     * do the math, then create a temporary object on the source token
     * and move it.  Otherwise, it is of course temporary in either case.
     */
    temporary = (source != creator->destination || !creator->persistent);

    /* The key will be private, so login is required */
    slot = nssToken_GetSlot(creator->destination);
    status = nssSlot_Login(slot, creator->uhh);
    nssSlot_Destroy(slot);
    if (status == PR_FAILURE) {
	goto loser;
    }

    if (creator->session && source == creator->destination) {
	/* given a session to use on the destination token */
	session = creator->session;
    } else {
	/* need a new session for the destination token */
	session = nssTrustDomain_GetSessionForToken(creator->td, 
	                                            source, temporary);
	if (!session) {
	    goto loser;
	}
    }

    status = nssToken_GenerateKeyPair(source, session, 
                                      creator->ap, !temporary, 
                                      creator->nickname, 
                                      creator->properties, 
                                      creator->operations,
                                      &bkey, &vkey);
    if (status == PR_FAILURE) {
	goto loser;
    }

#if 0
    if (source != destination) {
	/* Have to move the keys to the destination, and destroy the sources */
	nssCryptokiObject *destbKey, *destvKey;
	nssSession *copySession;

	/* need a read/write session on the destination token */
	copySession = nssTrustDomain_GetSessionForToken(td, destination, 
	                                                PR_FALSE);
	if (!copySession) {
	    goto loser;
	}
	status = nssCryptokiKeyPair_Copy(bkey, vkey, session,
	                                 destination, copySession,
	                                 &destbKey, &destvKey,
	                                 PR_TRUE);
	nssCryptokiObject_DeleteStoredObject(bkey, session);
	nssCryptokiObject_DeleteStoredObject(vkey, session);
	bkey = vkey = NULL;
	nssSession_Destroy(copySession);
	if (status == PR_FAILURE) {
	    goto loser;
	}
	bkey = destbKey;
	vkey = destvKey;
    }
#endif

    *pbkOpt = nssPublicKey_CreateFromInstance(bkey, creator->td, NULL, NULL);
    if (!*pbkOpt) {
	goto loser;
    }
    *pvkOpt = nssPrivateKey_CreateFromInstance(vkey, creator->td, NULL, NULL);
    if (!*pvkOpt) {
	goto loser;
    }
    if (session != creator->session) {
	nssSession_Destroy(session);
    }
    nssToken_Destroy(source);
    return PR_SUCCESS;

loser:
    if (session != creator->session) {
	nssSession_Destroy(session);
    }
    if (bkey) {
	nssCryptokiObject_Destroy(bkey);
    }
    if (vkey) {
	nssCryptokiObject_Destroy(vkey);
    }
    nssToken_Destroy(source);
    return PR_FAILURE;
}

NSS_IMPLEMENT NSSSymKey *
nssPKIObjectCreator_GenerateSymKey (
  nssPKIObjectCreator *creator,
  PRUint32 keysize
)
{
    PRStatus status;
    PRBool temporary;
    NSSToken *source;
    nssSession *session = NULL;
    nssCryptokiObject *key = NULL;
    NSSSymKey *rvKey = NULL;
    NSSSlot *slot;

    /* search the trust domain for a usable token for the keygen */
    source = nssTrustDomain_FindSourceToken(creator->td, 
                                            creator->ap, 
                                            creator->destination);
    if (!source) {
	return (NSSSymKey *)NULL;
    }
    /* If we want a persistent object but the destination token can't
     * do the math, then create a temporary object on the source token
     * and move it.  Otherwise, it is of course temporary in either case.
     */
    temporary = (source != creator->destination || !creator->persistent);

    /* The key will be private, so login is required */
    slot = nssToken_GetSlot(creator->destination);
    status = nssSlot_Login(slot, creator->uhh);
    nssSlot_Destroy(slot);
    if (status == PR_FAILURE) {
	goto loser;
    }

    if (creator->session && source == creator->destination) {
	/* given a session to use on the destination token */
	session = creator->session;
    } else {
	/* need a new session for the destination token */
	session = nssTrustDomain_GetSessionForToken(creator->td, 
	                                            source, temporary);
	if (!session) {
	    goto loser;
	}
    }

    /* XXX */
    key = nssToken_GenerateSymKey(source, session, creator->ap, 
                                        keysize, NULL, !temporary, 0, 0);
    if (!key) {
	goto loser;
    }

    if (source != creator->destination) {
	/* Have to move the key to the destination, and destroy the source */
	nssCryptokiObject *destKey;
	nssSession *copySession;
	if (creator->session) {
	    /* the supplied session is for the destination token, use it */
	    copySession = creator->session;
	} else {
	    copySession = nssTrustDomain_GetSessionForToken(creator->td, 
	                                                creator->destination, 
	                                                creator->persistent);
	    if (!copySession) {
		goto loser;
	    }
	}
	destKey = nssCryptokiSymKey_Copy(key, session,
	                                       creator->destination, 
	                                       copySession, 
	                                       creator->persistent);
	nssCryptokiObject_DeleteStoredObject(key);
	key = NULL;
	if (copySession != creator->session) {
	    nssSession_Destroy(copySession);
	}
	if (!destKey) {
	    goto loser;
	}
	key = destKey;
    }

    rvKey = nssSymKey_CreateFromInstance(key, creator->td, creator->vd);
    if (!rvKey) {
	goto loser;
    }
    if (session != creator->session) {
	nssSession_Destroy(session);
    }
    nssToken_Destroy(source);
    return rvKey;

loser:
    if (session != creator->session) {
	nssSession_Destroy(session);
    }
    if (key) {
	nssCryptokiObject_Destroy(key);
    }
    nssToken_Destroy(source);
    return (NSSSymKey *)NULL;
}

struct nssTokenSessionHashStr {
  NSSArena *arena;
  PZLock *lock;
  struct token2session_str {
    NSSToken *token;
    nssSession *session;
    nssSession *rwSession;
  } *token2session;
  PRUint32 count;
  PRUint32 size;
};

/* using this interface to keep things abstract, but there's no real need
 * for a hash table here (it would be overkill), so just implement using
 * an array
 */
NSS_IMPLEMENT nssTokenSessionHash *
nssTokenSessionHash_Create (
  void
)
{
    nssTokenSessionHash *rvHash;
    NSSArena *arena;

    arena = nssArena_Create();
    if (!arena) {
	return (nssTokenSessionHash *)NULL;
    }
    rvHash = nss_ZNEW(arena, nssTokenSessionHash);
    if (!rvHash) {
	nssArena_Destroy(arena);
	return (nssTokenSessionHash *)NULL;
    }
    rvHash->arena = arena;
    rvHash->size = 2;
    rvHash->lock = PZ_NewLock(nssILockOther);
    if (!rvHash->lock) {
	nssArena_Destroy(arena);
	return (nssTokenSessionHash *)NULL;
    }
    rvHash->token2session = nss_ZNEWARRAY(arena, struct token2session_str,
                                          rvHash->size);
    if (!rvHash->token2session) {
	nssArena_Destroy(arena);
	return (nssTokenSessionHash *)NULL;
    }
    return rvHash;
}

NSS_IMPLEMENT void
nssTokenSessionHash_Destroy (
  nssTokenSessionHash *tsHash
)
{
    PRUint32 i;
    struct token2session_str *t2s;

    for (i=0; i<tsHash->count; i++) {
	t2s = &tsHash->token2session[i];
	nssToken_Destroy(t2s->token);
	if (t2s->session) {
	    nssSession_Destroy(t2s->session);
	}
	if (t2s->rwSession) {
	    nssSession_Destroy(t2s->rwSession);
	}
    }
    PZ_DestroyLock(tsHash->lock);
    nssArena_Destroy(tsHash->arena);
}

NSS_IMPLEMENT nssSession *
nssTokenSessionHash_GetSession (
  nssTokenSessionHash *tsHash,
  NSSToken *token,
  PRBool readWrite
)
{
    PRUint32 i;
    nssSession *session = NULL;
    struct token2session_str *t2s = NULL;

    PZ_Lock(tsHash->lock);
    for (i=0; i<tsHash->count; i++) {
	if (tsHash->token2session[i].token == token) {
	    t2s = &tsHash->token2session[i];
	    session = readWrite ? t2s->rwSession : t2s->session;
	    if (session) {
		goto have_session;
	    } else {
		goto new_session;
	    }
	}
    }
new_session:
    if (!t2s) {
	if (tsHash->count == tsHash->size) {
	    tsHash->size *= 2;
	    tsHash->token2session = nss_ZREALLOCARRAY(tsHash->token2session,
	                                          struct token2session_str,
	                                          tsHash->size);
	    if (!tsHash->token2session) {
		goto finish;
	    }
	}
	t2s = &tsHash->token2session[tsHash->count++];
    }
    session = nssToken_CreateSession(token, readWrite);
    if (!session) {
	goto finish;
    }
    if (readWrite) {
	t2s->rwSession = session;
    } else {
	t2s->session = session;
    }
    t2s->token = nssToken_AddRef(token);
have_session:
    session = nssSession_AddRef(session); /* get a ref */
finish:
    PZ_Unlock(tsHash->lock);
    return session;
}

