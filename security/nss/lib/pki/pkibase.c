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

struct volatile_domain_instance_str {
    PRCList link;
    NSSVolatileDomain *vd;
};

static PRStatus
virtual_copy_to_token(nssPKIObject *object, NSSToken *destination,
                      nssSession *sessionOpt, PRBool asPersistentObject,
                      NSSUTF8 *labelOpt, nssCryptokiObject **rvInstanceOpt)
{
    PR_ASSERT(0);
    nss_SetError(NSS_ERROR_INTERNAL_ERROR);
    return PR_FAILURE;
}


NSS_IMPLEMENT nssPKIObject *
nssPKIObject_Create (
  NSSTrustDomain *td,
  nssCryptokiObject *instanceOpt,
  PRUint32 size
)
{
    NSSArena *arena;
    nssPKIObject *object;

    arena = nssArena_Create();
    if (!arena) {
	return (nssPKIObject *)NULL;
    }
    object = (nssPKIObject *)nss_ZAlloc(arena, size);
    if (!object) {
	goto loser;
    }
    object->arena = arena;
    object->td = td; /* XXX */
    object->lock = PZ_NewLock(nssILockOther);
    object->copyToToken = virtual_copy_to_token;
    if (!object->lock) {
	goto loser;
    }
    if (instanceOpt) {
	if (nssPKIObject_AddInstance(object, instanceOpt) != PR_SUCCESS) {
	    goto loser;
	}
	if (instanceOpt->label) {
	    object->nickname = nssUTF8_Duplicate(instanceOpt->label, NULL);
	}
    }
    PR_AtomicIncrement(&object->refCount);
    return object;
loser:
    nssArena_Destroy(arena);
    return (nssPKIObject *)NULL;
}

NSS_IMPLEMENT PRStatus
nssPKIObject_Destroy (
  nssPKIObject *object
)
{
    PRUint32 i;
    PRStatus status;

    PR_ASSERT(object->refCount > 0);
    PR_AtomicDecrement(&object->refCount);
    status = PR_SUCCESS;
    if (object->refCount == 0) {
	for (i=0; i<object->numInstances; i++) {
	    nssCryptokiObject_Destroy(object->instances[i]);
	}
	if (object->destructor) {
	    status = object->destructor(object);
	}
	/*nssVolatileDomain_Destroy(object->vd);*/
	PZ_DestroyLock(object->lock);
	nssUTF8_Destroy(object->nickname);
	nssArena_Destroy(object->arena);
    }
    return status;
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

static nssPKIObject *
nssPKIObject_Merge (
  nssPKIObject *object1,
  nssPKIObject *object2
)
{
    PRUint32 i;
    PZ_Lock(object2->lock);
    for (i = 0; i < object2->numInstances; i++) {
	if (!nssPKIObject_HasInstanceOnToken(object1, 
	                                     object2->instances[i]->token)) 
	{
	    (void)nssPKIObject_AddInstance(object1, object2->instances[i]); 
	}
    }
    PZ_Unlock(object2->lock);
    return object1;
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
    if (tokenOpt) {
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
    if (!object->nickname) {
	object->nickname = nssUTF8_Duplicate(nickname, NULL);
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
    if (tokenOpt) {
	for (i=0; i<object->numInstances; i++) {
	    if ((!tokenOpt && object->instances[i]->label) ||
	        (object->instances[i]->token == tokenOpt)) 
	    {
		/* XXX should be copy? safe as long as caller has reference */
		nickname = object->instances[i]->label; 
		break;
	    }
	}
    } else {
	nickname = object->nickname;
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

/* XXX currently, all callers of this function are using allowMove=true,
 *     but this is in need of a scheme to determine when/how to wrap
 *     sensitive objects before moving
 */
NSS_IMPLEMENT nssCryptokiObject *
nssPKIObject_FindInstanceForAlgorithm (
  nssPKIObject *object,
  const NSSAlgNParam *ap,
  PRBool allowMove
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
    if (!instance && allowMove) {
	NSSToken *token;
	token = nssTrustDomain_FindTokenForAlgNParam(object->td, ap);
	if (token) {
	    (void)nssPKIObject_CopyToToken(object, token, NULL,
	                                   PR_FALSE, NULL, &instance);
	    nssToken_Destroy(token);
	}
    }
    return instance;
}

NSS_IMPLEMENT NSSTrustDomain *
nssPKIObject_GetTrustDomain (
  nssPKIObject *object
)
{
    return object->td;
}

static PRBool 
object_is_in_vd(nssPKIObject *object, NSSVolatileDomain *vd)
{
    PRCList *link;
    PRBool inVD = PR_FALSE;
    struct volatile_domain_instance_str *vdInstance;

    link = PR_NEXT_LINK(&object->vds);
    while (link && link != &object->vds) {
	vdInstance = (struct volatile_domain_instance_str *)link;
	if (vdInstance->vd == vd) {
	    inVD = PR_TRUE;
	    break;
	}
	link = PR_NEXT_LINK(link);
    }
    return inVD;
}

NSS_IMPLEMENT void
nssPKIObject_SetVolatileDomain (
  nssPKIObject *object,
  NSSVolatileDomain *vd
)
{
    struct volatile_domain_instance_str *vdInstance;

    PZ_Lock(object->lock);
    if (!object_is_in_vd(object, vd)) {
	/* XXX in arena? */
	vdInstance = nss_ZNEW(object->arena, 
	                      struct volatile_domain_instance_str);
	if (vdInstance) {
	    PR_INIT_CLIST(&vdInstance->link);
	    vdInstance->vd = vd; /* no addref */
	    PR_INSERT_BEFORE(&object->vds, &vdInstance->link);
	}
    }
    PZ_Unlock(object->lock);
    /* XXX probably should return error */
}

NSS_IMPLEMENT PRBool
nssPKIObject_IsInVolatileDomain (
  nssPKIObject *object,
  NSSVolatileDomain *vd
)
{
    PRBool inVD;
    PZ_Lock(object->lock);
    inVD = object_is_in_vd(object, vd);
    PZ_Unlock(object->lock);
    return inVD;
}


NSS_IMPLEMENT NSSVolatileDomain **
nssPKIObject_GetVolatileDomains (
  nssPKIObject *object,
  NSSVolatileDomain **vdsOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt,
  PRStatus *statusOpt
)
{
    PRCList *link;
    PRUint32 i;
    NSSVolatileDomain **vds;
    struct volatile_domain_instance_str *vdInstance;

    if (statusOpt) *statusOpt = PR_SUCCESS;
    if (vdsOpt) {
	vds = vdsOpt;
    } else {
	if (maximumOpt > 0) {
	    i = maximumOpt;
	} else {
	    PZ_Lock(object->lock);
	    /* count the number of VD instances */
	    for (link = PR_NEXT_LINK(&object->vds), i=0;
	         link != &object->vds; 
	         link = PR_NEXT_LINK(link), i++);
	    PZ_Unlock(object->lock);
	}
	if (i == 0) {
	    return (NSSVolatileDomain **)NULL;
	}
	vds = nss_ZNEWARRAY(arenaOpt, NSSVolatileDomain *, i + 1);
	if (!vds) {
	    if (statusOpt) *statusOpt = PR_FAILURE;
	    return (NSSVolatileDomain **)NULL;
	}
    }
    i = 0;
    vds[0] = NULL;
    PZ_Lock(object->lock);
    link = PR_NEXT_LINK(&object->vds);
    while (link && link != &object->vds) {
	vdInstance = (struct volatile_domain_instance_str *)link;
	vds[i++] = nssVolatileDomain_AddRef(vdInstance->vd);
	if (maximumOpt > 0 && i == maximumOpt)
	    break;
	link = PR_NEXT_LINK(link);
    }
    PZ_Unlock(object->lock);
    if (!vdsOpt || maximumOpt == 0) vds[i] = NULL;
    return vds;
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
	rvCerts[i] = nssCert_CreateFromInstance(instances[i], td, vdOpt);
	if (!rvCerts[i]) {
	    nssCertArray_Destroy(rvCerts); /* it's NULL-terminated */
	    return (NSSCert **)NULL;
	}
    }
    return rvCerts;
}

NSS_IMPLEMENT PRStatus
nssPKIObject_CopyToToken (
  nssPKIObject *object,
  NSSToken *destination,
  nssSession *sessionOpt,
  PRBool asPersistentObject,
  NSSUTF8 *labelOpt,
  nssCryptokiObject **rvInstanceOpt
)
{
    return object->copyToToken(object, destination, sessionOpt,
                               asPersistentObject, labelOpt, rvInstanceOpt);
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

NSS_IMPLEMENT PRIntn
nssObjectArray_Count (
  void **objects
)
{
    PRIntn n;
    void **p;
    for (p = objects, n = 0; p && *p; p++, n++);
    return n;
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
	    if (!usagesOpt ||
	        ((usagesOpt->ca & certUsages->ca) == usagesOpt->ca && 
	         (usagesOpt->peer & certUsages->peer) == usagesOpt->peer)) 
	    {
		bestCert = nssCert_AddRef(c);
	    }
	    continue;
	} else {
	    /* already have a cert for this usage, if this cert doesn't have
	     * the correct usage, continue
	     * if ths cert does match usage, defer to time/policies
	     */
	    if (usagesOpt &&
	        ((usagesOpt->ca & certUsages->ca) != usagesOpt->ca || 
	         (usagesOpt->peer & certUsages->peer) != usagesOpt->peer)) 
	    {
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

NSS_IMPLEMENT NSSPublicKey **
nssPublicKeyArray_CreateFromInstances (
  nssCryptokiObject **instances,
  NSSTrustDomain *td,
  NSSVolatileDomain *vdOpt,
  NSSArena *arenaOpt
)
{
    PRIntn i, count;
    nssCryptokiObject **ip;
    NSSPublicKey **rvBKeys;

    for (ip = instances, count = 0; *ip; ip++, count++);
    rvBKeys = nss_ZNEWARRAY(arenaOpt, NSSPublicKey *, count + 1);
    if (!rvBKeys) {
	return (NSSPublicKey **)NULL;
    }
    for (i = 0; i < count; i++) {
	rvBKeys[i] = nssPublicKey_CreateFromInstance(instances[i], td, vdOpt);
	if (!rvBKeys[i]) {
	    nssPublicKeyArray_Destroy(rvBKeys); /* it's NULL-terminated */
	    return (NSSPublicKey **)NULL;
	}
    }
    return rvBKeys;
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

NSS_IMPLEMENT NSSPrivateKey **
nssPrivateKeyArray_CreateFromInstances (
  nssCryptokiObject **instances,
  NSSTrustDomain *td,
  NSSVolatileDomain *vdOpt,
  NSSArena *arenaOpt
)
{
    PRIntn i, count;
    nssCryptokiObject **ip;
    NSSPrivateKey **rvVKeys;

    for (ip = instances, count = 0; *ip; ip++, count++);
    rvVKeys = nss_ZNEWARRAY(arenaOpt, NSSPrivateKey *, count + 1);
    if (!rvVKeys) {
	return (NSSPrivateKey **)NULL;
    }
    for (i = 0; i < count; i++) {
	rvVKeys[i] = nssPrivateKey_CreateFromInstance(instances[i], td, vdOpt);
	if (!rvVKeys[i]) {
	    nssPrivateKeyArray_Destroy(rvVKeys); /* it's NULL-terminated */
	    return (NSSPrivateKey **)NULL;
	}
    }
    return rvVKeys;
}

/*
 * Object table
 */

struct nssPKIObjectTableStr
{
  PZLock *lock;
  PLHashTable *hash;
};

static PLHashNumber
nss_pkiobject_hash (
  const void *key
)
{
    int i, j;
    PLHashNumber h;
    nssPKIObject *pkio = (nssPKIObject *)key;
    h = 0;
    for (i = 0; i < pkio->numIDs; i++) {
	for (j=0; j < pkio->uid[i]->size; j++) {
	    h = (h >> 28) ^ (h << 4) ^ 
	        ((unsigned char *)pkio->uid[i]->data)[i];
	}
    }
    return h;
}

static int
nss_compare_pkiobjects(const void *v1, const void *v2)
{
    int i;
    int rv = 0;
    nssPKIObject *pkio1 = (nssPKIObject *)v1;
    nssPKIObject *pkio2 = (nssPKIObject *)v2;
    if (pkio1->objectType != pkio2->objectType) {
	return 1;
    }
    for (i = 0; i < pkio1->numIDs; i++) {
	if (!nssItem_Equal(pkio1->uid[i], pkio1->uid[i], NULL)) {
	    rv = 1;
	    break;
	}
    }
    return rv;
}

NSS_IMPLEMENT nssPKIObjectTable *
nssPKIObjectTable_Create (
  NSSArena *arena
)
{
    nssPKIObjectTable *rvTable;

    rvTable = nss_ZNEW(arena, nssPKIObjectTable);
    if (rvTable == NULL) {
	return (nssPKIObjectTable *)NULL;
    }

    rvTable->lock = PZ_NewLock(nssILockOther);
    if (rvTable->lock == NULL) {
	return (nssPKIObjectTable *)NULL;
    }

    rvTable->hash = PL_NewHashTable(0, 
                                    nss_pkiobject_hash, 
                                    nss_compare_pkiobjects,
                                    PL_CompareValues,
                                    NULL, NULL);
    if (rvTable->hash == NULL) {
	PZ_DestroyLock(rvTable->lock);
	return (nssPKIObjectTable *)NULL;
    }
    return rvTable;
}

NSS_IMPLEMENT void
nssPKIObjectTable_Destroy (
  nssPKIObjectTable *table
)
{
    PZ_DestroyLock(table->lock);
    PL_HashTableDestroy(table->hash);
}

NSS_IMPLEMENT nssPKIObject *
nssPKIObjectTable_Add (
  nssPKIObjectTable *table,
  nssPKIObject *object
)
{
    PLHashEntry *he;
    nssPKIObject *pkio;

    PZ_Lock(table->lock);

    pkio = (nssPKIObject *)PL_HashTableLookup(table->hash, object);
    if (pkio) {
	pkio = nssPKIObject_Merge(pkio, object);
    } else {
	he = PL_HashTableAdd(table->hash, object, object);
	if( (PLHashEntry *)NULL == he ) {
	    nss_SetError(NSS_ERROR_NO_MEMORY);
	    pkio = NULL;
	} else {
	    pkio = object;
	}
    }

    PZ_Unlock(table->lock);

    return pkio;
}

NSS_IMPLEMENT PRStatus
nssPKIObjectTable_Remove (
  nssPKIObjectTable *table,
  nssPKIObject *object
)
{

    PRStatus status;
    PZ_Lock(table->lock);
    status = PL_HashTableRemove(table->hash, object);
    PZ_Unlock(table->lock);
    return status;
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

    *pbkOpt = nssPublicKey_CreateFromInstance(bkey, creator->td, NULL);
    if (!*pbkOpt) {
	goto loser;
    }
    *pvkOpt = nssPrivateKey_CreateFromInstance(vkey, creator->td, NULL);
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

