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

#ifndef NSSCKEPV_H
#include "nssckepv.h"
#endif /* NSSCKEPV_H */

#ifndef DEVM_H
#include "devm.h"
#endif /* DEVM_H */

#ifndef CKHELPER_H
#include "ckhelper.h"
#endif /* CKHELPER_H */

NSS_IMPLEMENT nssCryptokiObject *
nssCryptokiObject_Create (
  NSSToken *t, 
  nssSession *session,
  CK_OBJECT_HANDLE h
)
{
    PRStatus status;
    NSSSlot *slot;
    nssCryptokiObject *object;
    CK_BBOOL *isTokenObject;
    CK_ATTRIBUTE cert_template[] = {
	{ CKA_TOKEN, NULL, 0 },
	{ CKA_LABEL, NULL, 0 }
    };
    slot = nssToken_GetSlot(t);
    status = nssCKObject_GetAttributes(h, cert_template, 2,
                                       NULL, session, slot);
    nssSlot_Destroy(slot);
    if (status != PR_SUCCESS) {
	/* a failure here indicates a device error */
	return (nssCryptokiObject *)NULL;
    }
    object = nss_ZNEW(NULL, nssCryptokiObject);
    if (!object) {
	return (nssCryptokiObject *)NULL;
    }
    object->handle = h;
    object->session = nssSession_AddRef(session);
    object->token = nssToken_AddRef(t);
    isTokenObject = (CK_BBOOL *)cert_template[0].pValue;
    object->isTokenObject = *isTokenObject;
    nss_ZFreeIf(isTokenObject);
    NSS_CK_ATTRIBUTE_TO_UTF8(&cert_template[1], object->label);
    return object;
}

NSS_IMPLEMENT void
nssCryptokiObject_Destroy (
  nssCryptokiObject *object
)
{
    if (object) {
	nssToken_Destroy(object->token);
	nssSession_Destroy(object->session);
	nss_ZFreeIf(object->label);
	nss_ZFreeIf(object);
    }
}

NSS_IMPLEMENT PRStatus
nssCryptokiObject_DeleteStoredObject (
  nssCryptokiObject *object
)
{
    CK_RV ckrv;
    nssSession *rwSession; /* XXX is there a better way? */
    void *epv = nssToken_GetCryptokiEPV(object->token);

    if (!object->isTokenObject || nssSession_IsReadWrite(object->session)) {
	rwSession = object->session;
    } else {
	rwSession = nssToken_CreateSession(object->token, PR_TRUE);
	if (!rwSession) {
	    return PR_FAILURE;
	}
    }

    nssSession_EnterMonitor(rwSession);
    ckrv = CKAPI(epv)->C_DestroyObject(rwSession->handle, 
                                       object->handle);
    nssSession_ExitMonitor(rwSession);
    /* Destroying the object's data.  The object is useless at this point
     * anyway.
     */
    if (rwSession != object->session) {
	nssSession_Destroy(rwSession);
    }
    nssCryptokiObject_Destroy(object);
    return (ckrv == CKR_OK) ? PR_SUCCESS : PR_FAILURE;
}

NSS_IMPLEMENT nssCryptokiObject *
nssCryptokiObject_Clone (
  nssCryptokiObject *object
)
{
    nssCryptokiObject *rvObject;
    rvObject = nss_ZNEW(NULL, nssCryptokiObject);
    if (rvObject) {
	rvObject->handle = object->handle;
	rvObject->token = nssToken_AddRef(object->token);
	rvObject->session = nssSession_AddRef(object->session);
	rvObject->isTokenObject = object->isTokenObject;
	if (object->label) {
	    rvObject->label = nssUTF8_Duplicate(object->label, NULL);
	}
    }
    return rvObject;
}

NSS_IMPLEMENT nssCryptokiObject *
nssCryptokiObject_WeakClone (
  nssCryptokiObject *object,
  nssCryptokiObject *copyObject
)
{
    copyObject->handle = object->handle;
    copyObject->token = nssToken_AddRef(object->token);
    copyObject->session = nssSession_AddRef(object->session);
    copyObject->isTokenObject = object->isTokenObject;
    copyObject->label = NULL;
    return copyObject;
}


NSS_EXTERN PRBool
nssCryptokiObject_Equal (
  nssCryptokiObject *o1,
  nssCryptokiObject *o2
)
{
    return (o1->token == o2->token && o1->handle == o2->handle);
}

NSS_IMPLEMENT PRUint32
nssPKCS11String_Length(CK_CHAR *pkcs11Str, PRUint32 bufLen)
{
    PRInt32 i;
    for (i = bufLen - 1; i>=0; ) {
	if (pkcs11Str[i] != ' ' && pkcs11Str[i] != '\0') break;
	--i;
    }
    return (PRUint32)(i + 1);
}

/*
 * Slot arrays
 */

NSS_IMPLEMENT NSSSlot **
nssSlotArray_Clone (
  NSSSlot **slots
)
{
    NSSSlot **rvSlots = NULL;
    NSSSlot **sp = slots;
    PRUint32 count = 0;
    while (sp && *sp) count++;
    if (count > 0) {
	rvSlots = nss_ZNEWARRAY(NULL, NSSSlot *, count + 1);
	if (rvSlots) {
	    sp = slots;
	    count = 0;
	    for (sp = slots; *sp; sp++) {
		rvSlots[count++] = nssSlot_AddRef(*sp);
	    }
	}
    }
    return rvSlots;
}

NSS_IMPLEMENT void
nssModuleArray_Destroy (
  NSSModule **modules
)
{
    if (modules) {
	NSSModule **mp;
	for (mp = modules; *mp; mp++) {
	    nssModule_Destroy(*mp);
	}
	nss_ZFreeIf(modules);
    }
}

NSS_IMPLEMENT void
NSSModuleArray_Destroy (
  NSSModule **modules
)
{
    nssModuleArray_Destroy(modules);
}

NSS_IMPLEMENT void
nssSlotArray_Destroy (
  NSSSlot **slots
)
{
    if (slots) {
	NSSSlot **slotp;
	for (slotp = slots; *slotp; slotp++) {
	    nssSlot_Destroy(*slotp);
	}
	nss_ZFreeIf(slots);
    }
}

NSS_IMPLEMENT void
NSSSlotArray_Destroy (
  NSSSlot **slots
)
{
    nssSlotArray_Destroy(slots);
}

NSS_IMPLEMENT void
nssTokenArray_Destroy (
  NSSToken **tokens
)
{
    if (tokens) {
	NSSToken **tokenp;
	for (tokenp = tokens; *tokenp; tokenp++) {
	    nssToken_Destroy(*tokenp);
	}
	nss_ZFreeIf(tokens);
    }
}

NSS_IMPLEMENT void
NSSTokenArray_Destroy (
  NSSToken **tokens
)
{
    nssTokenArray_Destroy(tokens);
}

NSS_IMPLEMENT void
nssCryptokiObjectArray_Destroy (
  nssCryptokiObject **objects
)
{
    if (objects) {
	nssCryptokiObject **op;
	for (op = objects; *op; op++) {
	    nssCryptokiObject_Destroy(*op);
	}
	nss_ZFreeIf(objects);
    }
}

