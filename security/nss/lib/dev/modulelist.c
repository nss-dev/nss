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

/* modulelist.c
 *
 * The global list of loaded modules and module databases
 */

#include "nspr.h"
#include "nssrwlk.h"

#ifndef DEVM_H
#include "devm.h"
#endif /* DEVM_H */

/* just your basic linked list */
struct global_module_list_node_str
{
    NSSModule *module;
    struct global_module_list_node_str *next;
};

struct nssGlobalModuleListStr
{
    NSSArena *arena;
    PRLock *lock;
    NSSModule *internalModule; 
    NSSModule *dbModule;
    struct global_module_list_node_str *loadedModules;
    PRUint32 numLoadedModules;
};
typedef struct nssGlobalModuleListStr nssGlobalModuleList;

/* The global module list */
static nssGlobalModuleList *nss_global_module_list = NULL;

NSS_IMPLEMENT PRStatus
nss_InitializeGlobalModuleList
(
  void
)
{
    NSSArena *arena;
    nssGlobalModuleList *mlist = NULL;
    arena = nssArena_Create();
    if (!arena) {
	return PR_FAILURE;
    }
    nss_global_module_list = nss_ZNEW(arena, nssGlobalModuleList);
    if (!nss_global_module_list) {
	nssArena_Destroy(arena);
	return PR_FAILURE;
    }
    mlist = nss_global_module_list;
    mlist->lock = PZ_NewLock(nssILockOther);
    if (!mlist->lock) {
	nssArena_Destroy(arena);
	return PR_FAILURE;
    }
    mlist->arena = arena;
    return PR_SUCCESS;
}

NSS_IMPLEMENT PRStatus
nss_DestroyGlobalModuleList
(
  void
)
{
    PRStatus nssrv = PR_FAILURE;
    struct global_module_list_node_str *node;
    nssGlobalModuleList *mlist = nss_global_module_list;
    PR_DestroyLock(mlist->lock);
    node = mlist->loadedModules;
    while (node != NULL) {
	nssModule_Destroy(node->module);
	node = node->next;
    }
    nssModule_Destroy(mlist->internalModule);
    nssModule_Destroy(mlist->dbModule);
    nssArena_Destroy(mlist->arena);
    return nssrv;
}

NSS_IMPLEMENT NSSModule **
nss_GetLoadedModules
(
  void
)
{
    PRUint32 i;
    struct global_module_list_node_str *node;
    nssGlobalModuleList *mlist = nss_global_module_list;
    NSSModule **rvModules = NULL;
    PR_Lock(mlist->lock);
    node = mlist->loadedModules;
    rvModules = nss_ZNEWARRAY(NULL, NSSModule *, mlist->numLoadedModules + 1);
    if (rvModules) {
	i = 0;
	while (node != NULL) {
	    rvModules[i++] = nssModule_AddRef(node->module);
	    node = node->next;
	}
    }
    PR_Unlock(mlist->lock);
    return rvModules;
}

#ifdef nodef
NSS_IMPLEMENT NSSSlot **
nss_GetActiveSlots
(
  void
)
{
    NSSSlot **rvSlots = NULL;
    PRUint32 i, numSlots;
    struct global_module_list_node_str *node;
    nssGlobalModuleList *mlist = nss_global_module_list;
    PR_Lock(mlist->lock);
    node = mlist->loadedModules;
    numSlots = 0;
    while (node != NULL) {
	numSlots += nssModule_GetNumberOfSlots(node->module);
	node = node->next;
    }
    node = mlist->loadedModules;
    rvSlots = nss_ZNEWARRAY(NULL, NSSSlot *, numSlots + 1);
    if (rvSlots) {
	i = 0;
	while (node != NULL) {
	    (void)nssModule_GetSlots(node->module, &rvSlots[i], 0);
	    i += nssModule_GetNumberOfSlots(node->module);
	    node = node->next;
	}
    }
    PR_Unlock(mlist->lock);
    return rvSlots;
}
#endif /* nodef */

NSS_IMPLEMENT PRStatus
nssGlobalModuleList_Add
(
  NSSModule *module
)
{
    PRStatus nssrv = PR_SUCCESS;
    struct global_module_list_node_str *node, *bnode;
    nssGlobalModuleList *mlist = nss_global_module_list;
    PR_Lock(mlist->lock);
    if (nssModule_IsModuleDBOnly(module)) {
	/* The module database, store it separately, and not in the list */
	mlist->dbModule = nssModule_AddRef(module);
    } else {
	/* A regular module, add it to the list */
	node = nss_ZNEW(mlist->arena, struct global_module_list_node_str);
	node->module = nssModule_AddRef(module);
	if (mlist->loadedModules == NULL) {
	    mlist->loadedModules = node;
	} else {
	    /* add it to the tail */
	    bnode = mlist->loadedModules;
	    /* should the list be checked to see if it already exists? */
	    while (bnode->next != NULL) bnode = bnode->next;
	    bnode->next = node;
	}
	if (nssModule_IsInternal(module)) {
	    /* The internal module, store it separately */
	    mlist->internalModule = nssModule_AddRef(module);
	}
	mlist->numLoadedModules++;
    }
    PR_Unlock(mlist->lock);
    return nssrv;
}

NSS_IMPLEMENT PRStatus
nssGlobalModuleList_Remove
(
  NSSModule *module
)
{
    PRStatus nssrv = PR_FAILURE;
    struct global_module_list_node_str *node, *bnode;
    nssGlobalModuleList *mlist = nss_global_module_list;
    PR_Lock(mlist->lock);
    bnode = NULL;
    node = mlist->loadedModules;
    while (node != NULL) {
	if (node->module == module) {
	    if (bnode) {
		bnode->next = node->next;
	    } else {
		mlist->loadedModules = node->next;
	    }
	    nss_ZFreeIf(node);
	    nssrv = PR_SUCCESS;
	    mlist->numLoadedModules--;
	    break;
	}
	bnode = node;
	node = node->next;
    }
    PR_Unlock(mlist->lock);
    return nssrv;
}

NSS_IMPLEMENT NSSModule *
nssGlobalModuleList_FindModuleByName
(
  NSSUTF8 *moduleName
)
{
    PRStatus nssrv;
    NSSModule *module = NULL;
    struct global_module_list_node_str *node;
    nssGlobalModuleList *mlist = nss_global_module_list;
    PR_Lock(mlist->lock);
    node = mlist->loadedModules;
    while (node != NULL) {
	NSSUTF8 *name = nssModule_GetName(node->module);
	if (nssUTF8_Equal(name, moduleName, &nssrv)) {
	    module = nssModule_AddRef(node->module);
	    break;
	}
	node = node->next;
    }
    PR_Unlock(mlist->lock);
    return module;
}

NSS_IMPLEMENT NSSSlot *
nssGlobalModuleList_FindSlotByName
(
  NSSUTF8 *slotName
)
{
    NSSSlot *slot = NULL;
    struct global_module_list_node_str *node;
    nssGlobalModuleList *mlist = nss_global_module_list;
    PR_Lock(mlist->lock);
    node = mlist->loadedModules;
    while (node != NULL) {
	slot = nssModule_FindSlotByName(node->module, slotName);
	node = node->next;
    }
    PR_Unlock(mlist->lock);
    return slot;
}

NSS_IMPLEMENT NSSToken *
nssGlobalModuleList_FindTokenByName
(
  NSSUTF8 *tokenName
)
{
    NSSToken *token = NULL;
    struct global_module_list_node_str *node;
    nssGlobalModuleList *mlist = nss_global_module_list;
    PR_Lock(mlist->lock);
    node = mlist->loadedModules;
    while (node != NULL) {
	token = nssModule_FindTokenByName(node->module, tokenName);
	node = node->next;
    }
    PR_Unlock(mlist->lock);
    return token;
}

/* XXX this is hack for now */
NSS_IMPLEMENT NSSToken *
nss_GetDefaultCryptoToken
(
  void
)
{
    NSSModule *module;
    NSSSlot **slots;
    NSSToken *rvToken;
    nssGlobalModuleList *mlist = nss_global_module_list;
    PR_Lock(mlist->lock);
    module = mlist->internalModule;
    PR_Unlock(mlist->lock);
    slots = nssModule_GetSlots(module);
    rvToken = nssSlot_GetToken(slots[0]);
    nssSlotArray_Destroy(slots);
    return rvToken;
}

/* XXX this is hack for now */
NSS_IMPLEMENT NSSToken *
nss_GetDefaultDatabaseToken
(
  void
)
{
    NSSModule *module;
    NSSSlot **slots;
    NSSToken *rvToken;
    nssGlobalModuleList *mlist = nss_global_module_list;
    PR_Lock(mlist->lock);
    module = mlist->internalModule;
    PR_Unlock(mlist->lock);
    slots = nssModule_GetSlots(module);
    rvToken = nssSlot_GetToken(slots[1]);
    nssSlotArray_Destroy(slots);
    return rvToken;
}

NSS_IMPLEMENT NSSModule **
NSS_GetLoadedModules
(
  void
)
{
    return nss_GetLoadedModules();
}

NSS_IMPLEMENT NSSModule *
NSS_FindModuleByName
(
  NSSUTF8 *name
)
{
    return nssGlobalModuleList_FindModuleByName(name);
}

