/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Netscape security libraries.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 2001
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */
/*
 * The following handles the loading, unloading and management of
 * various PCKS #11 modules
 */

#include <ctype.h>
#include "pkcs11.h"
#include "seccomon.h"
#include "secmod.h"
#include "secmodi.h"
#include "secmodti.h"
#include "pki3hack.h"
#include "secerr.h"
   
#include "pk11pars.h" 

/* create a new module */
static  SECMODModule *
secmod_NewModule(void)
{
    SECMODModule *newMod;
    PRArenaPool *arena;


    /* create an arena in which dllName and commonName can be
     * allocated.
     */
    arena = PORT_NewArena(512);
    if (arena == NULL) {
	return NULL;
    }

    newMod = (SECMODModule *)PORT_ArenaAlloc(arena,sizeof (SECMODModule));
    if (newMod == NULL) {
	PORT_FreeArena(arena,PR_FALSE);
	return NULL;
    }

    /*
     * initialize of the fields of the module
     */
    newMod->arena = arena;
    newMod->internal = PR_FALSE;
    newMod->loaded = PR_FALSE;
    newMod->isFIPS = PR_FALSE;
    newMod->dllName = NULL;
    newMod->commonName = NULL;
    newMod->library = NULL;
    newMod->functionList = NULL;
    newMod->slotCount = 0;
    newMod->slots = NULL;
    newMod->slotInfo = NULL;
    newMod->slotInfoCount = 0;
    newMod->refCount = 1;
    newMod->ssl[0] = 0;
    newMod->ssl[1] = 0;
    newMod->libraryParams = NULL;
    newMod->moduleDBFunc = NULL;
    newMod->parent = NULL;
    newMod->isCritical = PR_FALSE;
    newMod->isModuleDB = PR_FALSE;
    newMod->moduleDBOnly = PR_FALSE;
    newMod->trustOrder = 0;
    newMod->cipherOrder = 0;
    newMod->evControlMask = 0;
    newMod->refLock = PZ_NewLock(nssILockRefLock);
    if (newMod->refLock == NULL) {
	PORT_FreeArena(arena,PR_FALSE);
	return NULL;
    }
    return newMod;
    
}

/* private flags. */
/* The meaing of these flags is as follows:
 *
 * SECMOD_FLAG_IS_MODULE_DB - This is a module that accesses the database of
 *   other modules to load. Module DBs are loadable modules that tells
 *   NSS which PKCS #11 modules to load and when. These module DBs are 
 *   chainable. That is, one module DB can load another one. NSS system init 
 *   design takes advantage of this feature. In system NSS, a fixed system 
 *   module DB loads the system defined libraries, then chains out to the 
 *   traditional module DBs to load any system or user configured modules 
 *   (like smart cards). This bit is the same as the already existing meaning 
 *   of  isModuleDB = PR_TRUE. None of the other flags should be set if this
 *   flag isn't on.
 *
 * SECMOD_FLAG_SKIP_FIRST - This flag tells NSS to skip the first 
 *   PKCS #11 module presented by a module DB. This allows the OS to load a 
 *   softoken from the system module, then ask the existing module DB code to 
 *   load the other PKCS #11 modules in that module DB (skipping it's request 
 *   to load softoken). This gives the system init finer control over the 
 *   configuration of that softoken module.
 *
 * SECMOD_FLAG_DEFAULT_MODDB - This flag allows system init to mark a 
 *   different module DB as the 'default' module DB (the one in which 
 *   'Add module' changes will go). Without this flag NSS takes the first 
 *   module as the default Module DB, but in system NSS, that first module 
 *   is the system module, which is likely read only (at least to the user).
 *   This  allows system NSS to delegate those changes to the user's module DB, 
 *   preserving the user's ability to load new PKCS #11 modules (which only 
 *   affect him), from existing applications like Firefox.
 */
#define SECMOD_FLAG_IS_MODULE_DB  0x01 /* must be set if any of the other flags
                                        * are set */
#define SECMOD_FLAG_SKIP_FIRST    0x02
#define SECMOD_FLAG_DEFAULT_MODDB 0x04

/*
 * for 3.4 we continue to use the old SECMODModule structure
 */
SECMODModule *
SECMOD_CreateModule(const char *library, const char *moduleName, 
				const char *parameters, const char *nss)
{
    SECMODModule *mod = secmod_NewModule();
    char *slotParams,*ciphers;
    /* pk11pars.h still does not have const char * interfaces */
    char *nssc = (char *)nss;
    if (mod == NULL) return NULL;

    mod->commonName = PORT_ArenaStrdup(mod->arena,moduleName ? moduleName : "");
    if (library) {
	mod->dllName = PORT_ArenaStrdup(mod->arena,library);
    }
    /* new field */
    if (parameters) {
	mod->libraryParams = PORT_ArenaStrdup(mod->arena,parameters);
    }
    mod->internal   = secmod_argHasFlag("flags","internal",nssc);
    mod->isFIPS     = secmod_argHasFlag("flags","FIPS",nssc);
    mod->isCritical = secmod_argHasFlag("flags","critical",nssc);
    slotParams      = secmod_argGetParamValue("slotParams",nssc);
    mod->slotInfo   = secmod_argParseSlotInfo(mod->arena,slotParams,
							&mod->slotInfoCount);
    if (slotParams) PORT_Free(slotParams);
    /* new field */
    mod->trustOrder  = secmod_argReadLong("trustOrder",nssc,
					SECMOD_DEFAULT_TRUST_ORDER,NULL);
    /* new field */
    mod->cipherOrder = secmod_argReadLong("cipherOrder",nssc,
					SECMOD_DEFAULT_CIPHER_ORDER,NULL);
    /* new field */
    mod->isModuleDB   = secmod_argHasFlag("flags","moduleDB",nssc);
    mod->moduleDBOnly = secmod_argHasFlag("flags","moduleDBOnly",nssc);
    if (mod->moduleDBOnly) mod->isModuleDB = PR_TRUE;

    /* we need more bits, but we also want to preserve binary compatibility 
     * so we overload the isModuleDB PRBool with additional flags. 
     * These flags are only valid if mod->isModuleDB is already set.
     * NOTE: this depends on the fact that PRBool is at least a char on 
     * all platforms. These flags are only valid if moduleDB is set, so 
     * code checking if (mod->isModuleDB) will continue to work correctly. */
    if (mod->isModuleDB) {
	char flags = SECMOD_FLAG_IS_MODULE_DB;
	if (secmod_argHasFlag("flags","skipFirst",nssc)) {
	    flags |= SECMOD_FLAG_SKIP_FIRST;
	}
	if (secmod_argHasFlag("flags","defaultModDB",nssc)) {
	    flags |= SECMOD_FLAG_DEFAULT_MODDB;
	}
	/* additional moduleDB flags could be added here in the future */
	mod->isModuleDB = (PRBool) flags;
    }

    ciphers = secmod_argGetParamValue("ciphers",nssc);
    secmod_argSetNewCipherFlags(&mod->ssl[0],ciphers);
    if (ciphers) PORT_Free(ciphers);

    secmod_PrivateModuleCount++;

    return mod;
}

PRBool
SECMOD_GetSkipFirstFlag(SECMODModule *mod)
{
   char flags = (char) mod->isModuleDB;

   return (flags & SECMOD_FLAG_SKIP_FIRST) ? PR_TRUE : PR_FALSE;
}

PRBool
SECMOD_GetDefaultModDBFlag(SECMODModule *mod)
{
   char flags = (char) mod->isModuleDB;

   return (flags & SECMOD_FLAG_DEFAULT_MODDB) ? PR_TRUE : PR_FALSE;
}

static char *
secmod_mkModuleSpec(SECMODModule * module)
{
    char *nss = NULL, *modSpec = NULL, **slotStrings = NULL;
    int slotCount, i, si;
    SECMODListLock *moduleLock = SECMOD_GetDefaultModuleListLock();

    /* allocate target slot info strings */
    slotCount = 0;

    SECMOD_GetReadLock(moduleLock);
    if (module->slotCount) {
	for (i=0; i < module->slotCount; i++) {
	    if (module->slots[i]->defaultFlags !=0) {
		slotCount++;
	    }
	}
    } else {
	slotCount = module->slotInfoCount;
    }

    slotStrings = (char **)PORT_ZAlloc(slotCount*sizeof(char *));
    if (slotStrings == NULL) {
        SECMOD_ReleaseReadLock(moduleLock);
	goto loser;
    }


    /* build the slot info strings */
    if (module->slotCount) {
	for (i=0, si= 0; i < module->slotCount; i++) {
	    if (module->slots[i]->defaultFlags) {
		PORT_Assert(si < slotCount);
		if (si >= slotCount) break;
		slotStrings[si] = secmod_mkSlotString(module->slots[i]->slotID,
			module->slots[i]->defaultFlags,
			module->slots[i]->timeout,
			module->slots[i]->askpw,
			module->slots[i]->hasRootCerts,
			module->slots[i]->hasRootTrust);
		si++;
	    }
	}
     } else {
	for (i=0; i < slotCount; i++) {
		slotStrings[i] = secmod_mkSlotString(module->slotInfo[i].slotID,
			module->slotInfo[i].defaultFlags,
			module->slotInfo[i].timeout,
			module->slotInfo[i].askpw,
			module->slotInfo[i].hasRootCerts,
			module->slotInfo[i].hasRootTrust);
	}
    }

    SECMOD_ReleaseReadLock(moduleLock);
    nss = secmod_mkNSS(slotStrings,slotCount,module->internal, module->isFIPS,
		       module->isModuleDB, module->moduleDBOnly, 
		       module->isCritical, module->trustOrder,
		       module->cipherOrder,module->ssl[0],module->ssl[1]);
    modSpec= secmod_mkNewModuleSpec(module->dllName,module->commonName,
						module->libraryParams,nss);
    PORT_Free(slotStrings);
    PR_smprintf_free(nss);
loser:
    return (modSpec);
}
    

char **
SECMOD_GetModuleSpecList(SECMODModule *module)
{
    SECMODModuleDBFunc func = (SECMODModuleDBFunc) module->moduleDBFunc;
    if (func) {
	return (*func)(SECMOD_MODULE_DB_FUNCTION_FIND,
		module->libraryParams,NULL);
    }
    return NULL;
}

SECStatus
SECMOD_AddPermDB(SECMODModule *module)
{
    SECMODModuleDBFunc func;
    char *moduleSpec;
    char **retString;

    if (module->parent == NULL) return SECFailure;

    func  = (SECMODModuleDBFunc) module->parent->moduleDBFunc;
    if (func) {
	moduleSpec = secmod_mkModuleSpec(module);
	retString = (*func)(SECMOD_MODULE_DB_FUNCTION_ADD,
		module->parent->libraryParams,moduleSpec);
	PORT_Free(moduleSpec);
	if (retString != NULL) return SECSuccess;
    }
    return SECFailure;
}

SECStatus
SECMOD_DeletePermDB(SECMODModule *module)
{
    SECMODModuleDBFunc func;
    char *moduleSpec;
    char **retString;

    if (module->parent == NULL) return SECFailure;

    func  = (SECMODModuleDBFunc) module->parent->moduleDBFunc;
    if (func) {
	moduleSpec = secmod_mkModuleSpec(module);
	retString = (*func)(SECMOD_MODULE_DB_FUNCTION_DEL,
		module->parent->libraryParams,moduleSpec);
	PORT_Free(moduleSpec);
	if (retString != NULL) return SECSuccess;
    }
    return SECFailure;
}

SECStatus
SECMOD_FreeModuleSpecList(SECMODModule *module, char **moduleSpecList)
{
    SECMODModuleDBFunc func = (SECMODModuleDBFunc) module->moduleDBFunc;
    char **retString;
    if (func) {
	retString = (*func)(SECMOD_MODULE_DB_FUNCTION_RELEASE,
		module->libraryParams,moduleSpecList);
	if (retString != NULL) return SECSuccess;
    }
    return SECFailure;
}

/*
 * load a PKCS#11 module but do not add it to the default NSS trust domain
 */
SECMODModule *
SECMOD_LoadModule(char *modulespec,SECMODModule *parent, PRBool recurse)
{
    char *library = NULL, *moduleName = NULL, *parameters = NULL, *nss= NULL;
    SECStatus status;
    SECMODModule *module = NULL;
    SECStatus rv;

    /* initialize the underlying module structures */
    SECMOD_Init();

    status = secmod_argParseModuleSpec(modulespec, &library, &moduleName, 
							&parameters, &nss);
    if (status != SECSuccess) {
	goto loser;
    }

    module = SECMOD_CreateModule(library, moduleName, parameters, nss);
    if (library) PORT_Free(library);
    if (moduleName) PORT_Free(moduleName);
    if (parameters) PORT_Free(parameters);
    if (nss) PORT_Free(nss);
    if (!module) {
	goto loser;
    }
    if (parent) {
    	module->parent = SECMOD_ReferenceModule(parent);
    }

    /* load it */
    rv = SECMOD_LoadPKCS11Module(module);
    if (rv != SECSuccess) {
	goto loser;
    }

    if (recurse && module->isModuleDB) {
	char ** moduleSpecList;
	PORT_SetError(0);

	moduleSpecList = SECMOD_GetModuleSpecList(module);
	if (moduleSpecList) {
	    char **index;

	    index = moduleSpecList;
	    if (*index && SECMOD_GetSkipFirstFlag(module)) {
		index++;
	    }

	    for (; *index; index++) {
		SECMODModule *child;
		child = SECMOD_LoadModule(*index,module,PR_TRUE);
		if (!child) break;
		if (child->isCritical && !child->loaded) {
		    int err = PORT_GetError();
		    if (!err)  
			err = SEC_ERROR_NO_MODULE;
		    SECMOD_DestroyModule(child);
		    PORT_SetError(err);
		    rv = SECFailure;
		    break;
		}
		SECMOD_DestroyModule(child);
	    }
	    SECMOD_FreeModuleSpecList(module,moduleSpecList);
	} else {
	    if (!PORT_GetError())
		PORT_SetError(SEC_ERROR_NO_MODULE);
	    rv = SECFailure;
	}
    }

    if (rv != SECSuccess) {
	goto loser;
    }


    /* inherit the reference */
    if (!module->moduleDBOnly) {
	SECMOD_AddModuleToList(module);
    } else {
	SECMOD_AddModuleToDBOnlyList(module);
    }
   
    /* handle any additional work here */
    return module;

loser:
    if (module) {
	if (module->loaded) {
	    SECMOD_UnloadModule(module);
	}
	SECMOD_AddModuleToUnloadList(module);
    }
    return module;
}

/*
 * load a PKCS#11 module and add it to the default NSS trust domain
 */
SECMODModule *
SECMOD_LoadUserModule(char *modulespec,SECMODModule *parent, PRBool recurse)
{
    SECStatus rv = SECSuccess;
    SECMODModule * newmod = SECMOD_LoadModule(modulespec, parent, recurse);
    SECMODListLock *moduleLock = SECMOD_GetDefaultModuleListLock();

    if (newmod) {
	SECMOD_GetReadLock(moduleLock);
        rv = STAN_AddModuleToDefaultTrustDomain(newmod);
	SECMOD_ReleaseReadLock(moduleLock);
        if (SECSuccess != rv) {
            SECMOD_DestroyModule(newmod);
            return NULL;
        }
    }
    return newmod;
}

/*
 * remove the PKCS#11 module from the default NSS trust domain, call
 * C_Finalize, and destroy the module structure
 */
SECStatus SECMOD_UnloadUserModule(SECMODModule *mod)
{
    SECStatus rv = SECSuccess;
    int atype = 0;
    SECMODListLock *moduleLock = SECMOD_GetDefaultModuleListLock();
    if (!mod) {
        return SECFailure;
    }

    SECMOD_GetReadLock(moduleLock);
    rv = STAN_RemoveModuleFromDefaultTrustDomain(mod);
    SECMOD_ReleaseReadLock(moduleLock);
    if (SECSuccess != rv) {
        return SECFailure;
    }
    return SECMOD_DeleteModuleEx(NULL, mod, &atype, PR_FALSE);
}

