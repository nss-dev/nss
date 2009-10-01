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

#define SECMOD_SPEC_COPY(new, start, end)    \
  if (end > start) {                         \
	int _cnt = end - start;	             \
	PORT_Memcpy(new, start, _cnt);       \
	new += _cnt;                         \
  }

/*
 * Find any tokens= values in the module spec. 
 * Always return a new spec which does not have any tokens= arguments.
 * If tokens= arguments are found, Split the the various tokens defined into
 * an array of child specs to return.
 *
 * Caller is responsible for freeing the child spec and the new token
 * spec.
 */
char *
secmod_ParseModuleSpecForTokens(char *moduleSpec, char ***children, 
				CK_SLOT_ID **ids)
{
    char       *newSpec     = PORT_Alloc(PORT_Strlen(moduleSpec)+2);
    char       *newSpecPtr  = newSpec;
    char       *modulePrev  = moduleSpec;
    char       *target      = NULL;
    char       **childArray = NULL;
    char       *tokenIndex;
    CK_SLOT_ID *idArray     = NULL;
    int        tokenCount = 0;
    int        i;

    if (newSpec == NULL) {
	return NULL;
    }

    *children = NULL;
    if (ids) {
	*ids = NULL;
    }
    moduleSpec = secmod_argStrip(moduleSpec);
    SECMOD_SPEC_COPY(newSpecPtr, modulePrev, moduleSpec);

    /*
     * walk down the list. if we find a tokens= argument, save it,
     * otherise copy the argument.
     */
    while (*moduleSpec) {
	int next;
	modulePrev = moduleSpec;
	SECMOD_HANDLE_STRING_ARG(moduleSpec, target, "tokens=",
			modulePrev = moduleSpec; /* skip copying */ )
	SECMOD_HANDLE_FINAL_ARG(moduleSpec)
	SECMOD_SPEC_COPY(newSpecPtr, modulePrev, moduleSpec);
    }
    *newSpecPtr = 0;

    /* no target found, return the newSpec */
    if (target == NULL) {
	return newSpec;
    }

    /* now build the child array from target */
    /*first count them */
    for (tokenIndex = secmod_argStrip(target); *tokenIndex;
	tokenIndex = secmod_argStrip(secmod_argSkipParameter(tokenIndex))) {
	tokenCount++;
    }

    childArray = PORT_NewArray(char *, tokenCount+1);
    if (childArray == NULL) {
	/* just return the spec as is then */
	PORT_Free(target);
	return newSpec;
    }
    if (ids) {
	idArray = PORT_NewArray(CK_SLOT_ID, tokenCount+1);
	if (idArray == NULL) {
	    PORT_Free(childArray);
	    PORT_Free(target);
	    return newSpec;
	}
    }

    /* now fill them in */
    for (tokenIndex = secmod_argStrip(target), i=0 ; 
			*tokenIndex && (i < tokenCount); 
			tokenIndex=secmod_argStrip(tokenIndex)) {
	int next;
	char *name = secmod_argGetName(tokenIndex, &next);
	tokenIndex += next;

 	if (idArray) {
	   idArray[i] = secmod_argDecodeNumber(name);
	}

	PORT_Free(name); /* drop the explicit number */

	/* if anything is left, copy the args to the child array */
	if (!secmod_argIsBlank(*tokenIndex)) {
	    childArray[i++] = secmod_argFetchValue(tokenIndex, &next);
	    tokenIndex += next;
	}
    }

    PORT_Free(target);
    childArray[i] = 0;
    if (idArray) {
	idArray[i] = 0;
    }

    /* return it */
    *children = childArray;
    if (ids) {
	*ids = idArray;
    }
    return newSpec;
}

void
secmod_FreeChildren(char **children, CK_SLOT_ID *ids)
{
    char **thisChild;

    if (!children) {
	return;
    }

    for (thisChild = children; thisChild && *thisChild; thisChild++ ) {
	PORT_Free(*thisChild);
    }
    PORT_Free(children);
    if (ids) {
	PORT_Free(ids);
    }
    return;
}


static int
secmod_escapeSize(const char *string, char quote)
{
    int escapes = 0, size = 0;
    const char *src;
    for (src=string; *src ; src++) {
        if ((*src == quote) || (*src == '\\')) escapes++;
        size++;
    }

    return escapes+size+1;
}


/*
 * add escapes to protect quote characters...
 */
static char *
secmod_addEscape(const char *string, char quote)
{
    char *newString = 0;
    int size = 0;
    const char *src;
    char *dest;


    size = secmod_escapeSize(string,quote);
    newString = PORT_ZAlloc(size);
    if (newString == NULL) {
        return NULL;
    }

    for (src=string, dest=newString; *src; src++,dest++) {
        if ((*src == '\\') || (*src == quote)) {
            *dest++ = '\\';
        }
        *dest = *src;
    }

    return newString;
}

static int
secmod_doubleEscapeSize(const char *string, char quote1, char quote2)
{
    int escapes = 0, size = 0;
    const char *src;
    for (src=string; *src ; src++) {
        if (*src == '\\')   escapes+=3; /* \\\\ */
        if (*src == quote1) escapes+=2; /* \\quote1 */
        if (*src == quote2) escapes++;   /* \quote2 */
        size++;
    }

    return escapes+size+1;
}

char *
secmod_DoubleEscape(const char *string, char quote1, char quote2)
{
    char *round1 = NULL;
    char *retValue = NULL;
    if (string == NULL) {
        goto done;
    }
    round1 = secmod_addEscape(string,quote1);
    if (round1) {
        retValue = secmod_addEscape(round1,quote2);
        PORT_Free(round1);
    }

done:
    if (retValue == NULL) {
        retValue = PORT_Strdup("");
    }
    return retValue;
}


/*
 * caclulate the length of each child record:
 * " 0x{id}=<{escaped_child}>"
 */
static int
secmod_getChildLength(char *child, CK_SLOT_ID id)
{
    int length = secmod_doubleEscapeSize(child, '>', ']');
    if (id == 0) {
	length++;
    }
    while (id) {
	length++;
	id = id >> 4;
    }
    length += 6; /* {sp}0x[id]=<{child}> */
    return length;
}

/*
 * Build a child record:
 * " 0x{id}=<{escaped_child}>"
 */
static SECStatus
secmod_mkTokenChild(char **next, int *length, char *child, CK_SLOT_ID id)
{
    int len;
    char *escSpec;

    len = PR_snprintf(*next, *length, " 0x%x=<",id);
    if (len < 0) {
	return SECFailure;
    }
    *next += len;
    *length -= len;
    escSpec = secmod_DoubleEscape(child, '>', ']');
    if (escSpec == NULL) {
	return SECFailure;
    }
    if (*child && (*escSpec == 0)) {
	PORT_Free(escSpec);
	return SECFailure;
    }
    len = strlen(escSpec);
    if (len+1 > *length) {
	PORT_Free(escSpec);
	return SECFailure;
    }
    PORT_Memcpy(*next,escSpec, len);
    *next += len;
    *length -= len;
    PORT_Free(escSpec);
    **next = '>';
    (*next)++;
    (*length)--;
    return SECSuccess;
}

#define TOKEN_STRING " tokens=["

char *
secmod_MkAppendTokensList(PRArenaPool *arena, char *oldParam, char *newToken, 
			CK_SLOT_ID newID, char **children, CK_SLOT_ID *ids)
{
    char *rawParam = NULL;	/* oldParam with tokens stripped off */
    char *newParam = NULL;	/* space for the return parameter */
    char *nextParam = NULL;	/* current end of the new parameter */
    char **oldChildren = NULL;
    CK_SLOT_ID *oldIds = NULL;
    void *mark = NULL;         /* mark the arena pool in case we need 
				* to release it */
    int length, i, tmpLen;
    SECStatus rv;

    /* first strip out and save the old tokenlist */
    rawParam = secmod_ParseModuleSpecForTokens(oldParam,&oldChildren,&oldIds);
    if (!rawParam) {
	goto loser;
    }

    /* now calculate the total length of the new buffer */
    /* First the 'fixed stuff', length of rawparam (does not include a NULL),
     * length of the token string (does include the NULL), closing bracket */
    length = strlen(rawParam) + sizeof(TOKEN_STRING) + 1;
    /* now add then length of all the old children */
    for (i=0; oldChildren && oldChildren[i]; i++) {
	length += secmod_getChildLength(oldChildren[i], oldIds[i]);
    }

    /* add the new token */
    length += secmod_getChildLength(newToken, newID);

    /* and it's new children */
    for (i=0; children && children[i]; i++) {
	if (ids[i] == -1) {
	    continue;
	}
	length += secmod_getChildLength(children[i], ids[i]);
    }

    /* now allocate and build the string */
    mark = PORT_ArenaMark(arena);
    if (!mark) {
	goto loser;
    }
    newParam =  PORT_ArenaAlloc(arena,length);
    if (!newParam) {
	goto loser;
    }

    PORT_Strcpy(newParam, oldParam);
    tmpLen = strlen(oldParam);
    nextParam = newParam + tmpLen;
    length -= tmpLen;
    PORT_Memcpy(nextParam, TOKEN_STRING, sizeof(TOKEN_STRING)-1);
    nextParam += sizeof(TOKEN_STRING)-1;
    length -= sizeof(TOKEN_STRING)-1;

    for (i=0; oldChildren && oldChildren[i]; i++) {
	rv = secmod_mkTokenChild(&nextParam,&length,oldChildren[i],oldIds[i]);
	if (rv != SECSuccess) {
	    goto loser;
	}
    }

    rv = secmod_mkTokenChild(&nextParam, &length, newToken, newID);
    if (rv != SECSuccess) {
	goto loser;
    }

    for (i=0; children && children[i]; i++) {
	if (ids[i] == -1) {
	    continue;
	}
	rv = secmod_mkTokenChild(&nextParam, &length, children[i], ids[i]);
	if (rv != SECSuccess) {
	    goto loser;
	}
    }

    if (length < 2) {
	goto loser;
    }

    *nextParam++ = ']';
    *nextParam++ = 0;

    /* we are going to return newParam now, don't release the mark */
    PORT_ArenaUnmark(arena, mark);
    mark = NULL;

loser:
    if (mark) {
	PORT_ArenaRelease(arena, mark);
	newParam = NULL; /* if the mark is still active, 
			  * don't return the param */
    }
    if (rawParam) {
	PORT_Free(rawParam);
    }
    if (oldChildren) {
	secmod_FreeChildren(oldChildren, oldIds);
    }
    return newParam;
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
    SECMODModule *oldModule = NULL;
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
    rv = secmod_LoadPKCS11Module(module, &oldModule);
    if (rv != SECSuccess) {
	goto loser;
    }

    /* if we just reload an old module, no need to add it to any lists.
     * we simple release all our references */
    if (oldModule) {
	/* This module already exists, don't link it anywhere. This
	 * will probably destroy this module */
	SECMOD_DestroyModule(module);
	/* free the reference we inheritted from secmod_LoadPKCS11Module. We
	 * no longer need the reference (though the module is still on the
	 * module lists and will not likely be destroyed at this point */
	SECMOD_DestroyModule(oldModule);
	return SECSuccess;
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

