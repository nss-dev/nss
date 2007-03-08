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
 * Portions created by the Initial Developer are Copyright (C) 1994-2000
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
 *  The following code handles the storage of PKCS 11 modules used by the
 * NSS. This file is written to abstract away how the modules are
 * stored so we can deside that later.
 */
#include "sftkdb.h"
#include "pkcs11t.h"
#include "pkcs11i.h"
#include "sdb.h"
#include "prprf.h" 
#include "secmodt.h"
#include "sftkpars.h"
#include "pratom.h"
#include "blapi.h"
#include "secoid.h"
#include "sechash.h"
#include "lowpbe.h"

/*
 * private defines
 */
struct SFTKDBHandleStr {
    SDB   *db;
    PRInt32 ref;
    CK_OBJECT_HANDLE type;
    SECItem passwordKey;
    PZLock *passwordLock;
};

#define SFTK_KEYDB_TYPE 0x40000000
#define SFTK_CERTDB_TYPE 0x00000000
#define SFTK_OBJ_TYPE_MASK 0xc0000000
#define SFTK_OBJ_ID_MASK (~SFTK_OBJ_TYPE_MASK)
#define SFTK_TOKEN_TYPE 0x80000000

static SECStatus sftkdb_decrypt(SECItem *passKey, SECItem *cipherText, 
                                SECItem **plainText);
static SECStatus sftkdb_encrypt(PLArenaPool *arena, SECItem *passKey, 
                                SECItem *plainText, SECItem **cipherText);


/*
 * We want all databases to have the same binary representation independent of
 * endianness or length of the host architecture. In general PKCS #11 attributes
 * are endian/length independent except those attributes that pass CK_ULONG.
 *
 * The following functions fixes up the CK_ULONG type attributes so that the data
 * base sees a machine independent view. CK_ULONGs are stored as 4 byte network
 * byte order values (big endian).
 */
#define DB_ULONG_SIZE 4
#define BBP 8

static PRBool
sftkdb_isULONG(CK_ATTRIBUTE_TYPE type) 
{
    switch(type) {
    case CKA_CLASS:
    case CKA_CERTIFICATE_TYPE:
    case CKA_CERTIFICATE_CATEGORY:
    case CKA_KEY_TYPE:
    case CKA_JAVA_MIDP_SECURITY_DOMAIN:
	return PR_TRUE;
    default:
	break;
    }
    return PR_FALSE;
    
}

/* are the attributes private? */
static PRBool
sftkdb_isPrivate(CK_ATTRIBUTE_TYPE type) 
{
    switch(type) {
    case CKA_VALUE:
    case CKA_PRIVATE_EXPONENT:
    case CKA_PRIME_1:
    case CKA_PRIME_2:
    case CKA_EXPONENT_1:
    case CKA_EXPONENT_2:
    case CKA_COEFFICIENT:
	return PR_TRUE;
    default:
	break;
    }
    return PR_FALSE;
}

/*
 * fix up the input templates. Our fixed up ints are stored in data and must
 * be freed by the caller. The new template must also be freed. If there are no
 * CK_ULONG attributes, the orignal template is passed in as is.
 */
static CK_ATTRIBUTE *
sftkdb_fixupTemplateIn(const CK_ATTRIBUTE *template, int count, 
			unsigned char **dataOut)
{
    int i,j;
    int ulongCount = 0;
    unsigned char *data;
    CK_ATTRIBUTE *ntemplate;

    *dataOut = NULL;

    /* first count the number of CK_ULONG attributes */
    for (i=0; i < count; i++) {
	/* Don't 'fixup' NULL values */
	if (!template[i].pValue) {
	    continue;
	}
	if (template[i].ulValueLen == sizeof (CK_ULONG)) {
	    if ( sftkdb_isULONG(template[i].type)) {
		ulongCount++;
	    }
	}
    }
    /* no attributes to fixup, just call on through */
    if (ulongCount == 0) {
	return (CK_ATTRIBUTE *)template;
    }

    /* allocate space for new ULONGS */
    data = (unsigned char *)PORT_Alloc(DB_ULONG_SIZE*ulongCount);
    if (!data) {
	return NULL;
    }

    /* allocate new template */
    ntemplate = PORT_NewArray(CK_ATTRIBUTE,count);
    if (!ntemplate) {
	PORT_Free(data);
	return NULL;
    }
    *dataOut = data;
    /* copy the old template, fixup the actual ulongs */
    for (i=0; i < count; i++) {
	ntemplate[i] = template[i];
	/* Don't 'fixup' NULL values */
	if (!template[i].pValue) {
	    continue;
	}
	if (template[i].ulValueLen == sizeof (CK_ULONG)) {
	    if ( sftkdb_isULONG(template[i].type) ) {
		CK_ULONG value = *(CK_ULONG *) template[i].pValue;
		for (j=0; j < DB_ULONG_SIZE; j++) {
		    data[j] = (value >> (DB_ULONG_SIZE-j)*BBP) & 0xff;
		}
		ntemplate[i].pValue = data;
		ntemplate[i].ulValueLen = DB_ULONG_SIZE;
		data += DB_ULONG_SIZE;
	    }
	}
    }
    return ntemplate;
}



/*
 * fix up returned data. NOTE: sftkdb_fixupTemplateIn has already allocated
 * separate data sections for the database ULONG values.
 */
static CK_RV
sftkdb_fixupTemplateOut(CK_ATTRIBUTE *template, CK_ATTRIBUTE *ntemplate, 
		int count, SFTKDBHandle *handle)
{
    int i,j;
    CK_RV crv = CKR_OK;

    for (i=0; i < count; i++) {
	CK_ULONG length = template[i].ulValueLen;
	template[i].ulValueLen = ntemplate[i].ulValueLen;
	/* fixup ulongs */
	if (ntemplate[i].ulValueLen == DB_ULONG_SIZE) {
	    if (sftkdb_isULONG(template[i].type)) {
		if (template[i].pValue) {
		    CK_ULONG value = 0;
		    unsigned char *data;

		    data = (unsigned char *)ntemplate[i].pValue;
		    for (j=0; j < DB_ULONG_SIZE; j++) {
			value |= (((CK_ULONG)data[j]) << (DB_ULONG_SIZE-j)*BBP);
		    }
		    if (length < sizeof(CK_ULONG)) {
			template[i].ulValueLen = -1;
			crv = CKR_BUFFER_TOO_SMALL;
			continue;
		    } 
		    PORT_Memcpy(template[i].pValue,&value,sizeof(CK_ULONG));
		}
		template[i].ulValueLen = sizeof(CK_ULONG);
	    }
	}
	/* fixup private attributes */
	if ((handle != NULL) && (handle->type == SFTK_KEYDB_TYPE) &&
	  (template[i].pValue != NULL) &&  (template[i].ulValueLen != -1)
	  && sftkdb_isPrivate(ntemplate[i].type)) {
	    /* we have a private attribute */
	    SECItem cipherText;
	    SECItem *plainText;
	    SECStatus rv;

	    cipherText.data = ntemplate[i].pValue;
	    cipherText.len = ntemplate[i].ulValueLen;
    	    PZ_Lock(handle->passwordLock);
	    if (handle->passwordKey.data == NULL) {
		PZ_Unlock(handle->passwordLock);
		template[i].ulValueLen = -1;
		crv = CKR_USER_NOT_LOGGED_IN;
		continue;
	    }
	    rv = sftkdb_decrypt(&handle->passwordKey, &cipherText, &plainText);
	    PZ_Unlock(handle->passwordLock);
	    if (rv != SECSuccess) {
		PORT_Memset(template[i].pValue, 0, template[i].ulValueLen);
		template[i].ulValueLen = -1;
		crv = CKR_GENERAL_ERROR;
	    }
	    PORT_Memcpy(template[i].pValue, plainText->data, plainText->len);
	    template[i].ulValueLen = plainText->len;
	    SECITEM_FreeItem(plainText,PR_TRUE);
	}
    }
    return crv;
}

CK_ATTRIBUTE * 
sftk_ExtractTemplate(PLArenaPool *arena, SFTKObject *object, 
		     SFTKDBHandle *handle,CK_ULONG *pcount, 
		     CK_RV *crv)
{
    int count;
    CK_ATTRIBUTE *template;
    int i, templateIndex;
    SFTKSessionObject *sessObject = sftk_narrowToSessionObject(object);

    *crv = CKR_OK;

    if (sessObject == NULL) {
	*crv = CKR_GENERAL_ERROR; /* internal programming error */
	return NULL;
    }

    PZ_Lock(sessObject->attributeLock);
    count = 0;
    for (i=0; i < sessObject->hashSize; i++) {
	SFTKAttribute *attr;
   	for (attr=sessObject->head[i]; attr; attr=attr->next) {
	    count++;
	}
    }
    template = PORT_ArenaNewArray(arena, CK_ATTRIBUTE, count);
    if (template == NULL) {
        PZ_Unlock(sessObject->attributeLock);
	*crv = CKR_HOST_MEMORY;
	return NULL;
    }
    templateIndex = 0;
    for (i=0; i < sessObject->hashSize; i++) {
	SFTKAttribute *attr;
   	for (attr=sessObject->head[i]; attr; attr=attr->next) {
	    CK_ATTRIBUTE *tp = &template[templateIndex++];
	    /* copy the attribute */
	    *tp = attr->attrib;

	    /* fixup  ULONG s */
	    if ((tp->ulValueLen == sizeof (CK_ULONG)) &&
		(sftkdb_isULONG(tp->type)) ) {
		CK_ULONG value = *(CK_ULONG *) tp->pValue;
		unsigned char *data;
		int j;

		tp->pValue = PORT_ArenaAlloc(arena, DB_ULONG_SIZE);
		data = (unsigned char *)tp->pValue;
		if (data == NULL) {
		    *crv = CKR_HOST_MEMORY;
		    break;
		}
		for (j=0; j < DB_ULONG_SIZE; j++) {
		    data[j] = (value >> (DB_ULONG_SIZE-j)*BBP) & 0xff;
		}
		tp->ulValueLen = DB_ULONG_SIZE;
	    }

	    /* encrypt private attributes */
	    if ((handle != NULL) && (handle->type == SFTK_KEYDB_TYPE) &&
	         sftkdb_isPrivate(tp->type)) {

		/* we have a private attribute */
		SECItem *cipherText;
		SECItem plainText;
		SECStatus rv;

		plainText.data = tp->pValue;
		plainText.len = tp->ulValueLen;
		PZ_Lock(handle->passwordLock);
		if (handle->passwordKey.data == NULL) {
		    PZ_Unlock(handle->passwordLock);
		    *crv = CKR_USER_NOT_LOGGED_IN;
		    break;
		}
		rv = sftkdb_encrypt(arena, &handle->passwordKey, &plainText, 
				    &cipherText);
		PZ_Unlock(handle->passwordLock);
		if (rv == SECSuccess) {
		    tp->pValue = cipherText->data;
		    tp->ulValueLen = cipherText->len;
		} else {
		    *crv = CKR_GENERAL_ERROR; /* better error code here? */
		    break;
		}
	    }
	}
    }
    PORT_Assert(templateIndex <= count);
    PZ_Unlock(sessObject->attributeLock);

    if (*crv != CKR_OK) {
	return NULL;
    }
    if (pcount) {
	*pcount = count;
    }
    return template;

}

CK_RV
sftkdb_write(SFTKDBHandle *handle, SFTKObject *object, 
	     CK_OBJECT_HANDLE *objectID)
{
    CK_ATTRIBUTE *template;
    PLArenaPool *arena;
    CK_ULONG count;
    PRBool inTransaction = PR_FALSE;
    CK_RV crv;

    if (handle == NULL) {
	return  CKR_TOKEN_WRITE_PROTECTED;
    }

    arena = PORT_NewArena(256);
    if (arena ==  NULL) {
	return CKR_HOST_MEMORY;
    }

    template = sftk_ExtractTemplate(arena, object, handle, &count, &crv);
    if (!template) {
	goto loser;
    }
    crv = (*handle->db->sdb_Begin)(handle->db);
    if (crv != CKR_OK) {
	goto loser;
    }
    inTransaction = PR_TRUE;
    crv = (*handle->db->sdb_CreateObject)(handle->db, objectID, 
					  template, count);
    if (crv != CKR_OK) {
	goto loser;
    }
    crv = (*handle->db->sdb_Commit)(handle->db);
    inTransaction = PR_FALSE;

loser:
    if (arena) {
	PORT_FreeArena(arena,PR_FALSE);
    }
    if (crv == CKR_OK) {
	*objectID |= (handle->type | SFTK_TOKEN_TYPE);
    } 
    if (inTransaction) {
	(*handle->db->sdb_Abort)(handle->db);
	/* It should be trivial to show the following code cannot
	 * happen unless something is horribly wrong with our compilier or
	 * hardware */
	PORT_Assert(crv != CKR_OK);
	if (crv == CKR_OK) crv = CKR_GENERAL_ERROR;
    }
    return crv;
}




CK_RV 
sftkdb_FindObjectsInit(SFTKDBHandle *handle, const CK_ATTRIBUTE *template,
				 int count, SDBFind **find) 
{
    unsigned char *data = NULL;
    CK_ATTRIBUTE *ntemplate = NULL;
    CK_RV crv;

    if (handle == NULL) {
	return CKR_OK;
    }

    if (count !=  0) {
	ntemplate = sftkdb_fixupTemplateIn(template, count, &data);
	if (ntemplate == NULL) {
	    return CKR_HOST_MEMORY;
	}
    }
	
    crv = (*handle->db->sdb_FindObjectsInit)(handle->db, ntemplate, 
					     count, find);
    if (data) {
	PORT_Free(ntemplate);
	PORT_Free(data);
    }
    return crv;
}

CK_RV 
sftkdb_FindObjects(SFTKDBHandle *handle, SDBFind *find, 
			CK_OBJECT_HANDLE *ids, int arraySize, int *count)
{
    CK_RV crv;
    if (handle == NULL) {
	*count = 0;
	return CKR_OK;
    }

    crv = (*handle->db->sdb_FindObjects)(handle->db, find, ids, 
					    arraySize, count);
    if (crv == CKR_OK) {
	int i;
	for (i=0; i < *count; i++) {
	    ids[i] |= (handle->type | SFTK_TOKEN_TYPE);
	}
    }
    return crv;
}

CK_RV sftkdb_FindObjectsFinal(SFTKDBHandle *handle, SDBFind *find)
{
    if (handle == NULL) {
	return CKR_OK;
    }
    return (*handle->db->sdb_FindObjectsFinal)(handle->db, find);
}

CK_RV
sftkdb_GetAttributeValue(SFTKDBHandle *handle, CK_OBJECT_HANDLE object_id,
                                CK_ATTRIBUTE *template, int count)
{
    CK_RV crv,crv2;
    CK_ATTRIBUTE *ntemplate;
    unsigned char *data = NULL;

    if (handle == NULL) {
	return CKR_GENERAL_ERROR;
    }
    /* nothing to do */
    if (count == 0) {
	return CKR_OK;
    }
    ntemplate = sftkdb_fixupTemplateIn(template, count, &data);
    if (ntemplate == NULL) {
	return CKR_HOST_MEMORY;
    }
    object_id &= SFTK_OBJ_ID_MASK;
    crv = (*handle->db->sdb_GetAttributeValue)(handle->db, object_id, 
						ntemplate, count);
    crv2 = sftkdb_fixupTemplateOut(template, ntemplate, count, handle);
    if (crv == CKR_OK) crv = crv2;
    if (data) {
	PORT_Free(ntemplate);
	PORT_Free(data);
    }
    return crv;

}

CK_RV
sftkdb_SetAttributeValue(SFTKDBHandle *handle, CK_OBJECT_HANDLE object_id,
                                const CK_ATTRIBUTE *template, int count)
{
    CK_RV crv = CKR_OK;
    CK_ATTRIBUTE *ntemplate;
    unsigned char *data = NULL;

    if (handle == NULL) {
	return CKR_TOKEN_WRITE_PROTECTED;
    }
    /* nothing to do */
    if (count == 0) {
	return CKR_OK;
    }
    ntemplate = sftkdb_fixupTemplateIn(template, count, &data);
    if (ntemplate == NULL) {
	return CKR_HOST_MEMORY;
    }
    object_id &= SFTK_OBJ_ID_MASK;
    crv = (*handle->db->sdb_Begin)(handle->db);
    if (crv != CKR_OK) {
	goto loser;
    }
    crv = (*handle->db->sdb_SetAttributeValue)(handle->db, object_id, 
						ntemplate, count);
    if (crv != CKR_OK) {
	goto loser;
    }
    crv = (*handle->db->sdb_Commit)(handle->db);
loser:
    if (crv != CKR_OK) {
	(*handle->db->sdb_Abort)(handle->db);
    }
    if (data) {
	PORT_Free(ntemplate);
	PORT_Free(data);
    }
    return crv;
}

CK_RV
sftkdb_DestroyObject(SFTKDBHandle *handle, CK_OBJECT_HANDLE object_id)
{
    CK_RV crv = CKR_OK;
    if (handle == NULL) {
	return CKR_TOKEN_WRITE_PROTECTED;
    }
    object_id &= SFTK_OBJ_ID_MASK;
    crv = (*handle->db->sdb_Begin)(handle->db);
    if (crv != CKR_OK) {
	goto loser;
    }
    crv = (*handle->db->sdb_DestroyObject)(handle->db, object_id);
    if (crv != CKR_OK) {
	goto loser;
    }
    crv = (*handle->db->sdb_Commit)(handle->db);
loser:
    if (crv != CKR_OK) {
	(*handle->db->sdb_Abort)(handle->db);
    }
    return crv;
}

CK_RV
sftkdb_CloseDB(SFTKDBHandle *handle)
{
    if (handle == NULL) {
	return CKR_OK;
    }
    if (handle->db) {
	(*handle->db->sdb_Close)(handle->db);
    }
    PORT_Free(handle);
    return CKR_OK;
}

CK_RV
sftkdb_Begin(SFTKDBHandle *handle)
{
    if (handle == NULL) {
	return CKR_OK;
    }
    if (handle->db) {
	(*handle->db->sdb_Begin)(handle->db);
    }
    PORT_Free(handle);
    return CKR_OK;
}

CK_RV
sftkdb_Commit(SFTKDBHandle *handle)
{
    if (handle == NULL) {
	return CKR_OK;
    }
    if (handle->db) {
	(*handle->db->sdb_Commit)(handle->db);
    }
    PORT_Free(handle);
    return CKR_OK;
}

CK_RV
sftkdb_Abort(SFTKDBHandle *handle)
{
    if (handle == NULL) {
	return CKR_OK;
    }
    if (handle->db) {
	(*handle->db->sdb_Abort)(handle->db);
    }
    PORT_Free(handle);
    return CKR_OK;
}


/****************************************************************
 *
 * Secmod database.
 *
 * The new secmod database is simply a text file with each of the module
 * entries. in the following form:
 *
 * #
 * # This is a comment The next line is the library to load
 * library=libmypkcs11.so
 * name="My PKCS#11 module"
 * params="my library's param string"
 * nss="NSS parameters"
 * other="parameters for other libraries and applications"
 * 
 * library=libmynextpk11.so
 * name="My other PKCS#11 module"
 */


static char *
sftkdb_quote(const char *string, char quote)
{
    char *newString = 0;
    int escapes = 0, size = 0;
    const char *src;
    char *dest;

    size=2;
    for (src=string; *src ; src++) {
	if ((*src == quote) || (*src == '\\')) escapes++;
	size++;
    }

    dest = newString = PORT_ZAlloc(escapes+size+1); 
    if (newString == NULL) {
	return NULL;
    }

    *dest++=quote;
    for (src=string; *src; src++,dest++) {
	if ((*src == '\\') || (*src == quote)) {
	    *dest++ = '\\';
	}
	*dest = *src;
    }
    *dest=quote;

    return newString;
}

/*
 * Smart string cat functions. Automatically manage the memory.
 * The first parameter is the source string. If it's null, we 
 * allocate memory for it. If it's not, we reallocate memory
 * so the the concanenated string fits.
 */
static char *
sftkdb_DupnCat(char *baseString, const char *str, int str_len)
{
    int len = (baseString ? PORT_Strlen(baseString) : 0) + 1;
    char *newString;

    len += str_len;
    newString = (char *) PORT_Realloc(baseString,len);
    if (newString == NULL) {
	PORT_Free(baseString);
	return NULL;
    }
    if (baseString == NULL) *newString = 0;
    return PORT_Strncat(newString,str, str_len);
}

/* Same as sftkdb_DupnCat except it concatenates the full string, not a
 * partial one */
static char *
sftkdb_DupCat(char *baseString, const char *str)
{
    return sftkdb_DupnCat(baseString, str, PORT_Strlen(str));
}

/* function to free up all the memory associated with a null terminated
 * array of module specs */
static SECStatus
sftkdb_releaseSpecList(char **moduleSpecList)
{
    if (moduleSpecList) {
	char **index;
	for(index = moduleSpecList; *index; index++) {
	    PORT_Free(*index);
	}
	PORT_Free(moduleSpecList);
    }
    return SECSuccess;
}

#define SECMOD_STEP 10
#define MAX_LINE_LENGTH 2048
#define SFTK_DEFAULT_INTERNAL_INIT1 "library= name=\"NSS Internal PKCS #11 Module\" parameters="
#define SFTK_DEFAULT_INTERNAL_INIT2 " NSS=\"Flags=internal,critical trustOrder=75 cipherOrder=100 slotParams=(1={"
#define SFTK_DEFAULT_INTERNAL_INIT3 " askpw=any timeout=30})\""
/*
 * Read all the existing modules in out of the file.
 */
char **
sftkdb_ReadSecmodDB(const char *dbType, const char *appName, 
		    const char *filename, const char *dbname, 
		    char *params, PRBool rw)
{
    FILE *fd = NULL;
    char **moduleList = NULL, **newModuleList = NULL;
    int moduleCount = 1;
    int useCount = SECMOD_STEP;
    char line[MAX_LINE_LENGTH];
    PRBool internal = PR_FALSE;
    PRBool skipParams = PR_FALSE;
    char *moduleString = NULL;
    char *paramsValue=NULL;
    PRBool failed = PR_TRUE;

    if ((dbType == NULL) || (PORT_Strcmp(dbType, MULTIACCESS) == 0)) {
	/* SHDB_FIXME: Handle Legacy code */
    	return moduleList;
    }

    moduleList = (char **) PORT_ZAlloc(useCount*sizeof(char **));
    if (moduleList == NULL) return NULL;

    /* do we really want to use streams here */
    fd = fopen(dbname, "r");
    if (fd == NULL) goto done;

    /*
     * the following loop takes line separated config lines and colapses
     * the lines to a single string, escaping and quoting as necessary.
     */
    /* loop state variables */
    moduleString = NULL;  /* current concatenated string */
    internal = PR_FALSE;	     /* is this an internal module */
    skipParams = PR_FALSE;	   /* did we find an override parameter block*/
    paramsValue = NULL;		   /* the current parameter block value */
    while (fgets(line, sizeof(line), fd) != NULL) { 
	int len = PORT_Strlen(line);

	/* remove the ending newline */
	if (len && line[len-1] == '\n') {
	    len--;
	    line[len] = 0;
	}
	if (*line == '#') {
	    continue;
	}
	if (*line != 0) {
	    /*
	     * The PKCS #11 group standard assumes blocks of strings
	     * separated by new lines, clumped by new lines. Internally
	     * we take strings separated by spaces, so we may need to escape
	     * certain spaces.
	     */
	    char *value = PORT_Strchr(line,'=');

	    /* there is no value, write out the stanza as is */
	    if (value == NULL || value[1] == 0) {
		if (moduleString) {
		    moduleString = sftkdb_DupnCat(moduleString," ", 1);
		    if (moduleString == NULL) goto loser;
		}
	        moduleString = sftkdb_DupCat(moduleString, line);
		if (moduleString == NULL) goto loser;
	    /* value is already quoted, just write it out */
	    } else if (value[1] == '"') {
		if (moduleString) {
		    moduleString = sftkdb_DupnCat(moduleString," ", 1);
		    if (moduleString == NULL) goto loser;
		}
	        moduleString = sftkdb_DupCat(moduleString, line);
		if (moduleString == NULL) goto loser;
		/* we have an override parameter section, remember that
		 * we found this (see following comment about why this
		 * is necessary). */
	        if (PORT_Strncasecmp(line, "parameters", 10) == 0) {
			skipParams = PR_TRUE;
		}
	    /*
	     * The internal token always overrides it's parameter block
	     * from the passed in parameters, so wait until then end
	     * before we include the parameter block in case we need to 
	     * override it. NOTE: if the parameter block is quoted with ("),
	     * this override does not happen. This allows you to override
	     * the application's parameter configuration.
	     *
	     * parameter block state is controlled by the following variables:
	     *  skipParams - Bool : set to true of we have an override param
	     *    block (all other blocks, either implicit or explicit are
	     *    ignored).
	     *  paramsValue - char * : pointer to the current param block. In
	     *    the absence of overrides, paramsValue is set to the first
	     *    parameter block we find. All subsequent blocks are ignored.
	     *    When we find an internal token, the application passed
	     *    parameters take precident.
	     */
	    } else if (PORT_Strncasecmp(line, "parameters", 10) == 0) {
		/* already have parameters */
		if (paramsValue) {
			continue;
		}
		paramsValue = sftkdb_quote(&value[1], '"');
		if (paramsValue == NULL) goto loser;
		continue;
	    } else {
	    /* may need to quote */
	        char *newLine;
		if (moduleString) {
		    moduleString = sftkdb_DupnCat(moduleString," ", 1);
		    if (moduleString == NULL) goto loser;
		}
		moduleString = sftkdb_DupnCat(moduleString,line,value-line+1);
		if (moduleString == NULL)  goto loser;
	        newLine = sftkdb_quote(&value[1],'"');
		if (newLine == NULL) goto loser;
		moduleString = sftkdb_DupCat(moduleString,newLine);
	        PORT_Free(newLine);
		if (moduleString == NULL) goto loser;
	    }

	    /* check to see if it's internal? */
	    if (PORT_Strncasecmp(line, "NSS=", 4) == 0) {
		/* This should be case insensitive! reviewers make
		 * me fix it if it's not */
		if (PORT_Strstr(line,"internal")) {
		    internal = PR_TRUE;
		    /* override the parameters */
		    if (paramsValue) {
			PORT_Free(paramsValue);
		    }
		    paramsValue = sftkdb_quote(params, '"');
		}
	    }
	    continue;
	}
	if ((moduleString == NULL) || (*moduleString == 0)) {
	    continue;
	}

	/* 
	 * if we are here, we have found a complete stanza. Now write out
	 * any param section we may have found.
	 */
	if (paramsValue) {
	    /* we had an override */
	    if (!skipParams) {
		moduleString = sftkdb_DupnCat(moduleString," parameters=", 12);
		if (moduleString == NULL) goto loser;
		moduleString = sftkdb_DupCat(moduleString, paramsValue);
		if (moduleString == NULL) goto loser;
	    }
	    PORT_Free(paramsValue);
	    paramsValue = NULL;
	}

	if ((moduleCount+1) >= useCount) {
	    useCount += SECMOD_STEP;
	    newModuleList =
		(char **)PORT_Realloc(moduleList,useCount*sizeof(char *));
	    if (newModuleList == NULL) goto loser;
	    moduleList = newModuleList;
	    PORT_Memset(&moduleList[moduleCount+1],0,
						sizeof(char *)*SECMOD_STEP);
	}
	if (internal) {
	    moduleList[0] = moduleString;
	} else {
	    moduleList[moduleCount] = moduleString;
	    moduleCount++;
	}
	moduleString = NULL;
	internal = PR_FALSE;
	skipParams = PR_FALSE;
    } 

    if (moduleString) {
	PORT_Free(moduleString);
	moduleString = NULL;
    }
done:
    if (!moduleList[0]) {
	char * newParams;
	moduleString = PORT_Strdup(SFTK_DEFAULT_INTERNAL_INIT1);
	newParams = sftkdb_quote(params,'"');
	if (newParams == NULL) goto loser;
	moduleString = sftkdb_DupCat(moduleString, newParams);
	PORT_Free(newParams);
	if (moduleString == NULL) goto loser;
	moduleString = sftkdb_DupCat(moduleString, SFTK_DEFAULT_INTERNAL_INIT2);
	if (moduleString == NULL) goto loser;
	moduleString = sftkdb_DupCat(moduleString, SECMOD_SLOT_FLAGS);
	if (moduleString == NULL) goto loser;
	moduleString = sftkdb_DupCat(moduleString, SFTK_DEFAULT_INTERNAL_INIT3);
	if (moduleString == NULL) goto loser;
	moduleList[0] = moduleString;
	moduleString = NULL;
    }
    failed = PR_FALSE;

loser:
    /*
     * cleanup
     */
    /* deal with trust cert db here */
    if (moduleString) {
	PORT_Free(moduleString);
	moduleString = NULL;
    }
    if (paramsValue) {
	PORT_Free(paramsValue);
	paramsValue = NULL;
    }
    if (failed || (moduleList[0] == NULL)) {
	/* This is wrong! FIXME */
	sftkdb_releaseSpecList(moduleList);
	moduleList = NULL;
	failed = PR_TRUE;
    }
    if (fd != NULL) {
	fclose(fd);
    } else if (!failed && rw) {
	/* update our internal module */
	sftkdb_AddSecmodDB(dbType,appName,filename,dbname,moduleList[0],rw);
    }
    return moduleList;
}

SECStatus
sftkdb_ReleaseSecmodDBData(const char *dbType, const char *appName, 
			const char *filename, const char *dbname, 
			char **moduleSpecList, PRBool rw)
{
    if (moduleSpecList) {
	sftkdb_releaseSpecList(moduleSpecList);
    }
    return SECSuccess;
}


/*
 * Delete a module from the Data Base
 */
SECStatus
sftkdb_DeleteSecmodDB(const char *dbType, const char *appName, 
		      const char *filename, const char *dbname, 
		      char *args, PRBool rw)
{
    /* SHDB_FIXME implement */
    FILE *fd = NULL;
    FILE *fd2 = NULL;
    char line[MAX_LINE_LENGTH];
    char *dbname2 = NULL;
    char *block = NULL;
    char *name = NULL;
    char *lib = NULL;
    int name_len, lib_len;
    PRBool skip = PR_FALSE;
    PRBool found = PR_FALSE;

    if ((dbType == NULL) || (PORT_Strcmp(dbType, MULTIACCESS) == 0)) {
	/* SHDB_FIXME: Handle Legacy code */
    	return SECFailure;
    }

    if (!rw) {
	return SECFailure;
    }

    dbname2 = strdup(dbname);
    if (dbname2 == NULL) goto loser;
    dbname2[strlen(dbname)-1]++;

    /* do we really want to use streams here */
    fd = fopen(dbname, "r");
    if (fd == NULL) goto loser;
    fd2 = fopen(dbname2, "w+");
    if (fd2 == NULL) goto loser;

printf("args=|%s|\n", args);

    name = sftk_argGetParamValue("name",args);
    if (name) {
	name_len = PORT_Strlen(name);
    }
    lib = sftk_argGetParamValue("library",args);
    if (lib) {
	lib_len = PORT_Strlen(lib);
    }

if (name) printf("name=|%s|\n",name);
if (lib) printf("lib=|%s|\n",lib);

    /*
     * the following loop takes line separated config files and colapses
     * the lines to a single string, escaping and quoting as necessary.
     */
    /* loop state variables */
    block = NULL;
    skip = PR_FALSE;
    while (fgets(line, sizeof(line), fd) != NULL) { 
	/* If we are processing a block (we haven't hit a blank line yet */
	if (*line != '\n') {
	    /* skip means we are in the middle of a block we are deleting */
	    if (skip) {
		continue;
	    }
	    /* if we haven't found the block yet, check to see if this block
	     * matches our requirements */
	    if (!found && ((name && (PORT_Strncasecmp(line,"name=",5) == 0) &&
		 (PORT_Strncmp(line+5,name,name_len) == 0))  ||
	        (lib && (PORT_Strncasecmp(line,"library=",8) == 0) &&
		 (PORT_Strncmp(line+8,lib,lib_len) == 0)))) {

		/* yup, we don't need to save any more data, */
		PORT_Free(block);
		block=NULL;
		/* we don't need to collect more of this block */
		skip = PR_TRUE;
		/* we don't need to continue searching for the block */
		found =PR_TRUE;
		continue;
	    }
	    /* not our match, continue to collect data in this block */
	    block = sftkdb_DupCat(block,line);
	    continue;
	}
	/* we've collected a block of data that wasn't the module we were
	 * looking for, write it out */
	if (block) {
	    fwrite(block, PORT_Strlen(block), 1, fd2);
	    PORT_Free(block);
	    block = NULL;
	}
	/* If we didn't just delete the this block, keep the blank line */
	if (!skip) {
	    fputs(line,fd2);
	}
	/* we are definately not in a deleted block anymore */
	skip = PR_FALSE;
    } 
    fclose(fd);
    fclose(fd2);
    /* rename dbname2 to dbname */
    if (found) {
	PR_Delete(dbname);
	PR_Rename(dbname2,dbname);
    }
    PORT_Free(dbname2);
    return SECSuccess;

loser:
    if (fd != NULL) {
	fclose(fd);
    }
    if (fd2 != NULL) {
	fclose(fd2);
    }
    if (dbname2) {
	PR_Delete(dbname2);
	PORT_Free(dbname2);
    }
    return SECFailure;
}

/*
 * Add a module to the Data base 
 */
SECStatus
sftkdb_AddSecmodDB(const char *dbType, const char *appName, 
		   const char *filename, const char *dbname, 
		   char *module, PRBool rw)
{
    FILE *fd = NULL;
    char *block = NULL;
    PRBool libFound = PR_FALSE;

    if ((dbType == NULL) || (PORT_Strcmp(dbType, MULTIACCESS) == 0)) {
	/* SHDB_FIXME: Handle Legacy code */
    	return SECFailure;
    }

    /* can't write to a read only module */
    if (!rw) {
	return SECFailure;
    }

    /* do we really want to use streams here */
    fd = fopen(dbname, "a+");
    if (fd == NULL) {
	return SECFailure;
    }
    module = sftk_argStrip(module);
    while (*module) {
	int count;
	char *keyEnd = PORT_Strchr(module,'=');
	char *value;

	if (PORT_Strncmp(module, "library=", 8) == 0) {
	   libFound=PR_TRUE;
	}
	if (keyEnd == NULL) {
	    block = sftkdb_DupCat(block, module);
	    break;
	}
	value = sftk_argFetchValue(&keyEnd[1], &count);
	block = sftkdb_DupnCat(block, module, keyEnd-module+1);
	if (block == NULL) { goto loser; }
	if (value) {
	    block = sftkdb_DupCat(block, sftk_argStrip(value));
	    PORT_Free(value);
	}
	if (block == NULL) { goto loser; }
	block = sftkdb_DupnCat(block, "\n", 1);
	module = keyEnd + 1 + count;
	module = sftk_argStrip(module);
    }
    if (block) {
	if (!libFound) {
	    fprintf(fd,"library=\n");
	}
	fwrite(block, PORT_Strlen(block), 1, fd);
	fprintf(fd,"\n");
	PORT_Free(block);
	block = NULL;
    }
    fclose(fd);
    return SECSuccess;

loser:
    PORT_Free(block);
    fclose(fd);
    return SECFailure;
}
  
/******************************************************************
 * 
 * Key DB password handling functions
 *
 * These functions manage the key db password (set, reset, initialize, use).
 *
 * The key is managed on 'this side' of the database. All private data is
 * encrypted before it is sent to the database itself. Besides PBE's, the
 * database management code can also mix in various fixed keys so the data
 * in the database is no longer considered 'plain text'.
 */


/* take string password and turn it into a key. The key is dependent
 * on a global salt entry acquired from the database. This salted
 * value will be based to a pkcs5 pbe function before it is used
 * in an actual encryption */
static SECStatus
sftkdb_passwordToKey(SFTKDBHandle *keydb, SDBPasswordEntry *entry, 
			const char *pw, SECItem *key)
{
    SHA1Context *cx = NULL;
    SECStatus rv = SECFailure;

    key->data = PORT_Alloc(SHA1_LENGTH);
    if (key->data == NULL) {
	goto loser;
    }
    key->len = SHA1_LENGTH;

    cx = SHA1_NewContext();
    if ( cx == NULL) {
	goto loser;
    }
    SHA1_Begin(cx);
    if (entry  && entry->salt.data ) {
	SHA1_Update(cx, entry->salt.data, entry->salt.len);
    }
    SHA1_Update(cx, (unsigned char *)pw, PORT_Strlen(pw));
    SHA1_End(cx, key->data, &key->len, key->len);
    rv = SECSuccess;
    
loser:
    if (cx) {
	SHA1_DestroyContext(cx, PR_TRUE);
    }
    if (rv != SECSuccess) {
	if (key->data != NULL) {
	    PORT_ZFree(key->data,key->len);
	}
	key->data = NULL;
    }
    return rv;
}

/*
 * Cipher text stored in the database contains 3 elements:
 * 1) an identifier describing the encryption algorithm.
 * 2) an entry specific salt value.
 * 3) the encrypted value.
 *
 * The following data structure represents the encrypted data in a decoded
 * (but still encrypted) form.
 */
typedef struct sftkCipherValueStr sftkCipherValue;
struct sftkCipherValueStr {
    SECOidTag  alg;
    SECItem    salt;
    SECItem    value;
};

#define SFTK_CIPHERTEXT_VERSION 3

/*
 * This parses the cipherText into cipher value. NOTE: cipherValue will point
 * to data in cipherText, if cipherText is freed, cipherValue will be invalid.
 *
 * Use existing NSS data record: (sizes and offsets in bytes)
 *
 *   offset     size  label         Description
 *     0         1    version       Data base version number must be 3
 *     1         1    slen          Length of Salt
 *     2         1    nlen          Length of optional nickname
 *     3        slen  sdata         Salt data
 *   3+slen     nlen  ndata         Optional nickname data
 * 3+nlen+slen   1    olen          Length of algorithm OID
 * 4+nlen+slen  olen  odata         Algorithm OID data.
 * 4+nlen+slen+
 *    olen      rest  vdata         Encrypted data.
 *
 * rest is the rest of the block passed into us.
 */
static SECStatus
sftkdb_decodeCipherText(SECItem *cipherText, sftkCipherValue *cipherValue)
{
    int slen, olen, vlen, nlen;
    SECItem oid;

    /* make sure we have data to check */
    if (cipherText->data == NULL || cipherText->len <= 3 ) {
	goto loser;
    }
    if (cipherText->data[0] != SFTK_CIPHERTEXT_VERSION) {
	goto loser;
    }

    /* parse the header */
    slen = cipherText->data[1];
    nlen = cipherText->data[2];
    if (cipherText->len <= (3+nlen+slen) ) {
	goto loser;
    }
    olen = cipherText->data[3+nlen+slen];
    vlen = cipherText->len - (4+nlen+slen+olen);
    if (vlen <= 0 ) {
	goto loser;
    }
    cipherValue->salt.data = &cipherText->data[3];
    cipherValue->salt.len = slen;
    oid.data = &cipherText->data[4+nlen+slen];
    oid.len = olen;
    cipherValue->value.data = &cipherText->data[4+nlen+slen+olen];
    cipherValue->value.len = vlen;
    cipherValue->alg = SECOID_FindOIDTag(&oid);
    if (cipherValue->alg == SEC_OID_UNKNOWN) {
	goto loser;
    }
    return SECSuccess;
loser:
    /* PORT_SETERROR */
    return SECFailure;
}

/* 
 * unlike decode, Encode actually allocates a SECItem the caller must free
 * The caller can pass an optional arena to to indicate where to place
 * the resultant cipherText.
 */
static SECStatus
sftkdb_encodeCipherText(PLArenaPool *arena, sftkCipherValue *cipherValue, 
                        SECItem **cipherText)
{
    int slen, olen, vlen, len;
    SECOidData *oid;

    /* First get the entire length */
    oid = SECOID_FindOIDByTag(cipherValue->alg);
    if (oid == NULL) {
	goto loser;
    }

    slen = cipherValue->salt.len;
    olen = oid->oid.len;
    vlen = cipherValue->value.len;
    /* now get the total length */
    len = 4 + slen + olen + vlen;

    /* get our new secitem */
    *cipherText = SECITEM_AllocItem(arena, NULL, len);
    if (*cipherText == NULL) {
	goto loser;
    }
    (*cipherText)->data[0] = SFTK_CIPHERTEXT_VERSION;
    (*cipherText)->data[1] = slen;
    (*cipherText)->data[2] = 0;
    PORT_Memcpy(&(*cipherText)->data[3],cipherValue->salt.data,slen);
    (*cipherText)->data[3+slen] = olen;
    PORT_Memcpy(&(*cipherText)->data[4+slen],oid->oid.data,olen);
    PORT_Memcpy(&(*cipherText)->data[4+slen+olen],cipherValue->value.data,vlen);

    return SECSuccess;

loser:
    return SECFailure;
}


/*
 * Use our key to decode a cipherText block from the database.
 *
 * plain text is allocated by nsspkcs5_CipherData and must be freed
 * with SECITEM_FreeItem by the caller.
 */
static SECStatus
sftkdb_decrypt(SECItem *passKey, SECItem *cipherText, SECItem **plain) 
{
    SECStatus rv;
    sftkCipherValue cipherValue;
    NSSPKCS5PBEParameter *param = NULL;

    /* First get the cipher type */
    rv = sftkdb_decodeCipherText(cipherText, &cipherValue);
    if (rv != SECSuccess) {
	goto loser;
    }

    param = nsspkcs5_NewParam(cipherValue.alg, &cipherValue.salt, 1);
    if (param == NULL) {
	rv = SECFailure;
	goto loser;
    }
    *plain = nsspkcs5_CipherData(param, passKey, &cipherValue.value, 
				    PR_FALSE, NULL);
    if (*plain == NULL) {
	rv = SECFailure;
	goto loser;
    } 

loser:
    if (param) {
	nsspkcs5_DestroyPBEParameter(param);
    }
    return rv;
}

#define SALT_LENGTH 20

/*
 * encrypt a block. This function returned the encrypted ciphertext which
 * the caller must free. If the caller provides an arena, cipherText will
 * be allocated out of that arena. This also generated the per entry
 * salt automatically.
 */
static SECStatus
sftkdb_encrypt(PLArenaPool *arena, SECItem *passKey, SECItem *plainText, 
	       SECItem **cipherText) 
{
    SECStatus rv;
    sftkCipherValue cipherValue;
    SECItem *cipher = NULL;
    NSSPKCS5PBEParameter *param = NULL;
    unsigned char saltData[SALT_LENGTH];

    cipherValue.alg = SEC_OID_PKCS12_PBE_WITH_SHA1_AND_TRIPLE_DES_CBC;
    cipherValue.salt.len = SALT_LENGTH;
    cipherValue.salt.data = saltData;
    RNG_GenerateGlobalRandomBytes(saltData,SALT_LENGTH);

    param = nsspkcs5_NewParam(cipherValue.alg, &cipherValue.salt, 1);
    if (param == NULL) {
	rv = SECFailure;
	goto loser;
    }
    cipher = nsspkcs5_CipherData(param, passKey, plainText, PR_TRUE, NULL);
    if (cipher == NULL) {
	rv = SECFailure;
	goto loser;
    } 
    cipherValue.value.data = cipher->data;
    cipherValue.value.len = cipher->len;

    rv = sftkdb_encodeCipherText(arena, &cipherValue, cipherText);
    if (rv != SECSuccess) {
	goto loser;
    }

loser:
    if (cipher) {
	SECITEM_FreeItem(cipher, PR_FALSE);
    }
    if (param) {
	nsspkcs5_DestroyPBEParameter(param);
    }
    return rv;
}
  
/*
 * safely swith the passed in key for the one caches in the keydb handle
 * 
 * A key attached to the handle tells us the the token is logged in.
 * We can used the key attached to the handle in sftkdb_encrypt 
 *  and sftkdb_decrypt calls.
 */  
static void 
sftkdb_switchKeys(SFTKDBHandle *keydb, SECItem *passKey)
{
    unsigned char *data;
    int len;

    if (keydb->passwordLock == NULL) {
	PORT_Assert(keydb->type != SFTK_KEYDB_TYPE);
	return;
    }

    /* an atomic pointer set would be nice */
    PZ_Lock(keydb->passwordLock);
    data = keydb->passwordKey.data;
    len = keydb->passwordKey.len;
    keydb->passwordKey.data = passKey->data;
    keydb->passwordKey.len = passKey->len;
    passKey->data = data;
    passKey->len = len;
    PZ_Unlock(keydb->passwordLock);
}
    

/*
 * return success if we have a valid password entry.
 * This is will show up outside of PKCS #11 as CKF_USER_PIN_INIT
 * in the token flags.
 */
SECStatus 
sftkdb_HasPasswordSet(SFTKDBHandle *keydb)
{
    SDBPasswordEntry entry;
    CK_RV crv;

    if (keydb == NULL || keydb->db == NULL) {
	return SECFailure;
    }
    crv = (*keydb->db->sdb_GetPWEntry)(keydb->db, &entry);
    return (crv == CKR_OK) ? SECSuccess : SECFailure;
}

#define SFTK_PW_CHECK_STRING "password-check"
#define SFTK_PW_CHECK_LEN 14

/*
 * check if the supplied password is valid
 */
SECStatus  
sftkdb_CheckPassword(SFTKDBHandle *keydb, const char *pw)
{
    SECStatus rv;
    SDBPasswordEntry entry;
    SECItem key;
    SECItem *result = NULL;
    CK_RV crv;

    key.data = NULL;
    key.len = 0;

    if (pw == NULL) pw="";

    /* get the entry from the database */
    crv = (*keydb->db->sdb_GetPWEntry)(keydb->db, &entry);
    if (crv != CKR_OK) {
	rv = SECFailure;
	goto loser;
    }

    /* get our intermediate key based on the entry salt value */
    rv = sftkdb_passwordToKey(keydb, &entry, pw, &key);
    if (rv != SECSuccess) {
	goto loser;
    }

    /* decrypt the entry value */
    rv = sftkdb_decrypt(&key, &entry.value, &result);
    if (rv != SECSuccess) {
	goto loser;
    }

    /* if it's what we expect, update our key in the database handle and
     * return Success */
    if ((result->len == SFTK_PW_CHECK_LEN) &&
      PORT_Memcmp(result->data, SFTK_PW_CHECK_STRING, SFTK_PW_CHECK_LEN) == 0){
	sftkdb_switchKeys(keydb, &key);
    } else {
        rv = SECFailure;
	/*PORT_SetError( bad password); */
    }

loser:
    if (key.data) {
	PORT_ZFree(key.data,key.len);
    }
    if (result) {
	SECITEM_FreeItem(result,PR_TRUE);
    }
    return rv;
}

/*
 * return Success if the there is a cached password key.
 */
SECStatus
sftkdb_PWCached(SFTKDBHandle *keydb)
{
    return keydb->passwordKey.data ? SECSuccess : SECFailure;
}

/*
 * reset the key database to it's uninitialized state. This call
 * will clear all the key entried.
 */
SECStatus
sftkdb_ResetKeyDB(SFTKDBHandle *keydb)
{
    /* add legacy hook */
    return SECFailure;
}

/*
 * change the database password.
 */
SECStatus
sftkdb_ChangePassword(SFTKDBHandle *keydb, char *oldPin, char *newPin)
{
    SECStatus rv = SECSuccess;
    SECItem plainText;
    SECItem newKey;
    SECItem *result = NULL;
    SDBPasswordEntry entry;
    CK_RV crv;

    /* make sure we have a valid old pin */
    crv = (*keydb->db->sdb_Begin)(keydb->db);
    if (crv != CKR_OK) {
	rv = SECFailure;
	goto loser;
    }
    crv = (*keydb->db->sdb_GetPWEntry)(keydb->db, &entry);
    if (crv == CKR_OK) {
	rv = sftkdb_CheckPassword(keydb, oldPin);
	if (rv == SECFailure) {
	    goto loser;
	}
    } else {
	entry.salt.data = entry.data;
	entry.salt.len = SALT_LENGTH;
    	RNG_GenerateGlobalRandomBytes(entry.data,entry.salt.len);
    }

    rv = sftkdb_passwordToKey(keydb, &entry, newPin, &newKey);
    if (rv != SECSuccess) {
	goto loser;
    }

    /*
     * convert encrypted entries here.
     * SDB_FIXME
     */

    plainText.data = (unsigned char *)SFTK_PW_CHECK_STRING;
    plainText.len = SFTK_PW_CHECK_LEN;

    rv = sftkdb_encrypt(NULL, &newKey, &plainText, &result);
    if (rv != SECSuccess) {
	goto loser;
    }
    entry.value.data = result->data;
    entry.value.len = result->len;
    crv = (*keydb->db->sdb_PutPWEntry)(keydb->db, &entry);
    if (crv != CKR_OK) {
	rv = SECFailure;
	goto loser;
    }
    crv = (*keydb->db->sdb_Commit)(keydb->db);
    if (crv != CKR_OK) {
	rv = SECFailure;
	goto loser;
    }

    sftkdb_switchKeys(keydb, &newKey);

loser:
    if (newKey.data) {
	PORT_ZFree(newKey.data,newKey.len);
    }
    if (result) {
	SECITEM_FreeItem(result, PR_FALSE);
    }
    if (rv != SECSuccess) {
        (*keydb->db->sdb_Abort)(keydb->db);
    }
    
    return rv;
}

/*
 * loose our cached password
 */
SECStatus
sftkdb_ClearPassword(SFTKDBHandle *keydb)
{
    SECItem oldKey;
    oldKey.data = NULL;
    oldKey.len = 0;
    sftkdb_switchKeys(keydb, &oldKey);
    if (oldKey.data) {
	PORT_ZFree(oldKey.data, oldKey.len);
    }
    return SECSuccess;
}

/******************************************************************
 * DB handle managing functions.
 * 
 * These functions are called by softoken to initialize, acquire,
 * and release database handles.
 */

/* release a database handle */
void
sftk_freeDB(SFTKDBHandle *handle)
{
    PRInt32 ref;

    if (!handle) return;
    ref = PR_AtomicDecrement(&handle->ref);
    if (ref == 0) {
	sftkdb_CloseDB(handle);
    }
    return;
}


/*
 * acquire a database handle for a certificate db  
 * (database for public objects) 
 */
SFTKDBHandle *
sftk_getCertDB(SFTKSlot *slot)
{
    SFTKDBHandle *dbHandle;

    PZ_Lock(slot->slotLock);
    dbHandle = slot->certDB;
    if (dbHandle) {
        PR_AtomicIncrement(&dbHandle->ref);
    }
    PZ_Unlock(slot->slotLock);
    return dbHandle;
}

/*
 * acquire a database handle for a key database 
 * (database for private objects)
 */
SFTKDBHandle *
sftk_getKeyDB(SFTKSlot *slot)
{
    SFTKDBHandle *dbHandle;

    PZ_Lock(slot->slotLock);
    dbHandle = slot->keyDB;
    if (dbHandle) {
        PR_AtomicIncrement(&dbHandle->ref);
    }
    PZ_Unlock(slot->slotLock);
    return dbHandle;
}

/*
 * acquire the database for a specific object. NOTE: objectID must point
 * to a Token object!
 */
SFTKDBHandle *
sftk_getDBForObject(SFTKSlot *slot, CK_OBJECT_HANDLE objectID)
{
    SFTKDBHandle *dbHandle;

    PZ_Lock(slot->slotLock);
    dbHandle = objectID & SFTK_KEYDB_TYPE ? slot->keyDB : slot->certDB;
    if (dbHandle) {
        PR_AtomicIncrement(&dbHandle->ref);
    }
    PZ_Unlock(slot->slotLock);
    return dbHandle;
}

/*
 * initialize a new database handle
 */
static SFTKDBHandle *
sftk_NewDBHandle(SDB *sdb, int type)
{
   SFTKDBHandle *handle = PORT_New(SFTKDBHandle);
   handle->ref = 1;
   handle->db = sdb;
   handle->type = type;
   handle->passwordKey.data = NULL;
   handle->passwordKey.len = 0;
   handle->passwordLock = NULL;
   if (type == SFTK_KEYDB_TYPE) {
	handle->passwordLock = PZ_NewLock();
   }
   return handle;
}


/*
 * initialize certificate and key database handles
 */
CK_RV 
sftk_DBInit(const char *configdir, const char *certPrefix,
                const char *keyPrefix, PRBool readOnly, PRBool noCertDB,
                PRBool noKeyDB, PRBool forceOpen,
                SFTKDBHandle **certDB, SFTKDBHandle **keyDB)
{
    const char *confdir;
    const char *dbType = NULL;
    char *appName = NULL;
    SDB *keySDB, *certSDB;
    CK_RV crv = CKR_OK;
    int flags = SDB_RDONLY;

    if (!readOnly) {
	flags = SDB_CREATE;
    }

    *certDB = NULL;
    *keyDB = NULL;

    if (noKeyDB && noCertDB) {
	return CKR_OK;
    }
    confdir = sftk_EvaluateConfigDir(configdir, &dbType, &appName);
    /* FIXME_ -- prefixes */
    crv = s_open(confdir, certPrefix, keyPrefix, 9, 4, flags, 
	noCertDB? NULL : &certSDB, noKeyDB ? NULL : &keySDB);
    if (crv != CKR_OK) {
	goto loser;
    }
    if (!noCertDB) {
	*certDB = sftk_NewDBHandle(certSDB, SFTK_CERTDB_TYPE);
    } else {
	*certDB = NULL;
    }
    if (!noKeyDB) {
	*keyDB = sftk_NewDBHandle(keySDB, SFTK_KEYDB_TYPE);
    } else {
	*keyDB = NULL;
    }

loser:
    if (appName) {
	PORT_Free(appName);
    }
   return forceOpen ? CKR_OK : crv;
}

