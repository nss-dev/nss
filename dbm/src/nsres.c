/* What?  No mozilla license boilerplate? */

#include "watcomfx.h"
#include "nsres.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


struct RESDATABASE
{
	DB *hdb;
	NSRESTHREADINFO *threadinfo;
	int WhichString;
	char * pbuf[MAXBUFNUM];
} ;
typedef struct RESDATABASE *  RESHANDLE;

typedef struct STRINGDATA
{
	char *str;
	unsigned int charsetid;
} STRINGDATA;


typedef unsigned int CHARSETTYPE;
#define RES_LOCK    if (hres->threadinfo)   \
                        hres->threadinfo->fn_lock(hres->threadinfo->lock);
#define RES_UNLOCK  if (hres->threadinfo)   \
                        hres->threadinfo->fn_unlock(hres->threadinfo->lock);

static int GenKeyData(const char *library, int32 id, DBT *key);

/* 
  Right now, the page size used for resource is same as for Navigator cache
  database
 */
HASHINFO res_hash_info = {
        32*1024,
        0,
        0,
        0,
        0,   /* 64 * 1024U  */
        0};

static int GenKeyData(const char *library, int32 id, DBT *key)
{
	char * strdata = NULL;
	size_t len;
	char idstr[10];

	if (id == 0)
		idstr[0] = '\0';
	else
	{
		sprintf(idstr, "%d", id);
		/*	itoa(id, idstr, 10);  */
	}

	if (library == NULL)
		len = strlen(idstr) + 1;
	else
		len = strlen(library) + strlen(idstr) + 1;
	strdata = (char *)PR_Malloc(len);
	if (strdata) {
		strcpy(strdata, library);
		strcat(strdata, idstr);
    }
	key->size = len;
	key->data = strdata;

	return (strdata != NULL);
}

NSRESHANDLE NSResCreateTable(const char *filename, NSRESTHREADINFO *threadinfo)
{
	RESHANDLE hres;
	int flag;

	flag = PR_RDWR | PR_CREATE_FILE;

	hres = PR_NEWZAP(struct RESDATABASE);
	if (!hres) 
		return NULL;

	if (threadinfo && threadinfo->lock && threadinfo->fn_lock 
		&& threadinfo->fn_unlock)
	{
		hres->threadinfo = PR_NEW(NSRESTHREADINFO);
		if (!hres->threadinfo)
			goto fail;
		hres->threadinfo->lock = threadinfo->lock;
		hres->threadinfo->fn_lock = threadinfo->fn_lock;
		hres->threadinfo->fn_unlock = threadinfo->fn_unlock;
	}


	RES_LOCK

	hres->hdb = dbopen(filename, flag, 0644, DB_HASH, &res_hash_info);

	RES_UNLOCK

	if(!hres->hdb) {
fail:
		if (hres->threadinfo)
			PR_Free(hres->threadinfo);
		PR_Free(hres);	
		return NULL;
	}

	return (NSRESHANDLE) hres;
}

NSRESHANDLE NSResOpenTable(const char *filename, NSRESTHREADINFO *threadinfo)
{
	RESHANDLE hres;
	int flag;

	flag = PR_RDONLY;  /* only open database for reading */

	hres = PR_NEWZAP(struct RESDATABASE);
	if (!hres)
		return NULL;

	if (threadinfo && threadinfo->lock && threadinfo->fn_lock 
	  && threadinfo->fn_unlock)
	{
		hres->threadinfo = PR_NEW(NSRESTHREADINFO);
		if (!hres->threadinfo)
			goto fail;
		hres->threadinfo->lock = threadinfo->lock;
		hres->threadinfo->fn_lock = threadinfo->fn_lock;
		hres->threadinfo->fn_unlock = threadinfo->fn_unlock;
	}


	RES_LOCK

	hres->hdb = dbopen(filename, flag, 0644, DB_HASH, &res_hash_info);

	RES_UNLOCK

	if(!hres->hdb) {
fail:
		if (hres->threadinfo)
			PR_Free(hres->threadinfo);
		PR_Free(hres);
		return NULL;
	}
	return (NSRESHANDLE) hres;
}



void NSResCloseTable(NSRESHANDLE handle)
{
	RESHANDLE hres;
	int i;

	if (handle == NULL)
		return;
	hres = (RESHANDLE) handle;

	RES_LOCK

	(*hres->hdb->sync)(hres->hdb, 0);
	(*hres->hdb->close)(hres->hdb);

	RES_UNLOCK

	for (i = 0; i < MAXBUFNUM; i++)
	{
		if (hres->pbuf[i])
			PR_Free(hres->pbuf[i]);
	}

	if (hres->threadinfo)
		PR_Free(hres->threadinfo);
	PR_Free(hres);
}


char *NSResLoadString(NSRESHANDLE handle, const char * library, int32 id, 
	unsigned int charsetid, char *retbuf)
{
	int status;
	RESHANDLE hres;
	DBT key, data;
	if (handle == NULL)
		return NULL;

	if (!GenKeyData(library, id, &key))
		return NULL;

	hres = (RESHANDLE) handle;
	RES_LOCK

	if (!retbuf) {
		int i  = hres->WhichString;
		retbuf = hres->pbuf[i];
		if (!retbuf) {
			retbuf = (char *)PR_Malloc(MAXSTRINGLEN * sizeof(char));
			if (!retbuf)
				goto fail;
			hres->pbuf[i] = retbuf;
		}

		/* reset to 0, if WhichString reaches to the end */
		if (++hres->WhichString >= MAXBUFNUM)  {
			  hres->WhichString = 0;
		}
	}

	status = (*hres->hdb->get)(hres->hdb, &key, &data, 0);

    /* lock protects shared output buffer, so cannot unlock until 
	** results are copied out!
	*/

	if (status) 
		retbuf[0] = 0;
	else
		memcpy(retbuf, (char *)data.data + sizeof(CHARSETTYPE), 
							   data.size - sizeof(CHARSETTYPE));
fail:
	RES_UNLOCK
	PR_Free(key.data);
	return retbuf;
}


int32 NSResGetSize(NSRESHANDLE handle, const char *library, int32 id)
{
	int status;
	RESHANDLE hres;
	DBT key, data;
	if (handle == NULL)
		return 0;	/* failure */

	if (!GenKeyData(library, id, &key))
		return 0;

	hres = (RESHANDLE) handle;
	RES_LOCK

	status = (*hres->hdb->get)(hres->hdb, &key, &data, 0);

	RES_UNLOCK
	PR_Free(key.data);

	if (status)
		return 0;	/* failure */

	return data.size - sizeof(CHARSETTYPE);
}

int32 NSResLoadResource(NSRESHANDLE handle, const char *library, int32 id, char *retbuf)
{
	int status;
	RESHANDLE hres;
	DBT key, data;
	if (handle == NULL || !retbuf)
		return 0;

	if (!GenKeyData(library, id, &key))
		return 0;

	hres = (RESHANDLE) handle;
	RES_LOCK

	status = (*hres->hdb->get)(hres->hdb, &key, &data, 0);
	PR_Free(key.data);

	if (!status) {
		memcpy(retbuf, (char *)data.data + sizeof(CHARSETTYPE), 
		                       data.size - sizeof(CHARSETTYPE));
		RES_UNLOCK
		return data.size;
	}

	RES_UNLOCK
	return 0;
}

/* Apparently, this function wants to return 0 on failure, and non-zero
** on success.  But the status returned by the DB's put routine returns
** zero on success, and non-zero on failure. 
*/
int NSResAddString(NSRESHANDLE handle, const char *library, int32 id, 
  const char *string, unsigned int charset)
{
	int status;
	RESHANDLE hres;
	DBT key, data;
	char * recdata;

	if (handle == NULL)
		return 0;
	hres = (RESHANDLE) handle;

	if (!GenKeyData(library, id, &key))
		return 0;

	data.size = sizeof(CHARSETTYPE) + (strlen(string) + 1) ;

	recdata = (char *)PR_Malloc(data.size);
	if (!recdata) 
		return 0;	/* DBM internal error code */

	/* set charset to the first field of record data */
	*((CHARSETTYPE *)recdata) = (CHARSETTYPE)charset;

	/* set data field */
	memcpy(recdata+sizeof(CHARSETTYPE), string, strlen(string) + 1);

	data.data = recdata;

	RES_LOCK

	status = (*hres->hdb->put)(hres->hdb, &key, &data, 0);

	RES_UNLOCK

	PR_Free(key.data);
	PR_Free(recdata);

	return !status;
}
