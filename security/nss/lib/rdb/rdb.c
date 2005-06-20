/*
 * the following data structures are from rdb.h.
 */
#include "sqlite3.h"
#include "mcom_db.h"
#include "errno.h"
#include "malloc.h"
#include "stdlib.h"
#include "string.h"
#include "sys/stat.h"
#include "fcntl.h"
#ifdef _WINDOWS
#include "direct.h"
#define usleep(x)
#else
#include "unistd.h"
#endif

#define STATIC_CMD_SIZE 2048
struct RDBStr {
    DB  db;
    int (*xactstart)(DB *db);
    int (*xactdone)(DB *db, PRBool abort);
    int version;
    int (*dbinitcomplete)(DB *db);
    int flags;
    int index;
    unsigned char *dataPool;
    int dataPoolSize;
    unsigned char *keyPool;
    int keyPoolSize;
    sqlite3_stmt *delStmt;
    sqlite3_stmt *getStmt;
    sqlite3_stmt *seqStmt;
    sqlite3_stmt *insertStmt;
    sqlite3_stmt *replaceStmt;
    sqlite3_stmt *beginStmt;
    sqlite3_stmt *rollbackStmt;
    sqlite3_stmt *commitStmt;
};


typedef struct RDBStr RDB;
#define DB_RDB ((DBTYPE) 0xff)
#define RDB_RDONLY      1
#define RDB_RDWR        2
#define RDB_CREATE      4

#define DBM_OK 0
#define DBM_ERROR -1
#define DBM_END  1

#define DEL_CMD      "DELETE FROM nssTable WHERE key=$KEY;"
#define GET_CMD      "SELECT ALL * FROM nssTable WHERE key=$KEY;"
#define SEQ_CMD      "SELECT ALL * FROM nssTable LIMIT 1 OFFSET $OFFSET;"
#define INSERT_CMD   "INSERT INTO nssTable VALUES ( $KEY, $DATA );"
#define REPLACE_CMD  "REPLACE INTO nssTable VALUES ( $KEY, $DATA );"
#define BEGIN_CMD    "BEGIN EXCLUSIVE TRANSACTION;"
#define ROLLBACK_CMD "ROLLBACK TRANSACTION;"
#define COMMIT_CMD   "COMMIT TRANSACTION;"
#define INIT_CMD  \
 "CREATE TABLE nssTable (Key PRIMARY KEY UNIQUE ON CONFLICT ABORT, Data);"
#define IN_INIT_CMD   "CREATE TABLE nssInit (dummy);"
#define DONE_INIT_CMD "DROP TABLE nssInit;"
#define CHECK_TABLE_CMD "SELECT ALL * FROM %s LIMIT 0;"

static int rdbupdateStmt(sqlite3 *db, sqlite3_stmt **stmt, const char *cmd)
{
    sqlite3_finalize(*stmt);
    return sqlite3_prepare(db, cmd, -1, stmt, NULL);
}

#define MAX_RETRIES 10
static int rdbdone(int err, int *count)
{
    /* allow as many rows as the database wants to give */
    if (err == SQLITE_ROW) {
	*count = 0;
	return 0;
    }
    if (err != SQLITE_BUSY) {
	return 1;
    }
    /* err == SQLITE_BUSY, Dont' retry forever in this case */
    if (++(*count) >= MAX_RETRIES) {
	return 1;
    }
    return 0;
}

static int rdbmapSQLError(sqlite3 *db, int sqlerr)
{
    if ((sqlerr == SQLITE_OK) ||
	(sqlerr == SQLITE_DONE)) {
	return DBM_OK;
    } else {
	return DBM_ERROR;
    }
}

int rdbxactstart(DB *db)
{
    sqlite3  *psqlDB = (sqlite3 *)db->internal;
    RDB *rdb = (RDB *)db;
    sqlite3_stmt *stmt;
    int retry = 0;
    int sqlerr;


    if (psqlDB == NULL) {
	return DBM_ERROR;
    }
    if (rdb->flags == RDB_RDONLY) {
	errno = EPERM;
	return DBM_ERROR;
    }
    sqlerr = rdbupdateStmt(psqlDB, &rdb->beginStmt, BEGIN_CMD);
    if (sqlerr != SQLITE_OK) {
	return DBM_ERROR;
    }
    stmt = rdb->beginStmt;

    do {
	sqlerr = sqlite3_step(stmt);
	if (sqlerr == SQLITE_BUSY) {
	    usleep(5);
	}
    } while (!rdbdone(sqlerr,&retry));
    sqlite3_reset(stmt);

    return rdbmapSQLError(psqlDB, sqlerr);
}

int rdbxactdone(DB *db, PRBool abort)
{
    sqlite3  *psqlDB = (sqlite3 *)db->internal;
    RDB *rdb = (RDB *)db;
    sqlite3_stmt *stmt;
    int retry = 0;
    int sqlerr;

    if (psqlDB == NULL) {
	return DBM_ERROR;
    }
    if (rdb->flags == RDB_RDONLY) {
	errno = EPERM;
	return DBM_ERROR;
    }
    sqlerr = rdbupdateStmt(psqlDB, &rdb->rollbackStmt, ROLLBACK_CMD);
    if (sqlerr != SQLITE_OK) {
	return DBM_ERROR;
    }
    sqlerr = rdbupdateStmt(psqlDB, &rdb->commitStmt, COMMIT_CMD);
    if (sqlerr != SQLITE_OK) {
	return DBM_ERROR;
    }
    stmt = abort ? rdb->rollbackStmt : rdb->commitStmt;

    do {
	sqlerr = sqlite3_step(stmt);
	if (sqlerr == SQLITE_BUSY) {
	    usleep(5);
	}
    } while (!rdbdone(sqlerr,&retry));
    sqlite3_reset(stmt);

    return rdbmapSQLError(psqlDB, sqlerr);
}

int rdbclose(DB *db)
{
    sqlite3  *psqlDB = (sqlite3 *)db->internal;
    RDB *rdb = (RDB *)db;
    int sqlerr = SQLITE_OK;

    sqlite3_finalize(rdb->delStmt);
    sqlite3_finalize(rdb->getStmt);
    sqlite3_finalize(rdb->seqStmt);
    sqlite3_finalize(rdb->insertStmt);
    sqlite3_finalize(rdb->replaceStmt);
    sqlite3_finalize(rdb->beginStmt);
    sqlite3_finalize(rdb->rollbackStmt);
    sqlite3_finalize(rdb->commitStmt);

    sqlerr = sqlite3_close(psqlDB);
    /* assert sqlerr == SQLITE_OK */
    free(rdb);
    return DBM_OK;
}


int rdbdel(const DB *db, const DBT *key, uint flags)
{
    sqlite3  *psqlDB = (sqlite3 *)db->internal;
    RDB *rdb = (RDB *)db;
    sqlite3_stmt *stmt;
    int retry = 0;
    int sqlerr;

    if (psqlDB == NULL) {
	return DBM_ERROR;
    }
    if (rdb->flags == RDB_RDONLY) {
	errno = EPERM;
	return DBM_ERROR;
    }
    sqlerr = rdbupdateStmt(psqlDB, &rdb->delStmt, DEL_CMD);
    if (sqlerr != SQLITE_OK) {
	return DBM_ERROR;
    }
    stmt = rdb->delStmt;

    sqlite3_bind_blob(stmt, 1, key->data, key->size, SQLITE_STATIC);
    do {
	sqlerr = sqlite3_step(stmt);
	if (sqlerr == SQLITE_BUSY) {
	    usleep(5);
	}
    } while (!rdbdone(sqlerr,&retry));
    sqlite3_reset(stmt);
    sqlite3_bind_null(stmt,1);

    return rdbmapSQLError(psqlDB, sqlerr);
}

void
setData(DBT *dbt,const char *blobData, int blobSize, 
	unsigned char **poolPtr, int *poolSizePtr) 
{
    int size = blobSize < 2048 ? blobSize : 2048;

    if (size > *poolSizePtr) {
	*poolPtr = realloc(*poolPtr,size);
	*poolSizePtr = size;
    }
    memcpy(*poolPtr, blobData, blobSize);
    dbt->data = *poolPtr;
    dbt->size = blobSize;
}


int rdbget(const DB *db, const DBT *key, DBT *data, uint flags)
{
    sqlite3  *psqlDB = (sqlite3 *)db->internal;
    RDB *rdb = (RDB *)db;
    sqlite3_stmt *stmt;
    int retry = 0;
    int found = 0;
    int sqlerr;
    int ret;

    if (psqlDB == NULL) {
	return DBM_ERROR;
    }
    sqlerr = rdbupdateStmt(psqlDB, &rdb->getStmt, GET_CMD);
    if (sqlerr != SQLITE_OK) {
	return DBM_ERROR;
    }
    stmt = rdb->getStmt;

    sqlite3_bind_blob(stmt, 1, key->data, key->size, SQLITE_STATIC);
    do {
	sqlerr = sqlite3_step(stmt);
	if (sqlerr == SQLITE_BUSY) {
	    usleep(5);
	}
	if (sqlerr == SQLITE_ROW) {
	    /* we only asked for 1, this will return the last one */
	    int blobSize = sqlite3_column_bytes(stmt, 1);
	    const char *blobData = sqlite3_column_blob(stmt, 1);
	    setData(data,blobData,blobSize, &rdb->dataPool, &rdb->dataPoolSize);
	    found = 1;
	}
    } while (!rdbdone(sqlerr,&retry));

    sqlite3_reset(stmt);
    sqlite3_bind_null(stmt,1);

    ret = rdbmapSQLError(psqlDB, sqlerr);
    if ((ret == 0) && (!found)) {
	ret = DBM_END;
    }

    return ret;
}

int rdbput(const DB *db, const DBT *key, const DBT *data, uint flag)
{
    sqlite3  *psqlDB = (sqlite3 *)db->internal;
    RDB *rdb = (RDB *)db;
    sqlite3_stmt *stmt;
    int retry = 0;
    int sqlerr;

    if (psqlDB == NULL) {
	return DBM_ERROR;
    }
    if (rdb->flags == RDB_RDONLY) {
	errno = EPERM;
	return DBM_ERROR;
    }
    sqlerr = rdbupdateStmt(psqlDB, &rdb->insertStmt, INSERT_CMD);
    if (sqlerr != SQLITE_OK) {
	return DBM_ERROR;
    }
    sqlerr = rdbupdateStmt(psqlDB, &rdb->replaceStmt, REPLACE_CMD);
    if (sqlerr != SQLITE_OK) {
	return DBM_ERROR;
    }
    stmt = (flag == R_NOOVERWRITE) ? rdb->insertStmt : rdb->replaceStmt;

    sqlite3_bind_blob(stmt, 1, key->data, key->size, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, data->data, data->size, SQLITE_STATIC);
    do {
	sqlerr = sqlite3_step(stmt);
	if (sqlerr == SQLITE_BUSY) {
	    usleep(5);
	}
    } while (!rdbdone(sqlerr,&retry));

    sqlite3_reset(stmt);
    sqlite3_bind_null(stmt,1);
    sqlite3_bind_null(stmt,0);

    return rdbmapSQLError(psqlDB, sqlerr);
}
	
int rdbseq(const DB *db, DBT *key, DBT *data, uint flags)
{
    sqlite3  *psqlDB = (sqlite3 *)db->internal;
    RDB *rdb = (RDB *)db;
    sqlite3_stmt *stmt;
    int retry = 0;
    int found = 0;
    int sqlerr;
    int ret;

    if (psqlDB == NULL) {
	return DBM_ERROR;
    }
    if (flags == R_FIRST) {
	rdb->index = 0;
    } else if (flags == R_NEXT) {
	rdb->index++;
    } else {
	errno = EINVAL;
	return DBM_ERROR;
    }
    sqlerr = rdbupdateStmt(psqlDB, &rdb->seqStmt, SEQ_CMD);
    if (sqlerr != SQLITE_OK) {
	return DBM_ERROR;
    }
    stmt = rdb->seqStmt;

    sqlite3_bind_int(stmt, 1, rdb->index);
    do {
	sqlerr = sqlite3_step(stmt);
	if (sqlerr == SQLITE_BUSY) {
	    usleep(5);
	}
	if (sqlerr == SQLITE_ROW) {
	    /* we only asked for 1, this will return the last one */
	    int blobSize = sqlite3_column_bytes(stmt, 0);
	    const char *blobData = sqlite3_column_blob(stmt, 0);
	    setData(key,blobData,blobSize, &rdb->keyPool, &rdb->keyPoolSize);
	    blobSize = sqlite3_column_bytes(stmt, 1);
	    blobData = sqlite3_column_blob(stmt, 1);
	    setData(data,blobData,blobSize, &rdb->dataPool, &rdb->dataPoolSize);
	    found = 1;
	}
    } while (!rdbdone(sqlerr,&retry));

    sqlite3_reset(stmt);
    sqlite3_bind_null(stmt,1);

    ret = rdbmapSQLError(psqlDB, sqlerr);
    if ((ret == 0) && (!found)) {
	ret = DBM_END;
    }
    return ret;
}


int rdbsync(const DB *db, uint flags)
{
   return DBM_OK;
}


int rdbfd(const DB *db)
{
    errno = EINVAL;
    return DBM_ERROR;
}

int rdbinitcomplete(DB *db)
{
    sqlite3  *psqlDB = (sqlite3 *)db->internal;
    int sqlerr;

    sqlerr = sqlite3_exec(psqlDB, DONE_INIT_CMD, NULL, 0, NULL);
    /* deal with the error! */
    return DBM_OK;
}


static int grdbstatus = 0;
int rdbstatus(void)
{
    return grdbstatus;
}

static int tableExists(sqlite3 *sqlDB, const char *tableName)
{
    int sqlerr;
    char * cmd = sqlite3_mprintf(CHECK_TABLE_CMD, tableName);

    if (cmd == NULL) {
	return 0;
    }

    sqlerr = 
	 sqlite3_exec(sqlDB, cmd, NULL, 0, 0);
    sqlite3_free(cmd);

    return (sqlerr == SQLITE_OK) ? 1 : 0;
}


static int rdbIsDirectory(const char *dir)
{
    struct stat sbuf;
    int rc;

    rc = stat(dir,&sbuf);
    if (rc == 0) {
	return ((sbuf.st_mode & S_IFDIR) == S_IFDIR);
    }
    return 0;
}

static int rdbRmFile(const char *fileName)
{
    int rc = unlink(fileName);
    if ((rc < 0) && (errno == EPERM)) {
	chmod(fileName,0644);
	rc = unlink(fileName);
    }
    return rc;
}

#define MAX_RECURSE_LEVEL 15
#define DIR_MODE 0755
#ifdef _WINDOWS
#define MKDIR(x,y) mkdir(x)
#else
#define MKDIR(x,y) mkdir(x,y)
#endif

/*
 * Create a directory. Create any missing or broken 
 * components we need along the way. If we already have a
 * directory, return success.
 */
int rdbMakedir(const char *directory, int level, int mode)
{
   int rc;
   char *buf, *cp;
#ifdef _WINDOWS
   char *cp1;
#endif

   /* prevent arbitrary stack overflow */
   if (level > MAX_RECURSE_LEVEL) {
	errno = ENAMETOOLONG;
	return -1;
   }
   umask(0);

   /* just try it first */
   rc = MKDIR(directory, mode);
   if (rc != 0) {
	if (errno == EEXIST) {
	    if (rdbIsDirectory(directory)) {
		/* we have a directory, use it */
		return 0;
	    } else  { /* must be a file */
		/* remove the file and try again */
		rc = rdbRmFile(directory);
		if (rc == 0) {
			rc = MKDIR(directory, mode);
		}
		return rc;
	    }
	}
	/* if we fail because on of the subdirectory entries was a
	 * file, or one of the subdirectory entries didn't exist,
	 * move back one component and try the whole thing again
	 */
	if ((errno != ENOENT) && (errno != ENOTDIR)) {
	    return rc;
	}
	buf = (char *)malloc(strlen(directory)+1);
	strcpy(buf,directory);
	cp = strrchr(buf,'/');
#ifdef _WINDOWS
	cp1 = strrchr(buf,'\\');
	if (cp1 > cp) {
	   cp = cp1;
	}
#endif
	if (cp) {
	    *cp = 0;
	    rc = rdbMakedir(buf,level+1, mode);
	    if (rc == 0) {
	     	rc = MKDIR(directory, mode);
	     }
	 }
	free(buf);
    }
    return rc;
}

static char *rdbBuildFileName(const char *appName, const char *prefix,
				 const char *type, int flags)
{
    const char *home = getenv("HOME");
    char *dir, *dbname;
    char *prefixDir = NULL;
    const char *prefixName = NULL;

     /*
      * build up the name of our database file.
      * if create is set, make sure the directory path exists.
      */
    if (prefix) {
	/*
	 * prefix may have directory elements in it. If it does, we need
	 * to break out the directory versus the actual prefix portions
	 * so we can make sure the directory is created before we try to
	 * create the db file.
	 */
	const char *end = strrchr(prefix,'/');
#ifdef WINDOWS
	/* windows has two possible directory field separators. Make sure
	 * we pick the one that is furthest down the string. (this code
	 * will also pick the non-null value. */
	const char *end2 = strrchr(prefix,'\\');
	/* find the last directory path element */
	if (end2 > end) {
	    end = end2;
	}
#endif
	/* if the directory path exists, split the components */
	if (end) {
	   prefixDir = strdup(prefix);
	   if (prefixDir == NULL) return NULL;
	   prefixDir[prefix-end] = 0;
	   prefixName = end+1;
	} else {
	   prefixName = prefix;
	}
    }
    /* build the directory portion */
    if (prefixDir) {
	dir = sqlite3_mprintf("%s/.nssdb/%s/%s",home,appName,prefixDir);
	free(prefixDir);
    } else {
	dir = sqlite3_mprintf("%s/.nssdb/%s",home,appName);
    }
    if (dir == NULL) return NULL;
    /* if we are creating, make sure the directory is created as well */
    if (flags == RDB_CREATE) {
	rdbMakedir(dir,0, DIR_MODE);
    }
    /* build the full dbname */
    dbname = sqlite3_mprintf("%s/%s%sS.sqldb",dir,prefixName? prefixName:"",type);
    sqlite3_free(dir);
    return dbname;
}



/* rdbopen */
DB * rdbopen(const char *appName, const char *prefix, const char *type,
				 int flags)
{
    char *name = rdbBuildFileName(appName, prefix, type, flags);
    sqlite3  *psqlDB = NULL;
    RDB  *rdb = NULL;
    int sqlerr = SQLITE_OK;
    int inTransaction = 0;
    int inInit = 0;

    if (name == NULL) {
	errno = EINVAL;
	return NULL;
    }

    sqlerr = sqlite3_open(name,&psqlDB );
    sqlite3_free(name);
    if (sqlerr != SQLITE_OK) {
	goto cleanup;
    }

    sqlerr = sqlite3_busy_timeout(psqlDB, 1000);
    if (sqlerr != SQLITE_OK) {
	goto cleanup;
    }
    

    sqlerr = sqlite3_exec(psqlDB, BEGIN_CMD, NULL, 0, NULL);
    if (sqlerr != SQLITE_OK) {
	goto cleanup;
    }
    inTransaction = 1;

    if (!tableExists(psqlDB,"nssTable")) {
	if (flags != RDB_CREATE) {
	    goto cleanup;
	}
	sqlerr = sqlite3_exec(psqlDB, INIT_CMD, NULL, 0, NULL);
	if (sqlerr != SQLITE_OK) {
	    goto cleanup;
	}
	/* hack. don't create the init on secmod db files */
	if (strcmp(type,"secmod") != 0) {
	    sqlerr = sqlite3_exec(psqlDB, IN_INIT_CMD, NULL, 0, NULL);
	    if (sqlerr != SQLITE_OK) {
		goto cleanup;
	    }
	}
    } else {
	/* if the nssInit table exists, then someone else is initing the
	 * nss database. We don't want to complete the open until the init 
	 * is completed. */
	if (tableExists(psqlDB,"nssInit")) {
	   inInit = 1;
	}
    }
    rdb = (RDB *) malloc(sizeof(RDB));
    rdb->db.internal = psqlDB;
    rdb->db.type = DB_RDB;
    rdb->db.close = rdbclose;
    rdb->db.del = rdbdel;
    rdb->db.get = rdbget;
    rdb->db.put = rdbput;
    rdb->db.seq = rdbseq;
    rdb->db.sync = rdbsync;
    rdb->db.fd = rdbfd;
    rdb->version = 1;
    rdb->index = 0;
    rdb->flags = flags;
    rdb->xactstart = rdbxactstart;
    rdb->xactdone = rdbxactdone;
    rdb->dbinitcomplete = rdbinitcomplete;
    rdb->dataPool = NULL;
    rdb->dataPoolSize = 0;
    rdb->keyPool = NULL;
    rdb->keyPoolSize = 0;
    sqlerr = sqlite3_prepare(psqlDB, DEL_CMD, sizeof(DEL_CMD), 
		&rdb->delStmt, NULL);
    if (sqlerr != SQLITE_OK) {
	goto cleanup;
    }
    sqlerr = sqlite3_prepare(psqlDB, GET_CMD, sizeof(GET_CMD), 
		&rdb->getStmt, NULL);
    if (sqlerr != SQLITE_OK) {
	goto cleanup;
    }
    sqlerr = sqlite3_prepare(psqlDB, SEQ_CMD, sizeof(SEQ_CMD), 
		&rdb->seqStmt, NULL);
    if (sqlerr != SQLITE_OK) {
	goto cleanup;
    }
    sqlerr = sqlite3_prepare(psqlDB, INSERT_CMD, sizeof(INSERT_CMD), 
		&rdb->insertStmt, NULL);
    if (sqlerr != SQLITE_OK) {
	goto cleanup;
    }
    sqlerr = sqlite3_prepare(psqlDB, REPLACE_CMD, sizeof(REPLACE_CMD), 
		&rdb->replaceStmt, NULL);
    if (sqlerr != SQLITE_OK) {
	goto cleanup;
    }
    sqlerr = sqlite3_prepare(psqlDB, BEGIN_CMD, sizeof(BEGIN_CMD), 
		&rdb->beginStmt, NULL);
    if (sqlerr != SQLITE_OK) {
	goto cleanup;
    }
    sqlerr = sqlite3_prepare(psqlDB, ROLLBACK_CMD, sizeof(ROLLBACK_CMD), 
		&rdb->rollbackStmt, NULL);
    if (sqlerr != SQLITE_OK) {
	goto cleanup;
    }
    sqlerr = sqlite3_prepare(psqlDB, COMMIT_CMD, sizeof(COMMIT_CMD), 
		&rdb->commitStmt, NULL);
    if (sqlerr != SQLITE_OK) {
	goto cleanup;
    }
    sqlerr = sqlite3_exec(psqlDB, COMMIT_CMD, NULL, 0, NULL);
    if (sqlerr != SQLITE_OK) {
	goto cleanup;
    }
    inTransaction = 0;
    if (inInit) {
	while (tableExists(psqlDB,"nssInit")) {
	    usleep(5);
	}
    }
    return &rdb->db;

cleanup:
    /* lots of stuff to do */
    if (inTransaction) {
	sqlerr = sqlite3_exec(psqlDB, ROLLBACK_CMD, NULL, 0, NULL);
	if (sqlerr != SQLITE_OK) {
	    goto cleanup;
	}
    }
    if (rdb) {
	if (rdb->delStmt) {
	    sqlite3_finalize(rdb->delStmt);
	}
	if (rdb->getStmt) {
	    sqlite3_finalize(rdb->getStmt);
	}
	if (rdb->seqStmt) {
	    sqlite3_finalize(rdb->seqStmt);
	}
	if (rdb->insertStmt) {
	    sqlite3_finalize(rdb->insertStmt);
	}
	if (rdb->replaceStmt) {
	    sqlite3_finalize(rdb->replaceStmt);
	}
	if (rdb->beginStmt) {
	    sqlite3_finalize(rdb->beginStmt);
	}
	if (rdb->rollbackStmt) {
	    sqlite3_finalize(rdb->rollbackStmt);
	}
	if (rdb->commitStmt) {
	    sqlite3_finalize(rdb->commitStmt);
	}
	free(rdb);
    }
    if (psqlDB) {
	sqlite3_close(psqlDB);
    }
    return NULL;

};
