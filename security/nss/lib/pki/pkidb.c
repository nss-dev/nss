/* 
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License")
{
} you may not use this file
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

#include "mcom_db.h"

#ifndef BASE_H
#include "base.h"
#endif /* BASE_H */

#ifndef PKIM_H
#include "pkim.h"
#endif /* PKIM_H */

#define DBM_DEFAULT     0
#define DBS_BLOCK_SIZE (16*1024) /* XXX not doing blobbing yet */
#define DBS_CACHE_SIZE (DBS_BLOCK_SIZE * 8)

static const HASHINFO s_db_hash_info = {
  DBS_BLOCK_SIZE,  /* bucket size, must be greater than = to
                    * or maximum record size (+ header)
                    * we allow before blobing 
                    */
  DBM_DEFAULT,     /* Fill Factor */
  DBM_DEFAULT,     /* number of elements */
  DBS_CACHE_SIZE,  /* cache size */
  DBM_DEFAULT,     /* hash function */
  DBM_DEFAULT,     /* byte order */
};

struct nssPKIDatabaseStr
{
  NSSTrustDomain *td;
  PZLock *lock;
  DB *db;
};

#define PKIDB_VERSION 10

#define ROWID_CERT_HEADER     1
#define ROWID_SUBJECT_HEADER  2
#define ROWID_NICKNAME_HEADER 3
#define ROWID_EMAIL_HEADER    4

#define PKIDB_IS_CERT_RECORD(rowID) \
    (((unsigned char *)(rowID)->data)[0] == ROWID_CERT_HEADER)

#define PAYLOAD_HEADER_LENGTH   3
#define PAYLOAD_CERT_HEADER     1
#define PAYLOAD_SUBJECT_HEADER  2
#define PAYLOAD_NICKNAME_HEADER 3
#define PAYLOAD_EMAIL_HEADER    4

#define CERT_PAYLOAD_TRUST_OFFSET PAYLOAD_HEADER_LENGTH
#define TRUST_RECORD_LENGTH     16

#define SET_DBT_BYTE(dbt, index, val) \
    ((unsigned char *)(dbt)->data)[index] = val

#define SET_DBT_INT(dbt, index, num) \
    nsslibc_memcpy(((unsigned char *)(dbt)->data) + index, &num, sizeof(num))

#define SET_DBT_BUF(dbt, index, buf, len) \
    nsslibc_memcpy(((unsigned char *)(dbt)->data) + index, buf, len)

#define SET_DBT_ITEM(dbt, index, it) \
    nsslibc_memcpy(((unsigned char *)(dbt)->data) + index, \
                   (it)->data, (it)->size)

#define GET_DBT_INT(dbt, index, num) \
    num = *(PRUint32 *)(((unsigned char *)(dbt)->data) + index)

#define GET_DBT_BUF(dbt, index, buf) \
    buf = ((unsigned char *)(dbt)->data) + index

static PRStatus
write_record(nssPKIDatabase *pkidb, DBT *rowID, DBT *payload)
{
    int dberr;
    PZ_Lock(pkidb->lock);
    dberr = pkidb->db->put(pkidb->db, rowID, payload, 0);
    PZ_Unlock(pkidb->lock);
    return (dberr == 0) ? PR_SUCCESS : PR_FAILURE;
}

static PRStatus
delete_record(nssPKIDatabase *pkidb, DBT *rowID)
{
    int dberr;
    PZ_Lock(pkidb->lock);
    dberr = pkidb->db->del(pkidb->db, rowID, 0);
    PZ_Unlock(pkidb->lock);
    return (dberr == 0) ? PR_SUCCESS : PR_FAILURE;
}

static PRStatus
make_cert_rowid_from_issuer_serial(DBT *rowID, 
                                   NSSBER *issuer, NSSBER *serial, 
                                   NSSArena *arenaOpt)
{
    int i;
    rowID->size = 1 + issuer->size + serial->size;
    rowID->data = nss_ZAlloc(arenaOpt, rowID->size);
    if (!rowID->data) {
	return PR_FAILURE;
    }
    i = 0;
    SET_DBT_BYTE(rowID, 0, ROWID_CERT_HEADER); i++;
    SET_DBT_ITEM(rowID, i, issuer);            i += issuer->size;
    SET_DBT_ITEM(rowID, i, serial);            i += serial->size;
    return PR_SUCCESS;
}

static PRStatus
make_cert_rowid(DBT *rowID, NSSCert *cert, NSSArena *arenaOpt)
{
    NSSBER *issuer, *serial;
    issuer = nssCert_GetIssuer(cert);
    serial = nssCert_GetSerialNumber(cert);
    return make_cert_rowid_from_issuer_serial(rowID, issuer, serial, arenaOpt);
}

static PRStatus
write_cert_record(nssPKIDatabase *pkidb, DBT *rowID, NSSCert *certOpt, 
                  NSSUTF8 *nicknameOpt, nssTrust *trustOpt, 
                  NSSArena *arena)
{
    DBT payload;
    NSSBER *ber;
    PRUint32 size;
    PRUint32 berSize;
    PRUint32 nicknameLen;
    int i;

    if (certOpt) {
	ber = nssCert_GetEncoding(certOpt);
	berSize = ber->size;
    } else {
	berSize = 0;
    }
    nicknameLen = nicknameOpt ? nssUTF8_Length(nicknameOpt, NULL) : 0;

    payload.size = PAYLOAD_HEADER_LENGTH +
                    TRUST_RECORD_LENGTH  +
                    4 + berSize          +
                    4 + nicknameLen;

    payload.data = nss_ZAlloc(arena, payload.size);
    if (!payload.data) {
	return PR_FAILURE;
    }

    /* HEADER */
    i = 0;
    SET_DBT_BYTE(&payload, i, PKIDB_VERSION);       i++;
    SET_DBT_BYTE(&payload, i, PAYLOAD_CERT_HEADER); i++;
    SET_DBT_BYTE(&payload, i, 0);                   i++; /* flags */
    /* TRUST */
    if (trustOpt) {
	SET_DBT_INT(&payload, i, trustOpt->trustedUsages.ca);      i += 4;
	SET_DBT_INT(&payload, i, trustOpt->trustedUsages.peer);    i += 4;
	SET_DBT_INT(&payload, i, trustOpt->notTrustedUsages.ca);   i += 4;
	SET_DBT_INT(&payload, i, trustOpt->notTrustedUsages.peer); i += 4;
    } else {
	i += TRUST_RECORD_LENGTH; /* skip it */
    }
    /* BER size */
    size = PR_htonl(berSize);
    SET_DBT_INT(&payload, i, size); i += 4;
    /* nickname length */
    size = PR_htonl(nicknameLen);
    SET_DBT_INT(&payload, i, size); i += 4;
    /* BER data */
    if (certOpt) {
	SET_DBT_ITEM(&payload, i, ber); i += berSize;
    }
    /* nickname */
    if (nicknameOpt) {
	SET_DBT_BUF(&payload, i, nicknameOpt, nicknameLen); i += nicknameLen;
    }
    /* always overwrite? */
    return write_record(pkidb, rowID, &payload);
}

static PRStatus
decode_cert_payload(DBT *payload, NSSBER *ber, NSSItem *nick,
                    nssTrust *trustOpt)
{
    int i;
    PRUint32 size;

    i = PAYLOAD_HEADER_LENGTH; /* skip the header */
    if (trustOpt) {
	GET_DBT_INT(payload, i, trustOpt->trustedUsages.ca);      i += 4;
	GET_DBT_INT(payload, i, trustOpt->trustedUsages.peer);    i += 4;
	GET_DBT_INT(payload, i, trustOpt->notTrustedUsages.ca);   i += 4;
	GET_DBT_INT(payload, i, trustOpt->notTrustedUsages.peer); i += 4;
    } else {
	i += TRUST_RECORD_LENGTH; /* skip it */
    }
    GET_DBT_INT(payload, i, size); i += 4;
    ber->size = PR_ntohl(size);
    GET_DBT_INT(payload, i, size); i += 4;
    nick->size = PR_ntohl(size);
    if (ber->size > 0) {
	GET_DBT_BUF(payload, i, ber->data); i += ber->size;
    }
    if (nick->size > 0) {
	GET_DBT_BUF(payload, i, nick->data); i += nick->size;
    }
    return PR_SUCCESS;
}

static PRStatus
make_subject_rowid(DBT *rowID, NSSBER *subject, NSSArena *arenaOpt)
{
    int i;
    rowID->size = 1 + subject->size;
    rowID->data = nss_ZAlloc(arenaOpt, rowID->size);
    if (!rowID->data) {
	return PR_FAILURE;
    }
    i = 0;
    SET_DBT_BYTE(rowID, 0, ROWID_SUBJECT_HEADER); i++;
    SET_DBT_ITEM(rowID, i, subject);              i += subject->size;
    return PR_SUCCESS;
}

static PRStatus
write_subject_record(nssPKIDatabase *pkidb, DBT *rowID, 
                     NSSCert *cert, NSSArena *arena)
{
    DBT certRowID, payload, oldPayload;
    int dberr;
    PRUint32 size;
    PRBool haveRecord;
    int i, j, numCerts, numOldCerts;

    PZ_Lock(pkidb->lock);
    dberr = pkidb->db->get(pkidb->db, rowID, &payload, 0);
    PZ_Unlock(pkidb->lock);
    if (dberr < 0) {
	return PR_FAILURE;
    }
    haveRecord = (dberr == 0) ? PR_TRUE : PR_FALSE;

    /* XXX redundant */
    make_cert_rowid(&certRowID, cert, arena);
    if (haveRecord) {
	payload.size = 4 + certRowID.size + oldPayload.size;
    } else {
	payload.size = PAYLOAD_HEADER_LENGTH +
	                4                    +
	                4 + certRowID.size;
    }

    payload.data = nss_ZAlloc(arena, payload.size);
    if (!payload.data) {
	nss_ZFreeIf(certRowID.data);
	return PR_FAILURE;
    }

    /* HEADER */
    i = 0;
    SET_DBT_BYTE(&payload, i, PKIDB_VERSION);          i++;
    SET_DBT_BYTE(&payload, i, PAYLOAD_SUBJECT_HEADER); i++;
    SET_DBT_BYTE(&payload, i, 0);                      i++; /* flags */
    /* # of cert rowIDs */
    if (haveRecord) {
	GET_DBT_INT(&payload, i, numOldCerts); j += 4;
    } else {
	numOldCerts = 0;
    }
    numCerts = PR_htonl(numOldCerts + 1);
    SET_DBT_INT(&payload, i, numCerts); i += 4;
    /* lengths of cert rowIDs */
    if (haveRecord) {
	unsigned char *oldLengths;
	GET_DBT_BUF(&oldPayload, i, oldLengths);
	SET_DBT_BUF(&payload, i, oldLengths,  4 * numOldCerts);
	i += 4 * numOldCerts;
    }
    size = PR_htonl(certRowID.size);
    SET_DBT_INT(&payload, i, size); i += 4;
    /* cert rowIDs */
    if (haveRecord) {
	unsigned char *oldCertRowIDs;
	int j = i - 4; /* -4 because we added one length */
	int remaining = oldPayload.size - j;
	GET_DBT_BUF(&oldPayload, j, oldCertRowIDs);
	SET_DBT_BUF(&payload, i, oldCertRowIDs, remaining);
	i += remaining;
    }
    SET_DBT_ITEM(&payload, i, &certRowID); i += certRowID.size;
    nss_ZFreeIf(certRowID.data);
    return write_record(pkidb, rowID, &payload);
}

static NSSCert *
get_cert_from_rowid(nssPKIDatabase *pkidb, DBT *rowID)
{
    DBT payload;
    int dberr;
    PRStatus status;
    NSSBER ber, nick;
    nssTrust trust;
    NSSCert *cert = NULL;

    PZ_Lock(pkidb->lock);
    dberr = pkidb->db->get(pkidb->db, rowID, &payload, 0);
    PZ_Unlock(pkidb->lock);

    if (dberr == 0) {
	status = decode_cert_payload(&payload, &ber, &nick, &trust);
	if (status == PR_SUCCESS) {
	    cert = nssCert_Decode(&ber, &nick, &trust, pkidb->td, NULL);
	}
    }
    return cert;
}

static PRUint32
get_num_certs_from_subject_payload(DBT *payload)
{
    PRUint32 numCerts;
    GET_DBT_INT(payload, PAYLOAD_HEADER_LENGTH, numCerts);
    numCerts = PR_ntohl(numCerts);
    return numCerts;
}

static PRStatus
get_cert_rowid_from_subject_payload(DBT *payload, int i, int *last, 
                                    int numCerts, DBT *rowID)
{
    int offset = PAYLOAD_HEADER_LENGTH + 4 + 4 * i;
    GET_DBT_INT(payload, offset, rowID->size);
    rowID->size = PR_ntohl(rowID->size);
    if (*last == 0) {
	offset = PAYLOAD_HEADER_LENGTH + 4 + 4 * numCerts;
    } else {
	offset = *last;
    }
    GET_DBT_BUF(payload, offset, rowID->data);
    *last += rowID->size;
    return PR_SUCCESS;
}

static NSSCert **
get_certs_from_subject_record(nssPKIDatabase *pkidb, DBT *subjectRowID, 
                              NSSArena *arenaOpt)
{
    DBT payload, certRowID;
    int dberr;
    PRStatus status;
    NSSCert **certs = NULL;
    int i, last = 0;
    int numCerts;

    PZ_Lock(pkidb->lock);
    dberr = pkidb->db->get(pkidb->db, subjectRowID, &payload, 0);
    PZ_Unlock(pkidb->lock);

    if (dberr == 0) {
	numCerts = get_num_certs_from_subject_payload(&payload);
	if (numCerts == 0) {
	    return (NSSCert **)NULL;
	}
	certs = nss_ZNEWARRAY(arenaOpt, NSSCert *, numCerts + 1);
	if (!certs) {
	    return (NSSCert **)NULL;
	}
	for (i = 0; i < numCerts; i++) {
	    status = get_cert_rowid_from_subject_payload(&payload, i, 
	                                                 &last, numCerts,
	                                                 &certRowID);
	    if (status == PR_SUCCESS) {
		certs[i] = get_cert_from_rowid(pkidb, &certRowID);
		if (!certs[i]) {
		    break;
		}
	    } else {
		break;
	    }
	}
    }
    return certs;
}

static PRStatus
make_nickname_rowid(DBT *rowID, NSSUTF8 *nickname, NSSArena *arenaOpt)
{
    int i;
    PRUint32 nickLen = nssUTF8_Length(nickname, NULL);
    rowID->size = 1 + nickLen;
    rowID->data = nss_ZAlloc(arenaOpt, rowID->size);
    if (!rowID->data) {
	return PR_FAILURE;
    }
    i = 0;
    SET_DBT_BYTE(rowID, 0, ROWID_NICKNAME_HEADER); i++;
    SET_DBT_BUF( rowID, i, nickname, nickLen);     i += nickLen;
    return PR_SUCCESS;
}

static PRStatus
write_nickname_record(nssPKIDatabase *pkidb, DBT *rowID, NSSCert *cert, 
                      NSSArena *arena)
{
    DBT payload;
    DBT subjectRowID;
    PRStatus status;
    NSSBER *berSubject;
    PRUint32 size;
    int i;

    berSubject = nssCert_GetSubject(cert);
    status = make_subject_rowid(&subjectRowID, berSubject, arena);
    if (status == PR_FAILURE) {
	return status;
    }

    payload.size = PAYLOAD_HEADER_LENGTH + 4 + 1 + berSubject->size;

    payload.data = nss_ZAlloc(arena, payload.size);
    if (!payload.data) {
	return PR_FAILURE;
    }

    /* HEADER */
    i = 0;
    SET_DBT_BYTE(&payload, i, PKIDB_VERSION);           i++;
    SET_DBT_BYTE(&payload, i, PAYLOAD_NICKNAME_HEADER); i++;
    SET_DBT_BYTE(&payload, i, 0);                       i++; /* flags */
    /* BER subject size */
    size = PR_htonl(subjectRowID.size);
    SET_DBT_INT(&payload, i, size); i += 4;
    /* BER subject data */
    SET_DBT_ITEM(&payload, i, &subjectRowID); i += subjectRowID.size;
    /* always overwrite? */
    return write_record(pkidb, rowID, &payload);
}

static NSSCert **
get_certs_from_nickname_record(nssPKIDatabase *pkidb, DBT *rowID, 
                               NSSArena *arenaOpt)
{
    DBT payload;
    DBT subjectRowID;
    int dberr;

    PZ_Lock(pkidb->lock);
    dberr = pkidb->db->get(pkidb->db, rowID, &payload, 0);
    PZ_Unlock(pkidb->lock);

    if (dberr == 0) {
	int i = 0;
	i += PAYLOAD_HEADER_LENGTH;
	GET_DBT_INT(&payload, i, subjectRowID.size); i += 4;
	subjectRowID.size = PR_ntohl(subjectRowID.size);
	GET_DBT_BUF(&payload, i, subjectRowID.data); i += subjectRowID.size;
	return get_certs_from_subject_record(pkidb, &subjectRowID, arenaOpt);
    }
    return (NSSCert **)NULL;
}

/* XXX needs nickname fixes above */
static PRStatus
make_email_rowid(DBT *rowID, NSSASCII7 *email, NSSArena *arenaOpt)
{
    int i;
    PRUint32 emailLen = nssUTF8_Length(email, NULL);
    rowID->size = 1 + emailLen;
    rowID->data = nss_ZAlloc(arenaOpt, rowID->size);
    if (!rowID->data) {
	return PR_FAILURE;
    }
    i = 0;
    SET_DBT_BYTE(rowID, 0, ROWID_EMAIL_HEADER); i++;
    SET_DBT_BUF( rowID, i, email, emailLen);    i += emailLen;
    return PR_SUCCESS;
}

static NSSCert **
get_certs_from_email_record(nssPKIDatabase *pkidb, DBT *rowID, 
                            NSSArena *arenaOpt)
{
    DBT payload;
    int dberr;

    PZ_Lock(pkidb->lock);
    dberr = pkidb->db->get(pkidb->db, rowID, &payload, 0);
    PZ_Unlock(pkidb->lock);

    if (dberr == 0) {
	return get_certs_from_subject_record(pkidb, &payload, arenaOpt);
    }
    return (NSSCert **)NULL;
}

#define DB_RDONLY O_RDONLY
#define DB_RDWR   O_RDWR
#define DB_CREATE O_CREAT
#define PKIDB_FLAGS_READ_ONLY 1

NSS_IMPLEMENT nssPKIDatabase *
nssPKIDatabase_Open (
  NSSTrustDomain *td,
  const NSSUTF8 *path,
  PRUint32 flags
)
{
    nssPKIDatabase *rvDB;
    PRIntn dbFlags;
    const char *dbName = "certX.db"; /* XXX */
    char *filename;
    PRUint32 pathLen, dbNameLen;

    pathLen = nssUTF8_Length(path, NULL);
    dbNameLen = nssUTF8_Length(dbName, NULL); 
    filename = nss_ZAlloc(NULL, pathLen + dbNameLen + 2);
    if (!filename) {
	return (nssPKIDatabase *)NULL;
    }
    nsslibc_memcpy(filename, path, pathLen);
    filename[pathLen] = '/';
    nsslibc_memcpy(filename + pathLen + 1, dbName, dbNameLen);
    filename[pathLen + 1 + dbNameLen] = '\0';

    rvDB = nss_ZNEW(NULL, nssPKIDatabase);
    if (!rvDB) {
	nssUTF8_Destroy(filename);
	return (nssPKIDatabase *)NULL;
    }

    rvDB->lock = PZ_NewLock(nssILockOther);
    if (!rvDB) {
	nssUTF8_Destroy(filename);
	nss_ZFreeIf(rvDB);
	return (nssPKIDatabase *)NULL;
    }

    dbFlags = (flags & PKIDB_FLAGS_READ_ONLY) ? DB_RDONLY : DB_RDWR;
    dbFlags |= DB_CREATE; /* always? */

    rvDB->db = dbopen(filename, dbFlags, 0600, DB_HASH, &s_db_hash_info);
    if (!rvDB->db) {
	nssUTF8_Destroy(filename);
	PZ_DestroyLock(rvDB->lock);
	nss_ZFreeIf(rvDB);
	return (nssPKIDatabase *)NULL;
    }
    rvDB->td = td;
    return rvDB;
}

NSS_IMPLEMENT PRStatus
nssPKIDatabase_Close (
  nssPKIDatabase *pkidb
)
{
    pkidb->db->close(pkidb->db);
    PZ_DestroyLock(pkidb->lock);
    nss_ZFreeIf(pkidb);
    return PR_SUCCESS;
}

NSS_IMPLEMENT PRStatus
nssPKIDatabase_ImportCert (
  nssPKIDatabase *pkidb,
  NSSCert *cert,
  NSSUTF8 *nicknameOpt,
  nssTrust *trustOpt
)
{
    DBT rowID;
    PRStatus status;
    NSSArena *tmparena;
    NSSBER *subject;
    NSSUTF8 *nickname;

    tmparena = nssArena_Create();
    if (!tmparena) {
	return PR_FAILURE;
    }

    status = make_cert_rowid(&rowID, cert, tmparena);
    if (status == PR_FAILURE) {
	goto cleanup;
    }
    status = write_cert_record(pkidb, &rowID, cert, 
                               nicknameOpt, trustOpt, tmparena);
    if (status == PR_FAILURE) {
	goto cleanup;
    }

    subject = nssCert_GetSubject(cert);
    status = make_subject_rowid(&rowID, subject, tmparena);
    if (status == PR_FAILURE) {
	goto cleanup;
    }
    status = write_subject_record(pkidb, &rowID, cert, tmparena);
    if (status == PR_FAILURE) {
	goto cleanup;
    }

    nickname = nicknameOpt ? nicknameOpt : nssCert_GetNickname(cert, NULL);
    if (nickname) {
	status = make_nickname_rowid(&rowID, nickname, tmparena);
	if (status == PR_FAILURE) {
	    goto cleanup;
	}
	status = write_nickname_record(pkidb, &rowID, cert, tmparena);
	if (status == PR_FAILURE) {
	    goto cleanup;
	}
    }

cleanup:
    nssArena_Destroy(tmparena);
    return status;
}

NSS_IMPLEMENT PRStatus
nssPKIDatabase_DeleteCert (
  nssPKIDatabase *pkidb,
  NSSCert *cert
)
{
    DBT rowID;
    PRStatus status;

    status = make_cert_rowid(&rowID, cert, NULL);
    if (status == PR_FAILURE) {
	return PR_FAILURE;
    }

    status = delete_record(pkidb, &rowID);

    nss_ZFreeIf(rowID.data);
    return status;
}

NSS_IMPLEMENT PRStatus
nssPKIDatabase_SetCertTrust (
  nssPKIDatabase *pkidb,
  NSSCert *cert,
  nssTrust *trust
)
{
    DBT rowID, payload;
    int dberr;
    PRStatus status;
    NSSArena *tmparena;

    tmparena = nssArena_Create();
    if (!tmparena) {
	return PR_FAILURE;
    }

    status = make_cert_rowid(&rowID, cert, tmparena);
    if (status == PR_FAILURE) {
	nssArena_Destroy(tmparena);
	return PR_FAILURE;
    }

    /* look up the cert record */
    PZ_Lock(pkidb->lock);
    dberr = pkidb->db->get(pkidb->db, &rowID, &payload, 0);
    PZ_Unlock(pkidb->lock);

    if (dberr == 0) {
	/* cert already present, set the new trust value */
	PRUint32 i = CERT_PAYLOAD_TRUST_OFFSET;
	DBT tmp;
	/* XXX apparently, I must copy the dbt before writing.  how lame. */
	tmp.data = nss_ZAlloc(NULL, payload.size);
	nsslibc_memcpy(tmp.data, payload.data, payload.size);
	tmp.size = payload.size;
	payload = tmp;
	SET_DBT_INT(&payload, i, trust->trustedUsages.ca);      i += 4;
	SET_DBT_INT(&payload, i, trust->trustedUsages.peer);    i += 4;
	SET_DBT_INT(&payload, i, trust->notTrustedUsages.ca);   i += 4;
	SET_DBT_INT(&payload, i, trust->notTrustedUsages.peer); i += 4;
        status = write_record(pkidb, &rowID, &payload);
	nss_ZFreeIf(tmp.data);
    } else if (dberr == 1) {
	/* cert is not present, create a new record */
	NSSUTF8 *nickname = nssCert_GetNickname(cert, NULL);
	status = write_cert_record(pkidb, &rowID, cert, 
	                           nickname, trust, tmparena);
    } else {
	/* db failed */
	status = PR_FAILURE;
    }
    nssArena_Destroy(tmparena);
    return status;
}

/*
NSS_IMPLEMENT PRStatus
nssPKIDatabase_DeleteCertTrust (
  nssPKIDatabase *pkidb,
  NSSCert *cert
)
{
}
*/

NSS_IMPLEMENT NSSCert **
nssPKIDatabase_FindCertsBySubject (
  nssPKIDatabase *pkidb,
  NSSBER *subject,
  NSSCert **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    DBT rowID;
    PRStatus status;
    NSSCert **certs;

    status = make_subject_rowid(&rowID, subject, NULL);
    if (status == PR_SUCCESS) {
	certs = get_certs_from_subject_record(pkidb, &rowID, arenaOpt);
	nss_ZFreeIf(rowID.data);
    }
    return certs;
}

NSS_IMPLEMENT NSSCert **
nssPKIDatabase_FindCertsByNickname (
  nssPKIDatabase *pkidb,
  NSSUTF8 *nickname,
  NSSCert **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    DBT rowID;
    PRStatus status;
    NSSCert **certs;

    status = make_nickname_rowid(&rowID, nickname, NULL);
    if (status == PR_SUCCESS) {
	certs = get_certs_from_nickname_record(pkidb, &rowID, arenaOpt);
	nss_ZFreeIf(rowID.data);
    }
    return certs;
}

NSS_IMPLEMENT NSSCert **
nssPKIDatabase_FindCertsByEmail (
  nssPKIDatabase *pkidb,
  NSSASCII7 *email,
  NSSCert **rvOpt,
  PRUint32 maximumOpt,
  NSSArena *arenaOpt
)
{
    DBT rowID;
    PRStatus status;
    NSSCert **certs;

    status = make_email_rowid(&rowID, email, NULL);
    if (status == PR_SUCCESS) {
	certs = get_certs_from_email_record(pkidb, &rowID, arenaOpt);
	nss_ZFreeIf(rowID.data);
    }
    return certs;
}

NSS_IMPLEMENT NSSCert *
nssPKIDatabase_FindCertByIssuerAndSerialNumber (
  nssPKIDatabase *pkidb,
  NSSBER *issuer,
  NSSBER *serial
)
{
    DBT rowID;
    PRStatus status;
    NSSCert *cert = NULL;

    status = make_cert_rowid_from_issuer_serial(&rowID, issuer, serial, NULL);
    if (status == PR_SUCCESS) {
	cert = get_cert_from_rowid(pkidb, &rowID);
	nss_ZFreeIf(rowID.data);
    }
    return cert;
}

/* d'oh! */
struct match_encoded_cert_str { NSSCert *cert; NSSBER *ber; };

static PRStatus match_encoded_cert(NSSCert *cert, void *arg)
{
    struct match_encoded_cert_str *me = (struct match_encoded_cert_str *)arg;
    NSSBER *certBER = nssCert_GetEncoding(cert);
    if (nssItem_Equal(me->ber, certBER, NULL)) {
	me->cert = nssCert_AddRef(cert);
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSCert *
nssPKIDatabase_FindCertByEncodedCert (
  nssPKIDatabase *pkidb,
  NSSBER *ber
)
{
    struct match_encoded_cert_str me;
    me.cert = NULL;
    me.ber = ber;
    nssPKIDatabase_TraverseCerts(pkidb, match_encoded_cert, &me);
    return me.cert;
}

NSS_IMPLEMENT PRStatus
nssPKIDatabase_FindTrustForCert (
  nssPKIDatabase *pkidb,
  NSSCert *cert,
  nssTrust *rvTrust
)
{
    DBT rowID, payload;
    int dberr;
    PRStatus status;

    status = make_cert_rowid(&rowID, cert, NULL);
    if (status == PR_FAILURE) {
	return PR_FAILURE;
    }

    /* look up the cert record */
    PZ_Lock(pkidb->lock);
    dberr = pkidb->db->get(pkidb->db, &rowID, &payload, 0);
    PZ_Unlock(pkidb->lock);

    if (dberr == 0) {
	/* cert already present, set the new trust value */
	PRUint32 i = CERT_PAYLOAD_TRUST_OFFSET;
	GET_DBT_INT(&payload, i, rvTrust->trustedUsages.ca);      i += 4;
	GET_DBT_INT(&payload, i, rvTrust->trustedUsages.peer);    i += 4;
	GET_DBT_INT(&payload, i, rvTrust->notTrustedUsages.ca);   i += 4;
	GET_DBT_INT(&payload, i, rvTrust->notTrustedUsages.peer); i += 4;
	status = PR_SUCCESS;
    } else {
	nsslibc_memset(rvTrust, 0, sizeof(*rvTrust));
	status = PR_FAILURE;
    }
    nss_ZFreeIf(rowID.data);
    return status;
}

NSS_IMPLEMENT PRStatus
nssPKIDatabase_TraverseCerts (
  nssPKIDatabase *pkidb,
  PRStatus (*callback)(NSSCert *c, void *arg),
  void *arg
)
{
    DBT rowID, payload;
    int dberr;
    PRStatus status = PR_SUCCESS;
    NSSBER ber, nick;
    nssTrust trust;
    NSSCert *cert;

    PZ_Lock(pkidb->lock);
    dberr = pkidb->db->seq(pkidb->db, &rowID, &payload, R_FIRST);
    while (dberr == 0) {
	if (PKIDB_IS_CERT_RECORD(&rowID)) {
	    status = decode_cert_payload(&payload, &ber, &nick, &trust);
	    if (status == PR_SUCCESS) {
		cert = nssCert_Decode(&ber, &nick, &trust, pkidb->td, NULL);
		if (cert) {
		    status = (*callback)(cert, arg);
		    if (status == PR_FAILURE) {
			break; /* allow for early termination */
		    }
		} /* else ? */
	    } /* else ? */
	}
	dberr = pkidb->db->seq(pkidb->db, &rowID, &payload, R_NEXT);
    }
    PZ_Unlock(pkidb->lock);

    return status;
}

