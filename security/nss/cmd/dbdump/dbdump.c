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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mcom_db.h"

int verbose = 0;
const char *blobstr = "Blob entry stored as a file";
const char *dbVersionStr[3] = { "v7", "v8-", "v8" };
enum { version7 = 0, version8minus = 1, version8 = 2 };
int dbVersion = 0;

/* database entry types */
enum {
    Version = 0,
    Cert = 1,
    Nickname = 2,
    Subject = 3,
    Revocation = 4,
    KeyRevocation = 5,
    SMimeProfile = 6,
    ContentVersion = 7,
    Blob = 8
};

typedef struct ItemStr {
    unsigned char *data;
    int size;
} Item;    

typedef struct VersionEntryStr {
    int version;
    int isBlob;
} VersionEntry;

typedef struct CertEntryStr {
    Item issuerAndSN; /* from rowID */
    unsigned char trust[6]; /* from payload ... */
    char *nickname;
    Item derCert;
    int isBlob;
} CertEntry;

typedef struct NicknameEntryStr {
    char *nickname; /* from rowID */
    Item derSubject; /* from payload */ 
    int isBlob;
} NicknameEntry;

typedef struct SubjectEntryStr {
    Item derSubject; /* from rowID */
    int numCerts; /* from payload ... */
    char *nickname;
    char *email;
    Item *certIDs;
    Item *keyIDs;
    char **v8emails;
    int numV8emails;
    int isBlob;
} SubjectEntry;

typedef struct CRLEntryStr {
    Item issuerDN; /* from rowID */
    char *url; /* from payload */
    Item derCRL;
    int isBlob;
} CRLEntry;

typedef struct SMimeEntryStr {
    char *email; /* from rowID */
    Item derSubject; /* from payload... */
    Item options;
    Item timestamp;
    int isBlob;
} SMimeEntry;

#define BYTE(dbt, off) (((unsigned char *)(dbt)->data)[off])
#define SHORT(dbt, off) (int)((BYTE(dbt, off) << 8) | BYTE(dbt, off+1))
#define STRING(dbt, off) (&((char *)(dbt)->data)[off])

#define STR(s) (s) ? (s) : "<NONE>"

#define GRABIT(it, dbt, off, num) \
  (it)->data = &((unsigned char *)(dbt)->data)[off]; \
  (it)->size = num;

#define GRABSTR(str, dbt, off) \
  str = &((char *)(dbt)->data)[off]; \
  if (strlen(str) == 0) str = NULL;

void print_bytes(unsigned char *buf, int len)
{
    int i;
    int mylen;
    if (len == 0) { printf("<NONE>\n"); return; }
    mylen = (verbose <= 1 && len > 10) ? 10 : len;
    for (i=0; i<mylen; ++i) {
	printf("%02X", buf[i]);
    }
    if (verbose <= 1 && len > 10) printf("...");
    printf("\n");
}

void print_it(Item *it)
{
    print_bytes(it->data, it->size);
}

void print_header(const char *typestr)
{
    printf("<<<<<<%s>>>>>>\n", typestr);
}

void print_version(VersionEntry *ent)
{
    print_header("Version");
    printf("Version = %d\n", ent->version);
    printf("\n");
}

void print_cert(CertEntry *ent)
{
    Item tmp;
    print_header("Cert");
    printf("Cert Issuer/SN: ");
    print_it(&ent->issuerAndSN);
    if (ent->isBlob) {
	printf("%s\n", blobstr);
	return;
    }
    printf("Trust: ");
    tmp.data = ent->trust; tmp.size = 6;
    print_it(&tmp);
    printf("Cert: ");
    print_it(&ent->derCert);
    printf("Nickname: %s\n", STR(ent->nickname));
    printf("\n");
}

void print_nickname(NicknameEntry *ent)
{
    print_header("Nickname");
    printf("Nickname: %s\n", STR(ent->nickname));
    if (ent->isBlob) {
	printf("%s\n", blobstr);
	return;
    }
    printf("Subject: ");
    print_it(&ent->derSubject);
    printf("\n");
}

void print_subject(SubjectEntry *ent)
{
    int i;
    print_header("Subject");
    printf("Subject: ");
    print_it(&ent->derSubject);
    if (ent->isBlob) {
	printf("%s\n", blobstr);
	return;
    }
    printf("Number of certs: %d\n", ent->numCerts);
    printf("Nickname: %s\n", STR(ent->nickname));
    printf("Email: %s\n", STR(ent->email));
    for (i=0; i<ent->numCerts; i++) {
	printf("Cert%d [%d]: ", i, ent->certIDs[i].size);
	print_it(&ent->certIDs[i]);
	printf("Key%d [%d]: ", i, ent->keyIDs[i].size);
	print_it(&ent->keyIDs[i]);
    }
    for (i=0; i<ent->numV8emails; i++) {
	printf("Email%d: %s\n", i, STR(ent->v8emails[i]));
    }
    printf("\n");
}

void print_crl(CRLEntry *ent)
{
    print_header("CRL");
    printf("CRL Issuer: ");
    print_it(&ent->issuerDN);
    if (ent->isBlob) {
	printf("%s\n", blobstr);
	return;
    }
    printf("CRL[%d]: ", ent->derCRL.size);
    print_it(&ent->derCRL);
    printf("URL: %s\n", STR(ent->url));
    printf("\n");
}

void print_krl(DBT *rowID, DBT *payload)
{
    printf("KRL\n");
    printf("\n");
}

void print_smprofile(SMimeEntry *ent)
{
    print_header("S/MIME Profile");
    printf("Email = %s\n", ent->email);
    if (ent->isBlob) {
	printf("%s\n", blobstr);
	return;
    }
    printf("\n");
}

void print_contentversion(DBT *rowID, DBT *payload)
{
    printf("Content Version = %d\n", BYTE(payload, 3));
    printf("\n");
}

int is_blob(DBT *payload)
{
    return (BYTE(payload, 1) == Blob);
}

void do_version(DBT *rowID, DBT *payload)
{
    VersionEntry ent;
    ent.version = BYTE(payload, 0);
    if (ent.version == 7) dbVersion = version7;
    else dbVersion = version8minus;
    if (verbose > 0) print_version(&ent);
}

void do_cert(DBT *rowID, DBT *payload)
{
    CertEntry ent;
    int len, nlen;
    ent.isBlob = is_blob(payload);
    if (ent.isBlob) goto finish;
    GRABIT(&ent.issuerAndSN, rowID, 1, rowID->size - 1);
    memcpy(ent.trust, &BYTE(payload, 3), 6);
    len = SHORT(payload, 9);
    nlen = SHORT(payload, 11);
    GRABIT(&ent.derCert, payload, 13, len);
    GRABSTR(ent.nickname, payload, len + 13);
finish:
    if (verbose > 0) print_cert(&ent);
}

void do_nickname(DBT *rowID, DBT *payload)
{
    NicknameEntry ent;
    ent.isBlob = is_blob(payload);
    if (ent.isBlob) goto finish;
    GRABSTR(ent.nickname, rowID, 1);
    GRABIT(&ent.derSubject, payload, 5, payload->size - 5);
finish:
    if (verbose > 0) print_nickname(&ent);
}

void do_subject(DBT *rowID, DBT *payload)
{
    SubjectEntry ent;
    int i;
    int off, certoff, keyoff, tmpoff;
    int len, nlen, elen;
    ent.isBlob = is_blob(payload);
    if (ent.isBlob) goto finish;
    off = 3; /* past header */
    ent.numCerts = SHORT(payload, off);
    ent.certIDs = (Item *)malloc(ent.numCerts * sizeof(Item));
    ent.keyIDs = (Item *)malloc(ent.numCerts * sizeof(Item));
    off += 2;
    nlen = SHORT(payload, off);
    off += 2;
    elen = SHORT(payload, off);
    off += 2;
    GRABSTR(ent.nickname, payload, off);
    off += nlen;
    GRABSTR(ent.email, payload, off);
    off += elen;
    certoff = off + 4*ent.numCerts;
    keyoff = certoff;
    tmpoff = off;
    for (i=0; i<ent.numCerts; i++) {
	keyoff += SHORT(payload, tmpoff);
	tmpoff += 2;
    }
    for (i=0; i<ent.numCerts; i++) {
	len = SHORT(payload, off);
	GRABIT(&ent.certIDs[i], payload, certoff, len);
	certoff += len;
	len = SHORT(payload, off + 2*ent.numCerts);
	GRABIT(&ent.keyIDs[i], payload, keyoff, len);
	keyoff += len;
	off += 2;
    }
    ent.v8emails = NULL;
    ent.numV8emails = 0;
    if (keyoff < payload->size) {
	dbVersion = version8; /* only 3.7+ v8 db's do this */
	off = keyoff;
	i = 0;
	ent.numV8emails = SHORT(payload, off);
	off += 2;
	ent.v8emails = (char **)malloc(ent.numV8emails*sizeof(char *));
	while (off < payload->size) {
	    len = SHORT(payload, off);
	    off += 2;
	    GRABSTR(ent.v8emails[i], payload, off);
	    off += len;
	    ++i;
	}
    }
finish:
    if (verbose > 0) print_subject(&ent);
}

void do_crl(DBT *rowID, DBT *payload)
{
    CRLEntry ent;
    int len, ulen;
    ent.isBlob = is_blob(payload);
    if (ent.isBlob) goto finish;
    GRABIT(&ent.issuerDN, rowID, 1, rowID->size - 1);
    len = SHORT(payload, 3);
    ulen = SHORT(payload, 5);
    GRABIT(&ent.derCRL, payload, 7, len);
    GRABSTR(ent.url, payload, len + 7);
finish:
    if (verbose > 0) print_crl(&ent);
}

void do_krl(DBT *rowID, DBT *payload)
{
    printf("KRL\n");
}

void do_smprofile(DBT *rowID, DBT *payload)
{
    SMimeEntry ent;
    ent.isBlob = is_blob(payload);
    if (ent.isBlob) goto finish;
    GRABSTR(ent.email, rowID, 1);
finish:
    if (verbose > 0) print_smprofile(&ent);
}

void do_contentversion(DBT *rowID, DBT *payload)
{
    printf("Content Version = %d\n", BYTE(payload, 3));
}

static void Usage(const char *progName)
{
    printf("Usage:  %s [-v [-v [...]]] <cert.db>\n", progName);
    exit(1);
}

int main(int argc, char **argv)
{
    DB *db;
    DBT rowID, payload;
    int ret;
    int i;

    for (i=1; i<argc-1; i++) {
	if (strcmp(argv[i], "-v") == 0) {
	    verbose++;
	} else Usage(argv[0]);
    }
    if (i >= argc) Usage(argv[0]);

    db = dbopen(argv[i], O_RDONLY, 0600, DB_HASH, 0 );
    if (!db) {
	fprintf(stderr, "Failed to open %s [%d]\n", argv[1], errno);
	return 1;
    }
    ret = (*db->seq)(db, &rowID, &payload, R_FIRST);
    if (ret) {
	fprintf(stderr, "Failed to read [%d]\n", errno);
	return 1;
    }
    do {
	switch (BYTE(&rowID, 0)) {
	case Version:        do_version(&rowID, &payload);   break;
	case Cert:           do_cert(&rowID, &payload);      break;
	case Nickname:       do_nickname(&rowID, &payload);  break;
	case Subject:        do_subject(&rowID, &payload);   break;
	case Revocation:     do_crl(&rowID, &payload);       break;
	case KeyRevocation:  do_krl(&rowID, &payload);       break;
	case SMimeProfile:   do_smprofile(&rowID, &payload); break;
	case ContentVersion: do_contentversion(&rowID, &payload); break;
	default:
	    printf("Unknown record type %d\n", BYTE(&rowID, 0));
	}
    } while ( (*db->seq)(db, &rowID, &payload, R_NEXT) == 0 );

    printf("Database Version Compatibility: %s\n", dbVersionStr[dbVersion]);

    return 0;
}

