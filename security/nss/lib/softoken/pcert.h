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

#ifndef _PCERTDB_H_
#define _PCERTDB_H_

#include "plarena.h"
#include "prlong.h"
#include "pcertt.h"
/*
 * Certificate Database related definitions and data structures
 */

/* version number of certificate database */
#define CERT_DB_FILE_VERSION		7
#ifdef USE_NS_ROOTS
#define CERT_DB_CONTENT_VERSION		28
#else
#define CERT_DB_CONTENT_VERSION		2
#endif

#define SEC_DB_ENTRY_HEADER_LEN		3
#define SEC_DB_KEY_HEADER_LEN		1

/* All database entries have this form:
 * 	
 *	byte offset	field
 *	-----------	-----
 *	0		version
 *	1		type
 *	2		flags
 */

/* database entry types */
typedef enum {
    certDBEntryTypeVersion = 0,
    certDBEntryTypeCert = 1,
    certDBEntryTypeNickname = 2,
    certDBEntryTypeSubject = 3,
    certDBEntryTypeRevocation = 4,
    certDBEntryTypeKeyRevocation = 5,
    certDBEntryTypeSMimeProfile = 6,
    certDBEntryTypeContentVersion = 7
} certDBEntryType;

typedef struct {
    certDBEntryType type;
    unsigned int version;
    unsigned int flags;
    PRArenaPool *arena;
} certDBEntryCommon;

/*
 * Certificate entry:
 *
 *	byte offset	field
 *	-----------	-----
 *	0		sslFlags-msb
 *	1		sslFlags-lsb
 *	2		emailFlags-msb
 *	3		emailFlags-lsb
 *	4		objectSigningFlags-msb
 *	5		objectSigningFlags-lsb
 *	6		derCert-len-msb
 *	7		derCert-len-lsb
 *	8		nickname-len-msb
 *	9		nickname-len-lsb
 *	...		derCert
 *	...		nickname
 *
 * NOTE: the nickname string as stored in the database is null terminated,
 *		in other words, the last byte of the db entry is always 0
 *		if a nickname is present.
 * NOTE: if nickname is not present, then nickname-len-msb and
 *		nickname-len-lsb will both be zero.
 */
struct _certDBEntryCert {
    certDBEntryCommon common;
    NSSLOWCERTCertTrust trust;
    SECItem derCert;
    char *nickname;
};

/*
 * Certificate Nickname entry:
 *
 *	byte offset	field
 *	-----------	-----
 *	0		subjectname-len-msb
 *	1	        subjectname-len-lsb
 *	2...		subjectname
 *
 * The database key for this type of entry is a nickname string
 * The "subjectname" value is the DER encoded DN of the identity
 *   that matches this nickname.
 */
typedef struct {
    certDBEntryCommon common;
    char *nickname;
    SECItem subjectName;
} certDBEntryNickname;

#define DB_NICKNAME_ENTRY_HEADER_LEN 2

/*
 * Certificate Subject entry:
 *
 *	byte offset	field
 *	-----------	-----
 *	0		ncerts-msb
 *	1		ncerts-lsb
 *	2		nickname-msb
 *	3		nickname-lsb
 *	4		emailAddr-msb
 *	5		emailAddr-lsb
 *	...		nickname
 *	...		emailAddr
 *	...+2*i		certkey-len-msb
 *	...+1+2*i       certkey-len-lsb
 *	...+2*ncerts+2*i keyid-len-msb
 *	...+1+2*ncerts+2*i keyid-len-lsb
 *	...		certkeys
 *	...		keyids
 *
 * The database key for this type of entry is the DER encoded subject name
 * The "certkey" value is an array of  certificate database lookup keys that
 *   points to the database entries for the certificates that matche
 *   this subject.
 *
 */
typedef struct _certDBEntrySubject {
    certDBEntryCommon common;
    SECItem derSubject;
    unsigned int ncerts;
    char *nickname;
    char *emailAddr;
    SECItem *certKeys;
    SECItem *keyIDs;
} certDBEntrySubject;

#define DB_SUBJECT_ENTRY_HEADER_LEN 6

/*
 * Certificate SMIME profile entry:
 *
 *	byte offset	field
 *	-----------	-----
 *	0		subjectname-len-msb
 *	1	        subjectname-len-lsb
 *	2		smimeoptions-len-msb
 *	3		smimeoptions-len-lsb
 *	4		options-date-len-msb
 *	5		options-date-len-lsb
 *	6...		subjectname
 *	...		smimeoptions
 *	...		options-date
 *
 * The database key for this type of entry is the email address string
 * The "subjectname" value is the DER encoded DN of the identity
 *   that matches this nickname.
 * The "smimeoptions" value is a string that represents the algorithm
 *   capabilities on the remote user.
 * The "options-date" is the date that the smime options value was created.
 *   This is generally the signing time of the signed message that contained
 *   the options.  It is a UTCTime value.
 */
typedef struct {
    certDBEntryCommon common;
    char *emailAddr;
    SECItem subjectName;
    SECItem smimeOptions;
    SECItem optionsDate;
} certDBEntrySMime;

#define DB_SMIME_ENTRY_HEADER_LEN 6

/*
 * Crl/krl entry:
 *
 *	byte offset	field
 *	-----------	-----
 *	0		derCert-len-msb
 *	1		derCert-len-lsb
 *	2		url-len-msb
 *	3		url-len-lsb
 *	...		derCert
 *	...		url
 *
 * NOTE: the url string as stored in the database is null terminated,
 *		in other words, the last byte of the db entry is always 0
 *		if a nickname is present. 
 * NOTE: if url is not present, then url-len-msb and
 *		url-len-lsb will both be zero.
 */
#define DB_CRL_ENTRY_HEADER_LEN	4
struct _certDBEntryRevocation {
    certDBEntryCommon common;
    SECItem	derCrl;
    char	*url;	/* where to load the crl from */
};

/*
 * Database Version Entry:
 *
 *	byte offset	field
 *	-----------	-----
 *	only the low level header...
 *
 * The database key for this type of entry is the string "Version"
 */
typedef struct {
    certDBEntryCommon common;
} certDBEntryVersion;

#define SEC_DB_VERSION_KEY "Version"
#define SEC_DB_VERSION_KEY_LEN sizeof(SEC_DB_VERSION_KEY)

/*
 * Database Content Version Entry:
 *
 *	byte offset	field
 *	-----------	-----
 *	0		contentVersion
 *
 * The database key for this type of entry is the string "ContentVersion"
 */
typedef struct {
    certDBEntryCommon common;
    char contentVersion;
} certDBEntryContentVersion;

#define SEC_DB_CONTENT_VERSION_KEY "ContentVersion"
#define SEC_DB_CONTENT_VERSION_KEY_LEN sizeof(SEC_DB_CONTENT_VERSION_KEY)

typedef union {
    certDBEntryCommon common;
    certDBEntryVersion version;
    certDBEntryCert cert;
    certDBEntryNickname nickname;
    certDBEntrySubject subject;
    certDBEntryRevocation revocation;
} certDBEntry;

/* length of the fixed part of a database entry */
#define DBCERT_V4_HEADER_LEN	7
#define DB_CERT_V5_ENTRY_HEADER_LEN	7
#define DB_CERT_V6_ENTRY_HEADER_LEN	7
#define DB_CERT_ENTRY_HEADER_LEN	10

/* common flags for all types of certificates */
#define CERTDB_VALID_PEER	(1<<0)
#define CERTDB_TRUSTED		(1<<1)
#define CERTDB_SEND_WARN	(1<<2)
#define CERTDB_VALID_CA		(1<<3)
#define CERTDB_TRUSTED_CA	(1<<4) /* trusted for issuing server certs */
#define CERTDB_NS_TRUSTED_CA	(1<<5)
#define CERTDB_USER		(1<<6)
#define CERTDB_TRUSTED_CLIENT_CA (1<<7) /* trusted for issuing client certs */
#define CERTDB_INVISIBLE_CA	(1<<8) /* don't show in UI */
#define CERTDB_GOVT_APPROVED_CA	(1<<9) /* can do strong crypto in export ver */
#define CERTDB_NOT_TRUSTED	(1<<10) /* explicitly don't trust this cert */
#define CERTDB_TRUSTED_UNKNOWN	(1<<11) /* accept trust from another source */

/* bits not affected by the CKO_NETSCAPE_TRUST object */
#define CERTDB_PRESERVE_TRUST_BITS (CERTDB_USER | CERTDB_VALID_PEER | \
        CERTDB_NS_TRUSTED_CA | CERTDB_VALID_CA | CERTDB_INVISIBLE_CA | \
                                        CERTDB_GOVT_APPROVED_CA)


SEC_BEGIN_PROTOS

/*
** Add a DER encoded certificate to the permanent database.
**	"derCert" is the DER encoded certificate.
**	"nickname" is the nickname to use for the cert
**	"trust" is the trust parameters for the cert
*/
SECStatus SEC_AddPermCertificate(NSSLOWCERTCertDBHandle *handle, SECItem *derCert,
				char *nickname, NSSLOWCERTCertTrust *trust);

certDBEntryCert *
SEC_FindPermCertByKey(NSSLOWCERTCertDBHandle *handle, SECItem *certKey);

certDBEntryCert
*SEC_FindPermCertByName(NSSLOWCERTCertDBHandle *handle, SECItem *name);

#ifdef notdef
SECStatus SEC_OpenPermCertDB(NSSLOWCERTCertDBHandle *handle,
			     PRBool readOnly,
			     NSSLOWCERTDBNameFunc namecb,
			     void *cbarg);
#endif

SECStatus SEC_DeletePermCertificate(NSSLOWCERTCertificate *cert);

typedef SECStatus (PR_CALLBACK * PermCertCallback)(NSSLOWCERTCertificate *cert,
                                                   SECItem *k, void *pdata);
/*
** Traverse the entire permanent database, and pass the certs off to a
** user supplied function.
**	"certfunc" is the user function to call for each certificate
**	"udata" is the user's data, which is passed through to "certfunc"
*/
SECStatus
nsslowcert_TraversePermCerts(NSSLOWCERTCertDBHandle *handle,
		      PermCertCallback certfunc,
		      void *udata );

PRBool
nsslowcert_CertDBKeyConflict(SECItem *derCert, NSSLOWCERTCertDBHandle *handle);

SECItem *
nsslowcert_FindCrlByKey(NSSLOWCERTCertDBHandle *handle, SECItem *crlKey,
				 		char **urlp, PRBool isKRL);

SECStatus
nsslowcert_DeletePermCRL(NSSLOWCERTCertDBHandle *handle,SECItem *derName,
								PRBool isKRL);
SECStatus
nsslowcert_AddCrl(NSSLOWCERTCertDBHandle *handle, SECItem *derCrl ,
				SECItem *derKey, char *url, PRBool isKRL);

NSSLOWCERTCertDBHandle *nsslowcert_GetDefaultCertDB();
NSSLOWKEYPublicKey *nsslowcert_ExtractPublicKey(NSSLOWCERTCertificate *);

NSSLOWCERTCertificate *
nsslowcert_NewTempCertificate(NSSLOWCERTCertDBHandle *handle, SECItem *derCert,
                        char *nickname, PRBool isperm, PRBool copyDER);
NSSLOWCERTCertificate *
nsslowcert_DupCertificate(NSSLOWCERTCertificate *cert);
void nsslowcert_DestroyCertificate(NSSLOWCERTCertificate *cert);

/*
 * Lookup a certificate in the databases without locking
 *	"certKey" is the database key to look for
 *
 * XXX - this should be internal, but pkcs 11 needs to call it during a
 * traversal.
 */
NSSLOWCERTCertificate *
nsslowcert_FindCertByKey(NSSLOWCERTCertDBHandle *handle, SECItem *certKey);

/*
** Generate a certificate key from the issuer and serialnumber, then look it
** up in the database.  Return the cert if found.
**	"issuerAndSN" is the issuer and serial number to look for
*/
extern NSSLOWCERTCertificate *
nsslowcert_FindCertByIssuerAndSN (NSSLOWCERTCertDBHandle *handle, NSSLOWCERTIssuerAndSN *issuerAndSN);

/*
** Find a certificate in the database by a DER encoded certificate
**	"derCert" is the DER encoded certificate
*/
extern NSSLOWCERTCertificate *
nsslowcert_FindCertByDERCert(NSSLOWCERTCertDBHandle *handle, SECItem *derCert);

/* convert an email address to lower case */
char *nsslowcert_FixupEmailAddr(char *emailAddr);

/*
** Decode a DER encoded certificate into an NSSLOWCERTCertificate structure
**      "derSignedCert" is the DER encoded signed certificate
**      "copyDER" is true if the DER should be copied, false if the
**              existing copy should be referenced
**      "nickname" is the nickname to use in the database.  If it is NULL
**              then a temporary nickname is generated.
*/
extern NSSLOWCERTCertificate *
nsslowcert_DecodeDERCertificate (SECItem *derSignedCert, PRBool copyDER, char *nickname);

SECStatus
nsslowcert_KeyFromDERCert(PRArenaPool *arena, SECItem *derCert, SECItem *key);

SEC_END_PROTOS

 #endif /* _PCERTDB_H_ */
