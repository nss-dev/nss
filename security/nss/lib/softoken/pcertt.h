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
/*
 * certt.h - public data structures for the certificate library
 *
 * $Id$
 */
#ifndef _PCERTT_H_
#define _PCERTT_H_

#include "prclist.h"
#include "pkcs11t.h"
#include "seccomon.h"
/*#include "secmodt.h" */
#include "secoidt.h"
#include "plarena.h"
#include "prcvar.h"
#include "nssilock.h"
#include "prio.h"
#include "prmon.h"

/* Non-opaque objects */
typedef struct NSSLOWCERTCertDBHandleStr               NSSLOWCERTCertDBHandle;
typedef struct NSSLOWCERTCertKeyStr                    NSSLOWCERTCertKey;
typedef struct NSSLOWCERTCertListStr                   NSSLOWCERTCertList;
typedef struct NSSLOWCERTCertListNodeStr               NSSLOWCERTCertListNode;
typedef struct NSSLOWCERTCertNicknamesStr              NSSLOWCERTCertNicknames;
typedef struct NSSLOWCERTCertTrustStr                  NSSLOWCERTCertTrust;
typedef struct NSSLOWCERTCertificateStr                NSSLOWCERTCertificate;
typedef struct NSSLOWCERTCertificateListStr            NSSLOWCERTCertificateList;
typedef struct NSSLOWCERTCrlStr                        NSSLOWCERTCrl;
typedef struct NSSLOWCERTCrlKeyStr                     NSSLOWCERTCrlKey;
typedef struct NSSLOWCERTCrlNodeStr                    NSSLOWCERTCrlNode;
typedef struct NSSLOWCERTDERCertsStr                   NSSLOWCERTDERCerts;
typedef struct NSSLOWCERTIssuerAndSNStr                NSSLOWCERTIssuerAndSN;
typedef struct NSSLOWCERTNameStr                       NSSLOWCERTName;
typedef struct NSSLOWCERTSignedCrlStr                  NSSLOWCERTSignedCrl;
typedef struct NSSLOWCERTSignedDataStr                 NSSLOWCERTSignedData;
typedef struct NSSLOWCERTSubjectPublicKeyInfoStr       NSSLOWCERTSubjectPublicKeyInfo;
typedef struct NSSLOWCERTValidityStr                   NSSLOWCERTValidity;

/*
** An X.509 validity object
*/
struct NSSLOWCERTValidityStr {
    PRArenaPool *arena;
    SECItem notBefore;
    SECItem notAfter;
};

/*
 * A serial number and issuer name, which is used as a database key
 */
struct NSSLOWCERTCertKeyStr {
    SECItem serialNumber;
    SECItem derIssuer;
};

/*
** A signed data object. Used to implement the "signed" macro used
** in the X.500 specs.
*/
struct NSSLOWCERTSignedDataStr {
    SECItem data;
    SECAlgorithmID signatureAlgorithm;
    SECItem signature;
};

/*
** An X.509 subject-public-key-info object
*/
struct NSSLOWCERTSubjectPublicKeyInfoStr {
    PRArenaPool *arena;
    SECAlgorithmID algorithm;
    SECItem subjectPublicKey;
};

typedef struct _certDBEntryCert certDBEntryCert;
typedef struct _certDBEntryRevocation certDBEntryRevocation;

struct NSSLOWCERTCertTrustStr {
    unsigned int sslFlags;
    unsigned int emailFlags;
    unsigned int objectSigningFlags;
};

/*
** An X.509 certificate object (the unsigned form)
*/
struct NSSLOWCERTCertificateStr {
    /* the arena is used to allocate any data structures that have the same
     * lifetime as the cert.  This is all stuff that hangs off of the cert
     * structure, and is all freed at the same time.  I is used when the
     * cert is decoded, destroyed, and at some times when it changes
     * state
     */
    PRArenaPool *arena;
    NSSLOWCERTCertDBHandle *dbhandle;

    SECItem derCert;			/* original DER for the cert */
    SECItem derIssuer;			/* DER for issuer name */
    SECItem serialNumber;
    SECItem derSubject;			/* DER for subject name */
    SECItem derPublicKey;		/* DER for the public key */
    NSSLOWCERTSubjectPublicKeyInfo subjectPublicKeyInfo;
    SECItem certKey;			/* database key for this cert */
    SECItem version;
    NSSLOWCERTValidity validity;
    certDBEntryCert *dbEntry;		/* database entry struct */
    SECItem subjectKeyID;	/* x509v3 subject key identifier */
    char *nickname;
    char *emailAddr;
    NSSLOWCERTCertTrust *trust;

    /* the reference count is modified whenever someone looks up, dups
     * or destroys a certificate
     */
    int referenceCount;
};
#define SEC_CERTIFICATE_VERSION_1		0	/* default created */
#define SEC_CERTIFICATE_VERSION_2		1	/* v2 */
#define SEC_CERTIFICATE_VERSION_3		2	/* v3 extensions */

#define SEC_CRL_VERSION_1		0	/* default */
#define SEC_CRL_VERSION_2		1	/* v2 extensions */

/*
 * used to identify class of cert in mime stream code
 */
#define SEC_CERT_CLASS_CA	1
#define SEC_CERT_CLASS_SERVER	2
#define SEC_CERT_CLASS_USER	3
#define SEC_CERT_CLASS_EMAIL	4

struct NSSLOWCERTDERCertsStr {
    PRArenaPool *arena;
    int numcerts;
    SECItem *rawCerts;
};



struct NSSLOWCERTCrlStr {
    PRArenaPool *arena;
    SECItem version;
    SECAlgorithmID signatureAlg;
    SECItem derName;
};

struct NSSLOWCERTCrlKeyStr {
    SECItem derName;
    SECItem dummy;			/* The decoder can not skip a primitive,
					   this serves as a place holder for the
					   decoder to finish its task only
					*/
};

struct NSSLOWCERTSignedCrlStr {
    PRArenaPool *arena;
    NSSLOWCERTCrl crl;
    certDBEntryRevocation *dbEntry;	/* database entry struct */
    PRBool keep;			/* keep this crl in the cache for the  session*/
    PRBool isperm;
    PRBool istemp;
    int referenceCount;
    NSSLOWCERTCertDBHandle *dbhandle;
    NSSLOWCERTSignedData signatureWrap;	/* XXX */
    char *url;
};

/*
 * Does the cert belong to the user, a peer, or a CA.
 */
typedef enum {
    certOwnerUser = 0,
    certOwnerPeer = 1,
    certOwnerCA = 2
} NSSLOWCERTCertOwner;

/*
 * This enum represents the state of validity times of a certificate
 */
typedef enum {
    secCertTimeValid = 0,
    secCertTimeExpired = 1,
    secCertTimeNotValidYet = 2
} SECCertTimeValidity;

/*
 * Interface for getting certificate nickname strings out of the database
 */

/* these are values for the what argument below */
#define SEC_CERT_NICKNAMES_ALL		1
#define SEC_CERT_NICKNAMES_USER		2
#define SEC_CERT_NICKNAMES_SERVER	3
#define SEC_CERT_NICKNAMES_CA		4

struct NSSLOWCERTCertNicknamesStr {
    PRArenaPool *arena;
    void *head;
    int numnicknames;
    char **nicknames;
    int what;
    int totallen;
};

struct NSSLOWCERTIssuerAndSNStr {
    SECItem derIssuer;
    SECItem serialNumber;
};

typedef SECStatus (* NSSLOWCERTCertCallback)(NSSLOWCERTCertificate *cert, void *arg);

/* This is the typedef for the callback passed to nsslowcert_OpenCertDB() */
/* callback to return database name based on version number */
typedef char * (*NSSLOWCERTDBNameFunc)(void *arg, int dbVersion);

/* XXX Lisa thinks the template declarations belong in cert.h, not here? */

#include "secasn1t.h"	/* way down here because I expect template stuff to
			 * move out of here anyway */

SEC_BEGIN_PROTOS

extern const SEC_ASN1Template nsslowcert_CertificateTemplate[];
extern const SEC_ASN1Template SEC_SignedCertificateTemplate[];
extern const SEC_ASN1Template nsslowcert_SignedDataTemplate[];
extern const SEC_ASN1Template NSSLOWKEY_PublicKeyTemplate[];
extern const SEC_ASN1Template nsslowcert_SubjectPublicKeyInfoTemplate[];
extern const SEC_ASN1Template nsslowcert_ValidityTemplate[];

SEC_END_PROTOS

#endif /* _PCERTT_H_ */
