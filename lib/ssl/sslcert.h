/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is PRIVATE to SSL.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __sslcert_h_
#define __sslcert_h_

#include "cert.h"
#include "secitem.h"
#include "keyhi.h"

/* The following struct identifies a single slot into which a certificate can be
** loaded.  The authType field determines the basic slot, then additional
** parameters further narrow the slot.
**
** An EC key (ssl_auth_ecdh or ssl_auth_ecdsa) is assigned to a slot
** based on the named curve of the key.
*/
typedef struct sslServerCertTypeStr {
    SSLAuthType authType;
    union {
#ifndef NSS_DISABLE_ECC
        /* for ssl_auth_ecdh and ssl_auth_ecdsa: */
        ECName namedCurve;
#endif
    } u;
} sslServerCertType;

typedef struct sslServerCertStr {
    PRCList link; /* The linked list link */

    sslServerCertType certType; /* The certificate slot this occupies */

    /* Configuration state for server sockets */
    CERTCertificate *serverCert;
    CERTCertificateList *serverCertChain;
    ssl3KeyPair *serverKeyPair;
    unsigned int serverKeyBits;
    /* Each certificate needs its own status. */
    SECItemArray *certStatusArray;
    /* Serialized signed certificate timestamps to be sent to the client
    ** in a TLS extension (server only). Each certificate needs its own
    ** timestamps item.
    */
    SECItem signedCertTimestamps;
} sslServerCert;

extern sslServerCert *ssl_NewServerCert(const sslServerCertType *slot);
extern sslServerCert *ssl_FindServerCert(const sslSocket *ss,
                                         const sslServerCertType *slot);
extern sslServerCert *ssl_FindServerCertByAuthType(const sslSocket *ss,
                                                   SSLAuthType authType);
extern void ssl_FreeServerCert(sslServerCert *sc);

#endif /* __sslcert_h_ */
