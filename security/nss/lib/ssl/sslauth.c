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
 *
 * $Id$
 */
#include "ssl.h"
#include "sslimpl.h"
#include "sslproto.h"

#include "nsspki.h"

/* NEED LOCKS IN HERE.  */
NSSCert *
SSL_PeerCertificate(PRFileDesc *fd)
{
    sslSocket *ss;

    ss = ssl_FindSocket(fd);
    if (!ss) {
	SSL_DBG(("%d: SSL[%d]: bad socket in PeerCertificate",
		 SSL_GETPID(), fd));
	return 0;
    }
    if (ss->useSecurity && ss->sec.peerCert) {
	return nssCert_AddRef(ss->sec.peerCert);
    }
    return 0;
}

/* NEED LOCKS IN HERE.  */
NSSCert *
SSL_LocalCertificate(PRFileDesc *fd)
{
    sslSocket *ss;

    ss = ssl_FindSocket(fd);
    if (!ss) {
	SSL_DBG(("%d: SSL[%d]: bad socket in PeerCertificate",
		 SSL_GETPID(), fd));
	return NULL;
    }
    if (ss->useSecurity) {
    	if (ss->sec.localCert) {
	    return nssCert_AddRef(ss->sec.localCert);
	}
	if (ss->sec.ci.sid && ss->sec.ci.sid->localCert) {
	    return nssCert_AddRef(ss->sec.ci.sid->localCert);
	}
    }
    return NULL;
}



/* NEED LOCKS IN HERE.  */
SECStatus
SSL_SecurityStatus(PRFileDesc *fd, int *op, char **cp, int *kp0, int *kp1,
		   char **ip, char **sp)
{
    sslSocket *ss;
    const char *cipherName;
    PRBool isDes = PR_FALSE;

    ss = ssl_FindSocket(fd);
    if (!ss) {
	SSL_DBG(("%d: SSL[%d]: bad socket in SecurityStatus",
		 SSL_GETPID(), fd));
	return SECFailure;
    }

    if (cp) *cp = 0;
    if (kp0) *kp0 = 0;
    if (kp1) *kp1 = 0;
    if (ip) *ip = 0;
    if (sp) *sp = 0;
    if (op) {
	*op = SSL_SECURITY_STATUS_OFF;
    }

    if (ss->useSecurity && ss->firstHsDone) {

	if (ss->version < SSL_LIBRARY_VERSION_3_0) {
	    cipherName = ssl_cipherName[ss->sec.cipherType];
	} else {
	    cipherName = ssl3_cipherName[ss->sec.cipherType];
	}
	if (cipherName && strstr(cipherName, "DES")) isDes = PR_TRUE;
	/* do same key stuff for fortezza */
    
	if (cp) {
	    *cp = (char *)NSSUTF8_Duplicate(cipherName);
	}

	if (kp0) {
	    *kp0 = ss->sec.keyBits;
	    if (isDes) *kp0 = (*kp0 * 7) / 8;
	}
	if (kp1) {
	    *kp1 = ss->sec.secretKeyBits;
	    if (isDes) *kp1 = (*kp1 * 7) / 8;
	}
	if (op) {
	    if (ss->sec.keyBits == 0) {
		*op = SSL_SECURITY_STATUS_OFF;
	    } else if (ss->sec.secretKeyBits < 90) {
		*op = SSL_SECURITY_STATUS_ON_LOW;

	    } else {
		*op = SSL_SECURITY_STATUS_ON_HIGH;
	    }
	}

	if (ip || sp) {
	    NSSCert *cert;

	    cert = ss->sec.peerCert;
	    if (cert) {
		if (ip) {
		    *ip = NSSCert_GetIssuerNames(cert, ip, 1, NULL);
		}
		if (sp) {
		    *sp = NSSCert_GetNames(cert, sp, 1, NULL);
		}
	    } else {
		if (ip) {
		    *ip = NSSUTF8_Duplicate("no certificate");
		}
		if (sp) {
		    *sp = NSSUTF8_Duplicate("no certificate");
		}
	    }
	}
    }

    return SECSuccess;
}

/************************************************************************/

/* NEED LOCKS IN HERE.  */
SECStatus
SSL_AuthCertificateHook(PRFileDesc *s, SSLAuthCertificate func, void *arg)
{
    sslSocket *ss;
    SECStatus rv;

    ss = ssl_FindSocket(s);
    if (!ss) {
	SSL_DBG(("%d: SSL[%d]: bad socket in AuthCertificateHook",
		 SSL_GETPID(), s));
	return SECFailure;
    }

    ss->authCertificate = func;
    ss->authCertificateArg = arg;

    return SECSuccess;
}

/* NEED LOCKS IN HERE.  */
SECStatus 
SSL_GetClientAuthDataHook(PRFileDesc *s, SSLGetClientAuthData func,
			      void *arg)
{
    sslSocket *ss;
    SECStatus rv;

    ss = ssl_FindSocket(s);
    if (!ss) {
	SSL_DBG(("%d: SSL[%d]: bad socket in GetClientAuthDataHook",
		 SSL_GETPID(), s));
	return SECFailure;
    }

    ss->getClientAuthData = func;
    ss->getClientAuthDataArg = arg;
    return SECSuccess;
}

/* NEED LOCKS IN HERE.  */
SECStatus 
SSL_SetPKCS11PinArg(PRFileDesc *s, void *arg)
{
    sslSocket *ss;
    SECStatus rv;

    ss = ssl_FindSocket(s);
    if (!ss) {
	SSL_DBG(("%d: SSL[%d]: bad socket in GetClientAuthDataHook",
		 SSL_GETPID(), s));
	return SECFailure;
    }

    ss->pkcs11PinArg = arg;
    return SECSuccess;
}


/* This is the "default" authCert callback function.  It is called when a 
 * certificate message is received from the peer and the local application
 * has not registered an authCert callback function.
 */
SECStatus
SSL_AuthCertificate(void *arg, PRFileDesc *fd, PRBool checkSig, PRBool isServer)
{
    SECStatus          rv;
    sslSocket *        ss;
    NSSUsages          usage;
    PRStatus           status;
    const char *             hostname    = NULL;
    NSSUTF8 **name;
    NSSUTF8 **names;
    NSSArena *arena;
    
    ss = ssl_FindSocket(fd);
    PR_ASSERT(ss != NULL);
    if (!ss) {
	return SECFailure;
    }

    /* this may seem backwards, but isn't. */
    usage.peer = isServer ? NSSUsage_SSLClient : NSSUsage_SSLServer;
    usage.ca = 0;

    /* XXX checkSig? */
    status = NSSCert_Validate(ss->sec.peerCert, NSSTime_Now(), &usage, NULL);

    rv = (status == PR_SUCCESS) ? SECSuccess : SECFailure;

    if ( status == PR_FAILURE || isServer )
	return rv;
  
    /* cert is OK.  This is the client side of an SSL connection.
     * Now check the name field in the cert against the desired hostname.
     * NB: This is our only defense against Man-In-The-Middle (MITM) attacks!
     */
    hostname = ss->url;
    if (hostname && hostname[0]) {
	NSSArena *arena;
	rv = SECFailure;
	arena = NSSArena_Create();
	if (!arena) {
	    return SECFailure;
	}
	names = NSSCert_GetNames(ss->sec.peerCert, NULL, 0, arena);
	if (names) {
	    for (name = names; *name; name++) {
		if (NSSUTF8_Equal(*name, hostname, NULL)) {
		    rv = SECSuccess;
		    break;
		}
	    }
	}
	NSSArena_Destroy(arena); /* clears all parts of 'names' */
    } else  {
	rv = SECFailure;
    }
    if (rv != SECSuccess)
	nss_SetError(SSL_ERROR_BAD_CERT_DOMAIN);

    return rv;
}
