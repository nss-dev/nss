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

#ifndef PKITM_H
#define PKITM_H

#ifdef DEBUG
static const char PKITM_CVS_ID[] = "@(#) $RCSfile$ $Revision$ $Date$ $Name$";
#endif /* DEBUG */

/*
 * pkitm.h
 *
 * This file contains PKI-module specific types.
 */

#ifndef BASET_H
#include "baset.h"
#endif /* BASET_H */

#ifndef DEVT_H
#include "devt.h"
#endif /* DEVT_H */

#ifndef PKIT_H
#include "pkit.h"
#endif /* PKIT_H */

PR_BEGIN_EXTERN_C

/*
 * A note on ephemeral certs
 *
 * The key objects defined here can only be created on tokens, and can only
 * exist on tokens.  Therefore, any instance of a key object must have
 * a corresponding cryptoki instance.  OTOH, certificates created in 
 * crypto contexts need not be stored as session objects on the token.
 * There are good performance reasons for not doing so.  The certificate
 * and trust objects have been defined with a cryptoContext field to
 * allow for ephemeral certs, which may have a single instance in a crypto
 * context along with any number (including zero) of cryptoki instances.
 * Since contexts may not share objects, there can be only one context
 * for each object.
 */

/* nssPKIObject
 *
 * This is the base object class, common to all PKI objects defined in
 * nsspkit.h
 */
struct nssPKIObjectStr 
{
    /* The arena for all object memory */
    NSSArena *arena;
    /* Atomically incremented/decremented reference counting */
    PRInt32 refCount;
    /* lock protects the array of nssCryptokiInstance's of the object */
    PZLock *lock;
    /* XXX with LRU cache, this cannot be guaranteed up-to-date.  It cannot
     * be compared against the update level of the trust domain, since it is
     * also affected by import/export.  Where is this array needed?
     */
    nssCryptokiObject **instances;
    PRUint32 numInstances;
    /* The object must live in a trust domain */
    NSSTrustDomain *trustDomain;
    /* The object may live in a crypto context */
    NSSCryptoContext *cryptoContext;
    /* XXX added so temp certs can have nickname, think more ... */
    NSSUTF8 *tempName;
};

typedef struct nssPKIObjectStr nssPKIObject;

/* nssCertificateCollection
 *
 * You guessed it; a collection of certs.  Each entry may be either an
 * NSSCertificate or an nssProtoCertificate.
 */

typedef struct nssPKIObjectCollectionStr nssPKIObjectCollection;

typedef struct
{
  union {
    PRStatus (*  cert)(NSSCertificate *c, void *arg);
    PRStatus (*   crl)(NSSCRL       *crl, void *arg);
    PRStatus (* pvkey)(NSSPrivateKey *vk, void *arg);
    PRStatus (* pbkey)(NSSPublicKey  *bk, void *arg);
  } func;
  void *arg;
} nssPKIObjectCallback;

PR_END_EXTERN_C

#endif /* PKITM_H */
