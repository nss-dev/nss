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

typedef enum
{
  pkiObjectType_Cert = 0,
  pkiObjectType_CRL = 1,
  pkiObjectType_PrivateKey = 2,
  pkiObjectType_PublicKey = 3,
  pkiObjectType_SymKey = 4
} pkiObjectType;

#define MAX_ITEMS_FOR_UID 2

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
    /* the set of token instances (if any) for the object */
    nssCryptokiObject **instances;
    PRUint32 numInstances;
    /* The object must live in a trust domain */
    NSSTrustDomain *td;
    /* The object may live in a volatile domain */
    NSSVolatileDomain *vd;
    /* The "meta"-name of the object (token instance labels may differ) */
    NSSUTF8 *nickname;
    /* The following data index the UID for the object.  The UID is used
     * in the table of active token objects, to ensure that the same object
     * never appears as two different objects.
     */
    pkiObjectType objectType;
    NSSItem *uid[MAX_ITEMS_FOR_UID];
    PRUint32 numIDs;
};

typedef struct nssPKIObjectStr nssPKIObject;

typedef struct nssPKIObjectTableStr nssPKIObjectTable;

typedef struct nssPKIObjectCreatorStr
{
  NSSTrustDomain *td;
  NSSVolatileDomain *vd;
  NSSToken *destination;
  nssSession *session;
  PRBool persistent;
  const NSSAlgNParam *ap;
  NSSCallback *uhh;
  const NSSUTF8 *nickname;
  NSSProperties properties;
  NSSOperations operations;
} nssPKIObjectCreator;

struct nssTrustStr
{
  NSSUsages trustedUsages;
  NSSUsages notTrustedUsages;
};

typedef struct nssTokenSessionHashStr nssTokenSessionHash;

typedef struct nssTokenStoreStr nssTokenStore;

typedef struct nssPKIDatabaseStr nssPKIDatabase;

PR_END_EXTERN_C

#endif /* PKITM_H */
