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

#ifndef NSSDEV_H
#define NSSDEV_H

#ifdef DEBUG
static const char NSSDEV_CVS_ID[] = "@(#) $RCSfile$ $Revision$ $Date$ $Name$";
#endif /* DEBUG */
/*
 * nssdev.h
 *
 * High-level methods for interaction with cryptoki devices
 */

#ifndef NSSDEVT_H
#include "nssdevt.h"
#endif /* NSSDEVT_H */

PR_BEGIN_EXTERN_C

/* Global NSS functions */

NSS_EXTERN NSSModule **
NSS_GetLoadedModules
(
  void
);

NSS_EXTERN NSSModule *
NSS_LoadModule
(
  NSSUTF8 *moduleOpt,
  NSSUTF8 *uriOpt,
  NSSUTF8 *opaqueOpt,
  PRBool keepModule,
  void *reserved
);

/* removes from the database...  perhaps this is a trust domain function? */
NSS_EXTERN PRStatus
NSS_DeleteStoredModule
(
  NSSModule *module
);

NSS_EXTERN NSSModule *
NSS_FindModuleByName
(
  NSSUTF8 *name
);

/* NSS_SeedRandom
 *
 * On the basis of "what's good for one, is good for all", this should
 * be a global API (not module/trust domain specific).
 * 
 * If randomSeedOpt is NULL, NSS will attempt to collect random info from
 * the machine and seed with that.
 */
NSS_EXTERN PRStatus
NSS_SeedRandom
(
  NSSItem *randomSeedOpt
);

/* NSSModule
 *
 * NSSModule_Destroy
 * NSSModule_GetInfo
 *
 * NSSModuleInfo_Destroy
 */

NSS_EXTERN PRStatus
NSSModule_Destroy
(
  NSSModule *module
);

NSS_EXTERN void
NSSModuleInfo_Destroy
(
  NSSModuleInfo *moduleInfo
);

NSS_EXTERN void
NSSModule_GetInfo
(
  NSSModule *module,
  NSSModuleInfo *moduleInfo
);

/* NSSSlot
 *
 * NSSSlot_Destroy
 * NSSSlot_GetInfo
 * nssSlot_GetToken
 */

NSS_EXTERN void
NSSSlot_Destroy
(
  NSSSlot *slot
);

NSS_EXTERN PRStatus
NSSSlot_GetInfo
(
  NSSSlot *slot,
  NSSSlotInfo *slotInfo
);

NSS_EXTERN NSSToken *
NSSSlot_GetToken
(
  NSSSlot *slot
);

NSS_EXTERN PRStatus
NSSSlot_SetPassword
(
  NSSSlot *slot,
  NSSUTF8 *oldPasswordOpt,
  NSSUTF8 *newPassword
);

/* NSSToken
 *
 * NSSToken_Destroy
 * NSSToken_GetName
 * NSSToken_GetInfo
 * NSSToken_GetSlot
 */
NSS_EXTERN void
NSSToken_Destroy
(
  NSSToken *token
);

NSS_EXTERN NSSUTF8 *
NSSToken_GetName
(
  NSSToken *token
);

NSS_EXTERN NSSSlot *
NSSToken_GetSlot
(
  NSSToken *tok
);

NSS_EXTERN PRStatus
NSSToken_GetInfo
(
  NSSToken *token,
  NSSTokenInfo *tokenInfo
);

/* NSSAlgorithmAndParameters
 *
 * 
 */

#ifdef notdefhere
/* this should be a protected "friend" method available to the PKI1 module
 * (which contains the OID implementation)
 */
NSS_EXTERN NSSAlgorithmAndParameters *
nssAlgorithmAndParameters_CreateFromOID
(
  NSSArena *arenaOpt,
  CK_MECHANISM_TYPE algorithm,
  const NSSItem *parametersOpt /* XXX or already decoded? */
);
#endif

NSS_EXTERN NSSAlgorithmAndParameters *
NSSAlgorithmAndParameters_Create
(
  NSSArena *arenaOpt,
  NSSAlgorithmType algorithm,
  NSSParameters *parameters
);

NSS_EXTERN NSSAlgorithmAndParameters *
NSSAlgorithmAndParameters_CreateKeyGen
(
  NSSArena *arenaOpt,
  NSSAlgorithmType algorithm,
  NSSParameters *parametersOpt
);

NSS_EXTERN NSSAlgorithmAndParameters *
NSSAlgorithmAndParameters_CreateMAC
(
  NSSArena *arenaOpt,
  NSSAlgorithmType blockCipher,
  NSSParameters *cipherParameters,
  PRUint32 macLength /* in bytes, 0 means maximum for block cipher */
);

NSS_EXTERN NSSAlgorithmAndParameters *
NSSAlgorithmAndParameters_CreateHMAC
(
  NSSArena *arenaOpt,
  NSSAlgorithmType hashAlgorithm,
  PRUint32 hmacLength /* in bytes, 0 means maximum for hash algorithm */
);

/* NSSAlgorithmAndParameters_GetParameters
 *
 * Return the parameters, properly encoded for the algorithm OID.  The
 * returned item must be freed.
 */
NSS_EXTERN NSSItem *
NSSAlgorithmAndParameters_GetParameters
(
  NSSAlgorithmAndParameters *ap
);

/* NSSAlgorithmAndParameters_Destroy
 *
 */
NSS_EXTERN void
NSSAlgorithmAndParameters_Destroy
(
  NSSAlgorithmAndParameters *ap
);

NSS_EXTERN void
NSSSlotArray_Destroy
(
  NSSSlot **slots
);

NSS_EXTERN void
NSSTokenArray_Destroy
(
  NSSToken **tokens
);

PR_END_EXTERN_C

#endif /* DEV_H */
