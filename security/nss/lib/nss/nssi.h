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

#ifndef NSSI_H
#define NSSI_H

#include "nsst.h"
#include "nssdevt.h"
#include "nsspkit.h"

PR_BEGIN_EXTERN_C

/* the global module list
 *
 * These functions are for managing the global set of modules.  Trust Domains,
 * etc., will draw from this set.  These functions are completely internal
 * and only invoked when there are changes to the global module state
 * (load or unload).
 *
 * nss_InitializeGlobalModuleList
 * nss_DestroyGlobalModuleList
 * nss_GetLoadedModules
 *
 * nssGlobalModuleList_Add
 * nssGlobalModuleList_Remove
 * nssGlobalModuleList_FindModuleByName
 * nssGlobalModuleList_FindSlotByName
 * nssGlobalModuleList_FindTokenByName
 */

NSS_EXTERN PRStatus
nss_InitializeGlobalModuleList (
  void
);

NSS_EXTERN PRStatus
nss_DestroyGlobalModuleList (
  void
);

NSS_EXTERN NSSModule **
nss_GetLoadedModules (
  void
);

NSS_EXTERN PRStatus
nssGlobalModuleList_Add (
  NSSModule *module
);

NSS_EXTERN PRStatus
nssGlobalModuleList_Remove (
  NSSModule *module
);

NSS_EXTERN NSSModule *
nssGlobalModuleList_FindModuleByName (
  NSSUTF8 *moduleName
);

NSS_EXTERN NSSSlot *
nssGlobalModuleList_FindSlotByName (
  NSSUTF8 *slotName
);

NSS_EXTERN NSSToken *
nssGlobalModuleList_FindTokenByName (
  NSSUTF8 *tokenName
);

NSS_EXTERN NSSToken *
nss_GetDefaultCryptoToken (
  void
);

NSS_EXTERN NSSToken *
nss_GetDefaultDatabaseToken (
  void
);

PR_END_EXTERN_C

#endif /* NSSI_H */
