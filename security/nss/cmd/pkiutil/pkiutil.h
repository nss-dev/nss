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

#include "cmdutil.h"

#define PKIUTIL_VERSION_STRING "pkiutil version 0.1"

extern char *progName;

typedef enum 
{
    PKIUnknown = -1,
    PKICert,
    PKIPublicKey,
    PKIPrivateKey,
    PKIAny
} PKIObjectType;

PRStatus
ImportObject
(
  NSSTrustDomain *td,
  NSSToken *tokenOpt,
  char *objectTypeOpt,
  char *nickname,
  char *keyTypeOpt,
  char *keypass,
  CMDRunTimeData *rtData
);

PRStatus
ExportObject
(
  NSSTrustDomain *td,
  NSSToken *tokenOpt,
  char *objectTypeOpt,
  char *nickname,
  char *keypass,
  CMDRunTimeData *rtData
);

PRStatus
GenerateKeyPair
(
  NSSTrustDomain *td,
  NSSToken *tokenOpt,
  char *keyTypeOpt,
  char *keySizeOpt,
  char *nickname,
  CMDRunTimeData *rtData
);

/* XXX need to be more specific (serial number?) */
PRStatus
DeleteObject
(
  NSSTrustDomain *td,
  NSSToken *tokenOpt,
  char *objectTypeOpt,
  char *nickname
);

PRStatus
ListObjects
(
  NSSTrustDomain *td,
  NSSToken *tokenOpt,
  char *objectTypeOpt,
  char *nicknameOpt,
  PRUint32 maximumOpt,
  CMDRunTimeData *rtData
);

PRStatus
ListChain
(
  NSSTrustDomain *td,
  char *nickname,
  char *serial,
  PRUint32 maximumOpt,
  CMDRunTimeData *rtData
);

PRStatus
DumpObject
(
  NSSTrustDomain *td,
  char *objectType,
  char *nickname,
  char *serialOpt,
  PRBool info,
  CMDRunTimeData *rtData
);

PRStatus
ValidateCert
(
  NSSTrustDomain *td,
  char *nickname,
  char *serial,
  char *usages,
  PRBool info,
  CMDRunTimeData *rtData
);

PRStatus
SetCertTrust
(
  NSSTrustDomain *td,
  char *nickname,
  char *serial,
  char *trustedUsages
);

PRStatus
DeleteOrphanedKeyPairs
(
  NSSTrustDomain *td,
  NSSToken *tokenOpt,
  CMDRunTimeData *rtData
);

