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

#ifndef DEVT_H
#define DEVT_H

#ifdef DEBUG
static const char DEVT_CVS_ID[] = "@(#) $RCSfile$ $Revision$ $Date$ $Name$";
#endif /* DEBUG */

/*
 * devt.h
 *
 * This file contains definitions for the low-level cryptoki devices.
 */

#ifndef NSSCKT_H
#include "nssckt.h"
#endif /* NSSCKT_H */

#ifndef NSSDEVT_H
#include "nssdevt.h"
#endif /* NSSDEVT_H */

PR_BEGIN_EXTERN_C

typedef struct nssSessionStr nssSession;

/* The list of boolean flags used to describe properties of a
 * slot.
 * XXX maybe cipher flags should be moved somewhere else?  too constrictive
 *    on the availability of other slot flags?
 */
#define NSSSLOT_FLAGS_LOGIN_REQUIRED  0x00000001 /* needLogin  */
/*#define NSSSLOT_FLAGS_READONLY        0x00000002*/ /* readOnly */
#define NSSSLOT_FLAGS_HAS_RANDOM      0x00000010 /* hasRandom  */
#define NSSSLOT_FLAGS_RSA             0x00000020 /* RSA        */
#define NSSSLOT_FLAGS_DSA             0x00000040 /* DSA        */
#define NSSSLOT_FLAGS_DH              0x00000080 /* DH         */
#define NSSSLOT_FLAGS_RC2             0x00000100 /* RC2        */
#define NSSSLOT_FLAGS_RC4             0x00000200 /* RC4        */
#define NSSSLOT_FLAGS_RC5             0x00000400 /* RC5        */
#define NSSSLOT_FLAGS_DES             0x00000800 /* DES        */
#define NSSSLOT_FLAGS_AES             0x00001000 /* AES        */
#define NSSSLOT_FLAGS_SHA1            0x00002000 /* SHA1       */
#define NSSSLOT_FLAGS_MD2             0x00004000 /* MD2        */
#define NSSSLOT_FLAGS_MD5             0x00008000 /* MD5        */
#define NSSSLOT_FLAGS_SSL             0x00010000 /* SSL        */
#define NSSSLOT_FLAGS_TLS             0x00020000 /* TLS        */
#define NSSSLOT_FLAGS_FRIENDLY        0x00040000 /* isFriendly */

typedef struct nssSlotListStr nssSlotList;

typedef enum {
  nssTrustLevel_Unknown = 0,
  nssTrustLevel_NotTrusted = 1,
  nssTrustLevel_Trusted = 2,
  nssTrustLevel_TrustedDelegator = 3,
  nssTrustLevel_Valid = 4,
  nssTrustLevel_ValidDelegator = 5
} nssTrustLevel;

typedef enum {
  nssTokenSearchType_AllObjects = 0,
  nssTokenSearchType_SessionOnly = 1,
  nssTokenSearchType_TokenOnly = 2,
  nssTokenSearchType_TokenForced = 3 /* XXX internal only */
} nssTokenSearchType;

struct nssCryptokiObjectStr
{
  CK_OBJECT_HANDLE handle;
  NSSToken *token;
  nssSession *session;
  PRBool isTokenObject;
  NSSUTF8 *label;
};

typedef struct nssCryptokiObjectStr nssCryptokiObject;

PR_END_EXTERN_C

#endif /* DEVT_H */
