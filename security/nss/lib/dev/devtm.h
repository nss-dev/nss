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

#ifndef DEVTM_H
#define DEVTM_H

#ifdef DEBUG
static const char DEVTM_CVS_ID[] = "@(#) $RCSfile$ $Revision$ $Date$ $Name$";
#endif /* DEBUG */

/*
 * devtm.h
 *
 * This file contains module-private definitions for the low-level 
 * cryptoki device interface.
 */

#ifndef DEVT_H
#include "devt.h"
#endif /* DEVT_H */

PR_BEGIN_EXTERN_C

struct nssDeviceBaseStr
{
  NSSArena *arena;
  PZLock *lock;
  PRInt32 refCount;
  NSSUTF8 *name;
  PRUint32 flags;
};

/* I've left this exposed because using session->handle within the dev
 * module is much easier than calling a function, and it happens a lot.
 *
 * The refCount of a session may increment if one of the followng occurs:
 *
 * 1) A call to nssSession_AddRef
 *      In this case, a higher-level object is using a session, and wishes
 *      to share it with another object.  For example, a key pair is
 *      created within the same session.  Both keys should have a reference
 *      to the session, and the session will remain active until both keys
 *      have been destroyed.
 *
 * 2) The session is a parent
 *      Child sessions are "virtual".  They share the same handle as their
 *      parent, but appear to be unique.  This is to prevent higher-level
 *      code from having to handle the session starvation case.
 *
 * If one imagines the limiting case of a token that supports only a single
 * session, there will be a single parent session, and any number of
 * children.  The sum of all references to the parent and all children is
 * the number of sessions that appear to be in use, when in fact, there is
 * only one.
 */
struct nssSessionStr
{
  PZLock *lock;
  CK_SESSION_HANDLE handle;
  NSSSlot *slot;
  PRBool isRW;

  PRUint32 refCount;
  PRBool owner;
  nssSession *parent;
  NSSItem state;
};

#define MAX_LOCAL_CACHE_OBJECTS 10

typedef struct nssTokenObjectCacheStr nssTokenObjectCache;

PR_END_EXTERN_C

#endif /* DEVTM_H */
