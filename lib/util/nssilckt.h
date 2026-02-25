/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef _NSSILCKT_H_
#define _NSSILCKT_H_

typedef enum {
    nssILockArena = 0,
    nssILockSession = 1,
    nssILockObject = 2,
    nssILockRefLock = 3,
    nssILockCert = 4,
    nssILockCertDB = 5,
    nssILockDBM = 6,
    nssILockCache = 7,
    nssILockSSL = 8,
    nssILockList = 9,
    nssILockSlot = 10,
    nssILockFreelist = 11,
    nssILockOID = 12,
    nssILockAttribute = 13,
    nssILockPK11cxt = 14, /* pk11context */
    nssILockRWLock = 15,
    nssILockOther = 16,
    nssILockSelfServ = 17,
    nssILockKeyDB = 18,
    nssILockLast /* don't use this one! */
} nssILockType;

#define PZLock PRLock
#define PZCondVar PRCondVar
#define PZMonitor PRMonitor

#endif /* _NSSILCKT_H_ */
