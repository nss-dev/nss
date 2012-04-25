/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
/*
 * Internal header file included in pk11wrap dir, or in softoken
 */
#ifndef _PK11_INIT_H_
#define _PK11_INIT_H_ 1

/* hold slot default flags until we initialize a slot. This structure is only
 * useful between the time we define a module (either by hand or from the
 * database) and the time the module is loaded. Not reference counted  */
struct PK11PreSlotInfoStr {
    CK_SLOT_ID slotID;  	/* slot these flags are for */
    unsigned long defaultFlags; /* bit mask of default implementation this slot
				 * provides */
    int askpw;			/* slot specific password bits */
    long timeout;		/* slot specific timeout value */
    char hasRootCerts;		/* is this the root cert PKCS #11 module? */
    char hasRootTrust;		/* is this the root cert PKCS #11 module? */
};

#endif /* _PK11_INIT_H_ 1 */
