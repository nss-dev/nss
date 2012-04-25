/*
 * blapii.h - private data structures and prototypes for the crypto library
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef _BLAPII_H_
#define _BLAPII_H_

#include "blapit.h"

SEC_BEGIN_PROTOS

#if defined(XP_UNIX) && !defined(NO_FORK_CHECK)

extern PRBool bl_parentForkedAfterC_Initialize;

#define SKIP_AFTER_FORK(x) if (!bl_parentForkedAfterC_Initialize) x

#else

#define SKIP_AFTER_FORK(x) x

#endif

SEC_END_PROTOS

#endif /* _BLAPII_H_ */

