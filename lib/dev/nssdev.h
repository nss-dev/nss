/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef NSSDEV_H
#define NSSDEV_H

/*
 * nssdev.h
 *
 * High-level methods for interaction with cryptoki devices
 */

#ifndef NSSDEVT_H
#include "nssdevt.h"
#endif /* NSSDEVT_H */
#include "pkcs11t.h"

PR_BEGIN_EXTERN_C

/* NSSAlgorithmAndParameters
 *
 * NSSAlgorithmAndParameters_CreateDigest
 * NSSAlgorithm_DigestBuf
 */

NSS_EXTERN NSSAlgorithmAndParameters *
NSSAlgorithmAndParameters_CreateDigest(
    NSSArena *arenaOpt, CK_MECHANISM_TYPE type);

NSS_EXTERN PRStatus
NSSAlgorithm_DigestBuf(CK_MECHANISM_TYPE type, NSSItem *input, NSSItem *output);

PR_END_EXTERN_C

#endif /* DEV_H */
