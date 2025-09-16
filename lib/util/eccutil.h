/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef _FREEBL_H_
#define _FREEBL_H_

#define X25519_PUBLIC_KEY_BYTES 32U
#define SECP256_PUBLIC_KEY_BYTES 65U

/* deprecated */
typedef enum {
    ECPoint_Uncompressed,
    ECPoint_XOnly,
    ECPoint_Undefined
} ECPointEncoding;

#endif /* _FREEBL_H_ */
