/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef PLATFORM_GCM_H
#define PLATFORM_GCM_H 1

#include "blapii.h"

PRBool platform_gcm_support();

typedef struct platform_AES_GCMContextStr platform_AES_GCMContext;

platform_AES_GCMContext *platform_AES_GCM_CreateContext(void *context, freeblCipherFunc cipher,
                                                        const unsigned char *params);

void platform_AES_GCM_DestroyContext(platform_AES_GCMContext *gcm, PRBool freeit);

SECStatus platform_AES_GCM_EncryptUpdate(platform_AES_GCMContext *gcm, unsigned char *outbuf,
                                         unsigned int *outlen, unsigned int maxout,
                                         const unsigned char *inbuf, unsigned int inlen,
                                         unsigned int blocksize);

SECStatus platform_AES_GCM_DecryptUpdate(platform_AES_GCMContext *gcm, unsigned char *outbuf,
                                         unsigned int *outlen, unsigned int maxout,
                                         const unsigned char *inbuf, unsigned int inlen,
                                         unsigned int blocksize);
SECStatus platform_AES_GCM_EncryptAEAD(platform_AES_GCMContext *gcm,
                                       unsigned char *outbuf,
                                       unsigned int *outlen, unsigned int maxout,
                                       const unsigned char *inbuf, unsigned int inlen,
                                       void *params, unsigned int paramLen,
                                       const unsigned char *aad, unsigned int aadLen,
                                       unsigned int blocksize);
SECStatus platform_AES_GCM_DecryptAEAD(platform_AES_GCMContext *gcm,
                                       unsigned char *outbuf,
                                       unsigned int *outlen, unsigned int maxout,
                                       const unsigned char *inbuf, unsigned int inlen,
                                       void *params, unsigned int paramLen,
                                       const unsigned char *aad, unsigned int aadLen,
                                       unsigned int blocksize);

#endif // PLATFORM_GCM_H
