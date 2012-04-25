/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
/* $Id$ */

#ifndef _HASHT_H_
#define _HASHT_H_

/* Opaque objects */
typedef struct SECHashObjectStr SECHashObject;
typedef struct HASHContextStr HASHContext;

/*
 * The hash functions the security library supports
 * NOTE the order must match the definition of SECHashObjects[]!
 */
typedef enum {
    HASH_AlgNULL   = 0,
    HASH_AlgMD2    = 1,
    HASH_AlgMD5    = 2,
    HASH_AlgSHA1   = 3,
    HASH_AlgSHA256 = 4,
    HASH_AlgSHA384 = 5,
    HASH_AlgSHA512 = 6,
    HASH_AlgSHA224 = 7,
    HASH_AlgTOTAL
} HASH_HashType;

/*
 * Number of bytes each hash algorithm produces
 */
#define MD2_LENGTH	16
#define MD5_LENGTH	16
#define SHA1_LENGTH	20
#define SHA224_LENGTH 	28
#define SHA256_LENGTH 	32
#define SHA384_LENGTH 	48
#define SHA512_LENGTH 	64
#define HASH_LENGTH_MAX SHA512_LENGTH

/*
 * Structure to hold hash computation info and routines
 */
struct SECHashObjectStr {
    unsigned int length;  /* hash output length (in bytes) */
    void * (*create)(void);
    void * (*clone)(void *);
    void (*destroy)(void *, PRBool);
    void (*begin)(void *);
    void (*update)(void *, const unsigned char *, unsigned int);
    void (*end)(void *, unsigned char *, unsigned int *, unsigned int);
    unsigned int blocklength;  /* hash input block size (in bytes) */
    HASH_HashType type;
};

struct HASHContextStr {
    const struct SECHashObjectStr *hashobj;
    void *hash_context;
};

/* This symbol is NOT exported from the NSS DLL.  Code that needs a 
 * pointer to one of the SECHashObjects should call HASH_GetHashObject()
 * instead. See "sechash.h".
 */
extern const SECHashObject SECHashObjects[];

/* Only those functions below the PKCS #11 line should use SECRawHashObjects.
 * This symbol is not exported from the NSS DLL.
 */
extern const SECHashObject SECRawHashObjects[];

#endif /* _HASHT_H_ */
