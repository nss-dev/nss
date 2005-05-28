/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Netscape security libraries.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 1994-2000
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

/* These keygen functions have been removed from rsa.c and placed here
 * to avoid rewriting for platforms that use TFM for other RSA operations.
 * Therefore, this file uses only MPI on all platforms.
 */

#include "secerr.h"
#include "prclist.h"
#include "nssilock.h"
#include "prinit.h"
#include "blapi.h"
#include "mpi.h"
#include "mpprime.h"
#include "mplogic.h"
#include "secmpi.h"
#include "secitem.h"

/*
** Number of times to attempt to generate a prime (p or q) from a random
** seed (the seed changes for each iteration).
*/
#define MAX_PRIME_GEN_ATTEMPTS 10

/*
** Number of times to attempt to generate a key.  The primes p and q change
** for each attempt.
*/
#define MAX_KEY_GEN_ATTEMPTS 10

static SECStatus
rsa_keygen_from_primes(mp_int *p, mp_int *q, mp_int *e, RSAPrivateKey *key,
                       unsigned int keySizeInBits)
{
    mp_int n, d, phi;
    mp_int psub1, qsub1, tmp;
    mp_err   err = MP_OKAY;
    SECStatus rv = SECSuccess;
    MP_DIGITS(&n)     = 0;
    MP_DIGITS(&d)     = 0;
    MP_DIGITS(&phi)   = 0;
    MP_DIGITS(&psub1) = 0;
    MP_DIGITS(&qsub1) = 0;
    MP_DIGITS(&tmp)   = 0;
    CHECK_MPI_OK( mp_init(&n)     );
    CHECK_MPI_OK( mp_init(&d)     );
    CHECK_MPI_OK( mp_init(&phi)   );
    CHECK_MPI_OK( mp_init(&psub1) );
    CHECK_MPI_OK( mp_init(&qsub1) );
    CHECK_MPI_OK( mp_init(&tmp)   );
    /* 1.  Compute n = p*q */
    CHECK_MPI_OK( mp_mul(p, q, &n) );
    /*     verify that the modulus has the desired number of bits */
    if ((unsigned)mpl_significant_bits(&n) != keySizeInBits) {
	PORT_SetError(SEC_ERROR_NEED_RANDOM);
	rv = SECFailure;
	goto cleanup;
    }
    /* 2.  Compute phi = (p-1)*(q-1) */
    CHECK_MPI_OK( mp_sub_d(p, 1, &psub1) );
    CHECK_MPI_OK( mp_sub_d(q, 1, &qsub1) );
    CHECK_MPI_OK( mp_mul(&psub1, &qsub1, &phi) );
    /* 3.  Compute d = e**-1 mod(phi) */
    err = mp_invmod(e, &phi, &d);
    /*     Verify that phi(n) and e have no common divisors */
    if (err != MP_OKAY) {
	if (err == MP_UNDEF) {
	    PORT_SetError(SEC_ERROR_NEED_RANDOM);
	    err = MP_OKAY; /* to keep PORT_SetError from being called again */
	    rv = SECFailure;
	}
	goto cleanup;
    }
    MPINT_TO_SECITEM(&n, &key->modulus, key->arena);
    MPINT_TO_SECITEM(&d, &key->privateExponent, key->arena);
    /* 4.  Compute exponent1 = d mod (p-1) */
    CHECK_MPI_OK( mp_mod(&d, &psub1, &tmp) );
    MPINT_TO_SECITEM(&tmp, &key->exponent1, key->arena);
    /* 5.  Compute exponent2 = d mod (q-1) */
    CHECK_MPI_OK( mp_mod(&d, &qsub1, &tmp) );
    MPINT_TO_SECITEM(&tmp, &key->exponent2, key->arena);
    /* 6.  Compute coefficient = q**-1 mod p */
    CHECK_MPI_OK( mp_invmod(q, p, &tmp) );
    MPINT_TO_SECITEM(&tmp, &key->coefficient, key->arena);
cleanup:
    mp_clear(&n);
    mp_clear(&d);
    mp_clear(&phi);
    mp_clear(&psub1);
    mp_clear(&qsub1);
    mp_clear(&tmp);
    if (err) {
	MP_TO_SEC_ERROR(err);
	rv = SECFailure;
    }
    return rv;
}
static SECStatus
generate_prime(mp_int *prime, int primeLen)
{
    mp_err   err = MP_OKAY;
    SECStatus rv = SECSuccess;
    unsigned long counter = 0;
    int piter;
    unsigned char *pb = NULL;
    pb = PORT_Alloc(primeLen);
    if (!pb) {
	PORT_SetError(SEC_ERROR_NO_MEMORY);
	goto cleanup;
    }
    for (piter = 0; piter < MAX_PRIME_GEN_ATTEMPTS; piter++) {
	CHECK_SEC_OK( RNG_GenerateGlobalRandomBytes(pb, primeLen) );
	pb[0]          |= 0xC0; /* set two high-order bits */
	pb[primeLen-1] |= 0x01; /* set low-order bit       */
	CHECK_MPI_OK( mp_read_unsigned_octets(prime, pb, primeLen) );
	err = mpp_make_prime(prime, primeLen * 8, PR_FALSE, &counter);
	if (err != MP_NO)
	    goto cleanup;
	/* keep going while err == MP_NO */
    }
cleanup:
    if (pb)
	PORT_ZFree(pb, primeLen);
    if (err) {
	MP_TO_SEC_ERROR(err);
	rv = SECFailure;
    }
    return rv;
}

/*
** Generate and return a new RSA public and private key.
**	Both keys are encoded in a single RSAPrivateKey structure.
**	"cx" is the random number generator context
**	"keySizeInBits" is the size of the key to be generated, in bits.
**	   512, 1024, etc.
**	"publicExponent" when not NULL is a pointer to some data that
**	   represents the public exponent to use. The data is a byte
**	   encoded integer, in "big endian" order.
*/
RSAPrivateKey *
RSA_NewKey(int keySizeInBits, SECItem *publicExponent)
{
    unsigned int primeLen;
    mp_int p, q, e;
    int kiter;
    mp_err   err = MP_OKAY;
    SECStatus rv = SECSuccess;
    int prerr = 0;
    RSAPrivateKey *key = NULL;
    PRArenaPool *arena = NULL;
    /* Require key size to be a multiple of 16 bits. */
    if (!publicExponent || keySizeInBits % 16 != 0) {
	PORT_SetError(SEC_ERROR_INVALID_ARGS);
	return NULL;
    }
    /* 1. Allocate arena & key */
    arena = PORT_NewArena(NSS_FREEBL_DEFAULT_CHUNKSIZE);
    if (!arena) {
	PORT_SetError(SEC_ERROR_NO_MEMORY);
	return NULL;
    }
    key = (RSAPrivateKey *)PORT_ArenaZAlloc(arena, sizeof(RSAPrivateKey));
    if (!key) {
	PORT_SetError(SEC_ERROR_NO_MEMORY);
	PORT_FreeArena(arena, PR_TRUE);
	return NULL;
    }
    key->arena = arena;
    /* length of primes p and q (in bytes) */
    primeLen = keySizeInBits / (2 * BITS_PER_BYTE);
    MP_DIGITS(&p) = 0;
    MP_DIGITS(&q) = 0;
    MP_DIGITS(&e) = 0;
    CHECK_MPI_OK( mp_init(&p) );
    CHECK_MPI_OK( mp_init(&q) );
    CHECK_MPI_OK( mp_init(&e) );
    /* 2.  Set the version number (PKCS1 v1.5 says it should be zero) */
    SECITEM_AllocItem(arena, &key->version, 1);
    key->version.data[0] = 0;
    /* 3.  Set the public exponent */
    SECITEM_CopyItem(arena, &key->publicExponent, publicExponent);
    SECITEM_TO_MPINT(*publicExponent, &e);
    kiter = 0;
    do {
	prerr = 0;
	PORT_SetError(0);
	CHECK_SEC_OK( generate_prime(&p, primeLen) );
	CHECK_SEC_OK( generate_prime(&q, primeLen) );
	/* Assure q < p */
	if (mp_cmp(&p, &q) < 0)
	    mp_exch(&p, &q);
	/* Attempt to use these primes to generate a key */
	rv = rsa_keygen_from_primes(&p, &q, &e, key, keySizeInBits);
	if (rv == SECSuccess)
	    break; /* generated two good primes */
	prerr = PORT_GetError();
	kiter++;
	/* loop until have primes */
    } while (prerr == SEC_ERROR_NEED_RANDOM && kiter < MAX_KEY_GEN_ATTEMPTS);
    if (prerr)
	goto cleanup;
    MPINT_TO_SECITEM(&p, &key->prime1, arena);
    MPINT_TO_SECITEM(&q, &key->prime2, arena);
cleanup:
    mp_clear(&p);
    mp_clear(&q);
    mp_clear(&e);
    if (err) {
	MP_TO_SEC_ERROR(err);
	rv = SECFailure;
    }
    if (rv && arena) {
	PORT_FreeArena(arena, PR_TRUE);
	key = NULL;
    }
    return key;
}
