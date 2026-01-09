/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef FREEBL_NO_DEPEND
#include "stubs.h"
#endif

#include "blapi.h"

#include "mpi.h"
#include "mpprime.h"
#include "secerr.h"
#include "secmpi.h"

mp_err
mpp_random_secure(mp_int *a)
{
    SECStatus rv;
    rv = RNG_GenerateGlobalRandomBytes((unsigned char *)MP_DIGITS(a), MP_USED(a) * sizeof(mp_digit));
    if (rv != SECSuccess) {
        return MP_UNDEF;
    }
    MP_SIGN(a) = MP_ZPOS;
    return MP_OKAY;
}

mp_err
mpp_pprime_secure(mp_int *a, int nt)
{
    return mpp_pprime_ext_random(a, nt, &mpp_random_secure);
}

mp_err
mpp_make_prime_secure(mp_int *start, mp_size nBits, mp_size strong)
{
    return mpp_make_prime_ext_random(start, nBits, strong, &mpp_random_secure);
}

/*
** Number of times to attempt to generate a prime (p or q) from a random
** seed (the seed changes for each iteration).
*/
#define MAX_PRIME_GEN_ATTEMPTS 10

SECStatus
generate_prime(mp_int *prime, int primeLen)
{
    mp_err err = MP_OKAY;
    SECStatus rv = SECSuccess;
    int piter;
    unsigned char *pb = NULL;
    pb = PORT_Alloc(primeLen);
    if (!pb) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        goto cleanup;
    }
    for (piter = 0; piter < MAX_PRIME_GEN_ATTEMPTS; piter++) {
        CHECK_SEC_OK(RNG_GenerateGlobalRandomBytes(pb, primeLen));
        pb[0] |= 0xC0;            /* set two high-order bits */
        pb[primeLen - 1] |= 0x01; /* set low-order bit       */
        CHECK_MPI_OK(mp_read_unsigned_octets(prime, pb, primeLen));
        err = mpp_make_prime_secure(prime, primeLen * 8, PR_FALSE);
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
