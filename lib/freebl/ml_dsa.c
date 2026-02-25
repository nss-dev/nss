/*
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef FREEBL_NO_DEPEND
#include "stubs.h"
#endif

#include "prerror.h"
#include "secerr.h"

#include "prtypes.h"
#include "prinit.h"
#include "blapi.h"
#include "secitem.h"
#include "blapit.h"
#include "secport.h"
#include "secrng.h"
#include "ml_dsat.h"

/* include other ml-dsa library specific includes here */

/* this is private to this function and can be changed at will */
struct MLDSAContextStr {
    PLArenaPool *arena;
    MLDSAPrivateKey *privKey;
    MLDSAPublicKey *pubKey;
    CK_HEDGE_TYPE hedgeType;
    CK_ML_DSA_PARAMETER_SET_TYPE paramSet;
    /* other ml-dsa lowelevel library require values and contexts */
};

/*
** Generate and return a new DSA public and private key pair,
**  both of which are encoded into a single DSAPrivateKey struct.
**  "params" is a pointer to the PQG parameters for the domain
**  Uses a random seed.
*/
SECStatus
MLDSA_NewKey(CK_ML_DSA_PARAMETER_SET_TYPE paramSet, SECItem *seed,
             MLDSAPrivateKey *privKey, MLDSAPublicKey *pubKey)
{
    /* needs to support returning the seed in the private key
     * (if seed is not supplied) or generating the key using the seed
     * (if it is supplied) if seed is supplied, it must be the correct
     * length */
    PORT_SetError(SEC_ERROR_INVALID_ARGS);
    return SECFailure;
}

/*
 * we don't have a streaming interace, so use our own local context
 * to keep track of things */
SECStatus
MLDSA_SignInit(MLDSAPrivateKey *key, CK_HEDGE_TYPE hedgeType,
               const SECItem *sgnCtx, MLDSAContext **ctx)
{
    /* if hedgeType is CKH_DETERMINISTIC_REQUIRED, otherwise it
     * should generate a HEDGE signature, can stash this value
     * if the library takes the hedge parameter in a later call */
    PORT_SetError(SEC_ERROR_INVALID_ARGS);
    return SECFailure;
}

SECStatus
MLDSA_SignUpdate(MLDSAContext *ctx, const SECItem *data)
{
    /* streaming interface. should not return a signature yet.
     * if the library can't do streaming, we need to buffer */
    PORT_SetError(SEC_ERROR_INVALID_ARGS);
    return SECFailure;
}

SECStatus
MLDSA_SignFinal(MLDSAContext *ctx, SECItem *signature)
{
    /* produce the actual signature, may need the key, so it needs to be
     * stashed in ML_DSA_SignInit */
    PORT_SetError(SEC_ERROR_INVALID_ARGS);
    return SECFailure;
}

/*
 * we don't have a streaming interace, so use our own local context
 * to keep track of things */
SECStatus
MLDSA_VerifyInit(MLDSAPublicKey *key, const SECItem *sgnCtx, MLDSAContext **ctx)
{
    PORT_SetError(SEC_ERROR_INVALID_ARGS);
    return SECFailure;
}

SECStatus
MLDSA_VerifyUpdate(MLDSAContext *ctx, const SECItem *data)
{
    /* like Sign, a streaming interface some rules about buffering */
    PORT_SetError(SEC_ERROR_INVALID_ARGS);
    return SECFailure;
}

SECStatus
MLDSA_VerifyFinal(MLDSAContext *ctx, const SECItem *signature)
{
    PORT_SetError(SEC_ERROR_INVALID_ARGS);
    return SECFailure;
}
