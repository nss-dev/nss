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

/* This file uses macros to convert MPI calls in freebl to 
   equivalent calls in TomsFastMath.  */

#ifndef _TFM_MPI_H_
#define _TFM_MPI_H_

#include "tfm.h"

/* return codes */
#define MP_OKAY FP_OKAY
#define MP_VAL  FP_VAL
#define MP_MEM     FP_MEM
#define MP_RANGE   FP_VAL
#define MP_BADARG  FP_VAL
#define MP_UNDEF   FP_VAL
/* this last value is important because invmod returns FP_VAL
 * or MP_UNDEF, which is checked in rsa_keygen_from_primes.
 */

#define MP_ZPOS FP_ZPOS
#define MP_NEG  FP_NEG
#define MP_LT   FP_LT
#define MP_EQ   FP_EQ
#define MP_GT   FP_GT
#define MP_YES  FP_YES
#define MP_NO   FP_NO

typedef int mp_err;
typedef unsigned long  mp_digit;
#define MP_DIGIT_MAX   ULONG_MAX

/* MPI has a pointer to alloc'ed memory for its bignum, while TFM does not.
 * This macro should do nothing because it is used to null the bignum pointer. 
 */
int garbage = 0;
#define MP_DIGITS(x)  garbage

/* Yuk... CHECK_MPI_OK would often check functions in TFM that do nothing.
 * Unfortunately, we can't assign a void type to rv or err.  Therefore, make
 * the macro a no-op.  This may hurt us later.
 */
#define CHECK_MPI_OK(x) x

#define mp_int fp_int

#define mp_init      fp_init
#define mp_set       fp_set
#define mp_clear     fp_init
#define mp_copy      fp_copy
#define mp_set_ulong fp_set
#define mp_exch      fp_exch

#define mp_add     fp_add
#define mp_sub     fp_sub
#define mp_mul     fp_mul
#define mp_cmp     fp_cmp

#define mp_add_d   fp_add_d
#define mp_sub_d   fp_sub_d
#define mp_cmp_d   fp_cmp_d

#define mp_div_2   fp_div_2
#define mp_div_2d  fp_div_2d

#define mp_mod     fp_mod
#define mp_addmod  fp_addmod
#define mp_submod  fp_submod
#define mp_mulmod  fp_mulmod
#define mp_invmod  fp_invmod
#define mp_exptmod fp_exptmod

#define mp_gcd     fp_gcd

#define mpl_significant_bits fp_count_bits
#define mp_unsigned_octet_size fp_unsigned_bin_size
#define mp_read_unsigned_octets(a, b, c) MP_OKAY; \
        fp_read_unsigned_bin(a, (unsigned char *) b, c)
#define mp_to_unsigned_octets(a, b, c) MP_OKAY; \
        fp_to_unsigned_bin(a, (unsigned char *) b)
#define mp_to_fixlen_octets fp_to_fixlen_octets

/* Begin ugly MP-to-FP macros */

#define CHECK_MP_OK(func) if (FP_OKAY < (err = func)) goto cleanup

#define CHECK_SEC_OK(func) if (SECSuccess != (rv = func)) goto cleanup

#define SECITEM_TO_MPINT(it, mp) \
    fp_read_unsigned_bin((mp), (unsigned char *)(it).data, (it).len)

#define MP_TO_SEC_ERROR(err) \
    switch(err) { \
    case FP_MEM:    PORT_SetError(SEC_ERROR_NO_MEMORY);       break;  \
    case FP_VAL:    PORT_SetError(SEC_ERROR_BAD_DATA);        break;  \
    default:        PORT_SetError(SEC_ERROR_LIBRARY_FAILURE); break;  \
    }

#define OCTETS_TO_MPINT(oc, mp, len) \
    fp_read_unsigned_bin(mp, (unsigned char *)oc, len)


#endif /* end _TFM_MPI_H_ */
