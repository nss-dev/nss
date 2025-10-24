/*
 * SPDX-FileCopyrightText: 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: 667d2fc98984ff7f3df989c2367e6c1fa4a000e7
 * Eurydice: 2381cbc416ef2ad0b561c362c500bc84f36b6785
 * Karamel: 80f5435f2fc505973c469a4afcc8d875cddd0d8b
 * F*: 71d8221589d4d438af3706d89cb653cf53e18aab
 * Libcrux: 68dfed5a4a9e40277f62828471c029afed1ecdcc
 */

#ifndef libcrux_mlkem_portable_H
#define libcrux_mlkem_portable_H

#include "eurydice_glue.h"

#if defined(__cplusplus)
extern "C" {
#endif

void libcrux_ml_kem_hash_functions_portable_G(Eurydice_slice input,
                                              uint8_t ret[64U]);

void libcrux_ml_kem_hash_functions_portable_H(Eurydice_slice input,
                                              uint8_t ret[32U]);

#define LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR ((size_t)16U)

#define LIBCRUX_ML_KEM_VECTOR_TRAITS_MONTGOMERY_R_SQUARED_MOD_FIELD_MODULUS \
    ((int16_t)1353)

typedef struct libcrux_ml_kem_vector_portable_vector_type_PortableVector_s {
    int16_t elements[16U];
} libcrux_ml_kem_vector_portable_vector_type_PortableVector;

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_vector_type_zero(void);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_ZERO_b8(void);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_vector_type_from_i16_array(Eurydice_slice array);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_from_i16_array_b8(Eurydice_slice array);

void libcrux_ml_kem_vector_portable_vector_type_to_i16_array(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector x,
    int16_t ret[16U]);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
void libcrux_ml_kem_vector_portable_to_i16_array_b8(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector x,
    int16_t ret[16U]);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_vector_type_from_bytes(Eurydice_slice array);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_from_bytes_b8(Eurydice_slice array);

void libcrux_ml_kem_vector_portable_vector_type_to_bytes(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector x,
    Eurydice_slice bytes);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
void libcrux_ml_kem_vector_portable_to_bytes_b8(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector x,
    Eurydice_slice bytes);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_arithmetic_add(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector lhs,
    libcrux_ml_kem_vector_portable_vector_type_PortableVector *rhs);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_add_b8(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector lhs,
    libcrux_ml_kem_vector_portable_vector_type_PortableVector *rhs);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_arithmetic_sub(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector lhs,
    libcrux_ml_kem_vector_portable_vector_type_PortableVector *rhs);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_sub_b8(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector lhs,
    libcrux_ml_kem_vector_portable_vector_type_PortableVector *rhs);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_arithmetic_multiply_by_constant(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector vec, int16_t c);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_multiply_by_constant_b8(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector vec, int16_t c);

/**
 Note: This function is not secret independent
 Only use with public values.
*/
libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_arithmetic_cond_subtract_3329(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector vec);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_cond_subtract_3329_b8(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector v);

#define LIBCRUX_ML_KEM_VECTOR_PORTABLE_ARITHMETIC_BARRETT_MULTIPLIER \
    ((int32_t)20159)

#define LIBCRUX_ML_KEM_VECTOR_TRAITS_BARRETT_SHIFT ((int32_t)26)

#define LIBCRUX_ML_KEM_VECTOR_TRAITS_BARRETT_R \
    ((int32_t)1 << (uint32_t)LIBCRUX_ML_KEM_VECTOR_TRAITS_BARRETT_SHIFT)

#define LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_MODULUS ((int16_t)3329)

/**
 Signed Barrett Reduction

 Given an input `value`, `barrett_reduce` outputs a representative `result`
 such that:

 - result ≡ value (mod FIELD_MODULUS)
 - the absolute value of `result` is bound as follows:

 `|result| ≤ FIELD_MODULUS / 2 · (|value|/BARRETT_R + 1)

 Note: The input bound is 28296 to prevent overflow in the multiplication of
 quotient by FIELD_MODULUS

*/
int16_t libcrux_ml_kem_vector_portable_arithmetic_barrett_reduce_element(
    int16_t value);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_arithmetic_barrett_reduce(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector vec);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_barrett_reduce_b8(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector vector);

#define LIBCRUX_ML_KEM_VECTOR_TRAITS_INVERSE_OF_MODULUS_MOD_MONTGOMERY_R \
    (62209U)

#define LIBCRUX_ML_KEM_VECTOR_PORTABLE_ARITHMETIC_MONTGOMERY_SHIFT (16U)

/**
 Signed Montgomery Reduction

 Given an input `value`, `montgomery_reduce` outputs a representative `o`
 such that:

 - o ≡ value · MONTGOMERY_R^(-1) (mod FIELD_MODULUS)
 - the absolute value of `o` is bound as follows:

 `|result| ≤ ceil(|value| / MONTGOMERY_R) + 1665

 In particular, if `|value| ≤ FIELD_MODULUS-1 * FIELD_MODULUS-1`, then `|o| <=
 FIELD_MODULUS-1`. And, if `|value| ≤ pow2 16 * FIELD_MODULUS-1`, then `|o| <=
 FIELD_MODULUS + 1664

*/
int16_t libcrux_ml_kem_vector_portable_arithmetic_montgomery_reduce_element(
    int32_t value);

/**
 If `fe` is some field element 'x' of the Kyber field and `fer` is congruent to
 `y · MONTGOMERY_R`, this procedure outputs a value that is congruent to
 `x · y`, as follows:

    `fe · fer ≡ x · y · MONTGOMERY_R (mod FIELD_MODULUS)`

 `montgomery_reduce` takes the value `x · y · MONTGOMERY_R` and outputs a
 representative `x · y · MONTGOMERY_R * MONTGOMERY_R^{-1} ≡ x · y (mod
 FIELD_MODULUS)`.
*/
int16_t libcrux_ml_kem_vector_portable_arithmetic_montgomery_multiply_fe_by_fer(
    int16_t fe, int16_t fer);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_arithmetic_montgomery_multiply_by_constant(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector vec, int16_t c);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_montgomery_multiply_by_constant_b8(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector vector,
    int16_t constant);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_arithmetic_bitwise_and_with_constant(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector vec, int16_t c);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_arithmetic_to_unsigned_representative(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector a);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_to_unsigned_representative_b8(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector a);

/**
 The `compress_*` functions implement the `Compress` function specified in the
 NIST FIPS 203 standard (Page 18, Expression 4.5), which is defined as:

 ```plaintext
 Compress_d: ℤq -> ℤ_{2ᵈ}
 Compress_d(x) = ⌈(2ᵈ/q)·x⌋
 ```

 Since `⌈x⌋ = ⌊x + 1/2⌋` we have:

 ```plaintext
 Compress_d(x) = ⌊(2ᵈ/q)·x + 1/2⌋
               = ⌊(2^{d+1}·x + q) / 2q⌋
 ```

 For further information about the function implementations, consult the
 `implementation_notes.pdf` document in this directory.

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
uint8_t libcrux_ml_kem_vector_portable_compress_compress_message_coefficient(
    uint16_t fe);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_compress_compress_1(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector a);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_compress_1_b8(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector a);

uint32_t libcrux_ml_kem_vector_portable_arithmetic_get_n_least_significant_bits(
    uint8_t n, uint32_t value);

int16_t libcrux_ml_kem_vector_portable_compress_compress_ciphertext_coefficient(
    uint8_t coefficient_bits, uint16_t fe);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_compress_decompress_1(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector a);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_decompress_1_b8(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector a);

void libcrux_ml_kem_vector_portable_ntt_ntt_step(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector *vec,
    int16_t zeta, size_t i, size_t j);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_ntt_ntt_layer_1_step(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector vec,
    int16_t zeta0, int16_t zeta1, int16_t zeta2, int16_t zeta3);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_ntt_layer_1_step_b8(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector a, int16_t zeta0,
    int16_t zeta1, int16_t zeta2, int16_t zeta3);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_ntt_ntt_layer_2_step(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector vec,
    int16_t zeta0, int16_t zeta1);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_ntt_layer_2_step_b8(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector a, int16_t zeta0,
    int16_t zeta1);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_ntt_ntt_layer_3_step(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector vec,
    int16_t zeta);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_ntt_layer_3_step_b8(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector a, int16_t zeta);

void libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector *vec,
    int16_t zeta, size_t i, size_t j);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_ntt_inv_ntt_layer_1_step(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector vec,
    int16_t zeta0, int16_t zeta1, int16_t zeta2, int16_t zeta3);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_inv_ntt_layer_1_step_b8(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector a, int16_t zeta0,
    int16_t zeta1, int16_t zeta2, int16_t zeta3);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_ntt_inv_ntt_layer_2_step(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector vec,
    int16_t zeta0, int16_t zeta1);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_inv_ntt_layer_2_step_b8(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector a, int16_t zeta0,
    int16_t zeta1);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_ntt_inv_ntt_layer_3_step(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector vec,
    int16_t zeta);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_inv_ntt_layer_3_step_b8(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector a, int16_t zeta);

/**
 Compute the product of two Kyber binomials with respect to the
 modulus `X² - zeta`.

 This function almost implements <strong>Algorithm 11</strong> of the
 NIST FIPS 203 standard, which is reproduced below:

 ```plaintext
 Input:  a₀, a₁, b₀, b₁ ∈ ℤq.
 Input: γ ∈ ℤq.
 Output: c₀, c₁ ∈ ℤq.

 c₀ ← a₀·b₀ + a₁·b₁·γ
 c₁ ← a₀·b₁ + a₁·b₀
 return c₀, c₁
 ```
 We say "almost" because the coefficients output by this function are in
 the Montgomery domain (unlike in the specification).

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
void libcrux_ml_kem_vector_portable_ntt_ntt_multiply_binomials(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector *a,
    libcrux_ml_kem_vector_portable_vector_type_PortableVector *b, int16_t zeta,
    size_t i, libcrux_ml_kem_vector_portable_vector_type_PortableVector *out);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_ntt_ntt_multiply(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector *lhs,
    libcrux_ml_kem_vector_portable_vector_type_PortableVector *rhs,
    int16_t zeta0, int16_t zeta1, int16_t zeta2, int16_t zeta3);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_ntt_multiply_b8(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector *lhs,
    libcrux_ml_kem_vector_portable_vector_type_PortableVector *rhs,
    int16_t zeta0, int16_t zeta1, int16_t zeta2, int16_t zeta3);

void libcrux_ml_kem_vector_portable_serialize_serialize_1(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector v,
    uint8_t ret[2U]);

void libcrux_ml_kem_vector_portable_serialize_1(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector a,
    uint8_t ret[2U]);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
void libcrux_ml_kem_vector_portable_serialize_1_b8(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector a,
    uint8_t ret[2U]);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_serialize_deserialize_1(Eurydice_slice v);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_deserialize_1(Eurydice_slice a);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_deserialize_1_b8(Eurydice_slice a);

typedef struct uint8_t_x4_s {
    uint8_t fst;
    uint8_t snd;
    uint8_t thd;
    uint8_t f3;
} uint8_t_x4;

uint8_t_x4 libcrux_ml_kem_vector_portable_serialize_serialize_4_int(
    Eurydice_slice v);

void libcrux_ml_kem_vector_portable_serialize_serialize_4(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector v,
    uint8_t ret[8U]);

void libcrux_ml_kem_vector_portable_serialize_4(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector a,
    uint8_t ret[8U]);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
void libcrux_ml_kem_vector_portable_serialize_4_b8(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector a,
    uint8_t ret[8U]);

typedef struct int16_t_x8_s {
    int16_t fst;
    int16_t snd;
    int16_t thd;
    int16_t f3;
    int16_t f4;
    int16_t f5;
    int16_t f6;
    int16_t f7;
} int16_t_x8;

int16_t_x8 libcrux_ml_kem_vector_portable_serialize_deserialize_4_int(
    Eurydice_slice bytes);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_serialize_deserialize_4(Eurydice_slice bytes);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_deserialize_4(Eurydice_slice a);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_deserialize_4_b8(Eurydice_slice a);

typedef struct uint8_t_x5_s {
    uint8_t fst;
    uint8_t snd;
    uint8_t thd;
    uint8_t f3;
    uint8_t f4;
} uint8_t_x5;

uint8_t_x5 libcrux_ml_kem_vector_portable_serialize_serialize_5_int(
    Eurydice_slice v);

void libcrux_ml_kem_vector_portable_serialize_serialize_5(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector v,
    uint8_t ret[10U]);

void libcrux_ml_kem_vector_portable_serialize_5(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector a,
    uint8_t ret[10U]);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
void libcrux_ml_kem_vector_portable_serialize_5_b8(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector a,
    uint8_t ret[10U]);

int16_t_x8 libcrux_ml_kem_vector_portable_serialize_deserialize_5_int(
    Eurydice_slice bytes);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_serialize_deserialize_5(Eurydice_slice bytes);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_deserialize_5(Eurydice_slice a);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_deserialize_5_b8(Eurydice_slice a);

uint8_t_x5 libcrux_ml_kem_vector_portable_serialize_serialize_10_int(
    Eurydice_slice v);

void libcrux_ml_kem_vector_portable_serialize_serialize_10(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector v,
    uint8_t ret[20U]);

void libcrux_ml_kem_vector_portable_serialize_10(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector a,
    uint8_t ret[20U]);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
void libcrux_ml_kem_vector_portable_serialize_10_b8(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector a,
    uint8_t ret[20U]);

int16_t_x8 libcrux_ml_kem_vector_portable_serialize_deserialize_10_int(
    Eurydice_slice bytes);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_serialize_deserialize_10(Eurydice_slice bytes);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_deserialize_10(Eurydice_slice a);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_deserialize_10_b8(Eurydice_slice a);

typedef struct uint8_t_x11_s {
    uint8_t fst;
    uint8_t snd;
    uint8_t thd;
    uint8_t f3;
    uint8_t f4;
    uint8_t f5;
    uint8_t f6;
    uint8_t f7;
    uint8_t f8;
    uint8_t f9;
    uint8_t f10;
} uint8_t_x11;

uint8_t_x11 libcrux_ml_kem_vector_portable_serialize_serialize_11_int(
    Eurydice_slice v);

void libcrux_ml_kem_vector_portable_serialize_serialize_11(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector v,
    uint8_t ret[22U]);

void libcrux_ml_kem_vector_portable_serialize_11(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector a,
    uint8_t ret[22U]);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
void libcrux_ml_kem_vector_portable_serialize_11_b8(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector a,
    uint8_t ret[22U]);

int16_t_x8 libcrux_ml_kem_vector_portable_serialize_deserialize_11_int(
    Eurydice_slice bytes);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_serialize_deserialize_11(Eurydice_slice bytes);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_deserialize_11(Eurydice_slice a);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_deserialize_11_b8(Eurydice_slice a);

typedef struct uint8_t_x3_s {
    uint8_t fst;
    uint8_t snd;
    uint8_t thd;
} uint8_t_x3;

uint8_t_x3 libcrux_ml_kem_vector_portable_serialize_serialize_12_int(
    Eurydice_slice v);

void libcrux_ml_kem_vector_portable_serialize_serialize_12(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector v,
    uint8_t ret[24U]);

void libcrux_ml_kem_vector_portable_serialize_12(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector a,
    uint8_t ret[24U]);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
void libcrux_ml_kem_vector_portable_serialize_12_b8(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector a,
    uint8_t ret[24U]);

typedef struct int16_t_x2_s {
    int16_t fst;
    int16_t snd;
} int16_t_x2;

int16_t_x2 libcrux_ml_kem_vector_portable_serialize_deserialize_12_int(
    Eurydice_slice bytes);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_serialize_deserialize_12(Eurydice_slice bytes);

libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_deserialize_12(Eurydice_slice a);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_deserialize_12_b8(Eurydice_slice a);

size_t libcrux_ml_kem_vector_portable_sampling_rej_sample(
    Eurydice_slice a, Eurydice_slice result);

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
size_t libcrux_ml_kem_vector_portable_rej_sample_b8(Eurydice_slice a,
                                                    Eurydice_slice out);

/**
This function found in impl {core::clone::Clone for
libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
libcrux_ml_kem_vector_portable_vector_type_PortableVector
libcrux_ml_kem_vector_portable_vector_type_clone_9c(
    libcrux_ml_kem_vector_portable_vector_type_PortableVector *self);

#if defined(__cplusplus)
}
#endif

#define libcrux_mlkem_portable_H_DEFINED
#endif /* libcrux_mlkem_portable_H */
