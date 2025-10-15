// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

#include "gtest/gtest.h"

#include "blapi.h"
#include "nss_scoped_ptrs.h"
#include "kat/kyber768_kat.h"
#include "testvectors_base/test-structs.h"
#include "testvectors/ml-kem-keygen-vectors.h"
#include "testvectors/ml-kem-encap-vectors.h"
#include "testvectors/ml-kem-decap-vectors.h"

namespace nss_test {

size_t get_ciphertext_length(KyberParams param) {
  size_t len = 0;
  switch (param) {
    case params_kyber768_round3:
    case params_kyber768_round3_test_mode:
    case params_ml_kem768:
    case params_ml_kem768_test_mode:
      len = KYBER768_CIPHERTEXT_BYTES;
      break;
    case params_ml_kem1024:
    case params_ml_kem1024_test_mode:
      len = MLKEM1024_CIPHERTEXT_BYTES;
      break;
    case params_kyber_invalid:
      break;
  }
  return len;
}

size_t get_private_key_length(KyberParams param) {
  size_t len = 0;
  switch (param) {
    case params_kyber768_round3:
    case params_kyber768_round3_test_mode:
    case params_ml_kem768:
    case params_ml_kem768_test_mode:
      len = KYBER768_PRIVATE_KEY_BYTES;
      break;
    case params_ml_kem1024:
    case params_ml_kem1024_test_mode:
      len = MLKEM1024_PRIVATE_KEY_BYTES;
      break;
    case params_kyber_invalid:
      break;
  }
  return len;
}

size_t get_public_key_length(KyberParams param) {
  size_t len = 0;
  switch (param) {
    case params_kyber768_round3:
    case params_kyber768_round3_test_mode:
    case params_ml_kem768:
    case params_ml_kem768_test_mode:
      len = KYBER768_PUBLIC_KEY_BYTES;
      break;
    case params_ml_kem1024:
    case params_ml_kem1024_test_mode:
      len = MLKEM1024_PUBLIC_KEY_BYTES;
      break;
    case params_kyber_invalid:
      break;
  }
  return len;
}

class KyberTest : public ::testing::Test {};

class KyberSelfTest : public KyberTest,
                      public ::testing::WithParamInterface<KyberParams> {};

TEST_P(KyberSelfTest, ConsistencyTest) {
  const KyberParams& param(GetParam());

  ScopedSECItem privateKey(
      SECITEM_AllocItem(nullptr, nullptr, MAX_ML_KEM_PRIVATE_KEY_LENGTH));
  ScopedSECItem publicKey(
      SECITEM_AllocItem(nullptr, nullptr, MAX_ML_KEM_PUBLIC_KEY_LENGTH));
  ScopedSECItem ciphertext(
      SECITEM_AllocItem(nullptr, nullptr, MAX_ML_KEM_CIPHER_LENGTH));
  ScopedSECItem secret(
      SECITEM_AllocItem(nullptr, nullptr, KYBER_SHARED_SECRET_BYTES));
  ScopedSECItem secret2(
      SECITEM_AllocItem(nullptr, nullptr, KYBER_SHARED_SECRET_BYTES));

  privateKey->len = get_private_key_length(param);
  publicKey->len = get_public_key_length(param);

  SECStatus rv =
      Kyber_NewKey(param, nullptr, privateKey.get(), publicKey.get());
  EXPECT_EQ(SECSuccess, rv);

  ciphertext->len = get_ciphertext_length(param);

  rv = Kyber_Encapsulate(param, nullptr, publicKey.get(), ciphertext.get(),
                         secret.get());
  EXPECT_EQ(SECSuccess, rv);

  rv = Kyber_Decapsulate(param, privateKey.get(), ciphertext.get(),
                         secret2.get());
  EXPECT_EQ(SECSuccess, rv);

  EXPECT_EQ(secret->len, KYBER_SHARED_SECRET_BYTES);
  EXPECT_EQ(secret2->len, KYBER_SHARED_SECRET_BYTES);
  EXPECT_EQ(0, memcmp(secret->data, secret2->data, KYBER_SHARED_SECRET_BYTES));
}

TEST_P(KyberSelfTest, InvalidParameterTest) {
  const KyberParams& param(GetParam());

  ScopedSECItem privateKey(
      SECITEM_AllocItem(nullptr, nullptr, MAX_ML_KEM_PRIVATE_KEY_LENGTH));
  ScopedSECItem publicKey(
      SECITEM_AllocItem(nullptr, nullptr, MAX_ML_KEM_PUBLIC_KEY_LENGTH));
  ScopedSECItem ciphertext(
      SECITEM_AllocItem(nullptr, nullptr, MAX_ML_KEM_CIPHER_LENGTH));
  ScopedSECItem secret(
      SECITEM_AllocItem(nullptr, nullptr, KYBER_SHARED_SECRET_BYTES));

  privateKey->len = get_private_key_length(param);
  publicKey->len = get_public_key_length(param);

  SECStatus rv = Kyber_NewKey(params_kyber_invalid, nullptr, privateKey.get(),
                              publicKey.get());
  EXPECT_EQ(SECFailure, rv);

  rv = Kyber_NewKey(param, nullptr, privateKey.get(), publicKey.get());
  EXPECT_EQ(SECSuccess, rv);

  ciphertext->len = get_ciphertext_length(param);

  rv = Kyber_Encapsulate(params_kyber_invalid, nullptr, publicKey.get(),
                         ciphertext.get(), secret.get());
  EXPECT_EQ(SECFailure, rv);

  rv = Kyber_Encapsulate(param, nullptr, publicKey.get(), ciphertext.get(),
                         secret.get());
  EXPECT_EQ(SECSuccess, rv);

  rv = Kyber_Decapsulate(params_kyber_invalid, privateKey.get(),
                         ciphertext.get(), secret.get());
  EXPECT_EQ(SECFailure, rv);

  rv = Kyber_Decapsulate(param, privateKey.get(), ciphertext.get(),
                         secret.get());
  EXPECT_EQ(SECSuccess, rv);
}

TEST_P(KyberSelfTest, InvalidPublicKeyTest) {
  const KyberParams& param(GetParam());

  ScopedSECItem shortBuffer(SECITEM_AllocItem(nullptr, nullptr, 7));
  ScopedSECItem privateKey(
      SECITEM_AllocItem(nullptr, nullptr, MAX_ML_KEM_PRIVATE_KEY_LENGTH));

  privateKey->len = get_private_key_length(param);

  SECStatus rv =
      Kyber_NewKey(param, nullptr, privateKey.get(), shortBuffer.get());
  EXPECT_EQ(SECFailure, rv);  // short publicKey buffer
}

TEST_P(KyberSelfTest, InvalidCiphertextTest) {
  const KyberParams& param(GetParam());

  ScopedSECItem shortBuffer(SECITEM_AllocItem(nullptr, nullptr, 7));
  ScopedSECItem privateKey(
      SECITEM_AllocItem(nullptr, nullptr, MAX_ML_KEM_PRIVATE_KEY_LENGTH));
  ScopedSECItem publicKey(
      SECITEM_AllocItem(nullptr, nullptr, MAX_ML_KEM_PUBLIC_KEY_LENGTH));
  ScopedSECItem ciphertext(
      SECITEM_AllocItem(nullptr, nullptr, MAX_ML_KEM_CIPHER_LENGTH));
  ScopedSECItem secret(
      SECITEM_AllocItem(nullptr, nullptr, KYBER_SHARED_SECRET_BYTES));
  ScopedSECItem secret2(
      SECITEM_AllocItem(nullptr, nullptr, KYBER_SHARED_SECRET_BYTES));

  privateKey->len = get_private_key_length(param);
  publicKey->len = get_public_key_length(param);

  SECStatus rv =
      Kyber_NewKey(param, nullptr, privateKey.get(), publicKey.get());
  EXPECT_EQ(SECSuccess, rv);

  ciphertext->len = get_ciphertext_length(param);

  rv = Kyber_Encapsulate(param, nullptr, publicKey.get(), shortBuffer.get(),
                         secret.get());
  EXPECT_EQ(SECFailure, rv);  // short ciphertext input

  rv = Kyber_Encapsulate(param, nullptr, publicKey.get(), ciphertext.get(),
                         secret.get());
  EXPECT_EQ(SECSuccess, rv);

  // Modify a random byte in the ciphertext
  size_t pos;
  rv = RNG_GenerateGlobalRandomBytes((uint8_t*)&pos, sizeof(pos));
  EXPECT_EQ(SECSuccess, rv);

  uint8_t byte;
  rv = RNG_GenerateGlobalRandomBytes((uint8_t*)&byte, sizeof(byte));
  EXPECT_EQ(SECSuccess, rv);

  size_t ct_len = get_ciphertext_length(param);
  EXPECT_EQ(ciphertext->len, ct_len);
  ciphertext->data[pos % ct_len] ^= (byte | 1);

  rv = Kyber_Decapsulate(param, privateKey.get(), ciphertext.get(),
                         secret2.get());
  EXPECT_EQ(SECSuccess, rv);

  EXPECT_EQ(secret->len, KYBER_SHARED_SECRET_BYTES);
  EXPECT_EQ(secret2->len, KYBER_SHARED_SECRET_BYTES);
  EXPECT_NE(0, memcmp(secret->data, secret2->data, KYBER_SHARED_SECRET_BYTES));
}

TEST_P(KyberSelfTest, InvalidPrivateKeyTest) {
  const KyberParams& param(GetParam());

  ScopedSECItem shortBuffer(SECITEM_AllocItem(nullptr, nullptr, 7));
  ScopedSECItem privateKey(
      SECITEM_AllocItem(nullptr, nullptr, MAX_ML_KEM_PRIVATE_KEY_LENGTH));
  ScopedSECItem publicKey(
      SECITEM_AllocItem(nullptr, nullptr, MAX_ML_KEM_PUBLIC_KEY_LENGTH));
  ScopedSECItem ciphertext(
      SECITEM_AllocItem(nullptr, nullptr, MAX_ML_KEM_CIPHER_LENGTH));
  ScopedSECItem secret(
      SECITEM_AllocItem(nullptr, nullptr, KYBER_SHARED_SECRET_BYTES));
  ScopedSECItem secret2(
      SECITEM_AllocItem(nullptr, nullptr, KYBER_SHARED_SECRET_BYTES));

  privateKey->len = get_private_key_length(param);
  publicKey->len = get_public_key_length(param);

  SECStatus rv =
      Kyber_NewKey(param, nullptr, shortBuffer.get(), publicKey.get());
  EXPECT_EQ(SECFailure, rv);  // short privateKey buffer

  rv = Kyber_NewKey(param, nullptr, privateKey.get(), publicKey.get());
  EXPECT_EQ(SECSuccess, rv);

  ciphertext->len = get_ciphertext_length(param);

  rv = Kyber_Encapsulate(param, nullptr, publicKey.get(), ciphertext.get(),
                         secret.get());
  EXPECT_EQ(SECSuccess, rv);

  // Modify a random byte in the private key
  size_t pos;
  rv = RNG_GenerateGlobalRandomBytes((uint8_t*)&pos, sizeof(pos));
  EXPECT_EQ(SECSuccess, rv);

  uint8_t byte;
  rv = RNG_GenerateGlobalRandomBytes((uint8_t*)&byte, sizeof(byte));
  EXPECT_EQ(SECSuccess, rv);

  // Modifying the implicit rejection key will not cause decapsulation failure.
  size_t pvk_len = get_private_key_length(param);
  size_t puk_len = get_public_key_length(param);
  EXPECT_EQ(privateKey->len, pvk_len);
  size_t ir_pos = pvk_len - (pos % KYBER_SHARED_SECRET_BYTES) - 1;
  uint8_t ir_pos_old = privateKey->data[ir_pos];
  privateKey->data[ir_pos] ^= (byte | 1);

  rv = Kyber_Decapsulate(param, privateKey.get(), ciphertext.get(),
                         secret2.get());
  EXPECT_EQ(SECSuccess, rv);

  EXPECT_EQ(secret->len, KYBER_SHARED_SECRET_BYTES);
  EXPECT_EQ(secret2->len, KYBER_SHARED_SECRET_BYTES);
  EXPECT_EQ(0, memcmp(secret->data, secret2->data, KYBER_SHARED_SECRET_BYTES));

  // Fix the private key
  privateKey->data[ir_pos] = ir_pos_old;

  // For ML-KEM when modifying the public key, the key must be rejected.
  // Kyber will decapsulate without an error in these cases
  size_t pk_pos = pvk_len - 2 * KYBER_SHARED_SECRET_BYTES - (pos % puk_len) - 1;
  uint8_t pk_pos_old = privateKey->data[pk_pos];
  privateKey->data[pk_pos] ^= (byte | 1);

  rv = Kyber_Decapsulate(param, privateKey.get(), ciphertext.get(),
                         secret2.get());
  if (param == params_kyber768_round3) {
    EXPECT_EQ(SECSuccess, rv);
  } else {
    EXPECT_EQ(SECFailure, rv);
  }

  // Fix the key again.
  privateKey->data[pk_pos] = pk_pos_old;

  // For ML-KEM when modifying the public key hash, the key must be rejected.
  // Kyber will decapsulate without an error in these cases
  size_t pk_hash_pos = pvk_len - KYBER_SHARED_SECRET_BYTES -
                       (pos % KYBER_SHARED_SECRET_BYTES) - 1;
  privateKey->data[pk_hash_pos] ^= (byte | 1);

  rv = Kyber_Decapsulate(param, privateKey.get(), ciphertext.get(),
                         secret2.get());
  if (param == params_kyber768_round3) {
    EXPECT_EQ(SECSuccess, rv);
  } else {
    EXPECT_EQ(SECFailure, rv);
  }
}

TEST_P(KyberSelfTest, DecapsulationWithModifiedRejectionKeyTest) {
  const KyberParams& param(GetParam());

  ScopedSECItem privateKey(
      SECITEM_AllocItem(nullptr, nullptr, MAX_ML_KEM_PRIVATE_KEY_LENGTH));
  ScopedSECItem publicKey(
      SECITEM_AllocItem(nullptr, nullptr, MAX_ML_KEM_PUBLIC_KEY_LENGTH));
  ScopedSECItem ciphertext(
      SECITEM_AllocItem(nullptr, nullptr, MAX_ML_KEM_CIPHER_LENGTH));
  ScopedSECItem secret(
      SECITEM_AllocItem(nullptr, nullptr, KYBER_SHARED_SECRET_BYTES));
  ScopedSECItem secret2(
      SECITEM_AllocItem(nullptr, nullptr, KYBER_SHARED_SECRET_BYTES));
  ScopedSECItem secret3(
      SECITEM_AllocItem(nullptr, nullptr, KYBER_SHARED_SECRET_BYTES));

  privateKey->len = get_private_key_length(param);
  publicKey->len = get_public_key_length(param);

  SECStatus rv =
      Kyber_NewKey(param, nullptr, privateKey.get(), publicKey.get());
  EXPECT_EQ(SECSuccess, rv);

  ciphertext->len = get_ciphertext_length(param);

  rv = Kyber_Encapsulate(param, nullptr, publicKey.get(), ciphertext.get(),
                         secret.get());
  EXPECT_EQ(SECSuccess, rv);

  // Modify a random byte in the ciphertext and decapsulate it
  size_t pos;
  rv = RNG_GenerateGlobalRandomBytes((uint8_t*)&pos, sizeof(pos));
  EXPECT_EQ(SECSuccess, rv);

  uint8_t byte;
  rv = RNG_GenerateGlobalRandomBytes((uint8_t*)&byte, sizeof(byte));
  EXPECT_EQ(SECSuccess, rv);

  size_t ct_len = get_ciphertext_length(param);
  EXPECT_EQ(ciphertext->len, ct_len);
  ciphertext->data[pos % ct_len] ^= (byte | 1);

  rv = Kyber_Decapsulate(param, privateKey.get(), ciphertext.get(),
                         secret2.get());
  EXPECT_EQ(SECSuccess, rv);

  // Now, modify a random byte in the implicit rejection key and try
  // the decapsulation again. The result should be different.
  rv = RNG_GenerateGlobalRandomBytes((uint8_t*)&pos, sizeof(pos));
  EXPECT_EQ(SECSuccess, rv);

  rv = RNG_GenerateGlobalRandomBytes((uint8_t*)&byte, sizeof(byte));
  EXPECT_EQ(SECSuccess, rv);

  size_t pvk_len = get_private_key_length(param);
  pos =
      (pvk_len - KYBER_SHARED_SECRET_BYTES) + (pos % KYBER_SHARED_SECRET_BYTES);
  EXPECT_EQ(privateKey->len, pvk_len);
  privateKey->data[pos] ^= (byte | 1);

  rv = Kyber_Decapsulate(param, privateKey.get(), ciphertext.get(),
                         secret3.get());
  EXPECT_EQ(SECSuccess, rv);

  EXPECT_EQ(secret2->len, KYBER_SHARED_SECRET_BYTES);
  EXPECT_EQ(secret3->len, KYBER_SHARED_SECRET_BYTES);
  EXPECT_NE(0, memcmp(secret2->data, secret3->data, KYBER_SHARED_SECRET_BYTES));
}

#ifdef NSS_DISABLE_KYBER
INSTANTIATE_TEST_SUITE_P(SelfTests, KyberSelfTest,
                         ::testing::Values(params_ml_kem768,
                                           params_ml_kem1024));
#else
INSTANTIATE_TEST_SUITE_P(SelfTests, KyberSelfTest,
                         ::testing::Values(params_ml_kem768, params_ml_kem1024,
                                           params_kyber768_round3));
#endif

TEST(Kyber768Test, KnownAnswersTest) {
  ScopedSECItem privateKey(
      SECITEM_AllocItem(nullptr, nullptr, MAX_ML_KEM_PRIVATE_KEY_LENGTH));
  ScopedSECItem publicKey(
      SECITEM_AllocItem(nullptr, nullptr, MAX_ML_KEM_PUBLIC_KEY_LENGTH));
  ScopedSECItem ciphertext(
      SECITEM_AllocItem(nullptr, nullptr, MAX_ML_KEM_CIPHER_LENGTH));
  ScopedSECItem secret(
      SECITEM_AllocItem(nullptr, nullptr, KYBER_SHARED_SECRET_BYTES));
  ScopedSECItem secret2(
      SECITEM_AllocItem(nullptr, nullptr, KYBER_SHARED_SECRET_BYTES));

  SECStatus rv;
  uint8_t digest[SHA256_LENGTH];

  for (const auto& kat : KyberKATs) {
    SECItem keypair_seed = {siBuffer, (unsigned char*)kat.newKeySeed,
                            sizeof kat.newKeySeed};
    SECItem enc_seed = {siBuffer, (unsigned char*)kat.encapsSeed,
                        sizeof kat.encapsSeed};

    privateKey->len = get_private_key_length(kat.params);
    publicKey->len = get_public_key_length(kat.params);
    ciphertext->len = get_ciphertext_length(kat.params);

    rv = Kyber_NewKey(kat.params, &keypair_seed, privateKey.get(),
                      publicKey.get());
    EXPECT_EQ(SECSuccess, rv);

    SHA256_HashBuf(digest, privateKey->data, privateKey->len);
    EXPECT_EQ(0, memcmp(kat.privateKeyDigest, digest, sizeof digest));

    SHA256_HashBuf(digest, publicKey->data, publicKey->len);
    EXPECT_EQ(0, memcmp(kat.publicKeyDigest, digest, sizeof digest));

    rv = Kyber_Encapsulate(kat.params, &enc_seed, publicKey.get(),
                           ciphertext.get(), secret.get());
    EXPECT_EQ(SECSuccess, rv);

    SHA256_HashBuf(digest, ciphertext->data, ciphertext->len);
    EXPECT_EQ(0, memcmp(kat.ciphertextDigest, digest, sizeof digest));

    EXPECT_EQ(secret->len, KYBER_SHARED_SECRET_BYTES);
    EXPECT_EQ(0, memcmp(kat.secret, secret->data, secret->len));

    rv = Kyber_Decapsulate(kat.params, privateKey.get(), ciphertext.get(),
                           secret2.get());
    EXPECT_EQ(SECSuccess, rv);
    EXPECT_EQ(secret2->len, KYBER_SHARED_SECRET_BYTES);
    EXPECT_EQ(0, memcmp(secret->data, secret2->data, secret2->len));
  }
}

TEST(MlKemKeyGen, KnownAnswersTest) {
  ScopedSECItem privateKey(
      SECITEM_AllocItem(nullptr, nullptr, MAX_ML_KEM_PRIVATE_KEY_LENGTH));
  ScopedSECItem publicKey(
      SECITEM_AllocItem(nullptr, nullptr, MAX_ML_KEM_PUBLIC_KEY_LENGTH));

  uint8_t digest[SHA3_256_LENGTH];

  for (const auto& kat : MlKemKeyGenTests) {
    SECItem keypair_seed = {siBuffer, (unsigned char*)kat.seed.data(),
                            (unsigned int)kat.seed.size()};

    privateKey->len = get_private_key_length(kat.params);
    publicKey->len = get_public_key_length(kat.params);

    SECStatus rv = Kyber_NewKey(kat.params, &keypair_seed, privateKey.get(),
                                publicKey.get());
    EXPECT_EQ(SECSuccess, rv);

    rv = SHA3_256_HashBuf(digest, privateKey->data, privateKey->len);
    EXPECT_EQ(SECSuccess, rv);
    EXPECT_EQ(kat.privateKeyDigest.size(), sizeof(digest));
    EXPECT_EQ(0, memcmp(kat.privateKeyDigest.data(), digest, sizeof(digest)));

    rv = SHA3_256_HashBuf(digest, publicKey->data, publicKey->len);
    EXPECT_EQ(SECSuccess, rv);
    EXPECT_EQ(kat.publicKeyDigest.size(), sizeof(digest));
    EXPECT_EQ(0, memcmp(kat.publicKeyDigest.data(), digest, sizeof(digest)));
    break;
  }
}

TEST(MlKemEncap, KnownAnswersTest) {
  ScopedSECItem ciphertext(
      SECITEM_AllocItem(nullptr, nullptr, MAX_ML_KEM_CIPHER_LENGTH));
  ScopedSECItem secret(
      SECITEM_AllocItem(nullptr, nullptr, KYBER_SHARED_SECRET_BYTES));

  uint8_t digest[SHA3_256_LENGTH];

  for (const auto& kat : MlKemEncapTests) {
    SECItem seed = {siBuffer, (unsigned char*)kat.entropy.data(),
                    (unsigned int)kat.entropy.size()};
    SECItem publicKey = {siBuffer, (unsigned char*)kat.publicKey.data(),
                         (unsigned int)kat.publicKey.size()};

    ciphertext->len = get_ciphertext_length(kat.params);

    // Only valid tests for now
    EXPECT_TRUE(kat.expectedResult);

    SECStatus rv = Kyber_Encapsulate(kat.params, &seed, &publicKey,
                                     ciphertext.get(), secret.get());
    EXPECT_EQ(SECSuccess, rv);

    rv = SHA3_256_HashBuf(digest, ciphertext->data, ciphertext->len);
    EXPECT_EQ(SECSuccess, rv);
    EXPECT_EQ(kat.cipherTextDigest.size(), sizeof(digest));
    EXPECT_EQ(0, memcmp(kat.cipherTextDigest.data(), digest, sizeof(digest)));

    EXPECT_EQ(kat.secret.size(), secret->len);
    EXPECT_EQ(0, memcmp(kat.secret.data(), secret->data, secret->len));
  }
}

TEST(MlKemDecap, KnownAnswersTest) {
  ScopedSECItem secret(
      SECITEM_AllocItem(nullptr, nullptr, KYBER_SHARED_SECRET_BYTES));

  for (const auto& kat : MlKemDecapTests) {
    SECItem ciphertext = {siBuffer, (unsigned char*)kat.cipherText.data(),
                          (unsigned int)kat.cipherText.size()};
    SECItem privateKey = {siBuffer, (unsigned char*)kat.privateKey.data(),
                          (unsigned int)kat.privateKey.size()};

    // Only valid tests for now
    EXPECT_TRUE(kat.expectedResult);

    SECStatus rv =
        Kyber_Decapsulate(kat.params, &privateKey, &ciphertext, secret.get());
    EXPECT_EQ(SECSuccess, rv);
    EXPECT_EQ(secret->len, KYBER_SHARED_SECRET_BYTES);
    EXPECT_EQ(
        0, memcmp(secret->data, kat.secret.data(), KYBER_SHARED_SECRET_BYTES));
  }
}

}  // namespace nss_test
