/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <memory>
#include "nss.h"
#include "pk11pub.h"
#include "sechash.h"
#include "secerr.h"

#include "cpputil.h"
#include "nss_scoped_ptrs.h"

#include "testvectors/chachapoly-vectors.h"
#include "gtest/gtest.h"

namespace nss_test {

static const CK_MECHANISM_TYPE kMech = CKM_NSS_CHACHA20_POLY1305;
static const CK_MECHANISM_TYPE kMechXor = CKM_NSS_CHACHA20_CTR;
// Some test data for simple tests.
static const uint8_t kKeyData[32] = {'k'};
static const uint8_t kCtrNonce[16] = {'c', 0, 0, 0, 'n'};
static const uint8_t kData[16] = {'d'};

class Pkcs11ChaCha20Poly1305Test
    : public ::testing::TestWithParam<chaChaTestVector> {
 public:
  void EncryptDecrypt(const ScopedPK11SymKey& key, const bool invalidIV,
                      const bool invalidTag, const uint8_t* pt, size_t ptLen,
                      const uint8_t* aad, size_t aadLen, const uint8_t* iv,
                      size_t ivLen, const uint8_t* ct = nullptr,
                      size_t ctLen = 0) {
    // Prepare AEAD params.
    CK_NSS_AEAD_PARAMS aeadParams;
    aeadParams.pNonce = toUcharPtr(iv);
    aeadParams.ulNonceLen = ivLen;
    aeadParams.pAAD = toUcharPtr(aad);
    aeadParams.ulAADLen = aadLen;
    aeadParams.ulTagLen = 16;

    SECItem params = {siBuffer, reinterpret_cast<unsigned char*>(&aeadParams),
                      sizeof(aeadParams)};

    // Encrypt.
    unsigned int encryptedLen = 0;
    std::vector<uint8_t> encrypted(ptLen + aeadParams.ulTagLen);
    SECStatus rv = PK11_Encrypt(key.get(), kMech, &params, encrypted.data(),
                                &encryptedLen, encrypted.size(), pt, ptLen);

    // Return if encryption failure was expected due to invalid IV.
    // Without valid ciphertext, all further tests can be skipped.
    if (invalidIV) {
      EXPECT_EQ(rv, SECFailure);
      return;
    } else {
      EXPECT_EQ(rv, SECSuccess);
    }

    // Check ciphertext and tag.
    if (ct) {
      ASSERT_EQ(ctLen, encryptedLen);
      EXPECT_TRUE(!memcmp(ct, encrypted.data(), encryptedLen) != invalidTag);
    }

    // Get the *estimated* plaintext length. This value should
    // never be zero as it could lead to a NULL outPtr being
    // passed to a subsequent decryption call (for AEAD we
    // must authenticate even when the pt is zero-length).
    unsigned int decryptBytesNeeded = 0;
    rv = PK11_Decrypt(key.get(), kMech, &params, nullptr, &decryptBytesNeeded,
                      0, encrypted.data(), encryptedLen);
    EXPECT_EQ(rv, SECSuccess);
    EXPECT_GT(decryptBytesNeeded, ptLen);

    // Now decrypt it
    std::vector<uint8_t> decrypted(decryptBytesNeeded);
    unsigned int decryptedLen = 0;
    rv =
        PK11_Decrypt(key.get(), kMech, &params, decrypted.data(), &decryptedLen,
                     decrypted.size(), encrypted.data(), encryptedLen);
    EXPECT_EQ(rv, SECSuccess);

    // Check the plaintext.
    ASSERT_EQ(ptLen, decryptedLen);
    EXPECT_TRUE(!memcmp(pt, decrypted.data(), decryptedLen));

    // Decrypt with bogus data.
    // Skip if there's no data to modify.
    if (encryptedLen != 0) {
      std::vector<uint8_t> bogusCiphertext(encrypted);
      bogusCiphertext[0] ^= 0xff;
      rv = PK11_Decrypt(key.get(), kMech, &params, decrypted.data(),
                        &decryptedLen, decrypted.size(), bogusCiphertext.data(),
                        encryptedLen);
      EXPECT_NE(rv, SECSuccess);
    }

    // Decrypt with bogus tag.
    // Skip if there's no tag to modify.
    if (encryptedLen != 0) {
      std::vector<uint8_t> bogusTag(encrypted);
      bogusTag[encryptedLen - 1] ^= 0xff;
      rv = PK11_Decrypt(key.get(), kMech, &params, decrypted.data(),
                        &decryptedLen, decrypted.size(), bogusTag.data(),
                        encryptedLen);
      EXPECT_NE(rv, SECSuccess);
    }

    // Decrypt with bogus IV.
    // ivLen == 0 is invalid and should be caught earlier.
    // Still skip, if there's no IV to modify.
    if (ivLen != 0) {
      SECItem bogusParams(params);
      CK_NSS_AEAD_PARAMS bogusAeadParams(aeadParams);
      bogusParams.data = reinterpret_cast<unsigned char*>(&bogusAeadParams);

      std::vector<uint8_t> bogusIV(iv, iv + ivLen);
      bogusAeadParams.pNonce = toUcharPtr(bogusIV.data());
      bogusIV[0] ^= 0xff;

      rv = PK11_Decrypt(key.get(), kMech, &bogusParams, decrypted.data(),
                        &decryptedLen, ptLen, encrypted.data(), encryptedLen);
      EXPECT_NE(rv, SECSuccess);
    }

    // Decrypt with bogus additional data.
    // Skip when AAD was empty and can't be modified.
    // Alternatively we could generate random aad.
    if (aadLen != 0) {
      SECItem bogusParams(params);
      CK_NSS_AEAD_PARAMS bogusAeadParams(aeadParams);
      bogusParams.data = reinterpret_cast<unsigned char*>(&bogusAeadParams);

      std::vector<uint8_t> bogusAAD(aad, aad + aadLen);
      bogusAeadParams.pAAD = toUcharPtr(bogusAAD.data());
      bogusAAD[0] ^= 0xff;

      rv = PK11_Decrypt(key.get(), kMech, &bogusParams, decrypted.data(),
                        &decryptedLen, ptLen, encrypted.data(), encryptedLen);
      EXPECT_NE(rv, SECSuccess);
    }
  }

  void EncryptDecrypt(const chaChaTestVector testvector) {
    ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
    SECItem keyItem = {siBuffer, toUcharPtr(testvector.Key.data()),
                       static_cast<unsigned int>(testvector.Key.size())};

    // Import key.
    ScopedPK11SymKey key(PK11_ImportSymKey(slot.get(), kMech, PK11_OriginUnwrap,
                                           CKA_ENCRYPT, &keyItem, nullptr));
    EXPECT_TRUE(!!key);

    // Check.
    EncryptDecrypt(key, testvector.invalidIV, testvector.invalidTag,
                   testvector.Data.data(), testvector.Data.size(),
                   testvector.AAD.data(), testvector.AAD.size(),
                   testvector.IV.data(), testvector.IV.size(),
                   testvector.CT.data(), testvector.CT.size());
  }

 protected:
};

TEST_F(Pkcs11ChaCha20Poly1305Test, GenerateEncryptDecrypt) {
  // Generate a random key.
  ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
  ScopedPK11SymKey key(PK11_KeyGen(slot.get(), kMech, nullptr, 32, nullptr));
  EXPECT_TRUE(!!key);

  // Generate random data.
  std::vector<uint8_t> input(512);
  SECStatus rv =
      PK11_GenerateRandomOnSlot(slot.get(), input.data(), input.size());
  EXPECT_EQ(rv, SECSuccess);

  // Generate random AAD.
  std::vector<uint8_t> aad(16);
  rv = PK11_GenerateRandomOnSlot(slot.get(), aad.data(), aad.size());
  EXPECT_EQ(rv, SECSuccess);

  // Generate random IV.
  std::vector<uint8_t> iv(12);
  rv = PK11_GenerateRandomOnSlot(slot.get(), iv.data(), iv.size());
  EXPECT_EQ(rv, SECSuccess);

  // Check.
  EncryptDecrypt(key, false, false, input.data(), input.size(), aad.data(),
                 aad.size(), iv.data(), iv.size());
}

TEST_F(Pkcs11ChaCha20Poly1305Test, Xor) {
  static const uint8_t kExpected[sizeof(kData)] = {
      0xd8, 0x15, 0xd3, 0xb3, 0xe9, 0x34, 0x3b, 0x7a,
      0x24, 0xf6, 0x5f, 0xd7, 0x95, 0x3d, 0xd3, 0x51};

  ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
  SECItem keyItem = {siBuffer, toUcharPtr(kKeyData),
                     static_cast<unsigned int>(sizeof(kKeyData))};
  ScopedPK11SymKey key(PK11_ImportSymKey(
      slot.get(), kMechXor, PK11_OriginUnwrap, CKA_ENCRYPT, &keyItem, nullptr));
  EXPECT_TRUE(!!key);

  SECItem ctrNonceItem = {siBuffer, toUcharPtr(kCtrNonce),
                          static_cast<unsigned int>(sizeof(kCtrNonce))};
  uint8_t output[sizeof(kData)];
  unsigned int outputLen = 88;  // This should be overwritten.
  SECStatus rv = PK11_Encrypt(key.get(), kMechXor, &ctrNonceItem, output,
                              &outputLen, sizeof(output), kData, sizeof(kData));
  ASSERT_EQ(SECSuccess, rv);
  ASSERT_EQ(sizeof(kExpected), static_cast<size_t>(outputLen));
  EXPECT_EQ(0, memcmp(kExpected, output, sizeof(kExpected)));

  // Decrypting has the same effect.
  rv = PK11_Decrypt(key.get(), kMechXor, &ctrNonceItem, output, &outputLen,
                    sizeof(output), kData, sizeof(kData));
  ASSERT_EQ(SECSuccess, rv);
  ASSERT_EQ(sizeof(kData), static_cast<size_t>(outputLen));
  EXPECT_EQ(0, memcmp(kExpected, output, sizeof(kExpected)));

  // Operating in reverse too.
  rv = PK11_Encrypt(key.get(), kMechXor, &ctrNonceItem, output, &outputLen,
                    sizeof(output), kExpected, sizeof(kExpected));
  ASSERT_EQ(SECSuccess, rv);
  ASSERT_EQ(sizeof(kExpected), static_cast<size_t>(outputLen));
  EXPECT_EQ(0, memcmp(kData, output, sizeof(kData)));
}

// This test just ensures that a key can be generated for use with the XOR
// function.  The result is random and therefore cannot be checked.
TEST_F(Pkcs11ChaCha20Poly1305Test, GenerateXor) {
  ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
  ScopedPK11SymKey key(PK11_KeyGen(slot.get(), kMech, nullptr, 32, nullptr));
  EXPECT_TRUE(!!key);

  SECItem ctrNonceItem = {siBuffer, toUcharPtr(kCtrNonce),
                          static_cast<unsigned int>(sizeof(kCtrNonce))};
  uint8_t output[sizeof(kData)];
  unsigned int outputLen = 88;  // This should be overwritten.
  SECStatus rv = PK11_Encrypt(key.get(), kMechXor, &ctrNonceItem, output,
                              &outputLen, sizeof(output), kData, sizeof(kData));
  ASSERT_EQ(SECSuccess, rv);
  ASSERT_EQ(sizeof(kData), static_cast<size_t>(outputLen));
}

TEST_F(Pkcs11ChaCha20Poly1305Test, XorInvalidParams) {
  ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
  ScopedPK11SymKey key(PK11_KeyGen(slot.get(), kMech, nullptr, 32, nullptr));
  EXPECT_TRUE(!!key);

  SECItem ctrNonceItem = {siBuffer, toUcharPtr(kCtrNonce),
                          static_cast<unsigned int>(sizeof(kCtrNonce)) - 1};
  uint8_t output[sizeof(kData)];
  unsigned int outputLen = 88;
  SECStatus rv = PK11_Encrypt(key.get(), kMechXor, &ctrNonceItem, output,
                              &outputLen, sizeof(output), kData, sizeof(kData));
  EXPECT_EQ(SECFailure, rv);

  ctrNonceItem.data = nullptr;
  rv = PK11_Encrypt(key.get(), kMechXor, &ctrNonceItem, output, &outputLen,
                    sizeof(output), kData, sizeof(kData));
  EXPECT_EQ(SECFailure, rv);
  EXPECT_EQ(SEC_ERROR_BAD_DATA, PORT_GetError());
}

TEST_P(Pkcs11ChaCha20Poly1305Test, TestVectors) { EncryptDecrypt(GetParam()); }

INSTANTIATE_TEST_CASE_P(NSSTestVector, Pkcs11ChaCha20Poly1305Test,
                        ::testing::ValuesIn(kChaCha20Vectors));

INSTANTIATE_TEST_CASE_P(WycheproofTestVector, Pkcs11ChaCha20Poly1305Test,
                        ::testing::ValuesIn(kChaCha20WycheproofVectors));

}  // namespace nss_test
