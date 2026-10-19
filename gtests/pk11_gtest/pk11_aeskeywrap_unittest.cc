/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <memory>
#include "nss.h"
#include "pk11pub.h"

#include "testvectors/kw-vectors.h"
#include "gtest/gtest.h"
#include "nss_scoped_ptrs.h"
#include "pk11_import.h"

namespace nss_test {

class Pkcs11AESKeyWrapTest : public ::testing::TestWithParam<keywrap_vector> {
 protected:
  CK_MECHANISM_TYPE mechanism = CKM_NSS_AES_KEY_WRAP;

  void WrapUnwrap(unsigned char* kek_data, unsigned int kek_len,
                  unsigned char* key_data, unsigned int key_data_len,
                  unsigned char* expected_ciphertext,
                  unsigned int expected_ciphertext_len,
                  std::map<Action, Result> tests, uint32_t test_id) {
    std::vector<unsigned char> wrapped_key(PR_MAX(1U, expected_ciphertext_len));
    std::vector<unsigned char> unwrapped_key(PR_MAX(1U, key_data_len));
    std::vector<unsigned char> zeros(PR_MAX(1U, expected_ciphertext_len));
    std::fill(zeros.begin(), zeros.end(), 0);
    unsigned int wrapped_key_len = 0;
    unsigned int unwrapped_key_len = 0;
    SECStatus rv;

    std::stringstream s;
    s << "Test with original ID #" << test_id << " failed." << std::endl;
    std::string msg = s.str();

    ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
    ASSERT_NE(nullptr, slot) << msg;

    // Import encryption key.
    SECItem kek_item = {siBuffer, kek_data, kek_len};
    ScopedPK11SymKey kek(nss_test::ImportSymKey(
        slot.get(), CKM_NSS_AES_KEY_WRAP, PK11_OriginUnwrap, CKA_ENCRYPT,
        &kek_item, nullptr));
    EXPECT_TRUE(!!kek) << msg;

    // Wrap key
    Action test = WRAP;
    if (tests.count(test)) {
      rv = PK11_Encrypt(kek.get(), mechanism, nullptr /* param */,
                        wrapped_key.data(), &wrapped_key_len,
                        wrapped_key.size(), key_data, key_data_len);
      ASSERT_EQ(rv, tests[test].expect_rv) << msg;

      // If we failed, check that output was not produced.
      if (rv == SECFailure) {
        EXPECT_TRUE(wrapped_key_len == 0);
        EXPECT_TRUE(!memcmp(wrapped_key.data(), zeros.data(), wrapped_key_len));
      }

      if (tests[test].output_match) {
        EXPECT_EQ(expected_ciphertext_len, wrapped_key_len) << msg;
        EXPECT_TRUE(!memcmp(expected_ciphertext, wrapped_key.data(),
                            expected_ciphertext_len))
            << msg;
      } else {
        // If we produced output, verify that it doesn't match the vector
        if (wrapped_key_len) {
          EXPECT_FALSE(wrapped_key_len == expected_ciphertext_len &&
                       !memcmp(wrapped_key.data(), expected_ciphertext,
                               expected_ciphertext_len))
              << msg;
        }
      }
    }

    // Unwrap key
    test = UNWRAP;
    if (tests.count(test)) {
      rv = PK11_Decrypt(kek.get(), mechanism, nullptr /* param */,
                        unwrapped_key.data(), &unwrapped_key_len,
                        unwrapped_key.size(), expected_ciphertext,
                        expected_ciphertext_len);
      ASSERT_EQ(rv, tests[test].expect_rv) << msg;

      // If we failed, check that output was not produced.
      if (rv == SECFailure) {
        EXPECT_TRUE(unwrapped_key_len == 0);
        EXPECT_TRUE(
            !memcmp(unwrapped_key.data(), zeros.data(), unwrapped_key_len));
      }

      if (tests[test].output_match) {
        EXPECT_EQ(unwrapped_key_len, key_data_len) << msg;
        EXPECT_TRUE(!memcmp(key_data, unwrapped_key.data(), key_data_len))
            << msg;
      } else {
        // If we produced output, verify that it doesn't match the vector
        if (unwrapped_key_len) {
          EXPECT_FALSE(
              unwrapped_key_len == expected_ciphertext_len &&
              !memcmp(unwrapped_key.data(), key_data, unwrapped_key_len))
              << msg;
        }
      }
    }
  }

  void WrapUnwrap(keywrap_vector testvector) {
    WrapUnwrap(testvector.key.data(), testvector.key.size(),
               testvector.msg.data(), testvector.msg.size(),
               testvector.ct.data(), testvector.ct.size(), testvector.tests,
               testvector.test_id);
  }
};

TEST_P(Pkcs11AESKeyWrapTest, TestVectors) { WrapUnwrap(GetParam()); }

INSTANTIATE_TEST_SUITE_P(Pkcs11WycheproofAESKWTest, Pkcs11AESKeyWrapTest,
                         ::testing::ValuesIn(kWycheproofAesKWVectors));

// Regression tests for a heap buffer over-read: AESKeyWrap_InitContext copies
// exactly 8 bytes (AES_KEY_WRAP_IV_BYTES) from the iv pointer unconditionally,
// so a pParameter buffer shorter than that would read past its end.
class Pkcs11AESKeyWrapIVParamTest
    : public ::testing::TestWithParam<CK_MECHANISM_TYPE> {
 protected:
  SECStatus TryEncryptMaybeDecrypt(SECItem* param, bool decrypt = false) {
    ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
    if (!slot) {
      return SECFailure;
    }
    ScopedPK11SymKey kek(
        PK11_KeyGen(slot.get(), CKM_AES_CBC, nullptr, 16, nullptr));
    if (!kek) {
      return SECFailure;
    }

    std::vector<unsigned char> plaintext = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                            0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                            0x0c, 0x0d, 0x0e, 0x0f};

    // Output size is plaintext + 8 (padding) + 8 KW Header
    std::vector<unsigned char> ciphertext(plaintext.size() + 16);
    unsigned int enc_len = 0;
    SECStatus rv = PK11_Encrypt(
        kek.get(), GetParam(), param, ciphertext.data(), &enc_len,
        static_cast<unsigned int>(ciphertext.size()), plaintext.data(),
        static_cast<unsigned int>(plaintext.size()));
    if (rv != SECSuccess || !decrypt) {
      return rv;
    }

    // PAD mechanisms need room for the intermediate
    // unwrapped-but-not-yet-unpadded result (plaintext + 8 padding bytes)
    // before stripping the padding. Then the dec_len result should point to the
    // correct decrypted buffer len.
    std::vector<unsigned char> decrypted(plaintext.size() + 8);
    unsigned int dec_len = 0;
    rv = PK11_Decrypt(kek.get(), GetParam(), param, decrypted.data(), &dec_len,
                      static_cast<unsigned int>(decrypted.size()),
                      ciphertext.data(), enc_len);
    if (rv != SECSuccess) {
      return rv;
    }

    EXPECT_EQ(plaintext.size(), dec_len);
    EXPECT_EQ(0, memcmp(plaintext.data(), decrypted.data(), dec_len));
    return rv;
  }
};

TEST_P(Pkcs11AESKeyWrapIVParamTest, ShortIVIsRejected) {
  // 2-byte IV — shorter than the required 8 bytes (AES_KEY_WRAP_IV_BYTES).
  unsigned char iv[2] = {0x01, 0x02};
  SECItem param = {siBuffer, iv, sizeof(iv)};
  EXPECT_EQ(SECFailure, TryEncryptMaybeDecrypt(&param));
}

TEST_P(Pkcs11AESKeyWrapIVParamTest, LongIVIsRejected) {
  // 9-byte IV — longer than the required 8 bytes (AES_KEY_WRAP_IV_BYTES).
  unsigned char iv[9] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};

  SECItem param = {siBuffer, iv, sizeof(iv)};
  EXPECT_EQ(SECFailure, TryEncryptMaybeDecrypt(&param));
}

TEST_P(Pkcs11AESKeyWrapIVParamTest, CorrectLengthIVIsAccepted) {
  // 8-byte custom IV — exactly AES_KEY_WRAP_IV_BYTES.
  unsigned char iv[8] = {0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6};
  SECItem param = {siBuffer, iv, sizeof(iv)};
  EXPECT_EQ(SECSuccess, TryEncryptMaybeDecrypt(&param, true));
}

INSTANTIATE_TEST_SUITE_P(AESKeyWrapMechanisms, Pkcs11AESKeyWrapIVParamTest,
                         ::testing::Values(CKM_NSS_AES_KEY_WRAP,
                                           CKM_NSS_AES_KEY_WRAP_PAD,
                                           CKM_AES_KEY_WRAP,
                                           CKM_AES_KEY_WRAP_PAD));
}  // namespace nss_test
