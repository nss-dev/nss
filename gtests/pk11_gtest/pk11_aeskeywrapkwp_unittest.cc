/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <limits.h>
#include <memory>
#include "nss.h"
#include "pk11pub.h"

#include "testvectors/kw-vectors.h"
#include "gtest/gtest.h"
#include "nss_scoped_ptrs.h"
#include "json_reader.h"
#include "pk11_import.h"

extern std::string g_source_dir;

namespace nss_test {

class Pkcs11AESKeyWrapKwpTest
    : public ::testing::TestWithParam<keywrap_vector> {
 protected:
  CK_MECHANISM_TYPE mechanism = CKM_AES_KEY_WRAP_KWP;

  void WrapUnwrap(unsigned char* kek_data, unsigned int kek_len,
                  unsigned char* key_data, unsigned int key_data_len,
                  unsigned char* expected_ciphertext,
                  unsigned int expected_ciphertext_len,
                  std::map<Action, Result> tests, uint32_t test_id) {
    std::vector<unsigned char> wrapped_key(PR_MAX(1U, expected_ciphertext_len));
    std::vector<unsigned char> unwrapped_key(PR_MAX(1U, key_data_len));
    std::vector<unsigned char> zeros(PR_MAX(1U, expected_ciphertext_len), 0);
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
    ScopedPK11SymKey kek(nss_test::ImportSymKeyWithFlags(
        slot.get(), mechanism, PK11_OriginUnwrap, CKA_ENCRYPT, &kek_item,
        CKF_DECRYPT, PR_FALSE, nullptr));
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
};

TEST_F(Pkcs11AESKeyWrapKwpTest, TestVectors) {
  std::string testvectors =
      ::g_source_dir + "/../common/testvectors/kwp-vectors.json";
  JsonReader r(testvectors);

  r.NextItem();
  ASSERT_EQ("numberOfTests", r.ReadLabel());
  uint64_t expected_count = r.ReadInt();
  uint64_t count = 0;

  r.NextItem();
  ASSERT_EQ("tests", r.ReadLabel());

  while (r.NextItemArray()) {
    count++;
    keywrap_vector testvector;

    uint8_t seen = 0;
    while (r.NextItem()) {
      std::string n = r.ReadLabel();
      if (n == "tcId") {
        seen |= 1;
        testvector.test_id = r.ReadInt();
      } else if (n == "key") {
        seen |= 2;
        testvector.key = r.ReadHex();
      } else if (n == "msg") {
        seen |= 4;
        testvector.msg = r.ReadHex();
      } else if (n == "ct") {
        seen |= 8;
        testvector.ct = r.ReadHex();
      } else if (n == "wrapRv") {
        seen |= 16;
        testvector.tests[Action::WRAP].expect_rv = r.ReadSECStatus();
      } else if (n == "wrapMatch") {
        seen |= 32;
        testvector.tests[Action::WRAP].output_match = r.ReadBool();
      } else if (n == "unwrapRv") {
        seen |= 64;
        testvector.tests[Action::UNWRAP].expect_rv = r.ReadSECStatus();
      } else if (n == "unwrapMatch") {
        seen |= 128;
        testvector.tests[Action::UNWRAP].output_match = r.ReadBool();
      }
    }
    EXPECT_EQ(seen, 255);
    WrapUnwrap(testvector.key.data(), testvector.key.size(),
               testvector.msg.data(), testvector.msg.size(),
               testvector.ct.data(), testvector.ct.size(), testvector.tests,
               testvector.test_id);
  }
  EXPECT_EQ(count, expected_count);
}

// KWP (RFC 5649) uses a fixed built-in AIV; sftk_CryptInit must reject any
// non-NULL mechanism parameter to prevent an over-read in
// AESKeyWrap_InitContext.
TEST_F(Pkcs11AESKeyWrapKwpTest, NonNullParamIsRejected) {
  ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
  ASSERT_NE(nullptr, slot);
  ScopedPK11SymKey kek(
      PK11_KeyGen(slot.get(), CKM_AES_CBC, nullptr, 16, nullptr));
  ASSERT_NE(nullptr, kek);

  // A valid 8-byte IV — correct length for KW, but KWP must reject it entirely.
  unsigned char iv[8] = {0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6};
  SECItem param = {siBuffer, iv, sizeof(iv)};

  std::vector<unsigned char> plaintext(16, 0);
  std::vector<unsigned char> ciphertext(plaintext.size() + 16);
  unsigned int out_len = 0;

  SECStatus rv = PK11_Encrypt(
      kek.get(), CKM_AES_KEY_WRAP_KWP, &param, ciphertext.data(), &out_len,
      static_cast<unsigned int>(ciphertext.size()), plaintext.data(),
      static_cast<unsigned int>(plaintext.size()));
  EXPECT_EQ(SECFailure, rv);
}

TEST_F(Pkcs11AESKeyWrapKwpTest, WrapUnwrapUnalignedKeyLength) {
  ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
  ASSERT_NE(nullptr, slot);

  std::vector<unsigned char> kek_data(16, 0x5a);
  SECItem kek_item = {siBuffer, kek_data.data(),
                      static_cast<unsigned int>(kek_data.size())};
  ScopedPK11SymKey kek(nss_test::ImportSymKey(slot.get(), CKM_AES_KEY_WRAP_KWP,
                                              PK11_OriginUnwrap, CKA_WRAP,
                                              &kek_item, nullptr));
  ASSERT_NE(nullptr, kek);

  std::vector<unsigned char> key_data(20);
  for (size_t i = 0; i < key_data.size(); ++i) {
    key_data[i] = static_cast<unsigned char>(i + 1);
  }
  SECItem key_item = {siBuffer, key_data.data(),
                      static_cast<unsigned int>(key_data.size())};
  ScopedPK11SymKey key(nss_test::ImportSymKey(slot.get(), CKM_SHA_1_HMAC,
                                              PK11_OriginUnwrap, CKA_SIGN,
                                              &key_item, nullptr));
  ASSERT_NE(nullptr, key);

  std::vector<unsigned char> wrapped(64, 0);
  SECItem wrapped_item = {siBuffer, wrapped.data(),
                          static_cast<unsigned int>(wrapped.size())};
  ASSERT_EQ(SECSuccess, PK11_WrapSymKey(CKM_AES_KEY_WRAP_KWP, nullptr,
                                        kek.get(), key.get(), &wrapped_item));
  EXPECT_EQ(32U, wrapped_item.len);

  ScopedPK11SymKey unwrapped(PK11_UnwrapSymKey(kek.get(), CKM_AES_KEY_WRAP_KWP,
                                               nullptr, &wrapped_item,
                                               CKM_SHA_1_HMAC, CKA_SIGN, 0));
  ASSERT_NE(nullptr, unwrapped);
  ASSERT_EQ(SECSuccess, nss_test::ExtractKeyValue(unwrapped.get()));
  SECItem* value = nss_test::GetKeyData(unwrapped.get());
  ASSERT_NE(nullptr, value);

  EXPECT_EQ(key_data,
            std::vector<unsigned char>(value->data, value->data + value->len));
}

// Regression test for integer overflow in AESKeyWrap_EncryptKWP: when
// inputLen > UINT_MAX - (2 * AES_KEY_WRAP_BLOCK_SIZE - 1), paddedInputLen
// (which equals inputLen + padLen, see aeskeywrap.c:531) overflows and
// could allocate a smaller buffer than the PORT_Memcpy expects
TEST_F(Pkcs11AESKeyWrapKwpTest, OverflowingInputLenIsRejected) {
  ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
  ASSERT_NE(nullptr, slot);
  ScopedPK11SymKey kek(
      PK11_KeyGen(slot.get(), CKM_AES_CBC, nullptr, 16, nullptr));
  ASSERT_NE(nullptr, kek);

  std::vector<unsigned char> plaintext(16, 0xAB);
  std::vector<unsigned char> ciphertext(plaintext.size() + 16);
  unsigned int out_len = 0;

  SECStatus rv = PK11_Encrypt(
      kek.get(), CKM_AES_KEY_WRAP_KWP, nullptr, ciphertext.data(), &out_len,
      static_cast<unsigned int>(ciphertext.size()), plaintext.data(), UINT_MAX);
  EXPECT_EQ(SECFailure, rv);
}

}  // namespace nss_test
