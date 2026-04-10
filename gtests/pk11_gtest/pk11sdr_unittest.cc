/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/* vim: set ts=4 et sw=4 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "gtest/gtest.h"
#include "nss.h"
#include "nss_scoped_ptrs.h"
#include "pk11sdr.h"
#include "prerror.h"

namespace nss_test {

class PK11SDRTest : public ::testing::Test {
 public:
  void SetUp() override {
    // Ensure there exists an AES key in the default key slot.
    ScopedPK11SlotInfo slot(PK11_GetInternalKeySlot());
    ASSERT_NE(slot.get(), nullptr);
    SECItem keyid = {siBuffer, nullptr, 0};
    unsigned char plaintextBytes[] = {'a', 'b', 'c'};
    SECItem plaintext = {siBuffer, &plaintextBytes[0], sizeof(plaintextBytes)};
    StackSECItem ciphertext;
    SECStatus rv = PK11SDR_EncryptWithMechanism(
        slot.get(), &keyid, CKM_AES_CBC, &plaintext, &ciphertext, nullptr);
    ASSERT_EQ(rv, SECSuccess);
  }
};

const std::vector<uint8_t> kUnsupportedAlgorithmDER = {
    0x30, 0x5B, 0x04, 0x10, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x30, 0x35, 0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x06, 0x04, 0x28, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0C, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x10,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x04, 0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

TEST_F(PK11SDRTest, RejectUnsupportedAlgorithmDecrypt) {
  SECItem data = {siBuffer,
                  const_cast<unsigned char*>(kUnsupportedAlgorithmDER.data()),
                  (unsigned int)kUnsupportedAlgorithmDER.size()};
  SECItem result = {siBuffer, nullptr, 0};
  EXPECT_EQ(PK11SDR_Decrypt(&data, &result, nullptr), SECFailure);
  EXPECT_EQ(PR_GetError(), SEC_ERROR_INVALID_ARGS);
}

TEST_F(PK11SDRTest, RejectUnsupportedAlgorithmEncrypt) {
  ScopedPK11SlotInfo slot(PK11_GetInternalKeySlot());
  ASSERT_NE(slot.get(), nullptr);
  SECItem keyid = {siBuffer, nullptr, 0};
  unsigned char plaintextBytes[] = {'a', 'b', 'c'};
  SECItem plaintext = {siBuffer, &plaintextBytes[0], sizeof(plaintextBytes)};
  StackSECItem ciphertext;
  SECStatus rv = PK11SDR_EncryptWithMechanism(slot.get(), &keyid, CKM_AES_GCM,
                                              &plaintext, &ciphertext, nullptr);
  EXPECT_EQ(rv, SECFailure);
  EXPECT_EQ(PR_GetError(), SEC_ERROR_INVALID_ARGS);
}

}  // namespace nss_test
