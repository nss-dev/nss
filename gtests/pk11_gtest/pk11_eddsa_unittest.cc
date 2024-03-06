/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <memory>
#include "nss.h"
#include "pk11pub.h"
#include "sechash.h"
#include "cryptohi.h"

#include "gtest/gtest.h"
#include "nss_scoped_ptrs.h"

#include "pk11_eddsa_vectors.h"
#include "pk11_signature_test.h"
#include "pk11_keygen.h"

namespace nss_test {
static const Pkcs11SignatureTestParams kEddsaVectors[] = {
    {DataBuffer(kEd25519Pkcs8_1, sizeof(kEd25519Pkcs8_1)),
     DataBuffer(kEd25519Spki_1, sizeof(kEd25519Spki_1)),
     DataBuffer(kEd25519Message_1, sizeof(kEd25519Message_1)),
     DataBuffer(kEd25519Signature_1, sizeof(kEd25519Signature_1))},

    {DataBuffer(kEd25519Pkcs8_2, sizeof(kEd25519Pkcs8_2)),
     DataBuffer(kEd25519Spki_2, sizeof(kEd25519Spki_2)),
     DataBuffer(kEd25519Message_2, sizeof(kEd25519Message_2)),
     DataBuffer(kEd25519Signature_2, sizeof(kEd25519Signature_2))},

    {DataBuffer(kEd25519Pkcs8_3, sizeof(kEd25519Pkcs8_3)),
     DataBuffer(kEd25519Spki_3, sizeof(kEd25519Spki_3)),
     DataBuffer(kEd25519Message_3, sizeof(kEd25519Message_3)),
     DataBuffer(kEd25519Signature_3, sizeof(kEd25519Signature_3))}};

class Pkcs11EddsaTest
    : public Pk11SignatureTest,
      public ::testing::WithParamInterface<Pkcs11SignatureTestParams> {
 protected:
  Pkcs11EddsaTest() : Pk11SignatureTest(CKM_EDDSA) {}
};

TEST_P(Pkcs11EddsaTest, SignAndVerify) { SignAndVerifyRaw(GetParam()); }

TEST_P(Pkcs11EddsaTest, ImportExport) { ImportExport(GetParam().pkcs8_); }

TEST_P(Pkcs11EddsaTest, ImportConvertToPublic) {
  ScopedSECKEYPrivateKey privKey(ImportPrivateKey(GetParam().pkcs8_));
  ASSERT_TRUE(privKey);

  ScopedSECKEYPublicKey pubKey(SECKEY_ConvertToPublicKey(privKey.get()));
  ASSERT_TRUE(pubKey);
}

TEST_P(Pkcs11EddsaTest, ImportPublicCreateSubjectPKInfo) {
  ScopedSECKEYPrivateKey privKey(ImportPrivateKey(GetParam().pkcs8_));
  ASSERT_TRUE(privKey);

  ScopedSECKEYPublicKey pubKey(
      (SECKEYPublicKey*)SECKEY_ConvertToPublicKey(privKey.get()));
  ASSERT_TRUE(pubKey);

  ScopedSECItem der_spki(SECKEY_EncodeDERSubjectPublicKeyInfo(pubKey.get()));
  ASSERT_TRUE(der_spki);
  ASSERT_EQ(der_spki->len, GetParam().spki_.len());
  ASSERT_EQ(0, memcmp(der_spki->data, GetParam().spki_.data(), der_spki->len));
}

INSTANTIATE_TEST_SUITE_P(EddsaSignVerify, Pkcs11EddsaTest,
                         ::testing::ValuesIn(kEddsaVectors));

class Pkcs11EddsaRoundtripTest
    : public Pk11SignatureTest,
      public ::testing::WithParamInterface<Pkcs11SignatureTestParams> {
 protected:
  Pkcs11EddsaRoundtripTest() : Pk11SignatureTest(CKM_EDDSA) {}

 protected:
  void GenerateExportImportSignVerify(Pkcs11SignatureTestParams params) {
    Pkcs11KeyPairGenerator generator(CKM_EC_EDWARDS_KEY_PAIR_GEN);
    ScopedSECKEYPrivateKey priv;
    ScopedSECKEYPublicKey pub;
    generator.GenerateKey(&priv, &pub, false);

    DataBuffer exported;
    ExportPrivateKey(&priv, exported);

    ScopedSECKEYPrivateKey privKey(ImportPrivateKey(exported));
    ASSERT_NE(privKey, nullptr);
    DataBuffer sig;

    SignRaw(privKey, params.data_, &sig);
    Verify(pub, params.data_, sig);
  }
};

TEST_P(Pkcs11EddsaRoundtripTest, GenerateExportImportSignVerify) {
  GenerateExportImportSignVerify(GetParam());
}

INSTANTIATE_TEST_SUITE_P(EddsaRound, Pkcs11EddsaRoundtripTest,
                         ::testing::ValuesIn(kEddsaVectors));

}  // namespace nss_test
