/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <vector>

#include "keyhi.h"
#include "nss.h"
#include "pk11pub.h"
#include "prerror.h"
#include "secerr.h"
#include "secitem.h"

#include "gtest/gtest.h"
#include "nss_scoped_ptrs.h"
#include "pk11_keygen.h"

namespace nss_test {

// Tests for PK11_CreatePrivateKeyFromTemplate, which builds a SECKEYPrivateKey
// directly from a fully-specified PKCS #11 private-key template.

class CreatePrivKeyFromTemplateTest : public ::testing::Test {
 protected:
  void SetUp() override {
    if (PK11_IsFIPS()) {
      GTEST_SKIP() << "FIPS tokens take no raw private key templates";
    }
  }

  // Read a raw PKCS #11 attribute off a private key. The key must be
  // non-sensitive for secret attributes (e.g. CKA_VALUE) to be readable.
  std::vector<uint8_t> ReadAttr(SECKEYPrivateKey* key, CK_ATTRIBUTE_TYPE type) {
    SECItem item = {siBuffer, nullptr, 0};
    EXPECT_EQ(SECSuccess,
              PK11_ReadRawAttribute(PK11_TypePrivKey, key, type, &item))
        << "failed to read attribute " << type;
    std::vector<uint8_t> out(item.data, item.data + item.len);
    SECITEM_FreeItem(&item, PR_FALSE);
    return out;
  }

  // Generate an extractable (non-sensitive, session) key pair so the raw
  // attributes that make up a template can be read back out.
  void GenerateExtractable(CK_MECHANISM_TYPE mech, SECOidTag curve,
                           ScopedSECKEYPrivateKey* priv,
                           ScopedSECKEYPublicKey* pub) {
    Pkcs11KeyPairGenerator generator(mech, curve);
    generator.GenerateKey(priv, pub, /*sensitive=*/false);
    ASSERT_TRUE(*priv);
    ASSERT_TRUE(*pub);
  }

  // Create a key from a fully-specified template tagged with a unique 'id'
  // (CKA_ID), then check the same properties for every key type: the object is
  // created in 'slot' (findable by its CKA_ID), it signs data that the original
  // public key verifies, and freeing the key destroys the underlying object.
  void VerifyRoundTrip(PK11SlotInfo* slot, CK_ATTRIBUTE* templ,
                       unsigned int count, SECItem* id, SECKEYPublicKey* pub,
                       CK_MECHANISM_TYPE mech, KeyType expected_type,
                       unsigned int hash_len) {
    ScopedSECKEYPrivateKey key(
        PK11_CreatePrivateKeyFromTemplate(slot, templ, count, nullptr));
    ASSERT_TRUE(key) << PORT_ErrorToName(PORT_GetError());
    EXPECT_EQ(expected_type, SECKEY_GetPrivateKeyType(key.get()));

    // The object was created in the slot.
    ScopedSECKEYPrivateKey found(PK11_FindKeyByKeyID(slot, id, nullptr));
    EXPECT_TRUE(found);
    // PK11_FindKeyByKeyID returns a non-owning wrapper; dropping it frees the
    // wrapper but leaves the underlying object in place.
    found.reset();

    // Sign with the imported key and verify with the original public key. This
    // confirms the private value was imported correctly and the key is usable.
    std::vector<uint8_t> hash_buf(hash_len, 0);
    SECItem hash = {siBuffer, hash_buf.data(), hash_len};
    int sig_len = PK11_SignatureLen(key.get());
    ASSERT_GT(sig_len, 0);
    std::vector<uint8_t> sig_buf(sig_len);
    SECItem sig = {siBuffer, sig_buf.data(), (unsigned int)sig_len};
    ASSERT_EQ(SECSuccess,
              PK11_SignWithMechanism(key.get(), mech, nullptr, &sig, &hash));
    EXPECT_EQ(SECSuccess, PK11_VerifyWithMechanism(pub, mech, nullptr, &sig,
                                                   &hash, nullptr));

    // The returned key owns its PKCS #11 object: destroying the key destroys
    // the object, so it can no longer be found by its ID.
    key.reset();
    ScopedSECKEYPrivateKey gone(PK11_FindKeyByKeyID(slot, id, nullptr));
    EXPECT_FALSE(gone);
  }
};

// Build an EC P-256 private-key template from raw key material, create a key
// from it, use it, and confirm it owns (and cleans up) its PKCS #11 object.
TEST_F(CreatePrivKeyFromTemplateTest, EcRoundTrip) {
  ScopedSECKEYPrivateKey gen_priv;
  ScopedSECKEYPublicKey gen_pub;
  GenerateExtractable(CKM_EC_KEY_PAIR_GEN, SEC_OID_SECG_EC_SECP256R1, &gen_priv,
                      &gen_pub);

  std::vector<uint8_t> ec_params = ReadAttr(gen_priv.get(), CKA_EC_PARAMS);
  std::vector<uint8_t> value = ReadAttr(gen_priv.get(), CKA_VALUE);
  // The public point lives on the public key, not the private key, just as
  // WebCrypto's AddPublicKeyData reads it from aPublicKey->u.ec.publicValue.
  SECItem& point = gen_pub->u.ec.publicValue;

  ScopedPK11SlotInfo slot(PK11_GetInternalKeySlot());
  ASSERT_TRUE(slot);

  // A unique CKA_ID lets us confirm via PK11_FindKeyByKeyID that the object is
  // first created and later destroyed.
  uint8_t id_buf[20];
  ASSERT_EQ(SECSuccess, PK11_GenerateRandom(id_buf, sizeof(id_buf)));
  SECItem id = {siBuffer, id_buf, sizeof(id_buf)};

  CK_OBJECT_CLASS classValue = CKO_PRIVATE_KEY;
  CK_KEY_TYPE keyTypeValue = CKK_EC;
  CK_BBOOL falseValue = CK_FALSE;
  CK_ATTRIBUTE templ[] = {
      {CKA_CLASS, &classValue, sizeof(classValue)},
      {CKA_KEY_TYPE, &keyTypeValue, sizeof(keyTypeValue)},
      {CKA_TOKEN, &falseValue, sizeof(falseValue)},
      {CKA_SENSITIVE, &falseValue, sizeof(falseValue)},
      {CKA_PRIVATE, &falseValue, sizeof(falseValue)},
      {CKA_ID, id_buf, sizeof(id_buf)},
      {CKA_EC_PARAMS, ec_params.data(), (CK_ULONG)ec_params.size()},
      {CKA_EC_POINT, point.data, point.len},
      {CKA_VALUE, value.data(), (CK_ULONG)value.size()},
  };

  VerifyRoundTrip(slot.get(), templ, PR_ARRAY_SIZE(templ), &id, gen_pub.get(),
                  CKM_ECDSA, ecKey, /*hash_len=*/32);
}

// Same round trip for an RSA key, exercising the multi-attribute CRT template.
TEST_F(CreatePrivKeyFromTemplateTest, RsaRoundTrip) {
  ScopedSECKEYPrivateKey gen_priv;
  ScopedSECKEYPublicKey gen_pub;
  GenerateExtractable(CKM_RSA_PKCS_KEY_PAIR_GEN, SEC_OID_UNKNOWN, &gen_priv,
                      &gen_pub);

  std::vector<uint8_t> modulus = ReadAttr(gen_priv.get(), CKA_MODULUS);
  std::vector<uint8_t> pub_exp = ReadAttr(gen_priv.get(), CKA_PUBLIC_EXPONENT);
  std::vector<uint8_t> priv_exp =
      ReadAttr(gen_priv.get(), CKA_PRIVATE_EXPONENT);
  std::vector<uint8_t> prime1 = ReadAttr(gen_priv.get(), CKA_PRIME_1);
  std::vector<uint8_t> prime2 = ReadAttr(gen_priv.get(), CKA_PRIME_2);
  std::vector<uint8_t> exp1 = ReadAttr(gen_priv.get(), CKA_EXPONENT_1);
  std::vector<uint8_t> exp2 = ReadAttr(gen_priv.get(), CKA_EXPONENT_2);
  std::vector<uint8_t> coeff = ReadAttr(gen_priv.get(), CKA_COEFFICIENT);

  ScopedPK11SlotInfo slot(PK11_GetInternalKeySlot());
  ASSERT_TRUE(slot);

  // A unique CKA_ID lets us confirm via PK11_FindKeyByKeyID that the object is
  // first created and later destroyed.
  uint8_t id_buf[20];
  ASSERT_EQ(SECSuccess, PK11_GenerateRandom(id_buf, sizeof(id_buf)));
  SECItem id = {siBuffer, id_buf, sizeof(id_buf)};

  CK_OBJECT_CLASS classValue = CKO_PRIVATE_KEY;
  CK_KEY_TYPE keyTypeValue = CKK_RSA;
  CK_BBOOL falseValue = CK_FALSE;
  CK_ATTRIBUTE templ[] = {
      {CKA_CLASS, &classValue, sizeof(classValue)},
      {CKA_KEY_TYPE, &keyTypeValue, sizeof(keyTypeValue)},
      {CKA_TOKEN, &falseValue, sizeof(falseValue)},
      {CKA_SENSITIVE, &falseValue, sizeof(falseValue)},
      {CKA_PRIVATE, &falseValue, sizeof(falseValue)},
      {CKA_ID, id_buf, sizeof(id_buf)},
      {CKA_MODULUS, modulus.data(), (CK_ULONG)modulus.size()},
      {CKA_PUBLIC_EXPONENT, pub_exp.data(), (CK_ULONG)pub_exp.size()},
      {CKA_PRIVATE_EXPONENT, priv_exp.data(), (CK_ULONG)priv_exp.size()},
      {CKA_PRIME_1, prime1.data(), (CK_ULONG)prime1.size()},
      {CKA_PRIME_2, prime2.data(), (CK_ULONG)prime2.size()},
      {CKA_EXPONENT_1, exp1.data(), (CK_ULONG)exp1.size()},
      {CKA_EXPONENT_2, exp2.data(), (CK_ULONG)exp2.size()},
      {CKA_COEFFICIENT, coeff.data(), (CK_ULONG)coeff.size()},
  };

  VerifyRoundTrip(slot.get(), templ, PR_ARRAY_SIZE(templ), &id, gen_pub.get(),
                  CKM_RSA_PKCS, rsaKey, /*hash_len=*/20);
}

// NULL slot, NULL template, and a zero count are rejected up front.
TEST_F(CreatePrivKeyFromTemplateTest, InvalidArgs) {
  ScopedPK11SlotInfo slot(PK11_GetInternalKeySlot());
  ASSERT_TRUE(slot);

  CK_OBJECT_CLASS classValue = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE templ[] = {{CKA_CLASS, &classValue, sizeof(classValue)}};

  EXPECT_EQ(nullptr,
            PK11_CreatePrivateKeyFromTemplate(nullptr, templ, 1, nullptr));
  EXPECT_EQ(SEC_ERROR_INVALID_ARGS, PORT_GetError());

  EXPECT_EQ(nullptr,
            PK11_CreatePrivateKeyFromTemplate(slot.get(), nullptr, 1, nullptr));
  EXPECT_EQ(SEC_ERROR_INVALID_ARGS, PORT_GetError());

  EXPECT_EQ(nullptr,
            PK11_CreatePrivateKeyFromTemplate(slot.get(), templ, 0, nullptr));
  EXPECT_EQ(SEC_ERROR_INVALID_ARGS, PORT_GetError());
}

// A template that lacks the required key material is rejected by the token; the
// function returns NULL rather than a half-formed key.
TEST_F(CreatePrivKeyFromTemplateTest, IncompleteTemplate) {
  ScopedPK11SlotInfo slot(PK11_GetInternalKeySlot());
  ASSERT_TRUE(slot);

  CK_OBJECT_CLASS classValue = CKO_PRIVATE_KEY;
  CK_KEY_TYPE keyTypeValue = CKK_EC;
  CK_BBOOL falseValue = CK_FALSE;
  // Missing CKA_EC_PARAMS / CKA_EC_POINT / CKA_VALUE.
  CK_ATTRIBUTE templ[] = {
      {CKA_CLASS, &classValue, sizeof(classValue)},
      {CKA_KEY_TYPE, &keyTypeValue, sizeof(keyTypeValue)},
      {CKA_TOKEN, &falseValue, sizeof(falseValue)},
  };

  EXPECT_EQ(nullptr, PK11_CreatePrivateKeyFromTemplate(
                         slot.get(), templ, PR_ARRAY_SIZE(templ), nullptr));
}

}  // namespace nss_test
