/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "nss_scoped_ptrs.h"

#include "keyhi.h"
#include "kyber.h"
#include "pk11_keygen.h"
#include "pk11pub.h"
#include "pq_pkcs8.h"
#include "prerror.h"
#include "secmodi.h"
#include "secmodti.h"

#include "secport.h"
#include "pk11_import.h"

namespace nss_test {

// The key generation mechanism does not determine the parameter set --
// CKM_ML_KEM_KEY_PAIR_GEN covers ML-KEM-512, -768 and -1024 -- so state all
// three explicitly rather than deriving one from another.
struct KemTestParams {
  CK_MECHANISM_TYPE keyGenMech;
  CK_MECHANISM_TYPE encapsMech;
  CK_NSS_KEM_PARAMETER_SET_TYPE paramSet;
  const char* name;
  // Expected SECKEY_*StrengthInBits, or 0 where cryptohi has no mapping for
  // the parameter set. These are key sizes in bits, not security levels.
  unsigned int pubStrengthBits;
  unsigned int privStrengthBits;
};

static const KemTestParams kKemTestParams[] = {
    // The vendor mechanism with its matching vendor parameter set. Both
    // spellings of ML-KEM-768 have to survive a generate/export/import round
    // trip; pk11wrap normalises the vendor one to CKP_ML_KEM_768 on the way
    // back, which is why this and the next case are not redundant.
    {CKM_NSS_ML_KEM_KEY_PAIR_GEN, CKM_NSS_ML_KEM, CKP_NSS_ML_KEM_768,
     "NssMlKem768", KYBER768_PUBLIC_KEY_BYTES * 8,
     KYBER768_PRIVATE_KEY_BYTES * 8},
    {CKM_ML_KEM_KEY_PAIR_GEN, CKM_ML_KEM, CKP_ML_KEM_768, "MlKem768",
     KYBER768_PUBLIC_KEY_BYTES * 8, KYBER768_PRIVATE_KEY_BYTES * 8},
    {CKM_ML_KEM_KEY_PAIR_GEN, CKM_ML_KEM, CKP_ML_KEM_1024, "MlKem1024",
     MLKEM1024_PUBLIC_KEY_BYTES * 8, MLKEM1024_PRIVATE_KEY_BYTES * 8},
    {CKM_ML_KEM_KEY_PAIR_GEN, CKM_ML_KEM, CKP_ML_KEM_512, "MlKem512",
     MLKEM512_PUBLIC_KEY_BYTES * 8, MLKEM512_PRIVATE_KEY_BYTES * 8},
};

class Pkcs11KEMTest : public ::testing::Test,
                      public ::testing::WithParamInterface<KemTestParams> {
 protected:
  PK11SymKey* Encapsulate(const ScopedSECKEYPublicKey& pub,
                          CK_MECHANISM_TYPE target, PK11AttrFlags attrFlags,
                          CK_FLAGS opFlags, ScopedSECItem* ciphertext) {
    PK11SymKey* sharedSecretRawPtr;
    SECItem* ciphertextRawPtr;

    EXPECT_EQ(SECSuccess,
              PK11_Encapsulate(pub.get(), target, attrFlags, opFlags,
                               &sharedSecretRawPtr, &ciphertextRawPtr));

    ciphertext->reset(ciphertextRawPtr);

    return sharedSecretRawPtr;
  }

  PK11SymKey* Decapsulate(const ScopedSECKEYPrivateKey& priv,
                          const ScopedSECItem& ciphertext,
                          CK_MECHANISM_TYPE target, PK11AttrFlags attrFlags,
                          CK_FLAGS opFlags) {
    PK11SymKey* sharedSecretRawPtr;

    EXPECT_EQ(SECSuccess,
              PK11_Decapsulate(priv.get(), ciphertext.get(), target, attrFlags,
                               opFlags, &sharedSecretRawPtr));

    return sharedSecretRawPtr;
  }

  SECItem* getRawKeyData(const ScopedPK11SymKey& key) {
    SECStatus rv = nss_test::ExtractKeyValue(key.get());
    EXPECT_EQ(SECSuccess, rv);

    SECItem* keyData = nss_test::GetKeyData(key.get());
    EXPECT_NE(nullptr, keyData);
    EXPECT_NE(nullptr, keyData->data);

    return keyData;
  }

  void checkSymKeyAttributeValue(const ScopedPK11SymKey& key,
                                 CK_ATTRIBUTE_TYPE attr,
                                 uint8_t* expectedValue) {
    SECItem attrValue;

    EXPECT_EQ(SECSuccess, PK11_ReadRawAttribute(PK11_TypeSymKey, key.get(),
                                                attr, &attrValue));
    EXPECT_EQ(0, memcmp(expectedValue, attrValue.data, attrValue.len));

    SECITEM_FreeItem(&attrValue, PR_FALSE);
  }

  CK_MECHANISM_TYPE keyGenMech() { return GetParam().keyGenMech; }
  CK_MECHANISM_TYPE encapsMech() { return GetParam().encapsMech; }
  CK_NSS_KEM_PARAMETER_SET_TYPE paramSet() { return GetParam().paramSet; }
};

TEST_P(Pkcs11KEMTest, KemConsistencyTest) {
  Pkcs11KeyPairGenerator generator(keyGenMech(), paramSet());
  ScopedSECKEYPrivateKey priv;
  ScopedSECKEYPublicKey pub;
  generator.GenerateKey(&priv, &pub, false);

  ASSERT_NE(nullptr, pub);
  ASSERT_NE(nullptr, priv);

  // Copy the public key to simulate receiving the key as an octet string
  ScopedSECKEYPublicKey pubCopy(SECKEY_CopyPublicKey(pub.get()));
  ASSERT_NE(nullptr, pubCopy);

  ScopedPK11SlotInfo slot(PK11_GetBestSlot(encapsMech(), nullptr));
  ASSERT_NE(nullptr, slot);
  ASSERT_TRUE(PK11_IsInternal(slot.get()));

  ASSERT_NE((unsigned int)CK_INVALID_HANDLE,
            PK11_ImportPublicKey(slot.get(), pubCopy.get(), PR_FALSE));

  ScopedSECItem ciphertext;
  ScopedPK11SymKey sharedSecret(Encapsulate(
      pubCopy, CKM_SALSA20_POLY1305, PK11_ATTR_PRIVATE | PK11_ATTR_UNMODIFIABLE,
      CKF_ENCRYPT, &ciphertext));

  ASSERT_EQ(CKM_SALSA20_POLY1305, PK11_GetMechanism(sharedSecret.get()));

  CK_BBOOL ckTrue = CK_TRUE;
  CK_BBOOL ckFalse = CK_FALSE;
  checkSymKeyAttributeValue(sharedSecret, CKA_PRIVATE, &ckTrue);
  checkSymKeyAttributeValue(sharedSecret, CKA_MODIFIABLE, &ckFalse);
  checkSymKeyAttributeValue(sharedSecret, CKA_ENCRYPT, &ckTrue);

  ScopedPK11SymKey sharedSecret2(
      Decapsulate(priv, ciphertext, CKM_SALSA20_POLY1305,
                  PK11_ATTR_PRIVATE | PK11_ATTR_UNMODIFIABLE, CKF_ENCRYPT));

  ASSERT_EQ(CKM_SALSA20_POLY1305, PK11_GetMechanism(sharedSecret2.get()));

  checkSymKeyAttributeValue(sharedSecret2, CKA_PRIVATE, &ckTrue);
  checkSymKeyAttributeValue(sharedSecret2, CKA_MODIFIABLE, &ckFalse);
  checkSymKeyAttributeValue(sharedSecret2, CKA_ENCRYPT, &ckTrue);

  SECItem* item1 = getRawKeyData(sharedSecret);
  SECItem* item2 = getRawKeyData(sharedSecret2);
  NSS_DECLASSIFY(item1->data, item1->len);
  NSS_DECLASSIFY(item2->data, item2->len);
  EXPECT_EQ(0, SECITEM_CompareItem(item1, item2));
}

// Verify that C_EncapsulateKey and C_DecapsulateKey reject handles whose
// object class does not match what is expected (CKO_PUBLIC_KEY and
// CKO_PRIVATE_KEY respectively) with CKR_KEY_TYPE_INCONSISTENT.
TEST_P(Pkcs11KEMTest, KemWrongObjectTypeTest) {
  Pkcs11KeyPairGenerator generator(keyGenMech(), paramSet());
  ScopedSECKEYPrivateKey priv;
  ScopedSECKEYPublicKey pub;
  generator.GenerateKey(&priv, &pub, false);
  ASSERT_NE(nullptr, priv);
  ASSERT_NE(nullptr, pub);

  // Both keys are on the same slot; use its default session for both checks.
  PK11SlotInfo* slot = priv->pkcs11Slot;
  ASSERT_NE(nullptr, slot);

  CK_MECHANISM mech = {encapsMech(), nullptr, 0};
  CK_OBJECT_HANDLE outKey = CK_INVALID_HANDLE;

  // C_EncapsulateKey: pass a CKO_PRIVATE_KEY handle where CKO_PUBLIC_KEY is
  // expected.
  CK_ULONG ciphertextLen = 0;
  CK_RV crv = PK11_GETTAB(slot)->C_EncapsulateKey(
      slot->session, &mech, priv->pkcs11ID, nullptr, 0, nullptr, &ciphertextLen,
      &outKey);
  EXPECT_EQ(CKR_KEY_TYPE_INCONSISTENT, crv);

  // C_DecapsulateKey: pass a CKO_PUBLIC_KEY handle where CKO_PRIVATE_KEY is
  // expected.
  CK_BYTE dummyCiphertext[1] = {0};
  CK_ATTRIBUTE dummyTemplate[1] = {};
  crv = PK11_GETTAB(slot)->C_DecapsulateKey(slot->session, &mech, pub->pkcs11ID,
                                            dummyTemplate, 0, dummyCiphertext,
                                            sizeof(dummyCiphertext), &outKey);
  EXPECT_EQ(CKR_KEY_TYPE_INCONSISTENT, crv);
}

TEST_P(Pkcs11KEMTest, KemRejectsWrongCiphertextLength) {
  Pkcs11KeyPairGenerator generator(keyGenMech(), paramSet());
  ScopedSECKEYPrivateKey priv;
  ScopedSECKEYPublicKey pub;
  generator.GenerateKey(&priv, &pub, false);
  ASSERT_NE(nullptr, priv);
  ASSERT_NE(nullptr, pub);

  ScopedSECItem ciphertext;
  ScopedPK11SymKey sharedSecret(Encapsulate(
      pub, CKM_SALSA20_POLY1305, PK11_ATTR_PRIVATE | PK11_ATTR_UNMODIFIABLE,
      CKF_ENCRYPT, &ciphertext));
  ASSERT_NE(nullptr, sharedSecret);
  ASSERT_NE(nullptr, ciphertext);
  ASSERT_LT(0U, ciphertext->len);

  PK11SlotInfo* slot = priv->pkcs11Slot;
  ASSERT_NE(nullptr, slot);
  CK_MECHANISM mech = {encapsMech(), nullptr, 0};
  CK_ATTRIBUTE tmpl[1] = {};
  CK_OBJECT_HANDLE outKey = CK_INVALID_HANDLE;

  // test one byte short, one byte long, and absent.
  std::vector<CK_BYTE> ct(ciphertext->data, ciphertext->data + ciphertext->len);
  EXPECT_EQ(CKR_ARGUMENTS_BAD, PK11_GETTAB(slot)->C_DecapsulateKey(
                                   slot->session, &mech, priv->pkcs11ID, tmpl,
                                   0, ct.data(), ct.size() - 1, &outKey));

  ct.push_back(0);
  EXPECT_EQ(CKR_ARGUMENTS_BAD, PK11_GETTAB(slot)->C_DecapsulateKey(
                                   slot->session, &mech, priv->pkcs11ID, tmpl,
                                   0, ct.data(), ct.size(), &outKey));

  EXPECT_EQ(CKR_ARGUMENTS_BAD, PK11_GETTAB(slot)->C_DecapsulateKey(
                                   slot->session, &mech, priv->pkcs11ID, tmpl,
                                   0, nullptr, ciphertext->len, &outKey));
}

// cryptohi can report a key's size, which for a KEM means running the
// parameter set through seckey_KyberParamsToLen. The private key path gets
// there the long way, via CKA_PARAMETER_SET -> OID -> KyberParams, so it also
// covers the parameter set lookups either side of that.
TEST_P(Pkcs11KEMTest, KeyStrengthInBits) {
  Pkcs11KeyPairGenerator generator(keyGenMech(), paramSet());
  ScopedSECKEYPrivateKey priv;
  ScopedSECKEYPublicKey pub;
  generator.GenerateKey(&priv, &pub, false);
  ASSERT_NE(nullptr, priv);
  ASSERT_NE(nullptr, pub);

  EXPECT_EQ(GetParam().pubStrengthBits,
            SECKEY_PublicKeyStrengthInBits(pub.get()));
  EXPECT_EQ(GetParam().privStrengthBits,
            SECKEY_PrivateKeyStrengthInBits(priv.get()));
}

INSTANTIATE_TEST_SUITE_P(Pkcs11KEMTest, Pkcs11KEMTest,
                         ::testing::ValuesIn(kKemTestParams),
                         [](const ::testing::TestParamInfo<KemTestParams>& i) {
                           return std::string(i.param.name);
                         });

// Getting an ML-KEM key into and out of storage. This mirrors
// Pkcs11MlDsaStorageTest: the two algorithms share the OneAsymmetricKey
// encoding, the pk11pk12.c tag dispatch and the softoken templates, so they
// share the failure modes too.
class Pkcs11MlKemStorageTest
    : public ::testing::TestWithParam<CK_ML_KEM_PARAMETER_SET_TYPE> {
 protected:
  void SetUp() override {
    slot_.reset(PK11_GetInternalKeySlot());
    ASSERT_TRUE(slot_);
    ASSERT_EQ(SECSuccess, PK11_Authenticate(slot_.get(), PR_TRUE, nullptr))
        << PORT_ErrorToString(PORT_GetError());

    CK_ML_KEM_PARAMETER_SET_TYPE paramSet = GetParam();
    SECKEYPublicKey* pub = nullptr;
    priv_.reset(PK11_GenerateKeyPair(slot_.get(), CKM_ML_KEM_KEY_PAIR_GEN,
                                     &paramSet, &pub, PR_FALSE, PK11_IsFIPS(),
                                     nullptr));
    pub_.reset(pub);
    ASSERT_TRUE(priv_) << PORT_ErrorToString(PORT_GetError());
    ASSERT_TRUE(pub_);
    ASSERT_EQ(kyberKey, pub_->keyType);
    ASSERT_EQ(ExpectedPublicKeyLen(GetParam()), pub_->u.kyber.publicValue.len);

    static const unsigned char pw[] = "pw";
    SECItem pwItem = {siBuffer, const_cast<unsigned char*>(pw), sizeof(pw)};
    password_.reset(SECITEM_DupItem(&pwItem));
    ASSERT_TRUE(password_);
  }

  static SECOidTag OidTag(CK_ML_KEM_PARAMETER_SET_TYPE paramSet) {
    switch (paramSet) {
      case CKP_ML_KEM_512:
        return SEC_OID_ML_KEM_512;
      case CKP_NSS_ML_KEM_768:
      case CKP_ML_KEM_768:
        return SEC_OID_ML_KEM_768;
      case CKP_ML_KEM_1024:
        return SEC_OID_ML_KEM_1024;
      default:
        ADD_FAILURE() << "unsupported parameter set";
        return SEC_OID_UNKNOWN;
    }
  }

  static unsigned int ExpectedPublicKeyLen(
      CK_ML_KEM_PARAMETER_SET_TYPE paramSet) {
    switch (paramSet) {
      case CKP_ML_KEM_512:
        return MLKEM512_PUBLIC_KEY_BYTES;
      case CKP_NSS_ML_KEM_768:
      case CKP_ML_KEM_768:
        return KYBER768_PUBLIC_KEY_BYTES;
      case CKP_ML_KEM_1024:
        return MLKEM1024_PUBLIC_KEY_BYTES;
      default:
        ADD_FAILURE() << "unsupported parameter set";
        return 0;
    }
  }

  // A key that came back out of storage has to still be the same key:
  // encapsulate to the public half of the pair it came from and check that it
  // decapsulates to the same shared secret.
  void ExpectPairs(SECKEYPrivateKey* priv, SECKEYPublicKey* pub) {
    // A FIPS token only makes sensitive secrets.
    PK11AttrFlags attrs =
        PK11_ATTR_SESSION | PK11_ATTR_PUBLIC | PK11_ATTR_EXTRACTABLE |
        (PK11_IsFIPS() ? PK11_ATTR_SENSITIVE : PK11_ATTR_INSENSITIVE);
    PK11SymKey* encRaw = nullptr;
    SECItem* ctRaw = nullptr;
    ASSERT_EQ(SECSuccess, PK11_Encapsulate(pub, CKM_HKDF_DERIVE, attrs,
                                           CKF_DERIVE, &encRaw, &ctRaw))
        << PORT_ErrorToString(PORT_GetError());
    ScopedPK11SymKey encSecret(encRaw);
    ScopedSECItem ciphertext(ctRaw);
    ASSERT_TRUE(encSecret);
    ASSERT_TRUE(ciphertext);

    PK11SymKey* decRaw = nullptr;
    ASSERT_EQ(SECSuccess,
              PK11_Decapsulate(priv, ciphertext.get(), CKM_HKDF_DERIVE, attrs,
                               CKF_DERIVE, &decRaw))
        << PORT_ErrorToString(PORT_GetError());
    ScopedPK11SymKey decSecret(decRaw);
    ASSERT_TRUE(decSecret);

    ASSERT_EQ(SECSuccess, nss_test::ExtractKeyValue(encSecret.get()));
    ASSERT_EQ(SECSuccess, nss_test::ExtractKeyValue(decSecret.get()));
    SECItem* a = nss_test::GetKeyData(encSecret.get());
    SECItem* b = nss_test::GetKeyData(decSecret.get());
    ASSERT_TRUE(a);
    ASSERT_TRUE(b);
    NSS_DECLASSIFY(a->data, a->len);
    NSS_DECLASSIFY(b->data, b->len);
    EXPECT_EQ(0, SECITEM_CompareItem(a, b));
  }

  SECKEYPrivateKey* ImportPkcs8(const std::vector<uint8_t>& pkcs8) {
    SECItem item = {siBuffer, const_cast<uint8_t*>(pkcs8.data()),
                    static_cast<unsigned int>(pkcs8.size())};
    SECKEYPrivateKey* key = nullptr;
    if (nss_test::ImportDERPrivateKeyInfoAndReturnKey(
            slot_.get(), &item, nullptr, nullptr, PR_FALSE, PR_FALSE, KU_ALL,
            &key, nullptr) != SECSuccess) {
      return nullptr;
    }
    return key;
  }

  ScopedPK11SlotInfo slot_;
  ScopedSECKEYPrivateKey priv_;
  ScopedSECKEYPublicKey pub_;
  ScopedSECItem password_;
};

// C_WrapKey on a private key packages it as a PKCS#8 first, and C_UnwrapKey
// takes one apart again.
TEST_P(Pkcs11MlKemStorageTest, WrapAndUnwrap) {
  ScopedPK11SymKey kek(
      PK11_KeyGen(slot_.get(), CKM_AES_CBC, nullptr, 16, nullptr));
  ASSERT_TRUE(kek);
  ScopedSECItem wrapParam(PK11_ParamFromIV(CKM_NSS_AES_KEY_WRAP_PAD, nullptr));
  ASSERT_TRUE(wrapParam);

  // Room for the largest key plus its seed, PKCS#8 framing and padding.
  ScopedSECItem wrapped(SECITEM_AllocItem(nullptr, nullptr, 8192));
  ASSERT_TRUE(wrapped);
  ASSERT_EQ(SECSuccess,
            PK11_WrapPrivKey(slot_.get(), kek.get(), priv_.get(),
                             CKM_NSS_AES_KEY_WRAP_PAD, wrapParam.get(),
                             wrapped.get(), nullptr))
      << PORT_ErrorToString(PORT_GetError());

  ScopedSECKEYPrivateKey unwrapped(PK11_UnwrapPrivKeyByKeyType(
      slot_.get(), kek.get(), CKM_NSS_AES_KEY_WRAP_PAD, wrapParam.get(),
      wrapped.get(), nullptr, &pub_->u.kyber.publicValue, PR_FALSE,
      PK11_IsFIPS(), kyberKey, KU_ALL, nullptr));
  ASSERT_TRUE(unwrapped) << PORT_ErrorToString(PORT_GetError());
  EXPECT_EQ(kyberKey, unwrapped->keyType);
  ExpectPairs(unwrapped.get(), pub_.get());
}

// C_WrapKey packages a key that has a seed as the seed CHOICE alone.
TEST_P(Pkcs11MlKemStorageTest, WrapWritesTheSeedChoice) {
  if (PK11_IsFIPS()) {
    GTEST_SKIP() << "FIPS tokens don't reveal CKA_SEED";
  }
  ScopedSECItem seed(SECITEM_AllocItem(nullptr, nullptr, 0));
  ASSERT_TRUE(seed);
  ASSERT_EQ(SECSuccess, PK11_ReadRawAttribute(PK11_TypePrivKey, priv_.get(),
                                              CKA_SEED, seed.get()))
      << PORT_ErrorToString(PORT_GetError());
  std::vector<uint8_t> seedBytes(seed->data, seed->data + seed->len);

  ScopedPK11SymKey kek(
      PK11_KeyGen(slot_.get(), CKM_AES_CBC, nullptr, 16, nullptr));
  ASSERT_TRUE(kek);
  ScopedSECItem wrapParam(PK11_ParamFromIV(CKM_NSS_AES_KEY_WRAP_PAD, nullptr));
  ASSERT_TRUE(wrapParam);
  ScopedSECItem wrapped(SECITEM_AllocItem(nullptr, nullptr, 8192));
  ASSERT_TRUE(wrapped);
  ASSERT_EQ(SECSuccess,
            PK11_WrapPrivKey(slot_.get(), kek.get(), priv_.get(),
                             CKM_NSS_AES_KEY_WRAP_PAD, wrapParam.get(),
                             wrapped.get(), nullptr))
      << PORT_ErrorToString(PORT_GetError());

  std::vector<uint8_t> pkcs8(wrapped->len);
  unsigned int pkcs8Len = 0;
  ASSERT_EQ(SECSuccess, PK11_Decrypt(kek.get(), CKM_NSS_AES_KEY_WRAP_PAD,
                                     wrapParam.get(), pkcs8.data(), &pkcs8Len,
                                     pkcs8.size(), wrapped->data, wrapped->len))
      << PORT_ErrorToString(PORT_GetError());
  pkcs8.resize(pkcs8Len);
  EXPECT_EQ(BuildPqPkcs8(OidTag(GetParam()), PqSeedChoice(seedBytes)), pkcs8);
}

// Importing as a permanent object also creates the matching public key object,
// which is what makes the key findable later.
TEST_P(Pkcs11MlKemStorageTest, ExportEncryptedAndImportAsTokenKey) {
  ScopedSECKEYEncryptedPrivateKeyInfo epki(PK11_ExportEncryptedPrivKeyInfo(
      slot_.get(), SEC_OID_AES_256_CBC, password_.get(), priv_.get(), 1,
      nullptr));
  ASSERT_TRUE(epki) << PORT_ErrorToString(PORT_GetError());

  static const unsigned char nick[] = "ml-kem token key";
  SECItem nickname = {siBuffer, const_cast<unsigned char*>(nick), sizeof(nick)};
  SECKEYPrivateKey* imported = nullptr;
  ASSERT_EQ(SECSuccess,
            PK11_ImportEncryptedPrivateKeyInfoAndReturnKey(
                slot_.get(), epki.get(), password_.get(), &nickname,
                &pub_->u.kyber.publicValue, PR_TRUE /* isPerm */,
                PR_TRUE /* isPrivate */, kyberKey, KU_ALL, &imported, nullptr))
      << PORT_ErrorToString(PORT_GetError());
  ScopedSECKEYPrivateKey tokenKey(imported);
  ASSERT_TRUE(tokenKey);
  EXPECT_EQ(kyberKey, tokenKey->keyType);
  ExpectPairs(tokenKey.get(), pub_.get());

  EXPECT_EQ(SECSuccess,
            PK11_DeleteTokenPrivateKey(tokenKey.release(), PR_TRUE));
}

// Loading a key onto a slot reads its attributes back out and creates a fresh
// object from them, which is the kyberKey branch of pk11_loadPrivKeyWithFlags.
TEST_P(Pkcs11MlKemStorageTest, LoadPrivKeyOntoASlot) {
  if (PK11_IsFIPS()) {
    GTEST_SKIP() << "FIPS tokens don't reveal private key attributes";
  }
  ScopedSECKEYPrivateKey loaded(PK11_LoadPrivKey(
      slot_.get(), priv_.get(), pub_.get(), PR_FALSE, PR_FALSE));
  ASSERT_TRUE(loaded) << PORT_ErrorToString(PORT_GetError());
  EXPECT_EQ(kyberKey, loaded->keyType);
  ExpectPairs(loaded.get(), pub_.get());
}

// Copying a token key to a session key is a C_CopyObject on the token side,
// which reassembles the key from its stored attributes rather than copying an
// in-memory object.
TEST_P(Pkcs11MlKemStorageTest, TokenKeyCopiesToASessionKey) {
  CK_ML_KEM_PARAMETER_SET_TYPE paramSet = GetParam();
  SECKEYPublicKey* pub = nullptr;
  ScopedSECKEYPrivateKey tokenPriv(
      PK11_GenerateKeyPair(slot_.get(), CKM_ML_KEM_KEY_PAIR_GEN, &paramSet,
                           &pub, PR_TRUE /* token */, PK11_IsFIPS(), nullptr));
  ScopedSECKEYPublicKey tokenPub(pub);
  ASSERT_TRUE(tokenPriv) << PORT_ErrorToString(PORT_GetError());
  ASSERT_TRUE(tokenPub);

  ScopedSECKEYPrivateKey sessionPriv(
      PK11_CopyTokenPrivKeyToSessionPrivKey(slot_.get(), tokenPriv.get()));
  ASSERT_TRUE(sessionPriv) << PORT_ErrorToString(PORT_GetError());
  EXPECT_EQ(kyberKey, sessionPriv->keyType);
  ExpectPairs(sessionPriv.get(), tokenPub.get());

  EXPECT_EQ(SECSuccess,
            PK11_DeleteTokenPrivateKey(tokenPriv.release(), PR_TRUE));
  EXPECT_EQ(SECSuccess, PK11_DeleteTokenPublicKey(tokenPub.release()));
}

// RFC 9881's encoding lets a PKCS#8 carry the seed and the expanded key
// together, which is the form older NSS versions wrote. Nothing forces the two
// to agree, so softoken re-derives the key from the seed and rejects the pair
// if they differ. This is the ML-KEM half of the same check tested for ML-DSA.
TEST_P(Pkcs11MlKemStorageTest, BothEncodedKeyChecksSeedAgainstExpandedKey) {
  if (PK11_IsFIPS()) {
    GTEST_SKIP() << "FIPS tokens don't reveal CKA_SEED or CKA_VALUE";
  }
  ScopedSECItem seed(SECITEM_AllocItem(nullptr, nullptr, 0));
  ScopedSECItem value(SECITEM_AllocItem(nullptr, nullptr, 0));
  ASSERT_TRUE(seed);
  ASSERT_TRUE(value);
  ASSERT_EQ(SECSuccess, PK11_ReadRawAttribute(PK11_TypePrivKey, priv_.get(),
                                              CKA_SEED, seed.get()))
      << PORT_ErrorToString(PORT_GetError());
  ASSERT_EQ(SECSuccess, PK11_ReadRawAttribute(PK11_TypePrivKey, priv_.get(),
                                              CKA_VALUE, value.get()))
      << PORT_ErrorToString(PORT_GetError());
  ASSERT_EQ(KYBER_KEYPAIR_COIN_BYTES, seed->len);
  ASSERT_NE(0U, value->len);

  std::vector<uint8_t> seedBytes(seed->data, seed->data + seed->len);
  std::vector<uint8_t> keyBytes(value->data, value->data + value->len);
  SECOidTag oid = OidTag(GetParam());

  // The matching pair has to import and work, otherwise the rejections below
  // would only be telling us the encoding is wrong.
  ScopedSECKEYPrivateKey good(
      ImportPkcs8(BuildPqPkcs8(oid, PqBothChoice(seedBytes, keyBytes))));
  ASSERT_TRUE(good) << PORT_ErrorToString(PORT_GetError());
  EXPECT_EQ(kyberKey, good->keyType);
  ExpectPairs(good.get(), pub_.get());

  // A seed that expands to something else.
  std::vector<uint8_t> badSeed = seedBytes;
  badSeed[0] ^= 0x01;
  EXPECT_FALSE(ImportPkcs8(BuildPqPkcs8(oid, PqBothChoice(badSeed, keyBytes))));

  // ...and the same disagreement reached from the other side.
  std::vector<uint8_t> badKey = keyBytes;
  badKey[0] ^= 0x01;
  EXPECT_FALSE(ImportPkcs8(BuildPqPkcs8(oid, PqBothChoice(seedBytes, badKey))));

  // A truncated expanded key disagrees on length rather than content, which is
  // the other half of the check.
  std::vector<uint8_t> shortKey(keyBytes.begin(), keyBytes.end() - 1);
  EXPECT_FALSE(
      ImportPkcs8(BuildPqPkcs8(oid, PqBothChoice(seedBytes, shortKey))));
}

// A seed-only PKCS#8 has to expand back to the same key, and an expanded-key
// PKCS#8 has to import without a seed to derive from.
TEST_P(Pkcs11MlKemStorageTest, SeedOnlyAndExpandedOnlyPkcs8) {
  if (PK11_IsFIPS()) {
    GTEST_SKIP() << "FIPS tokens don't reveal CKA_SEED or CKA_VALUE";
  }
  ScopedSECItem seed(SECITEM_AllocItem(nullptr, nullptr, 0));
  ScopedSECItem value(SECITEM_AllocItem(nullptr, nullptr, 0));
  ASSERT_TRUE(seed);
  ASSERT_TRUE(value);
  ASSERT_EQ(SECSuccess, PK11_ReadRawAttribute(PK11_TypePrivKey, priv_.get(),
                                              CKA_SEED, seed.get()));
  ASSERT_EQ(SECSuccess, PK11_ReadRawAttribute(PK11_TypePrivKey, priv_.get(),
                                              CKA_VALUE, value.get()));

  std::vector<uint8_t> seedBytes(seed->data, seed->data + seed->len);
  std::vector<uint8_t> keyBytes(value->data, value->data + value->len);
  SECOidTag oid = OidTag(GetParam());

  ScopedSECKEYPrivateKey fromSeed(
      ImportPkcs8(BuildPqPkcs8(oid, PqSeedChoice(seedBytes))));
  ASSERT_TRUE(fromSeed) << PORT_ErrorToString(PORT_GetError());
  ExpectPairs(fromSeed.get(), pub_.get());

  ScopedSECKEYPrivateKey fromExpanded(
      ImportPkcs8(BuildPqPkcs8(oid, PqExpandedKeyChoice(keyBytes))));
  ASSERT_TRUE(fromExpanded) << PORT_ErrorToString(PORT_GetError());
  ExpectPairs(fromExpanded.get(), pub_.get());
}

// Export writes the seed CHOICE, like the wrap path.
TEST_P(Pkcs11MlKemStorageTest, ExportPkcs8WritesTheSeedChoice) {
  if (PK11_IsFIPS()) {
    GTEST_SKIP() << "FIPS tokens don't reveal CKA_SEED";
  }
  ScopedSECItem seed(SECITEM_AllocItem(nullptr, nullptr, 0));
  ASSERT_TRUE(seed);
  ASSERT_EQ(SECSuccess, PK11_ReadRawAttribute(PK11_TypePrivKey, priv_.get(),
                                              CKA_SEED, seed.get()))
      << PORT_ErrorToString(PORT_GetError());
  std::vector<uint8_t> seedBytes(seed->data, seed->data + seed->len);

  ScopedSECItem der(PK11_ExportDERPrivateKeyInfo(priv_.get(), nullptr));
  ASSERT_TRUE(der) << PORT_ErrorToString(PORT_GetError());
  std::vector<uint8_t> exported(der->data, der->data + der->len);
  EXPECT_EQ(BuildPqPkcs8(OidTag(GetParam()), PqSeedChoice(seedBytes)),
            exported);

  ScopedSECKEYPrivateKey reimported(ImportPkcs8(exported));
  ASSERT_TRUE(reimported) << PORT_ErrorToString(PORT_GetError());
  ExpectPairs(reimported.get(), pub_.get());
}

TEST_P(Pkcs11MlKemStorageTest, ExportPkcs8FallsBackToTheExpandedKey) {
  if (PK11_IsFIPS()) {
    GTEST_SKIP() << "FIPS tokens don't reveal CKA_VALUE";
  }
  ScopedSECItem value(SECITEM_AllocItem(nullptr, nullptr, 0));
  ASSERT_TRUE(value);
  ASSERT_EQ(SECSuccess, PK11_ReadRawAttribute(PK11_TypePrivKey, priv_.get(),
                                              CKA_VALUE, value.get()))
      << PORT_ErrorToString(PORT_GetError());
  std::vector<uint8_t> keyBytes(value->data, value->data + value->len);
  SECOidTag oid = OidTag(GetParam());

  ScopedSECKEYPrivateKey seedless(
      ImportPkcs8(BuildPqPkcs8(oid, PqExpandedKeyChoice(keyBytes))));
  ASSERT_TRUE(seedless) << PORT_ErrorToString(PORT_GetError());

  ScopedSECItem der(PK11_ExportDERPrivateKeyInfo(seedless.get(), nullptr));
  ASSERT_TRUE(der) << PORT_ErrorToString(PORT_GetError());
  EXPECT_EQ(BuildPqPkcs8(oid, PqExpandedKeyChoice(keyBytes)),
            std::vector<uint8_t>(der->data, der->data + der->len));
}

// An ML-KEM public key has no DER structure of its own, so importing one is
// just a length-driven parameter set lookup, and the SubjectPublicKeyInfo
// carries it as a bare BIT STRING.
TEST_P(Pkcs11MlKemStorageTest, PublicKeyEncoding) {
  SECItem raw = pub_->u.kyber.publicValue;
  ScopedSECKEYPublicKey imported(SECKEY_ImportDERPublicKey(&raw, CKK_ML_KEM));
  ASSERT_TRUE(imported) << PORT_ErrorToString(PORT_GetError());
  EXPECT_EQ(kyberKey, imported->keyType);
  EXPECT_EQ(0, SECITEM_CompareItem(&raw, &imported->u.kyber.publicValue));

  // A length that matches no parameter set has to be rejected.
  SECItem truncated = {siBuffer, raw.data, raw.len - 1};
  EXPECT_FALSE(SECKEY_ImportDERPublicKey(&truncated, CKK_ML_KEM));

  ScopedSECItem der(SECKEY_EncodeDERSubjectPublicKeyInfo(pub_.get()));
  ASSERT_TRUE(der) << PORT_ErrorToString(PORT_GetError());
  ScopedCERTSubjectPublicKeyInfo spki(
      SECKEY_DecodeDERSubjectPublicKeyInfo(der.get()));
  ASSERT_TRUE(spki) << PORT_ErrorToString(PORT_GetError());
  EXPECT_EQ(OidTag(GetParam()), SECOID_GetAlgorithmTag(&spki->algorithm));

  ScopedSECKEYPublicKey decoded(SECKEY_ExtractPublicKey(spki.get()));
  ASSERT_TRUE(decoded) << PORT_ErrorToString(PORT_GetError());
  EXPECT_EQ(kyberKey, decoded->keyType);
  EXPECT_EQ(0, SECITEM_CompareItem(&pub_->u.kyber.publicValue,
                                   &decoded->u.kyber.publicValue));
}

INSTANTIATE_TEST_SUITE_P(Pkcs11MlKemStorageTest, Pkcs11MlKemStorageTest,
                         ::testing::Values(CKP_ML_KEM_512, CKP_ML_KEM_768,
                                           CKP_ML_KEM_1024));

}  // namespace nss_test
