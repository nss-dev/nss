/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <functional>
#include <string>
#include <vector>

#include "gtest/gtest.h"

#include "cert.h"
#include "cryptohi.h"
#include "hasht.h"
#include "json_reader.h"
#include "keyhi.h"
#include "nss_scoped_ptrs.h"
#include "pk11pub.h"
#include "prerror.h"
#include "secasn1.h"
#include "secerr.h"
#include "secitem.h"
#include "secoid.h"
#include "pk11_import.h"

namespace nss_test {

// Wycheproof ML-DSA vectors driven through cryptohi's SEC_SignData and
// VFY_VerifyData, which is the layer certificate verification goes through.
// The same vectors run against PKCS#11 in gtests/pk11_gtest and against freebl
// in gtests/freebl_gtest.
//
// Two things cryptohi cannot express, so the cases needing them are skipped and
// counted rather than quietly passing:
//
//   * A domain-separation context. RFC 9881 requires an ML-DSA
//     AlgorithmIdentifier's parameters to be absent, so there is nowhere for a
//     caller to put one; sec_DecodeSigAlg always asks for an empty context.
//   * Deterministic signing. sec_DecodeSigAlg asks for CKH_HEDGE_PREFERRED, so
//     a signature cannot be compared against the one in the vector; the
//     signing tests round-trip through verification instead.

struct MlDsaTestVector {
  uint64_t id;
  bool valid;
  std::vector<uint8_t> msg;
  std::vector<uint8_t> ctx;
  std::vector<uint8_t> sig;
  bool has_msg = false;
};

static SECItem as_item(const std::vector<uint8_t>& v) {
  SECItem item = {siBuffer, const_cast<uint8_t*>(v.data()),
                  static_cast<unsigned int>(v.size())};
  return item;
}

class CryptohiMlDsaWycheproofTest : public ::testing::Test {
 protected:
  typedef std::function<void(const MlDsaTestVector&)> Operation;

  void Run(const std::string& file, SECOidTag oid, const std::string& schema,
           Operation op) {
    oid_ = oid;
    op_ = op;
    skippedNoContext_ = 0;
    skippedNoPkcs8_ = 0;
    WycheproofHeader(file, ParameterSetName(oid), schema,
                     [this](JsonReader& r) { RunGroup(r); });
    std::cout << "  skipped " << skippedNoContext_
              << " case(s) needing a context or an external mu, and "
              << skippedNoPkcs8_ << " whose key is not given as a PKCS#8"
              << std::endl;
  }

  void Verify(const MlDsaTestVector& t) {
    ScopedSECKEYPublicKey pub(ImportPublicKey(publicKeyDer_));
    if (!pub) {
      EXPECT_FALSE(t.valid) << "could not import the public key of a valid "
                               "vector: "
                            << PORT_ErrorToString(PORT_GetError());
      return;
    }

    SECItem sig = as_item(t.sig);
    SECStatus rv = VFY_VerifyData(t.msg.data(), static_cast<int>(t.msg.size()),
                                  pub.get(), &sig, oid_, nullptr);
    EXPECT_EQ(t.valid ? SECSuccess : SECFailure, rv);
  }

  // Signatures are hedged here, so instead of comparing against the expected
  // signature this signs and then verifies what came out. Vectors that expect
  // signing to fail still have to fail.
  void SignAndVerify(const MlDsaTestVector& t) {
    // Some groups give only a raw seed or expanded key. Wrapping those in a
    // PKCS#8 is pk11_gtest's job, not this layer's.
    if (privateKeyPkcs8_.empty()) {
      skippedNoPkcs8_++;
      return;
    }

    ScopedSECKEYPrivateKey priv(ImportPrivateKey());
    if (!priv) {
      EXPECT_FALSE(t.valid) << "could not import the private key of a valid "
                               "vector: "
                            << PORT_ErrorToString(PORT_GetError());
      return;
    }

    ScopedSECItem sig(SECITEM_AllocItem(nullptr, nullptr, 0));
    ASSERT_TRUE(sig);
    SECStatus rv =
        SEC_SignData(sig.get(), t.msg.data(), static_cast<int>(t.msg.size()),
                     priv.get(), oid_);
    ASSERT_EQ(t.valid ? SECSuccess : SECFailure, rv)
        << PORT_ErrorToString(PORT_GetError());
    if (!t.valid) {
      return;
    }

    ScopedSECKEYPublicKey pub(SECKEY_ConvertToPublicKey(priv.get()));
    ASSERT_TRUE(pub);
    EXPECT_EQ(SECSuccess,
              VFY_VerifyData(t.msg.data(), static_cast<int>(t.msg.size()),
                             pub.get(), sig.get(), oid_, nullptr))
        << "a freshly made signature did not verify: "
        << PORT_ErrorToString(PORT_GetError());
  }

 private:
  static std::string ParameterSetName(SECOidTag oid) {
    switch (oid) {
      case SEC_OID_ML_DSA_44:
        return "ML-DSA-44";
      case SEC_OID_ML_DSA_65:
        return "ML-DSA-65";
      case SEC_OID_ML_DSA_87:
        return "ML-DSA-87";
      default:
        ADD_FAILURE() << "unsupported parameter set";
        return "";
    }
  }

  ScopedSECKEYPublicKey ImportPublicKey(const std::vector<uint8_t>& spki) {
    SECItem item = as_item(spki);
    ScopedCERTSubjectPublicKeyInfo info(
        SECKEY_DecodeDERSubjectPublicKeyInfo(&item));
    if (!info) {
      return nullptr;
    }
    return ScopedSECKEYPublicKey(SECKEY_ExtractPublicKey(info.get()));
  }

  // Only the groups that carry a PKCS#8 can be used; building one from a raw
  // key is pk11_gtest's job, not this layer's.
  ScopedSECKEYPrivateKey ImportPrivateKey() {
    ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
    EXPECT_TRUE(slot);
    if (!slot) {
      return nullptr;
    }

    SECItem item = as_item(privateKeyPkcs8_);
    SECKEYPrivateKey* key = nullptr;
    if (nss_test::ImportDERPrivateKeyInfoAndReturnKey(
            slot.get(), &item, nullptr, nullptr, false, false, KU_ALL, &key,
            nullptr) != SECSuccess) {
      return nullptr;
    }
    return ScopedSECKEYPrivateKey(key);
  }

  static void ReadTestAttr(MlDsaTestVector& t, const std::string& n,
                           JsonReader& r) {
    if (n == "msg") {
      t.msg = r.ReadHex();
      t.has_msg = true;
    } else if (n == "ctx") {
      t.ctx = r.ReadHex();
    } else if (n == "sig") {
      t.sig = r.ReadHex();
    } else if (n == "rnd" || n == "mu") {
      r.SkipValue();
    } else {
      FAIL() << "unsupported test case field: " << n;
    }
  }

  void RunGroup(JsonReader& r) {
    std::vector<MlDsaTestVector> tests;
    publicKeyDer_.clear();
    privateKeyPkcs8_.clear();

    while (r.NextItem()) {
      std::string n = r.ReadLabel();
      if (n == "") {
        break;
      }
      if (n == "publicKeyDer") {
        publicKeyDer_ = r.ReadHex();
      } else if (n == "privateKeyPkcs8") {
        privateKeyPkcs8_ = ReadOptionalHex(r);
      } else if (n == "type" || n == "source" || n == "publicKey" ||
                 n == "privateKey" || n == "privateSeed") {
        r.SkipValue();
      } else if (n == "tests") {
        WycheproofReadTests(r, &tests, ReadTestAttr, false);
      } else {
        FAIL() << "unknown group label: " << n;
      }
    }

    for (auto& t : tests) {
      // A non-empty context cannot be passed through cryptohi, and an
      // external-mu case has no message to sign or verify.
      if (!t.ctx.empty() || !t.has_msg) {
        skippedNoContext_++;
        continue;
      }
      SCOPED_TRACE(testing::Message() << "tcId " << t.id);
      op_(t);
    }
  }

  static std::vector<uint8_t> ReadOptionalHex(JsonReader& r) {
    if (r.PeekValue() == 'n') {  // null
      r.SkipValue();
      return std::vector<uint8_t>();
    }
    return r.ReadHex();
  }

  SECOidTag oid_;
  Operation op_;
  size_t skippedNoContext_;
  size_t skippedNoPkcs8_;
  std::vector<uint8_t> publicKeyDer_;
  std::vector<uint8_t> privateKeyPkcs8_;
};

#define ML_DSA_WYCHEPROOF_TESTS(name, bits, oid)                         \
  TEST_F(CryptohiMlDsaWycheproofTest, name##Verify) {                    \
    Run("mldsa_" #bits "_verify", oid, "mldsa_verify_schema.json",       \
        [this](const MlDsaTestVector& t) { Verify(t); });                \
  }                                                                      \
  TEST_F(CryptohiMlDsaWycheproofTest, name##Sign) {                      \
    Run("mldsa_" #bits "_sign_seed", oid, "mldsa_sign_seed_schema.json", \
        [this](const MlDsaTestVector& t) { SignAndVerify(t); });         \
  }

// RFC 9881: an ML-DSA AlgorithmIdentifier's parameters MUST be absent.
// sec_DecodeSigAlg has to reject anything else rather than ignore it, since a
// caller putting something there has asked for something cryptohi is not
// doing.
class CryptohiMlDsaParamsTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
    ASSERT_TRUE(slot);

    CK_ML_DSA_PARAMETER_SET_TYPE paramSet = CKP_ML_DSA_44;
    SECKEYPublicKey* pub = nullptr;
    priv_.reset(PK11_GenerateKeyPair(slot.get(), CKM_ML_DSA_KEY_PAIR_GEN,
                                     &paramSet, &pub, PR_FALSE, PR_TRUE,
                                     nullptr));
    pub_.reset(pub);
    ASSERT_TRUE(priv_);
    ASSERT_TRUE(pub_);

    arena_.reset(PORT_NewArena(DER_DEFAULT_CHUNKSIZE));
    ASSERT_TRUE(arena_);

    sig_.reset(SECITEM_AllocItem(nullptr, nullptr, 0));
    ASSERT_TRUE(sig_);
    ASSERT_EQ(SECSuccess, SEC_SignData(sig_.get(), kMsg, sizeof(kMsg),
                                       priv_.get(), SEC_OID_ML_DSA_44));
  }

  // Build an ML-DSA AlgorithmIdentifier, optionally with parameters.
  SECAlgorithmID AlgorithmID(SECItem* params) {
    SECAlgorithmID algid = {};
    EXPECT_EQ(SECSuccess, SECOID_SetAlgorithmID(arena_.get(), &algid,
                                                SEC_OID_ML_DSA_44, params));
    return algid;
  }

  static const unsigned char kMsg[6];
  ScopedPLArenaPool arena_;
  ScopedSECKEYPrivateKey priv_;
  ScopedSECKEYPublicKey pub_;
  ScopedSECItem sig_;
};

const unsigned char CryptohiMlDsaParamsTest::kMsg[6] = {'m', 'l', '-',
                                                        'd', 's', 'a'};

TEST_F(CryptohiMlDsaParamsTest, AbsentParametersAccepted) {
  SECAlgorithmID algid = AlgorithmID(nullptr);
  ASSERT_EQ(0U, algid.parameters.len)
      << "NSS should encode ML-DSA with absent parameters";

  VFYContext* cx = VFY_CreateContextWithAlgorithmID(pub_.get(), sig_.get(),
                                                    &algid, nullptr, nullptr);
  ASSERT_TRUE(cx);
  EXPECT_EQ(SECSuccess, VFY_Begin(cx));
  EXPECT_EQ(SECSuccess, VFY_Update(cx, kMsg, sizeof(kMsg)));
  EXPECT_EQ(SECSuccess, VFY_End(cx));
  VFY_DestroyContext(cx, PR_TRUE);

  SGNContext* sgn = SGN_NewContextWithAlgorithmID(&algid, priv_.get());
  EXPECT_TRUE(sgn);
  if (sgn) {
    SGN_DestroyContext(sgn, PR_TRUE);
  }
}

TEST_F(CryptohiMlDsaParamsTest, PresentParametersRejected) {
  // A DER NULL, which some encoders emit for algorithms that take no
  // parameters, is still not absent.
  unsigned char derNull[] = {SEC_ASN1_NULL, 0};
  SECItem params = {siBuffer, derNull, sizeof(derNull)};
  SECAlgorithmID algid = AlgorithmID(&params);
  ASSERT_EQ(sizeof(derNull), algid.parameters.len);

  EXPECT_FALSE(VFY_CreateContextWithAlgorithmID(pub_.get(), sig_.get(), &algid,
                                                nullptr, nullptr));
  EXPECT_FALSE(SGN_NewContextWithAlgorithmID(&algid, priv_.get()));
}

ML_DSA_WYCHEPROOF_TESTS(MlDsa44, 44, SEC_OID_ML_DSA_44)
ML_DSA_WYCHEPROOF_TESTS(MlDsa65, 65, SEC_OID_ML_DSA_65)
ML_DSA_WYCHEPROOF_TESTS(MlDsa87, 87, SEC_OID_ML_DSA_87)

// The rest of the cryptohi surface: key encoding, the algorithm-OID lookups,
// and the certificate signing and verification entry points. The Wycheproof
// tests above decode keys that the vector files hand them and call
// SEC_SignData/VFY_VerifyData, so none of this is reached from there.
class CryptohiMlDsaKeyTest : public ::testing::TestWithParam<SECOidTag> {
 protected:
  // SECKEY_GetMLDSAPkcs11ParamSetByOidTag is not exported from nss3, so map
  // the OID here rather than link against it.
  static CK_ML_DSA_PARAMETER_SET_TYPE Pkcs11ParamSet(SECOidTag oid) {
    switch (oid) {
      case SEC_OID_ML_DSA_44:
        return CKP_ML_DSA_44;
      case SEC_OID_ML_DSA_65:
        return CKP_ML_DSA_65;
      case SEC_OID_ML_DSA_87:
        return CKP_ML_DSA_87;
      default:
        ADD_FAILURE() << "unsupported parameter set";
        return CKP_ML_DSA_44;
    }
  }

  void SetUp() override {
    oid_ = GetParam();

    ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
    ASSERT_TRUE(slot);
    CK_ML_DSA_PARAMETER_SET_TYPE paramSet = Pkcs11ParamSet(oid_);
    SECKEYPublicKey* pub = nullptr;
    priv_.reset(PK11_GenerateKeyPair(slot.get(), CKM_ML_DSA_KEY_PAIR_GEN,
                                     &paramSet, &pub, PR_FALSE, PR_TRUE,
                                     nullptr));
    pub_.reset(pub);
    ASSERT_TRUE(priv_);
    ASSERT_TRUE(pub_);
    ASSERT_EQ(mldsaKey, pub_->keyType);
    ASSERT_EQ(oid_, pub_->u.mldsa.paramSet);

    sig_.reset(SECITEM_AllocItem(nullptr, nullptr, 0));
    ASSERT_TRUE(sig_);
    ASSERT_EQ(SECSuccess,
              SEC_SignData(sig_.get(), kMsg, sizeof(kMsg), priv_.get(), oid_));
  }

  static const unsigned char kMsg[6];
  // CERT_SignedDataTemplate holds what is signed as an ASN.1 ANY, so what goes
  // into SEC_DerSignData has to be well formed DER -- a TBSCertificate in real
  // use. This is an OCTET STRING wrapping kMsg.
  static const unsigned char kDerMsg[8];

  SECOidTag oid_;
  ScopedSECKEYPrivateKey priv_;
  ScopedSECKEYPublicKey pub_;
  ScopedSECItem sig_;
};

const unsigned char CryptohiMlDsaKeyTest::kMsg[6] = {'m', 'l', '-',
                                                     'd', 's', 'a'};
const unsigned char CryptohiMlDsaKeyTest::kDerMsg[8] = {
    SEC_ASN1_OCTET_STRING, 0x06, 'm', 'l', '-', 'd', 's', 'a'};

// An ML-DSA public key has no DER structure of its own, so importing one is
// just a length-driven parameter set lookup.
TEST_P(CryptohiMlDsaKeyTest, ImportRawPublicKey) {
  SECItem raw = pub_->u.mldsa.publicValue;
  ScopedSECKEYPublicKey imported(SECKEY_ImportDERPublicKey(&raw, CKK_ML_DSA));
  ASSERT_TRUE(imported) << PORT_ErrorToString(PORT_GetError());
  EXPECT_EQ(mldsaKey, imported->keyType);
  EXPECT_EQ(oid_, imported->u.mldsa.paramSet);
  EXPECT_EQ(0, SECITEM_CompareItem(&raw, &imported->u.mldsa.publicValue));

  // A length that matches no parameter set has to be rejected rather than
  // guessed at.
  SECItem truncated = {siBuffer, raw.data, raw.len - 1};
  EXPECT_FALSE(SECKEY_ImportDERPublicKey(&truncated, CKK_ML_DSA));
  EXPECT_EQ(SEC_ERROR_BAD_KEY, PORT_GetError());
}

TEST_P(CryptohiMlDsaKeyTest, SubjectPublicKeyInfoRoundTrip) {
  ScopedSECItem der(SECKEY_EncodeDERSubjectPublicKeyInfo(pub_.get()));
  ASSERT_TRUE(der) << PORT_ErrorToString(PORT_GetError());

  ScopedCERTSubjectPublicKeyInfo spki(
      SECKEY_DecodeDERSubjectPublicKeyInfo(der.get()));
  ASSERT_TRUE(spki) << PORT_ErrorToString(PORT_GetError());
  EXPECT_EQ(oid_, SECOID_GetAlgorithmTag(&spki->algorithm));
  // RFC 9881: the parameters component must be absent.
  EXPECT_EQ(0U, spki->algorithm.parameters.len);

  ScopedSECKEYPublicKey decoded(SECKEY_ExtractPublicKey(spki.get()));
  ASSERT_TRUE(decoded) << PORT_ErrorToString(PORT_GetError());
  EXPECT_EQ(mldsaKey, decoded->keyType);
  EXPECT_EQ(oid_, decoded->u.mldsa.paramSet);
  EXPECT_EQ(0, SECITEM_CompareItem(&pub_->u.mldsa.publicValue,
                                   &decoded->u.mldsa.publicValue));
}

// For ML-DSA the "hash" and the signature algorithm are the same OID, since
// the parameter set already fixes the hash.
TEST_P(CryptohiMlDsaKeyTest, SignatureAlgorithmOidTags) {
  EXPECT_EQ(oid_, SEC_GetSignatureAlgorithmOidTag(mldsaKey, oid_));
  EXPECT_EQ(SEC_OID_UNKNOWN,
            SEC_GetSignatureAlgorithmOidTag(mldsaKey, SEC_OID_SHA256));

  // Given a key, the parameter set is taken from the key and whatever hash the
  // caller passed is ignored.
  EXPECT_EQ(oid_, SEC_GetSignatureAlgorithmOidTagByKey(priv_.get(), nullptr,
                                                       SEC_OID_UNKNOWN));
  EXPECT_EQ(oid_, SEC_GetSignatureAlgorithmOidTagByKey(nullptr, pub_.get(),
                                                       SEC_OID_SHA256));
}

// SEC_DerSignData with no algorithm named has to derive it from the key.
TEST_P(CryptohiMlDsaKeyTest, DerSignDataDerivesTheParameterSet) {
  ScopedPLArenaPool arena(PORT_NewArena(DER_DEFAULT_CHUNKSIZE));
  ASSERT_TRUE(arena);

  SECItem signedData = {siBuffer, nullptr, 0};
  ASSERT_EQ(SECSuccess,
            SEC_DerSignData(arena.get(), &signedData, kDerMsg, sizeof(kDerMsg),
                            priv_.get(), SEC_OID_UNKNOWN))
      << PORT_ErrorToString(PORT_GetError());

  CERTSignedData sd = {};
  ASSERT_EQ(
      SECSuccess,
      SEC_ASN1DecodeItem(arena.get(), &sd,
                         SEC_ASN1_GET(CERT_SignedDataTemplate), &signedData));
  EXPECT_EQ(oid_, SECOID_GetAlgorithmTag(&sd.signatureAlgorithm));
  EXPECT_EQ(SECSuccess,
            CERT_VerifySignedDataWithPublicKey(&sd, pub_.get(), nullptr))
      << PORT_ErrorToString(PORT_GetError());
}

// CERT_VerifySignedDataWithPublicKey has to reject a key that does not match
// the signature algorithm, both when the key is not ML-DSA at all and when it
// is the wrong parameter set.
TEST_P(CryptohiMlDsaKeyTest, SignedDataRejectsAMismatchedKey) {
  ScopedPLArenaPool arena(PORT_NewArena(DER_DEFAULT_CHUNKSIZE));
  ASSERT_TRUE(arena);

  SECItem signedData = {siBuffer, nullptr, 0};
  ASSERT_EQ(SECSuccess, SEC_DerSignData(arena.get(), &signedData, kDerMsg,
                                        sizeof(kDerMsg), priv_.get(), oid_));
  CERTSignedData sd = {};
  ASSERT_EQ(
      SECSuccess,
      SEC_ASN1DecodeItem(arena.get(), &sd,
                         SEC_ASN1_GET(CERT_SignedDataTemplate), &signedData));

  // Same key material, relabelled as some other parameter set.
  SECOidTag otherOid =
      (oid_ == SEC_OID_ML_DSA_44) ? SEC_OID_ML_DSA_65 : SEC_OID_ML_DSA_44;
  ScopedSECKEYPublicKey wrongParamSet(SECKEY_CopyPublicKey(pub_.get()));
  ASSERT_TRUE(wrongParamSet);
  wrongParamSet->u.mldsa.paramSet = otherOid;
  EXPECT_EQ(SECFailure, CERT_VerifySignedDataWithPublicKey(
                            &sd, wrongParamSet.get(), nullptr));

  // Same key material, relabelled as a different algorithm entirely.
  ScopedSECKEYPublicKey wrongKeyType(SECKEY_CopyPublicKey(pub_.get()));
  ASSERT_TRUE(wrongKeyType);
  wrongKeyType->keyType = ecKey;
  EXPECT_EQ(SECFailure, CERT_VerifySignedDataWithPublicKey(
                            &sd, wrongKeyType.get(), nullptr));
}

// The *Direct entry points take the signature and hash algorithms already
// split apart, which is a different mechanism lookup than sec_DecodeSigAlg.
// For ML-DSA the parameter set is both halves of the pair, so naming it as
// the hash and leaving the hash unnamed both work; nothing else does.
TEST_P(CryptohiMlDsaKeyTest, VerifyDataDirect) {
  EXPECT_EQ(SECSuccess,
            VFY_VerifyDataDirect(kMsg, sizeof(kMsg), pub_.get(), sig_.get(),
                                 oid_, oid_, nullptr, nullptr))
      << PORT_ErrorToString(PORT_GetError());

  // An unnamed hash resolves to the parameter set, and is reported back as
  // such through the out parameter.
  SECOidTag hash = SEC_OID_UNKNOWN;
  EXPECT_EQ(SECSuccess,
            VFY_VerifyDataDirect(kMsg, sizeof(kMsg), pub_.get(), sig_.get(),
                                 oid_, SEC_OID_UNKNOWN, &hash, nullptr))
      << PORT_ErrorToString(PORT_GetError());
  EXPECT_EQ(oid_, hash);

  // Any other hash is not a rational pairing, so there is no mechanism for it.
  EXPECT_EQ(SECFailure,
            VFY_VerifyDataDirect(kMsg, sizeof(kMsg), pub_.get(), sig_.get(),
                                 oid_, SEC_OID_SHA256, nullptr, nullptr));
}

// The generic entry points take the algorithm from the signed object, so they
// have to reject a parameter set that isn't the key's rather than let the
// object's label pick which parameter set's policy is consulted. The signature
// itself would verify -- softoken takes the parameter set from the key -- so
// the mismatch has to be caught before that.
TEST_P(CryptohiMlDsaKeyTest, VerifyRejectsARelabelledParameterSet) {
  ScopedPLArenaPool arena(PORT_NewArena(DER_DEFAULT_CHUNKSIZE));
  ASSERT_TRUE(arena);

  for (SECOidTag other :
       {SEC_OID_ML_DSA_44, SEC_OID_ML_DSA_65, SEC_OID_ML_DSA_87}) {
    if (other == oid_) {
      continue;
    }
    SCOPED_TRACE(testing::Message() << "relabelled as " << other);

    SECAlgorithmID algid = {};
    ASSERT_EQ(SECSuccess,
              SECOID_SetAlgorithmID(arena.get(), &algid, other, nullptr));

    // hash must be left alone on failure, never set to the label.
    SECOidTag hash = SEC_OID_UNKNOWN;
    EXPECT_EQ(SECFailure, VFY_VerifyDataWithAlgorithmID(
                              kMsg, sizeof(kMsg), pub_.get(), sig_.get(),
                              &algid, &hash, nullptr));
    EXPECT_EQ(SEC_ERROR_PKCS7_KEYALG_MISMATCH, PORT_GetError());
    EXPECT_EQ(SEC_OID_UNKNOWN, hash);

    EXPECT_FALSE(VFY_CreateContextWithAlgorithmID(pub_.get(), sig_.get(),
                                                  &algid, &hash, nullptr));
    EXPECT_EQ(SEC_ERROR_PKCS7_KEYALG_MISMATCH, PORT_GetError());
    EXPECT_EQ(SEC_OID_UNKNOWN, hash);

    EXPECT_EQ(SECFailure, VFY_VerifyData(kMsg, sizeof(kMsg), pub_.get(),
                                         sig_.get(), other, nullptr));
    EXPECT_EQ(SEC_ERROR_PKCS7_KEYALG_MISMATCH, PORT_GetError());

    EXPECT_FALSE(VFY_CreateContext(pub_.get(), sig_.get(), other, nullptr));
    EXPECT_EQ(SEC_ERROR_PKCS7_KEYALG_MISMATCH, PORT_GetError());

    // The *Direct entry points are covered too, with the parameter set named
    // as the hash and left unnamed.
    EXPECT_EQ(SECFailure,
              VFY_VerifyDataDirect(kMsg, sizeof(kMsg), pub_.get(), sig_.get(),
                                   other, other, &hash, nullptr));
    EXPECT_EQ(SEC_ERROR_PKCS7_KEYALG_MISMATCH, PORT_GetError());
    EXPECT_EQ(SEC_OID_UNKNOWN, hash);

    EXPECT_EQ(SECFailure,
              VFY_VerifyDataDirect(kMsg, sizeof(kMsg), pub_.get(), sig_.get(),
                                   other, SEC_OID_UNKNOWN, &hash, nullptr));
    EXPECT_EQ(SEC_ERROR_PKCS7_KEYALG_MISMATCH, PORT_GetError());
    EXPECT_EQ(SEC_OID_UNKNOWN, hash);
  }

  // The honestly labelled signature still verifies, and reports the key's own
  // parameter set back.
  SECAlgorithmID algid = {};
  ASSERT_EQ(SECSuccess,
            SECOID_SetAlgorithmID(arena.get(), &algid, oid_, nullptr));
  SECOidTag hash = SEC_OID_UNKNOWN;
  EXPECT_EQ(SECSuccess,
            VFY_VerifyDataWithAlgorithmID(kMsg, sizeof(kMsg), pub_.get(),
                                          sig_.get(), &algid, &hash, nullptr))
      << PORT_ErrorToString(PORT_GetError());
  EXPECT_EQ(oid_, hash);
}

// ML-DSA signs the message, not a digest of it, so there is nothing for the
// digest entry point to do once it has a context.
TEST_P(CryptohiMlDsaKeyTest, VerifyDigestDirectIsUnsupported) {
  unsigned char digest[SHA256_LENGTH];
  ASSERT_EQ(SECSuccess,
            PK11_HashBuf(SEC_OID_SHA256, digest, kMsg, sizeof(kMsg)));
  SECItem digestItem = {siBuffer, digest, sizeof(digest)};

  EXPECT_EQ(SECFailure,
            VFY_VerifyDigestDirect(&digestItem, pub_.get(), sig_.get(), oid_,
                                   oid_, nullptr));
  EXPECT_EQ(SEC_ERROR_UNSUPPORTED_KEYALG, PORT_GetError());
}

INSTANTIATE_TEST_SUITE_P(CryptohiMlDsaKeyTest, CryptohiMlDsaKeyTest,
                         ::testing::Values(SEC_OID_ML_DSA_44, SEC_OID_ML_DSA_65,
                                           SEC_OID_ML_DSA_87));

}  // namespace nss_test
