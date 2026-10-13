/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <algorithm>
#include <memory>
#include "nss.h"
#include "prerror.h"
#include "pk11pub.h"
#include "sechash.h"
#include "cryptohi.h"

#include "cpputil.h"
#include "databuffer.h"
#include "json_reader.h"
#include "pk11_signature_test.h"

#include "gtest/gtest.h"
#include "nss_scoped_ptrs.h"

#include "testvectors_base/test-structs.h"

namespace nss_test {
CK_MECHANISM_TYPE
DsaHashToComboMech(SECOidTag hash) {
  switch (hash) {
    case SEC_OID_SHA1:
      return CKM_DSA_SHA1;
    case SEC_OID_SHA224:
      return CKM_DSA_SHA224;
    case SEC_OID_SHA256:
      return CKM_DSA_SHA256;
    case SEC_OID_SHA384:
      return CKM_DSA_SHA384;
    case SEC_OID_SHA512:
      return CKM_DSA_SHA512;
    default:
      break;
  }
  return CKM_INVALID_MECHANISM;
}

class Pkcs11DsaTestBase : public Pk11SignatureTest {
 protected:
  Pkcs11DsaTestBase(SECOidTag hashOid)
      : Pk11SignatureTest(CKM_DSA, hashOid, DsaHashToComboMech(hashOid)) {}

  void Verify(const DsaTestVector vec) {
    /* DSA vectors encode the signature in DER, we need to unwrap it before
     * we can send the raw signatures to PKCS #11. */
    DataBuffer pubKeyBuffer(vec.public_key.data(), vec.public_key.size());
    ScopedSECKEYPublicKey nssPubKey(ImportPublicKey(pubKeyBuffer));
    SECItem sigItem = {siBuffer, toUcharPtr(vec.sig.data()),
                       static_cast<unsigned int>(vec.sig.size())};
    ScopedSECItem decodedSigItem(
        DSAU_DecodeDerSigToLen(&sigItem, SECKEY_SignatureLen(nssPubKey.get())));
    if (!decodedSigItem) {
      ASSERT_FALSE(vec.valid) << "Failed to decode DSA signature Error: "
                              << PORT_ErrorToString(PORT_GetError()) << "\n";
      return;
    }

    Pkcs11SignatureTestParams params = {
        DataBuffer(), pubKeyBuffer, DataBuffer(vec.msg.data(), vec.msg.size()),
        DataBuffer(decodedSigItem.get()->data, decodedSigItem.get()->len)};
    Pk11SignatureTest::Verify(params, (bool)vec.valid);
  }
};

class Pkcs11DsaTest : public Pkcs11DsaTestBase,
                      public ::testing::WithParamInterface<SECOidTag> {
 public:
  Pkcs11DsaTest() : Pkcs11DsaTestBase(GetParam()), tests_run_(0) {}

 protected:
  void Run() {
    WycheproofHeader("dsa", "DSA", "dsa_verify_schema.json",
                     [this](JsonReader& r) { RunGroup(r); });
    EXPECT_LT(0U, tests_run_) << "no test groups use this hash";
  }

 private:
  void RunGroup(JsonReader& r) {
    std::vector<DsaTestVector> tests;
    std::vector<uint8_t> public_key;
    SECOidTag hash_oid = SEC_OID_UNKNOWN;

    while (r.NextItem()) {
      std::string n = r.ReadLabel();
      if (n == "") {
        break;
      }

      if (n == "key" || n == "keyPem") {
        r.SkipValue();
      } else if (n == "keyDer") {
        public_key = r.ReadHex();
      } else if (n == "sha") {
        hash_oid = r.ReadHash();
      } else if (n == "type") {
        ASSERT_EQ("DsaVerify", r.ReadString());
      } else if (n == "tests") {
        WycheproofReadTests(r, &tests, ReadTestAttr, false,
                            [](DsaTestVector& t, const std::string& result,
                               const std::vector<std::string>& flags) {
                              // NSS accepts signatures that are missing the
                              // leading zero on a positive integer.
                              if (result == "acceptable" &&
                                  std::find(flags.begin(), flags.end(),
                                            "NoLeadingZero") != flags.end()) {
                                t.valid = true;
                              }
                            });
      } else {
        FAIL() << "unknown label in group: " << n;
      }
    }

    // The file mixes groups for several hashes, but the base class is
    // configured for a single hash. Only run the groups that use it.
    if (hash_oid != GetParam()) {
      return;
    }

    for (auto& t : tests) {
      std::cout << "Running test " << t.id << std::endl;
      t.public_key = public_key;
      t.hash_oid = hash_oid;
      Verify(t);
      tests_run_++;
    }
  }

  static void ReadTestAttr(DsaTestVector& t, const std::string& n,
                           JsonReader& r) {
    if (n == "msg") {
      t.msg = r.ReadHex();
    } else if (n == "sig") {
      t.sig = r.ReadHex();
    } else {
      FAIL() << "unknown test key: " << n;
    }
  }

  size_t tests_run_;
};

TEST_P(Pkcs11DsaTest, WycheproofVectors) { Run(); }

INSTANTIATE_TEST_SUITE_P(DsaTest, Pkcs11DsaTest,
                         ::testing::Values(SEC_OID_SHA1, SEC_OID_SHA224,
                                           SEC_OID_SHA256));

}  // namespace nss_test
