/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <memory>
#include "gtest/gtest.h"
#include "json_reader.h"
#include "nss.h"
#include "nss_scoped_ptrs.h"
#include "pk11hpke.h"
#include "pk11pub.h"
#include "secerr.h"
#include "sechash.h"
#include "util.h"

extern std::string g_source_dir;

namespace nss_test {

/* See note in pk11pub.h. */
#include "cpputil.h"

class HpkeTest {
 protected:
  void CheckEquality(const std::vector<uint8_t>& expected, SECItem* actual) {
    if (!actual) {
      EXPECT_TRUE(expected.empty());
      return;
    }
    std::vector<uint8_t> vact(actual->data, actual->data + actual->len);
    EXPECT_EQ(expected, vact);
  }

  void CheckEquality(SECItem* expected, SECItem* actual) {
    EXPECT_EQ(!!expected, !!actual);
    if (expected && actual) {
      EXPECT_EQ(expected->len, actual->len);
      if (expected->len == actual->len) {
        EXPECT_EQ(0, memcmp(expected->data, actual->data, actual->len));
      }
    }
  }

  void CheckEquality(const std::vector<uint8_t>& expected, PK11SymKey* actual) {
    if (!actual) {
      EXPECT_TRUE(expected.empty());
      return;
    }
    SECStatus rv = PK11_ExtractKeyValue(actual);
    EXPECT_EQ(SECSuccess, rv);
    if (rv != SECSuccess) {
      return;
    }
    SECItem* rawkey = PK11_GetKeyData(actual);
    CheckEquality(expected, rawkey);
  }

  void CheckEquality(PK11SymKey* expected, PK11SymKey* actual) {
    if (!actual || !expected) {
      EXPECT_EQ(!!expected, !!actual);
      return;
    }
    SECStatus rv = PK11_ExtractKeyValue(expected);
    EXPECT_EQ(SECSuccess, rv);
    if (rv != SECSuccess) {
      return;
    }
    SECItem* raw = PK11_GetKeyData(expected);
    ASSERT_NE(nullptr, raw);
    ASSERT_NE(nullptr, raw->data);
    std::vector<uint8_t> expected_vec(raw->data, raw->data + raw->len);
    CheckEquality(expected_vec, actual);
  }

  void Seal(const ScopedHpkeContext& cx, const std::vector<uint8_t>& aad_vec,
            const std::vector<uint8_t>& pt_vec,
            std::vector<uint8_t>* out_sealed) {
    SECItem aad_item = {siBuffer, toUcharPtr(aad_vec.data()),
                        static_cast<unsigned int>(aad_vec.size())};
    SECItem pt_item = {siBuffer, toUcharPtr(pt_vec.data()),
                       static_cast<unsigned int>(pt_vec.size())};

    SECItem* sealed_item = nullptr;
    EXPECT_EQ(SECSuccess,
              PK11_HPKE_Seal(cx.get(), &aad_item, &pt_item, &sealed_item));
    ASSERT_NE(nullptr, sealed_item);
    ScopedSECItem sealed(sealed_item);
    out_sealed->assign(sealed->data, sealed->data + sealed->len);
  }

  void Open(const ScopedHpkeContext& cx, const std::vector<uint8_t>& aad_vec,
            const std::vector<uint8_t>& ct_vec,
            std::vector<uint8_t>* out_opened) {
    SECItem aad_item = {siBuffer, toUcharPtr(aad_vec.data()),
                        static_cast<unsigned int>(aad_vec.size())};
    SECItem ct_item = {siBuffer, toUcharPtr(ct_vec.data()),
                       static_cast<unsigned int>(ct_vec.size())};
    SECItem* opened_item = nullptr;
    EXPECT_EQ(SECSuccess,
              PK11_HPKE_Open(cx.get(), &aad_item, &ct_item, &opened_item));
    ASSERT_NE(nullptr, opened_item);
    ScopedSECItem opened(opened_item);
    out_opened->assign(opened->data, opened->data + opened->len);
  }

  void SealOpen(const ScopedHpkeContext& sender,
                const ScopedHpkeContext& receiver,
                const std::vector<uint8_t>& msg,
                const std::vector<uint8_t>& aad,
                const std::vector<uint8_t>* expect) {
    std::vector<uint8_t> sealed;
    std::vector<uint8_t> opened;
    Seal(sender, aad, msg, &sealed);
    if (expect) {
      EXPECT_EQ(*expect, sealed);
    }
    Open(receiver, aad, sealed, &opened);
    EXPECT_EQ(msg, opened);
  }

  void ExportSecret(const ScopedHpkeContext& receiver,
                    ScopedPK11SymKey& exported) {
    std::vector<uint8_t> context = {'c', 't', 'x', 't'};
    SECItem context_item = {siBuffer, context.data(),
                            static_cast<unsigned int>(context.size())};
    PK11SymKey* tmp_exported = nullptr;
    ASSERT_EQ(SECSuccess, PK11_HPKE_ExportSecret(receiver.get(), &context_item,
                                                 64, &tmp_exported));
    exported.reset(tmp_exported);
  }

  void ExportImportRecvContext(ScopedHpkeContext& scoped_cx,
                               PK11SymKey* wrapping_key) {
    SECItem* tmp_exported = nullptr;
    EXPECT_EQ(SECSuccess, PK11_HPKE_ExportContext(scoped_cx.get(), wrapping_key,
                                                  &tmp_exported));
    EXPECT_NE(nullptr, tmp_exported);
    ScopedSECItem context(tmp_exported);
    scoped_cx.reset();

    HpkeContext* tmp_imported =
        PK11_HPKE_ImportContext(context.get(), wrapping_key);
    EXPECT_NE(nullptr, tmp_imported);
    scoped_cx.reset(tmp_imported);
  }

  SECOidTag GetKemOid(HpkeKemId kem) {
    switch (kem) {
      case HpkeDhKemX25519Sha256:
        return SEC_OID_X25519;
      case HpkeDhKemP256Sha256:
        return SEC_OID_ANSIX962_EC_PRIME256V1;
      case HpkeDhKemP384Sha384:
        return SEC_OID_SECG_EC_SECP384R1;
      case HpkeDhKemP521Sha512:
        return SEC_OID_SECG_EC_SECP521R1;
      default:
        return SEC_OID_UNKNOWN;
    }
  }

  bool GenerateKeyPair(ScopedSECKEYPublicKey& pub_key,
                       ScopedSECKEYPrivateKey& priv_key,
                       HpkeKemId kem = HpkeDhKemX25519Sha256,
                       SECOidTag kemOid = SEC_OID_UNKNOWN,
                       CK_MECHANISM_TYPE mech = 0) {
    ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
    if (!slot) {
      ADD_FAILURE() << "Couldn't get slot";
      return false;
    }

    unsigned char param_buf[65];
    SECItem params = {siBuffer, param_buf, sizeof(param_buf)};
    if (kemOid == SEC_OID_UNKNOWN) {
      kemOid = GetKemOid(kem);
    }
    SECOidData* oid_data = SECOID_FindOIDByTag(kemOid);
    if (!oid_data) {
      ADD_FAILURE() << "Couldn't get oid_data";
      return false;
    }
    params.data[0] = SEC_ASN1_OBJECT_ID;
    params.data[1] = oid_data->oid.len;
    memcpy(params.data + 2, oid_data->oid.data, oid_data->oid.len);
    params.len = oid_data->oid.len + 2;

    if (!mech) {
      // mech 0 is CKM_RSA_PKCS_KEY_PAIR_GEN, but we won't be using that.
      switch (kem) {
        case HpkeDhKemX25519Sha256:
          mech = CKM_EC_MONTGOMERY_KEY_PAIR_GEN;
          break;
        case HpkeDhKemP256Sha256:
        case HpkeDhKemP384Sha384:
        case HpkeDhKemP521Sha512:
          mech = CKM_EC_KEY_PAIR_GEN;
          break;
        default:
          ADD_FAILURE() << "unknown mechanism for kem";
          return false;
      }
    }

    SECKEYPublicKey* pub_tmp;
    SECKEYPrivateKey* priv_tmp;
    priv_tmp = PK11_GenerateKeyPair(slot.get(), mech, &params, &pub_tmp,
                                    PR_FALSE, PR_TRUE, nullptr);
    if (!pub_tmp || !priv_tmp) {
      ADD_FAILURE() << "PK11_GenerateKeyPair failed: " << PORT_GetError();
      return false;
    }

    pub_key.reset(pub_tmp);
    priv_key.reset(priv_tmp);
    return true;
  }

  void MakeEphemeralContexts(ScopedHpkeContext& sender,
                             ScopedHpkeContext& receiver,
                             HpkeModeId mode = HpkeModeBase,
                             HpkeKemId kem = HpkeDhKemX25519Sha256,
                             HpkeKdfId kdf = HpkeKdfHkdfSha256,
                             HpkeAeadId aead = HpkeAeadAes128Gcm) {
    // Generate a PSK, if the mode calls for it.
    PRUint8 psk_id_buf[] = {'p', 's', 'k', '-', 'i', 'd'};
    SECItem psk_id = {siBuffer, psk_id_buf, sizeof(psk_id_buf)};
    SECItem* psk_id_item = (mode == HpkeModePsk) ? &psk_id : nullptr;
    ScopedPK11SymKey psk;
    if (mode == HpkeModePsk) {
      ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
      ASSERT_TRUE(slot);
      PK11SymKey* tmp_psk =
          PK11_KeyGen(slot.get(), CKM_HKDF_DERIVE, nullptr, 16, nullptr);
      ASSERT_NE(nullptr, tmp_psk);
      psk.reset(tmp_psk);
    }

    sender.reset(PK11_HPKE_NewContext(kem, kdf, aead, psk.get(), psk_id_item));
    receiver.reset(
        PK11_HPKE_NewContext(kem, kdf, aead, psk.get(), psk_id_item));
    ASSERT_TRUE(sender);
    ASSERT_TRUE(receiver);
  }

  void SetUpEphemeralContexts(ScopedHpkeContext& sender,
                              ScopedHpkeContext& receiver,
                              HpkeModeId mode = HpkeModeBase,
                              HpkeKemId kem = HpkeDhKemX25519Sha256,
                              HpkeKdfId kdf = HpkeKdfHkdfSha256,
                              HpkeAeadId aead = HpkeAeadAes128Gcm) {
    ASSERT_NO_FATAL_FAILURE(
        MakeEphemeralContexts(sender, receiver, mode, kem, kdf, aead));

    std::vector<uint8_t> info = {'t', 'e', 's', 't', '-', 'i', 'n', 'f', 'o'};
    SECItem info_item = {siBuffer, info.data(),
                         static_cast<unsigned int>(info.size())};

    ScopedSECKEYPublicKey pub_key_r;
    ScopedSECKEYPrivateKey priv_key_r;
    ASSERT_TRUE(GenerateKeyPair(pub_key_r, priv_key_r, kem));
    EXPECT_EQ(SECSuccess, PK11_HPKE_SetupS(sender.get(), nullptr, nullptr,
                                           pub_key_r.get(), &info_item));

    const SECItem* enc = PK11_HPKE_GetEncapPubKey(sender.get());
    EXPECT_NE(nullptr, enc);
    EXPECT_EQ(SECSuccess, PK11_HPKE_SetupR(
                              receiver.get(), pub_key_r.get(), priv_key_r.get(),
                              const_cast<SECItem*>(enc), &info_item));
  }
};

struct HpkeEncryptVector {
  std::vector<uint8_t> pt;
  std::vector<uint8_t> aad;
  std::vector<uint8_t> ct;

  static std::vector<HpkeEncryptVector> ReadVec(JsonReader& r) {
    std::vector<HpkeEncryptVector> all;

    while (r.NextItemArray()) {
      HpkeEncryptVector enc;
      while (r.NextItem()) {
        std::string n = r.ReadLabel();
        if (n == "") {
          break;
        }
        /* "plaintext"/"ciphertext" in the preprocessed form,
         * "pt"/"ct" in the official form. */
        if (n == "plaintext" || n == "pt") {
          enc.pt = r.ReadHex();
        } else if (n == "aad") {
          enc.aad = r.ReadHex();
        } else if (n == "ciphertext" || n == "ct") {
          enc.ct = r.ReadHex();
        } else {
          r.SkipValue();
        }
      }
      all.push_back(enc);
    }

    return all;
  }
};

struct HpkeExportVector {
  std::vector<uint8_t> ctxt;
  size_t len;
  std::vector<uint8_t> exported;

  static std::vector<HpkeExportVector> ReadVec(JsonReader& r) {
    std::vector<HpkeExportVector> all;

    while (r.NextItemArray()) {
      HpkeExportVector exp;
      while (r.NextItem()) {
        std::string n = r.ReadLabel();
        if (n == "") {
          break;
        }
        if (n == "exporter_context") {
          exp.ctxt = r.ReadHex();
        } else if (n == "L") {
          exp.len = r.ReadInt();
        } else if (n == "exported_value") {
          exp.exported = r.ReadHex();
        } else {
          r.SkipValue();
        }
      }
      all.push_back(exp);
    }

    return all;
  }
};

struct HpkeVector {
  uint32_t test_id;
  HpkeModeId mode;
  HpkeKemId kem_id;
  HpkeKdfId kdf_id;
  HpkeAeadId aead_id;
  std::vector<uint8_t> info;
  std::vector<uint8_t> pkcs8_e;
  std::vector<uint8_t> pkcs8_r;
  std::vector<uint8_t> psk;
  std::vector<uint8_t> psk_id;
  std::vector<uint8_t> enc;
  std::vector<uint8_t> key;
  std::vector<uint8_t> nonce;
  std::vector<HpkeEncryptVector> encryptions;
  std::vector<HpkeExportVector> exports;
  /* Some vector sets (the official form) only provide the ephemeral key as
   * ikmE, not as skEm/pkEm, so the sender flow can't be reproduced
   * deterministically. Those are validated via the receiver (decap) flow. */
  bool has_sender_keys;

  static std::vector<uint8_t> Pkcs8(HpkeKemId kem,
                                    const std::vector<uint8_t>& sk,
                                    const std::vector<uint8_t>& pk) {
    std::vector<uint8_t> v;
    switch (kem) {
      case HpkeDhKemX25519Sha256:
        EXPECT_EQ(32U, sk.size());
        v.assign(
            // PrivateKeyInfo SEQUENCE (97 bytes of content).
            {0x30, 0x61,
             // version INTEGER 0
             0x02, 0x01, 0x00,
             // privateKeyAlgorithm: ecPublicKey + X25519
             0x30, 0x0e, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
             0x06, 0x03, 0x2b, 0x65, 0x6e,
             // privateKey OCTET STRING wrapping the ECPrivateKey (74 bytes)
             0x04, 0x4c,
             // ECPrivateKey SEQUENCE (172 bytes of content)
             0x30, 0x4a,
             // version INTEGER 1
             0x02, 0x01, 0x01,
             // privateKey OCTET STRING (32 bytes)
             0x04, 0x20});
        break;

      case HpkeDhKemP256Sha256:
        EXPECT_EQ(32U, sk.size());
        v.assign(
            // PrivateKeyInfo SEQUENCE (135 bytes of content).
            {0x30, 0x81, 0x87,
             // version INTEGER 0
             0x02, 0x01, 0x00,
             // privateKeyAlgorithm: ecPublicKey + prime256v1
             0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
             0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
             // privateKey OCTET STRING wrapping the ECPrivateKey (109 bytes)
             0x04, 0x6d,
             // ECPrivateKey SEQUENCE (107 bytes of content)
             0x30, 0x6b,
             // version INTEGER 1
             0x02, 0x01, 0x01,
             // privateKey OCTET STRING (32 bytes)
             0x04, 0x20});
        break;

      case HpkeDhKemP384Sha384:
        EXPECT_EQ(48U, sk.size());
        v.assign(
            // PrivateKeyInfo SEQUENCE (182 bytes of content).
            {0x30, 0x81, 0xb6,
             // version INTEGER 0
             0x02, 0x01, 0x00,
             // privateKeyAlgorithm: ecPublicKey + secp384r1
             0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
             0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
             // privateKey OCTET STRING wrapping the ECPrivateKey (158 bytes)
             0x04, 0x81, 0x9e,
             // ECPrivateKey SEQUENCE (155 bytes of content)
             0x30, 0x81, 0x9b,
             // version INTEGER 1
             0x02, 0x01, 0x01,
             // privateKey OCTET STRING (48 bytes)
             0x04, 0x30});
        break;

      default:
        ADD_FAILURE() << "Unsupported KEM";
        return v;
    }
    v.insert(v.end(), sk.begin(), sk.end());

    switch (kem) {
      case HpkeDhKemX25519Sha256:
        EXPECT_EQ(32U, pk.size());
        // publicKey [1] EXPLICIT BIT STRING (32-byte point, 0 unused bits)
        v.insert(v.end(), {0xa1, 0x23, 0x03, 0x21, 0x00});
        break;

      case HpkeDhKemP256Sha256:
        EXPECT_EQ(65U, pk.size());
        // publicKey [1] EXPLICIT BIT STRING (65-byte point, 0 unused bits)
        v.insert(v.end(), {0xa1, 0x44, 0x03, 0x42, 0x00});
        break;

      case HpkeDhKemP384Sha384:
        EXPECT_EQ(97U, pk.size());
        // publicKey [1] EXPLICIT BIT STRING (97-byte point, 0 unused bits)
        v.insert(v.end(), {0xa1, 0x64, 0x03, 0x62, 0x00});
        break;

      default:
        break;  // unreachable
    }
    v.insert(v.end(), pk.begin(), pk.end());
    return v;
  }

  static std::vector<HpkeVector> Read(JsonReader& r) {
    std::vector<HpkeVector> all_tests;
    uint32_t test_id = 0;

    while (r.NextItemArray()) {
      HpkeVector vec = {0};
      uint32_t fields = 0;
      /* skEm/pkEm are intentionally not required: the official vector form
       * only provides the ephemeral key as ikmE. Vectors that omit them are
       * exercised through the receiver (decap) flow instead. */
      enum class RequiredFields { mode, kem, kdf, aead, skRm, pkRm, all };
      std::vector<uint8_t> sk_e, pk_e, sk_r, pk_r;
      test_id++;

      while (r.NextItem()) {
        std::string n = r.ReadLabel();
        if (n == "") {
          break;
        }
        if (n == "mode") {
          vec.mode = static_cast<HpkeModeId>(r.ReadInt());
          fields |= 1 << static_cast<uint32_t>(RequiredFields::mode);
        } else if (n == "kem_id") {
          vec.kem_id = static_cast<HpkeKemId>(r.ReadInt());
          fields |= 1 << static_cast<uint32_t>(RequiredFields::kem);
        } else if (n == "kdf_id") {
          vec.kdf_id = static_cast<HpkeKdfId>(r.ReadInt());
          fields |= 1 << static_cast<uint32_t>(RequiredFields::kdf);
        } else if (n == "aead_id") {
          vec.aead_id = static_cast<HpkeAeadId>(r.ReadInt());
          fields |= 1 << static_cast<uint32_t>(RequiredFields::aead);
        } else if (n == "info") {
          vec.info = r.ReadHex();
        } else if (n == "skEm") {
          sk_e = r.ReadHex();
        } else if (n == "pkEm") {
          pk_e = r.ReadHex();
        } else if (n == "skRm") {
          sk_r = r.ReadHex();
          fields |= 1 << static_cast<uint32_t>(RequiredFields::skRm);
        } else if (n == "pkRm") {
          pk_r = r.ReadHex();
          fields |= 1 << static_cast<uint32_t>(RequiredFields::pkRm);
        } else if (n == "psk") {
          vec.psk = r.ReadHex();
        } else if (n == "psk_id") {
          vec.psk_id = r.ReadHex();
        } else if (n == "enc") {
          vec.enc = r.ReadHex();
        } else if (n == "key") {
          vec.key = r.ReadHex();
        } else if (n == "base_nonce") {
          vec.nonce = r.ReadHex();
        } else if (n == "encryptions") {
          vec.encryptions = HpkeEncryptVector::ReadVec(r);
        } else if (n == "exports") {
          vec.exports = HpkeExportVector::ReadVec(r);
        } else {
          r.SkipValue();
        }
      }

      if (fields != (1 << static_cast<uint32_t>(RequiredFields::all)) - 1) {
        std::cerr << "Skipping entry " << test_id << " for missing fields"
                  << std::endl;
        continue;
      }
      // Skip modes and configurations we don't support.
      if (vec.mode != HpkeModeBase && vec.mode != HpkeModePsk) {
        continue;
      }
      SECStatus rv =
          PK11_HPKE_ValidateParameters(vec.kem_id, vec.kdf_id, vec.aead_id);
      if (rv != SECSuccess) {
        continue;
      }

      vec.test_id = test_id;
      vec.has_sender_keys = !sk_e.empty() && !pk_e.empty();
      if (vec.has_sender_keys) {
        vec.pkcs8_e = HpkeVector::Pkcs8(vec.kem_id, sk_e, pk_e);
      }
      vec.pkcs8_r = HpkeVector::Pkcs8(vec.kem_id, sk_r, pk_r);
      all_tests.push_back(vec);
    }

    return all_tests;
  }
};

class TestVectors : public HpkeTest, public ::testing::Test {
  struct Endpoint {
    bool init(const HpkeVector& vec, const std::vector<uint8_t>& sk_data) {
      ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
      if (!slot) {
        ADD_FAILURE() << "No slot";
        return false;
      }

      cx_ = Endpoint::MakeContext(slot, vec);

      SECItem item = {siBuffer, toUcharPtr(sk_data.data()),
                      static_cast<unsigned int>(sk_data.size())};
      SECKEYPrivateKey* sk = nullptr;
      SECStatus rv = PK11_ImportDERPrivateKeyInfoAndReturnKey(
          slot.get(), &item, nullptr, nullptr, false, false, KU_ALL, &sk,
          nullptr);
      if (rv != SECSuccess) {
        ADD_FAILURE() << "Failed to import secret";
        return false;
      }
      sk_.reset(sk);
      SECKEYPublicKey* pk = SECKEY_ConvertToPublicKey(sk_.get());
      pk_.reset(pk);
      return cx_ && sk_ && pk_;
    }

    static ScopedHpkeContext MakeContext(const ScopedPK11SlotInfo& slot,
                                         const HpkeVector& vec) {
      ScopedPK11SymKey psk = Endpoint::ReadPsk(slot, vec);
      SECItem psk_id_item = {siBuffer, toUcharPtr(vec.psk_id.data()),
                             static_cast<unsigned int>(vec.psk_id.size())};
      SECItem* psk_id = psk ? &psk_id_item : nullptr;
      return ScopedHpkeContext(PK11_HPKE_NewContext(
          vec.kem_id, vec.kdf_id, vec.aead_id, psk.get(), psk_id));
    }

    static ScopedPK11SymKey ReadPsk(const ScopedPK11SlotInfo& slot,
                                    const HpkeVector& vec) {
      ScopedPK11SymKey psk;
      if (!vec.psk.empty()) {
        SECItem psk_item = {siBuffer, toUcharPtr(vec.psk.data()),
                            static_cast<unsigned int>(vec.psk.size())};
        PK11SymKey* psk_key =
            PK11_ImportSymKey(slot.get(), CKM_HKDF_KEY_GEN, PK11_OriginUnwrap,
                              CKA_WRAP, &psk_item, nullptr);
        EXPECT_NE(nullptr, psk_key);
        psk.reset(psk_key);
      }
      return psk;
    }

    ScopedHpkeContext cx_;
    ScopedSECKEYPublicKey pk_;
    ScopedSECKEYPrivateKey sk_;
  };

 protected:
  void TestExports(const HpkeVector& vec, const Endpoint& sender,
                   const Endpoint& receiver) {
    for (auto& exp : vec.exports) {
      SECItem context_item = {siBuffer, toUcharPtr(exp.ctxt.data()),
                              static_cast<unsigned int>(exp.ctxt.size())};
      PK11SymKey* actual_r = nullptr;
      PK11SymKey* actual_s = nullptr;
      ASSERT_EQ(SECSuccess,
                PK11_HPKE_ExportSecret(sender.cx_.get(), &context_item, exp.len,
                                       &actual_s));
      ASSERT_EQ(SECSuccess,
                PK11_HPKE_ExportSecret(receiver.cx_.get(), &context_item,
                                       exp.len, &actual_r));
      ScopedPK11SymKey scoped_act_s(actual_s);
      ScopedPK11SymKey scoped_act_r(actual_r);
      CheckEquality(exp.exported, scoped_act_s.get());
      CheckEquality(exp.exported, scoped_act_r.get());
    }
  }

  void TestEncryptions(const HpkeVector& vec, const Endpoint& sender,
                       const Endpoint& receiver) {
    for (auto& enc : vec.encryptions) {
      SealOpen(sender.cx_, receiver.cx_, enc.pt, enc.aad, &enc.ct);
    }
  }

  /* When only receiver key material is available, validate the known-answer
   * ciphertexts by decrypting them. Encryptions are consecutive from
   * sequence 0, matching the receiver's per-Open nonce increment. */
  void TestDecryptions(const HpkeVector& vec, const Endpoint& receiver) {
    for (auto& enc : vec.encryptions) {
      std::vector<uint8_t> opened;
      Open(receiver.cx_, enc.aad, enc.ct, &opened);
      EXPECT_EQ(enc.pt, opened);
    }
  }

  void TestExportsReceiver(const HpkeVector& vec, const Endpoint& receiver) {
    for (auto& exp : vec.exports) {
      SECItem context_item = {siBuffer, toUcharPtr(exp.ctxt.data()),
                              static_cast<unsigned int>(exp.ctxt.size())};
      PK11SymKey* actual_r = nullptr;
      ASSERT_EQ(SECSuccess,
                PK11_HPKE_ExportSecret(receiver.cx_.get(), &context_item,
                                       exp.len, &actual_r));
      ScopedPK11SymKey scoped_act_r(actual_r);
      CheckEquality(exp.exported, scoped_act_r.get());
    }
  }

  void SetupS(const ScopedHpkeContext& cx, const ScopedSECKEYPublicKey& pkE,
              const ScopedSECKEYPrivateKey& skE,
              const ScopedSECKEYPublicKey& pkR,
              const std::vector<uint8_t>& info) {
    SECItem info_item = {siBuffer, toUcharPtr(info.data()),
                         static_cast<unsigned int>(info.size())};
    EXPECT_EQ(SECSuccess, PK11_HPKE_SetupS(cx.get(), pkE.get(), skE.get(),
                                           pkR.get(), &info_item));
  }

  void SetupR(const ScopedHpkeContext& cx, const ScopedSECKEYPublicKey& pkR,
              const ScopedSECKEYPrivateKey& skR,
              const std::vector<uint8_t>& enc,
              const std::vector<uint8_t>& info) {
    SECItem enc_item = {siBuffer, toUcharPtr(enc.data()),
                        static_cast<unsigned int>(enc.size())};
    SECItem info_item = {siBuffer, toUcharPtr(info.data()),
                         static_cast<unsigned int>(info.size())};
    EXPECT_EQ(SECSuccess, PK11_HPKE_SetupR(cx.get(), pkR.get(), skR.get(),
                                           &enc_item, &info_item));
  }

  void SetupSenderReceiver(const HpkeVector& vec, const Endpoint& sender,
                           const Endpoint& receiver) {
    SetupS(sender.cx_, sender.pk_, sender.sk_, receiver.pk_, vec.info);

    unsigned int len = 0;
    ASSERT_EQ(SECSuccess, PK11_HPKE_Serialize(sender.pk_.get(), NULL, &len, 0));
    std::vector<uint8_t> buf(static_cast<size_t>(len));

    SECItem encap_item = {siBuffer, buf.data(), len};
    ASSERT_EQ(SECSuccess, PK11_HPKE_Serialize(sender.pk_.get(), encap_item.data,
                                              &encap_item.len, len));
    CheckEquality(vec.enc, &encap_item);
    SetupR(receiver.cx_, receiver.pk_, receiver.sk_, vec.enc, vec.info);
  }

  void RunTestVector(const HpkeVector& vec) {
    Endpoint receiver;
    ASSERT_TRUE(receiver.init(vec, vec.pkcs8_r));

    if (vec.has_sender_keys) {
      /* Full sender + receiver flow, including deterministic enc. */
      Endpoint sender;
      ASSERT_TRUE(sender.init(vec, vec.pkcs8_e));
      SetupSenderReceiver(vec, sender, receiver);
      TestEncryptions(vec, sender, receiver);
      TestExports(vec, sender, receiver);
    } else {
      /* Receiver-only flow: decapsulate the provided enc and validate the
       * known-answer ciphertexts and exports. */
      SetupR(receiver.cx_, receiver.pk_, receiver.sk_, vec.enc, vec.info);
      TestDecryptions(vec, receiver);
      TestExportsReceiver(vec, receiver);
    }
  }
};

TEST_F(TestVectors, HpkeVectors) {
  for (const char* file : {"/hpke-vectors.json", "/hpke-vectors-decap.json"}) {
    JsonReader r(::g_source_dir + file);
    auto all_tests = HpkeVector::Read(r);
    for (auto& vec : all_tests) {
      std::cout << "HPKE vector " << file << " " << vec.test_id << std::endl;
      RunTestVector(vec);
    }
  }
}

class ModeParameterizedTest
    : public HpkeTest,
      public ::testing::TestWithParam<
          std::tuple<HpkeModeId, HpkeKemId, HpkeKdfId, HpkeAeadId>> {};

static const HpkeModeId kHpkeModesAll[] = {HpkeModeBase, HpkeModePsk};
static const HpkeKemId kHpkeKemIdsAll[] = {
    HpkeDhKemX25519Sha256, HpkeDhKemP256Sha256, HpkeDhKemP384Sha384};
static const HpkeKdfId kHpkeKdfIdsAll[] = {HpkeKdfHkdfSha256, HpkeKdfHkdfSha384,
                                           HpkeKdfHkdfSha512};
static const HpkeAeadId kHpkeAeadIdsAll[] = {HpkeAeadAes128Gcm,
                                             HpkeAeadChaCha20Poly1305};

INSTANTIATE_TEST_SUITE_P(
    Pk11Hpke, ModeParameterizedTest,
    ::testing::Combine(::testing::ValuesIn(kHpkeModesAll),
                       ::testing::ValuesIn(kHpkeKemIdsAll),
                       ::testing::ValuesIn(kHpkeKdfIdsAll),
                       ::testing::ValuesIn(kHpkeAeadIdsAll)));

TEST_P(ModeParameterizedTest, BadEncapsulatedPubKey) {
  ScopedHpkeContext sender(
      PK11_HPKE_NewContext(std::get<1>(GetParam()), std::get<2>(GetParam()),
                           std::get<3>(GetParam()), nullptr, nullptr));
  ScopedHpkeContext receiver(
      PK11_HPKE_NewContext(std::get<1>(GetParam()), std::get<2>(GetParam()),
                           std::get<3>(GetParam()), nullptr, nullptr));

  SECKEYPublicKey* tmp_pub_key;
  ScopedSECKEYPublicKey pub_key;
  ScopedSECKEYPrivateKey priv_key;
  ASSERT_TRUE(GenerateKeyPair(pub_key, priv_key, std::get<1>(GetParam())));

  SECItem empty = {siBuffer, nullptr, 0};
  unsigned int len = 0;
  ASSERT_EQ(SECSuccess, PK11_HPKE_Serialize(pub_key.get(), NULL, &len, 0));
  const unsigned int kExtra = 5;
  std::vector<uint8_t> buf(static_cast<size_t>(len + kExtra));
  SECItem short_encap = {siBuffer, buf.data(), 1};
  SECItem long_encap = {siBuffer, buf.data(), len + kExtra};

  // Decapsulating an empty buffer should fail.
  EXPECT_EQ(SECFailure, PK11_HPKE_Deserialize(sender.get(), empty.data,
                                              empty.len, &tmp_pub_key));
  EXPECT_EQ(SEC_ERROR_INVALID_ARGS, PORT_GetError());

  // Decapsulating anything short will succeed, but the setup will fail.
  EXPECT_EQ(SECSuccess, PK11_HPKE_Deserialize(sender.get(), short_encap.data,
                                              short_encap.len, &tmp_pub_key));
  ScopedSECKEYPublicKey bad_pub_key(tmp_pub_key);

  EXPECT_EQ(SECFailure,
            PK11_HPKE_SetupS(receiver.get(), pub_key.get(), priv_key.get(),
                             bad_pub_key.get(), &empty));
  EXPECT_EQ(SEC_ERROR_INVALID_KEY, PORT_GetError());

  // Test the same for a receiver.
  EXPECT_EQ(SECFailure, PK11_HPKE_SetupR(sender.get(), pub_key.get(),
                                         priv_key.get(), &empty, &empty));
  EXPECT_EQ(SEC_ERROR_INVALID_ARGS, PORT_GetError());
  EXPECT_EQ(SECFailure, PK11_HPKE_SetupR(sender.get(), pub_key.get(),
                                         priv_key.get(), &short_encap, &empty));
  EXPECT_EQ(SEC_ERROR_INVALID_KEY, PORT_GetError());

  // Encapsulated key too long
  EXPECT_EQ(SECSuccess, PK11_HPKE_Deserialize(sender.get(), long_encap.data,
                                              long_encap.len, &tmp_pub_key));
  bad_pub_key.reset(tmp_pub_key);
  EXPECT_EQ(SECFailure,
            PK11_HPKE_SetupS(receiver.get(), pub_key.get(), priv_key.get(),
                             bad_pub_key.get(), &empty));
  // The error handling for DER-encoded keys differs from X25519,
  // because DER decode is involved; tolerate either error code.
  EXPECT_TRUE(PORT_GetError() == SEC_ERROR_INVALID_KEY ||
              PORT_GetError() == SEC_ERROR_INVALID_ARGS);

  EXPECT_EQ(SECFailure, PK11_HPKE_SetupR(sender.get(), pub_key.get(),
                                         priv_key.get(), &long_encap, &empty));
  EXPECT_TRUE(PORT_GetError() == SEC_ERROR_INVALID_KEY ||
              PORT_GetError() == SEC_ERROR_INVALID_ARGS);
}

TEST_P(ModeParameterizedTest, ContextExportImportEncrypt) {
  std::vector<uint8_t> msg = {'s', 'e', 'c', 'r', 'e', 't'};
  std::vector<uint8_t> aad = {'a', 'a', 'd'};

  ScopedHpkeContext sender;
  ScopedHpkeContext receiver;
  SetUpEphemeralContexts(sender, receiver, std::get<0>(GetParam()),
                         std::get<1>(GetParam()), std::get<2>(GetParam()),
                         std::get<3>(GetParam()));
  SealOpen(sender, receiver, msg, aad, nullptr);
  ExportImportRecvContext(receiver, nullptr);
  SealOpen(sender, receiver, msg, aad, nullptr);
}

TEST_P(ModeParameterizedTest, ContextExportImportExport) {
  ScopedHpkeContext sender;
  ScopedHpkeContext receiver;
  ScopedPK11SymKey sender_export;
  ScopedPK11SymKey receiver_export;
  ScopedPK11SymKey receiver_reexport;
  SetUpEphemeralContexts(sender, receiver, std::get<0>(GetParam()),
                         std::get<1>(GetParam()), std::get<2>(GetParam()),
                         std::get<3>(GetParam()));
  ExportSecret(sender, sender_export);
  ExportSecret(receiver, receiver_export);
  CheckEquality(sender_export.get(), receiver_export.get());
  ExportImportRecvContext(receiver, nullptr);
  ExportSecret(receiver, receiver_reexport);
  CheckEquality(receiver_export.get(), receiver_reexport.get());
}

TEST_P(ModeParameterizedTest, ContextExportImportWithWrap) {
  std::vector<uint8_t> msg = {'s', 'e', 'c', 'r', 'e', 't'};
  std::vector<uint8_t> aad = {'a', 'a', 'd'};

  // Generate a wrapping key, then use it for export.
  ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
  ASSERT_TRUE(slot);
  ScopedPK11SymKey kek(
      PK11_KeyGen(slot.get(), CKM_AES_CBC, nullptr, 16, nullptr));
  ASSERT_NE(nullptr, kek);

  ScopedHpkeContext sender;
  ScopedHpkeContext receiver;
  SetUpEphemeralContexts(sender, receiver, std::get<0>(GetParam()),
                         std::get<1>(GetParam()), std::get<2>(GetParam()),
                         std::get<3>(GetParam()));
  SealOpen(sender, receiver, msg, aad, nullptr);
  ExportImportRecvContext(receiver, kek.get());
  SealOpen(sender, receiver, msg, aad, nullptr);
}

TEST_P(ModeParameterizedTest, ExportSenderContext) {
  std::vector<uint8_t> msg = {'s', 'e', 'c', 'r', 'e', 't'};
  std::vector<uint8_t> aad = {'a', 'a', 'd'};

  ScopedHpkeContext sender;
  ScopedHpkeContext receiver;
  SetUpEphemeralContexts(sender, receiver, std::get<0>(GetParam()),
                         std::get<1>(GetParam()), std::get<2>(GetParam()),
                         std::get<3>(GetParam()));

  SECItem* tmp_exported = nullptr;
  EXPECT_EQ(SECFailure,
            PK11_HPKE_ExportContext(sender.get(), nullptr, &tmp_exported));
  EXPECT_EQ(nullptr, tmp_exported);
  EXPECT_EQ(SEC_ERROR_NOT_A_RECIPIENT, PORT_GetError());
}

TEST_P(ModeParameterizedTest, ContextUnwrapBadKey) {
  std::vector<uint8_t> msg = {'s', 'e', 'c', 'r', 'e', 't'};
  std::vector<uint8_t> aad = {'a', 'a', 'd'};

  // Generate a wrapping key, then use it for export.
  ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
  ASSERT_TRUE(slot);
  ScopedPK11SymKey kek(
      PK11_KeyGen(slot.get(), CKM_AES_CBC, nullptr, 16, nullptr));
  ASSERT_NE(nullptr, kek);
  ScopedPK11SymKey not_kek(
      PK11_KeyGen(slot.get(), CKM_AES_CBC, nullptr, 16, nullptr));
  ASSERT_NE(nullptr, not_kek);
  ScopedHpkeContext sender;
  ScopedHpkeContext receiver;

  SetUpEphemeralContexts(sender, receiver, std::get<0>(GetParam()),
                         std::get<1>(GetParam()), std::get<2>(GetParam()),
                         std::get<3>(GetParam()));

  SECItem* tmp_exported = nullptr;
  EXPECT_EQ(SECSuccess,
            PK11_HPKE_ExportContext(receiver.get(), kek.get(), &tmp_exported));
  EXPECT_NE(nullptr, tmp_exported);
  ScopedSECItem context(tmp_exported);

  EXPECT_EQ(nullptr, PK11_HPKE_ImportContext(context.get(), not_kek.get()));
  EXPECT_EQ(SEC_ERROR_BAD_DATA, PORT_GetError());
}

TEST_P(ModeParameterizedTest, EphemeralKeys) {
  std::vector<uint8_t> msg = {'s', 'e', 'c', 'r', 'e', 't'};
  std::vector<uint8_t> aad = {'a', 'a', 'd'};
  SECItem msg_item = {siBuffer, msg.data(),
                      static_cast<unsigned int>(msg.size())};
  SECItem aad_item = {siBuffer, aad.data(),
                      static_cast<unsigned int>(aad.size())};
  ScopedHpkeContext sender;
  ScopedHpkeContext receiver;
  SetUpEphemeralContexts(sender, receiver, std::get<0>(GetParam()),
                         std::get<1>(GetParam()), std::get<2>(GetParam()),
                         std::get<3>(GetParam()));

  SealOpen(sender, receiver, msg, aad, nullptr);

  // Seal for negative tests
  SECItem* tmp_sealed = nullptr;
  SECItem* tmp_unsealed = nullptr;
  EXPECT_EQ(SECSuccess,
            PK11_HPKE_Seal(sender.get(), &aad_item, &msg_item, &tmp_sealed));
  ASSERT_NE(nullptr, tmp_sealed);
  ScopedSECItem sealed(tmp_sealed);

  // Drop AAD
  EXPECT_EQ(SECFailure, PK11_HPKE_Open(receiver.get(), nullptr, sealed.get(),
                                       &tmp_unsealed));
  EXPECT_EQ(SEC_ERROR_BAD_DATA, PORT_GetError());
  EXPECT_EQ(nullptr, tmp_unsealed);

  // Modify AAD
  aad_item.data[0] ^= 0xff;
  EXPECT_EQ(SECFailure, PK11_HPKE_Open(receiver.get(), &aad_item, sealed.get(),
                                       &tmp_unsealed));
  EXPECT_EQ(SEC_ERROR_BAD_DATA, PORT_GetError());
  EXPECT_EQ(nullptr, tmp_unsealed);
  aad_item.data[0] ^= 0xff;

  // Modify ciphertext
  sealed->data[0] ^= 0xff;
  EXPECT_EQ(SECFailure, PK11_HPKE_Open(receiver.get(), &aad_item, sealed.get(),
                                       &tmp_unsealed));
  EXPECT_EQ(SEC_ERROR_BAD_DATA, PORT_GetError());
  EXPECT_EQ(nullptr, tmp_unsealed);
  sealed->data[0] ^= 0xff;

  EXPECT_EQ(SECSuccess, PK11_HPKE_Open(receiver.get(), &aad_item, sealed.get(),
                                       &tmp_unsealed));
  EXPECT_NE(nullptr, tmp_unsealed);
  ScopedSECItem unsealed(tmp_unsealed);
  CheckEquality(&msg_item, unsealed.get());
}

TEST_F(ModeParameterizedTest, InvalidContextParams) {
  HpkeContext* cx =
      PK11_HPKE_NewContext(static_cast<HpkeKemId>(0xff), HpkeKdfHkdfSha256,
                           HpkeAeadChaCha20Poly1305, nullptr, nullptr);
  EXPECT_EQ(nullptr, cx);
  EXPECT_EQ(SEC_ERROR_INVALID_ARGS, PORT_GetError());

  cx = PK11_HPKE_NewContext(HpkeDhKemX25519Sha256, static_cast<HpkeKdfId>(0xff),
                            HpkeAeadChaCha20Poly1305, nullptr, nullptr);
  EXPECT_EQ(nullptr, cx);
  EXPECT_EQ(SEC_ERROR_INVALID_ARGS, PORT_GetError());
  cx = PK11_HPKE_NewContext(HpkeDhKemX25519Sha256, HpkeKdfHkdfSha256,
                            static_cast<HpkeAeadId>(0xff), nullptr, nullptr);
  EXPECT_EQ(nullptr, cx);
  EXPECT_EQ(SEC_ERROR_INVALID_ARGS, PORT_GetError());
}

TEST_F(ModeParameterizedTest, InvalidReceiverKeyType) {
  ScopedHpkeContext sender(
      PK11_HPKE_NewContext(HpkeDhKemX25519Sha256, HpkeKdfHkdfSha256,
                           HpkeAeadChaCha20Poly1305, nullptr, nullptr));
  ASSERT_TRUE(!!sender);

  ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
  if (!slot) {
    ADD_FAILURE() << "No slot";
    return;
  }

  // Give the client an RSA key
  PK11RSAGenParams rsa_param;
  rsa_param.keySizeInBits = 1024;
  rsa_param.pe = 65537L;
  SECKEYPublicKey* pub_tmp;
  ScopedSECKEYPublicKey pub_key;
  ScopedSECKEYPrivateKey priv_key(
      PK11_GenerateKeyPair(slot.get(), CKM_RSA_PKCS_KEY_PAIR_GEN, &rsa_param,
                           &pub_tmp, PR_FALSE, PR_FALSE, nullptr));
  ASSERT_NE(nullptr, priv_key);
  ASSERT_NE(nullptr, pub_tmp);
  pub_key.reset(pub_tmp);

  SECItem info_item = {siBuffer, nullptr, 0};
  EXPECT_EQ(SECFailure, PK11_HPKE_SetupS(sender.get(), nullptr, nullptr,
                                         pub_key.get(), &info_item));
  EXPECT_EQ(SEC_ERROR_BAD_KEY, PORT_GetError());

  // Try with an unexpected curve
  StackSECItem ecParams;
  SECOidData* oidData = SECOID_FindOIDByTag(SEC_OID_ANSIX962_EC_PRIME256V1);
  ASSERT_NE(oidData, nullptr);
  if (!SECITEM_AllocItem(nullptr, &ecParams, (2 + oidData->oid.len))) {
    FAIL() << "Couldn't allocate memory for OID.";
  }
  ecParams.data[0] = SEC_ASN1_OBJECT_ID;
  ecParams.data[1] = oidData->oid.len;
  memcpy(ecParams.data + 2, oidData->oid.data, oidData->oid.len);

  priv_key.reset(PK11_GenerateKeyPair(slot.get(), CKM_EC_KEY_PAIR_GEN,
                                      &ecParams, &pub_tmp, PR_FALSE, PR_FALSE,
                                      nullptr));
  ASSERT_NE(nullptr, priv_key);
  ASSERT_NE(nullptr, pub_tmp);
  pub_key.reset(pub_tmp);
  EXPECT_EQ(SECFailure, PK11_HPKE_SetupS(sender.get(), nullptr, nullptr,
                                         pub_key.get(), &info_item));
  EXPECT_EQ(SEC_ERROR_BAD_KEY, PORT_GetError());
}

TEST_F(ModeParameterizedTest, SetupLargeInfoLen) {
  ScopedHpkeContext sender(
      PK11_HPKE_NewContext(HpkeDhKemX25519Sha256, HpkeKdfHkdfSha256,
                           HpkeAeadAes128Gcm, nullptr, nullptr));
  ASSERT_TRUE(sender);

  ScopedSECKEYPublicKey pub_key_r;
  ScopedSECKEYPrivateKey priv_key_r;
  ASSERT_TRUE(GenerateKeyPair(pub_key_r, priv_key_r));

  // info->len near UINT_MAX must be rejected before reaching
  // pk11_hpke_MakeExtractLabel
  uint8_t info_data = 0;
  SECItem oversized_info = {siBuffer, &info_data, 0xFFFFFFE7U};
  EXPECT_EQ(SECFailure, PK11_HPKE_SetupS(sender.get(), nullptr, nullptr,
                                         pub_key_r.get(), &oversized_info));
  EXPECT_EQ(SEC_ERROR_INVALID_ARGS, PORT_GetError());

  // SetupR is also affected; use a valid sender to obtain enc first
  ScopedHpkeContext sender2(
      PK11_HPKE_NewContext(HpkeDhKemX25519Sha256, HpkeKdfHkdfSha256,
                           HpkeAeadAes128Gcm, nullptr, nullptr));
  ASSERT_TRUE(sender2);
  SECItem valid_info = {siBuffer, &info_data, 1};
  EXPECT_EQ(SECSuccess, PK11_HPKE_SetupS(sender2.get(), nullptr, nullptr,
                                         pub_key_r.get(), &valid_info));
  const SECItem* enc = PK11_HPKE_GetEncapPubKey(sender2.get());
  ASSERT_NE(nullptr, enc);

  ScopedHpkeContext receiver(
      PK11_HPKE_NewContext(HpkeDhKemX25519Sha256, HpkeKdfHkdfSha256,
                           HpkeAeadAes128Gcm, nullptr, nullptr));
  ASSERT_TRUE(receiver);
  EXPECT_EQ(SECFailure,
            PK11_HPKE_SetupR(receiver.get(), pub_key_r.get(), priv_key_r.get(),
                             const_cast<SECItem*>(enc), &oversized_info));
  EXPECT_EQ(SEC_ERROR_INVALID_ARGS, PORT_GetError());
}

// When using X25519, it should be valid to use a key pair that is generated
// using a pure EC mechanism, rather than an `ecMontKey`.
TEST_F(ModeParameterizedTest, KeyTypeMismatched) {
  ScopedHpkeContext sender;
  ScopedHpkeContext receiver;
  ASSERT_NO_FATAL_FAILURE(MakeEphemeralContexts(sender, receiver, HpkeModeBase,
                                                HpkeDhKemX25519Sha256));

  std::vector<uint8_t> info = {'i', 'n', 'f', 'o'};
  SECItem info_item = {siBuffer, info.data(),
                       static_cast<unsigned int>(info.size())};

  ScopedSECKEYPublicKey pub_key_r;
  ScopedSECKEYPrivateKey priv_key_r;
  ASSERT_TRUE(GenerateKeyPair(pub_key_r, priv_key_r, HpkeDhKemX25519Sha256,
                              SEC_OID_UNKNOWN, CKM_EC_KEY_PAIR_GEN));
  EXPECT_EQ(SECSuccess, PK11_HPKE_SetupS(sender.get(), nullptr, nullptr,
                                         pub_key_r.get(), &info_item));

  const SECItem* enc = PK11_HPKE_GetEncapPubKey(sender.get());
  EXPECT_NE(nullptr, enc);
  EXPECT_EQ(SECSuccess,
            PK11_HPKE_SetupR(receiver.get(), pub_key_r.get(), priv_key_r.get(),
                             const_cast<SECItem*>(enc), &info_item));

  std::vector<uint8_t> msg = {'s', 'e', 'c', 'r', 'e', 't'};
  std::vector<uint8_t> aad = {'a', 'a', 'd'};
  SealOpen(sender, receiver, msg, aad, nullptr);
}

// When using X25519, it should be valid to use a key pair that is generated
// using SEC_OID_CURVE25519, rather than SEC_OID_X25519.
TEST_F(ModeParameterizedTest, KemOidMismatched) {
  ScopedHpkeContext sender;
  ScopedHpkeContext receiver;
  ASSERT_NO_FATAL_FAILURE(MakeEphemeralContexts(sender, receiver, HpkeModeBase,
                                                HpkeDhKemX25519Sha256));

  std::vector<uint8_t> info = {'i', 'n', 'f', 'o'};
  SECItem info_item = {siBuffer, info.data(),
                       static_cast<unsigned int>(info.size())};

  ScopedSECKEYPublicKey pub_key_r;
  ScopedSECKEYPrivateKey priv_key_r;
  ASSERT_TRUE(GenerateKeyPair(pub_key_r, priv_key_r, HpkeDhKemX25519Sha256,
                              SEC_OID_CURVE25519));
  EXPECT_EQ(SECSuccess, PK11_HPKE_SetupS(sender.get(), nullptr, nullptr,
                                         pub_key_r.get(), &info_item));

  const SECItem* enc = PK11_HPKE_GetEncapPubKey(sender.get());
  EXPECT_NE(nullptr, enc);
  EXPECT_EQ(SECSuccess,
            PK11_HPKE_SetupR(receiver.get(), pub_key_r.get(), priv_key_r.get(),
                             const_cast<SECItem*>(enc), &info_item));

  std::vector<uint8_t> msg = {'s', 'e', 'c', 'r', 'e', 't'};
  std::vector<uint8_t> aad = {'a', 'a', 'd'};
  SealOpen(sender, receiver, msg, aad, nullptr);
}

}  // namespace nss_test
