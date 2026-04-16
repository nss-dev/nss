/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <functional>
#include <memory>
#include "secerr.h"
#include "ssl.h"
#include "sslerr.h"
#include "sslproto.h"

extern "C" {
#include "libssl_internals.h"
}

#include "gtest_utils.h"
#include "nss_scoped_ptrs.h"
#include "tls_connect.h"

namespace nss_test {

// ---- Test fixture ----------------------------------------------------------

class ReconfigTest : public TlsConnectTestBase,
                     public ::testing::WithParamInterface<
                         std::tuple<SSLProtocolVariant, uint16_t>> {
 public:
  ReconfigTest()
      : TlsConnectTestBase(std::get<0>(GetParam()), std::get<1>(GetParam())) {}

 protected:
  // Create a bare model socket (no test-harness callbacks) with a server
  // certificate, using the DummyPrSocket I/O layer for the correct variant.
  ScopedPRFileDesc CreateModel(
      const std::string& cert_name = TlsAgent::kServerRsa) {
    auto adapter = std::make_shared<DummyPrSocket>("model", variant_);
    ScopedPRFileDesc dummy_fd(adapter->CreateFD());
    EXPECT_NE(nullptr, dummy_fd.get());

    ScopedPRFileDesc fd;
    if (variant_ == ssl_variant_stream) {
      fd.reset(SSL_ImportFD(nullptr, dummy_fd.get()));
    } else {
      fd.reset(DTLS_ImportFD(nullptr, dummy_fd.get()));
    }
    EXPECT_NE(nullptr, fd.get());
    if (fd.get()) {
      dummy_fd.release();
    }

    SSLVersionRange vrange = {version_, version_};
    EXPECT_EQ(SECSuccess, SSL_VersionRangeSet(fd.get(), &vrange));

    ScopedCERTCertificate cert;
    ScopedSECKEYPrivateKey priv;
    EXPECT_TRUE(TlsAgent::LoadCertificate(cert_name, &cert, &priv));
    if (cert.get() && priv.get()) {
      EXPECT_EQ(SECSuccess, SSL_ConfigServerCert(fd.get(), cert.get(),
                                                 priv.get(), nullptr, 0));
    }
    model_adapter_ = adapter;
    return fd;
  }

  void InstallReconfigSniCallback(PRFileDesc* model_fd) {
    server_->SetSniCallback([model_fd](TlsAgent* agent,
                                       const SECItem* srvNameArr,
                                       uint32_t srvNameArrSize) -> int32_t {
      EXPECT_NE(nullptr, SSL_ReconfigFD(model_fd, agent->ssl_fd()));
      return 0;
    });
  }

 private:
  std::shared_ptr<DummyPrSocket> model_adapter_;
};

// ---- Tests ----------------------------------------------------------------

// Basic ReconfigFD: reconfigure from model, connection succeeds.
TEST_P(ReconfigTest, ReconfigBasic) {
  EnsureTlsSetup();
  ScopedPRFileDesc model(CreateModel());
  InstallReconfigSniCallback(model.get());
  Connect();
  SendReceive();
}

// ReconfigFD copies cipher suite configuration from the model.
TEST_P(ReconfigTest, ReconfigCipherSuites) {
  EnsureTlsSetup();
  ScopedPRFileDesc model(CreateModel());

  for (uint16_t i = 0; i < SSL_NumImplementedCiphers; i++) {
    SSL_CipherPrefSet(model.get(), SSL_ImplementedCiphers[i], PR_FALSE);
  }
  uint16_t chosen_cipher;
  if (version_ >= SSL_LIBRARY_VERSION_TLS_1_3) {
    chosen_cipher = TLS_AES_128_GCM_SHA256;
  } else {
    chosen_cipher = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
  }
  EXPECT_EQ(SECSuccess, SSL_CipherPrefSet(model.get(), chosen_cipher, PR_TRUE));

  InstallReconfigSniCallback(model.get());
  Connect();
  server_->CheckCipherSuite(chosen_cipher);
}

// ReconfigFD copies server certificates from the model.
// Only run on TLS 1.3+ where auth type is independent of cipher suite.
TEST_P(ReconfigTest, ReconfigServerCert) {
  if (version_ < SSL_LIBRARY_VERSION_TLS_1_3) {
    GTEST_SKIP();
  }
  Reset(TlsAgent::kServerEcdsa256);
  EnsureTlsSetup();

  // Model has an RSA cert; server initially has ECDSA.
  ScopedPRFileDesc model(CreateModel(TlsAgent::kServerRsa));
  InstallReconfigSniCallback(model.get());

  // The ReconfigFD replaces the server cert, so update the expected
  // key size to match the model's RSA cert (1024 bits).
  server_->SetServerKeyBits(1024);

  Connect();
  CheckKeys(ssl_auth_rsa_sign);
}

TEST_P(ReconfigTest, ReconfigAlpnNoDoubleFree) {
  EnsureTlsSetup();
  ScopedPRFileDesc model(CreateModel());

  const uint8_t alpn_val[] = {0x02, 'h', '2'};
  EXPECT_EQ(SECSuccess,
            SSL_SetNextProtoNego(model.get(), alpn_val, sizeof(alpn_val)));

  InstallReconfigSniCallback(model.get());
  Connect();

  const uint8_t alpn_val2[] = {0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'};
  EXPECT_EQ(SECSuccess,
            SSL_SetNextProtoNego(model.get(), alpn_val2, sizeof(alpn_val2)));
}

TEST_P(ReconfigTest, ReconfigTwice) {
  EnsureTlsSetup();
  ScopedPRFileDesc model(CreateModel());

  PRFileDesc* model_raw = model.get();
  server_->SetSniCallback([model_raw](TlsAgent* agent,
                                      const SECItem* srvNameArr,
                                      uint32_t srvNameArrSize) -> int32_t {
    EXPECT_NE(nullptr, SSL_ReconfigFD(model_raw, agent->ssl_fd()));
    EXPECT_NE(nullptr, SSL_ReconfigFD(model_raw, agent->ssl_fd()));
    return 0;
  });

  Connect();
  SendReceive();
}

TEST_P(ReconfigTest, ReconfigNullModel) {
  EnsureTlsSetup();
  EXPECT_EQ(nullptr, SSL_ReconfigFD(nullptr, server_->ssl_fd()));
}

// ---- TLS 1.3 PSK + ReconfigFD test ---------------------------------------

class ReconfigPskTest
    : public TlsConnectTestBase,
      public ::testing::WithParamInterface<SSLProtocolVariant> {
 public:
  ReconfigPskTest()
      : TlsConnectTestBase(GetParam(), SSL_LIBRARY_VERSION_TLS_1_3) {}

  void SetUp() override {
    TlsConnectTestBase::SetUp();
    ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
    ASSERT_NE(nullptr, slot.get());
    SECItem psk_item;
    psk_item.type = siBuffer;
    psk_item.len = sizeof(kPskVal_);
    psk_item.data = const_cast<uint8_t*>(kPskVal_);
    scoped_psk_.reset(PK11_ImportSymKey(slot.get(), CKM_HKDF_KEY_GEN,
                                        PK11_OriginUnwrap, CKA_DERIVE,
                                        &psk_item, nullptr));
    ASSERT_NE(nullptr, scoped_psk_.get());
  }

 protected:
  ScopedPK11SymKey scoped_psk_;
  const uint8_t kPskVal_[16] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
                                0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};
  const std::string kPskLabel_ = "reconfig psk label";
};

TEST_P(ReconfigPskTest, ReconfigWithExternalPsk) {
  EnsureTlsSetup();

  // Add PSK to the server so it's in the handshake state when the
  // SNI callback fires.
  server_->AddPsk(scoped_psk_, kPskLabel_, ssl_hash_sha256);
  client_->AddPsk(scoped_psk_, kPskLabel_, ssl_hash_sha256);

  // Create a model with a cert (no PSK — ReconfigFD will clear the
  // handshake PSKs and the connection will fall back to cert auth).
  auto adapter = std::make_shared<DummyPrSocket>("psk_model", variant_);
  ScopedPRFileDesc dummy(adapter->CreateFD());
  ASSERT_NE(nullptr, dummy.get());
  ScopedPRFileDesc model;
  if (variant_ == ssl_variant_stream) {
    model.reset(SSL_ImportFD(nullptr, dummy.get()));
  } else {
    model.reset(DTLS_ImportFD(nullptr, dummy.get()));
  }
  ASSERT_NE(nullptr, model.get());
  dummy.release();

  SSLVersionRange vrange = {SSL_LIBRARY_VERSION_TLS_1_3,
                            SSL_LIBRARY_VERSION_TLS_1_3};
  EXPECT_EQ(SECSuccess, SSL_VersionRangeSet(model.get(), &vrange));
  ScopedCERTCertificate cert;
  ScopedSECKEYPrivateKey priv;
  ASSERT_TRUE(TlsAgent::LoadCertificate(TlsAgent::kServerRsa, &cert, &priv));
  EXPECT_EQ(SECSuccess, SSL_ConfigServerCert(model.get(), cert.get(),
                                             priv.get(), nullptr, 0));

  PRFileDesc* model_raw = model.get();
  server_->SetSniCallback([model_raw](TlsAgent* agent,
                                      const SECItem* srvNameArr,
                                      uint32_t srvNameArrSize) -> int32_t {
    EXPECT_NE(nullptr, SSL_ReconfigFD(model_raw, agent->ssl_fd()));
    return 0;
  });

  Connect();
  SendReceive();
  // Connection falls back to cert auth since ReconfigFD cleared PSKs.
  CheckKeys(ssl_auth_rsa_sign);
}

// ---- Instantiations -------------------------------------------------------

INSTANTIATE_TEST_SUITE_P(
    ReconfigGeneric, ReconfigTest,
    ::testing::Combine(TlsConnectTestBase::kTlsVariantsStream,
                       TlsConnectTestBase::kTlsV12Plus));
INSTANTIATE_TEST_SUITE_P(
    ReconfigDatagram, ReconfigTest,
    ::testing::Combine(TlsConnectTestBase::kTlsVariantsDatagram,
                       TlsConnectTestBase::kTlsV13));
INSTANTIATE_TEST_SUITE_P(ReconfigPsk, ReconfigPskTest,
                         TlsConnectTestBase::kTlsVariantsAll);

}  // namespace nss_test
