/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "secerr.h"
#include "ssl.h"

#include "gtest_utils.h"
#include "tls_connect.h"
#include "util.h"

namespace nss_test {

// Generic Client GREASE test
TEST_P(TlsConnectGeneric, ClientGrease) {
  EnsureTlsSetup();
  ASSERT_EQ(SSL_OptionSet(client_->ssl_fd(), SSL_ENABLE_GREASE, PR_TRUE),
            SECSuccess);
  Connect();
}

// Generic Server GREASE test
TEST_P(TlsConnectGeneric, ServerGrease) {
  EnsureTlsSetup();
  ASSERT_EQ(SSL_OptionSet(server_->ssl_fd(), SSL_ENABLE_GREASE, PR_TRUE),
            SECSuccess);
  Connect();
}

// Generic GREASE test
TEST_P(TlsConnectGeneric, Grease) {
  EnsureTlsSetup();
  ASSERT_EQ(SSL_OptionSet(client_->ssl_fd(), SSL_ENABLE_GREASE, PR_TRUE),
            SECSuccess);
  ASSERT_EQ(SSL_OptionSet(server_->ssl_fd(), SSL_ENABLE_GREASE, PR_TRUE),
            SECSuccess);
  Connect();
}

// Test that ECH and GREASE work together successfully
TEST_F(TlsConnectStreamTls13, GreaseAndECH) {
  EnsureTlsSetup();
  SetupEch(client_, server_);
  ASSERT_EQ(SSL_OptionSet(client_->ssl_fd(), SSL_ENABLE_GREASE, PR_TRUE),
            SECSuccess);
  ASSERT_EQ(SSL_OptionSet(server_->ssl_fd(), SSL_ENABLE_GREASE, PR_TRUE),
            SECSuccess);
  Connect();
}

// Test that TLS12 Server handles Client GREASE correctly
TEST_F(TlsConnectTest, GreaseTLS12Server) {
  EnsureTlsSetup();
  ASSERT_EQ(SSL_OptionSet(client_->ssl_fd(), SSL_ENABLE_GREASE, PR_TRUE),
            SECSuccess);
  server_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_2,
                           SSL_LIBRARY_VERSION_TLS_1_2);
  client_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_2,
                           SSL_LIBRARY_VERSION_TLS_1_3);
  Connect();
}

// Test that TLS12 Client handles Server GREASE correctly
TEST_F(TlsConnectTest, GreaseTLS12Client) {
  EnsureTlsSetup();
  ASSERT_EQ(SSL_OptionSet(server_->ssl_fd(), SSL_ENABLE_GREASE, PR_TRUE),
            SECSuccess);
  server_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_2,
                           SSL_LIBRARY_VERSION_TLS_1_3);
  client_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_2,
                           SSL_LIBRARY_VERSION_TLS_1_2);
  Connect();
}

class GreaseOnlyTestStreamTls13 : public TlsConnectStreamTls13 {
 public:
  GreaseOnlyTestStreamTls13() : TlsConnectStreamTls13() {}

  void ConnectWithCustomChExpectFail(const std::string& ch,
                                     uint8_t server_alert, uint32_t server_code,
                                     uint32_t client_code) {
    std::vector<uint8_t> ch_vec = hex_string_to_bytes(ch);
    DataBuffer ch_buf;
    EnsureTlsSetup();

    TlsAgentTestBase::MakeRecord(variant_, ssl_ct_handshake,
                                 SSL_LIBRARY_VERSION_TLS_1_3, ch_vec.data(),
                                 ch_vec.size(), &ch_buf, 0);
    StartConnect();
    client_->SendDirect(ch_buf);
    ExpectAlert(server_, server_alert);
    server_->Handshake();
    server_->CheckErrorCode(server_code);
    client_->ExpectReceiveAlert(server_alert, kTlsAlertFatal);
    client_->Handshake();
    client_->CheckErrorCode(client_code);
  }
};

// Client: Offer only GREASE CipherSuite value
TEST_F(GreaseOnlyTestStreamTls13, GreaseOnlyClientCipherSuite) {
  // 0xdada
  std::string ch =
      "010000b003038afacda2963358e98f464f3ff0680ed3a9d382a8c3eac5e5604f5721add9"
      "855c000002dada010000850000000b0009000006736572766572ff01000100000a001400"
      "12001d00170018001901000101010201030104003300260024001d0020683668992de470"
      "38660ee37bafc7392b05b8a94402ea1f3463ad3cfd7a694a46002b0003020304000d0018"
      "001604030503060302030804080508060401050106010201002d00020101001c0002400"
      "1";

  ConnectWithCustomChExpectFail(ch, kTlsAlertHandshakeFailure,
                                SSL_ERROR_NO_CYPHER_OVERLAP,
                                SSL_ERROR_NO_CYPHER_OVERLAP);
}

// Client: Offer only GREASE SupportedGroups value
TEST_F(GreaseOnlyTestStreamTls13, GreaseOnlyClientSupportedGroup) {
  // 0x3a3a
  std::string ch =
      "010000a40303484a4e14f547404da6115d7f73bbb0f1c9d65e66ac073dee6c4a62f72de9"
      "a36f000006130113031302010000750000000b0009000006736572766572ff0100010000"
      "0a000400023a3a003300260024001d0020e75cb8e217c95176954e8b5fb95843882462ce"
      "2cd3fcfe67cf31463a05ea3d57002b0003020304000d0018001604030503060302030804"
      "080508060401050106010201002d00020101001c00024001";

  ConnectWithCustomChExpectFail(ch, kTlsAlertHandshakeFailure,
                                SSL_ERROR_NO_CYPHER_OVERLAP,
                                SSL_ERROR_NO_CYPHER_OVERLAP);
}

// Client: Offer only GREASE SigAlgs value
TEST_F(GreaseOnlyTestStreamTls13, GreaseOnlyClientSignatureAlgorithm) {
  // 0x8a8a
  std::string ch =
      "010000a00303dfd8e2438a8d1b9f48d921dfc08959108807bd1105238bb3da2a2a8e3db0"
      "6990000006130113031302010000710000000b0009000006736572766572ff0100010000"
      "0a00140012001d00170018001901000101010201030104003300260024001d002074bb2c"
      "94996d3ffc7ae5792f0c3c58676358a85ea304cd029fa3d6551013b333002b0003020304"
      "000d000400028a8a002d00020101001c00024001";

  ConnectWithCustomChExpectFail(ch, kTlsAlertHandshakeFailure,
                                SSL_ERROR_UNSUPPORTED_SIGNATURE_ALGORITHM,
                                SSL_ERROR_NO_CYPHER_OVERLAP);
}

// Client: Offer only GREASE SupportedVersions value
TEST_F(GreaseOnlyTestStreamTls13, GreaseOnlyClientSupportedVersion) {
  // 0xeaea
  std::string ch =
      "010000b203037e3618abae0dd0b3f06a504c47354551d1d5be36e9c3e1eac9c139c246b1"
      "66da000006130113031302010000830000000b0009000006736572766572ff0100010000"
      "0a00140012001d00170018001901000101010201030104003300260024001d00206b1816"
      "577ff2e69d4d2661419150eaefa0328ffd396425cf1733ec06536b4e55002b000100000d"
      "0018001604030503060302030804080508060401050106010201002d00020101001c0002"
      "4001";

  ConnectWithCustomChExpectFail(ch, kTlsAlertIllegalParameter,
                                SSL_ERROR_RX_MALFORMED_CLIENT_HELLO,
                                SSL_ERROR_ILLEGAL_PARAMETER_ALERT);
}

class GreaseTestStreamTls12
    : public TlsConnectStreamTls12,
      public ::testing::WithParamInterface<uint16_t /* GREASE */> {
 public:
  GreaseTestStreamTls12() : TlsConnectStreamTls12(), grease_(GetParam()){};

  void ConnectExpectSigAlgFail() {
    client_->ExpectSendAlert(kTlsAlertIllegalParameter);
    server_->ExpectReceiveAlert(kTlsAlertIllegalParameter);
    ConnectExpectFail();
    client_->CheckErrorCode(SSL_ERROR_UNSUPPORTED_SIGNATURE_ALGORITHM);
    server_->CheckErrorCode(SSL_ERROR_ILLEGAL_PARAMETER_ALERT);
  }

 protected:
  uint16_t grease_;
};

class TlsCertificateRequestSigAlgSetterFilter : public TlsHandshakeFilter {
 public:
  TlsCertificateRequestSigAlgSetterFilter(const std::shared_ptr<TlsAgent>& a,
                                          uint16_t sigAlg)
      : TlsHandshakeFilter(a, {kTlsHandshakeCertificateRequest}),
        sigAlg_(sigAlg) {}
  virtual PacketFilter::Action FilterHandshake(
      const TlsHandshakeFilter::HandshakeHeader& header,
      const DataBuffer& input, DataBuffer* output) {
    TlsParser parser(input);
    DataBuffer cert_types;
    if (!parser.ReadVariable(&cert_types, 1)) {
      ADD_FAILURE();
      return KEEP;
    }

    if (!parser.SkipVariable(2)) {
      ADD_FAILURE();
      return KEEP;
    }

    DataBuffer cas;
    if (!parser.ReadVariable(&cas, 2)) {
      ADD_FAILURE();
      return KEEP;
    }

    size_t idx = 0;

    // Write certificate types.
    idx = output->Write(idx, cert_types.len(), 1);
    idx = output->Write(idx, cert_types);

    // Write signature algorithm.
    idx = output->Write(idx, sizeof(sigAlg_), 2);
    idx = output->Write(idx, sigAlg_, 2);

    // Write certificate authorities.
    idx = output->Write(idx, cas.len(), 2);
    idx = output->Write(idx, cas);

    return CHANGE;
  }

 private:
  uint16_t sigAlg_;
};

// Server: Offer only GREASE CertificateRequest SigAlg value
TEST_P(GreaseTestStreamTls12, GreaseOnlyServerTLS12CertificateRequestSigAlg) {
  EnsureTlsSetup();
  client_->SetupClientAuth();
  server_->RequestClientAuth(true);
  MakeTlsFilter<TlsCertificateRequestSigAlgSetterFilter>(server_, grease_);

  client_->ExpectSendAlert(kTlsAlertHandshakeFailure);
  server_->ExpectReceiveAlert(kTlsAlertHandshakeFailure);
  ConnectExpectFail();
  server_->CheckErrorCode(SSL_ERROR_HANDSHAKE_FAILURE_ALERT);
  client_->CheckErrorCode(SSL_ERROR_UNSUPPORTED_SIGNATURE_ALGORITHM);
}

// Illegally GREASE ServerKeyExchange ECC SignatureAlgorithm
TEST_P(GreaseTestStreamTls12, GreasedTLS12ServerKexEccSigAlg) {
  MakeTlsFilter<ECCServerKEXSigAlgReplacer>(server_, grease_);
  EnableSomeEcdhCiphers();

  client_->ExpectSendAlert(kTlsAlertIllegalParameter);
  server_->ExpectReceiveAlert(kTlsAlertIllegalParameter);
  ConnectExpectFail();
  client_->CheckErrorCode(SSL_ERROR_UNSUPPORTED_SIGNATURE_ALGORITHM);
  server_->CheckErrorCode(SSL_ERROR_ILLEGAL_PARAMETER_ALERT);
}

// Illegally GREASE ServerKeyExchange DHE SignatureAlgorithm
TEST_P(GreaseTestStreamTls12, GreasedTLS12ServerKexDheSigAlg) {
  MakeTlsFilter<DHEServerKEXSigAlgReplacer>(server_, grease_);
  EnableOnlyDheCiphers();

  client_->ExpectSendAlert(kTlsAlertIllegalParameter);
  server_->ExpectReceiveAlert(kTlsAlertIllegalParameter);
  ConnectExpectFail();
  client_->CheckErrorCode(SSL_ERROR_UNSUPPORTED_SIGNATURE_ALGORITHM);
  server_->CheckErrorCode(SSL_ERROR_ILLEGAL_PARAMETER_ALERT);
}

// Illegally GREASE ServerKeyExchange ECDHE NamedCurve
TEST_P(GreaseTestStreamTls12, GreasedTLS12ServerKexEcdheNamedCurve) {
  MakeTlsFilter<ECCServerKEXNamedCurveReplacer>(server_, grease_);
  EnableSomeEcdhCiphers();

  client_->ExpectSendAlert(kTlsAlertHandshakeFailure);
  server_->ExpectReceiveAlert(kTlsAlertHandshakeFailure);
  ConnectExpectFail();
  server_->CheckErrorCode(SSL_ERROR_HANDSHAKE_FAILURE_ALERT);
  client_->CheckErrorCode(SEC_ERROR_UNSUPPORTED_ELLIPTIC_CURVE);
}

// Illegally GREASE TLS12 Client CertificateVerify SignatureAlgorithm
TEST_P(GreaseTestStreamTls12, GreasedTLS12ClientCertificateVerifySigAlg) {
  client_->SetupClientAuth();
  server_->RequestClientAuth(true);
  MakeTlsFilter<TlsReplaceSignatureSchemeFilter>(client_, grease_);

  server_->ExpectSendAlert(kTlsAlertIllegalParameter);
  client_->ExpectReceiveAlert(kTlsAlertIllegalParameter);
  ConnectExpectFail();
  client_->CheckErrorCode(SSL_ERROR_ILLEGAL_PARAMETER_ALERT);
  server_->CheckErrorCode(SSL_ERROR_UNSUPPORTED_SIGNATURE_ALGORITHM);
}

class GreaseTestStreamTls13
    : public TlsConnectStreamTls13,
      public ::testing::WithParamInterface<uint16_t /* GREASE */> {
 public:
  GreaseTestStreamTls13() : grease_(GetParam()){};

 protected:
  uint16_t grease_;
};

// Illegally GREASE TLS13 Client CertificateVerify SignatureAlgorithm
TEST_P(GreaseTestStreamTls13, GreasedTLS13ClientCertificateVerifySigAlg) {
  client_->SetupClientAuth();
  server_->RequestClientAuth(true);
  auto filter =
      MakeTlsFilter<TlsReplaceSignatureSchemeFilter>(client_, grease_);
  filter->EnableDecryption();

  server_->ExpectSendAlert(kTlsAlertIllegalParameter);
  client_->ExpectReceiveAlert(kTlsAlertIllegalParameter);

  // Manually trigger handshake to avoid race conditions
  StartConnect();
  client_->Handshake();
  server_->Handshake();
  client_->Handshake();
  server_->Handshake();
  client_->Handshake();

  server_->CheckErrorCode(SSL_ERROR_RX_MALFORMED_CERT_VERIFY);
  client_->CheckErrorCode(SSL_ERROR_ILLEGAL_PARAMETER_ALERT);
}

// Illegally GREASE TLS13 Server CertificateVerify SignatureAlgorithm
TEST_P(GreaseTestStreamTls13, GreasedTLS13ServerCertificateVerifySigAlg) {
  EnsureTlsSetup();
  auto filter =
      MakeTlsFilter<TlsReplaceSignatureSchemeFilter>(server_, grease_);
  filter->EnableDecryption();

  client_->ExpectSendAlert(kTlsAlertIllegalParameter);
  server_->ExpectReceiveAlert(kTlsAlertIllegalParameter);
  ConnectExpectFail();
  client_->CheckErrorCode(SSL_ERROR_RX_MALFORMED_CERT_VERIFY);
}

// Illegally GREASE HelloRetryRequest version value
TEST_P(GreaseTestStreamTls13, GreasedHelloRetryRequestVersion) {
  EnsureTlsSetup();
  // Trigger HelloRetryRequest
  MakeTlsFilter<TlsExtensionDropper>(client_, ssl_tls13_key_share_xtn);
  auto filter = MakeTlsFilter<TlsMessageVersionSetter>(
      server_, kTlsHandshakeHelloRetryRequest, grease_);
  filter->EnableDecryption();

  client_->ExpectSendAlert(kTlsAlertIllegalParameter);
  server_->ExpectReceiveAlert(kTlsAlertIllegalParameter);
  ConnectExpectFail();
  client_->CheckErrorCode(SSL_ERROR_RX_MALFORMED_SERVER_HELLO);
  server_->CheckErrorCode(SSL_ERROR_ILLEGAL_PARAMETER_ALERT);
}

class GreaseTestStreamTls123
    : public TlsConnectTestBase,
      public ::testing::WithParamInterface<
          std::tuple<uint16_t /* version */, uint16_t /* GREASE */>> {
 public:
  GreaseTestStreamTls123()
      : TlsConnectTestBase(ssl_variant_stream, std::get<0>(GetParam())),
        grease_(std::get<1>(GetParam())){};

  void ConnectExpectIllegalGreaseFail() {
    client_->ExpectSendAlert(kTlsAlertIllegalParameter);
    if (version_ >= SSL_LIBRARY_VERSION_TLS_1_3) {
      // Server expects handshake but receives encrypted alert.
      server_->ExpectSendAlert(kTlsAlertUnexpectedMessage);
    } else {
      server_->ExpectReceiveAlert(kTlsAlertIllegalParameter);
    }
    ConnectExpectFail();
  }

 protected:
  uint16_t grease_;
};

// Illegally GREASE TLS12 and TLS13 ServerHello version value
TEST_P(GreaseTestStreamTls123, GreasedServerHelloVersion) {
  EnsureTlsSetup();
  auto filter = MakeTlsFilter<TlsMessageVersionSetter>(
      server_, kTlsHandshakeServerHello, grease_);
  if (version_ >= SSL_LIBRARY_VERSION_TLS_1_3) {
    filter->EnableDecryption();
  }
  ConnectExpectIllegalGreaseFail();
  client_->CheckErrorCode(SSL_ERROR_RX_MALFORMED_SERVER_HELLO);
}

// Illegally GREASE TLS12 and TLS13 selected CipherSuite value
TEST_P(GreaseTestStreamTls123, GreasedServerHelloCipherSuite) {
  EnsureTlsSetup();
  auto filter = MakeTlsFilter<SelectedCipherSuiteReplacer>(server_, grease_);
  if (version_ >= SSL_LIBRARY_VERSION_TLS_1_3) {
    filter->EnableDecryption();
  }
  ConnectExpectIllegalGreaseFail();
  client_->CheckErrorCode(SSL_ERROR_NO_CYPHER_OVERLAP);
}

class GreaseExtensionTestStreamTls13
    : public TlsConnectStreamTls13,
      public ::testing::WithParamInterface<
          std::tuple<uint8_t /* message */, uint16_t /* GREASE */>> {
 public:
  GreaseExtensionTestStreamTls13()
      : TlsConnectStreamTls13(),
        message_(std::get<0>(GetParam())),
        grease_(std::get<1>(GetParam())){};

 protected:
  uint8_t message_;
  uint16_t grease_;
};

// Illegally GREASE TLS13 Server EncryptedExtensions and Certificate Extensions
// NSS currently allows offering unkown extensions in HelloRetryRequests!
TEST_P(GreaseExtensionTestStreamTls13, GreasedServerExtensions) {
  EnsureTlsSetup();
  DataBuffer empty = DataBuffer(1);
  auto filter =
      MakeTlsFilter<TlsExtensionAppender>(server_, message_, grease_, empty);
  filter->EnableDecryption();

  server_->ExpectReceiveAlert(kTlsAlertUnsupportedExtension);
  client_->ExpectSendAlert(kTlsAlertUnsupportedExtension);
  ConnectExpectFail();
  client_->CheckErrorCode(SSL_ERROR_RX_UNEXPECTED_EXTENSION);
  server_->CheckErrorCode(SSL_ERROR_UNSUPPORTED_EXTENSION_ALERT);
}

// Illegally GREASE TLS12 and TLS13 ServerHello Extensions
TEST_P(GreaseTestStreamTls123, GreasedServerHelloExtensions) {
  EnsureTlsSetup();
  DataBuffer empty = DataBuffer(1);
  auto filter = MakeTlsFilter<TlsExtensionAppender>(
      server_, kTlsHandshakeServerHello, grease_, empty);

  if (version_ >= SSL_LIBRARY_VERSION_TLS_1_3) {
    filter->EnableDecryption();
    server_->ExpectSendAlert(kTlsAlertUnexpectedMessage);
  } else {
    server_->ExpectReceiveAlert(kTlsAlertUnsupportedExtension);
  }
  client_->ExpectSendAlert(kTlsAlertUnsupportedExtension);
  ConnectExpectFail();
  client_->CheckErrorCode(SSL_ERROR_RX_UNEXPECTED_EXTENSION);
}

// Illegally GREASE TLS13 Client Certificate Extensions
// Server ignores injected client extensions and fails on CertificateVerify
TEST_P(GreaseTestStreamTls13, GreasedClientCertificateExtensions) {
  client_->SetupClientAuth();
  server_->RequestClientAuth(true);
  DataBuffer empty = DataBuffer(1);
  auto filter = MakeTlsFilter<TlsExtensionAppender>(
      client_, kTlsHandshakeCertificate, grease_, empty);
  filter->EnableDecryption();

  server_->ExpectSendAlert(kTlsAlertDecryptError);
  client_->ExpectReceiveAlert(kTlsAlertDecryptError);

  // Manually trigger handshake to avoid race conditions
  StartConnect();
  client_->Handshake();
  server_->Handshake();
  client_->Handshake();
  server_->Handshake();
  client_->Handshake();

  server_->CheckErrorCode(SEC_ERROR_BAD_SIGNATURE);
  client_->CheckErrorCode(SSL_ERROR_DECRYPT_ERROR_ALERT);
}

const uint8_t kTlsGreaseExtensionMessages[] = {kTlsHandshakeEncryptedExtensions,
                                               kTlsHandshakeCertificate};

const uint16_t kTlsGreaseValues[] = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa};

INSTANTIATE_TEST_SUITE_P(GreaseTestTls12, GreaseTestStreamTls12,
                         ::testing::ValuesIn(kTlsGreaseValues));

INSTANTIATE_TEST_SUITE_P(GreaseTestTls13, GreaseTestStreamTls13,
                         ::testing::ValuesIn(kTlsGreaseValues));

INSTANTIATE_TEST_SUITE_P(
    GreaseTestTls123, GreaseTestStreamTls123,
    ::testing::Combine(TlsConnectTestBase::kTlsV12Plus,
                       ::testing::ValuesIn(kTlsGreaseValues)));

INSTANTIATE_TEST_SUITE_P(
    GreaseExtensionTest, GreaseExtensionTestStreamTls13,
    testing::Combine(testing::ValuesIn(kTlsGreaseExtensionMessages),
                     testing::ValuesIn(kTlsGreaseValues)));

}  // namespace nss_test
