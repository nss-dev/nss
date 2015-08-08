/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "tls_agent.h"

#include "pk11func.h"
#include "ssl.h"
#include "sslerr.h"
#include "sslproto.h"
#include "keyhi.h"

#define GTEST_HAS_RTTI 0
#include "gtest/gtest.h"

namespace nss_test {

const char* TlsAgent::states[] = {"INIT", "CONNECTING", "CONNECTED", "ERROR"};

TlsAgent::TlsAgent(const std::string& name, Role role, Mode mode, SSLKEAType kea)
  : name_(name),
    mode_(mode),
    kea_(kea),
    pr_fd_(nullptr),
    adapter_(nullptr),
    ssl_fd_(nullptr),
    role_(role),
    state_(STATE_INIT),
    falsestart_enabled_(false),
    expected_version_(0),
    expected_cipher_suite_(0),
    expect_resumption_(false),
    can_falsestart_hook_called_(false),
    sni_hook_called_(false),
    auth_certificate_hook_called_(false),
    handshake_callback_called_(false),
    error_code_(0),
    send_ctr_(0),
    recv_ctr_(0),
    expected_read_error_(false) {

  memset(&info_, 0, sizeof(info_));
  memset(&csinfo_, 0, sizeof(csinfo_));
  SECStatus rv = SSL_VersionRangeGetDefault(mode_ == STREAM ?
                                            ssl_variant_stream : ssl_variant_datagram,
                                            &vrange_);
  EXPECT_EQ(SECSuccess, rv);
}

TlsAgent::~TlsAgent() {
  if (adapter_) {
    Poller::Instance()->Cancel(READABLE_EVENT, adapter_);
  }

  if (pr_fd_) {
    PR_Close(pr_fd_);
  }

  if (ssl_fd_) {
    PR_Close(ssl_fd_);
  }
}

bool TlsAgent::EnsureTlsSetup() {
  // Don't set up twice
  if (ssl_fd_) return true;

  if (adapter_->mode() == STREAM) {
    ssl_fd_ = SSL_ImportFD(nullptr, pr_fd_);
  } else {
    ssl_fd_ = DTLS_ImportFD(nullptr, pr_fd_);
  }

  EXPECT_NE(nullptr, ssl_fd_);
  if (!ssl_fd_) return false;
  pr_fd_ = nullptr;

  if (role_ == SERVER) {
    CERTCertificate* cert = PK11_FindCertFromNickname(name_.c_str(), nullptr);
    EXPECT_NE(nullptr, cert);
    if (!cert) return false;

    SECKEYPrivateKey* priv = PK11_FindKeyByAnyCert(cert, nullptr);
    EXPECT_NE(nullptr, priv);
    if (!priv) return false;  // Leak cert.

    SECStatus rv = SSL_ConfigSecureServer(ssl_fd_, cert, priv, kea_);
    EXPECT_EQ(SECSuccess, rv);
    if (rv != SECSuccess) return false;  // Leak cert and key.

    SECKEY_DestroyPrivateKey(priv);
    CERT_DestroyCertificate(cert);

    rv = SSL_SNISocketConfigHook(ssl_fd_, SniHook, this);
    EXPECT_EQ(SECSuccess, rv);  // don't abort, just fail
  } else {
    SECStatus rv = SSL_SetURL(ssl_fd_, "server");
    EXPECT_EQ(SECSuccess, rv);
    if (rv != SECSuccess) return false;
  }

  SECStatus rv = SSL_VersionRangeSet(ssl_fd_, &vrange_);
  EXPECT_EQ(SECSuccess, rv);
  if (rv != SECSuccess) return false;

  rv = SSL_AuthCertificateHook(ssl_fd_, AuthCertificateHook, this);
  EXPECT_EQ(SECSuccess, rv);
  if (rv != SECSuccess) return false;

  rv = SSL_HandshakeCallback(ssl_fd_, HandshakeCallback, this);
  EXPECT_EQ(SECSuccess, rv);
  if (rv != SECSuccess) return false;

  return true;
}

void TlsAgent::StartConnect() {
  EXPECT_TRUE(EnsureTlsSetup());

  SECStatus rv;
  rv = SSL_ResetHandshake(ssl_fd_, role_ == SERVER ? PR_TRUE : PR_FALSE);
  EXPECT_EQ(SECSuccess, rv);
  SetState(STATE_CONNECTING);
}

void TlsAgent::EnableSomeEcdheCiphers() {
  EXPECT_TRUE(EnsureTlsSetup());

  const uint32_t EcdheCiphers[] = {TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                                   TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                                   TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                                   TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA};

  for (size_t i = 0; i < PR_ARRAY_SIZE(EcdheCiphers); ++i) {
    SECStatus rv = SSL_CipherPrefSet(ssl_fd_, EcdheCiphers[i], PR_TRUE);
    EXPECT_EQ(SECSuccess, rv);
  }
}


void TlsAgent::DisableDheCiphers() {
  EXPECT_TRUE(EnsureTlsSetup());

  for (size_t i = 0; i < SSL_NumImplementedCiphers; ++i) {
    SSLCipherSuiteInfo csinfo;

    SECStatus rv = SSL_GetCipherSuiteInfo(SSL_ImplementedCiphers[i],
                                          &csinfo, sizeof(csinfo));
    ASSERT_EQ(SECSuccess, rv);

    if (csinfo.keaType == ssl_kea_dh) {
      rv = SSL_CipherPrefSet(ssl_fd_, SSL_ImplementedCiphers[i], PR_FALSE);
      EXPECT_EQ(SECSuccess, rv);
    }
  }
}

void TlsAgent::SetSessionTicketsEnabled(bool en) {
  EXPECT_TRUE(EnsureTlsSetup());

  SECStatus rv = SSL_OptionSet(ssl_fd_, SSL_ENABLE_SESSION_TICKETS,
                               en ? PR_TRUE : PR_FALSE);
  EXPECT_EQ(SECSuccess, rv);
}

void TlsAgent::SetSessionCacheEnabled(bool en) {
  EXPECT_TRUE(EnsureTlsSetup());

  SECStatus rv = SSL_OptionSet(ssl_fd_, SSL_NO_CACHE,
                               en ? PR_FALSE : PR_TRUE);
  EXPECT_EQ(SECSuccess, rv);
}

void TlsAgent::SetVersionRange(uint16_t minver, uint16_t maxver) {
   vrange_.min = minver;
   vrange_.max = maxver;

   if (ssl_fd_) {
     SECStatus rv = SSL_VersionRangeSet(ssl_fd_, &vrange_);
     EXPECT_EQ(SECSuccess, rv);
   }
}

void TlsAgent::SetExpectedVersion(uint16_t version) {
  expected_version_ = version;
}

void TlsAgent::SetExpectedReadError(bool err) {
  expected_read_error_ = err;
}

void TlsAgent::CheckKEAType(SSLKEAType type) const {
  EXPECT_EQ(STATE_CONNECTED, state_);
  EXPECT_EQ(type, csinfo_.keaType);
}

void TlsAgent::CheckAuthType(SSLAuthType type) const {
  EXPECT_EQ(STATE_CONNECTED, state_);
  EXPECT_EQ(type, csinfo_.authAlgorithm);
}

void TlsAgent::EnableFalseStart() {
  EXPECT_TRUE(EnsureTlsSetup());

  falsestart_enabled_ = true;
  EXPECT_EQ(SECSuccess,
            SSL_SetCanFalseStartCallback(ssl_fd_, CanFalseStartCallback, this));
  EXPECT_EQ(SECSuccess,
            SSL_OptionSet(ssl_fd_, SSL_ENABLE_FALSE_START, PR_TRUE));
}

void TlsAgent::ExpectResumption() {
  expect_resumption_ = true;
}

void TlsAgent::EnableAlpn(const uint8_t* val, size_t len) {
  EXPECT_TRUE(EnsureTlsSetup());

  EXPECT_EQ(SECSuccess, SSL_OptionSet(ssl_fd_, SSL_ENABLE_ALPN, PR_TRUE));
  EXPECT_EQ(SECSuccess, SSL_SetNextProtoNego(ssl_fd_, val, len));
}

void TlsAgent::CheckAlpn(SSLNextProtoState expected_state,
                         const std::string& expected) const {
  SSLNextProtoState state;
  char chosen[10];
  unsigned int chosen_len;
  SECStatus rv = SSL_GetNextProto(ssl_fd_, &state,
                                  reinterpret_cast<unsigned char*>(chosen),
                                  &chosen_len, sizeof(chosen));
  EXPECT_EQ(SECSuccess, rv);
  EXPECT_EQ(expected_state, state);
  EXPECT_EQ(expected, std::string(chosen, chosen_len));
}

void TlsAgent::EnableSrtp() {
  EXPECT_TRUE(EnsureTlsSetup());
  const uint16_t ciphers[] = {
    SRTP_AES128_CM_HMAC_SHA1_80, SRTP_AES128_CM_HMAC_SHA1_32
  };
  EXPECT_EQ(SECSuccess, SSL_SetSRTPCiphers(ssl_fd_, ciphers,
                                           PR_ARRAY_SIZE(ciphers)));

}

void TlsAgent::CheckSrtp() const {
  uint16_t actual;
  EXPECT_EQ(SECSuccess, SSL_GetSRTPCipher(ssl_fd_, &actual));
  EXPECT_EQ(SRTP_AES128_CM_HMAC_SHA1_80, actual);
}

void TlsAgent::CheckErrorCode(int32_t expected) const {
  EXPECT_EQ(STATE_ERROR, state_);
  EXPECT_EQ(expected, error_code_);
}

void TlsAgent::CheckPreliminaryInfo() {
  SSLPreliminaryChannelInfo info;
  EXPECT_EQ(SECSuccess,
            SSL_GetPreliminaryChannelInfo(ssl_fd_, &info, sizeof(info)));
  EXPECT_TRUE(info.valuesSet & ssl_preinfo_version);
  EXPECT_TRUE(info.valuesSet & ssl_preinfo_cipher_suite);

  // A version of 0 is invalid and indicates no expectation.  This value is
  // initialized to 0 so that tests that don't explicitly set an expected
  // version can negotiate a version.
  if (!expected_version_) {
    expected_version_ = info.protocolVersion;
  }
  EXPECT_EQ(expected_version_, info.protocolVersion);

  // As with the version; 0 is the null cipher suite (and also invalid).
  if (!expected_cipher_suite_) {
    expected_cipher_suite_ = info.cipherSuite;
  }
  EXPECT_EQ(expected_cipher_suite_, info.cipherSuite);
}

// Check that all the expected callbacks have been called.
void TlsAgent::CheckCallbacks() const {
  // If false start happens, the handshake is reported as being complete at the
  // point that false start happens.
  if (expect_resumption_ || !falsestart_enabled_) {
    EXPECT_TRUE(handshake_callback_called_);
  }

  // These callbacks shouldn't fire if we are resuming.
  if (role_ == SERVER) {
    EXPECT_EQ(!expect_resumption_, sni_hook_called_);
  } else {
    EXPECT_EQ(!expect_resumption_, auth_certificate_hook_called_);
    // Note that this isn't unconditionally called, even with false start on.
    // But the callback is only skipped if a cipher that is ridiculously weak
    // (80 bits) is chosen.  Don't test that: plan to remove bad ciphers.
    EXPECT_EQ(falsestart_enabled_ && !expect_resumption_,
              can_falsestart_hook_called_);
  }
}

void TlsAgent::Connected() {
  LOG("Handshake success");
  CheckCallbacks();

  SECStatus rv = SSL_GetChannelInfo(ssl_fd_, &info_, sizeof(info_));
  EXPECT_EQ(SECSuccess, rv);

  // Preliminary values are exposed through callbacks during the handshake.
  // If either expected values were set or the callbacks were called, check
  // that the final values are correct.
  EXPECT_EQ(expected_version_, info_.protocolVersion);
  EXPECT_EQ(expected_cipher_suite_, info_.cipherSuite);

  rv = SSL_GetCipherSuiteInfo(info_.cipherSuite, &csinfo_, sizeof(csinfo_));
  EXPECT_EQ(SECSuccess, rv);

  SetState(STATE_CONNECTED);
}

void TlsAgent::Handshake() {
  SECStatus rv = SSL_ForceHandshake(ssl_fd_);
  if (rv == SECSuccess) {
    Connected();

    Poller::Instance()->Wait(READABLE_EVENT, adapter_, this,
                             &TlsAgent::ReadableCallback);

    return;
  }

  int32_t err = PR_GetError();
  switch (err) {
    case PR_WOULD_BLOCK_ERROR:
      LOG("Would have blocked");
      // TODO(ekr@rtfm.com): set DTLS timeouts
      Poller::Instance()->Wait(READABLE_EVENT, adapter_, this,
                               &TlsAgent::ReadableCallback);
      return;
      break;

      // TODO(ekr@rtfm.com): needs special case for DTLS
    case SSL_ERROR_RX_MALFORMED_HANDSHAKE:
    default:
      LOG("Handshake failed with error " << err);
      error_code_ = err;
      SetState(STATE_ERROR);
      return;
  }
}

void TlsAgent::PrepareForRenegotiate() {
  EXPECT_EQ(STATE_CONNECTED, state_);

  SetState(STATE_CONNECTING);
}

void TlsAgent::StartRenegotiate() {
  PrepareForRenegotiate();

  SECStatus rv = SSL_ReHandshake(ssl_fd_, PR_TRUE);
  EXPECT_EQ(SECSuccess, rv);
}

void TlsAgent::SendData(size_t bytes, size_t blocksize) {
  uint8_t block[4096];

  ASSERT_LT(blocksize, sizeof(block));

  while(bytes) {
    size_t tosend = std::min(blocksize, bytes);

    for(size_t i = 0; i < tosend; ++i) {
      block[i] = 0xff & send_ctr_;
      ++send_ctr_;
    }

    LOG("Writing " << tosend << " bytes");
    int32_t rv = PR_Write(ssl_fd_, block, tosend);
    ASSERT_EQ(tosend, static_cast<size_t>(rv));

    bytes -= tosend;
  }
}

void TlsAgent::ReadBytes() {
  uint8_t block[1024];

  LOG("Reading application data from socket");

  int32_t rv = PR_Read(ssl_fd_, block, sizeof(block));

  int32_t err = PR_GetError();
  if (err != PR_WOULD_BLOCK_ERROR) {
    if (expected_read_error_) {
      error_code_ = err;
    } else {
      ASSERT_LE(0, rv);
      size_t count = static_cast<size_t>(rv);
      LOG("Read " << count << " bytes");
      for (size_t i = 0; i < count; ++i) {
        ASSERT_EQ(recv_ctr_ & 0xff, block[i]);
        recv_ctr_++;
      }
    }
  }

  Poller::Instance()->Wait(READABLE_EVENT, adapter_, this,
                           &TlsAgent::ReadableCallback);
}

void TlsAgent::ResetSentBytes() {
  send_ctr_ = 0;
}

void TlsAgent::ConfigureSessionCache(SessionResumptionMode mode) {
  EXPECT_TRUE(EnsureTlsSetup());

  SECStatus rv = SSL_OptionSet(ssl_fd_,
                               SSL_NO_CACHE,
                               mode & RESUME_SESSIONID ?
                               PR_FALSE : PR_TRUE);
  EXPECT_EQ(SECSuccess, rv);

  rv = SSL_OptionSet(ssl_fd_,
                     SSL_ENABLE_SESSION_TICKETS,
                     mode & RESUME_TICKET ?
                     PR_TRUE : PR_FALSE);
  EXPECT_EQ(SECSuccess, rv);
}


} // namespace nss_test
