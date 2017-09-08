/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "secerr.h"
#include "ssl.h"
#include "sslexp.h"

extern "C" {
// This is not something that should make you happy.
#include "libssl_internals.h"
}

#include "gtest_utils.h"
#include "scoped_ptrs.h"
#include "tls_connect.h"
#include "tls_filter.h"
#include "tls_parser.h"

namespace nss_test {

TEST_P(TlsConnectDatagramPre13, DropClientFirstFlightOnce) {
  client_->SetPacketFilter(std::make_shared<SelectiveDropFilter>(0x1));
  Connect();
  SendReceive();
}

TEST_P(TlsConnectDatagramPre13, DropServerFirstFlightOnce) {
  server_->SetPacketFilter(std::make_shared<SelectiveDropFilter>(0x1));
  Connect();
  SendReceive();
}

// This drops the first transmission from both the client and server of all
// flights that they send.  Note: In DTLS 1.3, the shorter handshake means that
// this will also drop some application data, so we can't call SendReceive().
TEST_P(TlsConnectDatagramPre13, DropAllFirstTransmissions) {
  client_->SetPacketFilter(std::make_shared<SelectiveDropFilter>(0x15));
  server_->SetPacketFilter(std::make_shared<SelectiveDropFilter>(0x5));
  Connect();
}

// This drops the server's first flight three times.
TEST_P(TlsConnectDatagramPre13, DropServerFirstFlightThrice) {
  server_->SetPacketFilter(std::make_shared<SelectiveDropFilter>(0x7));
  Connect();
}

// This drops the client's second flight once
TEST_P(TlsConnectDatagramPre13, DropClientSecondFlightOnce) {
  client_->SetPacketFilter(std::make_shared<SelectiveDropFilter>(0x2));
  Connect();
}

// This drops the client's second flight three times.
TEST_P(TlsConnectDatagramPre13, DropClientSecondFlightThrice) {
  client_->SetPacketFilter(std::make_shared<SelectiveDropFilter>(0xe));
  Connect();
}

// This drops the server's second flight three times.
TEST_P(TlsConnectDatagramPre13, DropServerSecondFlightThrice) {
  server_->SetPacketFilter(std::make_shared<SelectiveDropFilter>(0xe));
  Connect();
}

class TlsDropDatagram13 : public TlsConnectDatagram13 {
 public:
  TlsDropDatagram13()
      : client_filters_(),
        server_filters_(),
        expected_client_acks_(0),
        expected_server_acks_(1) {}

  void SetUp() {
    TlsConnectDatagram13::SetUp();
    ConfigureSessionCache(RESUME_NONE, RESUME_NONE);
    SetFilters();
  }

  void SetFilters() {
    EnsureTlsSetup();
    client_->SetPacketFilter(client_filters_.chain_);
    client_filters_.ack_->SetAgent(client_.get());
    client_filters_.ack_->EnableDecryption();
    server_->SetPacketFilter(server_filters_.chain_);
    server_filters_.ack_->SetAgent(server_.get());
    server_filters_.ack_->EnableDecryption();
  }

  void WaitTimeout(const std::shared_ptr<TlsAgent>& agent, uint32_t minTo) {
    PRIntervalTime timeout;
    ASSERT_EQ(SECSuccess, DTLS_GetHandshakeTimeout(agent->ssl_fd(), &timeout));
    ASSERT_GE(PR_MillisecondsToInterval(minTo), timeout);
    PR_Sleep(timeout);
  }

  void HandshakeAndAck(const std::shared_ptr<TlsAgent>& agent) {
    agent->Handshake();  // Read flight.
    WaitTimeout(agent, DTLS_RETRANSMIT_INITIAL_MS);
    agent->Handshake();  // Generate ACK.
  }

  void ShrinkPostServerHelloMtu() {
    // Abuse the custom extension mechanism to modify the MTU so that the
    // Certificate message is split into two pieces.
    ASSERT_EQ(
        SECSuccess,
        SSL_InstallExtensionHooks(
            server_->ssl_fd(), 1,
            [](PRFileDesc* fd, SSLHandshakeType message, PRUint8* data,
               unsigned int* len, unsigned int maxLen, void* arg) -> PRBool {
              SSLInt_SetMTU(fd, 384);  // Splits the certificate.
              return PR_FALSE;
            },
            nullptr,
            [](PRFileDesc* fd, SSLHandshakeType message, const PRUint8* data,
               unsigned int len, SSLAlertDescription* alert,
               void* arg) -> SECStatus { return SECSuccess; },
            nullptr));
  }

 protected:
  class DropAckChain {
   public:
    DropAckChain()
        : records_(std::make_shared<TlsRecordRecorder>()),
          ack_(std::make_shared<TlsRecordRecorder>(content_ack)),
          drop_(std::make_shared<SelectiveRecordDropFilter>(0, false)),
          chain_(std::make_shared<ChainedPacketFilter>(
              ChainedPacketFilterInit({records_, ack_, drop_}))) {}

    const TlsRecord& record(size_t i) const { return records_->record(i); }

    std::shared_ptr<TlsRecordRecorder> records_;
    std::shared_ptr<TlsRecordRecorder> ack_;
    std::shared_ptr<SelectiveRecordDropFilter> drop_;
    std::shared_ptr<PacketFilter> chain_;
  };

  void CheckAcks(const DropAckChain& chain, size_t index,
                 std::vector<uint64_t> acks) {
    const DataBuffer& buf = chain.ack_->record(index).buffer;
    size_t offset = 0;

    EXPECT_EQ(acks.size() * 8, buf.len());
    if ((acks.size() * 8) != buf.len()) {
      while (offset < buf.len()) {
        uint64_t ack;
        ASSERT_TRUE(buf.Read(offset, 8, &ack));
        offset += 8;
        std::cerr << "Ack=0x" << std::hex << ack << std::dec << std::endl;
      }
      return;
    }

    for (size_t i = 0; i < acks.size(); ++i) {
      uint64_t a = acks[i];
      uint64_t ack;
      ASSERT_TRUE(buf.Read(offset, 8, &ack));
      offset += 8;
      if (a != ack) {
        ADD_FAILURE() << "Wrong ack " << i << " expected=0x" << std::hex << a
                      << " got=0x" << ack << std::dec;
      }
    }
  }

  void CheckedHandshakeSendReceive() {
    Handshake();
    CheckPostHandshake();
  }

  void CheckPostHandshake() {
    CheckConnected();
    SendReceive();
    EXPECT_EQ(expected_client_acks_, client_filters_.ack_->count());
    EXPECT_EQ(expected_server_acks_, server_filters_.ack_->count());
  }

 protected:
  DropAckChain client_filters_;
  DropAckChain server_filters_;
  size_t expected_client_acks_;
  size_t expected_server_acks_;
};

// All of these tests produce a minimum one ACK, from the server
// to the client upon receiving the client Finished.
// Dropping complete first and second flights does not produce
// ACKs
TEST_F(TlsDropDatagram13, DropClientFirstFlightOnce) {
  client_filters_.drop_->Enable(1);
  StartConnect();
  client_->Handshake();
  server_->Handshake();
  CheckedHandshakeSendReceive();
  CheckAcks(server_filters_, 0, {0x0002000000000000ULL});
}

TEST_F(TlsDropDatagram13, DropServerFirstFlightOnce) {
  server_filters_.drop_->Enable(0xff);
  StartConnect();
  client_->Handshake();
  // Send the first flight, all dropped.
  server_->Handshake();
  server_filters_.drop_->Disable();
  CheckedHandshakeSendReceive();
  CheckAcks(server_filters_, 0, {0x0002000000000000ULL});
}

// Dropping the server's first record also does not produce
// an ACK because the next record is ignored.
// TODO(ekr@rtfm.com): We should generate an empty ACK.
TEST_F(TlsDropDatagram13, DropServerFirstRecordOnce) {
  server_filters_.drop_->Enable(1);
  StartConnect();
  client_->Handshake();
  server_->Handshake();
  Handshake();
  CheckedHandshakeSendReceive();
  CheckAcks(server_filters_, 0, {0x0002000000000000ULL});
}

// Dropping the second packet of the server's flight should
// produce an ACK.
TEST_F(TlsDropDatagram13, DropServerSecondRecordOnce) {
  server_filters_.drop_->Enable(2);
  StartConnect();
  client_->Handshake();
  server_->Handshake();
  HandshakeAndAck(client_);
  expected_client_acks_ = 1;
  CheckedHandshakeSendReceive();
  CheckAcks(client_filters_, 0, {0});
  CheckAcks(server_filters_, 0, {0x0002000000000000ULL});
}

// Drop the server ACK and verify that the client retransmits
// the ClientHello.
TEST_F(TlsDropDatagram13, DropServerAckOnce) {
  StartConnect();
  client_->Handshake();
  server_->Handshake();
  // At this point the server has sent it's first flight,
  // so make it drop the ACK.
  server_filters_.drop_->Enable(1);
  client_->Handshake();  // Send the client Finished.
  server_->Handshake();  // Receive the Finished and send the ACK.
  EXPECT_EQ(TlsAgent::STATE_CONNECTED, client_->state());
  EXPECT_EQ(TlsAgent::STATE_CONNECTED, server_->state());
  // Wait for the DTLS timeout to make sure we retransmit the
  // Finished.
  WaitTimeout(client_, DTLS_RETRANSMIT_INITIAL_MS * 2);
  client_->Handshake();  // Retransmit the Finished.
  server_->Handshake();  // Read the Finished and send an ACK.
  uint8_t buf[1];
  PRInt32 rv = PR_Read(client_->ssl_fd(), buf, sizeof(buf));
  expected_server_acks_ = 2;
  EXPECT_GT(0, rv);
  EXPECT_EQ(PR_WOULD_BLOCK_ERROR, PORT_GetError());
  CheckPostHandshake();
  // There should be two copies of the finished ACK
  CheckAcks(server_filters_, 0, {0x0002000000000000ULL});
  CheckAcks(server_filters_, 0, {0x0002000000000000ULL});
}

// Drop the client certificate verify.
TEST_F(TlsDropDatagram13, DropClientCertVerify) {
  StartConnect();
  client_->SetupClientAuth();
  server_->RequestClientAuth(true);
  client_->Handshake();
  server_->Handshake();
  // Have the client drop Cert Verify
  client_filters_.drop_->Enable(2);
  expected_server_acks_ = 2;
  CheckedHandshakeSendReceive();
  // Ack of the Cert.
  CheckAcks(server_filters_, 0, {0x0002000000000000ULL});
  // Ack of the whole client handshake.
  CheckAcks(
      server_filters_, 1,
      {0x0002000000000000ULL,  // CH (we drop everything after this on client)
       0x0002000000000003ULL,  // CT (2)
       0x0002000000000004ULL}  // FIN (2)
      );
}

// Shrink the MTU down so that certs get split and drop the first piece.
TEST_F(TlsDropDatagram13, DropFirstHalfOfServerCertificate) {
  server_filters_.drop_->Enable(4);
  StartConnect();
  ShrinkPostServerHelloMtu();
  client_->Handshake();
  server_->Handshake();
  // Check that things got split.
  EXPECT_EQ(6UL,
            server_filters_.records_->count());  // SH, EE, CT1, CT2, CV, FIN
  size_t ct1_size = server_filters_.record(2).buffer.len();
  server_filters_.records_->Clear();
  expected_client_acks_ = 1;
  HandshakeAndAck(client_);
  server_->Handshake();                               // Retransmit
  EXPECT_EQ(3UL, server_filters_.records_->count());  // CT2, CV, FIN
  // Check that the first record is CT1 (which is identical to the same
  // as the previous CT1).
  EXPECT_EQ(ct1_size, server_filters_.record(0).buffer.len());
  CheckedHandshakeSendReceive();
  CheckAcks(client_filters_, 0,
            {0,                      // SH
             0x0002000000000000ULL,  // EE
             0x0002000000000002ULL}  // CT2
            );
  CheckAcks(server_filters_, 0, {0x0002000000000000ULL});
}

// Shrink the MTU down so that certs get split and drop the second piece.
TEST_F(TlsDropDatagram13, DropSecondHalfOfServerCertificate) {
  server_filters_.drop_->Enable(8);
  StartConnect();
  ShrinkPostServerHelloMtu();
  client_->Handshake();
  server_->Handshake();
  // Check that things got split.
  EXPECT_EQ(6UL,
            server_filters_.records_->count());  // SH, EE, CT1, CT2, CV, FIN
  size_t ct1_size = server_filters_.record(3).buffer.len();
  server_filters_.records_->Clear();
  expected_client_acks_ = 1;
  HandshakeAndAck(client_);
  server_->Handshake();                               // Retransmit
  EXPECT_EQ(3UL, server_filters_.records_->count());  // CT1, CV, FIN
  // Check that the first record is CT1
  EXPECT_EQ(ct1_size, server_filters_.record(0).buffer.len());
  CheckedHandshakeSendReceive();
  CheckAcks(client_filters_, 0,
            {
                0,                      // SH
                0x0002000000000000ULL,  // EE
                0x0002000000000001ULL,  // CT1
            });
  CheckAcks(server_filters_, 0, {0x0002000000000000ULL});
}

TEST_F(TlsDropDatagram13, NoDropsDuringZeroRtt) {
  SetupForZeroRtt();
  SetFilters();
  std::cerr << "Starting second handshake" << std::endl;
  client_->Set0RttEnabled(true);
  server_->Set0RttEnabled(true);
  ExpectResumption(RESUME_TICKET);
  ZeroRttSendReceive(true, true);
  Handshake();
  ExpectEarlyDataAccepted(true);
  CheckConnected();
  SendReceive();
  CheckAcks(server_filters_, 0, {0x0002000000000000ULL});
}

TEST_F(TlsDropDatagram13, DropEEDuringZeroRtt) {
  SetupForZeroRtt();
  SetFilters();
  std::cerr << "Starting second handshake" << std::endl;
  client_->Set0RttEnabled(true);
  server_->Set0RttEnabled(true);
  ExpectResumption(RESUME_TICKET);
  server_filters_.drop_->Enable(2);
  ZeroRttSendReceive(true, true);
  HandshakeAndAck(client_);
  Handshake();
  ExpectEarlyDataAccepted(true);
  CheckConnected();
  SendReceive();
  CheckAcks(client_filters_, 0, {0});
  CheckAcks(server_filters_, 0, {0x0002000000000000ULL});
}

class TlsReorderDatagram13 : public TlsDropDatagram13 {
 public:
  TlsReorderDatagram13() {}

  // Send records from the records buffer in the given order.
  void ReSend(TlsAgent::Role side, std::vector<size_t> indices) {
    std::shared_ptr<TlsAgent> agent;
    std::shared_ptr<TlsRecordRecorder> records;

    if (side == TlsAgent::CLIENT) {
      agent = client_;
      records = client_filters_.records_;
    } else {
      agent = server_;
      records = server_filters_.records_;
    }

    for (auto i : indices) {
      agent->SendRecordDirect(records->record(i));
    }
  }
};

// Reorder the server records so that EE comes at the end
// of the flight and will still produce an ACK.
TEST_F(TlsDropDatagram13, ReorderServerEE) {
  server_filters_.drop_->Enable(2);
  StartConnect();
  client_->Handshake();
  server_->Handshake();
  // We dropped EE, now reinject.
  server_->SendRecordDirect(server_filters_.record(1));
  expected_client_acks_ = 1;
  HandshakeAndAck(client_);
  CheckedHandshakeSendReceive();
  CheckAcks(client_filters_, 0,
            {
                0,                   // SH
                0x0002000000000000,  // EE
            });
  CheckAcks(server_filters_, 0, {0x0002000000000000ULL});
}

// The client sends an out of order non-handshake message
// but with the handshake key.
class TlsSendCipherSpecCapturer {
 public:
  TlsSendCipherSpecCapturer(std::shared_ptr<TlsAgent>& agent)
      : is_server_(agent->role() == TlsAgent::SERVER), send_cipher_specs_() {
    SSLInt_SetCipherSpecChangeFunc(agent->ssl_fd(), CipherSpecChanged,
                                   (void*)this);
  }

  std::shared_ptr<TlsCipherSpec> spec(size_t i) {
    if (i >= send_cipher_specs_.size()) {
      return nullptr;
    }
    return send_cipher_specs_[i];
  }

 private:
  static void CipherSpecChanged(void* arg, PRBool sending,
                                ssl3CipherSpec* newSpec) {
    if (!sending) {
      return;
    }

    auto self = static_cast<TlsSendCipherSpecCapturer*>(arg);

    auto spec = std::make_shared<TlsCipherSpec>();
    bool ret =
        spec->Init(SSLInt_CipherSpecToEpoch(self->is_server_, newSpec),
                   SSLInt_CipherSpecToAlgorithm(self->is_server_, newSpec),
                   SSLInt_CipherSpecToKey(self->is_server_, newSpec),
                   SSLInt_CipherSpecToIv(self->is_server_, newSpec));
    EXPECT_EQ(true, ret);
    self->send_cipher_specs_.push_back(spec);
  }

  bool is_server_;
  std::vector<std::shared_ptr<TlsCipherSpec>> send_cipher_specs_;
};

TEST_F(TlsDropDatagram13, SendOutOfOrderAppWithHandshakeKey) {
  StartConnect();
  TlsSendCipherSpecCapturer capturer(client_);
  client_->Handshake();
  server_->Handshake();
  client_->Handshake();
  EXPECT_EQ(TlsAgent::STATE_CONNECTED, client_->state());
  server_->Handshake();
  EXPECT_EQ(TlsAgent::STATE_CONNECTED, server_->state());
  // After the client sends Finished, inject an app data record
  // with the handshake key. This should produce an alert.
  uint8_t buf[] = {'a', 'b', 'c'};
  auto spec = capturer.spec(0);
  ASSERT_NE(nullptr, spec.get());
  ASSERT_EQ(2, spec->epoch());
  ASSERT_TRUE(client_->SendEncryptedRecord(spec, 0xfeff, 0x0002000000000002,
                                           kTlsApplicationDataType,
                                           DataBuffer(buf, sizeof(buf))));

  // Now have the server consume the bogus message.
  server_->ExpectSendAlert(illegal_parameter, kTlsAlertFatal);
  server_->Handshake();
  EXPECT_EQ(TlsAgent::STATE_ERROR, server_->state());
  EXPECT_EQ(SSL_ERROR_RX_UNKNOWN_RECORD_TYPE, PORT_GetError());
}

TEST_F(TlsDropDatagram13, SendOutOfOrderHsNonsenseWithHandshakeKey) {
  StartConnect();
  TlsSendCipherSpecCapturer capturer(client_);
  client_->Handshake();
  server_->Handshake();
  client_->Handshake();
  EXPECT_EQ(TlsAgent::STATE_CONNECTED, client_->state());
  server_->Handshake();
  EXPECT_EQ(TlsAgent::STATE_CONNECTED, server_->state());
  // Inject a new bogus handshake record, which the server responds
  // to by just ACKing the original one (we ignore the contents).
  uint8_t buf[] = {'a', 'b', 'c'};
  auto spec = capturer.spec(0);
  ASSERT_NE(nullptr, spec.get());
  ASSERT_EQ(2, spec->epoch());
  ASSERT_TRUE(client_->SendEncryptedRecord(spec, 0xfeff, 0x0002000000000002,
                                           kTlsHandshakeType,
                                           DataBuffer(buf, sizeof(buf))));
  server_->Handshake();
  EXPECT_EQ(2UL, server_filters_.ack_->count());
  CheckAcks(server_filters_, 0, {0x0002000000000000ULL});
  CheckAcks(server_filters_, 1, {0x0002000000000000ULL});
}

// Shrink the MTU down so that certs get split and then swap the first and
// second pieces of the server certificate.
TEST_F(TlsReorderDatagram13, ReorderServerCertificate) {
  StartConnect();
  ShrinkPostServerHelloMtu();
  client_->Handshake();
  // Drop the entire handshake flight so we can reorder.
  server_filters_.drop_->Enable(255);
  server_->Handshake();
  // Check that things got split.
  EXPECT_EQ(6UL,
            server_filters_.records_->count());  // CH, EE, CT1, CT2, CV, FIN
  // Now re-send things in a different order.
  ReSend(TlsAgent::SERVER, std::vector<size_t>{0, 1, 3, 2, 4, 5});
  // Clear.
  server_filters_.drop_->Disable();
  server_filters_.records_->Clear();
  // Wait for client to send ACK.
  WaitTimeout(client_, DTLS_RETRANSMIT_INITIAL_MS);
  CheckedHandshakeSendReceive();
  EXPECT_EQ(2UL, server_filters_.records_->count());  // ACK + Data
  CheckAcks(server_filters_, 0, {0x0002000000000000ULL});
}

TEST_F(TlsReorderDatagram13, DataAfterEOEDDuringZeroRtt) {
  SetupForZeroRtt();
  SetFilters();
  std::cerr << "Starting second handshake" << std::endl;
  client_->Set0RttEnabled(true);
  server_->Set0RttEnabled(true);
  ExpectResumption(RESUME_TICKET);
  // Send the client's first flight of zero RTT data.
  ZeroRttSendReceive(true, true);
  // Now send another client application data record but
  // capture it.
  client_filters_.records_->Clear();
  client_filters_.drop_->Enable(255);
  const char* k0RttData = "123456";
  const PRInt32 k0RttDataLen = static_cast<PRInt32>(strlen(k0RttData));
  PRInt32 rv =
      PR_Write(client_->ssl_fd(), k0RttData, k0RttDataLen);  // 0-RTT write.
  EXPECT_EQ(k0RttDataLen, rv);
  EXPECT_EQ(1UL, client_filters_.records_->count());  // data
  server_->Handshake();
  client_->Handshake();
  ExpectEarlyDataAccepted(true);
  // The server still hasn't received anything at this point.
  EXPECT_EQ(3UL, client_filters_.records_->count());  // data, EOED, FIN
  EXPECT_EQ(TlsAgent::STATE_CONNECTED, client_->state());
  EXPECT_EQ(TlsAgent::STATE_CONNECTING, server_->state());
  // Now re-send the client's messages: EOED, data, FIN
  ReSend(TlsAgent::CLIENT, std::vector<size_t>({1, 0, 2}));
  server_->Handshake();
  CheckConnected();
  CheckAcks(server_filters_, 0, {0x0002000000000000ULL});
  uint8_t buf[8];
  rv = PR_Read(server_->ssl_fd(), buf, sizeof(buf));
  EXPECT_EQ(-1, rv);
  EXPECT_EQ(PR_WOULD_BLOCK_ERROR, PORT_GetError());
}

TEST_F(TlsReorderDatagram13, DataAfterFinDuringZeroRtt) {
  SetupForZeroRtt();
  SetFilters();
  std::cerr << "Starting second handshake" << std::endl;
  client_->Set0RttEnabled(true);
  server_->Set0RttEnabled(true);
  ExpectResumption(RESUME_TICKET);
  // Send the client's first flight of zero RTT data.
  ZeroRttSendReceive(true, true);
  // Now send another client application data record but
  // capture it.
  client_filters_.records_->Clear();
  client_filters_.drop_->Enable(255);
  const char* k0RttData = "123456";
  const PRInt32 k0RttDataLen = static_cast<PRInt32>(strlen(k0RttData));
  PRInt32 rv =
      PR_Write(client_->ssl_fd(), k0RttData, k0RttDataLen);  // 0-RTT write.
  EXPECT_EQ(k0RttDataLen, rv);
  EXPECT_EQ(1UL, client_filters_.records_->count());  // data
  server_->Handshake();
  client_->Handshake();
  ExpectEarlyDataAccepted(true);
  // The server still hasn't received anything at this point.
  EXPECT_EQ(3UL, client_filters_.records_->count());  // EOED, FIN, Data
  EXPECT_EQ(TlsAgent::STATE_CONNECTED, client_->state());
  EXPECT_EQ(TlsAgent::STATE_CONNECTING, server_->state());
  // Now re-send the client's messages: EOED, FIN, Data
  ReSend(TlsAgent::CLIENT, std::vector<size_t>({1, 2, 0}));
  server_->Handshake();
  CheckConnected();
  CheckAcks(server_filters_, 0, {0x0002000000000000ULL});
  uint8_t buf[8];
  rv = PR_Read(server_->ssl_fd(), buf, sizeof(buf));
  EXPECT_EQ(-1, rv);
  EXPECT_EQ(PR_WOULD_BLOCK_ERROR, PORT_GetError());
}

static void GetCipherAndLimit(uint16_t version, uint16_t* cipher,
                              uint64_t* limit = nullptr) {
  uint64_t l;
  if (!limit) limit = &l;

  if (version < SSL_LIBRARY_VERSION_TLS_1_2) {
    *cipher = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA;
    *limit = 0x5aULL << 28;
  } else if (version == SSL_LIBRARY_VERSION_TLS_1_2) {
    *cipher = TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
    *limit = (1ULL << 48) - 1;
  } else {
    *cipher = TLS_CHACHA20_POLY1305_SHA256;
    *limit = (1ULL << 48) - 1;
  }
}

// This simulates a huge number of drops on one side.
TEST_P(TlsConnectDatagram, MissLotsOfPackets) {
  uint16_t cipher;
  uint64_t limit;

  GetCipherAndLimit(version_, &cipher, &limit);

  EnsureTlsSetup();
  server_->EnableSingleCipher(cipher);
  Connect();

  // Note that the limit for ChaCha is 2^48-1.
  EXPECT_EQ(SECSuccess,
            SSLInt_AdvanceWriteSeqNum(client_->ssl_fd(), limit - 10));
  SendReceive();
}

class TlsConnectDatagram12Plus : public TlsConnectDatagram {
 public:
  TlsConnectDatagram12Plus() : TlsConnectDatagram() {}
};

// This simulates missing a window's worth of packets.
TEST_P(TlsConnectDatagram12Plus, MissAWindow) {
  EnsureTlsSetup();
  uint16_t cipher;
  GetCipherAndLimit(version_, &cipher);
  server_->EnableSingleCipher(cipher);
  Connect();
  EXPECT_EQ(SECSuccess, SSLInt_AdvanceWriteSeqByAWindow(client_->ssl_fd(), 0));
  SendReceive();
}

TEST_P(TlsConnectDatagram12Plus, MissAWindowAndOne) {
  EnsureTlsSetup();
  uint16_t cipher;
  GetCipherAndLimit(version_, &cipher);
  server_->EnableSingleCipher(cipher);
  Connect();

  EXPECT_EQ(SECSuccess, SSLInt_AdvanceWriteSeqByAWindow(client_->ssl_fd(), 1));
  SendReceive();
}

INSTANTIATE_TEST_CASE_P(Datagram12Plus, TlsConnectDatagram12Plus,
                        TlsConnectTestBase::kTlsV12Plus);
INSTANTIATE_TEST_CASE_P(DatagramPre13, TlsConnectDatagramPre13,
                        TlsConnectTestBase::kTlsV11V12);

}  // namespace nss_test
