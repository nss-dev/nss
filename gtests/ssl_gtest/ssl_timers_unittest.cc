/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "secerr.h"
#include "ssl.h"
#include "sslerr.h"
#include "sslproto.h"

extern "C" {
// This is not something that should make you happy.
#include "libssl_internals.h"
}

#include "gtest_utils.h"
#include "nss_scoped_ptrs.h"
#include "tls_connect.h"
#include "tls_filter.h"
#include "tls_parser.h"

namespace nss_test {

// Reproducing https://bugzilla.mozilla.org/show_bug.cgi?id=1978603
// The test causes assertion failure: timer->cb == NULL, at
// lib/ssl/dtlscon.c:922

// The general problem in the bug was that each post-handshake message
// was starting a new retransmit timer.
// We've decided to change the timer logic such that a retransmit timer
// will be restarted when a new request for a timer arrives.

// This test ensures that if two different post-handshake messages are queued
// for retransmission, the timer behaves correctly. When the second message is
// queued, we reset the timer. This means a message never waits longer than the
// minimum timer delay. The first message queued will be retransmitted a bit
// more aggressively than it would otherwise, but this is unlikely to be a
// problem.

// We're currently supporting NewSessionTicker and KeyUpdate post-handshake
// messages.

// The filter will be dropping Key Update and New Session Ticket until disabled
// When it's disabled, it will keep track of the New Session Ticket messages
// sent by the server, and when it founds one - it will record the sequence
// number This sequence number will then be provided to the second filter that
// will be checking the list of ACKs seaching for this message
class TLSSessionTicketAndKUDropper : public TlsRecordFilter {
 public:
  TLSSessionTicketAndKUDropper(const std::shared_ptr<TlsAgent>& a)
      : TlsRecordFilter(a), enabled_(true), sequenceNumberNST(0) {}

  void disable() { enabled_ = false; }

  uint64_t getSentSessionTicketSeqNum() { return sequenceNumberNST; }

 protected:
  PacketFilter::Action FilterRecord(const TlsRecordHeader& header,
                                    const DataBuffer& record, size_t* offset,
                                    DataBuffer* output) override {
    if (!header.is_protected()) {
      return KEEP;
    }

    uint16_t protection_epoch;
    uint8_t inner_content_type;
    DataBuffer plaintext;
    TlsRecordHeader out_header;

    if (!Unprotect(header, record, &protection_epoch, &inner_content_type,
                   &plaintext, &out_header)) {
      return KEEP;
    }

    if (plaintext.data()[0] == ssl_hs_new_session_ticket) {
      if (enabled_) {
        return DROP;
      } else {
        sequenceNumberNST = out_header.sequence_number();
      }
    }

    if (plaintext.data()[0] == ssl_hs_key_update && enabled_) {
      return DROP;
    }

    return KEEP;
  }

 private:
  bool enabled_;
  uint64_t sequenceNumberNST;
};

class TLSACKRecorder : public TlsRecordFilter {
 public:
  TLSACKRecorder(const std::shared_ptr<TlsAgent>& a)
      : TlsRecordFilter(a),
        enabled_(false),
        isSeqNumFound(false),
        sequenceNumberToFindACKed(0) {}

  void EnableTLSACKCatcherWithSeqNum(uint64_t seqNum) {
    enabled_ = true;
    sequenceNumberToFindACKed = seqNum;
  }

  bool isNSTACKFound() { return isSeqNumFound; }

 protected:
  PacketFilter::Action FilterRecord(const TlsRecordHeader& header,
                                    const DataBuffer& record, size_t* offset,
                                    DataBuffer* output) override {
    if (!enabled_) {
      return KEEP;
    }

    if (!header.is_protected()) {
      return KEEP;
    }

    uint16_t protection_epoch;
    uint8_t inner_content_type;
    DataBuffer plaintext;
    TlsRecordHeader out_header;

    if (!Unprotect(header, record, &protection_epoch, &inner_content_type,
                   &plaintext, &out_header)) {
      return KEEP;
    }

    if (plaintext.data() == NULL || plaintext.len() == 0) {
      return KEEP;
    }

    if (decrypting() && inner_content_type != ssl_ct_ack) {
      return KEEP;
    }

    uint8_t ack_message_header_len = 2;

    uint8_t ack_message_len_one_ACK = 16;
    size_t acks = plaintext.len() - ack_message_header_len;
    EXPECT_EQ((uint64_t)0, acks % ack_message_len_one_ACK);
    acks = acks / ack_message_len_one_ACK;

    // struct {
    //   uint64 epoch;
    //   uint64 sequence_number;
    // } RecordNumber;

    // sequenceNumberToFindACKed has 16 bits for epoch and 48 for seqNum
    uint64_t epoch = sequenceNumberToFindACKed >> 48;
    uint64_t seqNum = sequenceNumberToFindACKed & 0xFFFFFFFFFFFF;

    uint64_t lastByteEpoch = 0;
    uint64_t leastByteSequence = 0;

    for (size_t i = 0; i < acks; i++) {
      // Here we check that the last byte of the epoch and the last byte of the
      // sequence Because we just sent a couple of messages, so the values will
      // be less than 256.
      lastByteEpoch = plaintext.data()[2 + i * ack_message_len_one_ACK + 7];
      leastByteSequence =
          plaintext.data()[2 + i * ack_message_len_one_ACK + 15];

      if ((epoch % 256 == lastByteEpoch) &&
          (seqNum % 256) == leastByteSequence) {
        isSeqNumFound = true;
        return KEEP;
      }
    }
    return KEEP;
  }

 private:
  bool enabled_;
  bool isSeqNumFound;
  uint64_t sequenceNumberToFindACKed;
};

TEST_F(TlsConnectDatagram13, SendTicketThenKeyUpdate) {
  ConfigureSessionCache(RESUME_BOTH, RESUME_TICKET);
  Connect();

  SendReceive();  // Need to read so that we absorb the session tickets.
  CheckKeys();

  // Resume the connection.
  Reset();
  ConfigureSessionCache(RESUME_BOTH, RESUME_TICKET);
  ExpectResumption(RESUME_TICKET);

  auto filter = MakeTlsFilter<TLSSessionTicketAndKUDropper>(server_);
  filter->EnableDecryption();

  auto ackRecorderFilter = MakeTlsFilter<TLSACKRecorder>(client_);
  ackRecorderFilter->EnableDecryption();

  // This should cause sending a NewSessionTicket (thus, starting the timer)
  // Sending the NewSessionTicket will be blocked by the filter
  Connect();

  // Server sends Key Update
  // The first Key Update will also be dropped by the server
  EXPECT_EQ(SECSuccess, SSL_KeyUpdate(server_->ssl_fd(), false));

  client_->ReadBytes();
  // Check that the client indeed has not received the KU.
  SSLInt_SendImmediateACK(client_->ssl_fd());
  server_->ReadBytes();
  CheckEpochs(3, 3);

  // Disabling dropping the message, the effective retransmit will start
  filter->disable();

  // So, we don't have to wait until the next retransmit happens
  ShiftDtlsTimers();
  server_->ReadBytes();
  // We get the Sequence number of the NewSessionTicket that the server has sent
  uint64_t sequenceNumberNST = filter->getSentSessionTicketSeqNum();
  // And we check that the client has received (thus acked) the newly
  // retransmitted NewSessionTicket
  ackRecorderFilter->EnableTLSACKCatcherWithSeqNum(sequenceNumberNST);

  // Client Received NewSessionTicker and KU
  client_->ReadBytes();
  SSLInt_SendImmediateACK(client_->ssl_fd());
  server_->ReadBytes();

  // Client and Server both received and processed KU
  CheckEpochs(3, 4);

  // Client has successfully received and sent an ACK for NST message
  EXPECT_EQ(true, ackRecorderFilter->isNSTACKFound());

  SendReceive(50);
}

class TLSIthMessageSeqNumDropper : public TlsRecordFilter {
 public:
  TLSIthMessageSeqNumDropper(const std::shared_ptr<TlsAgent>& a,
                             uint8_t messageSeqNumToDrop)
      : TlsRecordFilter(a),
        enabled_(true),
        messageSeqNumToDrop_(messageSeqNumToDrop),
        currentMessageSeqNum_(0) {}

  void disable() { enabled_ = false; }

 protected:
  PacketFilter::Action FilterRecord(const TlsRecordHeader& header,
                                    const DataBuffer& record, size_t* offset,
                                    DataBuffer* output) override {
    if (enabled_ && currentMessageSeqNum_ == messageSeqNumToDrop_) {
      enabled_ = false;

      uint16_t protection_epoch;
      uint8_t inner_content_type;
      DataBuffer plaintext;
      TlsRecordHeader out_header;

      if (!Unprotect(header, record, &protection_epoch, &inner_content_type,
                     &plaintext, &out_header)) {
        return KEEP;
      }

      if (inner_content_type == ssl_ct_ack ||
          inner_content_type == ssl_ct_application_data) {
        return KEEP;
      }

      return DROP;
    }

    currentMessageSeqNum_ += 1;
    return KEEP;
  }

 private:
  bool enabled_;
  uint8_t messageSeqNumToDrop_;
  uint8_t currentMessageSeqNum_;
};

TEST_F(TlsConnectDatagram13, HandshakeDropIthMessageServer) {
  uint8_t maxServerMessageSeq = 10;

  for (uint8_t currMesSeqNum = 0; currMesSeqNum < maxServerMessageSeq;
       currMesSeqNum++) {
    EnsureTlsSetup();
    auto filter =
        MakeTlsFilter<TLSIthMessageSeqNumDropper>(server_, currMesSeqNum);
    filter->EnableDecryption();

    Connect();
    SendReceive();
    Reset();
  }
}

TEST_F(TlsConnectDatagram13, HandshakeDropIthMessageClient) {
  uint8_t maxClientMessageSeq = 10;

  for (uint8_t currMesSeqNum = 0; currMesSeqNum < maxClientMessageSeq;
       currMesSeqNum++) {
    EnsureTlsSetup();
    auto filter =
        MakeTlsFilter<TLSIthMessageSeqNumDropper>(client_, currMesSeqNum);
    filter->EnableDecryption();

    Connect();
    SendReceive();
    Reset();
  }
}

}  // namespace nss_test
