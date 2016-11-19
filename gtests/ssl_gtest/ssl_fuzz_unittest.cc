/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "blapi.h"
#include "ssl.h"
#include "sslimpl.h"
#include "tls_connect.h"

#include "gtest/gtest.h"

namespace nss_test {

#ifdef UNSAFE_FUZZER_MODE

class TlsFuzzTest : public ::testing::Test {};

// Record the application data stream.
class TlsApplicationDataRecorder : public TlsRecordFilter {
 public:
  TlsApplicationDataRecorder() : buffer_() {}

  virtual PacketFilter::Action FilterRecord(const RecordHeader& header,
                                            const DataBuffer& input,
                                            DataBuffer* output) {
    if (header.content_type() == kTlsApplicationDataType) {
      buffer_.Append(input);
    }

    return KEEP;
  }

  const DataBuffer& buffer() const { return buffer_; }

 private:
  DataBuffer buffer_;
};

void ResetState() {
  // Clear the list of RSA blinding params.
  BL_Cleanup();

  // Reinit the list of RSA blinding params.
  EXPECT_EQ(SECSuccess, BL_Init());

  // Reset the RNG state.
  EXPECT_EQ(SECSuccess, RNG_ResetForFuzzing());
}

// Ensure that ssl_Time() returns a constant value.
TEST_F(TlsFuzzTest, Fuzz_SSL_Time_Constant) {
  PRInt32 now = ssl_Time();
  PR_Sleep(PR_SecondsToInterval(2));
  EXPECT_EQ(ssl_Time(), now);
}

// Check that due to the deterministic PRNG we derive
// the same master secret in two consecutive TLS sessions.
TEST_P(TlsConnectGeneric, Fuzz_DeterministicExporter) {
  const char kLabel[] = "label";
  std::vector<unsigned char> out1(32), out2(32);

  ConfigureSessionCache(RESUME_NONE, RESUME_NONE);
  DisableECDHEServerKeyReuse();

  ResetState();
  Connect();

  // Export a key derived from the MS and nonces.
  SECStatus rv =
      SSL_ExportKeyingMaterial(client_->ssl_fd(), kLabel, strlen(kLabel), false,
                               NULL, 0, out1.data(), out1.size());
  EXPECT_EQ(SECSuccess, rv);

  Reset();
  ConfigureSessionCache(RESUME_NONE, RESUME_NONE);
  DisableECDHEServerKeyReuse();

  ResetState();
  Connect();

  // Export another key derived from the MS and nonces.
  rv = SSL_ExportKeyingMaterial(client_->ssl_fd(), kLabel, strlen(kLabel),
                                false, NULL, 0, out2.data(), out2.size());
  EXPECT_EQ(SECSuccess, rv);

  // The two exported keys should be the same.
  EXPECT_EQ(out1, out2);
}

// Check that due to the deterministic RNG two consecutive
// TLS sessions will have the exact same transcript.
TEST_P(TlsConnectGeneric, Fuzz_DeterministicTranscript) {
  // Connect a few times and compare the transcripts byte-by-byte.
  DataBuffer last;
  for (size_t i = 0; i < 5; i++) {
    Reset();
    ConfigureSessionCache(RESUME_NONE, RESUME_NONE);
    DisableECDHEServerKeyReuse();

    DataBuffer buffer;
    client_->SetPacketFilter(new TlsConversationRecorder(buffer));
    server_->SetPacketFilter(new TlsConversationRecorder(buffer));

    ResetState();
    Connect();

    // Ensure the filters go away before |buffer| does.
    client_->SetPacketFilter(nullptr);
    server_->SetPacketFilter(nullptr);

    if (last.len() > 0) {
      EXPECT_EQ(last, buffer);
    }

    last = buffer;
  }
}

// Check that we can establish and use a connection
// with all supported TLS versions, STREAM and DGRAM.
// Check that records are NOT encrypted.
// Check that records don't have a MAC.
TEST_P(TlsConnectGeneric, Fuzz_ConnectSendReceive_NullCipher) {
  EnsureTlsSetup();

  // Set up app data filters.
  auto client_recorder = new TlsApplicationDataRecorder();
  client_->SetPacketFilter(client_recorder);
  auto server_recorder = new TlsApplicationDataRecorder();
  server_->SetPacketFilter(server_recorder);

  Connect();

  // Construct the plaintext.
  DataBuffer buf;
  buf.Allocate(50);
  for (size_t i = 0; i < buf.len(); ++i) {
    buf.data()[i] = i & 0xff;
  }

  // Send/Receive data.
  client_->SendBuffer(buf);
  server_->SendBuffer(buf);
  Receive(buf.len());

  // Check for plaintext on the wire.
  EXPECT_EQ(buf, client_recorder->buffer());
  EXPECT_EQ(buf, server_recorder->buffer());
}

#endif
}
