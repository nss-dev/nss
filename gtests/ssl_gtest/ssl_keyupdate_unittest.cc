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
#include "scoped_ptrs.h"
#include "tls_connect.h"
#include "tls_filter.h"
#include "tls_parser.h"

namespace nss_test {

// All stream only tests; DTLS isn't supported yet.

TEST_F(TlsConnectTest, KeyUpdateClient) {
  ConfigureVersion(SSL_LIBRARY_VERSION_TLS_1_3);
  Connect();
  EXPECT_EQ(SECSuccess, SSL_KeyUpdate(client_->ssl_fd(), PR_FALSE));
  SendReceive(50);
  SendReceive(60);
  CheckEpochs(4, 3);
}

TEST_F(TlsConnectTest, KeyUpdateClientRequestUpdate) {
  ConfigureVersion(SSL_LIBRARY_VERSION_TLS_1_3);
  Connect();
  EXPECT_EQ(SECSuccess, SSL_KeyUpdate(client_->ssl_fd(), PR_TRUE));
  // SendReceive() only gives each peer one chance to read.  This isn't enough
  // when the read on one side generates another handshake message.  A second
  // read gives each peer an extra chance to consume the KeyUpdate.
  SendReceive(50);
  SendReceive(60);  // Cumulative count.
  CheckEpochs(4, 4);
}

TEST_F(TlsConnectTest, KeyUpdateServer) {
  ConfigureVersion(SSL_LIBRARY_VERSION_TLS_1_3);
  Connect();
  EXPECT_EQ(SECSuccess, SSL_KeyUpdate(server_->ssl_fd(), PR_FALSE));
  SendReceive(50);
  SendReceive(60);
  CheckEpochs(3, 4);
}

TEST_F(TlsConnectTest, KeyUpdateServerRequestUpdate) {
  ConfigureVersion(SSL_LIBRARY_VERSION_TLS_1_3);
  Connect();
  EXPECT_EQ(SECSuccess, SSL_KeyUpdate(server_->ssl_fd(), PR_TRUE));
  SendReceive(50);
  SendReceive(60);
  CheckEpochs(4, 4);
}

TEST_F(TlsConnectTest, KeyUpdateConsecutiveRequests) {
  ConfigureVersion(SSL_LIBRARY_VERSION_TLS_1_3);
  Connect();
  EXPECT_EQ(SECSuccess, SSL_KeyUpdate(server_->ssl_fd(), PR_TRUE));
  EXPECT_EQ(SECSuccess, SSL_KeyUpdate(server_->ssl_fd(), PR_TRUE));
  SendReceive(50);
  SendReceive(60);
  // The server should have updated twice, but the client should have declined
  // to respond to the second request from the server, since it doesn't send
  // anything in between those two requests.
  CheckEpochs(4, 5);
}

// Check that a local update can be immediately followed by a remotely triggered
// update even if there is no use of the keys.
TEST_F(TlsConnectTest, KeyUpdateLocalUpdateThenConsecutiveRequests) {
  ConfigureVersion(SSL_LIBRARY_VERSION_TLS_1_3);
  Connect();
  // This should trigger an update on the client.
  EXPECT_EQ(SECSuccess, SSL_KeyUpdate(client_->ssl_fd(), PR_FALSE));
  // The client should update for the first request.
  EXPECT_EQ(SECSuccess, SSL_KeyUpdate(server_->ssl_fd(), PR_TRUE));
  // ...but not the second.
  EXPECT_EQ(SECSuccess, SSL_KeyUpdate(server_->ssl_fd(), PR_TRUE));
  SendReceive(50);
  SendReceive(60);
  // Both should have updated twice.
  CheckEpochs(5, 5);
}

TEST_F(TlsConnectTest, KeyUpdateMultiple) {
  ConfigureVersion(SSL_LIBRARY_VERSION_TLS_1_3);
  Connect();
  EXPECT_EQ(SECSuccess, SSL_KeyUpdate(server_->ssl_fd(), PR_FALSE));
  EXPECT_EQ(SECSuccess, SSL_KeyUpdate(server_->ssl_fd(), PR_TRUE));
  EXPECT_EQ(SECSuccess, SSL_KeyUpdate(server_->ssl_fd(), PR_FALSE));
  EXPECT_EQ(SECSuccess, SSL_KeyUpdate(client_->ssl_fd(), PR_FALSE));
  SendReceive(50);
  SendReceive(60);
  CheckEpochs(5, 6);
}

// Both ask the other for an update, and both should react.
TEST_F(TlsConnectTest, KeyUpdateBothRequest) {
  ConfigureVersion(SSL_LIBRARY_VERSION_TLS_1_3);
  Connect();
  EXPECT_EQ(SECSuccess, SSL_KeyUpdate(client_->ssl_fd(), PR_TRUE));
  EXPECT_EQ(SECSuccess, SSL_KeyUpdate(server_->ssl_fd(), PR_TRUE));
  SendReceive(50);
  SendReceive(60);
  CheckEpochs(5, 5);
}

}  // namespace nss_test
