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

class HandshakeSecretTracker {
 public:
  HandshakeSecretTracker(const std::shared_ptr<TlsAgent>& agent,
                         uint16_t first_read_epoch, uint16_t first_write_epoch)
      : agent_(agent),
        next_read_epoch_(first_read_epoch),
        next_write_epoch_(first_write_epoch) {
    EXPECT_EQ(SECSuccess,
              SSL_SecretCallback(agent_->ssl_fd(),
                                 HandshakeSecretTracker::SecretCb, this));
  }

  void CheckComplete() const {
    EXPECT_EQ(0, next_read_epoch_);
    EXPECT_EQ(0, next_write_epoch_);
  }

 private:
  static void SecretCb(PRFileDesc* fd, PRUint16 epoch, SSLSecretDirection dir,
                       PK11SymKey* secret, void* arg) {
    HandshakeSecretTracker* t = reinterpret_cast<HandshakeSecretTracker*>(arg);
    t->SecretUpdated(epoch, dir, secret);
  }

  void SecretUpdated(PRUint16 epoch, SSLSecretDirection dir,
                     PK11SymKey* secret) {
    if (g_ssl_gtest_verbose) {
      std::cerr << agent_->role_str() << ": secret callback for "
                << (dir == ssl_secret_read ? "read" : "write") << " epoch "
                << epoch << std::endl;
    }

    EXPECT_TRUE(secret);
    uint16_t* p;
    if (dir == ssl_secret_read) {
      p = &next_read_epoch_;
    } else {
      ASSERT_EQ(ssl_secret_write, dir);
      p = &next_write_epoch_;
    }
    EXPECT_EQ(*p, epoch);
    switch (*p) {
      case 1:  // 1 == 0-RTT, next should be handshake.
      case 2:  // 2 == handshake, next should be application data.
        (*p)++;
        break;

      case 3:  // 3 == application data, there should be no more.
        // Use 0 as a sentinel value.
        *p = 0;
        break;

      default:
        ADD_FAILURE() << "Unexpected next epoch: " << *p;
    }
  }

  std::shared_ptr<TlsAgent> agent_;
  uint16_t next_read_epoch_;
  uint16_t next_write_epoch_;
};

TEST_F(TlsConnectTest, HandshakeSecrets) {
  ConfigureVersion(SSL_LIBRARY_VERSION_TLS_1_3);
  EnsureTlsSetup();

  HandshakeSecretTracker c(client_, 2, 2);
  HandshakeSecretTracker s(server_, 2, 2);

  Connect();
  SendReceive();

  c.CheckComplete();
  s.CheckComplete();
}

TEST_F(TlsConnectTest, ZeroRttSecrets) {
  SetupForZeroRtt();

  HandshakeSecretTracker c(client_, 2, 1);
  HandshakeSecretTracker s(server_, 1, 2);

  client_->Set0RttEnabled(true);
  server_->Set0RttEnabled(true);
  ExpectResumption(RESUME_TICKET);
  ZeroRttSendReceive(true, true);
  Handshake();
  ExpectEarlyDataAccepted(true);
  CheckConnected();
  SendReceive();

  c.CheckComplete();
  s.CheckComplete();
}

class KeyUpdateTracker {
 public:
  KeyUpdateTracker(const std::shared_ptr<TlsAgent>& agent,
                   bool expect_read_secret)
      : agent_(agent), expect_read_secret_(expect_read_secret), called_(false) {
    EXPECT_EQ(SECSuccess, SSL_SecretCallback(agent_->ssl_fd(),
                                             KeyUpdateTracker::SecretCb, this));
  }

  void CheckCalled() const { EXPECT_TRUE(called_); }

 private:
  static void SecretCb(PRFileDesc* fd, PRUint16 epoch, SSLSecretDirection dir,
                       PK11SymKey* secret, void* arg) {
    KeyUpdateTracker* t = reinterpret_cast<KeyUpdateTracker*>(arg);
    t->SecretUpdated(epoch, dir, secret);
  }

  void SecretUpdated(PRUint16 epoch, SSLSecretDirection dir,
                     PK11SymKey* secret) {
    EXPECT_EQ(4U, epoch);
    EXPECT_EQ(expect_read_secret_, dir == ssl_secret_read);
    EXPECT_TRUE(secret);
    called_ = true;
  }

  std::shared_ptr<TlsAgent> agent_;
  bool expect_read_secret_;
  bool called_;
};

TEST_F(TlsConnectTest, KeyUpdateSecrets) {
  ConfigureVersion(SSL_LIBRARY_VERSION_TLS_1_3);
  Connect();
  // The update is to the client write secret; the server read secret.
  KeyUpdateTracker c(client_, false);
  KeyUpdateTracker s(server_, true);
  EXPECT_EQ(SECSuccess, SSL_KeyUpdate(client_->ssl_fd(), PR_FALSE));
  SendReceive(50);
  SendReceive(60);
  CheckEpochs(4, 3);
  c.CheckCalled();
  s.CheckCalled();
}

}  // namespace nss_test
