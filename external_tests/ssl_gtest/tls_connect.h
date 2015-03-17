/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef tls_connect_h_
#define tls_connect_h_

#include <tuple>

#include "sslt.h"

#include "tls_agent.h"

#define GTEST_HAS_RTTI 0
#include "gtest/gtest.h"

namespace nss_test {

// A generic TLS connection test base.
class TlsConnectTestBase : public ::testing::Test {
 public:
  TlsConnectTestBase(Mode mode);
  virtual ~TlsConnectTestBase();

  void SetUp();
  void TearDown();

  // Initialize client and server.
  void Init();
  // Re-initialize client and server.
  void Reset();
  // Make sure TLS is configured for a connection.
  void EnsureTlsSetup();

  // Run the handshake.
  void Handshake();
  // Connect and check that it works.
  void Connect();
  // Connect and expect it to fail.
  void ConnectExpectFail();

  void EnableSomeECDHECiphers();
  void ConfigureSessionCache(SessionResumptionMode client,
                             SessionResumptionMode server);
  void CheckResumption(SessionResumptionMode expected);
  void EnableAlpn();
  void EnableSrtp();
  void CheckSrtp();
 protected:

  Mode mode_;
  TlsAgent* client_;
  TlsAgent* server_;
  uint16_t version_;
  std::vector<std::vector<uint8_t>> session_ids_;
};

// A TLS-only test base.
class TlsConnectTest : public TlsConnectTestBase {
 public:
  TlsConnectTest() : TlsConnectTestBase(STREAM) {}
};

// A DTLS-only test base.
class DtlsConnectTest : public TlsConnectTestBase {
 public:
  DtlsConnectTest() : TlsConnectTestBase(DGRAM) {}
};

// A generic test class that can be either STREAM or DGRAM.  This is configured
// in ssl_loopback_unittest.cc.  All uses of this should use TEST_P().
class TlsConnectGeneric : public TlsConnectTestBase,
                          public ::testing::WithParamInterface<std::string> {
 public:
  TlsConnectGeneric();
};

// A generic test class that is a single version of TLS.   This is configured
// in ssl_loopback_unittest.cc.  All uses of this should use TEST_P().
class TlsConnectGenericSingleVersion : public TlsConnectTestBase,
                                       public ::testing::WithParamInterface<
std::tuple<std::string,uint16_t>> {
public:
 TlsConnectGenericSingleVersion() : TlsConnectTestBase(
     std::get<0>(GetParam()) == "TLS" ? STREAM : DGRAM) {
   uint16_t version = std::get<1>(GetParam());

   std::cerr << "Version : " << version << std::endl;
   client_->SetVersionRange(version, version);
   server_->SetVersionRange(version, version);
   version_ = version;
 }
};

} // namespace nss_test

#endif
