/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "tls_client_config.h"

const uint64_t CONFIG_FAIL_CERT_AUTH = 1 << 0;
const uint64_t CONFIG_ENABLE_EXTENDED_MS = 1 << 1;
const uint64_t CONFIG_REQUIRE_DH_NAMED_GROUPS = 1 << 2;
const uint64_t CONFIG_ENABLE_FALSE_START = 1 << 3;
const uint64_t CONFIG_ENABLE_DEFLATE = 1 << 4;
const uint64_t CONFIG_ENABLE_CBC_RANDOM_IV = 1 << 5;
const uint64_t CONFIG_REQUIRE_SAFE_NEGOTIATION = 1 << 6;
const uint64_t CONFIG_ENABLE_CACHE = 1 << 7;
const uint64_t CONFIG_ENABLE_GREASE = 1 << 8;
const uint64_t CONFIG_ENABLE_CH_EXTENSION_PERMUTATION = 1 << 9;

// XOR 64-bit chunks of data to build a bitmap of config options derived from
// the fuzzing input. This seems the only way to fuzz various options while
// still maintaining compatibility with BoringSSL or OpenSSL fuzzers.
ClientConfig::ClientConfig(const uint8_t* data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    config_ ^= static_cast<uint64_t>(data[i]) << (8 * (i % 8));
  }
}

bool ClientConfig::FailCertificateAuthentication() {
  return config_ & CONFIG_FAIL_CERT_AUTH;
}

bool ClientConfig::EnableExtendedMasterSecret() {
  return config_ & CONFIG_ENABLE_EXTENDED_MS;
}

bool ClientConfig::RequireDhNamedGroups() {
  return config_ & CONFIG_REQUIRE_DH_NAMED_GROUPS;
}

bool ClientConfig::EnableFalseStart() {
  return config_ & CONFIG_ENABLE_FALSE_START;
}

bool ClientConfig::EnableDeflate() { return config_ & CONFIG_ENABLE_DEFLATE; }

bool ClientConfig::EnableCbcRandomIv() {
  return config_ & CONFIG_ENABLE_CBC_RANDOM_IV;
}

bool ClientConfig::RequireSafeNegotiation() {
  return config_ & CONFIG_REQUIRE_SAFE_NEGOTIATION;
}

bool ClientConfig::EnableCache() { return config_ & CONFIG_ENABLE_CACHE; }

bool ClientConfig::EnableGrease() { return config_ & CONFIG_ENABLE_GREASE; }

bool ClientConfig::EnableCHExtensionPermutation() {
  return config_ & CONFIG_ENABLE_CH_EXTENSION_PERMUTATION;
};
