// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdint.h>
#include <string>
#include <vector>

std::vector<uint8_t> hex_string_to_bytes(std::string s) {
  std::vector<uint8_t> bytes;
  assert(s.length() % 2 == 0);
  for (size_t i = 0; i < s.length(); i += 2) {
    bytes.push_back(std::stoul(s.substr(i, 2), nullptr, 16));
  }
  return bytes;
}
