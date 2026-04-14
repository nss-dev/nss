/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <cassert>
#include <cstddef>
#include <cstdint>

#include "nss_scoped_ptrs.h"
#include "prio.h"
#include "sslexp.h"

#include "base/database.h"
#include "tls/socket.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t len) {
  static NSSDatabase db = NSSDatabase();
  static PRDescIdentity id = PR_GetUniqueIdentity("fuzz-ech");

  static TlsSocket::DummyPrSocket socket = TlsSocket::DummyPrSocket(nullptr, 0);
  static ScopedPRFileDesc prFd(DummyIOLayerMethods::CreateFD(id, &socket));
  static PRFileDesc* sslFd = SSL_ImportFD(nullptr, prFd.get());
  assert(sslFd == prFd.get());

  SSL_SetClientEchConfigs(sslFd, data, len);

  return 0;
}
