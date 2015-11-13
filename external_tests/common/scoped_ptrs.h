/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef scoped_ptrs_h__
#define scoped_ptrs_h__

#include "keyhi.h"

namespace nss_test {

struct ScopedDelete {
  void operator()(PK11SlotInfo* slot) { PK11_FreeSlot(slot); }
  void operator()(SECItem* item) { SECITEM_FreeItem(item, true); }
  void operator()(PK11SymKey* key) { PK11_FreeSymKey(key); }
  void operator()(SECKEYPublicKey* key) { SECKEY_DestroyPublicKey(key); }
  void operator()(SECKEYPrivateKey* key) { SECKEY_DestroyPrivateKey(key); }
  void operator()(SECAlgorithmID* id) { SECOID_DestroyAlgorithmID(id, true); }
  void operator()(CERTSubjectPublicKeyInfo* spki) {
    SECKEY_DestroySubjectPublicKeyInfo(spki);
  }
};

template<class T>
struct ScopedMaybeDelete {
  void operator()(T* ptr) { if (ptr) { ScopedDelete del; del(ptr); } }
};

template<class T>
using ScopedUniquePtr = std::unique_ptr<T, ScopedMaybeDelete<T>>;

using ScopedPK11SlotInfo = ScopedUniquePtr<PK11SlotInfo>;
using ScopedSECItem = ScopedUniquePtr<SECItem>;
using ScopedPK11SymKey = ScopedUniquePtr<PK11SymKey>;
using ScopedSECKEYPublicKey = ScopedUniquePtr<SECKEYPublicKey>;
using ScopedSECKEYPrivateKey = ScopedUniquePtr<SECKEYPrivateKey>;
using ScopedSECAlgorithmID = ScopedUniquePtr<SECAlgorithmID>;
using ScopedCERTSubjectPublicKeyInfo = ScopedUniquePtr<CERTSubjectPublicKeyInfo>;

}  // namespace nss_test

#endif
