/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef scoped_ptrs_h__
#define scoped_ptrs_h__

namespace nss_test {

void ScopedDelete(PK11SlotInfo* slot) { PK11_FreeSlot(slot); }
void ScopedDelete(SECItem* item) { SECITEM_FreeItem(item, true); }
void ScopedDelete(SECKEYPublicKey* key) { SECKEY_DestroyPublicKey(key); }
void ScopedDelete(SECKEYPrivateKey* key) { SECKEY_DestroyPrivateKey(key); }
void ScopedDelete(CERTSubjectPublicKeyInfo* spki) {
  SECKEY_DestroySubjectPublicKeyInfo(spki);
}

template<class T>
struct ScopedMaybeDelete {
  void operator()(T* ptr) { if (ptr) ScopedDelete(ptr); }
};

template<class T>
using ScopedUniquePtr = std::unique_ptr<T, ScopedMaybeDelete<T>>;

using ScopedPK11SlotInfo = ScopedUniquePtr<PK11SlotInfo>;
using ScopedSECItem = ScopedUniquePtr<SECItem>;
using ScopedSECKEYPublicKey = ScopedUniquePtr<SECKEYPublicKey>;
using ScopedSECKEYPrivateKey = ScopedUniquePtr<SECKEYPrivateKey>;
using ScopedCERTSubjectPublicKeyInfo = ScopedUniquePtr<CERTSubjectPublicKeyInfo>;

}  // namespace nss_test

#endif
