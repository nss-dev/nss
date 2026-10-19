/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef pk11_import_h__
#define pk11_import_h__

#include "keyhi.h"
#include "pk11pub.h"

namespace nss_test {

// Drop-in replacements for the PK11 functions of the same names that also
// work when the internal token is in FIPS mode. A FIPS token refuses
// plaintext secret and private key material, so there the key is encrypted
// under a key generated in the token and then unwrapped.
PK11SymKey* ImportSymKey(PK11SlotInfo* slot, CK_MECHANISM_TYPE type,
                         PK11Origin origin, CK_ATTRIBUTE_TYPE operation,
                         SECItem* key, void* wincx);

PK11SymKey* ImportSymKeyWithFlags(PK11SlotInfo* slot, CK_MECHANISM_TYPE type,
                                  PK11Origin origin,
                                  CK_ATTRIBUTE_TYPE operation, SECItem* key,
                                  CK_FLAGS flags, PRBool isPerm, void* wincx);

SECStatus ImportDERPrivateKeyInfoAndReturnKey(
    PK11SlotInfo* slot, SECItem* derPKI, SECItem* nickname,
    const SECItem* publicValue, PRBool isPerm, PRBool isPrivate,
    unsigned int keyUsage, SECKEYPrivateKey** privk, void* wincx);

SECStatus ImportPrivateKeyInfoAndReturnKey(
    PK11SlotInfo* slot, SECKEYPrivateKeyInfo* pki, SECItem* nickname,
    const SECItem* publicValue, PRBool isPerm, PRBool isPrivate,
    unsigned int keyUsage, SECKEYPrivateKey** privk, void* wincx);

// True if plaintext keys can't be imported into |slot|.
bool SlotRequiresWrappedImport(PK11SlotInfo* slot);

// The reverse direction. A FIPS token won't release key material in
// plaintext, so there the key is wrapped and the result decrypted. As with
// PK11_GetKeyData, the item is owned elsewhere: here until the next
// ExtractKeyValue on |key|.
SECStatus ExtractKeyValue(PK11SymKey* key);
SECItem* GetKeyData(PK11SymKey* key);
SECItem* ExportDERPrivateKeyInfo(SECKEYPrivateKey* key, void* wincx);
SECKEYPrivateKeyInfo* ExportPrivKeyInfo(SECKEYPrivateKey* key, void* wincx);

}  // namespace nss_test

#endif  // pk11_import_h__
