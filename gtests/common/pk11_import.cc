/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "pk11_import.h"

#include <algorithm>
#include <cstddef>
#include <map>
#include <vector>

#include "nss_scoped_ptrs.h"
#include "secasn1.h"
#include "secerr.h"

namespace nss_test {

namespace {

const CK_MECHANISM_TYPE kWrapMech = CKM_AES_CBC_PAD;

// Generates a session AES key in |slot| and encrypts |data| under it. Returns
// the key with |wrapped| holding the ciphertext. |wrapMech| and |iv| are the
// mechanism and parameter for both the encryption and the subsequent unwrap.
PK11SymKey* EncryptForUnwrap(PK11SlotInfo* slot, const SECItem* data,
                             CK_MECHANISM_TYPE* wrapMech, ScopedSECItem* iv,
                             std::vector<uint8_t>* wrapped, void* wincx) {
  *wrapMech = kWrapMech;
  iv->reset(PK11_GenerateNewParam(*wrapMech, nullptr));
  if (!*iv) {
    return nullptr;
  }
  ScopedPK11SymKey kek(
      PK11_TokenKeyGenWithFlags(slot, CKM_AES_KEY_GEN, nullptr, 32, nullptr,
                                CKF_ENCRYPT | CKF_UNWRAP, 0, wincx));
  if (!kek) {
    return nullptr;
  }
  wrapped->resize(data->len + 16);
  unsigned int outLen = 0;
  if (PK11_Encrypt(kek.get(), *wrapMech, iv->get(), wrapped->data(), &outLen,
                   static_cast<unsigned int>(wrapped->size()), data->data,
                   data->len) != SECSuccess) {
    return nullptr;
  }
  wrapped->resize(outLen);
  return kek.release();
}

SEC_ASN1_MKSUB(SEC_AnyTemplate)
SEC_ASN1_MKSUB(SEC_BitStringTemplate)
SEC_ASN1_MKSUB(SECOID_AlgorithmIDTemplate)
SEC_ASN1_MKSUB(SEC_SetOfAnyTemplate)

// Just enough of RFC 5915's ECPrivateKey to find the public key.
struct ECPrivateKeyStr {
  SECItem version;
  SECItem privateValue;
  SECItem publicValue;
};

const SEC_ASN1Template kECPrivateKeyTemplate[] = {
    {SEC_ASN1_SEQUENCE, 0, nullptr, sizeof(ECPrivateKeyStr)},
    {SEC_ASN1_INTEGER, offsetof(ECPrivateKeyStr, version)},
    {SEC_ASN1_OCTET_STRING, offsetof(ECPrivateKeyStr, privateValue)},
    {SEC_ASN1_OPTIONAL | SEC_ASN1_CONSTRUCTED | SEC_ASN1_EXPLICIT |
         SEC_ASN1_CONTEXT_SPECIFIC |
         // NOLINTNEXTLINE(misc-redundant-expression)
         SEC_ASN1_XTRN | 0,
     0, SEC_ASN1_SUB(SEC_AnyTemplate)},
    {SEC_ASN1_OPTIONAL | SEC_ASN1_CONSTRUCTED | SEC_ASN1_EXPLICIT |
         SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_XTRN | 1,
     offsetof(ECPrivateKeyStr, publicValue),
     SEC_ASN1_SUB(SEC_BitStringTemplate)},
    {0}};

// A PrivateKeyInfo, or a v2 OneAsymmetricKey with its public key (RFC 5958).
struct PrivateKeyInfoV2Str {
  SECItem version;
  SECAlgorithmID algorithm;
  SECItem privateKey;
  SECItem** attributes;
  SECItem publicKey;
};

const SEC_ASN1Template kPrivateKeyInfoV2Template[] = {
    {SEC_ASN1_SEQUENCE, 0, nullptr, sizeof(PrivateKeyInfoV2Str)},
    {SEC_ASN1_INTEGER, offsetof(PrivateKeyInfoV2Str, version)},
    {SEC_ASN1_INLINE | SEC_ASN1_XTRN, offsetof(PrivateKeyInfoV2Str, algorithm),
     SEC_ASN1_SUB(SECOID_AlgorithmIDTemplate)},
    {SEC_ASN1_OCTET_STRING, offsetof(PrivateKeyInfoV2Str, privateKey)},
    {SEC_ASN1_OPTIONAL | SEC_ASN1_CONSTRUCTED | SEC_ASN1_CONTEXT_SPECIFIC |
         SEC_ASN1_XTRN | 0,  // NOLINT(misc-redundant-expression)
     offsetof(PrivateKeyInfoV2Str, attributes),
     SEC_ASN1_SUB(SEC_SetOfAnyTemplate)},
    {SEC_ASN1_OPTIONAL | SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_XTRN | 1,
     offsetof(PrivateKeyInfoV2Str, publicKey),
     SEC_ASN1_SUB(SEC_BitStringTemplate)},
    {0}};

// pk11wrap identifies an imported key by the public key the PKCS#8 carries,
// if any. Unwrapping doesn't look, so find it here. Returns an item in
// |arena|, or an empty one.
SECItem EmbeddedPublicKey(PLArenaPool* arena, const PrivateKeyInfoV2Str& pki,
                          KeyType keyType) {
  SECItem pub = pki.publicKey;
  if (!pub.len && keyType == ecKey) {
    ECPrivateKeyStr key = {};
    if (SEC_QuickDERDecodeItem(arena, &key, kECPrivateKeyTemplate,
                               &pki.privateKey) == SECSuccess) {
      pub = key.publicValue;
    }
  }
  pub.len = (pub.len + 7) / 8;  // bits to bytes
  return pub;
}

KeyType KeyTypeFromAlgorithm(SECOidTag tag) {
  switch (tag) {
    case SEC_OID_PKCS1_RSA_ENCRYPTION:
    case SEC_OID_PKCS1_RSA_PSS_SIGNATURE:
      return rsaKey;
    case SEC_OID_ANSIX9_DSA_SIGNATURE:
      return dsaKey;
    case SEC_OID_X942_DIFFIE_HELMAN_KEY:
      return dhKey;
    case SEC_OID_ANSIX962_EC_PUBLIC_KEY:
      return ecKey;
    case SEC_OID_ED25519_PUBLIC_KEY:
      return edKey;
    case SEC_OID_X25519:
      return ecMontKey;
    case SEC_OID_ML_DSA_44:
    case SEC_OID_ML_DSA_65:
    case SEC_OID_ML_DSA_87:
      return mldsaKey;
    case SEC_OID_ML_KEM_512:
    case SEC_OID_ML_KEM_768:
    case SEC_OID_ML_KEM_1024:
      return kyberKey;
    default:
      return nullKey;
  }
}

SECStatus UnwrapPrivateKey(PK11SlotInfo* slot, const SECItem* derPKI,
                           KeyType keyType, SECItem* nickname,
                           const SECItem* publicValue, PRBool isPerm,
                           unsigned int keyUsage, SECKEYPrivateKey** privk,
                           void* wincx) {
  if (keyType == nullKey) {
    PORT_SetError(SEC_ERROR_BAD_KEY);
    return SECFailure;
  }
  CK_MECHANISM_TYPE wrapMech;
  ScopedSECItem iv;
  std::vector<uint8_t> wrapped;
  ScopedPK11SymKey kek(
      EncryptForUnwrap(slot, derPKI, &wrapMech, &iv, &wrapped, wincx));
  if (!kek) {
    return SECFailure;
  }
  SECItem wrappedItem = {siBuffer, wrapped.data(),
                         static_cast<unsigned int>(wrapped.size())};
  // A FIPS token only holds sensitive private keys.
  SECKEYPrivateKey* key = PK11_UnwrapPrivKeyByKeyType(
      slot, kek.get(), wrapMech, iv.get(), &wrappedItem, nickname, publicValue,
      isPerm, PR_TRUE, keyType, keyUsage, wincx);
  if (!key) {
    return SECFailure;
  }
  // As with a plaintext import, a token key gets a token public key. Given a
  // public value, PK11_UnwrapPrivKey leaves that to the caller.
  if (isPerm && publicValue) {
    ScopedSECKEYPublicKey pub(SECKEY_ConvertToPublicKey(key));
    if (pub) {
      (void)PK11_ImportPublicKey(slot, pub.get(), PR_TRUE);
    }
  }
  if (privk) {
    *privk = key;
  } else {
    SECKEY_DestroyPrivateKey(key);
  }
  return SECSuccess;
}

// Decrypts |wrapped| under |kek|, the inverse of EncryptForUnwrap.
SECItem* DecryptWrapped(PK11SymKey* kek, CK_MECHANISM_TYPE wrapMech,
                        SECItem* iv, const SECItem* wrapped) {
  ScopedSECItem out(SECITEM_AllocItem(nullptr, nullptr, wrapped->len));
  if (!out) {
    return nullptr;
  }
  unsigned int outLen = 0;
  if (PK11_Decrypt(kek, wrapMech, iv, out->data, &outLen, out->len,
                   wrapped->data, wrapped->len) != SECSuccess) {
    return nullptr;
  }
  out->len = outLen;
  return out.release();
}

// Values recovered by ExtractKeyValue, keyed by the key they came from.
std::map<PK11SymKey*, ScopedSECItem> extractedKeys;

PK11SymKey* MakeExportKey(PK11SlotInfo* slot, void* wincx) {
  return PK11_TokenKeyGenWithFlags(slot, CKM_AES_KEY_GEN, nullptr, 32, nullptr,
                                   CKF_WRAP | CKF_DECRYPT, 0, wincx);
}

}  // namespace

bool SlotRequiresWrappedImport(PK11SlotInfo* slot) {
  return PK11_IsFIPS() && PK11_IsInternal(slot);
}

PK11SymKey* ImportSymKey(PK11SlotInfo* slot, CK_MECHANISM_TYPE type,
                         PK11Origin origin, CK_ATTRIBUTE_TYPE operation,
                         SECItem* key, void* wincx) {
  return ImportSymKeyWithFlags(slot, type, origin, operation, key, 0, PR_FALSE,
                               wincx);
}

PK11SymKey* ImportSymKeyWithFlags(PK11SlotInfo* slot, CK_MECHANISM_TYPE type,
                                  PK11Origin origin,
                                  CK_ATTRIBUTE_TYPE operation, SECItem* key,
                                  CK_FLAGS flags, PRBool isPerm, void* wincx) {
  if (!SlotRequiresWrappedImport(slot)) {
    if (!flags && !isPerm) {
      return PK11_ImportSymKey(slot, type, origin, operation, key, wincx);
    }
    return PK11_ImportSymKeyWithFlags(slot, type, origin, operation, key, flags,
                                      isPerm, wincx);
  }
  CK_MECHANISM_TYPE wrapMech;
  ScopedSECItem iv;
  std::vector<uint8_t> wrapped;
  ScopedPK11SymKey kek(
      EncryptForUnwrap(slot, key, &wrapMech, &iv, &wrapped, wincx));
  if (!kek) {
    return nullptr;
  }
  SECItem wrappedItem = {siBuffer, wrapped.data(),
                         static_cast<unsigned int>(wrapped.size())};
  // Unwrapping to a mechanism the slot lacks sends pk11wrap looking for
  // another slot, which a FIPS configuration doesn't have.
  CK_MECHANISM_TYPE target =
      PK11_DoesMechanism(slot, type) ? type : CKM_GENERIC_SECRET_KEY_GEN;
  return PK11_UnwrapSymKeyWithFlagsPerm(
      kek.get(), wrapMech, iv.get(), &wrappedItem, target, operation,
      static_cast<int>(key->len), flags, isPerm);
}

SECStatus ImportPrivateKeyInfoAndReturnKey(
    PK11SlotInfo* slot, SECKEYPrivateKeyInfo* pki, SECItem* nickname,
    const SECItem* publicValue, PRBool isPerm, PRBool isPrivate,
    unsigned int keyUsage, SECKEYPrivateKey** privk, void* wincx) {
  if (!SlotRequiresWrappedImport(slot)) {
    return PK11_ImportPrivateKeyInfoAndReturnKey(slot, pki, nickname,
                                                 publicValue, isPerm, isPrivate,
                                                 keyUsage, privk, wincx);
  }
  ScopedSECItem der(SEC_ASN1EncodeItem(
      nullptr, nullptr, pki, SEC_ASN1_GET(SECKEY_PrivateKeyInfoTemplate)));
  if (!der) {
    return SECFailure;
  }
  return UnwrapPrivateKey(
      slot, der.get(),
      KeyTypeFromAlgorithm(SECOID_GetAlgorithmTag(&pki->algorithm)), nickname,
      publicValue, isPerm, keyUsage, privk, wincx);
}

SECStatus ImportDERPrivateKeyInfoAndReturnKey(
    PK11SlotInfo* slot, SECItem* derPKI, SECItem* nickname,
    const SECItem* publicValue, PRBool isPerm, PRBool isPrivate,
    unsigned int keyUsage, SECKEYPrivateKey** privk, void* wincx) {
  if (!SlotRequiresWrappedImport(slot)) {
    return PK11_ImportDERPrivateKeyInfoAndReturnKey(
        slot, derPKI, nickname, publicValue, isPerm, isPrivate, keyUsage, privk,
        wincx);
  }
  ScopedPLArenaPool arena(PORT_NewArena(DER_DEFAULT_CHUNKSIZE));
  if (!arena) {
    return SECFailure;
  }
  PrivateKeyInfoV2Str pki = {};
  if (SEC_QuickDERDecodeItem(arena.get(), &pki, kPrivateKeyInfoV2Template,
                             derPKI) != SECSuccess) {
    return SECFailure;
  }
  KeyType keyType =
      KeyTypeFromAlgorithm(SECOID_GetAlgorithmTag(&pki.algorithm));
  SECItem embedded = {siBuffer, nullptr, 0};
  if (!publicValue) {
    embedded = EmbeddedPublicKey(arena.get(), pki, keyType);
    if (embedded.len) {
      publicValue = &embedded;
    }
  }
  return UnwrapPrivateKey(slot, derPKI, keyType, nickname, publicValue, isPerm,
                          keyUsage, privk, wincx);
}

SECStatus ExtractKeyValue(PK11SymKey* key) {
  extractedKeys.erase(key);
  ScopedPK11SlotInfo slot(PK11_GetSlotFromKey(key));
  if (!slot || !SlotRequiresWrappedImport(slot.get())) {
    return PK11_ExtractKeyValue(key);
  }
  // Data objects and non-sensitive keys can still be read directly.
  if (PK11_ExtractKeyValue(key) == SECSuccess) {
    return SECSuccess;
  }
  ScopedPK11SymKey kek(MakeExportKey(slot.get(), nullptr));
  if (!kek) {
    return SECFailure;
  }
  const CK_MECHANISM_TYPE wrapMech = kWrapMech;
  ScopedSECItem iv(PK11_GenerateNewParam(wrapMech, nullptr));
  if (!iv) {
    return SECFailure;
  }
  // PK11_GetKeyLength can report 0, e.g. for derived keys.
  std::vector<uint8_t> buf(std::max<size_t>(PK11_GetKeyLength(key), 8192) + 16);
  SECItem wrapped = {siBuffer, buf.data(),
                     static_cast<unsigned int>(buf.size())};
  if (PK11_WrapSymKey(wrapMech, iv.get(), kek.get(), key, &wrapped) !=
      SECSuccess) {
    return SECFailure;
  }
  ScopedSECItem value(DecryptWrapped(kek.get(), wrapMech, iv.get(), &wrapped));
  if (!value) {
    return SECFailure;
  }
  extractedKeys[key] = std::move(value);
  return SECSuccess;
}

SECItem* GetKeyData(PK11SymKey* key) {
  SECItem* data = PK11_GetKeyData(key);
  auto it = extractedKeys.find(key);
  if ((!data || !data->len) && it != extractedKeys.end()) {
    return it->second.get();
  }
  return data;
}

SECItem* ExportDERPrivateKeyInfo(SECKEYPrivateKey* key, void* wincx) {
  if (!key) {
    PORT_SetError(SEC_ERROR_INVALID_ARGS);
    return nullptr;
  }
  if (!SlotRequiresWrappedImport(key->pkcs11Slot)) {
    return PK11_ExportDERPrivateKeyInfo(key, wincx);
  }
  ScopedPK11SymKey kek(MakeExportKey(key->pkcs11Slot, wincx));
  if (!kek) {
    return nullptr;
  }
  const CK_MECHANISM_TYPE wrapMech = kWrapMech;
  ScopedSECItem iv(PK11_GenerateNewParam(wrapMech, nullptr));
  if (!iv) {
    return nullptr;
  }
  // 16KB exceeds every supported private key (ML-DSA, ML-KEM, SLH-DSA, EC,
  // RSA).
  ScopedSECItem wrapped(SECITEM_AllocItem(nullptr, nullptr, 16384));
  if (!wrapped ||
      PK11_WrapPrivKey(key->pkcs11Slot, kek.get(), key, wrapMech, iv.get(),
                       wrapped.get(), wincx) != SECSuccess) {
    return nullptr;
  }
  return DecryptWrapped(kek.get(), wrapMech, iv.get(), wrapped.get());
}

SECKEYPrivateKeyInfo* ExportPrivKeyInfo(SECKEYPrivateKey* key, void* wincx) {
  if (!key) {
    PORT_SetError(SEC_ERROR_INVALID_ARGS);
    return nullptr;
  }
  if (!SlotRequiresWrappedImport(key->pkcs11Slot)) {
    return PK11_ExportPrivKeyInfo(key, wincx);
  }
  ScopedSECItem der(ExportDERPrivateKeyInfo(key, wincx));
  if (!der) {
    return nullptr;
  }
  PLArenaPool* arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
  if (!arena) {
    return nullptr;
  }
  SECKEYPrivateKeyInfo* pki = PORT_ArenaZNew(arena, SECKEYPrivateKeyInfo);
  if (!pki || SEC_ASN1DecodeItem(arena, pki,
                                 SEC_ASN1_GET(SECKEY_PrivateKeyInfoTemplate),
                                 der.get()) != SECSuccess) {
    PORT_FreeArena(arena, PR_TRUE);
    return nullptr;
  }
  pki->arena = arena;
  return pki;
}

}  // namespace nss_test
