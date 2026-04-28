/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <cstring>

#include "gtest/gtest.h"
#include "scoped_ptrs_util.h"
#include "secitem.h"
#include "secport.h"

namespace nss_test {

// ---------------------------------------------------------------------------
// SECITEM_AllocItem / SECITEM_MakeItem
// ---------------------------------------------------------------------------

class SecItemAllocTest : public ::testing::Test {};

// AllocItem with NULL item: allocates the SECItem struct and its data buffer.
TEST_F(SecItemAllocTest, AllocItemHeapNullItem) {
  ScopedSECItem item(SECITEM_AllocItem(nullptr, nullptr, 10));
  ASSERT_TRUE(item);
  EXPECT_EQ(10U, item->len);
  EXPECT_TRUE(item->data);
}

// AllocItem with an existing item: allocates only the data buffer.
TEST_F(SecItemAllocTest, AllocItemHeapExistingItem) {
  SECItem item = {siBuffer, nullptr, 0};
  SECItem *result = SECITEM_AllocItem(nullptr, &item, 8);
  ASSERT_EQ(&item, result);
  EXPECT_EQ(8U, item.len);
  EXPECT_TRUE(item.data);
  SECITEM_FreeItem(&item, PR_FALSE);
}

// len=0: data buffer is not allocated; data is NULL and len is 0.
TEST_F(SecItemAllocTest, AllocItemZeroLen) {
  ScopedSECItem item(SECITEM_AllocItem(nullptr, nullptr, 0));
  ASSERT_TRUE(item);
  EXPECT_EQ(0U, item->len);
  EXPECT_FALSE(item->data);
}

// Arena alloc with NULL item: struct and data come from the arena.
TEST_F(SecItemAllocTest, AllocItemArenaNullItem) {
  ScopedPLArenaPool arena(PORT_NewArena(4096));
  ASSERT_TRUE(arena);
  SECItem *item = SECITEM_AllocItem(arena.get(), nullptr, 12);
  ASSERT_TRUE(item);
  EXPECT_EQ(12U, item->len);
  EXPECT_TRUE(item->data);
  // item and item->data live in the arena; freed when the arena is freed.
}

// Arena alloc with existing item: only data comes from the arena.
TEST_F(SecItemAllocTest, AllocItemArenaExistingItem) {
  ScopedPLArenaPool arena(PORT_NewArena(4096));
  ASSERT_TRUE(arena);
  SECItem item = {siBuffer, nullptr, 0};
  SECItem *result = SECITEM_AllocItem(arena.get(), &item, 7);
  ASSERT_EQ(&item, result);
  EXPECT_EQ(7U, item.len);
  EXPECT_TRUE(item.data);
}

// MakeItem: copies data, result type is always siBuffer.
TEST_F(SecItemAllocTest, MakeItemHeap) {
  const uint8_t data[] = {0x01, 0x02, 0x03};
  StackSECItem dest;
  ASSERT_EQ(SECSuccess, SECITEM_MakeItem(nullptr, &dest, data, sizeof(data)));
  EXPECT_EQ(siBuffer, dest.type);
  ASSERT_EQ(3U, dest.len);
  EXPECT_EQ(0, memcmp(dest.data, data, sizeof(data)));
}

TEST_F(SecItemAllocTest, MakeItemArena) {
  ScopedPLArenaPool arena(PORT_NewArena(4096));
  ASSERT_TRUE(arena);
  const uint8_t data[] = {0xDE, 0xAD};
  SECItem dest = {siBuffer, nullptr, 0};
  ASSERT_EQ(SECSuccess,
            SECITEM_MakeItem(arena.get(), &dest, data, sizeof(data)));
  EXPECT_EQ(siBuffer, dest.type);
  EXPECT_EQ(2U, dest.len);
  EXPECT_EQ(0, memcmp(dest.data, data, sizeof(data)));
}

// MakeItem with zero length: succeeds, data is NULL, len is 0.
TEST_F(SecItemAllocTest, MakeItemZeroLen) {
  StackSECItem dest;
  ASSERT_EQ(SECSuccess, SECITEM_MakeItem(nullptr, &dest, nullptr, 0));
  EXPECT_EQ(0U, dest.len);
  EXPECT_FALSE(dest.data);
}

// ---------------------------------------------------------------------------
// SECITEM_ReallocItemV2
// ---------------------------------------------------------------------------

class SecItemReallocTest : public ::testing::Test {};

// Grow an item that starts with no allocation.
TEST_F(SecItemReallocTest, ReallocV2GrowHeap) {
  StackSECItem item;
  ASSERT_EQ(SECSuccess, SECITEM_ReallocItemV2(nullptr, &item, 4));
  EXPECT_EQ(4U, item.len);
  EXPECT_TRUE(item.data);
  ASSERT_EQ(SECSuccess, SECITEM_ReallocItemV2(nullptr, &item, 16));
  EXPECT_EQ(16U, item.len);
  EXPECT_TRUE(item.data);
}

TEST_F(SecItemReallocTest, ReallocV2ShrinkHeap) {
  StackSECItem item;
  ASSERT_EQ(SECSuccess, SECITEM_ReallocItemV2(nullptr, &item, 16));
  ASSERT_EQ(SECSuccess, SECITEM_ReallocItemV2(nullptr, &item, 4));
  EXPECT_EQ(4U, item.len);
  EXPECT_TRUE(item.data);
}

// Shrink in an arena: reuses the existing block, just decrements len.
TEST_F(SecItemReallocTest, ReallocV2ShrinkArena) {
  ScopedPLArenaPool arena(PORT_NewArena(4096));
  ASSERT_TRUE(arena);
  SECItem item = {siBuffer, nullptr, 0};
  ASSERT_EQ(SECSuccess, SECITEM_ReallocItemV2(arena.get(), &item, 16));
  unsigned char *orig_ptr = item.data;
  ASSERT_EQ(SECSuccess, SECITEM_ReallocItemV2(arena.get(), &item, 4));
  EXPECT_EQ(4U, item.len);
  EXPECT_EQ(orig_ptr, item.data);  // still the same block
}

TEST_F(SecItemReallocTest, ReallocV2GrowArena) {
  ScopedPLArenaPool arena(PORT_NewArena(4096));
  ASSERT_TRUE(arena);
  SECItem item = {siBuffer, nullptr, 0};
  ASSERT_EQ(SECSuccess, SECITEM_ReallocItemV2(arena.get(), &item, 8));
  ASSERT_EQ(SECSuccess, SECITEM_ReallocItemV2(arena.get(), &item, 24));
  EXPECT_EQ(24U, item.len);
  EXPECT_TRUE(item.data);
}

// item->data == NULL: treated as a fresh allocation.
TEST_F(SecItemReallocTest, ReallocV2FromNull) {
  StackSECItem item;
  ASSERT_EQ(SECSuccess, SECITEM_ReallocItemV2(nullptr, &item, 8));
  EXPECT_EQ(8U, item.len);
  EXPECT_TRUE(item.data);
}

// newlen == 0: frees data and zeroes the item fields.
TEST_F(SecItemReallocTest, ReallocV2ToZero) {
  StackSECItem item;
  ASSERT_EQ(SECSuccess, SECITEM_ReallocItemV2(nullptr, &item, 8));
  ASSERT_EQ(SECSuccess, SECITEM_ReallocItemV2(nullptr, &item, 0));
  EXPECT_EQ(0U, item.len);
  EXPECT_FALSE(item.data);
  // StackSECItem dtor will call SECITEM_FreeItem with data==nullptr — safe.
}

// newlen == current len: no-op, pointer is unchanged.
TEST_F(SecItemReallocTest, ReallocV2SameSizeNoOp) {
  StackSECItem item;
  ASSERT_EQ(SECSuccess, SECITEM_ReallocItemV2(nullptr, &item, 8));
  unsigned char *ptr = item.data;
  ASSERT_EQ(SECSuccess, SECITEM_ReallocItemV2(nullptr, &item, 8));
  EXPECT_EQ(8U, item.len);
  EXPECT_EQ(ptr, item.data);
}


// ---------------------------------------------------------------------------
// SECITEM_ReallocItem (deprecated)
// ---------------------------------------------------------------------------

class SecItemReallocLegacyTest : public ::testing::Test {};

// oldlen=0, newlen=0: degenerate no-op, returns SECSuccess.
TEST_F(SecItemReallocLegacyTest, ReallocLegacyOldlenZeroNewlenZero) {
  SECItem item = {siBuffer, nullptr, 0};
  EXPECT_EQ(SECSuccess, SECITEM_ReallocItem(nullptr, &item, 0, 0));
}

// oldlen=0: allocates fresh data buffer (note: legacy bug — len is updated here).
TEST_F(SecItemReallocLegacyTest, ReallocLegacyOldlenZeroNewlenNonzero) {
  SECItem item = {siBuffer, nullptr, 0};
  ASSERT_EQ(SECSuccess, SECITEM_ReallocItem(nullptr, &item, 0, 8));
  EXPECT_TRUE(item.data);
  SECITEM_FreeItem(&item, PR_FALSE);
}

// oldlen>0: reallocates existing data buffer on the heap.
TEST_F(SecItemReallocLegacyTest, ReallocLegacyGrowHeap) {
  SECItem item = {siBuffer, nullptr, 0};
  ASSERT_EQ(SECSuccess, SECITEM_ReallocItem(nullptr, &item, 0, 4));
  ASSERT_EQ(SECSuccess, SECITEM_ReallocItem(nullptr, &item, 4, 16));
  EXPECT_TRUE(item.data);
  // Note: legacy bug — item.len is still 4, not 16.
  SECITEM_FreeItem(&item, PR_FALSE);
}

// oldlen=0, arena: allocates from arena.
TEST_F(SecItemReallocLegacyTest, ReallocLegacyArena) {
  ScopedPLArenaPool arena(PORT_NewArena(4096));
  ASSERT_TRUE(arena);
  SECItem item = {siBuffer, nullptr, 0};
  ASSERT_EQ(SECSuccess, SECITEM_ReallocItem(arena.get(), &item, 0, 8));
  EXPECT_TRUE(item.data);
}

// oldlen>0, arena: grows the existing arena block.
TEST_F(SecItemReallocLegacyTest, ReallocLegacyArenaGrow) {
  ScopedPLArenaPool arena(PORT_NewArena(4096));
  ASSERT_TRUE(arena);
  SECItem item = {siBuffer, nullptr, 0};
  ASSERT_EQ(SECSuccess, SECITEM_ReallocItem(arena.get(), &item, 0, 4));
  ASSERT_EQ(SECSuccess, SECITEM_ReallocItem(arena.get(), &item, 4, 16));
  EXPECT_TRUE(item.data);
}

// ---------------------------------------------------------------------------
// SECITEM_CompareItem / SECITEM_ItemsAreEqual
// ---------------------------------------------------------------------------

class SecItemCompareTest : public ::testing::Test {};

TEST_F(SecItemCompareTest, CompareEqualItems) {
  const uint8_t data[] = {1, 2, 3};
  SECItem a = {siBuffer, const_cast<uint8_t *>(data), sizeof(data)};
  SECItem b = {siBuffer, const_cast<uint8_t *>(data), sizeof(data)};
  EXPECT_EQ(SECEqual, SECITEM_CompareItem(&a, &b));
}

// Same pointer: short-circuits to SECEqual without touching data.
TEST_F(SecItemCompareTest, CompareSamePointer) {
  const uint8_t data[] = {1, 2, 3};
  SECItem a = {siBuffer, const_cast<uint8_t *>(data), sizeof(data)};
  EXPECT_EQ(SECEqual, SECITEM_CompareItem(&a, &a));
}

TEST_F(SecItemCompareTest, CompareBothEmpty) {
  SECItem a = {siBuffer, nullptr, 0};
  SECItem b = {siBuffer, nullptr, 0};
  EXPECT_EQ(SECEqual, SECITEM_CompareItem(&a, &b));
}

TEST_F(SecItemCompareTest, CompareNullItemA) {
  const uint8_t data[] = {1};
  SECItem b = {siBuffer, const_cast<uint8_t *>(data), sizeof(data)};
  EXPECT_EQ(SECLessThan, SECITEM_CompareItem(nullptr, &b));
}

TEST_F(SecItemCompareTest, CompareNullItemB) {
  const uint8_t data[] = {1};
  SECItem a = {siBuffer, const_cast<uint8_t *>(data), sizeof(data)};
  EXPECT_EQ(SECGreaterThan, SECITEM_CompareItem(&a, nullptr));
}

TEST_F(SecItemCompareTest, CompareLexLess) {
  const uint8_t d1[] = {1, 2, 3};
  const uint8_t d2[] = {1, 2, 4};
  SECItem a = {siBuffer, const_cast<uint8_t *>(d1), sizeof(d1)};
  SECItem b = {siBuffer, const_cast<uint8_t *>(d2), sizeof(d2)};
  EXPECT_EQ(SECLessThan, SECITEM_CompareItem(&a, &b));
}

TEST_F(SecItemCompareTest, CompareLexGreater) {
  const uint8_t d1[] = {1, 2, 4};
  const uint8_t d2[] = {1, 2, 3};
  SECItem a = {siBuffer, const_cast<uint8_t *>(d1), sizeof(d1)};
  SECItem b = {siBuffer, const_cast<uint8_t *>(d2), sizeof(d2)};
  EXPECT_EQ(SECGreaterThan, SECITEM_CompareItem(&a, &b));
}

// Same prefix, a is shorter: a < b.
TEST_F(SecItemCompareTest, CompareSamePrefixShorter) {
  const uint8_t d1[] = {1, 2};
  const uint8_t d2[] = {1, 2, 3};
  SECItem a = {siBuffer, const_cast<uint8_t *>(d1), sizeof(d1)};
  SECItem b = {siBuffer, const_cast<uint8_t *>(d2), sizeof(d2)};
  EXPECT_EQ(SECLessThan, SECITEM_CompareItem(&a, &b));
}

// Same prefix, a is longer: a > b.
TEST_F(SecItemCompareTest, CompareSamePrefixLonger) {
  const uint8_t d1[] = {1, 2, 3};
  const uint8_t d2[] = {1, 2};
  SECItem a = {siBuffer, const_cast<uint8_t *>(d1), sizeof(d1)};
  SECItem b = {siBuffer, const_cast<uint8_t *>(d2), sizeof(d2)};
  EXPECT_EQ(SECGreaterThan, SECITEM_CompareItem(&a, &b));
}

TEST_F(SecItemCompareTest, ItemsAreEqualTrue) {
  const uint8_t data[] = {0xAB, 0xCD};
  SECItem a = {siBuffer, const_cast<uint8_t *>(data), sizeof(data)};
  SECItem b = {siBuffer, const_cast<uint8_t *>(data), sizeof(data)};
  EXPECT_EQ(PR_TRUE, SECITEM_ItemsAreEqual(&a, &b));
}

TEST_F(SecItemCompareTest, ItemsAreEqualDifferentLen) {
  const uint8_t d1[] = {1, 2, 3};
  const uint8_t d2[] = {1, 2};
  SECItem a = {siBuffer, const_cast<uint8_t *>(d1), sizeof(d1)};
  SECItem b = {siBuffer, const_cast<uint8_t *>(d2), sizeof(d2)};
  EXPECT_EQ(PR_FALSE, SECITEM_ItemsAreEqual(&a, &b));
}

TEST_F(SecItemCompareTest, ItemsAreEqualSameLenDiffData) {
  const uint8_t d1[] = {1, 2, 3};
  const uint8_t d2[] = {1, 2, 4};
  SECItem a = {siBuffer, const_cast<uint8_t *>(d1), sizeof(d1)};
  SECItem b = {siBuffer, const_cast<uint8_t *>(d2), sizeof(d2)};
  EXPECT_EQ(PR_FALSE, SECITEM_ItemsAreEqual(&a, &b));
}

TEST_F(SecItemCompareTest, ItemsAreEqualBothZeroLen) {
  SECItem a = {siBuffer, nullptr, 0};
  SECItem b = {siBuffer, nullptr, 0};
  EXPECT_EQ(PR_TRUE, SECITEM_ItemsAreEqual(&a, &b));
}

// Both data pointers NULL with len==0: equal.
TEST_F(SecItemCompareTest, ItemsAreEqualBothNullData) {
  SECItem a = {siBuffer, nullptr, 0};
  SECItem b = {siBuffer, nullptr, 0};
  EXPECT_EQ(PR_TRUE, SECITEM_ItemsAreEqual(&a, &b));
}

// Same nonzero len but both data pointers NULL: equal (hits the null-data guard).
TEST_F(SecItemCompareTest, ItemsAreEqualBothNullDataNonzeroLen) {
  SECItem a = {siBuffer, nullptr, 3};
  SECItem b = {siBuffer, nullptr, 3};
  EXPECT_EQ(PR_TRUE, SECITEM_ItemsAreEqual(&a, &b));
}

// Same nonzero len, one data pointer NULL: not equal.
TEST_F(SecItemCompareTest, ItemsAreEqualOneNullDataNonzeroLen) {
  const uint8_t data[] = {1, 2, 3};
  SECItem a = {siBuffer, const_cast<uint8_t *>(data), 3};
  SECItem b = {siBuffer, nullptr, 3};
  EXPECT_EQ(PR_FALSE, SECITEM_ItemsAreEqual(&a, &b));
}

// ---------------------------------------------------------------------------
// SECITEM_CopyItem / SECITEM_DupItem / SECITEM_ArenaDupItem
// ---------------------------------------------------------------------------

class SecItemCopyTest : public ::testing::Test {};

// CopyItem: deep copy, original and copy are independent buffers.
TEST_F(SecItemCopyTest, CopyItemHeap) {
  const uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
  SECItem from = {siBuffer, const_cast<uint8_t *>(data), sizeof(data)};
  StackSECItem to;
  ASSERT_EQ(SECSuccess, SECITEM_CopyItem(nullptr, &to, &from));
  EXPECT_EQ(siBuffer, to.type);
  ASSERT_EQ(4U, to.len);
  EXPECT_EQ(0, memcmp(to.data, data, sizeof(data)));
  EXPECT_NE(from.data, to.data);
}

TEST_F(SecItemCopyTest, CopyItemArena) {
  ScopedPLArenaPool arena(PORT_NewArena(4096));
  ASSERT_TRUE(arena);
  const uint8_t data[] = {0x01, 0x02};
  SECItem from = {siBuffer, const_cast<uint8_t *>(data), sizeof(data)};
  SECItem to = {siBuffer, nullptr, 0};
  ASSERT_EQ(SECSuccess, SECITEM_CopyItem(arena.get(), &to, &from));
  EXPECT_EQ(2U, to.len);
  EXPECT_EQ(0, memcmp(to.data, data, sizeof(data)));
}

// Source has NULL data/zero len: dest gets data=NULL, len=0.
TEST_F(SecItemCopyTest, CopyItemZeroLen) {
  SECItem from = {siBuffer, nullptr, 0};
  StackSECItem to;
  ASSERT_EQ(SECSuccess, SECITEM_CopyItem(nullptr, &to, &from));
  EXPECT_EQ(0U, to.len);
  EXPECT_FALSE(to.data);
}

// data != NULL but len == 0: treated as empty, dest gets data=NULL, len=0.
TEST_F(SecItemCopyTest, CopyItemNonNullDataZeroLen) {
  const uint8_t data[] = {0x01};
  SECItem from = {siBuffer, const_cast<uint8_t *>(data), 0};
  StackSECItem to;
  ASSERT_EQ(SECSuccess, SECITEM_CopyItem(nullptr, &to, &from));
  EXPECT_EQ(0U, to.len);
  EXPECT_FALSE(to.data);
}

// data == NULL but len != 0: succeeds and zeroes dest (documented quirk).
TEST_F(SecItemCopyTest, CopyItemNullDataNonzeroLen) {
  SECItem from = {siBuffer, nullptr, 3};
  StackSECItem to;
  ASSERT_EQ(SECSuccess, SECITEM_CopyItem(nullptr, &to, &from));
  EXPECT_EQ(0U, to.len);
  EXPECT_FALSE(to.data);
}

// Non-siBuffer type is preserved in the copy.
TEST_F(SecItemCopyTest, CopyItemTypePreserved) {
  const uint8_t data[] = {0x30};
  SECItem from = {siDEROID, const_cast<uint8_t *>(data), sizeof(data)};
  StackSECItem to;
  ASSERT_EQ(SECSuccess, SECITEM_CopyItem(nullptr, &to, &from));
  EXPECT_EQ(siDEROID, to.type);
}

// Mutating the original after a copy must not affect the copy.
TEST_F(SecItemCopyTest, CopyItemIndependence) {
  uint8_t data[] = {0x01, 0x02, 0x03};
  SECItem from = {siBuffer, data, sizeof(data)};
  StackSECItem to;
  ASSERT_EQ(SECSuccess, SECITEM_CopyItem(nullptr, &to, &from));
  data[0] = 0xFF;
  EXPECT_EQ(0x01, to.data[0]);
}

TEST_F(SecItemCopyTest, DupItemBasic) {
  const uint8_t data[] = {0xCA, 0xFE};
  SECItem from = {siBuffer, const_cast<uint8_t *>(data), sizeof(data)};
  ScopedSECItem dup(SECITEM_DupItem(&from));
  ASSERT_TRUE(dup);
  EXPECT_EQ(siBuffer, dup->type);
  ASSERT_EQ(2U, dup->len);
  EXPECT_EQ(0, memcmp(dup->data, data, sizeof(data)));
  EXPECT_NE(from.data, dup->data);
}

// NULL input: must return NULL.
TEST_F(SecItemCopyTest, DupItemNullInput) {
  EXPECT_FALSE(SECITEM_DupItem(nullptr));
}

// Zero-length source: dup has NULL data and len==0.
TEST_F(SecItemCopyTest, DupItemZeroLen) {
  SECItem from = {siBuffer, nullptr, 0};
  ScopedSECItem dup(SECITEM_DupItem(&from));
  ASSERT_TRUE(dup);
  EXPECT_EQ(0U, dup->len);
  EXPECT_FALSE(dup->data);
}

TEST_F(SecItemCopyTest, DupItemTypePreserved) {
  const uint8_t data[] = {0x30};
  SECItem from = {siDEROID, const_cast<uint8_t *>(data), sizeof(data)};
  ScopedSECItem dup(SECITEM_DupItem(&from));
  ASSERT_TRUE(dup);
  EXPECT_EQ(siDEROID, dup->type);
}

TEST_F(SecItemCopyTest, DupItemIndependence) {
  uint8_t data[] = {0x01, 0x02};
  SECItem from = {siBuffer, data, sizeof(data)};
  ScopedSECItem dup(SECITEM_DupItem(&from));
  ASSERT_TRUE(dup);
  data[0] = 0xFF;
  EXPECT_EQ(0x01, dup->data[0]);
}

// ArenaDupItem: both the struct and the data buffer come from the arena.
TEST_F(SecItemCopyTest, ArenaDupItemWithArena) {
  ScopedPLArenaPool arena(PORT_NewArena(4096));
  ASSERT_TRUE(arena);
  const uint8_t data[] = {0x11, 0x22, 0x33};
  SECItem from = {siBuffer, const_cast<uint8_t *>(data), sizeof(data)};
  SECItem *dup = SECITEM_ArenaDupItem(arena.get(), &from);
  ASSERT_TRUE(dup);
  EXPECT_EQ(3U, dup->len);
  EXPECT_EQ(0, memcmp(dup->data, data, sizeof(data)));
  // dup and dup->data are arena-owned; freed when the arena is freed.
}

// NULL arena: equivalent to DupItem.
TEST_F(SecItemCopyTest, ArenaDupItemNullArena) {
  const uint8_t data[] = {0xAB};
  SECItem from = {siBuffer, const_cast<uint8_t *>(data), sizeof(data)};
  ScopedSECItem dup(SECITEM_ArenaDupItem(nullptr, &from));
  ASSERT_TRUE(dup);
  EXPECT_EQ(1U, dup->len);
  EXPECT_EQ(0xAB, dup->data[0]);
}

// NULL input: must return NULL regardless of arena.
TEST_F(SecItemCopyTest, ArenaDupItemNullInput) {
  ScopedPLArenaPool arena(PORT_NewArena(4096));
  ASSERT_TRUE(arena);
  EXPECT_FALSE(SECITEM_ArenaDupItem(arena.get(), nullptr));
}

// ---------------------------------------------------------------------------
// SECITEM_FreeItem / SECITEM_ZfreeItem
// ---------------------------------------------------------------------------

class SecItemFreeTest : public ::testing::Test {};

// freeit=PR_TRUE: frees both the data buffer and the struct itself.
TEST_F(SecItemFreeTest, FreeItemFreeit) {
  SECItem *item = SECITEM_AllocItem(nullptr, nullptr, 8);
  ASSERT_TRUE(item);
  SECITEM_FreeItem(item, PR_TRUE);
  // item is now invalid; we just verify no crash occurred.
}

// freeit=PR_FALSE: frees only the data buffer; struct fields are zeroed.
TEST_F(SecItemFreeTest, FreeItemNoFreeit) {
  SECItem item = {siBuffer, nullptr, 0};
  ASSERT_TRUE(SECITEM_AllocItem(nullptr, &item, 8));
  SECITEM_FreeItem(&item, PR_FALSE);
  EXPECT_FALSE(item.data);
  EXPECT_EQ(0U, item.len);
}

// NULL item pointer: must not crash.
TEST_F(SecItemFreeTest, FreeItemNull) {
  SECITEM_FreeItem(nullptr, PR_FALSE);
  SECITEM_FreeItem(nullptr, PR_TRUE);
}

// ZfreeItem: zeroes then frees the data buffer; freeit=PR_TRUE frees the struct.
TEST_F(SecItemFreeTest, ZfreeItemFreeit) {
  SECItem *item = SECITEM_AllocItem(nullptr, nullptr, 8);
  ASSERT_TRUE(item);
  memset(item->data, 0xAA, item->len);
  SECITEM_ZfreeItem(item, PR_TRUE);
}

// ZfreeItem freeit=PR_FALSE: data zeroed and freed; struct fields cleared.
TEST_F(SecItemFreeTest, ZfreeItemNoFreeit) {
  SECItem item = {siBuffer, nullptr, 0};
  ASSERT_TRUE(SECITEM_AllocItem(nullptr, &item, 8));
  memset(item.data, 0xBB, item.len);
  SECITEM_ZfreeItem(&item, PR_FALSE);
  EXPECT_FALSE(item.data);
  EXPECT_EQ(0U, item.len);
}

// NULL item pointer: must not crash.
TEST_F(SecItemFreeTest, ZfreeItemNull) {
  SECITEM_ZfreeItem(nullptr, PR_FALSE);
  SECITEM_ZfreeItem(nullptr, PR_TRUE);
}

// ---------------------------------------------------------------------------
// SECITEM_Hash / SECITEM_HashCompare
// ---------------------------------------------------------------------------

class SecItemHashTest : public ::testing::Test {};

// Same item hashed twice produces the same result.
TEST_F(SecItemHashTest, HashConsistent) {
  const uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
  SECItem item = {siBuffer, const_cast<uint8_t *>(data), sizeof(data)};
  EXPECT_EQ(SECITEM_Hash(&item), SECITEM_Hash(&item));
}

// Two distinct items produce different hash values.
TEST_F(SecItemHashTest, HashDifferentItems) {
  const uint8_t d1[] = {0x01, 0x02, 0x03, 0x04};
  const uint8_t d2[] = {0x05, 0x06, 0x07, 0x08};
  SECItem a = {siBuffer, const_cast<uint8_t *>(d1), sizeof(d1)};
  SECItem b = {siBuffer, const_cast<uint8_t *>(d2), sizeof(d2)};
  EXPECT_NE(SECITEM_Hash(&a), SECITEM_Hash(&b));
}

// Empty item: hash is 0 (XOR of nothing).
TEST_F(SecItemHashTest, HashEmpty) {
  SECItem item = {siBuffer, nullptr, 0};
  EXPECT_EQ(0U, SECITEM_Hash(&item));
}

// HashCompare delegates to ItemsAreEqual: returns non-zero for equal items.
TEST_F(SecItemHashTest, HashCompareEqualItems) {
  const uint8_t data[] = {0xAB, 0xCD};
  SECItem a = {siBuffer, const_cast<uint8_t *>(data), sizeof(data)};
  SECItem b = {siBuffer, const_cast<uint8_t *>(data), sizeof(data)};
  EXPECT_NE(0, SECITEM_HashCompare(&a, &b));
}

// HashCompare: returns 0 for unequal items.
TEST_F(SecItemHashTest, HashCompareUnequalItems) {
  const uint8_t d1[] = {0x01};
  const uint8_t d2[] = {0x02};
  SECItem a = {siBuffer, const_cast<uint8_t *>(d1), sizeof(d1)};
  SECItem b = {siBuffer, const_cast<uint8_t *>(d2), sizeof(d2)};
  EXPECT_EQ(0, SECITEM_HashCompare(&a, &b));
}

// ---------------------------------------------------------------------------
// SECITEM_AllocArray / SECITEM_DupArray / SECITEM_FreeArray / SECITEM_ZfreeArray
// ---------------------------------------------------------------------------

class SecItemArrayTest : public ::testing::Test {};

// AllocArray with NULL array: allocates the struct and a zero-filled items array.
TEST_F(SecItemArrayTest, AllocArrayHeapNullArray) {
  SECItemArray *arr = SECITEM_AllocArray(nullptr, nullptr, 3);
  ASSERT_TRUE(arr);
  EXPECT_EQ(3U, arr->len);
  ASSERT_TRUE(arr->items);
  for (unsigned int i = 0; i < arr->len; ++i) {
    EXPECT_FALSE(arr->items[i].data);
    EXPECT_EQ(0U, arr->items[i].len);
  }
  SECITEM_FreeArray(arr, PR_TRUE);
}

// AllocArray with existing array: allocates only the items buffer.
TEST_F(SecItemArrayTest, AllocArrayHeapExistingArray) {
  SECItemArray arr = {nullptr, 0};
  SECItemArray *result = SECITEM_AllocArray(nullptr, &arr, 2);
  ASSERT_EQ(&arr, result);
  EXPECT_EQ(2U, arr.len);
  ASSERT_TRUE(arr.items);
  SECITEM_FreeArray(&arr, PR_FALSE);
}

// len=0: items pointer is NULL.
TEST_F(SecItemArrayTest, AllocArrayZeroLen) {
  SECItemArray *arr = SECITEM_AllocArray(nullptr, nullptr, 0);
  ASSERT_TRUE(arr);
  EXPECT_EQ(0U, arr->len);
  EXPECT_FALSE(arr->items);
  SECITEM_FreeArray(arr, PR_TRUE);
}

TEST_F(SecItemArrayTest, AllocArrayArena) {
  ScopedPLArenaPool arena(PORT_NewArena(4096));
  ASSERT_TRUE(arena);
  SECItemArray *arr = SECITEM_AllocArray(arena.get(), nullptr, 4);
  ASSERT_TRUE(arr);
  EXPECT_EQ(4U, arr->len);
  EXPECT_TRUE(arr->items);
  // arr lives in the arena.
}

// DupArray: all items are deep-copied into freshly allocated buffers.
TEST_F(SecItemArrayTest, DupArrayBasic) {
  const uint8_t d0[] = {0x01, 0x02};
  const uint8_t d1[] = {0x03, 0x04, 0x05};
  SECItem items[2] = {
      {siBuffer, const_cast<uint8_t *>(d0), sizeof(d0)},
      {siBuffer, const_cast<uint8_t *>(d1), sizeof(d1)},
  };
  SECItemArray from = {items, 2};
  SECItemArray *dup = SECITEM_DupArray(nullptr, &from);
  ASSERT_TRUE(dup);
  ASSERT_EQ(2U, dup->len);
  EXPECT_EQ(sizeof(d0), dup->items[0].len);
  EXPECT_EQ(0, memcmp(dup->items[0].data, d0, sizeof(d0)));
  EXPECT_EQ(sizeof(d1), dup->items[1].len);
  EXPECT_EQ(0, memcmp(dup->items[1].data, d1, sizeof(d1)));
  EXPECT_NE(items[0].data, dup->items[0].data);
  SECITEM_FreeArray(dup, PR_TRUE);
}

// NULL from: must return NULL.
TEST_F(SecItemArrayTest, DupArrayNullFrom) {
  EXPECT_FALSE(SECITEM_DupArray(nullptr, nullptr));
}

// Zero-length from: valid — returns an empty array.
TEST_F(SecItemArrayTest, DupArrayEmptyFrom) {
  SECItemArray from = {nullptr, 0};
  SECItemArray *dup = SECITEM_DupArray(nullptr, &from);
  ASSERT_TRUE(dup);
  EXPECT_EQ(0U, dup->len);
  SECITEM_FreeArray(dup, PR_TRUE);
}

// DupArray with arena: struct and all item data come from the arena.
TEST_F(SecItemArrayTest, DupArrayArena) {
  ScopedPLArenaPool arena(PORT_NewArena(4096));
  ASSERT_TRUE(arena);
  const uint8_t d0[] = {0x01, 0x02};
  const uint8_t d1[] = {0x03};
  SECItem items[2] = {
      {siBuffer, const_cast<uint8_t *>(d0), sizeof(d0)},
      {siBuffer, const_cast<uint8_t *>(d1), sizeof(d1)},
  };
  SECItemArray from = {items, 2};
  SECItemArray *dup = SECITEM_DupArray(arena.get(), &from);
  ASSERT_TRUE(dup);
  ASSERT_EQ(2U, dup->len);
  EXPECT_EQ(0, memcmp(dup->items[0].data, d0, sizeof(d0)));
  EXPECT_EQ(0, memcmp(dup->items[1].data, d1, sizeof(d1)));
  // dup, dup->items, and all item data are arena-owned.
}

// Inconsistent from (NULL items but nonzero len): must return NULL.
TEST_F(SecItemArrayTest, DupArrayInconsistent) {
  SECItemArray from = {nullptr, 2};
  EXPECT_FALSE(SECITEM_DupArray(nullptr, &from));
}

// Mutating original after dup must not affect the dup.
TEST_F(SecItemArrayTest, DupArrayIndependence) {
  uint8_t data[] = {0xAA, 0xBB};
  SECItem items[1] = {{siBuffer, data, sizeof(data)}};
  SECItemArray from = {items, 1};
  SECItemArray *dup = SECITEM_DupArray(nullptr, &from);
  ASSERT_TRUE(dup);
  data[0] = 0xFF;
  EXPECT_EQ(0xAA, dup->items[0].data[0]);
  SECITEM_FreeArray(dup, PR_TRUE);
}

// freeit=PR_TRUE: frees the struct as well as all item data.
TEST_F(SecItemArrayTest, FreeArrayFreeit) {
  SECItemArray *arr = SECITEM_AllocArray(nullptr, nullptr, 2);
  ASSERT_TRUE(arr);
  SECITEM_FreeArray(arr, PR_TRUE);
}

// freeit=PR_FALSE: frees item data buffers; struct fields are cleared.
TEST_F(SecItemArrayTest, FreeArrayNoFreeit) {
  SECItemArray arr = {nullptr, 0};
  ASSERT_TRUE(SECITEM_AllocArray(nullptr, &arr, 2));
  SECITEM_FreeArray(&arr, PR_FALSE);
  EXPECT_FALSE(arr.items);
  EXPECT_EQ(0U, arr.len);
}

// NULL array: must not crash.
TEST_F(SecItemArrayTest, FreeArrayNull) {
  SECITEM_FreeArray(nullptr, PR_FALSE);
  SECITEM_FreeArray(nullptr, PR_TRUE);
}

// ZfreeArray: zeroes each item's data before freeing.
TEST_F(SecItemArrayTest, ZfreeArrayFreeit) {
  SECItemArray *arr = SECITEM_AllocArray(nullptr, nullptr, 2);
  ASSERT_TRUE(arr);
  arr->items[0].data = static_cast<uint8_t *>(PORT_Alloc(4));
  ASSERT_TRUE(arr->items[0].data);
  memset(arr->items[0].data, 0xCC, 4);
  arr->items[0].len = 4;
  SECITEM_ZfreeArray(arr, PR_TRUE);
}

// NULL array: must not crash.
TEST_F(SecItemArrayTest, ZfreeArrayNull) {
  SECITEM_ZfreeArray(nullptr, PR_FALSE);
  SECITEM_ZfreeArray(nullptr, PR_TRUE);
}

}  // namespace nss_test
