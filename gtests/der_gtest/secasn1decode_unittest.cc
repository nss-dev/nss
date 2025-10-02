/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "gtest/gtest.h"
#include "scoped_ptrs_util.h"

#include "nss.h"
#include "prerror.h"
#include "secasn1.h"
#include "secasn1t.h"
#include "secerr.h"
#include "secport.h"

class SECASN1DecodeTest : public ::testing::Test {};

struct Item {
  SECItem value;
};

const SEC_ASN1Template ItemTemplate[] = {
    {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(struct Item)}, {0}};

static const SEC_ASN1Template ItemsTemplate[] = {
    {SEC_ASN1_SEQUENCE_OF, 0, ItemTemplate}, {0}};

struct Container {
  struct Item** items;
};

const SEC_ASN1Template ContainerTemplate[] = {
    {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(struct Container)},
    {SEC_ASN1_CONSTRUCTED | SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_EXPLICIT | 0,
     offsetof(struct Container, items), ItemsTemplate},
    {0}};

// clang-format off
const unsigned char kEndOfContentsInDefiniteLengthContext[] = {
    0x30, 0x06,
      0xa0, 0x04,
        0x30, 0x00,
        0x00, 0x00, // EOC in definite length context
};
// clang-format on

TEST_F(SECASN1DecodeTest, EndOfContentsInDefiniteLengthContext) {
  ScopedPLArenaPool pool(PORT_NewArena(1024));
  struct Container* decoded = reinterpret_cast<struct Container*>(
      PORT_ArenaZAlloc(pool.get(), sizeof(struct Container)));
  SEC_ASN1DecoderContext* ctx =
      SEC_ASN1DecoderStart(pool.get(), decoded, ContainerTemplate);
  ASSERT_TRUE(ctx);
  ASSERT_EQ(
      SEC_ASN1DecoderUpdate(
          ctx,
          reinterpret_cast<const char*>(kEndOfContentsInDefiniteLengthContext),
          sizeof(kEndOfContentsInDefiniteLengthContext)),
      SECFailure);
  ASSERT_EQ(PR_GetError(), SEC_ERROR_BAD_DER);
  ASSERT_EQ(SECSuccess, SEC_ASN1DecoderFinish(ctx));
}

// clang-format off
const unsigned char kContentsTooShort[] = {
    0x30, 0x06,
      0xa0, 0x04,
        0x30, 0x00, // There should be two more bytes after this
};
// clang-format on

TEST_F(SECASN1DecodeTest, ContentsTooShort) {
  ScopedPLArenaPool pool(PORT_NewArena(1024));
  struct Container* decoded = reinterpret_cast<struct Container*>(
      PORT_ArenaZAlloc(pool.get(), sizeof(struct Container)));
  SEC_ASN1DecoderContext* ctx =
      SEC_ASN1DecoderStart(pool.get(), decoded, ContainerTemplate);
  ASSERT_TRUE(ctx);
  ASSERT_EQ(SEC_ASN1DecoderUpdate(
                ctx, reinterpret_cast<const char*>(kContentsTooShort),
                sizeof(kContentsTooShort)),
            SECFailure);
  ASSERT_EQ(PR_GetError(), SEC_ERROR_BAD_DER);
  ASSERT_EQ(SECSuccess, SEC_ASN1DecoderFinish(ctx));
}
