/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "secasn1.h"

#include "gtest/gtest.h"

namespace nss_test {

class SECASN1DTest : public ::testing::Test {
 protected:
  void SetUp() override { arena_ = PORT_NewArena(4096); }
  void TearDown() override { PORT_FreeArena(arena_, PR_FALSE); }

  template <typename T>
  SECStatus Decode(const SEC_ASN1Template* tmpl, T* dest,
                   const unsigned char* ber, size_t len) {
    SECItem item = {siBuffer, const_cast<unsigned char*>(ber),
                    static_cast<unsigned int>(len)};
    return SEC_ASN1DecodeItem(arena_, reinterpret_cast<void*>(dest), tmpl,
                              &item);
  }

  PLArenaPool* arena_;
};

struct InnerSequenceItem {
  SECItem value;
};

struct OuterSequence {
  InnerSequenceItem* item;
};

static const SEC_ASN1Template InnerSequenceTemplate[] = {
    {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(InnerSequenceItem)},
    {SEC_ASN1_ANY, offsetof(InnerSequenceItem, value)},
    {0}};

static const SEC_ASN1Template OuterSequenceTemplate[] = {
    {SEC_ASN1_SEQUENCE_OF, offsetof(OuterSequence, item), InnerSequenceTemplate,
     sizeof(OuterSequence)}};

/* SEQUENCE OF [0] EXPLICIT SEQUENCE { ANY } -- a group whose members are
 * explicitly tagged, so each member parses its own end-of-contents octets. */
static const SEC_ASN1Template ExplicitInnerSequenceTemplate[] = {
    {SEC_ASN1_EXPLICIT | SEC_ASN1_CONSTRUCTED | SEC_ASN1_CONTEXT_SPECIFIC | 0,
     0, InnerSequenceTemplate, sizeof(InnerSequenceItem)}};

static const SEC_ASN1Template GroupOfExplicitTemplate[] = {
    {SEC_ASN1_SEQUENCE_OF, 0, ExplicitInnerSequenceTemplate}};

/* [0] EXPLICIT { ANY OPTIONAL } -- an explicitly tagged wrapper whose content
 * may be absent, so "[0] indefinite {}" is a legal encoding. Decoding one of
 * these consumes the wrapper's end-of-contents octets while looking for the
 * absent content. */
struct OptionalContent {
  SECItem content;
};

static const SEC_ASN1Template OptionalAnyTemplate[] = {
    {SEC_ASN1_ANY | SEC_ASN1_OPTIONAL, offsetof(OptionalContent, content), NULL,
     sizeof(OptionalContent)}};

static const SEC_ASN1Template ExplicitOptionalTemplate[] = {
    {SEC_ASN1_EXPLICIT | SEC_ASN1_CONSTRUCTED | SEC_ASN1_CONTEXT_SPECIFIC | 0,
     0, OptionalAnyTemplate, sizeof(OptionalContent)}};

static const SEC_ASN1Template GroupOfExplicitOptionalTemplate[] = {
    {SEC_ASN1_SEQUENCE_OF, 0, ExplicitOptionalTemplate}};

/* SEQUENCE { [0] EXPLICIT { ANY OPTIONAL }, ANY OPTIONAL } */
struct WrappedThenAny {
  SECItem wrapped;
  SECItem rest;
};

static const SEC_ASN1Template SequenceWithExplicitOptionalTemplate[] = {
    {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(WrappedThenAny)},
    {SEC_ASN1_EXPLICIT | SEC_ASN1_CONSTRUCTED | SEC_ASN1_CONTEXT_SPECIFIC | 0,
     offsetof(WrappedThenAny, wrapped), OptionalAnyTemplate},
    {SEC_ASN1_ANY | SEC_ASN1_OPTIONAL, offsetof(WrappedThenAny, rest)},
    {0}};

/* SET OF CHOICE { UTCTime | GeneralizedTime }. NSS decodes this shape whenever
 * a dynamic attribute-value chooser returns a CHOICE template, e.g. a CMS
 * signing-time attribute (SET OF CERT_TimeChoiceTemplate). A CHOICE member
 * allocates its destination before it discovers whether there is a member
 * there at all, which is what makes an empty SET interesting. */
struct TimeChoice {
  int kind;
  SECItem value;
};

static const SEC_ASN1Template TimeChoiceTemplate[] = {
    {SEC_ASN1_CHOICE, offsetof(TimeChoice, kind), NULL, sizeof(TimeChoice)},
    {SEC_ASN1_UTC_TIME, offsetof(TimeChoice, value), NULL, 1},
    {SEC_ASN1_GENERALIZED_TIME, offsetof(TimeChoice, value), NULL, 2},
    {0}};

static const SEC_ASN1Template SetOfTimeChoiceTemplate[] = {
    {SEC_ASN1_SET_OF, 0, TimeChoiceTemplate}};

/* SEQUENCE { PrintableString, [0] EXPLICIT ANY OPTIONAL, ... } in one, two, and
 * three trailing-optional flavours. When such a sequence is indefinite-length
 * encoded and the optional fields are absent, the state that goes looking for
 * the first of them runs into the sequence's end-of-contents octets instead.
 * The sequence has to remember that those octets were its own while it walks
 * over the remaining optional fields. */
struct TrailingOptionals {
  SECItem required;
  SECItem first;
  SECItem second;
  SECItem third;
};

SEC_ASN1_MKSUB(SEC_AnyTemplate)

#define EXPLICIT_OPTIONAL(n, field)                                       \
  {SEC_ASN1_EXPLICIT | SEC_ASN1_CONSTRUCTED | SEC_ASN1_CONTEXT_SPECIFIC | \
       (n) | SEC_ASN1_OPTIONAL,                                           \
   offsetof(TrailingOptionals, field), SEC_ASN1_SUB(SEC_AnyTemplate)}

static const SEC_ASN1Template OneTrailingOptionalTemplate[] = {
    {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(TrailingOptionals)},
    {SEC_ASN1_PRINTABLE_STRING, offsetof(TrailingOptionals, required)},
    EXPLICIT_OPTIONAL(0, first),
    {0}};

static const SEC_ASN1Template TwoTrailingOptionalsTemplate[] = {
    {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(TrailingOptionals)},
    {SEC_ASN1_PRINTABLE_STRING, offsetof(TrailingOptionals, required)},
    EXPLICIT_OPTIONAL(0, first),
    EXPLICIT_OPTIONAL(1, second),
    {0}};

static const SEC_ASN1Template ThreeTrailingOptionalsTemplate[] = {
    {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(TrailingOptionals)},
    {SEC_ASN1_PRINTABLE_STRING, offsetof(TrailingOptionals, required)},
    EXPLICIT_OPTIONAL(0, first),
    EXPLICIT_OPTIONAL(1, second),
    EXPLICIT_OPTIONAL(2, third),
    {0}};

/* Same, but with a required field behind the optional one, so an encoding that
 * ends after the PrintableString is truncated no matter how it is encoded. */
static const SEC_ASN1Template OptionalThenRequiredTemplate[] = {
    {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(TrailingOptionals)},
    {SEC_ASN1_PRINTABLE_STRING, offsetof(TrailingOptionals, required)},
    EXPLICIT_OPTIONAL(0, first),
    {SEC_ASN1_INTEGER, offsetof(TrailingOptionals, second)},
    {0}};

#undef EXPLICIT_OPTIONAL

/* SEQUENCE { INLINE <one of the above>, INTEGER } */
struct TrailingOptionalsThenInteger {
  TrailingOptionals inner;
  SECItem integer;
};

/* SEQUENCE OF INLINE SEQUENCE { ANY }. A group member that is a transparent
 * (POINTER / INLINE / implicitly tagged) state has no header of its own, so it
 * is the member's child that runs into the group's end-of-contents octets, and
 * the flag has to travel back out through the member. */
static const SEC_ASN1Template InlineInnerSequenceTemplate[] = {
    {SEC_ASN1_INLINE, 0, InnerSequenceTemplate, sizeof(InnerSequenceItem)}};

static const SEC_ASN1Template GroupOfInlineTemplate[] = {
    {SEC_ASN1_SEQUENCE_OF, 0, InlineInnerSequenceTemplate}};

TEST_F(SECASN1DTest, IndefiniteSequenceInIndefiniteGroup) {
  OuterSequence* outer = nullptr;

  // echo "SEQUENCE indefinite {
  //         SEQUENCE indefinite {
  //            PrintableString { \"Test for Bug 1387919\" }
  //         }
  //       }" | ascii2der | xxd -i
  unsigned char ber[] = {0x30, 0x80, 0x30, 0x80, 0x13, 0x14, 0x54, 0x65,
                         0x73, 0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x42,
                         0x75, 0x67, 0x20, 0x31, 0x33, 0x38, 0x37, 0x39,
                         0x31, 0x39, 0x00, 0x00, 0x00, 0x00};

  // Decoding should fail if the trailing EOC is omitted (Bug 1387919)
  EXPECT_EQ(SECFailure,
            Decode(OuterSequenceTemplate, &outer, ber, sizeof(ber) - 2));

  // With the trailing EOC, this is well-formed BER.
  EXPECT_EQ(SECSuccess,
            Decode(OuterSequenceTemplate, &outer, ber, sizeof(ber)));

  // |outer| should now be a null terminated array of InnerSequenceItems

  // The first item is PrintableString { \"Test for Bug 1387919\" }
  EXPECT_EQ(outer[0].item->value.len, 22U);
  EXPECT_EQ(0, memcmp(outer[0].item->value.data, ber + 4, 22));

  // The second item is the null terminator
  EXPECT_EQ(outer[1].item, nullptr);
}

// An indefinite-length EXPLICIT member of an indefinite-length group parses its
// own end-of-contents octets. Those octets must not be mistaken for the
// group's terminator: the group ends only at its own end-of-contents octets.
TEST_F(SECASN1DTest, IndefiniteExplicitInIndefiniteGroup) {
  InnerSequenceItem** items = nullptr;

  // SEQUENCE indefinite {
  //   [0] indefinite { SEQUENCE indefinite { PrintableString { "AB" } } }
  // }
  unsigned char ber[] = {0x30, 0x80,            //
                         0xa0, 0x80,            //
                         0x30, 0x80,            //
                         0x13, 0x02, 'A', 'B',  //
                         0x00, 0x00,            // end SEQUENCE
                         0x00, 0x00,            // end [0]
                         0x00, 0x00};           // end group

  // The [0] wrapper's end-of-contents octets do not end the group, so an
  // encoding that stops there is truncated.
  EXPECT_EQ(SECFailure,
            Decode(GroupOfExplicitTemplate, &items, ber, sizeof(ber) - 2));

  EXPECT_EQ(SECSuccess,
            Decode(GroupOfExplicitTemplate, &items, ber, sizeof(ber)));
  ASSERT_NE(nullptr, items);
  ASSERT_NE(nullptr, items[0]);
  EXPECT_EQ(4U, items[0]->value.len);
  EXPECT_EQ(0, memcmp(items[0]->value.data, ber + 6, 4));
  EXPECT_EQ(nullptr, items[1]);
}

// Every member of the group must be parsed, not just the first one.
TEST_F(SECASN1DTest, TwoIndefiniteExplicitsInIndefiniteGroup) {
  InnerSequenceItem** items = nullptr;

  unsigned char ber[] = {0x30, 0x80,              //
                         0xa0, 0x80, 0x30, 0x80,  //
                         0x13, 0x01, 'A',         //
                         0x00, 0x00, 0x00, 0x00,  // end SEQ, [0]
                         0xa0, 0x80, 0x30, 0x80,  //
                         0x13, 0x01, 'B',         //
                         0x00, 0x00, 0x00, 0x00,  // end SEQ, [0]
                         0x00, 0x00};             // end group

  EXPECT_EQ(SECSuccess,
            Decode(GroupOfExplicitTemplate, &items, ber, sizeof(ber)));
  ASSERT_NE(nullptr, items);
  ASSERT_NE(nullptr, items[0]);
  ASSERT_NE(nullptr, items[1]);
  EXPECT_EQ(3U, items[0]->value.len);
  EXPECT_EQ(0, memcmp(items[0]->value.data, ber + 6, 3));
  EXPECT_EQ(3U, items[1]->value.len);
  EXPECT_EQ(0, memcmp(items[1]->value.data, ber + 17, 3));
  EXPECT_EQ(nullptr, items[2]);
}

// A group must not stop early and silently ignore the rest of its content:
// here the second member does not match the template and must be rejected.
TEST_F(SECASN1DTest, GroupWithMistaggedMemberAfterIndefiniteExplicit) {
  InnerSequenceItem** items = nullptr;

  unsigned char ber[] = {0x30, 0x80,              //
                         0xa0, 0x80, 0x30, 0x80,  //
                         0x13, 0x01, 'A',         //
                         0x00, 0x00, 0x00, 0x00,  // end SEQ, [0]
                         0x30, 0x00,              // not [0]
                         0x00, 0x00};             // end group

  EXPECT_EQ(SECFailure,
            Decode(GroupOfExplicitTemplate, &items, ber, sizeof(ber)));
}

// An indefinite-length EXPLICIT whose content is optional and absent has its
// end-of-contents octets consumed by the child that went looking for that
// content. The wrapper is then complete: it must not read a second set of
// end-of-contents octets, which would be its parent's.
TEST_F(SECASN1DTest, EmptyIndefiniteExplicit) {
  OptionalContent* content = nullptr;

  unsigned char truncated[] = {0xa0, 0x80};
  EXPECT_EQ(SECFailure, Decode(ExplicitOptionalTemplate, &content, truncated,
                               sizeof(truncated)));

  // [0] indefinite {}
  unsigned char ber[] = {0xa0, 0x80, 0x00, 0x00};
  content = static_cast<OptionalContent*>(
      PORT_ArenaZAlloc(arena_, sizeof(OptionalContent)));
  EXPECT_EQ(SECSuccess,
            Decode(ExplicitOptionalTemplate, content, ber, sizeof(ber)));
  EXPECT_EQ(nullptr, content->content.data);
  EXPECT_EQ(0U, content->content.len);
}

TEST_F(SECASN1DTest, EmptyIndefiniteExplicitInIndefiniteGroup) {
  OptionalContent** items = nullptr;

  // SEQUENCE indefinite { [0] indefinite {} }
  unsigned char one[] = {0x30, 0x80, 0xa0, 0x80, 0x00, 0x00, 0x00, 0x00};
  EXPECT_EQ(SECFailure, Decode(GroupOfExplicitOptionalTemplate, &items, one,
                               sizeof(one) - 2));
  EXPECT_EQ(SECSuccess,
            Decode(GroupOfExplicitOptionalTemplate, &items, one, sizeof(one)));
  ASSERT_NE(nullptr, items);
  ASSERT_NE(nullptr, items[0]);
  EXPECT_EQ(nullptr, items[0]->content.data);
  EXPECT_EQ(nullptr, items[1]);

  // SEQUENCE indefinite { [0] indefinite {}, [0] indefinite {} }
  unsigned char two[] = {0x30, 0x80, 0xa0, 0x80, 0x00, 0x00,
                         0xa0, 0x80, 0x00, 0x00, 0x00, 0x00};
  items = nullptr;
  EXPECT_EQ(SECSuccess,
            Decode(GroupOfExplicitOptionalTemplate, &items, two, sizeof(two)));
  ASSERT_NE(nullptr, items);
  ASSERT_NE(nullptr, items[0]);
  ASSERT_NE(nullptr, items[1]);
  EXPECT_EQ(nullptr, items[0]->content.data);
  EXPECT_EQ(nullptr, items[1]->content.data);
  EXPECT_EQ(nullptr, items[2]);

  // SEQUENCE indefinite { [0] indefinite { PrintableString { "A" } },
  //                       [0] indefinite {} }
  unsigned char mixed[] = {0x30, 0x80,                   //
                           0xa0, 0x80, 0x13, 0x01, 'A',  //
                           0x00, 0x00,                   // end [0]
                           0xa0, 0x80, 0x00, 0x00,       // empty [0]
                           0x00, 0x00};                  // end group
  items = nullptr;
  EXPECT_EQ(SECSuccess, Decode(GroupOfExplicitOptionalTemplate, &items, mixed,
                               sizeof(mixed)));
  ASSERT_NE(nullptr, items);
  ASSERT_NE(nullptr, items[0]);
  ASSERT_NE(nullptr, items[1]);
  EXPECT_EQ(3U, items[0]->content.len);
  EXPECT_EQ(0, memcmp(items[0]->content.data, mixed + 4, 3));
  EXPECT_EQ(nullptr, items[1]->content.data);
  EXPECT_EQ(nullptr, items[2]);

  // The same member inside a definite-length group.
  unsigned char definite[] = {0x30, 0x04, 0xa0, 0x80, 0x00, 0x00};
  items = nullptr;
  EXPECT_EQ(SECSuccess, Decode(GroupOfExplicitOptionalTemplate, &items,
                               definite, sizeof(definite)));
  ASSERT_NE(nullptr, items);
  ASSERT_NE(nullptr, items[0]);
  EXPECT_EQ(nullptr, items[0]->content.data);
  EXPECT_EQ(nullptr, items[1]);
}

TEST_F(SECASN1DTest, EmptyIndefiniteExplicitInSequence) {
  WrappedThenAny* seq = static_cast<WrappedThenAny*>(
      PORT_ArenaZAlloc(arena_, sizeof(WrappedThenAny)));

  // SEQUENCE indefinite { [0] indefinite {} }
  unsigned char indefinite[] = {0x30, 0x80, 0xa0, 0x80, 0x00, 0x00, 0x00, 0x00};
  EXPECT_EQ(SECSuccess, Decode(SequenceWithExplicitOptionalTemplate, seq,
                               indefinite, sizeof(indefinite)));
  EXPECT_EQ(nullptr, seq->wrapped.data);
  EXPECT_EQ(nullptr, seq->rest.data);

  // SEQUENCE { [0] indefinite {}, SEQUENCE {} }
  unsigned char withRest[] = {0x30, 0x06, 0xa0, 0x80, 0x00, 0x00, 0x30, 0x00};
  seq = static_cast<WrappedThenAny*>(
      PORT_ArenaZAlloc(arena_, sizeof(WrappedThenAny)));
  EXPECT_EQ(SECSuccess, Decode(SequenceWithExplicitOptionalTemplate, seq,
                               withRest, sizeof(withRest)));
  EXPECT_EQ(nullptr, seq->wrapped.data);
  ASSERT_NE(nullptr, seq->rest.data);
  EXPECT_EQ(2U, seq->rest.len);
  EXPECT_EQ(0, memcmp(seq->rest.data, withRest + 6, 2));
}

// An empty indefinite-length group must not produce a member. A CHOICE member
// has its destination allocated before the end-of-contents octets are seen, and
// that zero-filled destination used to be handed back as a phantom member.
TEST_F(SECASN1DTest, EmptyIndefiniteSetOfChoice) {
  TimeChoice** items = nullptr;

  unsigned char empty[] = {0x31, 0x80, 0x00, 0x00};
  EXPECT_EQ(SECSuccess,
            Decode(SetOfTimeChoiceTemplate, &items, empty, sizeof(empty)));
  ASSERT_NE(nullptr, items);
  EXPECT_EQ(nullptr, items[0]);

  // A non-empty SET still decodes.
  unsigned char utc[] = {0x31, 0x80, 0x17, 0x0d, '9', '9', '0', '1',  '0', '1',
                         '0',  '0',  '0',  '0',  '0', '0', 'Z', 0x00, 0x00};
  items = nullptr;
  EXPECT_EQ(SECSuccess,
            Decode(SetOfTimeChoiceTemplate, &items, utc, sizeof(utc)));
  ASSERT_NE(nullptr, items);
  ASSERT_NE(nullptr, items[0]);
  EXPECT_EQ(1, items[0]->kind);
  EXPECT_EQ(13U, items[0]->value.len);
  EXPECT_EQ(0, memcmp(items[0]->value.data, utc + 4, 13));
  EXPECT_EQ(nullptr, items[1]);
}

// An indefinite-length sequence whose trailing optional fields are all absent
// ends at its own end-of-contents octets, which the state that went looking for
// the first absent field consumes. That has to work for any number of trailing
// optional fields, not just one.
TEST_F(SECASN1DTest, AbsentTrailingOptionalsInIndefiniteSequence) {
  // SEQUENCE { PrintableString { "abc" } }, definite and indefinite.
  unsigned char definite[] = {0x30, 0x05, 0x13, 0x03, 'a', 'b', 'c'};
  unsigned char indefinite[] = {0x30, 0x80, 0x13, 0x03, 'a',
                                'b',  'c',  0x00, 0x00};

  const SEC_ASN1Template* templates[] = {OneTrailingOptionalTemplate,
                                         TwoTrailingOptionalsTemplate,
                                         ThreeTrailingOptionalsTemplate};
  for (const SEC_ASN1Template* tmpl : templates) {
    TrailingOptionals* seq = static_cast<TrailingOptionals*>(
        PORT_ArenaZAlloc(arena_, sizeof(TrailingOptionals)));
    EXPECT_EQ(SECSuccess, Decode(tmpl, seq, definite, sizeof(definite)));
    EXPECT_EQ(3U, seq->required.len);
    EXPECT_EQ(0, memcmp(seq->required.data, definite + 4, 3));
    EXPECT_EQ(nullptr, seq->first.data);
    EXPECT_EQ(nullptr, seq->second.data);
    EXPECT_EQ(nullptr, seq->third.data);

    seq = static_cast<TrailingOptionals*>(
        PORT_ArenaZAlloc(arena_, sizeof(TrailingOptionals)));
    EXPECT_EQ(SECSuccess, Decode(tmpl, seq, indefinite, sizeof(indefinite)));
    EXPECT_EQ(3U, seq->required.len);
    EXPECT_EQ(0, memcmp(seq->required.data, indefinite + 4, 3));
    EXPECT_EQ(nullptr, seq->first.data);
    EXPECT_EQ(nullptr, seq->second.data);
    EXPECT_EQ(nullptr, seq->third.data);
  }
}

// The same indefinite-length sequence nested in a definite-length one. The
// outer sequence checks that its children consumed exactly its length, so the
// inner sequence has to count the end-of-contents octets that its absent
// optional field ran into. At the top level nothing checks that count.
TEST_F(SECASN1DTest, AbsentTrailingOptionalsBeforeRequiredSibling) {
  // SEQUENCE { SEQUENCE indefinite { PrintableString { "abc" } }, INTEGER 7 }
  unsigned char ber[] = {0x30, 0x0c, 0x30, 0x80, 0x13, 0x03, 'a',
                         'b',  'c',  0x00, 0x00, 0x02, 0x01, 0x07};

  const SEC_ASN1Template* templates[] = {OneTrailingOptionalTemplate,
                                         TwoTrailingOptionalsTemplate,
                                         ThreeTrailingOptionalsTemplate};
  for (const SEC_ASN1Template* tmpl : templates) {
    const SEC_ASN1Template outerTemplate[] = {
        {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(TrailingOptionalsThenInteger)},
        {SEC_ASN1_INLINE, offsetof(TrailingOptionalsThenInteger, inner), tmpl},
        {SEC_ASN1_INTEGER, offsetof(TrailingOptionalsThenInteger, integer)},
        {0}};
    TrailingOptionalsThenInteger* seq =
        static_cast<TrailingOptionalsThenInteger*>(
            PORT_ArenaZAlloc(arena_, sizeof(TrailingOptionalsThenInteger)));
    EXPECT_EQ(SECSuccess, Decode(outerTemplate, seq, ber, sizeof(ber)));
    EXPECT_EQ(3U, seq->inner.required.len);
    EXPECT_EQ(0, memcmp(seq->inner.required.data, ber + 6, 3));
    EXPECT_EQ(nullptr, seq->inner.first.data);
    EXPECT_EQ(nullptr, seq->inner.second.data);
    EXPECT_EQ(nullptr, seq->inner.third.data);
    ASSERT_NE(nullptr, seq->integer.data);
    EXPECT_EQ(1U, seq->integer.len);
    EXPECT_EQ(0x07, seq->integer.data[0]);
  }
}

// Only the fields we have not looked at yet may be skipped, and only if they
// are optional. Running into the end-of-contents octets while a required field
// is still outstanding is an error.
TEST_F(SECASN1DTest, AbsentRequiredFieldAfterOptionalInIndefiniteSequence) {
  TrailingOptionals* seq = static_cast<TrailingOptionals*>(
      PORT_ArenaZAlloc(arena_, sizeof(TrailingOptionals)));

  unsigned char indefinite[] = {0x30, 0x80, 0x13, 0x03, 'a',
                                'b',  'c',  0x00, 0x00};
  EXPECT_EQ(SECFailure, Decode(OptionalThenRequiredTemplate, seq, indefinite,
                               sizeof(indefinite)));

  // With the required INTEGER present it decodes.
  unsigned char withRequired[] = {0x30, 0x80, 0x13, 0x03, 'a',  'b',
                                  'c',  0x02, 0x01, 0x07, 0x00, 0x00};
  seq = static_cast<TrailingOptionals*>(
      PORT_ArenaZAlloc(arena_, sizeof(TrailingOptionals)));
  EXPECT_EQ(SECSuccess, Decode(OptionalThenRequiredTemplate, seq, withRequired,
                               sizeof(withRequired)));
  EXPECT_EQ(nullptr, seq->first.data);
  ASSERT_NE(nullptr, seq->second.data);
  EXPECT_EQ(1U, seq->second.len);
  EXPECT_EQ(0x07, seq->second.data[0]);
}

// An empty indefinite-length group whose member template is a transparent
// (POINTER / INLINE / implicitly tagged) state: the member's child consumes the
// group's end-of-contents octets even though the child is not optional, so it
// is not marked "missing". The member still has to report the flag back to the
// group, which used to walk off the end of its state stack.
TEST_F(SECASN1DTest, EmptyIndefiniteGroupOfInline) {
  InnerSequenceItem** items = nullptr;

  unsigned char empty[] = {0x30, 0x80, 0x00, 0x00};
  EXPECT_EQ(SECSuccess,
            Decode(GroupOfInlineTemplate, &items, empty, sizeof(empty)));
  ASSERT_NE(nullptr, items);
  EXPECT_EQ(nullptr, items[0]);
}

}  // namespace nss_test
