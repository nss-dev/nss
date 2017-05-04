// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

#include "gtest/gtest.h"

#include "freebl_util.h"
#include "gcm.h"

namespace nss_test {

typedef struct ghash_kat_str {
  std::string hash_key;
  std::string additional_data;
  std::string cipher_text;
  std::string result;
} ghash_kat_value;

/*
 * http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
 */
const ghash_kat_value kKatValues[] = {
    {"66e94bd4ef8a2c3b884cfa59ca342b2e", "", "",
     "00000000000000000000000000000000"},

    {"66e94bd4ef8a2c3b884cfa59ca342b2e", "", "0388dace60b6a392f328c2b971b2fe78",
     "f38cbb1ad69223dcc3457ae5b6b0f885"},

    {"b83b533708bf535d0aa6e52980d53b78", "",
     "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25"
     "4"
     "66931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
     "7f1b32b81b820d02614f8895ac1d4eac"},

    {"b83b533708bf535d0aa6e52980d53b78",
     "feedfacedeadbeeffeedfacedeadbeefabaddad2",
     "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25"
     "4"
     "66931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
     "698e57f70e6ecc7fd9463b7260a9ae5f"},

    {"b83b533708bf535d0aa6e52980d53b78",
     "feedfacedeadbeeffeedfacedeadbeefabaddad2",
     "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e"
     "4"
     "9f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
     "df586bb4c249b92cb6922877e444d37b"},

    {"b83b533708bf535d0aa6e52980d53b78",
     "feedfacedeadbeeffeedfacedeadbeefabaddad2",
     "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4f"
     "b"
     "a43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5",
     "1c5afe9760d3932f3c9a878aac3dc3de"},

    {"aae06992acbf52a3e8f4a96ec9300bd7", "", "98e7247c07f0fe411c267e4384b0f600",
     "e2c63f0ac44ad0e02efa05ab6743d4ce"},

    {"466923ec9ae682214f2c082badb39249", "",
     "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c"
     "1"
     "44c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256",
     "51110d40f6c8fff0eb1ae33445a889f0"},

    {"466923ec9ae682214f2c082badb39249",
     "feedfacedeadbeeffeedfacedeadbeefabaddad2",
     "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c"
     "1"
     "44c525ac619d18c84a3f4718e2448b2fe324d9ccda2710",
     "ed2ce3062e4a8ec06db8b4c490e8a268"},

    {"466923ec9ae682214f2c082badb39249",
     "feedfacedeadbeeffeedfacedeadbeefabaddad2",
     "0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057fddc29df9"
     "a"
     "471f75c66541d4d4dad1c9e93a19a58e8b473fa0f062f7",
     "1e6a133806607858ee80eaf237064089"},

    {"466923ec9ae682214f2c082badb39249",
     "feedfacedeadbeeffeedfacedeadbeefabaddad2",
     "d27e88681ce3243c4830165a8fdcf9ff1de9a1d8e6b447ef6ef7b79828666e4581e79012a"
     "f"
     "34ddd9e2f037589b292db3e67c036745fa22e7e9b7373b",
     "82567fb0b4cc371801eadec005968e94"},

    {"dc95c078a2408989ad48a21492842087", "", "cea7403d4d606b6e074ec5d3baf39d18",
     "83de425c5edc5d498f382c441041ca92"},

    {"acbef20579b4b8ebce889bac8732dad7", "",
     "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e485"
     "9"
     "0dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
     "4db870d37cb75fcb46097c36230d1612"},

    {"acbef20579b4b8ebce889bac8732dad7",
     "feedfacedeadbeeffeedfacedeadbeefabaddad2",
     "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e485"
     "9"
     "0dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
     "8bd0c4d8aacd391e67cca447e8c38f65"},

    {"acbef20579b4b8ebce889bac8732dad7",
     "feedfacedeadbeeffeedfacedeadbeefabaddad2",
     "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33"
     "9"
     "34a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f",
     "75a34288b8c68f811c52b2e9a2f97f63"},

    {"acbef20579b4b8ebce889bac8732dad7",
     "feedfacedeadbeeffeedfacedeadbeefabaddad2",
     "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b78"
     "0"
     "f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f",
     "d5ffcf6fc5ac4d69722187421a7f170b"},

    /* Extra, non-nist, test case to test 64-bit binary multiplication carry
     * correctness. */
    {"0000000000000000fcefef64ffc4766c", "", "0000000000000000ffcef9ebbffdbd8b",
     "3561e34e52d8b598f9937982512fff27"}};

class GHashTest : public ::testing::TestWithParam<ghash_kat_value> {
 protected:
  void TestGHash(const ghash_kat_value val, bool sw) {
    // Read test data.
    std::vector<uint8_t> hash_key = hex_string_to_bytes(val.hash_key);
    ASSERT_EQ(16UL, hash_key.size());
    std::vector<uint8_t> additional_data =
        hex_string_to_bytes(val.additional_data);
    std::vector<uint8_t> cipher_text = hex_string_to_bytes(val.cipher_text);
    std::vector<uint8_t> expected = hex_string_to_bytes(val.result);
    ASSERT_EQ(16UL, expected.size());

    // Prepare context.
    gcmHashContext ghashCtx;
    ASSERT_EQ(SECSuccess, gcmHash_InitContext(&ghashCtx, hash_key.data(), sw));

    // Hash additional_data, cipher_text.
    gcmHash_Reset(&ghashCtx,
                  const_cast<const unsigned char *>(additional_data.data()),
                  additional_data.size(), 16);
    gcmHash_Update(&ghashCtx,
                   const_cast<const unsigned char *>(cipher_text.data()),
                   cipher_text.size(), 16);

    // Finalise (hash in the length).
    uint8_t result_bytes[16];
    unsigned int out_len;
    ASSERT_EQ(SECSuccess,
              gcmHash_Final(&ghashCtx, result_bytes, &out_len, 16, 16));
    ASSERT_EQ(16U, out_len);
    EXPECT_EQ(expected, std::vector<uint8_t>(result_bytes, result_bytes + 16));
  }
};

#ifdef NSS_X86_OR_X64
TEST_P(GHashTest, KAT_X86_HW) { TestGHash(GetParam(), false); }
#endif
TEST_P(GHashTest, KAT_Sftw) { TestGHash(GetParam(), true); }

INSTANTIATE_TEST_CASE_P(NISTTestVector, GHashTest,
                        ::testing::ValuesIn(kKatValues));

}  // nss_test
