/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "pk11pub.h"
#include "nssutil.h"
#include <stdio.h>
#include "prerror.h"
#include "nss.h"
#include "gtest/gtest.h"
#include "scoped_ptrs.h"
#include "util.h"

#define NSS_PERROR(string) \
  std::cerr << string << ": " << PORT_ErrorToString(PORT_GetError()) << std::endl;

#define NSS_PERROR2(string1, string2) \
  std::cerr << string1 << "-" << string2 << ": " \
            << PORT_ErrorToString(PORT_GetError()) << std::endl;

#define kKEYSIZE 16

namespace nss_test {

typedef enum { TYPE_STR, TYPE_AES, TYPE_DES } TEST_TYPE;

class EncryptDeriveTest : public ::testing::Test {

  public:

    static unsigned char IV[kKEYSIZE+1];
    static unsigned char TEST_STRING[kKEYSIZE+1];

    void setup_ed_params(
        const TEST_TYPE param_type,
        unsigned int blocksize,
        SECItem& d_param, SECItem& e_param) {

        switch (param_type) {
          case TYPE_STR:
            string_.pData = (CK_BYTE_PTR) &TEST_STRING;
            string_.ulLen = kKEYSIZE;
            d_param.data = (unsigned char *)&string_;
            d_param.len = sizeof(string_);
            e_param.data = NULL;
            e_param.len = 0;
            break;
          case TYPE_AES:
            aes_.pData = (CK_BYTE_PTR) &TEST_STRING;
            aes_.length = kKEYSIZE;
            PORT_Memcpy(aes_.iv, &IV, blocksize);
            d_param.data = (unsigned char *) &aes_;
            d_param.len = sizeof(aes_);
            e_param.data = IV;
            e_param.len = blocksize;
            break;
          case TYPE_DES:
            des_.pData = (CK_BYTE_PTR) &TEST_STRING;
            des_.length = kKEYSIZE;
            PORT_Memcpy(des_.iv, &IV, blocksize);
            d_param.data = (unsigned char *) &des_;
            d_param.len = sizeof(des_);
            e_param.data = IV;
            e_param.len = blocksize;
            break;
          default:
            ADD_FAILURE() << "Unexpected param_type " << param_type;
        }
    }

    void Derive(
        const char *name,
        TEST_TYPE param_type,
        CK_MECHANISM_TYPE derive_mech,
        CK_MECHANISM_TYPE encrypt_mech,
        unsigned int blocksize,
        bool has_check_sum
      ) {

        unsigned char test_out[16];
        unsigned int test_out_len;
        SECItem d_param, e_param;
        SECItem *data;
        SECStatus rv;

        ScopedPK11SlotInfo slot(PK11_GetBestSlot(derive_mech, NULL));
        ASSERT_NE(nullptr, slot);

        ScopedPK11SymKey baseKey(
            PK11_TokenKeyGenWithFlags(
                slot.get(), encrypt_mech,
                NULL, 16, NULL, CKF_ENCRYPT|CKF_DERIVE, 0, NULL));
        ASSERT_NE(nullptr, baseKey.get());

        setup_ed_params(param_type,
                        blocksize,
                        d_param, e_param);

        CK_MECHANISM_TYPE target = has_check_sum ? CKM_DES3_CBC : CKM_AES_CBC;
        ScopedPK11SymKey newKey(
            PK11_Derive(baseKey.get(), derive_mech, &d_param,
                        target, CKA_DECRYPT, kKEYSIZE));

        ASSERT_NE(nullptr, newKey.get());

        rv = PK11_ExtractKeyValue(newKey.get());
        ASSERT_EQ(SECSuccess, rv);

        data = PK11_GetKeyData(newKey.get());
        ASSERT_NE(nullptr, data);
        ASSERT_EQ((unsigned int) data->len, (unsigned int) kKEYSIZE);
        rv = PK11_Encrypt(baseKey.get(), encrypt_mech, &e_param,
                 test_out, &test_out_len,
                 kKEYSIZE, TEST_STRING, kKEYSIZE);
        ASSERT_EQ(SECSuccess, rv);
        ASSERT_EQ((unsigned int) kKEYSIZE, test_out_len);
        if (has_check_sum) {
            // Des keys have a checksum, mask them out first
            for (unsigned int j = 0; j < kKEYSIZE; j++) {
                test_out[j] &= 0xfe;
                data->data[j] &= 0xfe;
            }
        }
        EXPECT_EQ(0, memcmp(test_out, data->data, kKEYSIZE));
    }

  protected:

    CK_AES_CBC_ENCRYPT_DATA_PARAMS aes_;
    CK_DES_CBC_ENCRYPT_DATA_PARAMS des_;
    CK_KEY_DERIVATION_STRING_DATA string_;
};


TEST_F(EncryptDeriveTest, Test_DES_ECB) {
    Derive("DES ECB", TYPE_STR, CKM_DES_ECB_ENCRYPT_DATA, CKM_DES_ECB, 8, false);
}

TEST_F(EncryptDeriveTest, Test_DES_CBC) {
    Derive("DES CBC", TYPE_DES, CKM_DES_CBC_ENCRYPT_DATA,  CKM_DES_CBC,  8, false);
}

TEST_F(EncryptDeriveTest, Test_DES3_ECB) {
    Derive("DES3 ECB", TYPE_STR, CKM_DES3_ECB_ENCRYPT_DATA, CKM_DES3_ECB, 8, false);
}

TEST_F(EncryptDeriveTest, Test_DES3_CBC) {
    Derive("DES3 CBC", TYPE_DES, CKM_DES3_CBC_ENCRYPT_DATA, CKM_DES3_CBC, 8, false);
}

TEST_F(EncryptDeriveTest, Test_AES_ECB) {
    Derive("AES ECB", TYPE_STR, CKM_AES_ECB_ENCRYPT_DATA,  CKM_AES_ECB, 16, true);
}

TEST_F(EncryptDeriveTest, Test_AES_CBC) {
    Derive("AES CBC", TYPE_AES, CKM_AES_CBC_ENCRYPT_DATA,  CKM_AES_CBC, 16, true);
}

TEST_F(EncryptDeriveTest, Test_CAMELLIA_ECB) {
    Derive("CAMELLIA ECB", TYPE_STR, CKM_CAMELLIA_ECB_ENCRYPT_DATA,CKM_CAMELLIA_ECB, 16, true);
}

TEST_F(EncryptDeriveTest, Test_CAMELLIA_CBC) {
    Derive("CAMELLIA CBC", TYPE_AES, CKM_CAMELLIA_CBC_ENCRYPT_DATA,CKM_CAMELLIA_CBC, 16, true);
}

TEST_F(EncryptDeriveTest, Test_SEED_ECB) {
    Derive("SEED ECB", TYPE_STR, CKM_SEED_ECB_ENCRYPT_DATA, CKM_SEED_ECB, 16, true);
}

TEST_F(EncryptDeriveTest, Test_SEED_CBC) {
    Derive("SEED CBC", TYPE_AES, CKM_SEED_CBC_ENCRYPT_DATA, CKM_SEED_CBC, 16, true);
}


unsigned char EncryptDeriveTest::IV[] = "1234567890abcdef";
unsigned char EncryptDeriveTest::TEST_STRING[] = "FEDCBA0987654321";


int main(int argc, char **argv) {

  SECStatus rv;

  rv = NSS_InitializePRErrorTable();
  if (rv != SECSuccess) {
      fprintf(stderr, "Couldn't initialize NSS error table \n");
      exit (1);
  }

  rv = NSS_NoDB_Init(NULL);
  if (rv != SECSuccess) {
    NSS_PERROR("NSS_NoDB_Init");
    exit (1);
  }
  ::testing::InitGoogleTest(&argc, argv);

  return RUN_ALL_TESTS();
}

}  // namespace nss_test
