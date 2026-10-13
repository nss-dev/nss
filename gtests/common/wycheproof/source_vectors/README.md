# Wycheproof test vectors

The JSON files in this directory are unmodified copies of test vectors from
[Project Wycheproof](https://github.com/C2SP/wycheproof). The gtests read them
at runtime with `JsonReader` (`gtests/common/json_reader.h`); nothing is
generated from them.

`WycheproofHeader(name, ...)` opens `<name>_test.json` from this directory,
relative to the `-s <source>/gtests/<binary>` argument given to the gtest
binary. Without `-s` these tests fail with "error opening vectors".

## Provenance

Each file is byte-identical to the upstream file at the commit listed. Files
from `testvectors/` use the original (v0) format. Upstream removed that
directory in `156d287dd538` (2025-09-01), so those files are no longer
published and are updated by moving to the `testvectors_v1/` equivalent.

| Upstream path | Commit | Files | Read by |
| --- | --- | --- | --- |
| `testvectors/` | `4672ff74d687` | `aes_cbc_pkcs5` | `pk11_gtest/pk11_cbc_unittest.cc` |
| | | `aes_cmac` | `pk11_gtest/pk11_aes_cmac_unittest.cc` |
| | | `chacha20_poly1305` | `pk11_gtest/pk11_chacha20poly1305_unittest.cc` |
| | | `ecdh_secp{256,384,521}r1` | `pk11_gtest/pk11_ecdh_unittest.cc` |
| | | `ecdsa_secp*_sha*` | `pk11_gtest/pk11_ecdsa_unittest.cc` |
| | | `rsa_oaep_*` | `pk11_gtest/pk11_rsaoaep_unittest.cc` |
| | | `rsa_pkcs1_{2048,3072,4096}` | `pk11_gtest/pk11_rsaencrypt_unittest.cc` |
| | | `rsa_pss_*` | `pk11_gtest/pk11_rsapss_unittest.cc` |
| | | `rsa_signature`, `rsa_signature_<bits>_<hash>` | `pk11_gtest/pk11_rsapkcs1_unittest.cc` |
| | | `x25519` | `pk11_gtest/pk11_curve25519_unittest.cc` |
| `testvectors/` | `fe3dba2640b6` | `dsa` | `pk11_gtest/pk11_dsa_unittest.cc` |
| `testvectors/` | `f63678bb717b` | `eddsa` | `pk11_gtest/pk11_eddsa_unittest.cc` |
| `testvectors/` | `2fb91a6923b6` | `hmac_sha{224,256,384,512}`, `hmac_sha3_*` | `pk11_gtest/pk11_hmac_unittest.cc` |
| `testvectors_v1/` | `e0df04e0c033` | `aes_gcm` | `pk11_gtest/pk11_aes_gcm_unittest.cc` |
| | | `hkdf_sha{1,256,384,512}` | `pk11_gtest/pk11_hkdf_unittest.cc` |
| `testvectors_v1/` | `6d7cccd0fcb1` | `mldsa_{44,65,87}_sign_{seed,noseed}`, `mldsa_{44,65}_verify` | `freebl_gtest/mldsa_unittest.cc`, `pk11_gtest/pk11_mldsa_unittest.cc`, `cryptohi_gtest/cryptohi_mldsa_unittest.cc` |
| `testvectors_v1/` | `02872f4bdeda` | `mldsa_87_verify` | as above |
| `testvectors_v1/` | `fca0d3ba9f12` | `mlkem_{512,768,1024}`, `mlkem_*_keygen_seed` | `freebl_gtest/kyber_unittest.cc` |
| `testvectors_v1/` | `7a87c8699e57` | `mlkem_*_encaps` | `freebl_gtest/kyber_unittest.cc` |
| `testvectors_v1/` | `44dcf469edba` | `mlkem_*_semi_expanded_decaps` | `freebl_gtest/kyber_unittest.cc` |

File names in the table omit the `_test.json` suffix.

To check where a file came from, look its blob up in a clone of upstream:

```sh
git clone --bare https://github.com/C2SP/wycheproof.git /tmp/wycheproof.git
git -C /tmp/wycheproof.git log --all --reverse --format='%h %as %s' \
    --find-object=$(git hash-object hmac_sha256_test.json) | head -1
```

## Updating

Update one family of files at a time (for example, all `hmac_*` files), and
update the table above in the same change.

1. Download the new files from a specific upstream commit, not a branch:

   ```sh
   C=<commit>
   curl -fLO https://raw.githubusercontent.com/C2SP/wycheproof/$C/testvectors_v1/hmac_sha256_test.json
   ```

2. Copy them over the old files here and `hg add` any new names. Don't
   reformat or edit them, so that they stay byte-identical to upstream.

3. Build and run the gtest that reads them. The readers check the `schema`
   name and fail on group or test fields they don't recognize, so a format
   change shows up as a test failure rather than being silently misread.
   Moving a file from `testvectors/` to `testvectors_v1/` changes the schema
   name (`mac_test_schema.json` becomes `mac_test_schema_v1.json`, and so on),
   adds a `source` field to every test group, and for some families renames
   key fields (ECDSA's `keyDer` becomes `publicKeyDer`; RSA-OAEP's `n`/`e`/`d`
   become `privateKey`).

4. Investigate any new test failures. Each is a bug in NSS, a case NSS
   deliberately handles differently (handle it via the case's `flags`, as the
   DSA test does for `NoLeadingZero`), or an outdated assumption in the test.

Some v0 files have no v1 file of the same name: `dsa_test.json` is split into
`dsa_<p>_<q>_<hash>_test.json` files, `eddsa_test.json` became
`ed25519_test.json`, and `rsa_signature_test.json` has no direct equivalent.
