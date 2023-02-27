# DO NOT EDIT: generated from  liboqs.gyp.template
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
{
  'includes': [
    '../../coreconf/config.gypi'
  ],
  'conditions': [
    ['use_system_liboqs==1', {
      'targets': [{
        'target_name': 'oqs',
        'type': 'none',
        'link_settings': {
          'libraries': ['<(oqs_libs)'],
        },
      }],
    }, {
      'targets': [
        {
          'target_name': 'oqs_s',
          'type': 'static_library',
          'dependencies': [
            '<(DEPTH)/exports.gyp:nss_exports',
            'src/common/aes/aes.gyp:oqs_src_common_aes',
            'src/sig/sphincs/pqclean_sphincs-sha256-256s-simple_clean/pqclean_sphincs-sha256-256s-simple_clean.gyp:oqs_src_sig_sphincs_pqclean_sphincs-sha256-256s-simple_clean',
            'src/kem/kyber/pqcrystals-kyber_kyber512_ref/pqcrystals-kyber_kyber512_ref.gyp:oqs_src_kem_kyber_pqcrystals-kyber_kyber512_ref',
            'src/sig/sphincs/sphincs.gyp:oqs_src_sig_sphincs',
            'src/sig/sphincs/pqclean_sphincs-shake256-128s-simple_clean/pqclean_sphincs-shake256-128s-simple_clean.gyp:oqs_src_sig_sphincs_pqclean_sphincs-shake256-128s-simple_clean',
            'src/sig/dilithium/pqcrystals-dilithium_dilithium2_ref/pqcrystals-dilithium_dilithium2_ref.gyp:oqs_src_sig_dilithium_pqcrystals-dilithium_dilithium2_ref',
            'src/common/sha3/xkcp_low/KeccakP-1600/plain-64bits/plain-64bits.gyp:oqs_src_common_sha3_xkcp_low_KeccakP-1600_plain-64bits',
            'src/sig/sphincs/pqclean_sphincs-sha256-128f-simple_clean/pqclean_sphincs-sha256-128f-simple_clean.gyp:oqs_src_sig_sphincs_pqclean_sphincs-sha256-128f-simple_clean',
            'src/sig/sphincs/pqclean_sphincs-shake256-192f-simple_clean/pqclean_sphincs-shake256-192f-simple_clean.gyp:oqs_src_sig_sphincs_pqclean_sphincs-shake256-192f-simple_clean',
            'src/sig/sphincs/pqclean_sphincs-sha256-192f-simple_clean/pqclean_sphincs-sha256-192f-simple_clean.gyp:oqs_src_sig_sphincs_pqclean_sphincs-sha256-192f-simple_clean',
            'src/sig/sig.gyp:oqs_src_sig',
            'src/common/common.gyp:oqs_src_common',
            'src/sig/sphincs/pqclean_sphincs-sha256-192s-simple_clean/pqclean_sphincs-sha256-192s-simple_clean.gyp:oqs_src_sig_sphincs_pqclean_sphincs-sha256-192s-simple_clean',
            'src/sig/sphincs/pqclean_sphincs-shake256-256f-simple_clean/pqclean_sphincs-shake256-256f-simple_clean.gyp:oqs_src_sig_sphincs_pqclean_sphincs-shake256-256f-simple_clean',
            'src/kem/kem.gyp:oqs_src_kem',
            'src/sig/dilithium/pqcrystals-dilithium_dilithium3_ref/pqcrystals-dilithium_dilithium3_ref.gyp:oqs_src_sig_dilithium_pqcrystals-dilithium_dilithium3_ref',
            'src/common/sha3/xkcp_low/KeccakP-1600times4/serial/serial.gyp:oqs_src_common_sha3_xkcp_low_KeccakP-1600times4_serial',
            'src/sig/falcon/pqclean_falcon-512_clean/pqclean_falcon-512_clean.gyp:oqs_src_sig_falcon_pqclean_falcon-512_clean',
            'src/common/pqclean_shims/pqclean_shims.gyp:oqs_src_common_pqclean_shims',
            'src/common/rand/rand.gyp:oqs_src_common_rand',
            'src/sig/sphincs/pqclean_sphincs-shake256-192s-simple_clean/pqclean_sphincs-shake256-192s-simple_clean.gyp:oqs_src_sig_sphincs_pqclean_sphincs-shake256-192s-simple_clean',
            'src/sig/sphincs/pqclean_sphincs-shake256-256s-simple_clean/pqclean_sphincs-shake256-256s-simple_clean.gyp:oqs_src_sig_sphincs_pqclean_sphincs-shake256-256s-simple_clean',
            'src/sig/sphincs/pqclean_sphincs-sha256-128s-simple_clean/pqclean_sphincs-sha256-128s-simple_clean.gyp:oqs_src_sig_sphincs_pqclean_sphincs-sha256-128s-simple_clean',
            'src/sig/sphincs/pqclean_sphincs-sha256-256f-simple_clean/pqclean_sphincs-sha256-256f-simple_clean.gyp:oqs_src_sig_sphincs_pqclean_sphincs-sha256-256f-simple_clean',
            'src/sig/falcon/falcon.gyp:oqs_src_sig_falcon',
            'src/common/sha2/sha2.gyp:oqs_src_common_sha2',
            'src/common/sha3/sha3.gyp:oqs_src_common_sha3',
            'src/sig/falcon/pqclean_falcon-1024_clean/pqclean_falcon-1024_clean.gyp:oqs_src_sig_falcon_pqclean_falcon-1024_clean',
            'src/sig/dilithium/pqcrystals-dilithium_dilithium5_ref/pqcrystals-dilithium_dilithium5_ref.gyp:oqs_src_sig_dilithium_pqcrystals-dilithium_dilithium5_ref',
            'src/sig/sphincs/pqclean_sphincs-shake256-128f-simple_clean/pqclean_sphincs-shake256-128f-simple_clean.gyp:oqs_src_sig_sphincs_pqclean_sphincs-shake256-128f-simple_clean',
            'src/kem/kyber/kyber.gyp:oqs_src_kem_kyber',
            'src/kem/kyber/pqcrystals-kyber_kyber768_ref/pqcrystals-kyber_kyber768_ref.gyp:oqs_src_kem_kyber_pqcrystals-kyber_kyber768_ref',
            'src/sig/dilithium/dilithium.gyp:oqs_src_sig_dilithium',
            'src/kem/kyber/pqcrystals-kyber_kyber1024_ref/pqcrystals-kyber_kyber1024_ref.gyp:oqs_src_kem_kyber_pqcrystals-kyber_kyber1024_ref',
          ]
        },
        {
          'target_name': 'oqs',
          'type': 'shared_library',
          'dependencies': [
            'oqs_s'
          ],
          'variables': {
            'mapfile': 'oqs.def'
          }
        }
      ],
      'variables': {
        'module': 'oqs'
      }
    }]
  ],
}
