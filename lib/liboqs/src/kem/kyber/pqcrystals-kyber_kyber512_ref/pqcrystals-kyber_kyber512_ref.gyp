# DO NOT EDIT: generated from  subdir.gyp.template
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
{
  'includes': [
    '../../../../../../coreconf/config.gypi'
  ],
  'targets': [
    {
      'target_name': 'oqs_src_kem_kyber_pqcrystals-kyber_kyber512_ref',
      'type': 'static_library',
      'sources': [
            'cbd.c',
            'indcpa.c',
            'kem.c',
            'ntt.c',
            'poly.c',
            'polyvec.c',
            'reduce.c',
            'symmetric-shake.c',
            'verify.c',
      ],
      'dependencies': [
        '<(DEPTH)/exports.gyp:nss_exports'
      ]
    }
  ],
  'target_defaults': {
    'defines': [
            'KYBER_K=2',
    ],
    'include_dirs': [
      '<(DEPTH)/lib/liboqs/src/common/pqclean_shims',
      '<(DEPTH)/lib/liboqs/src/common/sha3/xkcp_low/KeccakP-1600/plain-64bits',
    ]
  },
  'variables': {
    'module': 'oqs'
  }
}
