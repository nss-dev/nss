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
      'target_name': 'oqs_src_sig_dilithium_pqcrystals-dilithium_dilithium3_ref',
      'type': 'static_library',
      'sources': [
            'ntt.c',
            'packing.c',
            'poly.c',
            'polyvec.c',
            'reduce.c',
            'rounding.c',
            'sign.c',
            'symmetric-shake.c',
      ],
      'dependencies': [
        '<(DEPTH)/exports.gyp:nss_exports'
      ]
    }
  ],
  'target_defaults': {
    'defines': [
            'DILITHIUM_MODE=3',
            'DILITHIUM_RANDOMIZED_SIGNING',
    ],
    'include_dirs': [
      '<(DEPTH)/lib/liboqs/src/common/pqclean_shims',
      '<(DEPTH)/lib/liboqs/src/common/sha3/xkcp_low/KeccakP-1600/plain-64bits',
    ],
    [ 'OS=="mac"', {
        'defines': [
            'OQS_HAVE_POSIX_MEMALIGN',
            'OQS_HAVE_ALIGNED_ALLOC',
            'OQS_HAVE_MEMALIGN'
        ]
    }]
  },
  'variables': {
    'module': 'oqs'
  }
}
