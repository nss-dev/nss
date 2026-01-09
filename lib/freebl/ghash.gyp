# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
{
  'includes': [
    '../../coreconf/config.gypi'
  ],
  'targets': [
    {
      'target_name': 'ghash-aes-x86_c_lib',
      'type': 'static_library',
      'sources': [
        'ghash-x86.c', 'aes-x86.c'
      ],
      'dependencies': [
        '<(DEPTH)/exports.gyp:nss_exports'
      ],
      # Enable isa option for pclmul and aes-ni; supported since gcc 4.4.
      # This is only supported by x84/x64. It's not needed for Windows,
      # unless clang-cl is used.
      'cflags_mozilla': [
        '-mpclmul', '-maes'
      ],
      'conditions': [
        [ 'OS=="linux" or OS=="android" or OS=="dragonfly" or OS=="freebsd" or OS=="netbsd" or OS=="openbsd"', {
          'cflags': [
            '-mpclmul', '-maes'
          ],
        }],
        # macOS build doesn't use cflags.
        [ 'OS=="mac" or OS=="ios"', {
          'xcode_settings': {
            'OTHER_CFLAGS': [
              '-mpclmul', '-maes'
            ],
          },
        }]
      ]
    },
    {
      'target_name': 'ghash-aes-arm32-neon_c_lib',
      'type': 'static_library',
      'sources': [
        'ghash-arm32-neon.c'
      ],
      'dependencies': [
        '<(DEPTH)/exports.gyp:nss_exports'
      ],
      'cflags': [
        '-march=armv7',
        '-mfpu=neon',
        '<@(softfp_cflags)',
      ],
      'cflags_mozilla': [
        '-mfpu=neon',
        '<@(softfp_cflags)',
      ]
    },
    {
      'target_name': 'ghash-aes-aarch64_c_lib',
      'type': 'static_library',
      'sources': [
        'ghash-aarch64.c'
      ],
      'dependencies': [
        '<(DEPTH)/exports.gyp:nss_exports'
      ],
      'cflags': [
        '-march=armv8-a+crypto'
      ],
      'cflags_mozilla': [
        '-march=armv8-a+crypto'
      ]
    },
    {
      'target_name': 'ghash-aes-ppc_c_lib',
      'type': 'static_library',
      'sources': [
        'ghash-ppc.c',
      ],
      'dependencies': [
        '<(DEPTH)/exports.gyp:nss_exports'
      ],
      'conditions': [
        [ 'disable_crypto_vsx==0', {
          'cflags': [
            '-mcrypto',
            '-maltivec'
           ],
           'cflags_mozilla': [
             '-mcrypto',
             '-maltivec'
           ],
        }, 'disable_crypto_vsx==1', {
          'cflags': [
            '-maltivec'
          ],
          'cflags_mozilla': [
            '-maltivec'
          ],
        }],
      ]
    },
  ],
  'variables': {
    'module': 'nss',
  }
}
