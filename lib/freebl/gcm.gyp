# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
{
  'includes': [
    '../../coreconf/config.gypi'
  ],
  'target_defaults': {
    'type': 'static_library',
    'sources': [
      'gcm.c',
    ],
    'dependencies': [
      '<(DEPTH)/exports.gyp:nss_exports'
    ],
    'conditions': [
      [ 'target_arch=="ia32" or target_arch=="x64"', {
        'dependencies': [
          'ghash.gyp:ghash-aes-x86_c_lib',
        ],
        'defines': [
          'HAVE_PLATFORM_GHASH'
        ]
      }],
      [ 'disable_arm32_neon==0 and target_arch=="arm"', {
        'dependencies': [
          'ghash.gyp:ghash-aes-arm32-neon_c_lib',
        ],
        'defines': [
          'HAVE_PLATFORM_GHASH'
        ]
      }],
      [ 'target_arch=="arm64" or target_arch=="aarch64"', {
        'dependencies': [
          'ghash.gyp:ghash-aes-aarch64_c_lib',
        ],
        'defines': [
          'HAVE_PLATFORM_GHASH'
        ]
      }],
      [ 'target_arch=="ppc64" or target_arch=="ppc64le"', {
        'dependencies': [
          'ghash.gyp:ghash-aes-ppc_c_lib',
        ],
        'defines': [
          'HAVE_PLATFORM_GHASH'
        ]
      }],
      [ 'OS=="linux"', {
        'defines': [
          'FREEBL_NO_DEPEND',
        ],
      }],
    ],
  },
  'targets': [
    {
      'target_name': 'gcm-nodepend',
      'conditions': [
        [ '(OS=="win" and cc_use_gnu_ld!=1 and (target_arch=="ia32" or target_arch=="x64")) or (target_arch=="x64" and OS!="win")', {
          'dependencies': [
            'intel-gcm-wrap.gyp:intel-gcm-wrap-nodepend_c_lib',
          ],
          'defines': [
            'HAVE_PLATFORM_GCM'
          ],
        }],
        [ 'disable_altivec==0 and target_arch=="ppc64le"', {
          'dependencies': [
            'ppc-gcm-wrap.gyp:ppc-gcm-wrap-nodepend_c_lib',
          ],
          'defines': [
            'HAVE_PLATFORM_GCM'
          ],
        }],
      ],
    },
    {
      'target_name': 'gcm',
      'conditions': [
        [ '(OS=="win" and cc_use_gnu_ld!=1 and (target_arch=="ia32" or target_arch=="x64")) or (target_arch=="x64" and OS!="win")', {
          'dependencies': [
            'intel-gcm-wrap.gyp:intel-gcm-wrap_c_lib',
          ],
          'defines': [
            'HAVE_PLATFORM_GCM'
          ],
        }],
        [ 'disable_altivec==0 and target_arch=="ppc64le"', {
          'dependencies': [
            'ppc-gcm-wrap.gyp:ppc-gcm-wrap_c_lib',
          ],
          'defines': [
            'HAVE_PLATFORM_GCM'
          ],
        }],
      ],
      'defines!': [
        'FREEBL_NO_DEPEND',
      ],
    },
  ],
  'variables': {
    'module': 'nss',
  }
}
