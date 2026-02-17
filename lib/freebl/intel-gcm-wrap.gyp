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
      'intel-gcm-wrap.c',
    ],
    'dependencies': [
      '<(DEPTH)/exports.gyp:nss_exports'
    ],
    'cflags': [
      '-mssse3',
    ],
    'cflags_mozilla': [
      '-mssse3'
    ],
    'conditions': [
      [ 'OS=="linux"', {
        'defines': [
          'FREEBL_NO_DEPEND',
        ],
      }],
      [ 'OS=="win" and cc_use_gnu_ld!=1', {
        'conditions': [
          [ 'target_arch=="ia32"', {
            'sources': [
              'intel-aes-x86-masm.asm',
              'intel-gcm-x86-masm.asm',
            ],
          }],
          [ 'target_arch=="x64"', {
            'sources': [
              'intel-aes-x64-masm.asm',
              'intel-gcm-x64-masm.asm',
            ],
          }],
        ],
      }],
      [ 'target_arch=="x64" and OS!="win"', {
        'sources': [
          'intel-aes.S',
          'intel-gcm.S',
        ],
      }],
    ],
  },
  'targets': [
    {
      'target_name': 'intel-gcm-wrap-nodepend_c_lib',
    },
    {
      'target_name': 'intel-gcm-wrap_c_lib',
      'defines!': [
        'FREEBL_NO_DEPEND',
      ],
    },
  ],
  'variables': {
    'module': 'nss',
  }
}
