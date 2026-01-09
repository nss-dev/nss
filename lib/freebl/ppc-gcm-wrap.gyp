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
      'ppc-gcm.s',
      'ppc-gcm-wrap.c',
    ],
    'dependencies': [
      '<(DEPTH)/exports.gyp:nss_exports'
    ],
    'conditions': [
      [ 'OS=="linux"', {
        'defines': [
          'FREEBL_NO_DEPEND',
        ],
      }],
    ],
  },
  'targets': [
    {
      'target_name': 'ppc-gcm-wrap-nodepend_c_lib',
    },
    {
      'target_name': 'ppc-gcm-wrap_c_lib',
      'defines!': [
        'FREEBL_NO_DEPEND',
      ],
    },
  ],
  'variables': {
    'module': 'nss',
  }
}
