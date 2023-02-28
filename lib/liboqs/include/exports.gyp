# DO NOT EDIT: generated from  exports.gyp.template
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
{
  'includes': [
    '../../../coreconf/config.gypi'
  ],
  'targets': [
    {
      'target_name': 'lib_oqs_include_exports',
      'type': 'none',
      'copies': [
        {
          'files': [
            './oqs/oqsconfig.h',
            './oqs/oqs.h',
            './oqs/common.h',
            './oqs/rand.h',
            './oqs/aes.h',
            './oqs/sha2.h',
            './oqs/sha3.h',
            './oqs/sha3x4.h',
            './oqs/kem.h',
            './oqs/sig.h',
            './oqs/kem_kyber.h',
            './oqs/sig_dilithium.h',
            './oqs/sig_falcon.h',
            './oqs/sig_sphincs.h',
          ],
          'destination': '<(nss_private_dist_dir)/<(module)/oqs'
        }
      ]
    }
  ],
  'variables': {
    'module': 'oqs'
  }
}

