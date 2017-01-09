# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
{
  'includes': [
    '../coreconf/config.gypi',
    '../cmd/platlibs.gypi'
  ],
  'targets': [
    {
      'target_name': 'libFuzzer',
      'type': 'static_library',
      'sources': [
        'libFuzzer/FuzzerCrossOver.cpp',
        'libFuzzer/FuzzerDriver.cpp',
        'libFuzzer/FuzzerExtFunctionsDlsym.cpp',
        'libFuzzer/FuzzerExtFunctionsWeak.cpp',
        'libFuzzer/FuzzerIO.cpp',
        'libFuzzer/FuzzerLoop.cpp',
        'libFuzzer/FuzzerMutate.cpp',
        'libFuzzer/FuzzerSHA1.cpp',
        'libFuzzer/FuzzerTracePC.cpp',
        'libFuzzer/FuzzerTraceState.cpp',
        'libFuzzer/FuzzerUtil.cpp',
        'libFuzzer/FuzzerUtilDarwin.cpp',
        'libFuzzer/FuzzerUtilLinux.cpp',
      ],
      'direct_dependent_settings': {
        'include_dirs': [
          'libFuzzer',
        ],
      }
    },
    {
      'target_name': 'nssfuzz',
      'type': 'executable',
      'sources': [
        'asn1_mutators.cc',
        'nssfuzz.cc',
        'pkcs8_target.cc',
        'quickder_targets.cc',
      ],
      'dependencies': [
        '<(DEPTH)/exports.gyp:nss_exports',
        'libFuzzer',
      ],
    }
  ],
  'target_defaults': {
    'variables': {
      'debug_optimization_level': '2',
    },
    'cflags/': [
      ['exclude', '-fsanitize-coverage'],
    ],
    'xcode_settings': {
      'OTHER_CFLAGS/': [
        ['exclude', '-fsanitize-coverage'],
      ],
    },
  },
  'variables': {
    'module': 'nss',
  }
}
