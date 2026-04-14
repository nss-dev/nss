# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
{
  'includes': [
    '../../coreconf/config.gypi'
  ],
  'targets': [
    {
      'target_name': 'lib_mpr_exports',
      'type': 'none',
      # prcpucfg.h is platform-specific: the classic make build renames the
      # right .cfg file via the install_mpr_md rule.  Here we use target-level
      # conditions so each OS gets its own action that copies the correct
      # source with the required output name.
      'conditions': [
        ['mozilla_client==0', {
          'conditions': [
            ['OS=="linux" or OS=="android"', {
              'actions': [{
                'action_name': 'install_prcpucfg',
                'inputs':  ['include/md/_linux.cfg'],
                'outputs': ['<(nss_public_dist_dir)/<(module)/prcpucfg.h'],
                'action':  ['cp', 'include/md/_linux.cfg',
                                  '<(nss_public_dist_dir)/<(module)/prcpucfg.h'],
              }],
            }],
            ['OS=="mac" or OS=="ios"', {
              'actions': [{
                'action_name': 'install_prcpucfg',
                'inputs':  ['include/md/_darwin.cfg'],
                'outputs': ['<(nss_public_dist_dir)/<(module)/prcpucfg.h'],
                'action':  ['cp', 'include/md/_darwin.cfg',
                                  '<(nss_public_dist_dir)/<(module)/prcpucfg.h'],
              }],
            }],
            ['OS=="win"', {
              'actions': [{
                'action_name': 'install_prcpucfg',
                'inputs':  ['include/md/_winnt.cfg'],
                'outputs': ['<(nss_public_dist_dir)/<(module)/prcpucfg.h'],
                'action':  ['cp', 'include/md/_winnt.cfg',
                                  '<(nss_public_dist_dir)/<(module)/prcpucfg.h'],
              }],
            }],
            ['OS=="freebsd" or OS=="dragonfly"', {
              'actions': [{
                'action_name': 'install_prcpucfg',
                'inputs':  ['include/md/_freebsd.cfg'],
                'outputs': ['<(nss_public_dist_dir)/<(module)/prcpucfg.h'],
                'action':  ['cp', 'include/md/_freebsd.cfg',
                                  '<(nss_public_dist_dir)/<(module)/prcpucfg.h'],
              }],
            }],
            ['OS=="netbsd"', {
              'actions': [{
                'action_name': 'install_prcpucfg',
                'inputs':  ['include/md/_netbsd.cfg'],
                'outputs': ['<(nss_public_dist_dir)/<(module)/prcpucfg.h'],
                'action':  ['cp', 'include/md/_netbsd.cfg',
                                  '<(nss_public_dist_dir)/<(module)/prcpucfg.h'],
              }],
            }],
            ['OS=="openbsd"', {
              'actions': [{
                'action_name': 'install_prcpucfg',
                'inputs':  ['include/md/_openbsd.cfg'],
                'outputs': ['<(nss_public_dist_dir)/<(module)/prcpucfg.h'],
                'action':  ['cp', 'include/md/_openbsd.cfg',
                                  '<(nss_public_dist_dir)/<(module)/prcpucfg.h'],
              }],
            }],
            ['OS=="solaris"', {
              'actions': [{
                'action_name': 'install_prcpucfg',
                'inputs':  ['include/md/_solaris.cfg'],
                'outputs': ['<(nss_public_dist_dir)/<(module)/prcpucfg.h'],
                'action':  ['cp', 'include/md/_solaris.cfg',
                                  '<(nss_public_dist_dir)/<(module)/prcpucfg.h'],
              }],
            }],
          ],
        }],
      ],
      'copies': [
        {
          'files': [
            'include/nspr.h',
            'include/plarena.h',
            'include/plbase64.h',
            'include/plerror.h',
            'include/plgetopt.h',
            'include/plhash.h',
            'include/plstr.h',
            'include/pratom.h',
            'include/prbit.h',
            'include/prclist.h',
            'include/prcmon.h',
            'include/prcountr.h',
            'include/prcvar.h',
            'include/prdtoa.h',
            'include/prenv.h',
            'include/prerr.h',
            'include/prerror.h',
            'include/prinet.h',
            'include/prinit.h',
            'include/prinrval.h',
            'include/prio.h',
            'include/pripcsem.h',
            'include/prlink.h',
            'include/prlock.h',
            'include/prlog.h',
            'include/prlong.h',
            'include/prmem.h',
            'include/prmon.h',
            'include/prmwait.h',
            'include/prnetdb.h',
            'include/prolock.h',
            'include/prpdce.h',
            'include/prprf.h',
            'include/prproces.h',
            'include/prrng.h',
            'include/prrwlock.h',
            'include/prshm.h',
            'include/prshma.h',
            'include/prsystem.h',
            'include/prthread.h',
            'include/prtime.h',
            'include/prtpool.h',
            'include/prtrace.h',
            'include/prtypes.h',
            'include/prvrsion.h',
          ],
          'destination': '<(nss_public_dist_dir)/<(module)'
        },
        {
          'files': [
            'include/private/pprio.h',
            'include/private/pprmwait.h',
            'include/private/pprthred.h',
            'include/private/primpl.h',
            'include/private/prpriv.h',
          ],
          'destination': '<(nss_private_dist_dir)/<(module)'
        },
        {
          # prpriv.h uses #include "private/pprio.h" (with the "private/"
          # prefix), so the private headers must also live one level deeper.
          'files': [
            'include/private/pprio.h',
            'include/private/pprmwait.h',
            'include/private/pprthred.h',
            'include/private/primpl.h',
            'include/private/prpriv.h',
          ],
          'destination': '<(nss_private_dist_dir)/<(module)/private'
        }
      ]
    }
  ],
  'variables': {
    'module': 'nss'
  }
}
