# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
{
  'includes': [
    '../../coreconf/config.gypi'
  ],
  'targets': [
    {
      # Static archive: all MPR source files.
      'target_name': 'mpr',
      'type': 'static_library',
      # Headers live in include/, include/private/, include/md/, include/obsolete/
      # relative to this directory.
      'include_dirs': [
        'include',
        'include/private',
        'include/md',
        'include/obsolete',
      ],
      # Cross-platform core sources (no platform-conditional code here).
      'sources': [
        'io/prfdcach.c',
        'io/prmwait.c',
        'io/prmapopt.c',
        'io/priometh.c',
        'io/pripv6.c',
        'io/prlayer.c',
        'io/prlog.c',
        'io/prmmap.c',
        'io/prpolevt.c',
        'io/prprf.c',
        'io/prscanf.c',
        'io/prstdio.c',
        'linking/prlink.c',
        'malloc/prmalloc.c',
        'malloc/prmem.c',
        'md/prosdep.c',
        'memory/prshm.c',
        'memory/prshma.c',
        'memory/prseg.c',
        'misc/pralarm.c',
        'misc/pratom.c',
        'misc/prcountr.c',
        'misc/prdtoa.c',
        'misc/prenv.c',
        'misc/prerr.c',
        'misc/prerror.c',
        'misc/prerrortable.c',
        'misc/prinit.c',
        'misc/prinrval.c',
        'misc/pripc.c',
        'misc/prlog2.c',
        'misc/prlong.c',
        'misc/prnetdb.c',
        'misc/praton.c',
        'misc/prolock.c',
        'misc/prrng.c',
        'misc/prsystem.c',
        'misc/prthinfo.c',
        'misc/prtpool.c',
        'misc/prtrace.c',
        'misc/prtime.c',
        'threads/prcmon.c',
        'threads/prrwlock.c',
        'threads/prtpd.c',
        # Only prvrsion.c: plvrsion.c and plcvrsion.c also define
        # libVersionPoint() which would conflict in a merged DSO.
        'prvrsion.c',
        # Former libplds4 (data structures)
        'plarena.c',
        'plhash.c',
        # Former libplc4 (string utilities, base64, getopt)
        'base64.c',
        'plerror.c',
        'plgetopt.c',
        'strcase.c',
        'strcat.c',
        'strchr.c',
        'strcmp.c',
        'strcpy.c',
        'strdup.c',
        'strlen.c',
        'strpbrk.c',
        'strstr.c',
        'strtok.c',
      ],
      'conditions': [
        # ---------------------------------------------------------------
        # Windows: md/windows/ threading/io, no pthreads, no md/unix/
        # ---------------------------------------------------------------
        [ 'OS=="win"', {
          'sources': [
            'md/windows/ntio.c',
            'md/windows/ntmisc.c',
            'md/windows/ntthread.c',
            'md/windows/ntsec.c',
            'md/windows/ntsem.c',
            'md/windows/ntinrval.c',
            'md/windows/ntdllmn.c',
            'md/windows/ntgc.c',
            'md/windows/w95cv.c',
            'md/windows/w95dllmain.c',
            'md/windows/w95io.c',
            'md/windows/w95sock.c',
            'md/windows/w95thred.c',
            'md/windows/w32ipcsem.c',
            'md/windows/w32poll.c',
            'md/windows/w32rng.c',
            'md/windows/w32shm.c',
            'md/windows/win32_errors.c',
          ],
          'libraries': ['advapi32.lib', 'ws2_32.lib', 'winmm.lib'],
        }],
        # ---------------------------------------------------------------
        # Unix: pthreads + md/unix/ common files
        # ---------------------------------------------------------------
        [ 'OS!="win"', {
          'sources': [
            'pthreads/ptsynch.c',
            'pthreads/ptio.c',
            'pthreads/ptthread.c',
            'pthreads/ptmisc.c',
            'md/unix/unix.c',
            'md/unix/unix_errors.c',
            'md/unix/uxproces.c',
            'md/unix/uxrng.c',
            'md/unix/uxshm.c',
            'md/unix/uxwrap.c',
          ],
          'defines': [
            '_PR_PTHREADS',
            '_PR_HAS_PRAGMA_DIAGNOSTIC',
          ],
          # NSPR code wasn't written under NSS's -Wshadow -Werror regime.
          # Remove -Wshadow from the merged cflags so it doesn't become fatal.
          'cflags!': ['-Wshadow'],
          'libraries': ['-lpthread'],
        }],
        # --- Linux and Android (same kernel, same md file) ---
        [ 'OS=="linux" or OS=="android"', {
          'sources': [
            'md/unix/linux.c',
          ],
          'defines': [
            '_LARGEFILE64_SOURCE',
            '_GNU_SOURCE',
            'HAVE_FCNTL_FILE_LOCKING',
            'HAVE_POINTER_LOCALTIME_R',
            'HAVE_SECURE_GETENV',
            'HAVE_DLADDR',
          ],
          'conditions': [
            [ 'target_arch=="x64"', {
              'sources': ['md/unix/os_Linux_x86_64.s'],
            }],
          ],
        }],
        # --- macOS / iOS ---
        [ 'OS=="mac" or OS=="ios"', {
          'sources': [
            'md/unix/darwin.c',
          ],
          'defines': [
            'HAVE_SOCKLEN_T',
            'HAVE_POINTER_LOCALTIME_R',
            'HAVE_DLADDR',
          ],
          'conditions': [
            [ 'target_arch=="x64"', {
              'sources': ['md/unix/os_Darwin_x86_64.s'],
            }],
          ],
          'xcode_settings': {
            'WARNING_CFLAGS': ['-Wno-shadow'],
          },
        }],
        # --- FreeBSD / DragonFly ---
        [ 'OS=="freebsd" or OS=="dragonfly"', {
          'sources': ['md/unix/freebsd.c'],
          'defines': [
            'HAVE_SOCKLEN_T',
            'HAVE_POINTER_LOCALTIME_R',
            'HAVE_DLADDR',
          ],
        }],
        # --- NetBSD ---
        [ 'OS=="netbsd"', {
          'sources': ['md/unix/netbsd.c'],
          'defines': [
            'HAVE_SOCKLEN_T',
            'HAVE_POINTER_LOCALTIME_R',
            'HAVE_DLADDR',
          ],
        }],
        # --- OpenBSD ---
        [ 'OS=="openbsd"', {
          'sources': ['md/unix/openbsd.c'],
          'defines': [
            'HAVE_SOCKLEN_T',
            'HAVE_POINTER_LOCALTIME_R',
            'HAVE_DLADDR',
          ],
        }],
        # --- Solaris ---
        [ 'OS=="solaris"', {
          'sources': ['md/unix/solaris.c'],
          'defines': [
            '_LARGEFILE64_SOURCE',
            '_PR_INET6',
            '_PR_HAVE_OFF64_T',
            'HAVE_POINTER_LOCALTIME_R',
          ],
          'conditions': [
            [ 'target_arch=="x64"', {
              'sources': ['md/unix/os_SunOS_x86_64.s'],
            }],
          ],
          'libraries': ['-lkstat', '-lrt'],
        }],
      ],
      'dependencies': [
        'exports.gyp:lib_mpr_exports',
      ],
    },
    {
      # Shared library: thin wrapper that re-exports the static archive.
      'target_name': 'mpr5',
      'type': 'shared_library',
      'dependencies': [
        'mpr',
      ],
      'variables': {
        'mapfile': 'mpr.def',
      },
      # mpr5 IS the NSPR replacement; it must not link against itself.
      # target_defaults injects nspr_libs into every shared_library.
      # nspr_libs may be '-lmpr5' (standalone NSS) or 'mpr5' (bare, when
      # built inside Firefox via gyp_vars["nspr_libs"]="mpr5"). Remove both.
      'conditions': [
        [ 'OS=="win"', {
          'libraries!': ['libmpr5.lib'],
        }, {
          'libraries!': ['-lmpr5', 'mpr5'],
        }],
      ],
    },
  ],
  'variables': {
    'module': 'nss'
  }
}
