#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# libmpr5 is the foundational runtime; it does not link against other
# NSS or NSPR libraries.  Platform system libraries are picked up via
# OS_LIBS from the sections below.
#
# All ifeq/ifneq blocks MUST be here (not in manifest.mn) because
# OS_ARCH / OS_TARGET / CPU_ARCH are set by coreconf/config.mk which
# is included after manifest.mn in the standard NSS Makefile ordering.

# -----------------------------------------------------------------------
# Platform source selection — Windows vs. Unix
# -----------------------------------------------------------------------

ifeq (,$(filter-out WIN%,$(OS_TARGET)))
# ===== Windows =====
# Windows uses its own threading and I/O; no pthreads, no md/unix/ files.
CSRCS += \
    md/windows/ntio.c \
    md/windows/ntmisc.c \
    md/windows/ntthread.c \
    md/windows/ntsec.c \
    md/windows/ntsem.c \
    md/windows/ntinrval.c \
    md/windows/ntdllmn.c \
    md/windows/ntgc.c \
    md/windows/w95cv.c \
    md/windows/w95dllmain.c \
    md/windows/w95io.c \
    md/windows/w95sock.c \
    md/windows/w95thred.c \
    md/windows/w32ipcsem.c \
    md/windows/w32poll.c \
    md/windows/w32rng.c \
    md/windows/w32shm.c \
    md/windows/win32_errors.c \
    $(NULL)

else
# ===== Unix (Linux, macOS, FreeBSD, Solaris, AIX, …) =====
# Always use the pthreads implementation on Unix.
DEFINES += -D_PR_PTHREADS -UHAVE_CVAR_BUILT_ON_SEM

CSRCS += \
    pthreads/ptsynch.c \
    pthreads/ptio.c \
    pthreads/ptthread.c \
    pthreads/ptmisc.c \
    md/unix/unix.c \
    md/unix/unix_errors.c \
    md/unix/uxproces.c \
    md/unix/uxrng.c \
    md/unix/uxshm.c \
    md/unix/uxwrap.c \
    $(NULL)

# --- Per-OS implementation file and (where needed) assembly atomic-ops shim ---
# NSPR's configure.in selected these via PR_MD_CSRCS / PR_MD_ASFILES.
# Assembly is only needed where the OS/arch lacks _PR_HAVE_ATOMIC_OPS gcc builtins.

ifeq ($(OS_ARCH),Linux)
  CSRCS += md/unix/linux.c
  ifeq ($(CPU_ARCH),x86_64)
    ASFILES = md/unix/os_Linux_x86_64.s
  endif
  # ia64, ppc, x86 (32-bit) would need their own .s files; omitted for POC.
  #
  # Defines that NSPR configure.in set for Linux:
  # _LARGEFILE64_SOURCE — exposes off64_t/stat64 on glibc (needed by _unixos.h).
  # _GNU_SOURCE — conservative superset; enables secure_getenv, strdup, etc. on
  #   glibc < 2.20 where _DEFAULT_SOURCE alone isn't enough.  Safe alongside
  #   the _DEFAULT_SOURCE/_BSD_SOURCE/_POSIX_SOURCE already set by NSS coreconf.
  # HAVE_FCNTL_FILE_LOCKING — unix.c uses fcntl(F_SETLKW) for PR_LockFile.
  # HAVE_POINTER_LOCALTIME_R — prtime.c uses the re-entrant localtime_r().
  # HAVE_SECURE_GETENV — prenv.c uses secure_getenv() in SUID processes
  #   (available since glibc 2.17; safe to assume on any modern Linux).
  # HAVE_DLADDR — prlink.c uses dladdr() for PR_GetLibraryFilePathname().
  DEFINES += \
    -D_LARGEFILE64_SOURCE \
    -D_GNU_SOURCE \
    -DHAVE_FCNTL_FILE_LOCKING \
    -DHAVE_POINTER_LOCALTIME_R \
    -DHAVE_SECURE_GETENV \
    -DHAVE_DLADDR \
    $(NULL)
endif

ifeq ($(OS_ARCH),Darwin)
  CSRCS += md/unix/darwin.c
  ifeq ($(CPU_ARCH),x86_64)
    # Intel Mac: needs assembly atomic ops.
    ASFILES = md/unix/os_Darwin_x86_64.s
  endif
  # aarch64 (Apple Silicon): _PR_HAVE_ATOMIC_OPS via GCC __sync_* builtins;
  # no assembly file exists or is needed for that arch.
  #
  # Defines that NSPR configure.in set for Darwin:
  # HAVE_SOCKLEN_T — ptio.c socket calls; Darwin headers have socklen_t.
  # HAVE_POINTER_LOCALTIME_R — prtime.c re-entrant localtime_r().
  # HAVE_SECURE_GETENV — prenv.c; macOS has getenv() but not secure_getenv().
  #   Use __secure_getenv alias present since macOS 10.5 via _darwin.h if needed,
  #   or leave undefined (plain getenv() fallback is the safe default on macOS).
  # HAVE_DLADDR — prlink.c dladdr() for PR_GetLibraryFilePathname().
  DEFINES += \
    -DHAVE_SOCKLEN_T \
    -DHAVE_POINTER_LOCALTIME_R \
    -DHAVE_DLADDR \
    $(NULL)
  # Note: macOS does not have secure_getenv(); leaving HAVE_SECURE_GETENV unset
  # causes prenv.c to fall back to plain getenv(), which is correct on macOS.
endif

ifeq ($(OS_ARCH),FreeBSD)
  CSRCS += md/unix/freebsd.c
  # _freebsd.h sets _PR_HAVE_ATOMIC_OPS (GCC __sync_* builtins); no asm needed.
  DEFINES += \
    -DHAVE_SOCKLEN_T \
    -DHAVE_POINTER_LOCALTIME_R \
    -DHAVE_DLADDR \
    $(NULL)
endif

ifeq ($(OS_ARCH),NetBSD)
  CSRCS += md/unix/netbsd.c
  DEFINES += \
    -DHAVE_SOCKLEN_T \
    -DHAVE_POINTER_LOCALTIME_R \
    -DHAVE_DLADDR \
    $(NULL)
endif

ifeq ($(OS_ARCH),OpenBSD)
  CSRCS += md/unix/openbsd.c
  DEFINES += \
    -DHAVE_SOCKLEN_T \
    -DHAVE_POINTER_LOCALTIME_R \
    -DHAVE_DLADDR \
    $(NULL)
endif

ifeq ($(OS_ARCH),SunOS)
  CSRCS += md/unix/solaris.c
  ifeq ($(CPU_ARCH),x86_64)
    ASFILES = md/unix/os_SunOS_x86_64.s
  endif
  # Defines for modern Solaris (5.8+, the only supported target):
  # _LARGEFILE64_SOURCE — large file support.
  # _PR_INET6 — Solaris 5.8+ has full IPv6; _solaris.h gates on this.
  # _PR_HAVE_OFF64_T — _unixos.h gates on this for stat64/off64_t types.
  # HAVE_POINTER_LOCALTIME_R — prtime.c re-entrant localtime_r().
  DEFINES += \
    -D_LARGEFILE64_SOURCE \
    -D_PR_INET6 \
    -D_PR_HAVE_OFF64_T \
    -DHAVE_POINTER_LOCALTIME_R \
    $(NULL)
endif

ifeq ($(OS_ARCH),AIX)
  CSRCS += md/unix/aix.c md/unix/aixwrap.c
  ASFILES = md/unix/os_AIX.s
  # Defines for AIX 4.3+ (minimum supported release):
  # _PR_INET6 — AIX 4.3+ has IPv6; _aix.h gates on this.
  # _PR_HAVE_OFF64_T — large file offset type selection in _unixos.h.
  # AIX4_3_PLUS — unlocks AIX 4.3+ code paths in _aix.h.
  # HAVE_SOCKLEN_T — AIX 4.3+ has socklen_t in sys/socket.h.
  # HAVE_FCNTL_FILE_LOCKING — unix.c fcntl(F_SETLKW) file locking.
  # HAVE_POINTER_LOCALTIME_R — prtime.c re-entrant localtime_r().
  DEFINES += \
    -D_PR_INET6 \
    -D_PR_HAVE_OFF64_T \
    -DAIX4_3_PLUS \
    -DHAVE_SOCKLEN_T \
    -DHAVE_FCNTL_FILE_LOCKING \
    -DHAVE_POINTER_LOCALTIME_R \
    $(NULL)
endif

endif  # !Windows

# -----------------------------------------------------------------------
# Compiler-specific flags — GCC/Clang only, not MSVC
# -----------------------------------------------------------------------

# _PR_HAS_PRAGMA_DIAGNOSTIC: lets prvrsion.c suppress -Wunused-but-set-variable
#   via the pragma guards already present in that file.
# -Wno-shadow: NSPR code was not written under NSS's -Wshadow -Werror regime.
# On Windows+MSVC (NS_USE_GCC not set) skip all of these.
ifeq (,$(filter-out WIN%,$(OS_TARGET)))
  ifdef NS_USE_GCC
    # Windows + GCC/MinGW
    DEFINES += -D_PR_HAS_PRAGMA_DIAGNOSTIC
    CFLAGS  += -Wno-shadow -Wno-error=shadow
  endif
  # else: MSVC — different warning system, pragmas not needed
else
  # All non-Windows platforms use GCC or Clang
  DEFINES += -D_PR_HAS_PRAGMA_DIAGNOSTIC
  CFLAGS  += -Wno-shadow -Wno-error=shadow
endif

# -----------------------------------------------------------------------
# prcpucfg.h selection
# Installed by install_mpr_md in Makefile as dist/public/nss/prcpucfg.h.
# -----------------------------------------------------------------------

ifeq ($(OS_ARCH),Linux)
  MPR_CPUCFG_H = _linux.cfg
endif
ifeq ($(OS_ARCH),Darwin)
  MPR_CPUCFG_H = _darwin.cfg
endif
ifeq ($(OS_ARCH),SunOS)
  MPR_CPUCFG_H = _solaris.cfg
endif
ifeq ($(OS_ARCH),WINNT)
  MPR_CPUCFG_H = _winnt.cfg
endif
ifeq ($(OS_ARCH),AIX)
  ifdef USE_64
    MPR_CPUCFG_H = _aix64.cfg
  else
    MPR_CPUCFG_H = _aix32.cfg
  endif
endif
ifeq ($(OS_ARCH),FreeBSD)
  MPR_CPUCFG_H = _freebsd.cfg
endif
ifeq ($(OS_ARCH),NetBSD)
  MPR_CPUCFG_H = _netbsd.cfg
endif
ifeq ($(OS_ARCH),OpenBSD)
  MPR_CPUCFG_H = _openbsd.cfg
endif
ifeq ($(OS_ARCH),NTO)
  MPR_CPUCFG_H = _nto.cfg
endif

# -----------------------------------------------------------------------
# Platform OS_LIBS
# -----------------------------------------------------------------------

ifeq ($(OS_TARGET),SunOS)
  OS_LIBS += -lkstat -lrt
endif

ifeq ($(OS_TARGET),AIX)
  OS_LIBS += -lpthread
endif

ifeq (,$(filter-out WIN%,$(OS_TARGET)))
  ifdef NS_USE_GCC
    OS_LIBS += -ladvapi32 -lws2_32 -lwinmm
  else
    OS_LIBS += advapi32.lib ws2_32.lib winmm.lib
  endif
endif

ifdef NSS_FIPS_140_3
  DEFINES += -DNSS_FIPS_140_3
endif
