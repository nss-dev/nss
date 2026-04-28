#!/usr/bin/env bash

# Build the sqlite3 command-line tool and install it into the NSS dist bin.
# Must be called after setup.sh has been sourced so that MSVC tools are in PATH.
#
# Usage: build_sqlite3.sh DIST_DIR SQLITE_SRC_DIR

set -v -e -x

DIST=$1
SQLITE_SRC=$2

OBJDIR=$(cat "${DIST}/latest")
BINDIR="${DIST}/${OBJDIR}/bin"

# Convert to Windows-style paths for cl.exe.
W_OUTFILE=$(cygpath -w "${BINDIR}/sqlite3.exe")
W_SQLITE_SRC=$(cygpath -w "${SQLITE_SRC}")

# MSYS2_ARG_CONV_EXCL="*" prevents MSYS2 from converting /flag arguments to
# Windows paths (e.g. /nologo -> C:/mozilla-build/msys2/nologo). Actual file
# paths are already Windows-style from cygpath above, so no conversion is needed.
MSYS2_ARG_CONV_EXCL="*" cl.exe /nologo \
    "/Fe${W_OUTFILE}" \
    /DSQLITE_THREADSAFE=1 /DNDEBUG /W0 \
    "/I${W_SQLITE_SRC}" \
    "${W_SQLITE_SRC}\\shell.c" \
    "${W_SQLITE_SRC}\\sqlite3.c"
