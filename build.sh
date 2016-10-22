#!/bin/bash
# This script builds NSS with gyp and ninja.
#
# This build system is still under development.  It does not yet support all
# the features or platforms that NSS supports.
#
# -c = clean before build
# -g = force a rebuild of gyp (and NSPR, because why not)

set -e

CWD=$(cd $(dirname $0); pwd -P)
OBJ_DIR=$(make platform)
DIST_DIR="$CWD/../dist/$OBJ_DIR"

if [ -n "$CCC" ] && [ -z "$CXX" ]; then
    export CXX="$CCC"
fi

# -c = clean first
if [ "$1" = "-c" ]; then
    rm -rf "$CWD/out"
fi

if [ "$BUILD_OPT" = "1" ]; then
    TARGET=Release
else
    TARGET=Debug
fi
TARGET_DIR="$CWD/out/$TARGET"
if [ "$USE_64" != "1" ]; then
    GYP_PARAMS="-Dtarget_arch=ia32"
fi

# These steps can take a while, so don't overdo them.
# Force a redo with -g.
if [ "$1" = "-g" -o ! -d "$TARGET_DIR" ]; then
    # Build NSPR.
    make NSS_GYP=1 install_nspr

    # Run gyp.
    PKG_CONFIG_PATH="$CWD/../nspr/$OBJ_DIR/config" $SCANBUILD \
        gyp -f ninja $GYP_PARAMS --depth=. --generator-output="." nss.gyp
fi

# Run ninja.
if which ninja >/dev/null 2>&1; then
    NINJA=ninja
elif which ninja-build >/dev/null 2>&1; then
    NINJA=ninja-build
else
    echo "Please install ninja" 1>&2
    exit 1
fi
$NINJA -C "$TARGET_DIR"
