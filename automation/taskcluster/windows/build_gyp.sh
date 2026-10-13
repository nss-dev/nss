#!/usr/bin/env bash

set -v -e -x

# Parse for the -t option.
m=x64
for i in "$@"; do
    case "$i" in
        -t|--target) m= ;;
        --target=*) m="${i#*=}" ;;
        *) [[ -z "$m" ]] && m="$i" ;;
    esac
done
[[ "$m" == "ia32" ]] && m=x86
source "$(dirname "$0")/setup.sh"

# Install gyp-next, as the macOS build does. chromium's original gyp has no
# ARM64 support at all: its MsvsSettings.GetArch() maps only Win32 and x64 and
# silently falls back to x86 for everything else, so an ARM64 configuration
# would quietly build for x86.
source "$(dirname "$0")/../scripts/install_gyp.sh"
install_gyp gyp-env

export PATH="${PATH}:${PWD}/ninja/bin"

test -v VCS_PATH

# builds write to the source dir (and its parent), so move the source trees to
# our workspace from the (cached) checkout dir
cp -a "${VCS_PATH}/nss" .
bash "$(dirname "$0")/../scripts/clone_nspr.sh"

pushd nspr
if [[ -f ../nss/nspr.patch && "$ALLOW_NSPR_PATCH" == "1" ]]; then
  cat ../nss/nspr.patch | patch -p1
fi
popd

make () {
	mozmake "$@"
}
export -f make

# Build with gyp.
./nss/build.sh -g -v --enable-libpkix -Denable_draft_hpke=1 "$@"

# Build sqlite3 CLI tool for use by dbtests.
bash "$(dirname "$0")/build_sqlite3.sh" dist nss/lib/sqlite

# A cross build's tests run on a different machine, which has no CRT for the
# target (and in any case none as new as the toolchain's). Ship the VC runtime
# next to the executables, since Windows looks in an executable's directory
# first, including for the DLLs in dist/$(cat dist/latest)/lib. The UCRT is not
# needed: it is part of Windows 10 and later, which ignore an app-local copy.
if [ "$m" == "arm64" ]; then
    cp "${WIN32_REDIST_DIR}"/*.dll "dist/$(cat dist/latest)/bin/"
fi

# Package.
7z a public/build/dist.7z dist
