#!/usr/bin/env bash
#
# NOTE: This file is used to build Cryptofuzz both on CI and OSS-Fuzz.
#

set -e
set -x
set -o pipefail

# Do differential fuzzing with Botan (and not OpenSSL) since NSS has
# symbol collisions with OpenSSL and therefore they can't be used together
# in Cryptofuzz.
export CRYPTOFUZZ_VERSION="3d2377257129fc5da6effb92b0736e31db147dee"
export BOTAN_VERSION="3.10.0"

git clone -q https://github.com/MozillaSecurity/cryptofuzz.git
git -C cryptofuzz checkout "$CRYPTOFUZZ_VERSION"

git clone -q https://github.com/randombit/botan.git
git -C botan checkout "$BOTAN_VERSION"

export CC="${CC-clang}"
export CCC="${CCC-clang++}"
export CXX="${CXX-clang++}"

# Default flags if CFLAGS is not set.
if [ -z "$CFLAGS" ]; then
    export CFLAGS="-fsanitize=address,fuzzer-no-link -O2 -g"
    export CXXFLAGS="-fsanitize=address,fuzzer-no-link -O2 -g"

    if [ "$1" = "--i386" ]; then
        # Make sure everything is compiled and linked with 32-bit.
        export CFLAGS="$CFLAGS -m32"
        export CXXFLAGS="$CXXFLAGS -m32"

        export LD_FLAGS="$LD_FLAGS -m32"
        export LINK_FLAGS="$LINK_FLAGS -m32"

        # Some static libraries aren't built on 32-bit systems, but still assumed
        # to exist by Cryptofuzz.
        sed -i "/libhw-acc-crypto-avx.a/d" cryptofuzz/modules/nss/Makefile
        sed -i "/libhw-acc-crypto-avx2.a/d" cryptofuzz/modules/nss/Makefile
    else
        # UBSan is only enabled for 64-bit builds of NSS.
        export CFLAGS="$CFLAGS -fsanitize=undefined"
        export CXXFLAGS="$CXXFLAGS -fsanitize=undefined"
    fi
fi

# Build Botan.
pushd botan
if [ "$1" = "--i386" ]; then
    ./configure.py --cpu=x86_32 \
                   --cc-bin=$CXX \
                   --cc-abi-flags="$CXXFLAGS" \
                   --disable-shared \
                   --disable-modules=locking_allocator \
                   --build-targets=static \
                   --without-documentation
else
    ./configure.py --cc-bin=$CXX \
                   --cc-abi-flags="$CXXFLAGS" \
                   --disable-shared \
                   --disable-modules=locking_allocator \
                   --build-targets=static \
                   --without-documentation
fi
make -j"$(nproc)"
popd

# Generate Cryptofuzz header.
pushd cryptofuzz
./gen_repository.py
popd

# Specify Cryptofuzz extra options.
pushd cryptofuzz
echo -n "\"--force-module=nss\"" > extra_options.h
popd

# Setup Botan module.
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BOTAN"
export LIBBOTAN_A_PATH="$(realpath botan/libbotan-3.a)"
export BOTAN_INCLUDE_PATH="$(realpath botan/build/include)"

# Build Botan module.
pushd cryptofuzz/modules/botan
make -j"$(nproc)"
popd

# Setup NSS module.
export NSS_NSPR_PATH="${SRC-$PWD}"
export CXXFLAGS="$CXXFLAGS -I $NSS_NSPR_PATH/dist/public/nss -I $NSS_NSPR_PATH/dist/Debug/include/nspr -DCRYPTOFUZZ_NSS -DCRYPTOFUZZ_NO_OPENSSL"
export LINK_FLAGS="$LINK_FLAGS -lsqlite3"

# On CI, the library lies somewhere else than what is expected by
# Cryptofuzz.
if [ ! -d "$NSS_NSPR_PATH/nspr/Debug/pr/src" ]; then
    sed -i "s/nspr\/Debug\/pr\/src/dist\/Debug\/lib/" cryptofuzz/modules/nss/Makefile
fi

# Build NSS module.
pushd cryptofuzz/modules/nss
make -j"$(nproc)"
popd

# Setup Cryptofuzz.
export LIBFUZZER_LINK="${LIB_FUZZING_ENGINE--fsanitize=fuzzer}"

# Build Cryptofuzz.
pushd cryptofuzz
make -j"$(nproc)"
popd

# Generate dictionary
pushd cryptofuzz
./generate_dict
popd

# Package
mkdir -p artifacts
tar cvfjh artifacts/cryptofuzz.tar.bz2 cryptofuzz
