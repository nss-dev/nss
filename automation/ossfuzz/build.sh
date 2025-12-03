#!/bin/bash -eu
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
################################################################################

# List of targets disabled for oss-fuzz.
declare -A disabled=()

# Helper function that copies a fuzzer binary and its seed corpus.
copy_fuzzer()
{
    local fuzzer=$1
    local name=$2

    # Copy the binary.
    cp ../dist/Debug/bin/$fuzzer $OUT/$name

    # Zip and copy the corpus, if any.
    if [ -d "$SRC/nss-corpus/$name" ]; then
        zip $OUT/${name}_seed_corpus.zip $SRC/nss-corpus/$name/*
    fi
}

# Copy libFuzzer options
cp fuzz/options/*.options $OUT/

# Build the library (non-TLS fuzzing mode).
CXX="$CXX -stdlib=libc++" LDFLAGS="$CFLAGS" \
    ./build.sh -c -v --fuzz=oss --fuzz --disable-tests

# Copy fuzzing targets.
for fuzzer in $(find ../dist/Debug/bin -name "nssfuzz-*" -printf "%f\n"); do
    name=${fuzzer:8}
    if [ -z "${disabled[$name]:-}" ]; then
        [ -f "fuzz/options/${name}-no_fuzzer_mode.options" ] && name="${name}-no_fuzzer_mode"
        copy_fuzzer $fuzzer $name
    fi
done

# Build Cryptofuzz.
# We want to build with the non-TLS fuzzing mode version of NSS.
./automation/taskcluster/scripts/build_cryptofuzz.sh

# Copy dictionary and fuzz target.
cp ./cryptofuzz/cryptofuzz-dict.txt $OUT/cryptofuzz.dict
cp ./cryptofuzz/cryptofuzz $OUT/cryptofuzz

# Zip and copy the corpus, if any.
if [ -d "$SRC/nss-corpus/cryptofuzz" ]; then
    zip $OUT/cryptofuzz_seed_corpus.zip $SRC/nss-corpus/cryptofuzz/*
fi

# TLS Fuzzing mode: Totally Lacking Security
# This mode disables a lot of cryptography to help the fuzzer.
# It was originally used for the TLS-specific fuzzers but has been generalized.
# Build the library again (TLS fuzzing mode).
CXX="$CXX -stdlib=libc++" LDFLAGS="$CFLAGS" \
    ./build.sh -c -v --fuzz=oss --fuzz=tls --disable-tests

for fuzzer in $(find ../dist/Debug/bin -name "nssfuzz-*" -printf "%f\n"); do
     name=${fuzzer:8}
     if [ -z "${disabled[$name]:-}" ] && [ -f "fuzz/options/${name}-no_fuzzer_mode.options" ]; then
        copy_fuzzer "$fuzzer" "$name"
    fi
done
