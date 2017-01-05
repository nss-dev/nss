#!/usr/bin/env bash

source $(dirname "$0")/tools.sh

# Fetch artifact if needed.
fetch_dist

# Clone corpus.
./nss/fuzz/clone_corpus.sh

# Fetch objdir name.
objdir=$(cat dist/latest)

# Run nssfuzz.
type="$1"
shift
LD_LIBRARY_PATH=$LD_LIBRARY_PATH:dist/$objdir/lib dist/$objdir/bin/nssfuzz-"$type" "$@"
