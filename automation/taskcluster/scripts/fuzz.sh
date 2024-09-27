#!/usr/bin/env bash

source $(dirname "$0")/tools.sh

target="$1"
corpus="$2"
shift 2

# Fetch artifact if needed.
fetch_dist

# Create and change to corpus directory.
mkdir -p "nss/fuzz/corpus/$corpus"
cd "nss/fuzz/corpus/$corpus"

# Fetch and unzip the public OSS-Fuzz corpus. Handle the case that there
# may be no corpus yet for new fuzz targets.
code=$(curl -w "%{http_code}" -O "https://storage.googleapis.com/nss-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/nss_$corpus/public.zip")
if [[ $code -eq 200 ]]; then
    unzip public.zip
fi
rm -f public.zip

# Change back to previous working directory.
cd $OLDPWD

# Fetch objdir name.
objdir=$(cat dist/latest)

# Run nssfuzz.
dist/"$objdir"/bin/nssfuzz-"$target" "nss/fuzz/corpus/$corpus" "$@"
