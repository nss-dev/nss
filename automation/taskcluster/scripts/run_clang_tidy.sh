#!/usr/bin/env bash

source $(dirname "$0")/tools.sh

if ! command -v clang-tidy &>/dev/null; then
    echo "error: clang-tidy not found" >&2
    exit 1
fi

cp -a "${VCS_PATH}/nss" "${VCS_PATH}/nspr" .
cd nspr
if [[ -f ../nss/nspr.patch && "$ALLOW_NSPR_PATCH" == "1" ]]; then
  cat ../nss/nspr.patch | patch -p1
fi
cd ..

cd nss

extra_args=(--fail-on-warnings)
if [[ -n "$NSS_BASE_REV" ]]; then
    echo "$(date '+%T') Checking diff against base revision $NSS_BASE_REV"
    extra_args+=(--diff-base "$NSS_BASE_REV")
else
    echo "$(date '+%T') NSS_BASE_REV not set — checking all lib/, gtests/, and cpputil/ files"
fi

./mach clang-tidy "${extra_args[@]}" --
