#!/bin/bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Create an NSS certificate database for NSS gtests.
# Usage: gtest_db.sh [db_dir [certutil [noise_file]]]
#   db_dir     - directory for the NSS cert DB (default: ./gtest_certdb)
#   certutil   - path to certutil binary (default: found in PATH)
#   noise_file - entropy file for key generation (default: auto-generated)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

PROFILEDIR="${1:-./gtest_certdb}"
CERTUTIL="${2:-}"
R_NOISE_FILE="${3:-}"

html_msg() { :; }

. "${SCRIPT_DIR}/../common/certsetup.sh"

# Use certutil from PATH if not provided
if [ -z "$CERTUTIL" ]; then
    CERTUTIL="$(command -v certutil 2>/dev/null || true)"
fi
if [ -z "$CERTUTIL" ]; then
    echo "certutil not found; pass it as \$2 or ensure it is in PATH" >&2
    exit 1
fi
BINDIR="$(dirname "$CERTUTIL")"

# Auto-generate a noise file if not provided
if [ -z "$R_NOISE_FILE" ]; then
    _noise_tmp="$(mktemp)"
    trap 'rm -f "$_noise_tmp"' EXIT
    dd if=/dev/urandom of="$_noise_tmp" bs=2048 count=1 2>/dev/null
    R_NOISE_FILE="$_noise_tmp"
fi

mkdir -p "$PROFILEDIR"
"$CERTUTIL" -N -d "$PROFILEDIR" --empty-password

counter=0
make_cert dummy p256 sign
