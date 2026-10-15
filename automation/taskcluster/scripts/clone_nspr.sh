#!/usr/bin/env bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Clone NSPR into ./nspr (or $1) and check out the revision CI is pinned to.
#
# This is not automation/release/nspr-version.txt, which records the *minimum*
# NSPR version NSS supports and is used when building release archives.

set -e

NSPR_REPOSITORY=${NSPR_REPOSITORY:-https://github.com/mozilla/nspr}
NSPR_REVISION=${NSPR_REVISION:-nspr4}

nspr_dir=${1:-nspr}

if [ ! -d "$nspr_dir" ]; then
    git clone "$NSPR_REPOSITORY" "$nspr_dir"
fi

# Discard whatever a previous run left behind (an applied nspr.patch, say)
# before moving to the pinned revision. A cached clone may predate the pin, so
# fetch if the revision isn't known yet.
git -C "$nspr_dir" checkout --quiet -- .
if ! git -C "$nspr_dir" checkout --quiet --detach "$NSPR_REVISION" 2>/dev/null; then
    git -C "$nspr_dir" fetch --quiet "$NSPR_REPOSITORY" "$NSPR_REVISION"
    git -C "$nspr_dir" checkout --quiet --detach FETCH_HEAD
fi
git -C "$nspr_dir" --no-pager log -1 --oneline
