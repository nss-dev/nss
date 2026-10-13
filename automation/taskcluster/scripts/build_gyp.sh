#!/usr/bin/env bash

. $(dirname "$0")/tools.sh

set -e

test -n "${VCS_PATH}"

# builds write to the source dir (and its parent), so move the source trees to
# our workspace from the (cached) checkout dir
cp -a "${VCS_PATH}/nss" .
"$(dirname "$0")/clone_nspr.sh"

pushd nspr
if [ -f "../nss/nspr.patch" ] && [ "$ALLOW_NSPR_PATCH" = "1" ]; then
  patch -p1 < ../nss/nspr.patch
fi
popd

# Dependencies
# For MacOS we have hardware in the CI which doesn't allow us to deploy VMs.
# The setup is hardcoded and can't be changed easily.
# This part is a helper We install dependencies manually to help.
if [ "$(uname)" = "Darwin" ]; then
  . "$(dirname "$0")/install_gyp.sh"
  install_gyp gyp-env ninja
fi

# Build.
nss/build.sh -g -v --enable-libpkix -Denable_draft_hpke=1 "$@"

# Package.
if [ "$(uname)" = Linux ]; then
  ln -s /builds/worker/artifacts artifacts
else
  mkdir -p artifacts
fi
tar cvfjh artifacts/dist.tar.bz2 dist
