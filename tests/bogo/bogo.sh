#!/bin/bash
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

########################################################################
#
# tests/bogo/bogo.sh
#
# Script to drive the ssl bogo interop unit tests
#
########################################################################

bogo_init()
{
  mkdir -p "${HOSTDIR}/bogo"
  cd "${HOSTDIR}/bogo"

  SCRIPTNAME="bogo.sh"
  if [ -z "${INIT_SOURCED}" -o "${INIT_SOURCED}" != "TRUE" ] ; then
    cd ../common
    . ./init.sh
  fi

  if [ ! -d "boringssl" ]; then
    git clone https://boringssl.googlesource.com/boringssl
    cd boringssl
    git checkout 57e929f3c8c3d412639eb123382c79ff3bdc3ed3
    cd ssl/test/runner
  else
    cd boringssl/ssl/test/runner
  fi

  SCRIPTNAME="bogo.sh"
  html_head "bogo test"
}

bogo_cleanup()
{
  html "</TABLE><BR>"
  cd ${QADIR}
  . common/cleanup.sh
}

# Need to add go to the PATH.
export PATH=$PATH:/usr/lib/go-1.6/bin

SOURCE_DIR=$(echo $PWD/../../)
bogo_init
exec 3>&1
BOGO_OUT=$(GOPATH=$PWD go test -pipe -shim-path "${BINDIR}"/nss_bogo_shim \
   -loose-errors -allow-unimplemented \
   -shim-config "${SOURCE_DIR}external_tests/nss_bogo_shim/config.json" \
   2>&1 1>&3)
BOGO_STATUS=$?
exec 3>&-
BOGO_OUT=`echo $BOGO_OUT | grep -i 'FAILED\|Assertion failure'`
if [ -n "$BOGO_OUT" ] || [ "$BOGO_STATUS" -ne "0" ]; then
  html_failed "Bogo test"
else
  html_passed "Bogo test"
fi
bogo_cleanup
