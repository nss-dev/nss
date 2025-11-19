#!/bin/bash
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

########################################################################
#
# tests/tlsinterop/tlsinterop-openssl.sh
#
# Script to drive openssl tls interop tests
#
########################################################################

echo "PATH: $(pwd)"
cd $(dirname $0)/../tlsinterop
source tlsinterop.sh

tlsinterop_init
tlsinterop_run_tests "openssl"
tlsinterop_cleanup
