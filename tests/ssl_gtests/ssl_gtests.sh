#!/bin/bash
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

########################################################################
#
# tests/ssl_gtests/ssl_gtests.sh
#
# Script to drive the ssl gtest unit tests
#
# needs to work on all Unix and Windows platforms
#
# special strings
# ---------------
#   FIXME ... known problems, search for this string
#   NOTE .... unexpected behavior
#
########################################################################

ssl_gtest_certs() {
  ./ssl_gtest_db.sh "${SSLGTESTDIR}" "${BINDIR}/certutil" "${R_NOISE_FILE}"
  html_msg $? 0 "create ssl_gtest certificates"
}

############################## ssl_gtest_init ##########################
# local shell function to initialize this script
########################################################################
ssl_gtest_init()
{
  SCRIPTNAME=ssl_gtest.sh      # sourced - $0 would point to all.sh

  if [ -z "${CLEANUP}" ] ; then     # if nobody else is responsible for
      CLEANUP="${SCRIPTNAME}"       # cleaning this script will do it
  fi
  if [ -z "${INIT_SOURCED}" -o "${INIT_SOURCED}" != "TRUE" ]; then
      cd ../common
      . ./init.sh
  fi

  SCRIPTNAME=ssl_gtest.sh
  html_head SSL Gtests

  if [ ! -d "${SSLGTESTDIR}" ]; then
    ssl_gtest_certs
  fi

  cd "${SSLGTESTDIR}"
}

########################## ssl_gtest_start #########################
# Local function to actually start the test
####################################################################
ssl_gtest_start()
{
  if [ ! -f ${BINDIR}/ssl_gtest ]; then
    html_unknown "Skipping ssl_gtest (not built)"
    return
  fi

  SSLGTESTREPORT="${SSLGTESTDIR}/report.xml"

  local nshards=1
  local prefix=""
  local postfix=""

  export -f parallel_fallback

  # Determine the number of chunks.
  if [ -n "$GTESTFILTER" ]; then
    echo "DEBUG: Not parallelizing ssl_gtests because \$GTESTFILTER is set"
  elif type parallel 2>/dev/null; then
    nshards=$(parallel --number-of-cores || 1)
  fi

  if [ "$nshards" != 1 ]; then
    local indices=$(for ((i=0; i<$nshards; i++)); do echo $i; done)
    prefix="parallel -j$nshards --line-buffer --halt soon,fail=1"
    postfix="\&\& exit 0 \|\| exit 1 ::: $indices"
  fi

  echo "DEBUG: ssl_gtests will be divided into $nshards chunk(s)"

  # Run tests.
  ${prefix:-parallel_fallback} \
    GTEST_SHARD_INDEX={} \
      GTEST_TOTAL_SHARDS=$nshards \
        DYLD_LIBRARY_PATH="${DIST}/${OBJDIR}/lib" \
          ${BINDIR}/ssl_gtest -d "${SSLGTESTDIR}" \
            --gtest_output=xml:"${SSLGTESTREPORT}.{}" \
            --gtest_filter="${GTESTFILTER-*}" \
            $postfix

  html_msg $? 0 "ssl_gtests ran successfully"

  # Parse XML report(s).
  gtest_parse_report "${SSLGTESTREPORT}".* 
}

# Helper function used when 'parallel' isn't available.
parallel_fallback()
{
  eval "${@//\{\}/0}"
}

ssl_gtest_cleanup()
{
  cd ${QADIR}
  . common/cleanup.sh
}

################## main #################################################
cd "$(dirname "$0")"
ssl_gtest_init
ssl_gtest_start
ssl_gtest_cleanup
