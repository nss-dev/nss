#! /bin/ksh
# 
# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is the Netscape security libraries.
#
# The Initial Developer of the Original Code is
# Netscape Communications Corporation.
# Portions created by the Initial Developer are Copyright (C) 1994-2000
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.
#
# ***** END LICENSE BLOCK *****
#
# runPLTests.sh
#

### when the script is exiting, handle it in the Cleanup routine...the result
### value will get set to 0 if all the tests completed successfully, so we can
### use that value in the handler
trap 'Cleanup' EXIT

### setup NIST files need to link in
linkNistFiles="ValidCertificatePathTest1EE.crt"

####################
# cleanup from tests
####################
function Cleanup
{
    for i in ${linkNistFiles}; do
        if [[ -f ./$i ]]; then
            rm ./$i
        fi
    done
}

function Display # string
{
    if [[ ${quiet} -eq 0 ]]; then
        echo "$1"
    fi
}

#
# Any test that use NIST files should have a tag of NIST-Test-Files-Used
# at the command option so if there is no NIST files installed in the system,
# the test can be skipped
#
if [ -z "${NIST_FILES_DIR}" ] ; then
    Display "\n*******************************************************************************"
    Display "NIST_FILES_DIR is not set but we need NIST file to run the"
    Display "performance for this nss db. Exiting..."
    Display "*******************************************************************************"
    exit
else

    NIST=${NIST_FILES_DIR}

    for i in ${linkNistFiles}; do
        if [[ -f ./$i ]]; then
            rm ./$i
        fi
        ln -s ${NIST_FILES_DIR}/$i ./$i
    done
fi

perf_bin=../../../../../dist/SunOS5.9_DBG.OBJ/bin
Display "${perf_bin}/libpkix_buildthreads 5 1 ValidCertificatePathTest1EE"
${perf_bin}/libpkix_buildthreads 5 1 ValidCertificatePathTest1EE
Display "${perf_bin}/libpkix_buildthreads 5 8 ValidCertificatePathTest1EE"
${perf_bin}/libpkix_buildthreads 5 8 ValidCertificatePathTest1EE
Display "${perf_bin}/nss_threads 5 1 ValidCertificatePathTest1EE"
${perf_bin}/nss_threads 5 1 ValidCertificatePathTest1EE
Display "${perf_bin}/nss_threads 5 8 ValidCertificatePathTest1EE"
${perf_bin}/nss_threads 5 8 ValidCertificatePathTest1EE
