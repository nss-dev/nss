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


typeset -i totalErrors=0
typeset -i moduleErrors=0
typeset -i systemErrors=0
typeset -i pkiErrors=0
typeset -i quiet=0
checkMemArg=""
arenasArg=""
quietArg=""

### ParseArgs
function ParseArgs # args
{
    while [[ $# -gt 0 ]]; do
        if [[ $1 = "-checkmem" ]]; then
            checkMemArg=$1
        elif [[ $1 = "-quiet" ]]; then
            quietArg=$1
            quiet=1
        elif [[ $1 = "-arenas" ]]; then
            arenasArg=$1
            quiet=1
        fi
        shift
    done
}

function Display # string
{
    if [[ ${quiet} -eq 0 ]]; then
        echo "$1"
    fi
}

ParseArgs $*



Display "*******************************************************************************"
Display "START OF TESTS FOR PKIX_PL${memText}"
Display "*******************************************************************************"
Display ""

Display "RUNNING tests in pki";
cd pki;
runPLTests.sh ${arenasArg} ${checkMemArg} ${quietArg}
pkiErrors=$?

Display "RUNNING tests in system";
cd ../system;
runPLTests.sh ${arenasArg} ${checkMemArg} ${quietArg}
systemErrors=$?

Display "RUNNING tests in module";
cd ../module;
runPLTests.sh ${arenasArg} ${checkMemArg} ${quietArg}
moduleErrors=$?

totalErrors=moduleErrors+systemErrors+pkiErrors

if [[ ${totalErrors} -eq 0 ]]; then
    Display "\n************************************************************"
    Display "END OF TESTS FOR PKIX_PL: ALL TESTS COMPLETED SUCCESSFULLY"
    Display "************************************************************"
    return 0
fi

if [[ ${totalErrors} -eq 1 ]]; then
    plural=""
else
    plural="S"
fi

Display "\n************************************************************"
Display "END OF TESTS FOR PKIX_PL: ${testErrors} TEST${plural} FAILED"
Display "************************************************************"


return ${totalErrors}

