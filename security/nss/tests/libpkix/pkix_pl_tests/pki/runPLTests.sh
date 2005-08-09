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
result=1
checkMem=0
arenas=0
quiet=0
typeset -i totalErrors=0
typeset -i combinedErrors=0
prematureTermination=0

### setup some defaults
WD=`pwd`
prog=`basename $0`
testOut=${WD}/${prog}.$$
testOutMem=${WD}/${prog}_mem.$$

### setup NIST files need to link in
linkNistFiles="InvalidDNnameConstraintsTest3EE.crt 
        InvalidonlySomeReasonsTest21EE.crt 
        indirectCRLCA3cRLIssuerCRL.crl  
        nameConstraintsDN3subCA2Cert.crt 
        nameConstraintsDN4CACert.crt 
        nameConstraintsDN5CACert.crt 
        onlyContainsAttributeCertsCACRL.crl 
        onlyContainsCACertsCACRL.crl 
        onlyContainsUserCertsCACRL.crl 
        onlySomeReasonsCA3compromiseCRL.crl
        requireExplicitPolicy2CACert.crt 
        inhibitPolicyMapping5CACert.crt 
        inhibitAnyPolicy5CACert.crt 
        inhibitAnyPolicy0CACert.crt 
        P1Mapping1to234CACert.crt 
        UserNoticeQualifierTest15EE.crt 
        UserNoticeQualifierTest16EE.crt 
        UserNoticeQualifierTest17EE.crt 
        UserNoticeQualifierTest18EE.crt 
        CPSPointerQualifierTest20EE.crt"

if [ -z "${INIT_SOURCED}" ] ; then
    curdir=`pwd`
    cd ../../../common
    . ./init.sh > /dev/null
    cd ${curdir}
fi

DIST_BIN=${DIST}/${OBJDIR}/bin

####################
# cleanup from tests
####################
function Cleanup
{
    if [[ ${testOut} != "" ]]; then
        rm -f ${testOut}
    fi

    if [[ ${testOutMem} != "" ]]; then
        rm -f ${testOutMem}
    fi

    for i in ${linkNistFiles}; do
        if [[ -f ./rev_data/local/$i ]]; then
            rm ./rev_data/local/$i
        fi
    done

    return ${result}
}

### ParseArgs
function ParseArgs # args
{
    while [[ $# -gt 0 ]]; do
        if [[ $1 == "-checkmem" ]]; then
            checkmem=1
        elif [[ $1 == "-quiet" ]]; then
            quiet=1
        elif [[ $1 == "-arenas" ]]; then
            arenas=1
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

#
# Any test that use NIST files should have a tag of NIST-Test-Files-Used
# at the command option so if there is no NIST files installed in the system,
# the test can be skipped
#
if [ -z "${NIST_FILES_DIR}" ] ; then
    Display "\n*******************************************************************************"
    Display "NIST_FILES_DIR is not set, therefore some tests sre skipped"
    Display "Set NIST_FILES_DIR to where NIST Certificates and CRLs located"
    Display "to enable tests at this directory"
    Display "*******************************************************************************"
    doNIST=0
else

    NIST=${NIST_FILES_DIR}
    if [[ ! -d ./rev_data/local ]]; then
      mkdir -p ./rev_data/local
    fi

    for i in ${linkNistFiles}; do
        if [[ -f ./rev_data/local/$i ]]; then
            rm ./rev_data/local/$i
        fi
        ln -s ${NIST_FILES_DIR}/$i ./rev_data/local/$i
    done

    doNIST=1
fi

###########
# RunTests
###########
function RunTests
{
    typeset -i errors=0
    typeset -i memErrors=0
    typeset -i prematureErrors=0

    failedpgms=""
    failedmempgms=""
    failedprematurepgms=""
    memText=""
    arenaCmd=""

    if [[ ${checkmem} -eq 1 ]]; then
            memText="   (Memory Checking Enabled)"
    fi

    if [[ ${arenas} -eq 1 ]]; then
            arenaCmd="-arenas"
    fi

    #
    # Announce start of tests
    #
    Display "*******************************************************************************"
    Display "START OF TESTS FOR PKIX_PL (PKI)${memText}"
    Display "*******************************************************************************"
    Display ""

    # run each test specified by the input redirection below

    while read -r testPgm; do

        if [[ ${doNIST} -eq 0 ]]; then
            hasNIST=`echo ${testPgm} | grep NIST-Test-Files-Used`
            if [ ! -z "${hasNIST}" ]; then
	      Display "SKIPPING ${testPgm}"
	      continue
	    fi
        fi

        Display "RUNNING ${testPgm} ${arenaCmd}"

        if [[ ${checkmem} -eq 1 ]]; then
            /net/zhadum/export/tools/sparc/on10/SUNWspro/SOS8/bin/dbx -C -c "check -all;run;exit" ${DIST_BIN}/${testPgm} ${arenaCmd}> ${testOut} 2>&1
        else
            ${DIST_BIN}/${testPgm} ${arenaCmd}> ${testOut} 2>&1
        fi

        # Examine output file to see if test failed and keep track of number
        # of failures and names of failed tests. This assumes that the test
        # uses our utility library for displaying information

        if [[ ${checkmem} -eq 1 ]]; then
            if [[ ${testPgm} == "testCert" ]]; then
                grep "TEST FAILURE: *** Cert Error - PKIX_PL_Cert_VerifySignature: Signature did not verify with this public key" ${testOut} >/dev/null 2>&1
            fi
        else
            grep "END OF TESTS FOR" ${testOut} | tail -1 | grep "COMPLETED SUCCESSFULLY" >/dev/null 2>&1            
        fi
        
        if [[ $? -ne 0 ]]; then
            errors=`expr ${errors} + 1`
            failedpgms="${failedpgms}${testPgm} "
            cat ${testOut}
        fi

        if [[ ${checkmem} -eq 1 ]]; then
            grep "(actual leaks:" ${testOut} > ${testOutMem} 2>&1
            if [[ $? -ne 0 ]]; then
                prematureErrors=`expr ${prematureErrors} + 1`
                failedprematurepgms="${failedprematurepgms}${testPgm} "
                Display "...program terminated prematurely (unable to check for memory leak errors) ..."
            else
                #grep "(actual leaks:         0" ${testOut} > /dev/null 2>&1
                # special consideration for memory leak in NSS_NoDB_Init
                grep  "(actual leaks:         1  total size:       4 bytes)" ${testOut} > /dev/null 2>&1
                if [[ $? -ne 0 ]]; then
                    memErrors=`expr ${memErrors} + 1`
                    failedmempgms="${failedmempgms}${testPgm} "
                    cat ${testOutMem}
                fi
            fi
        fi
    done <<EOF
test_cert NIST-Test-Files-Used
test_crl NIST-Test-Files-Used
test_x500name
test_generalname
test_date NIST-Test-Files-Used
test_crlentry
test_nameconstraints NIST-Test-Files-Used
EOF

    if [[ ${errors} -eq 0 ]]; then
        if [[ ${memErrors} -eq 0 ]]; then
            Display "\n************************************************************"
            Display "END OF TESTS FOR PKIX_PL (PKI): ALL TESTS COMPLETED SUCCESSFULLY"
            Display "************************************************************"
            return 0
        fi
    fi

    if [[ ${errors} -eq 1 ]]; then
        plural=""
    else
        plural="S"
    fi

    Display "\n*******************************************************************************"
    Display "END OF TESTS FOR PKIX_PL (PKI): ${errors} UNIT TEST${plural} FAILED: ${failedpgms}"
    if [[ ${checkmem} -eq 1 ]]; then
        if [[ ${memErrors} -eq 1 ]]; then
            memPlural=""
        else
            memPlural="S"
        fi
        Display "                          ${memErrors} MEMORY LEAK TEST${memPlural} FAILED: ${failedmempgms}"
        
        if [[ ${prematureErrors} -ne 0 ]]; then
            if [[ ${prematureErrors} -eq 1 ]]; then
                prematurePlural=""
            else
                prematurePlural="S"
            fi
            Display "                          ${prematureErrors} MEMORY LEAK TEST${prematurePlural} INDETERMINATE: ${failedprematurepgms}"
        fi

    fi
    Display "*******************************************************************************"
    combinedErrors=${errors}+${memErrors}+${prematureErrors}
    return ${combinedErrors}

}


##########
# main
#########
ParseArgs $*
RunTests
totalErrors=$?
return ${totalErrors}

