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
# runTests.sh
#


### when the script is exiting, handle it in the Cleanup routine...the result
### value will get set to 0 if all the tests completed successfully, so we can
### use that value in the handler
trap 'Cleanup' EXIT
result=1
checkmem=0
arenas=0
typeset -i combinedErrors=0
typeset -i totalErrors=0
prematureTermination=0

### setup some defaults
WD=`pwd`
prog=`basename $0`
testOut=${WD}/${prog}.$$
testOutMem=${WD}/${prog}_mem.$$

### setup NIST files need to link in
linkMStoreNistFiles="store1/TrustAnchorRootCRL.crl
    store1/TwoCRLsCABadCRL.crl
    store2/TwoCRLsCAGoodCRL.crl"

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

    if [[ -d ../../nist_pkits/certs ]]; then
        rm ../../nist_pkits/certs
    fi

    for i in ${linkMStoreNistFiles}; do
        if [[ -f ./rev_data/multiple_certstores/$i ]]; then
            rm ./rev_data/multiple_certstores/$i
        fi
    done
    if [[ -d ./rev_data/multiple_certstores ]]; then
        rm -fr rev_data/multiple_certstores
    fi

    return ${result}
}

### ParseArgs
function ParseArgs # args
{
    while [[ $# -gt 0 ]]; do
        if [[ $1 = "-checkmem" ]]; then
            checkmem=1
        elif [[ $1 = "-quiet" ]]; then
            quiet=1
        elif [[ $1 = "-arenas" ]]; then
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
# Any test that use NIST files should have a tag of either NIST-Test or
# NIST-Test-Files-Used at the command option so if there is no NIST files
# installed in the system, the test can be skipped
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
    if [[ ! -d ../../nist_pkits ]]; then
      mkdir -p ../../nist_pkits
    else
      if [[ -d ../../nist_pkits/certs ]]; then
        rm ../../nist_pkits/certs
      fi
    fi

    ln -s ${NIST_FILES_DIR} ../../nist_pkits/certs

    if [[ -d ./rev_data/multiple_certstores ]]; then
        rm -fr ./rev_data/multiple_certstores
    fi
    mkdir ./rev_data/multiple_certstores
    mkdir ./rev_data/multiple_certstores/store1
    mkdir ./rev_data/multiple_certstores/store2
    for i in ${linkMStoreNistFiles}; do
        if [[ -f ./rev_data/multiple_certstores/$i ]]; then
            rm ./rev_data/multiple_certstores/$i
        fi
        fname=`basename $i`
        ln -s ${NIST_FILES_DIR}/${fname} ./rev_data/multiple_certstores/$i
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
    Display "START OF TESTS FOR PKIX TOP${memText}"
Display "*******************************************************************************"
    Display ""

    # run each test specified by the input redirection below

    while read -r testPgm args; do

      test_purpose=`echo $args | awk '{print $1 " " $2 " "}'`

      if [[ ${doNIST} -eq 0 ]]; then
        hasNIST=`echo ${args} | grep NIST-Test`
        if [ ! -z "${hasNIST}" ]; then
          Display "SKIPPING ${testPgm} ${test_purpose}"
          continue
        fi
      fi

      if [[ ${testPgm} = "#" ]]; then
        Display "${testPgm} ${args}"
      else
        Display "RUNNING ${testPgm} ${arenaCmd} ${test_purpose}"
        if [[ ${checkmem} -eq 1 ]]; then
            dbx -C -c "runargs ${arenaCmd} $args; check -all ;run;exit" ${DIST_BIN}/${testPgm} > ${testOut} 2>&1
        else
            ${DIST_BIN}/${testPgm} ${arenaCmd} ${args}> ${testOut} 2>&1
        fi

        # Examine output file to see if test failed and keep track of number
        # of failures and names of failed tests. This assumes that the test
        # uses our utility library for displaying information

        grep "END OF TESTS FOR" ${testOut} | tail -1 | grep "COMPLETED SUCCESSFULLY" >/dev/null 2>&1
        
        if [[ $? -ne 0 ]]; then
            errors=`expr ${errors} + 1`
            failedpgms="${failedpgms}${testPgm} ${test_purpose}\n"
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
    fi
    done <<EOF
#    ENE = expect no error (validation should succeed)
#    EE = expect error (validation should fail)
test_basicchecker
test_basicconstraintschecker "Two-Certificates-Chain" ENE ../../certs/hy2hy-bc0 ../../certs/hy2hc-bc
test_basicconstraintschecker "Three-Certificates-Chain" ENE ../../certs/hy2hy-bc0 ../../certs/hy2hy-bc0 ../../certs/hy2hc-bc
test_basicconstraintschecker "Four-Certificates-Chain-with-error" EE ../../certs/hy2hy-bc0 ../../certs/hy2hy-bc0 ../../certs/hy2hc-bc ../../certs/hy2hc-bc
test_validatechain_bc  ../../certs/hy2hy-bc0 ../../certs/hy2hc-bc
test_policychecker NIST-Test-Files-Used
test_defaultcrlchecker2stores NIST-Test.4.4.7-with-multiple-CRL-stores ENE ./rev_data/multiple_certstores/store1 ./rev_data/multiple_certstores/store2 $NIST/TrustAnchorRootCertificate.crt $NIST/TwoCRLsCACert.crt $NIST/ValidTwoCRLsTest7EE.crt
test_customcrlchecker "CRL-test-without-revocation" ENE ./rev_data/crlchecker ./rev_data/crlchecker/sci2sci.crt ./rev_data/crlchecker/sci2phy.crt ./rev_data/crlchecker/phy2prof.crt ./rev_data/crlchecker/prof2test.crt
test_customcrlchecker "CRL-test-with-revocation-reasoncode" EE ./rev_data/crlchecker ./rev_data/crlchecker/sci2sci.crt ./rev_data/crlchecker/sci2chem.crt ./rev_data/crlchecker/chem2prof.crt ./rev_data/crlchecker/prof2test.crt
test_subjaltnamechecker "NIST-Test-Files-Used" "0R:testcertificates.gov+R:Test23EE@testcertificates.gov" ENE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsRFC822CA2Cert.crt $NIST/ValidRFC822nameConstraintsTest23EE.crt
test_subjaltnamechecker "NIST-Test-Files-Used" "0R:TEST.gov" EE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsRFC822CA2Cert.crt $NIST/ValidRFC822nameConstraintsTest23EE.crt
test_subjaltnamechecker "NIST-Test-Files-Used" "0N:testcertificates.gov+N:testserver.testcertificates.gov" ENE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDNS1CACert.crt $NIST/ValidDNSnameConstraintsTest30EE.crt
test_subjaltnamechecker "NIST-Test-Files-Used" "0N:notestcertificates.gov" EE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDNS1CACert.crt $NIST/ValidDNSnameConstraintsTest30EE.crt
test_subjaltnamechecker "NIST-Test-Files-Used" "0U:.gov+U:http://testserver.testcertificates.gov/index.html" ENE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsURI1CACert.crt $NIST/ValidURInameConstraintsTest34EE.crt
test_subjaltnamechecker "NIST-Test-Files-Used" "0U:test.testcertificates.gov" EE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsURI1CACert.crt $NIST/ValidURInameConstraintsTest34EE.crt
test_subjaltnamechecker "NIST-Test-Files-Used" "1D:C=US+D:CN=Certificates,C=US" EE  $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDN2CACert.crt $NIST/ValidDNnameConstraintsTest5EE.crt
test_subjaltnamechecker "NIST-Test-Files-Used" "0D:O=TestCertificates,C=CN" EE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDN2CACert.crt $NIST/ValidDNnameConstraintsTest5EE.crt
test_validatechain "CRL-test-without-revocation" ENE ./rev_data/crlchecker sci2sci.crt sci2phy.crt phy2prof.crt prof2test.crt
test_validatechain "CRL-test-with-revocation-reasoncode" EE ./rev_data/crlchecker sci2sci.crt sci2chem.crt chem2prof.crt prof2test.crt
test_validatechain "CRL-test-without-key-usage-cRLsign-bit-NIST-Test-Files-Used" EE $NIST TrustAnchorRootCertificate.crt SeparateCertificateandCRLKeysCertificateSigningCACert.crt SeparateCertificateandCRLKeysCRLSigningCert.crt InvalidSeparateCertificateandCRLKeysTest20EE.crt
test_validatechain NIST-Test.4.1.1 ENE $NIST TrustAnchorRootCertificate.crt GoodCACert.crt ValidCertificatePathTest1EE.crt
test_validatechain NIST-Test.4.1.2 EE $NIST TrustAnchorRootCertificate.crt BadSignedCACert.crt InvalidCASignatureTest2EE.crt
test_validatechain NIST-Test.4.1.3 EE $NIST TrustAnchorRootCertificate.crt GoodCACert.crt  InvalidEESignatureTest3EE.crt
test_validatechain NIST-Test.4.1.4 ENE $NIST TrustAnchorRootCertificate.crt DSACACert.crt ValidDSASignaturesTest4EE.crt
test_validatechain NIST-Test.4.1.5 ENE $NIST TrustAnchorRootCertificate.crt DSACACert.crt DSAParametersInheritedCACert.crt ValidDSAParameterInheritanceTest5EE.crt
test_validatechain NIST-Test.4.1.6 EE $NIST TrustAnchorRootCertificate.crt DSACACert.crt InvalidDSASignatureTest6EE.crt
test_validatechain NIST-Test.4.2.1 EE $NIST TrustAnchorRootCertificate.crt BadnotBeforeDateCACert.crt InvalidCAnotBeforeDateTest1EE.crt
test_validatechain NIST-Test.4.2.2 EE $NIST TrustAnchorRootCertificate.crt GoodCACert.crt InvalidEEnotBeforeDateTest2EE.crt
test_validatechain NIST-Test.4.2.3 ENE $NIST TrustAnchorRootCertificate.crt GoodCACert.crt Validpre2000UTCnotBeforeDateTest3EE.crt
test_validatechain NIST-Test.4.2.4 ENE $NIST TrustAnchorRootCertificate.crt GoodCACert.crt ValidGeneralizedTimenotBeforeDateTest4EE.crt
test_validatechain NIST-Test.4.2.5 EE $NIST TrustAnchorRootCertificate.crt BadnotAfterDateCACert.crt InvalidCAnotAfterDateTest5EE.crt
test_validatechain NIST-Test.4.2.6 EE $NIST TrustAnchorRootCertificate.crt GoodCACert.crt InvalidEEnotAfterDateTest6EE.crt
test_validatechain NIST-Test.4.2.7 EE $NIST TrustAnchorRootCertificate.crt GoodCACert.crt Invalidpre2000UTCEEnotAfterDateTest7EE.crt
test_validatechain NIST-Test.4.2.8 ENE $NIST TrustAnchorRootCertificate.crt GoodCACert.crt ValidGeneralizedTimenotAfterDateTest8EE.crt
test_validatechain NIST-Test.4.3.1 EE $NIST TrustAnchorRootCertificate.crt GoodCACert.crt InvalidNameChainingTest1EE.crt
test_validatechain NIST-Test.4.3.2 EE $NIST TrustAnchorRootCertificate.crt NameOrderingCACert.crt  InvalidNameChainingOrderTest2EE.crt
test_validatechain NIST-Test.4.3.3 ENE $NIST TrustAnchorRootCertificate.crt GoodCACert.crt ValidNameChainingWhitespaceTest3EE.crt
test_validatechain NIST-Test.4.3.4 ENE $NIST TrustAnchorRootCertificate.crt GoodCACert.crt ValidNameChainingWhitespaceTest4EE.crt
test_validatechain NIST-Test.4.3.5 ENE $NIST TrustAnchorRootCertificate.crt GoodCACert.crt ValidNameChainingCapitalizationTest5EE.crt
test_validatechain NIST-Test.4.3.6 ENE $NIST TrustAnchorRootCertificate.crt UIDCACert.crt  ValidNameUIDsTest6EE.crt
test_validatechain NIST-Test.4.3.7 ENE $NIST TrustAnchorRootCertificate.crt RFC3280MandatoryAttributeTypesCACert.crt ValidRFC3280MandatoryAttributeTypesTest7EE.crt
test_validatechain NIST-Test.4.3.9 ENE $NIST TrustAnchorRootCertificate.crt UTF8StringEncodedNamesCACert.crt  ValidUTF8StringEncodedNamesTest9EE.crt
test_validatechain NIST-Test.4.3.10 ENE $NIST TrustAnchorRootCertificate.crt RolloverfromPrintableStringtoUTF8StringCACert.crt  ValidRolloverfromPrintableStringtoUTF8StringTest10EE.crt
test_validatechain NIST-Test.4.3.11 ENE $NIST TrustAnchorRootCertificate.crt UTF8StringCaseInsensitiveMatchCACert.crt  ValidUTF8StringCaseInsensitiveMatchTest11EE.crt
test_validatechain NIST-Test.4.4.1 EE $NIST TrustAnchorRootCertificate.crt NoCRLCACert.crt InvalidMissingCRLTest1EE.crt
test_validatechain NIST-Test.4.4.2 EE $NIST TrustAnchorRootCertificate.crt GoodCACert.crt RevokedsubCACert.crt InvalidRevokedCATest2EE.crt
test_validatechain NIST-Test.4.4.3 EE $NIST TrustAnchorRootCertificate.crt GoodCACert.crt InvalidRevokedEETest3EE.crt
test_validatechain NIST-Test.4.4.4 EE $NIST TrustAnchorRootCertificate.crt BadSignedCACert.crt InvalidBadCRLSignatureTest4EE.crt
test_validatechain NIST-Test.4.4.5 EE $NIST TrustAnchorRootCertificate.crt BadCRLIssuerNameCACert.crt InvalidBadCRLIssuerNameTest5EE.crt
test_validatechain NIST-Test.4.4.6 EE $NIST TrustAnchorRootCertificate.crt WrongCRLCACert.crt InvalidWrongCRLTest6EE.crt
test_validatechain NIST-Test.4.4.7 ENE $NIST TrustAnchorRootCertificate.crt TwoCRLsCACert.crt ValidTwoCRLsTest7EE.crt
test_validatechain NIST-Test.4.4.8 EE $NIST TrustAnchorRootCertificate.crt UnknownCRLEntryExtensionCACert.crt InvalidUnknownCRLEntryExtensionTest8EE.crt
test_validatechain NIST-Test.4.4.9 EE $NIST TrustAnchorRootCertificate.crt UnknownCRLExtensionCACert.crt InvalidUnknownCRLExtensionTest9EE.crt
test_validatechain NIST-Test.4.4.10 EE $NIST TrustAnchorRootCertificate.crt UnknownCRLExtensionCACert.crt InvalidUnknownCRLExtensionTest10EE.crt
test_validatechain NIST-Test.4.4.11 EE $NIST TrustAnchorRootCertificate.crt OldCRLnextUpdateCACert.crt InvalidOldCRLnextUpdateTest11EE.crt
test_validatechain NIST-Test.4.4.12 EE $NIST TrustAnchorRootCertificate.crt pre2000CRLnextUpdateCACert.crt Invalidpre2000CRLnextUpdateTest12EE.crt
test_validatechain NIST-Test.4.4.13 ENE $NIST TrustAnchorRootCertificate.crt GeneralizedTimeCRLnextUpdateCACert.crt ValidGeneralizedTimeCRLnextUpdateTest13EE.crt
test_validatechain NIST-Test.4.4.14 ENE $NIST TrustAnchorRootCertificate.crt NegativeSerialNumberCACert.crt ValidNegativeSerialNumberTest14EE.crt
test_validatechain NIST-Test.4.4.15 EE $NIST TrustAnchorRootCertificate.crt NegativeSerialNumberCACert.crt InvalidNegativeSerialNumberTest15EE.crt
test_validatechain NIST-Test.4.4.16 ENE $NIST TrustAnchorRootCertificate.crt LongSerialNumberCACert.crt ValidLongSerialNumberTest16EE.crt
test_validatechain NIST-Test.4.4.17 ENE $NIST TrustAnchorRootCertificate.crt LongSerialNumberCACert.crt ValidLongSerialNumberTest17EE.crt
test_validatechain NIST-Test.4.4.18 EE $NIST TrustAnchorRootCertificate.crt LongSerialNumberCACert.crt InvalidLongSerialNumberTest18EE.crt
test_validatechain NIST-Test.4.4.20 EE $NIST TrustAnchorRootCertificate.crt SeparateCertificateandCRLKeysCertificateSigningCACert.crt SeparateCertificateandCRLKeysCRLSigningCert.crt InvalidSeparateCertificateandCRLKeysTest20EE.crt
test_validatechain NIST-Test.4.5.1 ENE $NIST TrustAnchorRootCertificate.crt BasicSelfIssuedNewKeyCACert.crt BasicSelfIssuedNewKeyOldWithNewCACert.crt ValidBasicSelfIssuedOldWithNewTest1EE.crt
test_validatechain NIST-Test.4.5.2 EE $NIST TrustAnchorRootCertificate.crt BasicSelfIssuedNewKeyCACert.crt BasicSelfIssuedNewKeyOldWithNewCACert.crt InvalidBasicSelfIssuedOldWithNewTest2EE.crt
test_validatechain NIST-Test.4.5.5 EE $NIST TrustAnchorRootCertificate.crt BasicSelfIssuedOldKeyCACert.crt BasicSelfIssuedOldKeyNewWithOldCACert.crt InvalidBasicSelfIssuedNewWithOldTest5EE.crt
test_validatechain NIST-Test.4.5.7 EE $NIST TrustAnchorRootCertificate.crt BasicSelfIssuedCRLSigningKeyCACert.crt BasicSelfIssuedCRLSigningKeyCRLCert.crt InvalidBasicSelfIssuedCRLSigningKeyTest7EE.crt
test_validatechain NIST-Test.4.5.8 EE $NIST TrustAnchorRootCertificate.crt BasicSelfIssuedCRLSigningKeyCACert.crt BasicSelfIssuedCRLSigningKeyCRLCert.crt InvalidBasicSelfIssuedCRLSigningKeyTest8EE.crt
test_basicconstraintschecker NIST-Test.4.6.1 EE $NIST/TrustAnchorRootCertificate.crt $NIST/MissingbasicConstraintsCACert.crt $NIST/InvalidMissingbasicConstraintsTest1EE.crt
test_basicconstraintschecker NIST-Test.4.6.2 EE $NIST/TrustAnchorRootCertificate.crt $NIST/basicConstraintsCriticalcAFalseCACert.crt $NIST/InvalidcAFalseTest2EE.crt
test_basicconstraintschecker NIST-Test.4.6.3 EE $NIST/TrustAnchorRootCertificate.crt $NIST/basicConstraintsNotCriticalcAFalseCACert.crt $NIST/InvalidcAFalseTest3EE.crt
test_basicconstraintschecker NIST-Test.4.6.4 ENE $NIST/TrustAnchorRootCertificate.crt $NIST/basicConstraintsNotCriticalCACert.crt $NIST/ValidbasicConstraintsNotCriticalTest4EE.crt
test_basicconstraintschecker NIST-Test.4.6.5 EE $NIST/TrustAnchorRootCertificate.crt $NIST/pathLenConstraint0CACert.crt $NIST/pathLenConstraint0subCACert.crt $NIST/InvalidpathLenConstraintTest5EE.crt
test_basicconstraintschecker NIST-Test.4.6.6 EE $NIST/TrustAnchorRootCertificate.crt $NIST/pathLenConstraint0CACert.crt $NIST/pathLenConstraint0subCACert.crt $NIST/InvalidpathLenConstraintTest6EE.crt
test_basicconstraintschecker NIST-Test.4.6.7 ENE $NIST/TrustAnchorRootCertificate.crt $NIST/pathLenConstraint0CACert.crt $NIST/ValidpathLenConstraintTest7EE.crt
test_basicconstraintschecker NIST-Test.4.6.8 ENE $NIST/TrustAnchorRootCertificate.crt $NIST/pathLenConstraint0CACert.crt $NIST/ValidpathLenConstraintTest8EE.crt
test_basicconstraintschecker NIST-Test.4.6.9 EE $NIST/TrustAnchorRootCertificate.crt $NIST/pathLenConstraint6CACert.crt $NIST/pathLenConstraint6subCA0Cert.crt $NIST/pathLenConstraint6subsubCA00Cert.crt $NIST/InvalidpathLenConstraintTest9EE.crt
test_basicconstraintschecker NIST-Test.4.6.10 EE $NIST/TrustAnchorRootCertificate.crt $NIST/pathLenConstraint6CACert.crt $NIST/pathLenConstraint6subCA0Cert.crt $NIST/pathLenConstraint6subsubCA00Cert.crt $NIST/InvalidpathLenConstraintTest10EE.crt
test_basicconstraintschecker NIST-Test.4.6.11 EE $NIST/TrustAnchorRootCertificate.crt $NIST/pathLenConstraint6CACert.crt $NIST/pathLenConstraint6subCA1Cert.crt $NIST/pathLenConstraint6subsubCA11Cert.crt $NIST/pathLenConstraint6subsubsubCA11XCert.crt $NIST/InvalidpathLenConstraintTest11EE.crt
test_basicconstraintschecker NIST-Test.4.6.12 EE $NIST/TrustAnchorRootCertificate.crt $NIST/pathLenConstraint6CACert.crt $NIST/pathLenConstraint6subCA1Cert.crt $NIST/pathLenConstraint6subsubCA11Cert.crt $NIST/pathLenConstraint6subsubsubCA11XCert.crt $NIST/InvalidpathLenConstraintTest12EE.crt
test_basicconstraintschecker NIST-Test.4.6.13 ENE $NIST/TrustAnchorRootCertificate.crt $NIST/pathLenConstraint6CACert.crt $NIST/pathLenConstraint6subCA4Cert.crt $NIST/pathLenConstraint6subsubCA41Cert.crt $NIST/pathLenConstraint6subsubsubCA41XCert.crt $NIST/ValidpathLenConstraintTest13EE.crt
test_basicconstraintschecker NIST-Test.4.6.14 ENE $NIST/TrustAnchorRootCertificate.crt $NIST/pathLenConstraint6CACert.crt $NIST/pathLenConstraint6subCA4Cert.crt $NIST/pathLenConstraint6subsubCA41Cert.crt $NIST/pathLenConstraint6subsubsubCA41XCert.crt $NIST/ValidpathLenConstraintTest14EE.crt
test_basicconstraintschecker NIST-Test.4.6.15 ENE $NIST/TrustAnchorRootCertificate.crt $NIST/pathLenConstraint0CACert.crt $NIST/pathLenConstraint0SelfIssuedCACert.crt $NIST/ValidSelfIssuedpathLenConstraintTest15EE.crt
test_basicconstraintschecker NIST-Test.4.6.16 EE $NIST/TrustAnchorRootCertificate.crt $NIST/pathLenConstraint0CACert.crt $NIST/pathLenConstraint0SelfIssuedCACert.crt $NIST/pathLenConstraint0subCA2Cert.crt $NIST/InvalidSelfIssuedpathLenConstraintTest16EE.crt
test_basicconstraintschecker NIST-Test.4.6.17 ENE $NIST/TrustAnchorRootCertificate.crt $NIST/pathLenConstraint1CACert.crt $NIST/pathLenConstraint1SelfIssuedCACert.crt $NIST/pathLenConstraint1subCACert.crt $NIST/pathLenConstraint1SelfIssuedsubCACert.crt $NIST/ValidSelfIssuedpathLenConstraintTest17EE.crt
test_validatechain "NIST-Test.4.7.1" EE $NIST TrustAnchorRootCertificate.crt keyUsageCriticalkeyCertSignFalseCACert.crt InvalidkeyUsageCriticalkeyCertSignFalseTest1EE.crt
test_validatechain "NIST-Test.4.7.2" EE $NIST TrustAnchorRootCertificate.crt keyUsageNotCriticalkeyCertSignFalseCACert.crt InvalidkeyUsageNotCriticalkeyCertSignFalseTest2EE.crt
test_validatechain "NIST-Test.4.7.3" ENE $NIST TrustAnchorRootCertificate.crt keyUsageNotCriticalCACert.crt ValidkeyUsageNotCriticalTest3EE.crt
test_validatechain "NIST-Test.4.7.4" EE $NIST TrustAnchorRootCertificate.crt keyUsageCriticalcRLSignFalseCACert.crt InvalidkeyUsageCriticalcRLSignFalseTest4EE.crt
test_validatechain "NIST-Test.4.7.5" EE $NIST TrustAnchorRootCertificate.crt  keyUsageNotCriticalcRLSignFalseCACert.crt InvalidkeyUsageNotCriticalcRLSignFalseTest5EE.crt
test_policychecker NIST-Test.4.8.1.1-1 ENE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/GoodCACert.crt $NIST/ValidCertificatePathTest1EE.crt
test_policychecker NIST-Test.4.8.1.1-2 ENE "{2.5.29.32.0}" E $NIST/TrustAnchorRootCertificate.crt $NIST/GoodCACert.crt $NIST/ValidCertificatePathTest1EE.crt
test_policychecker NIST-Test.4.8.1.2 ENE "{2.16.840.1.101.3.2.1.48.1}" E $NIST/TrustAnchorRootCertificate.crt $NIST/GoodCACert.crt $NIST/ValidCertificatePathTest1EE.crt
test_policychecker NIST-Test.4.8.1.3 EE "{2.16.840.1.101.3.2.1.48.2}" E $NIST/TrustAnchorRootCertificate.crt $NIST/GoodCACert.crt $NIST/ValidCertificatePathTest1EE.crt
test_policychecker NIST-Test.4.8.1.4 ENE "{2.16.840.1.101.3.2.1.48.1:2.16.840.1.101.3.2.1.48.2}" E $NIST/TrustAnchorRootCertificate.crt $NIST/GoodCACert.crt $NIST/ValidCertificatePathTest1EE.crt
test_policychecker NIST-Test.4.8.2.1 ENE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/NoPoliciesCACert.crt $NIST/AllCertificatesNoPoliciesTest2EE.crt
test_policychecker NIST-Test.4.8.2.2 EE "{2.5.29.32.0}" E $NIST/TrustAnchorRootCertificate.crt $NIST/NoPoliciesCACert.crt $NIST/AllCertificatesNoPoliciesTest2EE.crt
test_policychecker NIST-Test.4.8.3.1 ENE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/GoodCACert.crt $NIST/PoliciesP2subCACert.crt $NIST/DifferentPoliciesTest3EE.crt
test_policychecker NIST-Test.4.8.3.2 EE "{2.5.29.32.0}" E $NIST/TrustAnchorRootCertificate.crt $NIST/GoodCACert.crt $NIST/PoliciesP2subCACert.crt $NIST/DifferentPoliciesTest3EE.crt
test_policychecker NIST-Test.4.8.3.3 EE "{2.16.840.1.101.3.2.1.48.1:2.16.840.1.101.3.2.1.48.2}" E $NIST/TrustAnchorRootCertificate.crt $NIST/GoodCACert.crt $NIST/PoliciesP2subCACert.crt $NIST/DifferentPoliciesTest3EE.crt
test_policychecker NIST-Test.4.8.4 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/GoodCACert.crt $NIST/GoodsubCACert.crt $NIST/DifferentPoliciesTest4EE.crt
test_policychecker NIST-Test.4.8.5 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/GoodCACert.crt $NIST/PoliciesP2subCA2Cert.crt $NIST/DifferentPoliciesTest5EE.crt
test_policychecker NIST-Test.4.8.6.1 ENE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/PoliciesP1234CACert.crt $NIST/PoliciesP1234subCAP123Cert.crt $NIST/PoliciesP1234subsubCAP123P12Cert.crt $NIST/OverlappingPoliciesTest6EE.crt
test_policychecker NIST-Test.4.8.6.2 ENE "{2.16.840.1.101.3.2.1.48.1}" $NIST/TrustAnchorRootCertificate.crt $NIST/PoliciesP1234CACert.crt $NIST/PoliciesP1234subCAP123Cert.crt $NIST/PoliciesP1234subsubCAP123P12Cert.crt $NIST/OverlappingPoliciesTest6EE.crt
test_policychecker NIST-Test.4.8.6.3 EE "{2.16.840.1.101.3.2.1.48.2}" $NIST/TrustAnchorRootCertificate.crt $NIST/PoliciesP1234CACert.crt $NIST/PoliciesP1234subCAP123Cert.crt $NIST/PoliciesP1234subsubCAP123P12Cert.crt $NIST/OverlappingPoliciesTest6EE.crt
test_policychecker NIST-Test.4.8.7 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/PoliciesP123CACert.crt $NIST/PoliciesP123subCAP12Cert.crt $NIST/PoliciesP123subsubCAP12P1Cert.crt $NIST/DifferentPoliciesTest7EE.crt
test_policychecker NIST-Test.4.8.8 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/PoliciesP12CACert.crt $NIST/PoliciesP12subCAP1Cert.crt $NIST/PoliciesP12subsubCAP1P2Cert.crt $NIST/DifferentPoliciesTest8EE.crt
test_policychecker NIST-Test.4.8.9 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/PoliciesP123CACert.crt $NIST/PoliciesP123subCAP12Cert.crt $NIST/PoliciesP123subsubCAP12P2Cert.crt $NIST/PoliciesP123subsubsubCAP12P2P1Cert.crt
test_policychecker NIST-Test.4.8.10.1 ENE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/PoliciesP12CACert.crt $NIST/AllCertificatesSamePoliciesTest10EE.crt
test_policychecker NIST-Test.4.8.10.2 ENE "{2.16.840.1.101.3.2.1.48.1}" $NIST/TrustAnchorRootCertificate.crt $NIST/PoliciesP12CACert.crt $NIST/AllCertificatesSamePoliciesTest10EE.crt
test_policychecker NIST-Test.4.8.10.3 ENE "{2.16.840.1.101.3.2.1.48.2}" $NIST/TrustAnchorRootCertificate.crt $NIST/PoliciesP12CACert.crt $NIST/AllCertificatesSamePoliciesTest10EE.crt
test_policychecker NIST-Test.4.8.11.1 ENE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/anyPolicyCACert.crt $NIST/AllCertificatesanyPolicyTest11EE.crt
test_policychecker NIST-Test.4.8.11.2 ENE "{2.16.840.1.101.3.2.1.48.1}" $NIST/TrustAnchorRootCertificate.crt $NIST/anyPolicyCACert.crt $NIST/AllCertificatesanyPolicyTest11EE.crt
test_policychecker NIST-Test.4.8.12 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/PoliciesP3CACert.crt $NIST/DifferentPoliciesTest12EE.crt
test_policychecker NIST-Test.4.8.13.1 ENE "{2.16.840.1.101.3.2.1.48.1}" $NIST/TrustAnchorRootCertificate.crt $NIST/PoliciesP123CACert.crt $NIST/AllCertificatesSamePoliciesTest13EE.crt
test_policychecker NIST-Test.4.8.13.2 ENE "{2.16.840.1.101.3.2.1.48.2}" $NIST/TrustAnchorRootCertificate.crt $NIST/PoliciesP123CACert.crt $NIST/AllCertificatesSamePoliciesTest13EE.crt
test_policychecker NIST-Test.4.8.13.3 ENE "{2.16.840.1.101.3.2.1.48.3}" $NIST/TrustAnchorRootCertificate.crt $NIST/PoliciesP123CACert.crt $NIST/AllCertificatesSamePoliciesTest13EE.crt
test_policychecker NIST-Test.4.8.14.1 ENE "{2.16.840.1.101.3.2.1.48.1}" $NIST/TrustAnchorRootCertificate.crt $NIST/anyPolicyCACert.crt $NIST/AnyPolicyTest14EE.crt
test_policychecker NIST-Test.4.8.14.2 EE "{2.16.840.1.101.3.2.1.48.2}" E $NIST/TrustAnchorRootCertificate.crt $NIST/anyPolicyCACert.crt $NIST/AnyPolicyTest14EE.crt
test_policychecker NIST-Test.4.8.15.1 ENE "{2.16.840.1.101.3.2.1.48.1}" E $NIST/TrustAnchorRootCertificate.crt $NIST/UserNoticeQualifierTest15EE.crt
test_policychecker NIST-Test.4.8.15.2 EE "{2.16.840.1.101.3.2.1.48.2}" E $NIST/TrustAnchorRootCertificate.crt $NIST/UserNoticeQualifierTest15EE.crt
test_policychecker NIST-Test.4.8.16.1 ENE "{2.16.840.1.101.3.2.1.48.1}" E $NIST/TrustAnchorRootCertificate.crt $NIST/GoodCACert.crt $NIST/UserNoticeQualifierTest16EE.crt
test_policychecker NIST-Test.4.8.16.2 EE "{2.16.840.1.101.3.2.1.48.2}" E $NIST/TrustAnchorRootCertificate.crt $NIST/GoodCACert.crt $NIST/UserNoticeQualifierTest16EE.crt
test_policychecker NIST-Test.4.8.17 ENE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/GoodCACert.crt $NIST/UserNoticeQualifierTest17EE.crt
test_policychecker NIST-Test.4.8.18.1 ENE "{2.16.840.1.101.3.2.1.48.1}" $NIST/TrustAnchorRootCertificate.crt $NIST/PoliciesP12CACert.crt $NIST/UserNoticeQualifierTest18EE.crt
test_policychecker NIST-Test.4.8.18.2 ENE "{2.16.840.1.101.3.2.1.48.2}" $NIST/TrustAnchorRootCertificate.crt $NIST/PoliciesP12CACert.crt $NIST/UserNoticeQualifierTest18EE.crt
test_policychecker NIST-Test.4.8.19 ENE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/UserNoticeQualifierTest19EE.crt
test_policychecker NIST-Test.4.8.20 ENE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/GoodCACert.crt $NIST/CPSPointerQualifierTest20EE.crt
test_policychecker NIST-Test.4.9.1 ENE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/requireExplicitPolicy10CACert.crt $NIST/requireExplicitPolicy10subCACert.crt $NIST/requireExplicitPolicy10subsubCACert.crt $NIST/requireExplicitPolicy10subsubsubCACert.crt $NIST/ValidrequireExplicitPolicyTest1EE.crt
test_policychecker NIST-Test.4.9.2 ENE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/requireExplicitPolicy5CACert.crt $NIST/requireExplicitPolicy5subCACert.crt $NIST/requireExplicitPolicy5subsubCACert.crt $NIST/requireExplicitPolicy5subsubsubCACert.crt $NIST/ValidrequireExplicitPolicyTest2EE.crt
test_policychecker NIST-Test.4.9.3 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/requireExplicitPolicy4CACert.crt $NIST/requireExplicitPolicy4subCACert.crt $NIST/requireExplicitPolicy4subsubCACert.crt $NIST/requireExplicitPolicy4subsubsubCACert.crt $NIST/InvalidrequireExplicitPolicyTest3EE.crt
test_policychecker NIST-Test.4.9.4 ENE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/requireExplicitPolicy0CACert.crt $NIST/requireExplicitPolicy0subCACert.crt $NIST/requireExplicitPolicy0subsubCACert.crt $NIST/requireExplicitPolicy0subsubsubCACert.crt $NIST/ValidrequireExplicitPolicyTest4EE.crt
test_policychecker NIST-Test.4.9.5 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/requireExplicitPolicy7CACert.crt $NIST/requireExplicitPolicy7subCARE2Cert.crt $NIST/requireExplicitPolicy7subsubCARE2RE4Cert.crt $NIST/requireExplicitPolicy7subsubsubCARE2RE4Cert.crt $NIST/InvalidrequireExplicitPolicyTest5EE.crt
test_policychecker NIST-Test.4.9.6 ENE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/requireExplicitPolicy2CACert.crt $NIST/requireExplicitPolicy2SelfIssuedCACert.crt $NIST/ValidSelfIssuedrequireExplicitPolicyTest6EE.crt
test_policychecker NIST-Test.4.9.7 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/requireExplicitPolicy2CACert.crt $NIST/requireExplicitPolicy2SelfIssuedCACert.crt $NIST/requireExplicitPolicy2subCACert.crt $NIST/InvalidSelfIssuedrequireExplicitPolicyTest7EE.crt
test_policychecker NIST-Test.4.9.8 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/requireExplicitPolicy2CACert.crt $NIST/requireExplicitPolicy2SelfIssuedCACert.crt $NIST/requireExplicitPolicy2subCACert.crt $NIST/requireExplicitPolicy2SelfIssuedsubCACert.crt $NIST/InvalidSelfIssuedrequireExplicitPolicyTest8EE.crt
test_policychecker NIST-Test.4.10.1.1 ENE "{2.16.840.1.101.3.2.1.48.1}" $NIST/TrustAnchorRootCertificate.crt $NIST/Mapping1to2CACert.crt $NIST/ValidPolicyMappingTest1EE.crt
test_policychecker NIST-Test.4.10.1.2 EE "{2.16.840.1.101.3.2.1.48.2}" $NIST/TrustAnchorRootCertificate.crt $NIST/Mapping1to2CACert.crt $NIST/ValidPolicyMappingTest1EE.crt
test_policychecker NIST-Test.4.10.1.3 EE "{2.5.29.32.0}" P $NIST/TrustAnchorRootCertificate.crt $NIST/Mapping1to2CACert.crt $NIST/ValidPolicyMappingTest1EE.crt
test_policychecker NIST-Test.4.10.2.1 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/Mapping1to2CACert.crt $NIST/InvalidPolicyMappingTest2EE.crt
test_policychecker NIST-Test.4.10.2.2 EE "{2.5.29.32.0}" P $NIST/TrustAnchorRootCertificate.crt $NIST/Mapping1to2CACert.crt $NIST/InvalidPolicyMappingTest2EE.crt
test_policychecker NIST-Test.4.10.3.1 EE "{2.16.840.1.101.3.2.1.48.1}" $NIST/TrustAnchorRootCertificate.crt $NIST/P12Mapping1to3CACert.crt $NIST/P12Mapping1to3subCACert.crt $NIST/P12Mapping1to3subsubCACert.crt $NIST/ValidPolicyMappingTest3EE.crt
test_policychecker NIST-Test.4.10.3.2 ENE "{2.16.840.1.101.3.2.1.48.2}" $NIST/TrustAnchorRootCertificate.crt $NIST/P12Mapping1to3CACert.crt $NIST/P12Mapping1to3subCACert.crt $NIST/P12Mapping1to3subsubCACert.crt $NIST/ValidPolicyMappingTest3EE.crt
test_policychecker NIST-Test.4.10.4 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/P12Mapping1to3CACert.crt $NIST/P12Mapping1to3subCACert.crt $NIST/P12Mapping1to3subsubCACert.crt $NIST/InvalidPolicyMappingTest4EE.crt
test_policychecker NIST-Test.4.10.5.1 ENE "{2.16.840.1.101.3.2.1.48.1}" $NIST/TrustAnchorRootCertificate.crt $NIST/P1Mapping1to234CACert.crt $NIST/P1Mapping1to234subCACert.crt $NIST/ValidPolicyMappingTest5EE.crt
test_policychecker NIST-Test.4.10.5.2 EE "{2.16.840.1.101.3.2.1.48.6}" $NIST/TrustAnchorRootCertificate.crt $NIST/P1Mapping1to234CACert.crt $NIST/P1Mapping1to234subCACert.crt $NIST/ValidPolicyMappingTest5EE.crt
test_policychecker NIST-Test.4.10.6.1 ENE "{2.16.840.1.101.3.2.1.48.1}" $NIST/TrustAnchorRootCertificate.crt $NIST/P1Mapping1to234CACert.crt $NIST/P1Mapping1to234subCACert.crt $NIST/ValidPolicyMappingTest6EE.crt
test_policychecker NIST-Test.4.10.6.2 EE "{2.16.840.1.101.3.2.1.48.6}" $NIST/TrustAnchorRootCertificate.crt $NIST/P1Mapping1to234CACert.crt $NIST/P1Mapping1to234subCACert.crt $NIST/ValidPolicyMappingTest6EE.crt $NIST/TrustAnchorRootCertificate.crt
test_policychecker NIST-Test.4.10.7.1 ENE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/MappingFromanyPolicyCACert.crt
test_policychecker NIST-Test.4.10.7.2 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/MappingFromanyPolicyCACert.crt $NIST/InvalidMappingFromanyPolicyTest7EE.crt
test_policychecker NIST-Test.4.10.8.1 ENE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/MappingToanyPolicyCACert.crt
test_policychecker NIST-Test.4.10.8.2 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/MappingToanyPolicyCACert.crt $NIST/InvalidMappingToanyPolicyTest8EE.crt
test_policychecker NIST-Test.4.10.9 ENE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/PanyPolicyMapping1to2CACert.crt $NIST/ValidPolicyMappingTest9EE.crt
test_policychecker NIST-Test.4.10.10 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/GoodCACert.crt $NIST/GoodsubCAPanyPolicyMapping1to2CACert.crt $NIST/InvalidPolicyMappingTest10EE.crt
test_policychecker NIST-Test.4.10.11 ENE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/GoodCACert.crt $NIST/GoodsubCAPanyPolicyMapping1to2CACert.crt $NIST/ValidPolicyMappingTest11EE.crt
test_policychecker NIST-Test.4.10.12.1 ENE "{2.16.840.1.101.3.2.1.48.1}" $NIST/TrustAnchorRootCertificate.crt $NIST/P12Mapping1to3CACert.crt $NIST/ValidPolicyMappingTest12EE.crt
test_policychecker NIST-Test.4.10.12.2 ENE "{2.16.840.1.101.3.2.1.48.2}" $NIST/TrustAnchorRootCertificate.crt $NIST/P12Mapping1to3CACert.crt $NIST/ValidPolicyMappingTest12EE.crt
test_policychecker NIST-Test.4.10.13 ENE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/P1anyPolicyMapping1to2CACert.crt $NIST/ValidPolicyMappingTest13EE.crt
test_policychecker NIST-Test.4.10.14 ENE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/P1anyPolicyMapping1to2CACert.crt $NIST/ValidPolicyMappingTest14EE.crt
test_policychecker NIST-Test.4.11.1.1 ENE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/inhibitPolicyMapping0CACert.crt $NIST/inhibitPolicyMapping0subCACert.crt
test_policychecker NIST-Test.4.11.1.2 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/inhibitPolicyMapping0CACert.crt $NIST/inhibitPolicyMapping0subCACert.crt $NIST/InvalidinhibitPolicyMappingTest1EE.crt
test_policychecker NIST-Test.4.11.2 ENE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/inhibitPolicyMapping1P12CACert.crt $NIST/inhibitPolicyMapping1P12subCACert.crt $NIST/ValidinhibitPolicyMappingTest2EE.crt
test_policychecker NIST-Test.4.11.3 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/inhibitPolicyMapping1P12CACert.crt $NIST/inhibitPolicyMapping1P12subCACert.crt $NIST/inhibitPolicyMapping1P12subsubCACert.crt $NIST/InvalidinhibitPolicyMappingTest3EE.crt
test_policychecker NIST-Test.4.11.4 ENE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/inhibitPolicyMapping1P12CACert.crt $NIST/inhibitPolicyMapping1P12subCACert.crt $NIST/inhibitPolicyMapping1P12subsubCACert.crt $NIST/ValidinhibitPolicyMappingTest4EE.crt
test_policychecker NIST-Test.4.11.5 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/inhibitPolicyMapping5CACert.crt $NIST/inhibitPolicyMapping5subCACert.crt $NIST/inhibitPolicyMapping5subsubCACert.crt $NIST/inhibitPolicyMapping5subsubsubCACert.crt $NIST/InvalidinhibitPolicyMappingTest5EE.crt
test_policychecker NIST-Test.4.11.6 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/inhibitPolicyMapping1P12CACert.crt $NIST/inhibitPolicyMapping1P12subCAIPM5Cert.crt $NIST/inhibitPolicyMapping1P12subsubCAIPM5Cert.crt $NIST/InvalidinhibitPolicyMappingTest6EE.crt
test_policychecker NIST-Test.4.11.7 ENE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/inhibitPolicyMapping1P1CACert.crt $NIST/inhibitPolicyMapping1P1SelfIssuedCACert.crt $NIST/inhibitPolicyMapping1P1subCACert.crt $NIST/ValidSelfIssuedinhibitPolicyMappingTest7EE.crt
test_policychecker NIST-Test.4.11.8 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/inhibitPolicyMapping1P1CACert.crt $NIST/inhibitPolicyMapping1P1SelfIssuedCACert.crt $NIST/inhibitPolicyMapping1P1subCACert.crt $NIST/inhibitPolicyMapping1P1subsubCACert.crt $NIST/InvalidSelfIssuedinhibitPolicyMappingTest8EE.crt
test_policychecker NIST-Test.4.11.9 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/inhibitPolicyMapping1P1CACert.crt $NIST/inhibitPolicyMapping1P1SelfIssuedCACert.crt $NIST/inhibitPolicyMapping1P1subCACert.crt $NIST/inhibitPolicyMapping1P1subsubCACert.crt $NIST/InvalidSelfIssuedinhibitPolicyMappingTest9EE.crt
test_policychecker NIST-Test.4.11.10 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/inhibitPolicyMapping1P1CACert.crt $NIST/inhibitPolicyMapping1P1SelfIssuedCACert.crt $NIST/inhibitPolicyMapping1P1subCACert.crt $NIST/inhibitPolicyMapping1P1SelfIssuedsubCACert.crt $NIST/InvalidSelfIssuedinhibitPolicyMappingTest10EE.crt
test_policychecker NIST-Test.4.11.11 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/inhibitPolicyMapping1P1CACert.crt $NIST/inhibitPolicyMapping1P1SelfIssuedCACert.crt $NIST/inhibitPolicyMapping1P1subCACert.crt $NIST/inhibitPolicyMapping1P1SelfIssuedsubCACert.crt $NIST/InvalidSelfIssuedinhibitPolicyMappingTest11EE.crt
test_policychecker NIST-Test.4.12.1 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/inhibitAnyPolicy0CACert.crt $NIST/InvalidinhibitAnyPolicyTest1EE.crt
test_policychecker NIST-Test.4.12.2 ENE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/inhibitAnyPolicy0CACert.crt $NIST/ValidinhibitAnyPolicyTest2EE.crt
test_policychecker NIST-Test.4.12.3.1 ENE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/inhibitAnyPolicy1CACert.crt $NIST/inhibitAnyPolicy1subCA1Cert.crt $NIST/inhibitAnyPolicyTest3EE.crt
test_policychecker NIST-Test.4.12.3.2 EE "{2.5.29.32.0}" A $NIST/TrustAnchorRootCertificate.crt $NIST/inhibitAnyPolicy1CACert.crt $NIST/inhibitAnyPolicy1subCA1Cert.crt $NIST/inhibitAnyPolicyTest3EE.crt
test_policychecker NIST-Test.4.12.4 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/inhibitAnyPolicy1CACert.crt $NIST/inhibitAnyPolicy1subCA1Cert.crt $NIST/InvalidinhibitAnyPolicyTest4EE.crt
test_policychecker NIST-Test.4.12.5 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/inhibitAnyPolicy5CACert.crt $NIST/inhibitAnyPolicy5subCACert.crt $NIST/inhibitAnyPolicy5subsubCACert.crt $NIST/InvalidinhibitAnyPolicyTest5EE.crt
test_policychecker NIST-Test.4.12.6 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/inhibitAnyPolicy1CACert.crt $NIST/inhibitAnyPolicy1subCAIAP5Cert.crt $NIST/InvalidinhibitAnyPolicyTest6EE.crt
test_policychecker NIST-Test.4.12.7 ENE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/inhibitAnyPolicy1CACert.crt $NIST/inhibitAnyPolicy1SelfIssuedCACert.crt $NIST/inhibitAnyPolicy1subCA2Cert.crt $NIST/ValidSelfIssuedinhibitAnyPolicyTest7EE.crt
test_policychecker NIST-Test.4.12.8 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/inhibitAnyPolicy1CACert.crt $NIST/inhibitAnyPolicy1SelfIssuedCACert.crt $NIST/inhibitAnyPolicy1subCA2Cert.crt $NIST/inhibitAnyPolicy1subsubCA2Cert.crt $NIST/InvalidSelfIssuedinhibitAnyPolicyTest8EE.crt
test_policychecker NIST-Test.4.12.9 ENE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/inhibitAnyPolicy1CACert.crt $NIST/inhibitAnyPolicy1SelfIssuedCACert.crt $NIST/inhibitAnyPolicy1subCA2Cert.crt $NIST/inhibitAnyPolicy1SelfIssuedsubCA2Cert.crt $NIST/ValidSelfIssuedinhibitAnyPolicyTest9EE.crt
test_policychecker NIST-Test.4.12.10 EE "{2.5.29.32.0}" $NIST/TrustAnchorRootCertificate.crt $NIST/inhibitAnyPolicy1CACert.crt $NIST/inhibitAnyPolicy1SelfIssuedCACert.crt $NIST/inhibitAnyPolicy1subCA2Cert.crt $NIST/InvalidSelfIssuedinhibitAnyPolicyTest10EE.crt
test_basicconstraintschecker NIST-Test.4.13.1 ENE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDN1CACert.crt $NIST/ValidDNnameConstraintsTest1EE.crt
test_basicconstraintschecker NIST-Test.4.13.2 EE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDN1CACert.crt $NIST/InvalidDNnameConstraintsTest2EE.crt
test_basicconstraintschecker NIST-Test.4.13.3 EE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDN1CACert.crt $NIST/InvalidDNnameConstraintsTest3EE.crt
test_basicconstraintschecker NIST-Test.4.13.4 ENE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDN1CACert.crt $NIST/ValidDNnameConstraintsTest4EE.crt
test_basicconstraintschecker NIST-Test.4.13.5 ENE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDN2CACert.crt $NIST/ValidDNnameConstraintsTest5EE.crt
test_basicconstraintschecker NIST-Test.4.13.6 ENE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDN3CACert.crt $NIST/ValidDNnameConstraintsTest6EE.crt
test_basicconstraintschecker NIST-Test.4.13.7 EE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDN3CACert.crt $NIST/InvalidDNnameConstraintsTest7EE.crt
test_basicconstraintschecker NIST-Test.4.13.8 EE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDN4CACert.crt $NIST/InvalidDNnameConstraintsTest8EE.crt
test_basicconstraintschecker NIST-Test.4.13.9 EE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDN4CACert.crt $NIST/InvalidDNnameConstraintsTest9EE.crt
test_basicconstraintschecker NIST-Test.4.13.10 EE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDN5CACert.crt $NIST/InvalidDNnameConstraintsTest10EE.crt
test_basicconstraintschecker NIST-Test.4.13.11 ENE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDN5CACert.crt $NIST/ValidDNnameConstraintsTest11EE.crt
test_basicconstraintschecker NIST-Test.4.13.12 EE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDN1CACert.crt $NIST/nameConstraintsDN1subCA1Cert.crt $NIST/InvalidDNnameConstraintsTest12EE.crt
test_basicconstraintschecker NIST-Test.4.13.13 EE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDN1CACert.crt $NIST/nameConstraintsDN1subCA2Cert.crt $NIST/InvalidDNnameConstraintsTest13EE.crt
test_basicconstraintschecker NIST-Test.4.13.14 ENE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDN1CACert.crt $NIST/nameConstraintsDN1subCA2Cert.crt $NIST/ValidDNnameConstraintsTest14EE.crt
test_basicconstraintschecker NIST-Test.4.13.15 EE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDN3CACert.crt $NIST/nameConstraintsDN3subCA1Cert.crt $NIST/InvalidDNnameConstraintsTest15EE.crt
test_basicconstraintschecker NIST-Test.4.13.16 EE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDN3CACert.crt $NIST/nameConstraintsDN3subCA1Cert.crt $NIST/InvalidDNnameConstraintsTest16EE.crt
test_basicconstraintschecker NIST-Test.4.13.17 EE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDN3CACert.crt $NIST/nameConstraintsDN3subCA2Cert.crt $NIST/InvalidDNnameConstraintsTest17EE.crt
test_basicconstraintschecker NIST-Test.4.13.18 ENE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDN3CACert.crt $NIST/nameConstraintsDN3subCA2Cert.crt $NIST/ValidDNnameConstraintsTest18EE.crt
test_basicconstraintschecker NIST-Test.4.13.19 ENE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDN1CACert.crt $NIST/nameConstraintsDN1SelfIssuedCACert.crt $NIST/ValidDNnameConstraintsTest19EE.crt
test_basicconstraintschecker NIST-Test.4.13.20 EE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDN1CACert.crt $NIST/InvalidDNnameConstraintsTest20EE.crt
test_basicconstraintschecker NIST-Test.4.13.21 ENE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsRFC822CA1Cert.crt $NIST/ValidRFC822nameConstraintsTest21EE.crt
test_basicconstraintschecker NIST-Test.4.13.22 EE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsRFC822CA1Cert.crt $NIST/InvalidRFC822nameConstraintsTest22EE.crt
test_basicconstraintschecker NIST-Test.4.13.23 ENE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsRFC822CA2Cert.crt $NIST/ValidRFC822nameConstraintsTest23EE.crt
test_basicconstraintschecker NIST-Test.4.13.24 EE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsRFC822CA2Cert.crt $NIST/InvalidRFC822nameConstraintsTest24EE.crt
test_basicconstraintschecker NIST-Test.4.13.25 ENE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsRFC822CA3Cert.crt $NIST/ValidRFC822nameConstraintsTest25EE.crt
test_basicconstraintschecker NIST-Test.4.13.26 EE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsRFC822CA3Cert.crt $NIST/InvalidRFC822nameConstraintsTest26EE.crt
test_basicconstraintschecker NIST-Test.4.13.27 ENE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDN1CACert.crt  $NIST/nameConstraintsDN1subCA3Cert.crt $NIST/ValidDNandRFC822nameConstraintsTest27EE.crt
test_basicconstraintschecker NIST-Test.4.13.28 EE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDN1CACert.crt  $NIST/nameConstraintsDN1subCA3Cert.crt $NIST/InvalidDNandRFC822nameConstraintsTest28EE.crt
test_basicconstraintschecker NIST-Test.4.13.29 EE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDN1CACert.crt  $NIST/nameConstraintsDN1subCA3Cert.crt $NIST/InvalidDNandRFC822nameConstraintsTest29EE.crt
test_basicconstraintschecker NIST-Test.4.13.30 ENE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDNS1CACert.crt $NIST/ValidDNSnameConstraintsTest30EE.crt
test_basicconstraintschecker NIST-Test.4.13.31 EE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDNS1CACert.crt $NIST/InvalidDNSnameConstraintsTest31EE.crt
test_basicconstraintschecker NIST-Test.4.13.32 ENE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDNS2CACert.crt $NIST/ValidDNSnameConstraintsTest32EE.crt
test_basicconstraintschecker NIST-Test.4.13.33 EE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDNS2CACert.crt $NIST/InvalidDNSnameConstraintsTest33EE.crt
test_basicconstraintschecker NIST-Test.4.13.34 ENE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsURI1CACert.crt $NIST/ValidURInameConstraintsTest34EE.crt
test_basicconstraintschecker NIST-Test.4.13.35 EE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsURI1CACert.crt $NIST/InvalidURInameConstraintsTest35EE.crt
test_basicconstraintschecker NIST-Test.4.13.36 ENE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsURI2CACert.crt $NIST/ValidURInameConstraintsTest36EE.crt
test_basicconstraintschecker NIST-Test.4.13.37 EE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsURI2CACert.crt $NIST/InvalidURInameConstraintsTest37EE.crt
test_basicconstraintschecker NIST-Test.4.13.38 EE $NIST/TrustAnchorRootCertificate.crt $NIST/nameConstraintsDNS1CACert.crt $NIST/InvalidDNSnameConstraintsTest38EE.crt
test_basicconstraintschecker NIST-Test.4.16.1 ENE $NIST/TrustAnchorRootCertificate.crt $NIST/ValidUnknownNotCriticalCertificateExtensionTest1EE.crt
test_basicconstraintschecker NIST-Test.4.16.2 EE $NIST/TrustAnchorRootCertificate.crt $NIST/InvalidUnknownCriticalCertificateExtensionTest2EE.crt
test_buildchain_uchecker NIST-Test.4.1.1-without-OID ENE - $NIST ValidCertificatePathTest1EE.crt GoodCACert.crt TrustAnchorRootCertificate.crt
test_buildchain_uchecker NIST-Test.4.1.1-with-OID-without-forwardSupport ENE 2.5.29.19 $NIST ValidCertificatePathTest1EE.crt GoodCACert.crt TrustAnchorRootCertificate.crt
test_buildchain_uchecker NIST-Test.4.1.1-with-OID-forwardSupport ENE F2.5.29.19 $NIST ValidCertificatePathTest1EE.crt GoodCACert.crt TrustAnchorRootCertificate.crt
test_buildchain NIST-Test.4.1.1 ENE $NIST ValidCertificatePathTest1EE.crt GoodCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.1.2 EE $NIST InvalidCASignatureTest2EE.crt BadSignedCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.1.3 EE $NIST InvalidEESignatureTest3EE.crt GoodCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.1.4 ENE $NIST ValidDSASignaturesTest4EE.crt DSACACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.1.5 ENE $NIST ValidDSAParameterInheritanceTest5EE.crt DSAParametersInheritedCACert.crt DSACACert.crt TrustAnchorRootCertificate.crt  
test_buildchain NIST-Test.4.1.6 EE $NIST InvalidDSASignatureTest6EE.crt DSACACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.2.1 EE $NIST InvalidCAnotBeforeDateTest1EE.crt BadnotBeforeDateCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.2.2 EE $NIST InvalidEEnotBeforeDateTest2EE.crt GoodCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.2.3 ENE $NIST Validpre2000UTCnotBeforeDateTest3EE.crt GoodCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.2.4 ENE $NIST ValidGeneralizedTimenotBeforeDateTest4EE.crt GoodCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.2.5 EE $NIST InvalidCAnotAfterDateTest5EE.crt BadnotAfterDateCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.2.6 EE $NIST InvalidEEnotAfterDateTest6EE.crt GoodCACert.crt TrustAnchorRootCertificate.crt
test_buildchain NIST-Test.4.2.7 EE $NIST Invalidpre2000UTCEEnotAfterDateTest7EE.crt GoodCACert.crt TrustAnchorRootCertificate.crt
test_buildchain NIST-Test.4.2.8 ENE $NIST ValidGeneralizedTimenotAfterDateTest8EE.crt GoodCACert.crt TrustAnchorRootCertificate.crt
test_buildchain NIST-Test.4.3.1 EE $NIST InvalidNameChainingTest1EE.crt GoodCACert.crt TrustAnchorRootCertificate.crt
test_buildchain NIST-Test.4.3.2 EE $NIST InvalidNameChainingOrderTest2EE.crt NameOrderingCACert.crt TrustAnchorRootCertificate.crt
test_buildchain NIST-Test.4.3.3 ENE $NIST ValidNameChainingWhitespaceTest3EE.crt GoodCACert.crt TrustAnchorRootCertificate.crt
test_buildchain NIST-Test.4.3.4 ENE $NIST ValidNameChainingWhitespaceTest4EE.crt GoodCACert.crt TrustAnchorRootCertificate.crt
test_buildchain NIST-Test.4.3.5 ENE $NIST ValidNameChainingCapitalizationTest5EE.crt GoodCACert.crt TrustAnchorRootCertificate.crt
test_buildchain NIST-Test.4.3.6 ENE $NIST ValidNameUIDsTest6EE.crt UIDCACert.crt TrustAnchorRootCertificate.crt
test_buildchain NIST-Test.4.3.7 ENE $NIST ValidRFC3280MandatoryAttributeTypesTest7EE.crt RFC3280MandatoryAttributeTypesCACert.crt TrustAnchorRootCertificate.crt
test_buildchain NIST-Test.4.3.9 ENE $NIST ValidUTF8StringEncodedNamesTest9EE.crt UTF8StringEncodedNamesCACert.crt TrustAnchorRootCertificate.crt
test_buildchain NIST-Test.4.3.10 ENE $NIST ValidRolloverfromPrintableStringtoUTF8StringTest10EE.crt RolloverfromPrintableStringtoUTF8StringCACert.crt TrustAnchorRootCertificate.crt
test_buildchain NIST-Test.4.3.11 ENE $NIST ValidUTF8StringCaseInsensitiveMatchTest11EE.crt UTF8StringCaseInsensitiveMatchCACert.crt TrustAnchorRootCertificate.crt
test_buildchain NIST-Test.4.4.1 EE $NIST InvalidMissingCRLTest1EE.crt NoCRLCACert.crt TrustAnchorRootCertificate.crt
test_buildchain NIST-Test.4.4.2 EE $NIST InvalidRevokedCATest2EE.crt RevokedsubCACert.crt GoodCACert.crt TrustAnchorRootCertificate.crt
test_buildchain NIST-Test.4.4.3 EE $NIST InvalidRevokedEETest3EE.crt GoodCACert.crt TrustAnchorRootCertificate.crt
test_buildchain NIST-Test.4.4.4 EE $NIST InvalidBadCRLSignatureTest4EE.crt BadSignedCACert.crt TrustAnchorRootCertificate.crt
test_buildchain NIST-Test.4.4.5 EE $NIST InvalidBadCRLIssuerNameTest5EE.crt BadCRLIssuerNameCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.4.6 EE $NIST InvalidWrongCRLTest6EE.crt WrongCRLCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.4.7 ENE $NIST ValidTwoCRLsTest7EE.crt TwoCRLsCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.4.8 EE $NIST InvalidUnknownCRLEntryExtensionTest8EE.crt UnknownCRLEntryExtensionCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.4.9 EE $NIST InvalidUnknownCRLExtensionTest9EE.crt UnknownCRLExtensionCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.4.10 EE $NIST InvalidUnknownCRLExtensionTest10EE.crt UnknownCRLExtensionCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.4.11 EE $NIST InvalidOldCRLnextUpdateTest11EE.crt OldCRLnextUpdateCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.4.12 EE $NIST Invalidpre2000CRLnextUpdateTest12EE.crt pre2000CRLnextUpdateCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.4.13 ENE $NIST ValidGeneralizedTimeCRLnextUpdateTest13EE.crt GeneralizedTimeCRLnextUpdateCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.4.14 ENE $NIST ValidNegativeSerialNumberTest14EE.crt NegativeSerialNumberCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.4.15 EE $NIST InvalidNegativeSerialNumberTest15EE.crt NegativeSerialNumberCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.4.16 ENE $NIST ValidLongSerialNumberTest16EE.crt LongSerialNumberCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.4.17 ENE $NIST ValidLongSerialNumberTest17EE.crt LongSerialNumberCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.4.18 EE $NIST InvalidLongSerialNumberTest18EE.crt LongSerialNumberCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.4.20 EE $NIST InvalidSeparateCertificateandCRLKeysTest20EE.crt SeparateCertificateandCRLKeysCRLSigningCert.crt TrustAnchorRootCertificate.crt SeparateCertificateandCRLKeysCertificateSigningCACert.crt 
test_buildchain NIST-Test.4.5.1 ENE $NIST ValidBasicSelfIssuedOldWithNewTest1EE.crt BasicSelfIssuedNewKeyOldWithNewCACert.crt BasicSelfIssuedNewKeyCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.5.2 EE $NIST InvalidBasicSelfIssuedOldWithNewTest2EE.crt BasicSelfIssuedNewKeyOldWithNewCACert.crt BasicSelfIssuedNewKeyCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.6.1 EE $NIST InvalidMissingbasicConstraintsTest1EE.crt MissingbasicConstraintsCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.6.2 EE $NIST InvalidcAFalseTest2EE.crt basicConstraintsCriticalcAFalseCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.6.3 EE $NIST InvalidcAFalseTest3EE.crt basicConstraintsNotCriticalcAFalseCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.6.4 ENE $NIST ValidbasicConstraintsNotCriticalTest4EE.crt basicConstraintsNotCriticalCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.6.5 EE $NIST InvalidpathLenConstraintTest5EE.crt pathLenConstraint0subCACert.crt pathLenConstraint0CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.6.6 EE $NIST InvalidpathLenConstraintTest6EE.crt pathLenConstraint0subCACert.crt pathLenConstraint0CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.6.7 ENE $NIST ValidpathLenConstraintTest7EE.crt pathLenConstraint0CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.6.8 ENE $NIST ValidpathLenConstraintTest8EE.crt pathLenConstraint0CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.6.9 EE $NIST InvalidpathLenConstraintTest9EE.crt pathLenConstraint6subCA0Cert.crt pathLenConstraint6subsubCA00Cert.crt pathLenConstraint6CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.6.10 EE $NIST InvalidpathLenConstraintTest10EE.crt pathLenConstraint6subsubCA00Cert.crt pathLenConstraint6subCA0Cert.crt pathLenConstraint6CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.6.11 EE $NIST InvalidpathLenConstraintTest11EE.crt pathLenConstraint6subsubsubCA11XCert.crt pathLenConstraint6subsubCA11Cert.crt pathLenConstraint6subCA1Cert.crt pathLenConstraint6CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.6.12 EE $NIST InvalidpathLenConstraintTest12EE.crt pathLenConstraint6subsubsubCA11XCert.crt pathLenConstraint6subsubCA11Cert.crt pathLenConstraint6subCA1Cert.crt pathLenConstraint6CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.6.13 ENE $NIST ValidpathLenConstraintTest13EE.crt pathLenConstraint6subsubsubCA41XCert.crt pathLenConstraint6subsubCA41Cert.crt pathLenConstraint6subCA4Cert.crt pathLenConstraint6CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.6.14 ENE $NIST ValidpathLenConstraintTest14EE.crt pathLenConstraint6subsubsubCA41XCert.crt pathLenConstraint6subsubCA41Cert.crt pathLenConstraint6subCA4Cert.crt pathLenConstraint6CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.6.15 ENE $NIST ValidSelfIssuedpathLenConstraintTest15EE.crt pathLenConstraint0SelfIssuedCACert.crt pathLenConstraint0CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.6.16 EE $NIST InvalidSelfIssuedpathLenConstraintTest16EE.crt pathLenConstraint0subCA2Cert.crt pathLenConstraint0SelfIssuedCACert.crt pathLenConstraint0CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.6.17 ENE $NIST ValidSelfIssuedpathLenConstraintTest17EE.crt pathLenConstraint1SelfIssuedsubCACert.crt pathLenConstraint1subCACert.crt pathLenConstraint1SelfIssuedCACert.crt pathLenConstraint1CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.7.1 EE $NIST InvalidkeyUsageCriticalkeyCertSignFalseTest1EE.crt keyUsageCriticalkeyCertSignFalseCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.7.2 EE $NIST InvalidkeyUsageNotCriticalkeyCertSignFalseTest2EE.crt keyUsageNotCriticalkeyCertSignFalseCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.7.3 ENE $NIST ValidkeyUsageNotCriticalTest3EE.crt keyUsageNotCriticalCACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.7.4 EE $NIST InvalidkeyUsageCriticalcRLSignFalseTest4EE.crt keyUsageCriticalcRLSignFalseCACert.crt TrustAnchorRootCertificate.crt  
test_buildchain NIST-Test.4.7.5 EE $NIST InvalidkeyUsageNotCriticalcRLSignFalseTest5EE.crt keyUsageNotCriticalcRLSignFalseCACert.crt TrustAnchorRootCertificate.crt  
test_buildchain NIST-Test.4.13.1 ENE $NIST ValidDNnameConstraintsTest1EE.crt nameConstraintsDN1CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.2 EE $NIST InvalidDNnameConstraintsTest2EE.crt nameConstraintsDN1CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.3 EE $NIST InvalidDNnameConstraintsTest3EE.crt nameConstraintsDN1CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.4 ENE $NIST ValidDNnameConstraintsTest4EE.crt nameConstraintsDN1CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.5 ENE $NIST ValidDNnameConstraintsTest5EE.crt nameConstraintsDN2CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.6 ENE $NIST ValidDNnameConstraintsTest6EE.crt nameConstraintsDN3CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.7 EE $NIST InvalidDNnameConstraintsTest7EE.crt nameConstraintsDN3CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.8 EE $NIST InvalidDNnameConstraintsTest8EE.crt nameConstraintsDN4CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.9 EE $NIST InvalidDNnameConstraintsTest9EE.crt nameConstraintsDN4CACert.crt nameConstraintsDN4CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.10 EE $NIST InvalidDNnameConstraintsTest10EE.crt nameConstraintsDN5CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.11 ENE $NIST ValidDNnameConstraintsTest11EE.crt nameConstraintsDN5CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.12 EE $NIST InvalidDNnameConstraintsTest12EE.crt nameConstraintsDN1subCA1Cert.crt nameConstraintsDN1CACert.crt TrustAnchorRootCertificate.crt
test_buildchain NIST-Test.4.13.13 EE $NIST InvalidDNnameConstraintsTest13EE.crt nameConstraintsDN1subCA2Cert.crt nameConstraintsDN1subCA2Cert.crt nameConstraintsDN1CACert.crt TrustAnchorRootCertificate.crt
test_buildchain NIST-Test.4.13.14 ENE $NIST ValidDNnameConstraintsTest14EE.crt  nameConstraintsDN1subCA2Cert.crt nameConstraintsDN1CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.15 EE $NIST InvalidDNnameConstraintsTest15EE.crt nameConstraintsDN3subCA1Cert.crt nameConstraintsDN3CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.16 EE $NIST InvalidDNnameConstraintsTest16EE.crt nameConstraintsDN3subCA1Cert.crt nameConstraintsDN3CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.17 EE $NIST InvalidDNnameConstraintsTest17EE.crt nameConstraintsDN3subCA2Cert.crt nameConstraintsDN3CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.18 ENE $NIST ValidDNnameConstraintsTest18EE.crt nameConstraintsDN3subCA2Cert.crt nameConstraintsDN3CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.19 ENE $NIST ValidDNnameConstraintsTest19EE.crt nameConstraintsDN1SelfIssuedCACert.crt nameConstraintsDN1CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.20 EE $NIST InvalidDNnameConstraintsTest20EE.crt nameConstraintsDN1CACert.crt TrustAnchorRootCertificate.crt
test_buildchain NIST-Test.4.13.21 ENE $NIST ValidRFC822nameConstraintsTest21EE.crt nameConstraintsRFC822CA1Cert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.22 EE $NIST InvalidRFC822nameConstraintsTest22EE.crt nameConstraintsRFC822CA1Cert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.23 ENE $NIST ValidRFC822nameConstraintsTest23EE.crt nameConstraintsRFC822CA2Cert.crt  TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.24 EE $NIST InvalidRFC822nameConstraintsTest24EE.crt nameConstraintsRFC822CA2Cert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.25 ENE $NIST ValidRFC822nameConstraintsTest25EE.crt nameConstraintsRFC822CA3Cert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.26 EE $NIST InvalidRFC822nameConstraintsTest26EE.crt nameConstraintsRFC822CA3Cert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.27 ENE $NIST ValidDNandRFC822nameConstraintsTest27EE.crt nameConstraintsDN1subCA3Cert.crt nameConstraintsDN1CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.28 EE $NIST InvalidDNandRFC822nameConstraintsTest28EE.crt nameConstraintsDN1subCA3Cert.crt nameConstraintsDN1CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.29 EE $NIST InvalidDNandRFC822nameConstraintsTest29EE.crt nameConstraintsDN1subCA3Cert.crt nameConstraintsDN1CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.30 ENE $NIST ValidDNSnameConstraintsTest30EE.crt nameConstraintsDNS1CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.31 EE $NIST InvalidDNSnameConstraintsTest31EE.crt nameConstraintsDNS1CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.32 ENE $NIST ValidDNSnameConstraintsTest32EE.crt nameConstraintsDNS2CACert.crt TrustAnchorRootCertificate.crt
test_buildchain NIST-Test.4.13.33 EE $NIST InvalidDNSnameConstraintsTest33EE.crt nameConstraintsDNS2CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.34 ENE $NIST ValidURInameConstraintsTest34EE.crt nameConstraintsURI1CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.35 EE $NIST InvalidURInameConstraintsTest35EE.crt nameConstraintsURI1CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.36 ENE $NIST ValidURInameConstraintsTest36EE.crt nameConstraintsURI2CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.37 EE $NIST InvalidURInameConstraintsTest37EE.crt nameConstraintsURI2CACert.crt TrustAnchorRootCertificate.crt 
test_buildchain NIST-Test.4.13.38 EE $NIST InvalidDNSnameConstraintsTest38EE.crt nameConstraintsDNS1CACert.crt TrustAnchorRootCertificate.crt 
EOF


    if [[ ${errors} -eq 0 ]]; then
        if [[ ${memErrors} -eq 0 ]]; then
            Display "\n************************************************************"
            Display "END OF TESTS FOR PKIX TOP: ALL TESTS COMPLETED SUCCESSFULLY"
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
    Display "END OF TESTS FOR PKIX TOP: ${errors} UNIT TEST${plural} FAILED:\n${failedpgms}"
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
##########
ParseArgs $*
RunTests
totalErrors=$?
return ${totalErrors}

##########################################################
#
# Document NIST tests that are not currently running for builder...
# 4.3.8  4.4.19  4.4.21
#
# Others
# 4.5.4  4.5.5, 4.5.6, 4.5.7, 4.5.8
# 4.14.* Distribution Point - functionality not yet implemented
# 4.15.* Delta CRL - not supported
##########################################################
# Following tests are not run becuase of bugs beyond libpkix:
# test_buildchain NIST-Test.4.3.8 ENE $NIST ValidRFC3280OptionalAttributeTypesTest8EE.crt RFC3280OptionalAttributeTypesCACert.crt TrustAnchorRootCertificate.crt

# Following tests are not supported by libpkix : separate certificate
# NIST test 4.4.19 and 4.4.21

# Following tests are not supported by libpkix : cert dp, cert chain definition
# NIST tests 4.5.4, 4.5.5
#test_buildchain NIST-Test.4.5.7 EE $NIST InvalidBasicSelfIssuedCRLSigningKeyTest7EE.crt BasicSelfIssuedCRLSigningKeyCRLCert.crt TrustAnchorRootCertificate.crt BasicSelfIssuedCRLSigningKeyCACert.crt 
#test_buildchain NIST-Test.4.5.8 EE $NIST InvalidBasicSelfIssuedCRLSigningKeyTest8EE.crt BasicSelfIssuedCRLSigningKeyCRLCert.crt BasicSelfIssuedCRLSigningKeyCACert.crt TrustAnchorRootCertificate.crt 


# Following tests are not supported by libpkix : self-issued, multiple keys, one for cert, one for CRL
#test_validatechain NIST-Test.4.5.3 ENE $NIST TrustAnchorRootCertificate.crt BasicSelfIssuedOldKeyCACert.crt BasicSelfIssuedOldKeyNewWithOldCACert.crt ValidBasicSelfIssuedNewWithOldTest3EE.crt
#test_defaultcrlchecker NIST-Test.4.5.4 ENE $NIST/../crls $NIST/TrustAnchorRootCertificate.crt $NIST/BasicSelfIssuedOldKeyCACert.crt $NIST/BasicSelfIssuedOldKeyNewWithOldCACert.crt $NIST/ValidBasicSelfIssuedNewWithOldTest4EE.crt
#test_defaultcrlchecker NIST-Test.4.5.6 ENE $NIST/../crls $NIST/TrustAnchorRootCertificate.crt $NIST/BasicSelfIssuedCRLSigningKeyCACert.crt $NIST/BasicSelfIssuedCRLSigningKeyCRLCert.crt $NIST/ValidBasicSelfIssuedCRLSigningKeyTest6EE.crt

# Need to recreate certs with BC extension and Key Usage
#test_buildchain single_sig ENE build_data/single_path/signature/pass yassir2hanfei.crt greg2yassir.crt jes2greg.crt jes2jes.crt
#test_buildchain single-sig EE build_data/single_path/signature/fail yassir2hanfei.crt jes2jes.crt
#test_buildchain multi-sig ENE build_data/multi_path/signature/pass yassir2hanfei.crt greg2yassir.crt jes2greg.crt jes2jes.crt
#test_buildchain multi-sig EE build_data/multi_path/signature/fail yassir2hanfei.crt greg2yassir.crt yassir2hanfei.crt
#test_buildchain backtrack-sig ENE build_data/backtracking/signature yassir2hanfei.crt labs2yassir.crt jes2labs.crt jes2jes.crtn
