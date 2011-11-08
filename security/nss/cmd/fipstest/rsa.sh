#!/bin/sh
#
# A Bourne shell script for running the NIST RSA Validation System
#
# Before you run the script, set your PATH, LD_LIBRARY_PATH, ... environment
# variables appropriately so that the fipstest command and the NSPR and NSS
# shared libraries/DLLs are on the search path.  Then run this script in the
# directory where the REQUEST (.req) files reside.  The script generates the
# RESPONSE (.rsp) files in the same directory.
BASEDIR=${1-.}
TESTDIR=${BASEDIR}/RSA
COMMAND=${2-run}
REQDIR=${TESTDIR}/req
RSPDIR=${TESTDIR}/resp

if [ ${COMMAND} = "verify" ]; then
#verify the signatures. The fax file does not have any known answers, so
#use our own verify function.
    name=SigGen15_186-2
    echo ">>>>>  $name"
    fipstest rsa sigver ${RSPDIR}/$name.rsp | grep ^Result.=.F
#    fipstest rsa sigver ${REQDIR}/SigVer15_186-2.req | grep ^Result.=.F
#The Fax file has the private exponent and the salt value, remove it
#also remove the false reason
    sh ./validate1.sh ${TESTDIR} SigVer15_186-2.req ' ' '-e /^SaltVal/d -e/^d.=/d -e /^p.=/d -e /^q.=/d -e /^EM.with/d -e /^Result.=.F/s;.(.*);;'
    exit 0
fi

request=SigGen15_186-2.req
response=`echo $request | sed -e "s/req/rsp/"`
echo $request $response
fipstest rsa siggen ${REQDIR}/$request > ${RSPDIR}/$response

request=SigVer15_186-2.req
response=`echo $request | sed -e "s/req/rsp/"`
echo $request $response
fipstest rsa sigver ${REQDIR}/$request > ${RSPDIR}/$response
