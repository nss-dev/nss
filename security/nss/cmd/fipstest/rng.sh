#!/bin/sh
#
# A Bourne shell script for running the NIST RNG Validation Suite
#
# Before you run the script, set your PATH, LD_LIBRARY_PATH, ... environment
# variables appropriately so that the fipstest command and the NSPR and NSS
# shared libraries/DLLs are on the search path.  Then run this script in the
# directory where the REQUEST (.req) files reside.  The script generates the
# RESPONSE (.rsp) files in the same directory.
BASEDIR=${1-.}
TESTDIR=${BASEDIR}/DRBG800-90
COMMAND=${2-run}
REQDIR=${BASEDIR}/req
RSPDIR=${BASEDIR}/resp

drbg_requests="
Hash_DRBG.req
"

if [ ${COMMAND} = "verify" ]; then
    for request in $drbg_requests; do
	sh ./validate1.sh ${TESTDIR} $request
    done
    exit 0
fi
for request in $drbg_requests; do
    response=`echo $request | sed -e "s/req/rsp/"`
    echo $request $response
    fipstest drbg ${REQDIR}/$request > ${RSPDIR}/$response
done
