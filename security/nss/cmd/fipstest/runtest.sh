#!/bin/sh
TESTDIR=${1-.}
COMMAND=${2-run}
TESTS="aes dsa hmac rng rsa sha tdea"
#TESTS="aes hmac rng rsa sha tdea"
if [ ${NSS_ENABLE_ECC}x = 1x ]; then
   TESTS=${TESTS} ecdsa
fi
for i in $TESTS
do
    echo "********************Running $i tests"
    sh ./${i}.sh ${TESTDIR} ${COMMAND}
done
