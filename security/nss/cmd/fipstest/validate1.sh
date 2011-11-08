#!/bin/sh
TESTDIR=${1-.}
request=${2}
extraneous_response=${3}
extraneous_fax=${4}
name=`basename $request .req`
echo ">>>>>  $name"
sed -e 's;;;g' -e 's;	; ;g' -e '/^#/d' $extraneous_response ${TESTDIR}/resp/${name}.rsp > /tmp/y1
sed -e 's;;;g' -e 's;	; ;g' -e '/^#/d' $extraneous_fax ${TESTDIR}/fax/${name}.fax > /tmp/y2
diff -w -B /tmp/y1 /tmp/y2
