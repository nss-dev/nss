#! /bin/sh
#
# The contents of this file are subject to the Mozilla Public
# License Version 1.1 (the "License"); you may not use this file
# except in compliance with the License. You may obtain a copy of
# the License at http://www.mozilla.org/MPL/
# 
# Software distributed under the License is distributed on an "AS
# IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
# implied. See the License for the specific language governing
# rights and limitations under the License.
# 
# The Original Code is the Netscape security libraries.
# 
# The Initial Developer of the Original Code is Netscape
# Communications Corporation.  Portions created by Netscape are 
# Copyright (C) 1994-2000 Netscape Communications Corporation.  All
# Rights Reserved.
# 
# Contributor(s):
# 
# Alternatively, the contents of this file may be used under the
# terms of the GNU General Public License Version 2 or later (the
# "GPL"), in which case the provisions of the GPL are applicable 
# instead of those above.  If you wish to allow use of your 
# version of this file only under the terms of the GPL and not to
# allow others to use your version of this file under the MPL,
# indicate your decision by deleting the provisions above and
# replace them with the notice and other provisions required by
# the GPL.  If you do not delete the provisions above, a recipient
# may use your version of this file under either the MPL or the
# GPL.
#

########################################################################
#
# mozilla/security/nss/tests/cert/rcert.sh
#
# Certificate generating and handeling for NSS QA, can be included 
# multiple times from all.sh and the individual scripts
#
# needs to work on all Unix and Windows platforms
#
# included from (don't expect this to be up to date)
# --------------------------------------------------
#   all.sh
#   ssl.sh
#   smime.sh
#   tools.sh
#
# special strings
# ---------------
#   FIXME ... known problems, search for this string
#   NOTE .... unexpected behavior
#
# FIXME - Netscape - NSS
########################################################################

############################## cert_init ###############################
# local shell function to initialize this script
########################################################################
cert_init()
{
  SCRIPTNAME="cert.sh"
  if [ -z "${CLEANUP}" ] ; then     # if nobody else is responsible for
      CLEANUP="${SCRIPTNAME}"       # cleaning this script will do it
  fi
  if [ -z "${INIT_SOURCED}" ] ; then
      cd ../common
      . ./init.sh
  fi
  SCRIPTNAME="stan.sh"
  html_head "Pkiutil Tests"

  ################## Generate noise for our CA cert. ######################
  # NOTE: these keys are only suitable for testing, as this whole thing 
  # bypasses the entropy gathering. Don't use this method to generate 
  # keys and certs for product use or deployment.
  #
  ps -efl > ${NOISE_FILE} 2>&1
  ps aux >> ${NOISE_FILE} 2>&1
  noise

}

################################ noise ##################################
# Generate noise for our certs
#
# NOTE: these keys are only suitable for testing, as this whole thing bypasses
# the entropy gathering. Don't use this method to generate keys and certs for
# product use or deployment.
#########################################################################
noise()
{
    #netstat >> ${NOISE_FILE} 2>&1
    date >> ${NOISE_FILE} 2>&1
}

cert_cleanup()
{
  html "</TABLE><BR>" 
  cd ${QADIR}
  . common/cleanup.sh
}

pkiu()
{
  echo ""
  echo ">>>>>>>>>>>>>> ${PKIU_ACTION} <<<<<<<<<<<<<<"
  echo "pkiutil $*"
  pkiutil $*
  RET=$?
  if [ "$RET" -ne 0 ]; then
    html_failed "<TR><TD>${PKIU_ACTION} ($RET) " 
  else
    html_passed "<TR><TD>${PKIU_ACTION}"
  fi
  return $RET
}

pkiuf()
{
  echo ""
  echo ">>>>>>>>>>>>>> ${PKIU_ACTION} <<<<<<<<<<<<<<"
  echo "pkiutil $*"
  pkiutil $*
  RET=$?
  if [ "$RET" -ne ${FAILURE_CODE} ]; then
    html_failed "<TR><TD>${PKIU_ACTION} ($RET) " 
  else
    html_passed "<TR><TD>${PKIU_ACTION}"
  fi
  return $RET
}

nssu()
{
  echo ""
  echo ">>>>>>>>>>>>>> ${NSSU_ACTION} <<<<<<<<<<<<<<"
  if [ -n "${DEVNAME}" ]; then
    echo "nssutil $* -n \"${DEVNAME}\""
    nssutil $* -n "${DEVNAME}"
  else
    echo "nssutil $*"
    nssutil $*
  fi
  RET=$?
  DEVNAME=""
  if [ "$RET" -ne 0 ]; then
    html_failed "<TR><TD>${NSSU_ACTION} ($RET) " 
  else
    html_passed "<TR><TD>${NSSU_ACTION}"
  fi
  return $RET
}

ciph()
{
  echo ""
  echo ">>>>>>>>>>>>>> ${CIPHER_ACTION} <<<<<<<<<<<<<<"
  echo "cipher $*"
  cipher $*
  RET=$?
  if [ "$RET" -ne 0 ]; then
    html_failed "<TR><TD>${CIPHER_ACTION} ($RET) " 
  else
    html_passed "<TR><TD>${CIPHER_ACTION}"
  fi
  return $RET
}

cert_init
cd ${HOSTDIR}
cp ${QADIR}/stan/*.b64 .
cp ${QADIR}/stan/*.txt .

# XXX
# copying pre-built dbs for now, Stan can't create certs & importing
# via PKCS#8 doesn't seem to work
cp -r ${QADIR}/stan/server/ .
cp -r ${QADIR}/stan/client/ .

CERTDIR="certs"

mkdir -p ${CERTDIR}

PKIU_ACTION="Creating DBs"
pkiu -N -d ${CERTDIR}
if [ "$RET" -ne 0 ]; then
  Exit 6 "Fatal - failed ${PKIU_ACTION} [$RET]"
fi

PKIU_ACTION="Set password"
pkiu --change-password -d ${CERTDIR} -p nss
if [ "$RET" -ne 0 ]; then
  Exit 6 "Fatal - failed ${PKIU_ACTION} [$RET]"
fi

PKIU_ACTION="Import Root"
pkiu -I -d ${CERTDIR} -a -n stanRoot -i stanRoot.b64 
if [ "$RET" -ne 0 ]; then
  Exit 6 "Fatal - failed ${PKIU_ACTION} [$RET]"
fi

PKIU_ACTION="Import Intermediate"
pkiu -I -d ${CERTDIR} -a -n stanCA1 -i stanCA1.b64
if [ "$RET" -ne 0 ]; then
  Exit 6 "Fatal - failed ${PKIU_ACTION} [$RET]"
fi

PKIU_ACTION="Import Leaf Cert"
pkiu -I -d ${CERTDIR} -a -n stanCert -i stanCert.b64
if [ "$RET" -ne 0 ]; then
  Exit 6 "Fatal - failed ${PKIU_ACTION} [$RET]"
fi

PKIU_ACTION="Import Private Key"
pkiu -I -d ${CERTDIR} -a -n stanCert -i stanCert_key.b64 --type private-key -p nss -w asdf
if [ "$RET" -ne 0 ]; then
  Exit 6 "Fatal - failed ${PKIU_ACTION} [$RET]"
fi

PKIU_ACTION="List Certs"
pkiu -L -d ${CERTDIR}

PKIU_ACTION="List Keys"
pkiu -L -d ${CERTDIR} --type private-key -p nss

PKIU_ACTION="Attempt Validation of Server Cert (FAIL)"
FAILURE_CODE=255
pkiuf -V -d ${CERTDIR} -n stanCert -u cv

PKIU_ACTION="Set Root Cert Trust"
pkiu -M -d ${CERTDIR} -n stanRoot -u CV
if [ "$RET" -ne 0 ]; then
  Exit 6 "Fatal - failed ${PKIU_ACTION} [$RET]"
fi

PKIU_ACTION="Validate Leaf Cert"
pkiu -V -d ${CERTDIR} -n stanCert -u cv

PKIU_ACTION="Validate Intermediate CA Cert"
pkiu -V -d ${CERTDIR} -n stanCA1 -u CV

PKIU_ACTION="Export Copy of Leaf Cert"
pkiu -E -d ${CERTDIR} -n stanCert --type cert -a -o stanCertCopy.b64

PKIU_ACTION="Export Copy of Private Key"
pkiu -E -d ${CERTDIR} -n stanCert --type private-key -a -o stanKeyCopy.b64 -w asdf -p nss

PKIU_ACTION="Import Expired Cert"
pkiu -I -d ${CERTDIR} -a -n stanExpired -i stanExpired.b64
if [ "$RET" -ne 0 ]; then
  Exit 6 "Fatal - failed ${PKIU_ACTION} [$RET]"
fi

PKIU_ACTION="Attempt Validation of Expired Cert (FAIL)"
FAILURE_CODE=255
pkiuf -V -d ${CERTDIR} -n stanExpired -u cv

PKIU_ACTION="Delete Expired Cert"
pkiu -D -d ${CERTDIR} -n stanExpired 

PKIU_ACTION="List Certs"
pkiu -L -d ${CERTDIR}

PKIU_ACTION="List Cert Chain"
pkiu --list-chain -d ${CERTDIR} -n stanCert

NSSU_ACTION="List Modules"
nssu --list-modules -d ${CERTDIR}

NSSU_ACTION="Show Internal Module"
DEVNAME="NSS Internal PKCS #11 Module"
nssu --dump-module -d ${CERTDIR} 

NSSU_ACTION="Show Internal DB Slot"
DEVNAME="NSS User Private Key and Certificate Services"
nssu --dump-slot -d ${CERTDIR} 

NSSU_ACTION="Show Internal DB Token"
DEVNAME="NSS Certificate DB"
nssu --dump-token -d ${CERTDIR} 

CIPHER_ACTION="Run Symmetric Key Self-Tests"
ciph -T

cert_cleanup
