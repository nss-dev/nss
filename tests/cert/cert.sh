#! /bin/bash
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

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

#
# set up the arrays of supported keys. These arrays function like
# a single array of a struct the contains the:
#  keyType (all caps)
#  keySuffix (that suffix to add to files and cert names)
#  keyGenCmd (parameters to pass to certutil when generating a key)
#  keyIsMixed (generate mixed RSA/keyType certchains with RSA as the root)
#  keySerialOffset (serial offset used when generating mixed certs so
#                   these certs don't colide with other mixed certs or
#                   straight up RSA certs).
declare -a keyType
declare -a keySuffix
declare -a keyGenCmd
declare -a keyIsMixed
declare -a keySerialOffset
keyType=()
keySuffix=()
keyGenCmd=()
keyIsMixed=()
keySerialOffset=()

# we use this function to set up the array programatically so that
# 1) we can make sure each element matches it's peers in index, and
# 2) the arrays sizes will all be the same, and
# 3) we can add or subtract keys based on build flags (so if we don't
#    support dsa, we can drop the dsa cert test)
cert_add_algorithm()
{
    if [[ $# -ne 5 ]]; then
        html_failed "Test case error, Not enough args in cert_add_algorithm"
        cert_log "ERROR: Test case error, Not enough args in cert_add_algorithm"
        Exit 5 "Fatal - Not enough args in cert_add_algorithm"
    fi
    keyType+=("$1")
    keySuffix+=("$2")
    keyGenCmd+=("$3")
    keyIsMixed+=("$4")
    keySerialOffset+=($5)
}


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
  if [ -z "${IOPR_CERT_SOURCED}" ]; then
       . ../iopr/cert_iopr.sh
  fi
  SCRIPTNAME="cert.sh"
  CRL_GRP_DATE=`date -u "+%Y%m%d%H%M%SZ"`
  html_head "Certutil and Crlutil Tests"

  LIBDIR="${DIST}/${OBJDIR}/lib"

  ROOTCERTSFILE=`ls -1 ${LIBDIR}/*nssckbi.* | head -1`
  if [ ! "${ROOTCERTSFILE}" ] ; then
      html_failed "Looking for root certs module."
      cert_log "ERROR: Root certs module not found."
      Exit 5 "Fatal - Root certs module not found."
  else
      html_passed "Looking for root certs module."
  fi

  cert_add_algorithm "RSA" "" "" "false" 0
  cert_add_algorithm "DSA" "-dsa" "-k dsa" "true" 20000
  # NOTE: curve is added later, so the full command would be '-k ec -q curve'
  cert_add_algorithm "ECC" "-ec" "-k ec -q" "true" 10000
  # currently rsa-pss is only enabled for a subset of tests
  # this will enable a full suite of RSA-PSS certs, and we would
  # then remove the explicit ones
  # ulike the other tests, we would need to change ssl tests as this
  # will rename some of the RSA-PSS certificates.
  #cert_add_algorithm "RSA-PSS" "-rsa-pss" "-k rsa -pss -Z sha256" "true"
  #cert_add_algorithm "RSA-PSS-SHA1" "-rsa-pss-sha1" "-k rsa -pss -Z sha1" "true"

  if [ "${OS_ARCH}" = "WINNT" -a "$OS_NAME" = "CYGWIN_NT" ]; then
	ROOTCERTSFILE=`cygpath -m ${ROOTCERTSFILE}`
  fi
}

cert_log() ######################    write the cert_status file
{
    echo "$SCRIPTNAME $*"
    echo $* >>${CERT_LOG_FILE}
}

########################################################################
# function wraps calls to pk12util, also: writes action and options
# to stdout.
# Params are the same as to pk12util.
# Returns pk12util status
#
pk12u()
{
    echo "${CU_ACTION} --------------------------"

    echo "pk12util $@"
    ${BINDIR}/pk12util $@
    RET=$?

    return $RET
}

################################ certu #################################
# local shell function to call certutil, also: writes action and options to
# stdout, sets variable RET and writes results to the html file results
########################################################################
certu()
{
    echo "$SCRIPTNAME: ${CU_ACTION} --------------------------"
    EXPECTED=${RETEXPECTED-0}

    if [ -n "${CU_SUBJECT}" ]; then
        #the subject of the cert contains blanks, and the shell
        #will strip the quotes off the string, if called otherwise...
        echo "certutil -s \"${CU_SUBJECT}\" $*"
        ${PROFTOOL} ${BINDIR}/certutil -s "${CU_SUBJECT}" $*
        RET=$?
        CU_SUBJECT=""
    else
        echo "certutil $*"
        ${PROFTOOL} ${BINDIR}/certutil $*
        RET=$?
    fi
    if [ "$RET" -ne "$EXPECTED" ]; then
        CERTFAILED=$RET
        html_failed "${CU_ACTION} ($RET=$EXPECTED) "
        cert_log "ERROR: ${CU_ACTION} failed $RET"
    else
        html_passed "${CU_ACTION}"
    fi

    return $RET
}

################################ crlu #################################
# local shell function to call crlutil, also: writes action and options to
# stdout, sets variable RET and writes results to the html file results
########################################################################
crlu()
{
    echo "$SCRIPTNAME: ${CU_ACTION} --------------------------"

    CRLUTIL="crlutil -q"
    echo "$CRLUTIL $*"
    ${PROFTOOL} ${BINDIR}/$CRLUTIL $*
    RET=$?
    if [ "$RET" -ne 0 ]; then
        CRLFAILED=$RET
        html_failed "${CU_ACTION} ($RET) "
        cert_log "ERROR: ${CU_ACTION} failed $RET"
    else
        html_passed "${CU_ACTION}"
    fi

    return $RET
}

################################ ocspr ##################################
# local shell function to call ocsresp, also: writes action and options to
# stdout, sets variable RET and writes results to the html file results
#########################################################################
ocspr()
{
    echo "$SCRIPTNAME: ${OR_ACTION} --------------------------"

    OCSPRESP="ocspresp"
    echo "$OCSPRESP $*"
    ${PROFTOOL} ${BINDIR}/$OCSPRESP $*
    RET=$?
    if [ "$RET" -ne 0 ]; then
        OCSPFAILED=$RET
        html_failed "${OR_ACTION} ($RET) "
        cert_log "ERROR: ${OR_ACTION} failed $RET"
    else
        html_passed "${OR_ACTION}"
    fi

    return $RET
}

modu()
{
    echo "$SCRIPTNAME: ${CU_ACTION} --------------------------"

    MODUTIL="modutil"
    echo "$MODUTIL $*"
    # echo is used to press Enter expected by modutil
    echo | ${BINDIR}/$MODUTIL $*
    RET=$?
    if [ "$RET" -ne 0 ]; then
        MODFAILED=$RET
        html_failed "${CU_ACTION} ($RET) "
        cert_log "ERROR: ${CU_ACTION} failed $RET"
    else
        html_passed "${CU_ACTION}"
    fi

    return $RET
}

############################# cert_init_cert ##########################
# local shell function to initialize creation of client and server certs
########################################################################
cert_init_cert()
{
    CERTDIR="$1"
    CERTNAME="$2"
    CERTSERIAL="$3"
    DOMAIN="$4"

    if [ ! -d "${CERTDIR}" ]; then
        mkdir -p "${CERTDIR}"
    else
        echo "$SCRIPTNAME: WARNING - ${CERTDIR} exists"
    fi
    cd "${CERTDIR}"
    CERTDIR="."

    PROFILEDIR=`cd ${CERTDIR}; pwd`
    if [ "${OS_ARCH}" = "WINNT" -a "$OS_NAME" = "CYGWIN_NT" ]; then
        PROFILEDIR=`cygpath -m ${PROFILEDIR}`
    fi
    if [ -n "${MULTIACCESS_DBM}" ]; then
	PROFILEDIR="multiaccess:${DOMAIN}"
    fi

    noise
}

############################# hw_acc #################################
# local shell function to add hw accelerator modules to the db
########################################################################
hw_acc()
{
    HW_ACC_RET=0
    HW_ACC_ERR=""
    if [ -n "$O_HWACC" -a "$O_HWACC" = ON -a -z "$USE_64" ] ; then
        echo "creating $CERTNAME s cert with hwaccelerator..."
        #case $ACCELERATOR in
        #rainbow)

        echo "modutil -add rainbow -libfile /usr/lib/libcryptoki22.so "
        echo "         -dbdir ${PROFILEDIR} 2>&1 "
        echo | ${BINDIR}/modutil -add rainbow -libfile /usr/lib/libcryptoki22.so \
            -dbdir ${PROFILEDIR} 2>&1
        if [ "$?" -ne 0 ]; then
            echo "modutil -add rainbow failed in `pwd`"
            HW_ACC_RET=1
            HW_ACC_ERR="modutil -add rainbow"
        fi

        echo "modutil -add ncipher "
        echo "         -libfile /opt/nfast/toolkits/pkcs11/libcknfast.so "
        echo "         -dbdir ${PROFILEDIR} 2>&1 "
        echo | ${BINDIR}/modutil -add ncipher \
            -libfile /opt/nfast/toolkits/pkcs11/libcknfast.so \
            -dbdir ${PROFILEDIR} 2>&1
        if [ "$?" -ne 0 ]; then
            echo "modutil -add ncipher failed in `pwd`"
            HW_ACC_RET=`expr $HW_ACC_RET + 2`
            HW_ACC_ERR="$HW_ACC_ERR,modutil -add ncipher"
        fi
        if [ "$HW_ACC_RET" -ne 0 ]; then
            html_failed "Adding HW accelerators to certDB for ${CERTNAME} ($HW_ACC_RET) "
        else
            html_passed "Adding HW accelerators to certDB for ${CERTNAME}"
        fi

    fi
    return $HW_ACC_RET
}

############################# cert_create_cert #########################
# local shell function to create client certs
#     initialize DB, import
#     root cert
#     add cert to DB
########################################################################
cert_create_cert()
{
    cert_init_cert "$1" "$2" "$3" "$4"

    CU_ACTION="Initializing ${CERTNAME}'s Cert DB"
    certu -N -d "${PROFILEDIR}" -f "${R_PWFILE}" 2>&1
    if [ "$RET" -ne 0 ]; then
        return $RET
    fi

    CU_ACTION="Loading root cert module to ${CERTNAME}'s Cert DB"
    modu -add "RootCerts" -libfile "${ROOTCERTSFILE}" -dbdir "${PROFILEDIR}" 2>&1
    if [ "$RET" -ne 0 ]; then
        return $RET
    fi

    hw_acc

    for i in ${!keyType[@]}
    do
        suffix=${keySuffix[$i]}
        CU_ACTION="Import ${keyType[$i]} Root CA for ${CERTNAME}"
        certu -A -n "TestCA${suffix}" -t "TC,TC,TC" -f "${R_PWFILE}" \
              -d "${PROFILEDIR}" -i "${R_CADIR}/TestCA${suffix}.ca.cert" 2>&1
        if [ "$RET" -ne 0 ]; then
            return $RET
        fi
    done
    cert_add_cert "$5"
    return $?
}

############################# cert_add_cert ############################
# local shell function to add client certs to an existing CERT DB
#     generate request
#     sign request
#     import Cert
#
########################################################################
cert_add_cert()
{
    EC_CURVE=secp384r1
    for i in ${!keyType[@]}
    do
        suffix=${keySuffix[$i]}
        gencmd=${keyGenCmd[$i]}
        key_type=${keyType[$i]}
        if [ "$key_type" =  "ECC" ]; then
            gencmd="$gencmd ${EC_CURVE}"
        fi
        CU_ACTION="Generate $key_type Cert Request for $CERTNAME"
        CU_SUBJECT="CN=$CERTNAME, E=${CERTNAME}${suffix}@example.com, O=BOGUS NSS, L=Mountain View, ST=California, C=US"
        certu -R ${gencmd} -d "${PROFILEDIR}" -f "${R_PWFILE}" -z "${R_NOISE_FILE}" -o req  2>&1
        if [ "$RET" -ne 0 ]; then
            return $RET
        fi

        CU_ACTION="Sign ${CERTNAME}'s $key_type Request"
        certu -C -c "TestCA${suffix}" -m "$CERTSERIAL" -v 60 -d "${P_R_CADIR}" \
          -i req -o "${CERTNAME}${suffix}.cert" -f "${R_PWFILE}" "$1" 2>&1
        if [ "$RET" -ne 0 ]; then
            return $RET
        fi

        CU_ACTION="Import $CERTNAME's $key_type Cert"
        certu -A -n "${CERTNAME}${suffix}" -t "u,u,u" -d "${PROFILEDIR}" \
            -f "${R_PWFILE}" -i "${CERTNAME}${suffix}.cert" 2>&1
        if [ "$RET" -ne 0 ]; then
            return $RET
        fi

        cert_log "SUCCESS: $CERTNAME's $key_type Cert Created"

        #  Generate mixed certificate signed with RSA
        if [ "${keyIsMixed[$i]}" = "true" ]; then
	    CU_ACTION="Generate mixed $key_type Cert Request for $CERTNAME"
	    CU_SUBJECT="CN=$CERTNAME, E=${CERTNAME}${suffix}mixed@example.com, O=BOGUS NSS, L=Mountain View, ST=California, C=US"
	    certu -R ${gencmd} -d "${PROFILEDIR}" -f "${R_PWFILE}" \
	        -z "${R_NOISE_FILE}" -o req  2>&1
	    if [ "$RET" -ne 0 ]; then
                return $RET
	    fi

	    CU_ACTION="Sign ${CERTNAME}'s $key_type Request with RSA"
# Avoid conflicting serial numbers with TestCA issuer by keeping
# this set far away. A smaller number risks colliding with the
# extended ssl user certificates.
	    NEWSERIAL=`expr ${CERTSERIAL} + ${keySerialOffset[$i]}`
            certu -C -c "TestCA" -m "$NEWSERIAL" -v 60 -d "${P_R_CADIR}" \
                -i req -o "${CERTNAME}${suffix}mixed.cert" -f "${R_PWFILE}" "$1" 2>&1
	    if [ "$RET" -ne 0 ]; then
                return $RET
	    fi

	    CU_ACTION="Import $CERTNAME's mixed $key_type Cert"
	    certu -A -n "${CERTNAME}${suffix}mixed" -t "u,u,u" -d "${PROFILEDIR}" \
	        -f "${R_PWFILE}" -i "${CERTNAME}${suffix}mixed.cert" 2>&1
	    if [ "$RET" -ne 0 ]; then
                return $RET
	    fi
	    cert_log "SUCCESS: $CERTNAME's mixed $key_type Cert Created"
        fi
    done

    # RSA PSS is only 'mixed' and is isn't generated by using from the certuil
    # command line
    echo "Importing RSA-PSS server certificate"
    pk12u -i ${QADIR}/cert/TestUser-rsa-pss-interop.p12 -k ${R_PWFILE} -w ${R_PWFILE} -d ${PROFILEDIR}
    # Let's get the key ID of the imported private key.
    KEYID=`${BINDIR}/certutil -d ${PROFILEDIR} -K -f ${R_PWFILE} | \
          grep 'TestUser-rsa-pss-interop$' | sed -n 's/^<.*> [^ ]\{1,\} *\([^ ]\{1,\}\).*/\1/p'`

    CU_ACTION="Generate RSA-PSS Cert Request for $CERTNAME"
    CU_SUBJECT="CN=$CERTNAME, E=${CERTNAME}-rsa-pss@example.com, O=BOGUS NSS, L=Mountain View, ST=California, C=US"
    certu -R -d "${PROFILEDIR}" -k ${KEYID} -f "${R_PWFILE}" \
          -z "${R_NOISE_FILE}" -o req 2>&1

    CU_ACTION="Sign ${CERTNAME}'s RSA-PSS Request"
    NEWSERIAL=`expr ${CERTSERIAL} + 30000`
    certu -C -c "TestCA" -m "$NEWSERIAL" -v 60 -d "${P_R_CADIR}" \
        -i req -o "${CERTNAME}-rsa-pss.cert" -f "${R_PWFILE}" "$1" 2>&1

    CU_ACTION="Import $CERTNAME's RSA-PSS Cert -t u,u,u"
    certu -A -n "$CERTNAME-rsa-pss" -t "u,u,u" -d "${PROFILEDIR}" \
        -f "${R_PWFILE}" -i "${CERTNAME}-rsa-pss.cert" 2>&1
    cert_log "SUCCESS: $CERTNAME's RSA-PSS Cert Created"

    return 0
}

################################# cert_all_CA ################################
# local shell function to build the additional Temp. Certificate Authority (CA)
# used for the "real life" ssl test with 2 different CA's in the
# client and in the server's dir
##########################################################################
cert_all_CA()
{
    CA_CURVE="secp521r1"
    for i in ${!keyType[@]}
    do
        suffix=${keySuffix[$i]}
        key_type=${keyType[$i]}
        cn_type=""
        if [ "key_type" != "RSA" ]; then
            cn_type=" (${key_type})"
        fi
        ALL_CU_SUBJECT="CN=NSS Test CA${cn_type}, O=BOGUS NSS, L=Mountain View, ST=California, C=US"
        cert_CA $key_type $CADIR TestCA${suffix} -x "CTu,CTu,CTu" ${D_CA} "1" ${CA_CURVE}

        ALL_CU_SUBJECT="CN=NSS Server Test CA${cn_type}, O=BOGUS NSS, L=Santa Clara, ST=California, C=US"
        cert_CA $key_type $SERVER_CADIR serverCA${suffix} -x "Cu,Cu,Cu" ${D_SERVER_CA} "2" ${CA_CURVE}
        ALL_CU_SUBJECT="CN=NSS Chain1 Server Test CA${cn_type}, O=BOGUS NSS, L=Santa Clara, ST=California, C=US"
        cert_CA $key_type $SERVER_CADIR chain-1-serverCA${suffix} "-c serverCA${suffix}" "u,u,u" ${D_SERVER_CA} "3" ${CA_CURVE}
        ALL_CU_SUBJECT="CN=NSS Chain2 Server Test CA${cn_type}, O=BOGUS NSS, L=Santa Clara, ST=California, C=US"
        cert_CA $key_type $SERVER_CADIR chain-2-serverCA${suffix} "-c chain-1-serverCA${suffix}" "u,u,u" ${D_SERVER_CA} "4" ${CA_CURVE}

        ALL_CU_SUBJECT="CN=NSS Client Test CA${cn_type}, O=BOGUS NSS, L=Santa Clara, ST=California, C=US"
        cert_CA $key_type $CLIENT_CADIR clientCA${suffix} -x "Tu,Cu,Cu" ${D_CLIENT_CA} "5" ${CA_CURVE}
        ALL_CU_SUBJECT="CN=NSS Chain1 Client Test CA${cn_type}, O=BOGUS NSS, L=Santa Clara, ST=California, C=US"
        cert_CA $key_type $CLIENT_CADIR chain-1-clientCA${suffix} "-c clientCA${suffix}" "u,u,u" ${D_CLIENT_CA} "6" ${CA_CURVE}
        ALL_CU_SUBJECT="CN=NSS Chain2 Client Test CA${cn_type}, O=BOGUS NSS, L=Santa Clara, ST=California, C=US"
        cert_CA $key_type $CLIENT_CADIR chain-2-clientCA${suffix} "-c chain-1-clientCA${suffix}" "u,u,u" ${D_CLIENT_CA} "7" ${CA_CURVE}

        # root.cert in $CLIENT_CADIR and in $SERVER_CADIR is one of the last
        # in the chain
        rm $CLIENT_CADIR/root${suffix}.cert $SERVER_CADIR/root${suffix}.cert
    done
    #
    #  Create RSA-PSS version of TestCA
    ALL_CU_SUBJECT="CN=NSS Test CA (RSA-PSS), O=BOGUS NSS, L=Mountain View, ST=California, C=US"
    cert_CA RSA-PSS $CADIR TestCA-rsa-pss -x "CTu,CTu,CTu" ${D_CA} "1" SHA256
    rm $CADIR/root-rsa-pss.cert

    ALL_CU_SUBJECT="CN=NSS Test CA (RSA-PSS-SHA1), O=BOGUS NSS, L=Mountain View, ST=California, C=US"
    cert_CA RSA-PSS $CADIR TestCA-rsa-pss-sha1 -x "CTu,CTu,CTu" ${D_CA} "1" SHA1
    rm $CADIR/root-rsa-pss.cert
}

################################# cert_CA ################################
# local shell function to build the Temp. Certificate Authority (CA)
# used for testing purposes, creating  a CA Certificate and a root cert
# this function calls the key type specific keygen code
##########################################################################
cert_CA()
{
  KEY_TYPE=$1
  CUR_CADIR=$2
  NICKNAME=$3
  SIGNER=$4
  TRUSTARG=$5
  DOMAIN=$6
  CERTSERIAL=$7
  ALG=$8

#echo "cert_CA: KEY_TYPE=\"$KEY_TYPE\" CUR_CADIR=\"$CUR_CADIR\""
#  echo "         NICKNAME=\"$NICKNAME\" SIGNER=\"$SIGNER\" TRUSTARG=\"$TRUSTARG\""
#  echo "         DOMAIN=\"$DOMAIN\" CERTSERIAL=\"$CERTSERIAL\" ALG=\"$ALG\""

  case "$KEY_TYPE" in
  RSA)
      cert_rsa_CA "${CUR_CADIR}" "${NICKNAME}" "${SIGNER}" "${TRUSTARG}" "${DOMAIN}" "${CERTSERIAL}"
      ;;
  DSA)
      cert_dsa_CA "${CUR_CADIR}" "${NICKNAME}" "${SIGNER}" "${TRUSTARG}" "${DOMAIN}" "${CERTSERIAL}"
      ;;
  ECC)
      cert_ec_CA "${CUR_CADIR}" "${NICKNAME}" "${SIGNER}" "${TRUSTARG}" "${DOMAIN}" "${CERTSERIAL}" "${ALG}"
      ;;
  RSA-PSS)
      cert_rsa_pss_CA "${CUR_CADIR}" "${NICKNAME}" "${SIGNER}" "${TRUSTARG}" "${DOMAIN}" "${CERTSERIAL}" "${ALG}"
      ;;
  *)
      Exit 9 "Fatal - unknown key type ${KEY_TYPE}, failed to create CA cert"
      ;;
  esac
}



################################# cert_rsa_CA ############################
# local shell function to build the Temp. Certificate Authority (CA)
# used for testing purposes, creating  a CA Certificate and a root cert
##########################################################################
cert_rsa_CA()
{
  CUR_CADIR=$1
  NICKNAME=$2
  SIGNER=$3
  TRUSTARG=$4
  DOMAIN=$5
  CERTSERIAL=$6

  echo "$SCRIPTNAME: Creating a CA Certificate $NICKNAME =========================="

  if [ ! -d "${CUR_CADIR}" ]; then
      mkdir -p "${CUR_CADIR}"
  fi
  cd ${CUR_CADIR}
  pwd

  LPROFILE=`pwd`
  if [ "${OS_ARCH}" = "WINNT" -a "$OS_NAME" = "CYGWIN_NT" ]; then
     LPROFILE=`cygpath -m ${LPROFILE}`
  fi
  if [ -n "${MULTIACCESS_DBM}" ]; then
	LPROFILE="multiaccess:${DOMAIN}"
  fi

  if [ "$SIGNER" = "-x" ] ; then # self signed -> create DB
      CU_ACTION="Creating CA Cert DB"
      certu -N -d "${LPROFILE}" -f ${R_PWFILE} 2>&1
      if [ "$RET" -ne 0 ]; then
          Exit 5 "Fatal - failed to create CA $NICKNAME "
      fi

      CU_ACTION="Loading root cert module to CA Cert DB"
      modu -add "RootCerts" -libfile "${ROOTCERTSFILE}" -dbdir "${LPROFILE}" 2>&1
      if [ "$RET" -ne 0 ]; then
          return $RET
      fi

      echo "$SCRIPTNAME: Certificate initialized ----------"
  fi


  ################# Creating CA Cert ######################################
  #
  CU_ACTION="Creating CA Cert $NICKNAME "
  CU_SUBJECT=$ALL_CU_SUBJECT
  certu -S -n $NICKNAME -t $TRUSTARG -v 600 $SIGNER -d ${LPROFILE} -1 -2 -5 \
        -f ${R_PWFILE} -z ${R_NOISE_FILE} -m $CERTSERIAL 2>&1 <<CERTSCRIPT
5
6
9
n
y
-1
n
5
6
7
9
n
CERTSCRIPT

  if [ "$RET" -ne 0 ]; then
      echo "return value is $RET"
      Exit 6 "Fatal - failed to create CA cert"
  fi

  ################# Exporting Root Cert ###################################
  #
  CU_ACTION="Exporting Root Cert"
  certu -L -n  $NICKNAME -r -d ${LPROFILE} -o root.cert
  if [ "$RET" -ne 0 ]; then
      Exit 7 "Fatal - failed to export root cert"
  fi
  cp root.cert ${NICKNAME}.ca.cert
}





################################ cert_dsa_CA #############################
# local shell function to build the Temp. Certificate Authority (CA)
# used for testing purposes, creating  a CA Certificate and a root cert
# This is the DSA version of cert_CA.
##########################################################################
cert_dsa_CA()
{
  CUR_CADIR=$1
  NICKNAME=$2
  SIGNER=$3
  TRUSTARG=$4
  DOMAIN=$5
  CERTSERIAL=$6

  echo "$SCRIPTNAME: Creating a DSA CA Certificate $NICKNAME =========================="

  if [ ! -d "${CUR_CADIR}" ]; then
      mkdir -p "${CUR_CADIR}"
  fi
  cd ${CUR_CADIR}
  pwd

  LPROFILE=.
  if [ -n "${MULTIACCESS_DBM}" ]; then
	LPROFILE="multiaccess:${DOMAIN}"
  fi

  ################# Creating a DSA CA Cert ###############################
  #
  CU_ACTION="Creating DSA CA Cert $NICKNAME "
  CU_SUBJECT=$ALL_CU_SUBJECT
  certu -S -n $NICKNAME -k dsa -t $TRUSTARG -v 600 $SIGNER \
    -d ${LPROFILE} -1 -2 -5 -f ${R_PWFILE} -z ${R_NOISE_FILE} \
    -m $CERTSERIAL 2>&1 <<CERTSCRIPT
5
6
9
n
y
-1
n
5
6
7
9
n
CERTSCRIPT

  if [ "$RET" -ne 0 ]; then
      echo "return value is $RET"
      Exit 6 "Fatal - failed to create DSA CA cert"
  fi

  ################# Exporting DSA Root Cert ###############################
  #
  CU_ACTION="Exporting DSA Root Cert"
  certu -L -n  $NICKNAME -r -d ${LPROFILE} -o root-dsa.cert
  if [ "$RET" -ne 0 ]; then
      Exit 7 "Fatal - failed to export dsa root cert"
  fi
  cp root-dsa.cert ${NICKNAME}.ca.cert
}





################################ cert_rsa_pss_CA #############################
# local shell function to build the Temp. Certificate Authority (CA)
# used for testing purposes, creating  a CA Certificate and a root cert
# This is the RSA-PSS version of cert_CA.
##########################################################################
cert_rsa_pss_CA()
{
  CUR_CADIR=$1
  NICKNAME=$2
  SIGNER=$3
  TRUSTARG=$4
  DOMAIN=$5
  CERTSERIAL=$6
  HASHALG=$7

  echo "$SCRIPTNAME: Creating an RSA-PSS CA Certificate $NICKNAME =========================="

  if [ ! -d "${CUR_CADIR}" ]; then
      mkdir -p "${CUR_CADIR}"
  fi
  cd ${CUR_CADIR}
  pwd

  LPROFILE=.
  if [ -n "${MULTIACCESS_DBM}" ]; then
	LPROFILE="multiaccess:${DOMAIN}"
  fi

  HASHOPT=
  if [ -n "$HASHALG" ]; then
        HASHOPT="-Z $HASHALG"
  fi

  ################# Creating an RSA-PSS CA Cert ###############################
  #
  CU_ACTION="Creating RSA-PSS CA Cert $NICKNAME "
  CU_SUBJECT=$ALL_CU_SUBJECT
  certu -S -n $NICKNAME -k rsa --pss $HASHOPT -t $TRUSTARG -v 600 $SIGNER \
    -d ${LPROFILE} -1 -2 -5 -f ${R_PWFILE} -z ${R_NOISE_FILE} \
    -m $CERTSERIAL 2>&1 <<CERTSCRIPT
5
6
9
n
y
-1
n
5
6
7
9
n
CERTSCRIPT

  if [ "$RET" -ne 0 ]; then
      echo "return value is $RET"
      Exit 6 "Fatal - failed to create RSA-PSS CA cert"
  fi

  ################# Exporting RSA-PSS Root Cert ###############################
  #
  CU_ACTION="Exporting RSA-PSS Root Cert"
  certu -L -n  $NICKNAME -r -d ${LPROFILE} -o root-rsa-pss.cert
  if [ "$RET" -ne 0 ]; then
      Exit 7 "Fatal - failed to export RSA-PSS root cert"
  fi
  cp root-rsa-pss.cert ${NICKNAME}.ca.cert
}




################################ cert_ec_CA ##############################
# local shell function to build the Temp. Certificate Authority (CA)
# used for testing purposes, creating  a CA Certificate and a root cert
# This is the ECC version of cert_CA.
##########################################################################
cert_ec_CA()
{
  CUR_CADIR=$1
  NICKNAME=$2
  SIGNER=$3
  TRUSTARG=$4
  DOMAIN=$5
  CERTSERIAL=$6
  CURVE=$7

  echo "$SCRIPTNAME: Creating an EC CA Certificate $NICKNAME =========================="

  if [ ! -d "${CUR_CADIR}" ]; then
      mkdir -p "${CUR_CADIR}"
  fi
  cd ${CUR_CADIR}
  pwd

  LPROFILE=.
  if [ -n "${MULTIACCESS_DBM}" ]; then
	LPROFILE="multiaccess:${DOMAIN}"
  fi

  ################# Creating an EC CA Cert ################################
  #
  CU_ACTION="Creating EC CA Cert $NICKNAME "
  CU_SUBJECT=$ALL_CU_SUBJECT
  certu -S -n $NICKNAME -k ec -q $CURVE -t $TRUSTARG -v 600 $SIGNER \
    -d ${LPROFILE} -1 -2 -5 -f ${R_PWFILE} -z ${R_NOISE_FILE} \
    -m $CERTSERIAL 2>&1 <<CERTSCRIPT
5
6
9
n
y
-1
n
5
6
7
9
n
CERTSCRIPT

  if [ "$RET" -ne 0 ]; then
      echo "return value is $RET"
      Exit 6 "Fatal - failed to create EC CA cert"
  fi

  ################# Exporting EC Root Cert ################################
  #
  CU_ACTION="Exporting EC Root Cert"
  certu -L -n  $NICKNAME -r -d ${LPROFILE} -o root-ec.cert
  if [ "$RET" -ne 0 ]; then
      Exit 7 "Fatal - failed to export ec root cert"
  fi
  cp root-ec.cert ${NICKNAME}.ca.cert
}

############################## cert_smime_client #############################
# local shell function to create client Certificates for S/MIME tests
##############################################################################
cert_smime_client()
{
  CERTFAILED=0
  echo "$SCRIPTNAME: Creating Client CA Issued Certificates =============="

  cert_create_cert ${ALICEDIR} "Alice" 30 ${D_ALICE}
  cert_create_cert ${BOBDIR} "Bob" 40  ${D_BOB}

  echo "$SCRIPTNAME: Creating Dave's Certificate -------------------------"
  cert_create_cert "${DAVEDIR}" Dave 50 ${D_DAVE}

## XXX With this new script merging ECC and non-ECC tests, the
## call to cert_create_cert ends up creating two separate certs
## one for Eve and another for Eve-ec but they both end up with
## the same Subject Alt Name Extension, i.e., both the cert for
## Eve@example.com and the cert for Eve-ec@example.com end up
## listing eve@example.net in the Certificate Subject Alt Name extension.
## This can cause a problem later when cmsutil attempts to create
## enveloped data and accidently picks up the ECC cert (NSS currently
## does not support ECC for enveloped data creation). This script
## avoids the problem by ensuring that these conflicting certs are
## never added to the same cert database (see comment marked XXXX).
  echo "$SCRIPTNAME: Creating multiEmail's Certificate --------------------"
  cert_create_cert "${EVEDIR}" "Eve" 60 ${D_EVE} "-7 eve@example.net,eve@example.org,beve@example.com"

  #echo "************* Copying CA files to ${SERVERDIR}"
  #cp ${CADIR}/*.db .
  #hw_acc

  #########################################################################
  #
  #cd ${CERTDIR}
  #CU_ACTION="Creating ${CERTNAME}'s Server Cert"
  #CU_SUBJECT="CN=${CERTNAME}, E=${CERTNAME}@example.com, O=BOGUS Netscape, L=Mountain View, ST=California, C=US"
  #certu -S -n "${CERTNAME}" -c "TestCA" -t "u,u,u" -m "$CERTSERIAL" \
  #	-d ${PROFILEDIR} -f "${R_PWFILE}" -z "${R_NOISE_FILE}" -v 60 2>&1

  #CU_ACTION="Export Dave's Cert"
  #cd ${DAVEDIR}
  #certu -L -n "Dave" -r -d ${P_R_DAVE} -o Dave.cert

  ################# Importing Certificates for S/MIME tests ###############
  #
  echo "$SCRIPTNAME: Importing Certificates =============================="
  CU_ACTION="Import Bob's cert into Alice's db"
  certu -E -t ",," -d ${P_R_ALICEDIR} -f ${R_PWFILE} \
        -i ${R_BOBDIR}/Bob.cert 2>&1

  CU_ACTION="Import Dave's cert into Alice's DB"
  certu -E -t ",," -d ${P_R_ALICEDIR} -f ${R_PWFILE} \
        -i ${R_DAVEDIR}/Dave.cert 2>&1

  CU_ACTION="Import Dave's cert into Bob's DB"
  certu -E -t ",," -d ${P_R_BOBDIR} -f ${R_PWFILE} \
        -i ${R_DAVEDIR}/Dave.cert 2>&1

  CU_ACTION="Import Eve's cert into Alice's DB"
  certu -E -t ",," -d ${P_R_ALICEDIR} -f ${R_PWFILE} \
        -i ${R_EVEDIR}/Eve.cert 2>&1

  CU_ACTION="Import Eve's cert into Bob's DB"
  certu -E -t ",," -d ${P_R_BOBDIR} -f ${R_PWFILE} \
        -i ${R_EVEDIR}/Eve.cert 2>&1

      echo "$SCRIPTNAME: Importing EC Certificates =============================="
      CU_ACTION="Import Bob's EC cert into Alice's db"
      certu -E -t ",," -d ${P_R_ALICEDIR} -f ${R_PWFILE} \
          -i ${R_BOBDIR}/Bob-ec.cert 2>&1

      CU_ACTION="Import Dave's EC cert into Alice's DB"
      certu -E -t ",," -d ${P_R_ALICEDIR} -f ${R_PWFILE} \
          -i ${R_DAVEDIR}/Dave-ec.cert 2>&1

      CU_ACTION="Import Dave's EC cert into Bob's DB"
      certu -E -t ",," -d ${P_R_BOBDIR} -f ${R_PWFILE} \
          -i ${R_DAVEDIR}/Dave-ec.cert 2>&1

## XXXX Do not import Eve's EC cert until we can make sure that
## the email addresses listed in the Subject Alt Name Extension
## inside Eve's ECC and non-ECC certs are different.
#     CU_ACTION="Import Eve's EC cert into Alice's DB"
#     certu -E -t ",," -d ${P_R_ALICEDIR} -f ${R_PWFILE} \
#         -i ${R_EVEDIR}/Eve-ec.cert 2>&1

#     CU_ACTION="Import Eve's EC cert into Bob's DB"
#     certu -E -t ",," -d ${P_R_BOBDIR} -f ${R_PWFILE} \
#         -i ${R_EVEDIR}/Eve-ec.cert 2>&1

  if [ "$CERTFAILED" != 0 ] ; then
      cert_log "ERROR: SMIME failed $RET"
  else
      cert_log "SUCCESS: SMIME passed"
  fi
}

############################## cert_extended_ssl #######################
# local shell function to create client + server certs for extended SSL test
########################################################################
cert_extended_ssl()
{

  ################# Creating Certs for extended SSL test ####################
  #
  CERTFAILED=0
  echo "$SCRIPTNAME: Creating Certificates, issued by the last ==============="
  echo "     of a chain of CA's which are not in the same database============"

  echo "Server Cert"
  cert_init_cert ${EXT_SERVERDIR} "${HOSTADDR}" 1 ${D_EXT_SERVER}

  CU_ACTION="Initializing ${CERTNAME}'s Cert DB (ext.)"
  certu -N -d "${PROFILEDIR}" -f "${R_PWFILE}" 2>&1

  CU_ACTION="Loading root cert module to ${CERTNAME}'s Cert DB (ext.)"
  modu -add "RootCerts" -libfile "${ROOTCERTSFILE}" -dbdir "${PROFILEDIR}" 2>&1

  EC_CURVE="secp256r1"
  for i in ${!keyType[@]}
  do
    suffix=${keySuffix[$i]}
    gencmd=${keyGenCmd[$i]}
    key_type=${keyType[$i]}
    if [ "$key_type" =  "ECC" ]; then
        gencmd="$gencmd ${EC_CURVE}"
    fi

    CU_ACTION="Generate $key_type Cert Request for $CERTNAME (ext)"
    CU_SUBJECT="CN=${CERTNAME}, E=${CERTNAME}${suffix}@example.com, O=BOGUS NSS, L=Mountain View, ST=California, C=US"
    certu -R -d "${PROFILEDIR}" $gencmd -f "${R_PWFILE}" \
        -z "${R_NOISE_FILE}" -o req 2>&1

    CU_ACTION="Sign ${CERTNAME}'s $key_type Request (ext)"
    cp ${CERTDIR}/req ${SERVER_CADIR}
    certu -C -c "chain-2-serverCA${suffix}" -m 200 -v 60 \
        -d "${P_SERVER_CADIR}" -i req -o "${CERTNAME}${suffix}.cert" \
        -f "${R_PWFILE}" 2>&1

    CU_ACTION="Import $CERTNAME's $key_type Cert  -t u,u,u (ext)"
    certu -A -n "${CERTNAME}${suffix}" -t "u,u,u" -d "${PROFILEDIR}" \
        -f "${R_PWFILE}" -i "${CERTNAME}${suffix}.cert" 2>&1

    CU_ACTION="Import Client $key_type Root CA -t T,, for $CERTNAME (ext.)"
    certu -A -n "clientCA${suffix}" -t "T,," -f "${R_PWFILE}" \
           -d "${PROFILEDIR}" -i "${CLIENT_CADIR}/clientCA${suffix}.ca.cert" 2>&1
    #  Generate mixed certificate signed with RSA
    if [ "${keyIsMixed[$i]}" = "true" ]; then
      NEWSERIAL=`expr ${keySerialOffset[$i]} + 200`
      CU_ACTION="Generate mixed $key_type Cert Request for $CERTNAME (ext)"
      CU_SUBJECT="CN=$CERTNAME, E=${CERTNAME}${suffix}mixed@example.com, O=BOGUS NSS, L=Mountain View, ST=California, C=US"
      certu -R -d "${PROFILEDIR}" ${gencmd} -f "${R_PWFILE}" \
	  -z "${R_NOISE_FILE}" -o req 2>&1

      CU_ACTION="Sign ${CERTNAME}'s mixed $key_type Request (ext)"
      cp ${CERTDIR}/req ${SERVER_CADIR}
      certu -C -c "chain-2-serverCA" -m ${NEWSERIAL} -v 60 \
          -d "${P_SERVER_CADIR}" -i req -o "${CERTNAME}${suffix}mixed.cert" \
          -f "${R_PWFILE}" 2>&1

      CU_ACTION="Import $CERTNAME's mixed ${key_type} Cert  -t u,u,u (ext)"
      certu -A -n "${CERTNAME}${suffix}mixed" -t "u,u,u" -d "${PROFILEDIR}" \
	  -f "${R_PWFILE}" -i "${CERTNAME}${suffix}mixed.cert" 2>&1

#    CU_ACTION="Import Client mixed $key_type Root CA -t T,, for $CERTNAME (ext.)"
#    certu -A -n "clientCA${suffix}mixed" -t "T,," -f "${R_PWFILE}" \
#	  -d "${PROFILEDIR}" -i "${CLIENT_CADIR}/clientCA${suffix}mixed.ca.cert" \
#	  2>&1
    fi
  done

  # Check that a repeated import with a different nickname doesn't change the
  # nickname of the existing cert (bug 1458518).
  # We want to search for the results using grep, to avoid subset matches,
  # we'll use one of the longer nicknames for testing.
  # (Because "grep -w hostname" matches "grep -w hostname-dsamixed")
  MYDBPASS="-d ${PROFILEDIR} -f ${R_PWFILE}"
  TESTNAME="Ensure there's exactly one match for ${CERTNAME}-dsamixed"
  cert_check_nickname_exists "$MYDBPASS" "${CERTNAME}-dsamixed" 0 1 "${TESTNAME}"

  CU_ACTION="Repeated import of $CERTNAME's mixed DSA Cert with different nickname"
  certu -A -n "${CERTNAME}-repeated-dsamixed" -t "u,u,u" -d "${PROFILEDIR}" \
        -f "${R_PWFILE}" -i "${CERTNAME}-dsamixed.cert" 2>&1

  TESTNAME="Ensure there's still exactly one match for ${CERTNAME}-dsamixed"
  cert_check_nickname_exists "$MYDBPASS" "${CERTNAME}-dsamixed" 0 1 "${TESTNAME}"

  TESTNAME="Ensure there's zero matches for ${CERTNAME}-repeated-dsamixed"
  cert_check_nickname_exists "$MYDBPASS" "${CERTNAME}-repeated-dsamixed" 0 0 "${TESTNAME}"

  echo "Importing all the server's own CA chain into the servers DB"
  for CA in `find ${SERVER_CADIR} -name "?*.ca.cert"` ;
  do
      N=`basename $CA | sed -e "s/.ca.cert//"`
      if [[ "$N" =~ ^serverCA(-.*)?$ ]]; then
          T="-t C,C,C"
      else
          T="-t u,u,u"
      fi
      CU_ACTION="Import $N CA $T for $CERTNAME (ext.) "
      certu -A -n $N  $T -f "${R_PWFILE}" -d "${PROFILEDIR}" \
          -i "${CA}" 2>&1
  done
#============
  echo "Client Cert"
  cert_init_cert ${EXT_CLIENTDIR} ExtendedSSLUser 1 ${D_EXT_CLIENT}

  CU_ACTION="Initializing ${CERTNAME}'s Cert DB (ext.)"
  certu -N -d "${PROFILEDIR}" -f "${R_PWFILE}" 2>&1

  CU_ACTION="Loading root cert module to ${CERTNAME}'s Cert DB (ext.)"
  modu -add "RootCerts" -libfile "${ROOTCERTSFILE}" -dbdir "${PROFILEDIR}" 2>&1

  for i in ${!keyType[@]}
  do
    suffix=${keySuffix[$i]}
    gencmd=${keyGenCmd[$i]}
    key_type=${keyType[$i]}
    if [ "$key_type" =  "ECC" ]; then
        gencmd="$gencmd ${EC_CURVE}"
    fi

    CU_ACTION="Generate $key_type Cert Request for $CERTNAME (ext)"
    CU_SUBJECT="CN=$CERTNAME, E=${CERTNAME}${suffix}@example.com, O=BOGUS NSS, L=Mountain View, ST=California, C=US"
    certu -R -d "${PROFILEDIR}" ${gencmd} -f "${R_PWFILE}" \
        -z "${R_NOISE_FILE}" -o req 2>&1

    CU_ACTION="Sign ${CERTNAME}'s $key_type Request (ext)"
    cp ${CERTDIR}/req ${CLIENT_CADIR}
    certu -C -c "chain-2-clientCA${suffix}" -m 300 -v 60 \
        -d "${P_CLIENT_CADIR}" -i req -o "${CERTNAME}${suffix}.cert" \
        -f "${R_PWFILE}" 2>&1

    CU_ACTION="Import $CERTNAME's $key_type Cert -t u,u,u (ext)"
    certu -A -n "${CERTNAME}${suffix}" -t "u,u,u" -d "${PROFILEDIR}" \
        -f "${R_PWFILE}" -i "${CERTNAME}${suffix}.cert" 2>&1
    CU_ACTION="Import Server $key_type Root CA -t C,C,C for $CERTNAME (ext.)"
    certu -A -n "serverCA${suffix}" -t "C,C,C" -f "${R_PWFILE}" \
        -d "${PROFILEDIR}" -i "${SERVER_CADIR}/serverCA${suffix}.ca.cert" 2>&1
    #  Generate mixed certificate signed with RSA
    if [ "${keyIsMixed[$i]}" = "true" ]; then
      NEWSERIAL=`expr ${keySerialOffset[$i]} + 300`
      CU_ACTION="Generate mixed $key_type Cert Request for $CERTNAME (ext)"
      CU_SUBJECT="CN=$CERTNAME, E=${CERTNAME}-dsamixed@example.com, O=BOGUS NSS, L=Mountain View, ST=California, C=US"
      certu -R -d "${PROFILEDIR}" ${gencmd} -f "${R_PWFILE}" \
	  -z "${R_NOISE_FILE}" -o req 2>&1

      CU_ACTION="Sign ${CERTNAME}'s mixed ${key_type} Request (ext)"
      cp ${CERTDIR}/req ${CLIENT_CADIR}
      certu -C -c "chain-2-clientCA" -m ${NEWSERIAL}-v 60 \
          -d "${P_CLIENT_CADIR}" -i req -o "${CERTNAME}${suffix}mixed.cert" \
         -f "${R_PWFILE}" 2>&1

      CU_ACTION="Import $CERTNAME's mixed ${key_type} Cert -t u,u,u (ext)"
      certu -A -n "${CERTNAME}${suffix}mixed" -t "u,u,u" -d "${PROFILEDIR}" \
	  -f "${R_PWFILE}" -i "${CERTNAME}${suffix}mixed.cert" 2>&1

#     CU_ACTION="Import Server ${key_type} Root CA -t C,C,C for $CERTNAME (ext.)"
#     certu -A -n "serverCA${suffix}" -t "C,C,C" -f "${R_PWFILE}" \
#         -d "${PROFILEDIR}" -i "${SERVER_CADIR}/serverCA${suffix}.ca.cert" 2>&1
    fi
  done

  echo "Importing all the client's own CA chain into the servers DB"
  for CA in `find ${CLIENT_CADIR} -name "?*.ca.cert"` ;
  do
      N=`basename $CA | sed -e "s/.ca.cert//"`
      if [[ "$N" =~ ^clientCA(-.*)?$ ]]; then
          T="-t T,C,C"
      else
          T="-t u,u,u"
      fi
      echo " $T"
      CU_ACTION="Import $N CA $T for $CERTNAME (ext.)"
      certu -A -n $N  $T -f "${R_PWFILE}" -d "${PROFILEDIR}" \
          -i "${CA}" 2>&1
  done
  if [ "$CERTFAILED" != 0 ] ; then
      cert_log "ERROR: EXT failed $RET"
  else
      cert_log "SUCCESS: EXT passed"
  fi
}

############################## cert_ssl ################################
# local shell function to create client + server certs for SSL test
########################################################################
cert_ssl()
{
  ################# Creating Certs for SSL test ###########################
  #
  CERTFAILED=0
  echo "$SCRIPTNAME: Creating Client CA Issued Certificates ==============="
  cert_create_cert ${CLIENTDIR} "TestUser" 70 ${D_CLIENT}

  echo "$SCRIPTNAME: Creating Server CA Issued Certificate for \\"
  echo "             ${HOSTADDR} ------------------------------------"
  cert_create_cert ${SERVERDIR} "${HOSTADDR}" 100 ${D_SERVER}
  echo "$SCRIPTNAME: Creating Server CA Issued Certificate for \\"
  echo "             ${HOSTADDR}-sni --------------------------------"
  CERTSERIAL=101
  CERTNAME="${HOST}-sni${sniCertCount}.${DOMSUF}"
  cert_add_cert
  for i in ${!keyType[@]}
  do
    suffix=${keySuffix[$i]}
    key_type=${keyType[$i]}
    CU_ACTION="Modify trust attributes of $key_type Root CA -t TC,TC,TC"
    certu -M -n "TestCA${suffix}" -t "TC,TC,TC" -d ${PROFILEDIR} -f "${R_PWFILE}"
  done

#  cert_init_cert ${SERVERDIR} "${HOSTADDR}" 1 ${D_SERVER}
#  echo "************* Copying CA files to ${SERVERDIR}"
#  cp ${CADIR}/*.db .
#  hw_acc
#  CU_ACTION="Creating ${CERTNAME}'s Server Cert"
#  CU_SUBJECT="CN=${CERTNAME}, O=BOGUS Netscape, L=Mountain View, ST=California, C=US"
#  certu -S -n "${CERTNAME}" -c "TestCA" -t "Pu,Pu,Pu" -d ${PROFILEDIR} \
#	 -f "${R_PWFILE}" -z "${R_NOISE_FILE}" -v 60 2>&1

  if [ "$CERTFAILED" != 0 ] ; then
      cert_log "ERROR: SSL failed $RET"
  else
      cert_log "SUCCESS: SSL passed"
  fi

  echo "$SCRIPTNAME: Creating database for OCSP stapling tests  ==============="
  echo "cp -r ${SERVERDIR} ${STAPLINGDIR}"
  cp -r ${R_SERVERDIR} ${R_STAPLINGDIR}
  pk12u -o ${R_STAPLINGDIR}/ca.p12 -n TestCA -k ${R_PWFILE} -w ${R_PWFILE} -d ${R_CADIR}
  pk12u -i ${R_STAPLINGDIR}/ca.p12 -k ${R_PWFILE} -w ${R_PWFILE} -d ${R_STAPLINGDIR}

  echo "$SCRIPTNAME: Creating database for strsclnt no login tests  ==============="
  echo "cp -r ${CLIENTDIR} ${NOLOGINDIR}"
  cp -r ${R_CLIENTDIR} ${R_NOLOGINDIR}
  # change the password to empty
  certu -W -d "${R_NOLOGINDIR}" -f "${R_PWFILE}" -@ "${R_EMPTY_FILE}" 2>&1
}

############################## cert_stresscerts ################################
# local shell function to create client certs for SSL stresstest
########################################################################
cert_stresscerts()
{

  ############### Creating Certs for SSL stress test #######################
  #
  CERTDIR="$CLIENTDIR"
  cd "${CERTDIR}"

  PROFILEDIR=`cd ${CERTDIR}; pwd`
  if [ "${OS_ARCH}" = "WINNT" -a "$OS_NAME" = "CYGWIN_NT" ]; then
     PROFILEDIR=`cygpath -m ${PROFILEDIR}`
  fi
  if [ -n "${MULTIACCESS_DBM}" ]; then
     PROFILEDIR="multiaccess:${D_CLIENT}"
  fi
  CERTFAILED=0
  echo "$SCRIPTNAME: Creating Client CA Issued Certificates ==============="

  CONTINUE=$GLOB_MAX_CERT
  CERTSERIAL=10

  while [ $CONTINUE -ge $GLOB_MIN_CERT ]
  do
      CERTNAME="TestUser$CONTINUE"
#      cert_add_cert ${CLIENTDIR} "TestUser$CONTINUE" $CERTSERIAL
      cert_add_cert
      CERTSERIAL=`expr $CERTSERIAL + 1 `
      CONTINUE=`expr $CONTINUE - 1 `
  done
  if [ "$CERTFAILED" != 0 ] ; then
      cert_log "ERROR: StressCert failed $RET"
  else
      cert_log "SUCCESS: StressCert passed"
  fi
}

############################## cert_fips #####################################
# local shell function to create certificates for FIPS tests
##############################################################################
cert_fips()
{
  CERTFAILED=0
  echo "$SCRIPTNAME: Creating FIPS 140 DSA Certificates =============="
  cert_init_cert "${FIPSDIR}" "FIPS PUB 140 Test Certificate" 1000 "${D_FIPS}"

  CU_ACTION="Initializing ${CERTNAME}'s Cert DB"
  certu -N -d "${PROFILEDIR}" -f "${R_FIPSPWFILE}" 2>&1

  CU_ACTION="Loading root cert module to ${CERTNAME}'s Cert DB (ext.)"
  modu -add "RootCerts" -libfile "${ROOTCERTSFILE}" -dbdir "${PROFILEDIR}" 2>&1

  echo "$SCRIPTNAME: Enable FIPS mode on database -----------------------"
  CU_ACTION="Enable FIPS mode on database for ${CERTNAME}"
  echo "modutil -dbdir ${PROFILEDIR} -fips true "
  ${BINDIR}/modutil -dbdir ${PROFILEDIR} -fips true 2>&1 <<MODSCRIPT
y
MODSCRIPT
  RET=$?
  if [ "$RET" -ne 0 ]; then
    html_failed "${CU_ACTION} ($RET) "
    cert_log "ERROR: ${CU_ACTION} failed $RET"
  else
    html_passed "${CU_ACTION}"
  fi

  CU_ACTION="Setting invalid database password in FIPS mode"
  RETEXPECTED=255
  certu -W -d "${PROFILEDIR}" -f "${R_FIPSPWFILE}" -@ "${R_FIPSBADPWFILE}" 2>&1
  CU_ACTION="Attempt to generate a key with exponent of 3 (too small)"
  certu -G -k rsa -g 2048 -y 3 -d "${PROFILEDIR}" -z ${R_NOISE_FILE} -f "${R_FIPSPWFILE}"
  CU_ACTION="Attempt to generate a key with exponent of 17 (too small)"
  certu -G -k rsa -g 2048 -y 17 -d "${PROFILEDIR}" -z ${R_NOISE_FILE} -f "${R_FIPSPWFILE}"
  RETEXPECTED=0

  CU_ACTION="Generate Certificate for ${CERTNAME}"
  CU_SUBJECT="CN=${CERTNAME}, E=fips@example.com, O=BOGUS NSS, OU=FIPS PUB 140, L=Mountain View, ST=California, C=US"
  certu -S -n ${FIPSCERTNICK} -x -t "Cu,Cu,Cu" -d "${PROFILEDIR}" -f "${R_FIPSPWFILE}" -k ec -q nistp256  -v 600 -m 500 -z "${R_NOISE_FILE}" 2>&1
  if [ "$RET" -eq 0 ]; then
    cert_log "SUCCESS: FIPS passed"
  fi

}

########################## cert_rsa_exponent #################################
# local shell function to verify small rsa exponent can be used (only
# run if FIPS has not been turned on in the build).
##############################################################################
cert_rsa_exponent_nonfips()
{
  echo "$SCRIPTNAME: Verify that small RSA exponents still work  =============="
  CU_ACTION="Attempt to generate a key with exponent of 3"
  certu -G -k rsa -g 2048 -y 3 -d "${CLIENTDIR}" -z ${R_NOISE_FILE} -f "${R_PWFILE}"
  CU_ACTION="Attempt to generate a key with exponent of 17"
  certu -G -k rsa -g 2048 -y 17 -d "${CLIENTDIR}" -z ${R_NOISE_FILE} -f "${R_PWFILE}"
}

############################## cert_eccurves ###########################
# local shell function to create server certs for all EC curves
########################################################################
cert_eccurves()
{
  ################# Creating Certs for EC curves test ########################
  #
    echo "$SCRIPTNAME: Creating Server CA Issued Certificate for "
    echo "             EC Curves Test Certificates ------------------------------------"

    cert_init_cert "${ECCURVES_DIR}" "EC Curves Test Certificates" 1 ${D_ECCURVES}

    CU_ACTION="Initializing EC Curve's Cert DB"
    certu -N -d "${PROFILEDIR}" -f "${R_PWFILE}" 2>&1

    CU_ACTION="Loading root cert module to EC Curve's Cert DB"
    modu -add "RootCerts" -libfile "${ROOTCERTSFILE}" -dbdir "${PROFILEDIR}" 2>&1

    CU_ACTION="Import EC Root CA for $CERTNAME"
    certu -A -n "TestCA-ec" -t "TC,TC,TC" -f "${R_PWFILE}" \
        -d "${PROFILEDIR}" -i "${R_CADIR}/TestCA-ec.ca.cert" 2>&1

    CURVE_LIST="nistp256 nistp384 nistp521"
    CERTSERIAL=2000

    for CURVE in ${CURVE_LIST}
    do
	CERTFAILED=0
	CERTNAME="Curve-${CURVE}"
	CERTSERIAL=`expr $CERTSERIAL + 1 `
	CU_ACTION="Generate EC Cert Request for $CERTNAME"
	CU_SUBJECT="CN=$CERTNAME, E=${CERTNAME}-ec@example.com, O=BOGUS NSS, L=Mountain View, ST=California, C=US"
	certu -R -k ec -q "${CURVE}" -d "${PROFILEDIR}" -f "${R_PWFILE}" \
		-z "${R_NOISE_FILE}" -o req  2>&1
	
	if [ $RET -eq 0 ] ; then
	  CU_ACTION="Sign ${CERTNAME}'s EC Request"
	  certu -C -c "TestCA-ec" -m "$CERTSERIAL" -v 60 -d "${P_R_CADIR}" \
		-i req -o "${CERTNAME}-ec.cert" -f "${R_PWFILE}" "$1" 2>&1
	fi
	
	if [ $RET -eq 0 ] ; then
	  CU_ACTION="Import $CERTNAME's EC Cert"
	  certu -A -n "${CERTNAME}-ec" -t "u,u,u" -d "${PROFILEDIR}" \
		-f "${R_PWFILE}" -i "${CERTNAME}-ec.cert" 2>&1
	fi
    done
}

########################### cert_extensions_test #############################
# local shell function to test cert extensions generation
##############################################################################
cert_extensions_test()
{
    COUNT=`expr ${COUNT} + 1`
    CERTNAME=TestExt${COUNT}
    CU_SUBJECT="CN=${CERTNAME}, E=${CERTNAME}@example.com, O=BOGUS NSS, L=Mountain View, ST=California, C=US"

    echo
    echo certutil -d ${CERT_EXTENSIONS_DIR} -S -n ${CERTNAME} \
        -t "u,u,u" -o ${CERT_EXTENSIONS_DIR}/tempcert -s "${CU_SUBJECT}" -x -f ${R_PWFILE} \
        -z "${R_NOISE_FILE}" -${OPT} \< ${TARG_FILE}
    echo "certutil options:"
    cat ${TARG_FILE}
    ${BINDIR}/certutil -d ${CERT_EXTENSIONS_DIR} -S -n ${CERTNAME} \
        -t "u,u,u" -o ${CERT_EXTENSIONS_DIR}/tempcert -s "${CU_SUBJECT}" -x -f ${R_PWFILE} \
        -z "${R_NOISE_FILE}" -${OPT} < ${TARG_FILE}
    RET=$?
    if [ "${RET}" -ne 0 ]; then
        CERTFAILED=1
        html_failed "${TESTNAME} (${COUNT}) - Create and Add Certificate"
        cert_log "ERROR: ${TESTNAME} - Create and Add Certificate failed"
        return 1
    fi

    echo certutil -d ${CERT_EXTENSIONS_DIR} -L -n ${CERTNAME}
    EXTLIST=`${BINDIR}/certutil -d ${CERT_EXTENSIONS_DIR} -L -n ${CERTNAME}`
    RET=$?
    echo "${EXTLIST}"
    if [ "${RET}" -ne 0 ]; then
        CERTFAILED=1
        html_failed "${TESTNAME} (${COUNT}) - List Certificate"
        cert_log "ERROR: ${TESTNAME} - List Certificate failed"
        return 1
    fi

    for FL in `echo ${FILTERLIST} | tr \| ' '`; do
        FL="`echo ${FL} | tr _ ' '`"
        EXPSTAT=0
        if [ X`echo "${FL}" | cut -c 1` = 'X!' ]; then
            EXPSTAT=1
            FL=`echo ${FL} | tr -d '!'`
        fi
        echo "${EXTLIST}" | grep "${FL}" >/dev/null 2>&1
        RET=$?
        if [ "${RET}" -ne "${EXPSTAT}" ]; then
            CERTFAILED=1
            html_failed "${TESTNAME} (${COUNT}) - Looking for ${FL}" "returned ${RET}, expected is ${EXPSTAT}"
            cert_log "ERROR: ${TESTNAME} - Looking for ${FL} failed"
            return 1
        fi
    done

    html_passed "${TESTNAME} (${COUNT})"
    return 0
}

############################## cert_extensions ###############################
# local shell function to run cert extensions tests
##############################################################################
cert_extensions()
{
    CERTNAME=TestExt
    cert_create_cert ${CERT_EXTENSIONS_DIR} ${CERTNAME} 90 ${D_CERT_EXTENSTIONS}
    TARG_FILE=${CERT_EXTENSIONS_DIR}/test.args

    COUNT=0
    while read ARG OPT FILTERLIST; do
        if [ X"`echo ${ARG} | cut -c 1`" = "X#" ]; then
            continue
        fi
        if [ X"`echo ${ARG} | cut -c 1`" = "X!" ]; then
            TESTNAME="${FILTERLIST}"
            continue
        fi
        if [ X"${ARG}" = "X=" ]; then
            cert_extensions_test
            rm -f ${TARG_FILE}
        else
            echo ${ARG} >> ${TARG_FILE}
        fi
    done < ${QADIR}/cert/certext.txt
}

cert_make_with_param()
{
    DIRPASS="$1"
    CERTNAME="$2"
    MAKE="$3"
    SUBJ="$4"
    EXTRA="$5"
    EXPECT="$6"
    TESTNAME="$7"

    echo certutil ${DIRPASS} -s "${SUBJ}" ${MAKE} ${CERTNAME} ${EXTRA}
    ${BINDIR}/certutil ${DIRPASS} -s "${SUBJ}" ${MAKE} ${CERTNAME} ${EXTRA}

    RET=$?
    if [ "${RET}" -ne "${EXPECT}" ]; then
        # if we expected failure to create, then delete unexpected certificate
        if [ "${EXPECT}" -ne 0 ]; then
            ${BINDIR}/certutil ${DIRPASS} -D ${CERTNAME}
        fi

        CERTFAILED=1
        html_failed "${TESTNAME} (${COUNT}) - ${EXTRA}"
        cert_log "ERROR: ${TESTNAME} - ${EXTRA} failed"
        return 1
    fi

    html_passed "${TESTNAME} (${COUNT})"
    return 0
}

cert_check_nickname_exists()
{
    MYDIRPASS="$1"
    MYCERTNAME="$2"
    EXPECT="$3"
    EXPECTCOUNT="$4"
    MYTESTNAME="$5"

    echo certutil ${MYDIRPASS} -L
    ${BINDIR}/certutil ${MYDIRPASS} -L

    RET=$?
    if [ "${RET}" -ne "${EXPECT}" ]; then
        CERTFAILED=1
        html_failed "${MYTESTNAME} - list"
        cert_log "ERROR: ${MYTESTNAME} - list"
        return 1
    fi

    LISTCOUNT=`${BINDIR}/certutil ${MYDIRPASS} -L | grep -wc ${MYCERTNAME}`
    if [ "${LISTCOUNT}" -ne "${EXPECTCOUNT}" ]; then
        CERTFAILED=1
        html_failed "${MYTESTNAME} - list and count"
        cert_log "ERROR: ${MYTESTNAME} - list and count failed"
        return 1
    fi

    html_passed "${MYTESTNAME}"
    return 0
}

cert_list_and_count_dns()
{
    DIRPASS="$1"
    CERTNAME="$2"
    EXPECT="$3"
    EXPECTCOUNT="$4"
    TESTNAME="$5"

    echo certutil ${DIRPASS} -L ${CERTNAME}
    ${BINDIR}/certutil ${DIRPASS} -L ${CERTNAME}

    RET=$?
    if [ "${RET}" -ne "${EXPECT}" ]; then
        CERTFAILED=1
        html_failed "${TESTNAME} (${COUNT}) - list and count"
        cert_log "ERROR: ${TESTNAME} - list and count failed"
        return 1
    fi

    LISTCOUNT=`${BINDIR}/certutil ${DIRPASS} -L ${CERTNAME} | grep -wc DNS`
    if [ "${LISTCOUNT}" -ne "${EXPECTCOUNT}" ]; then
        CERTFAILED=1
        html_failed "${TESTNAME} (${COUNT}) - list and count"
        cert_log "ERROR: ${TESTNAME} - list and count failed"
        return 1
    fi

    html_passed "${TESTNAME} (${COUNT})"
    return 0
}

cert_dump_ext_to_file()
{
    DIRPASS="$1"
    CERTNAME="$2"
    OID="$3"
    OUTFILE="$4"
    EXPECT="$5"
    TESTNAME="$6"

    echo certutil ${DIRPASS} -L ${CERTNAME} --dump-ext-val ${OID}
    echo "writing output to ${OUTFILE}"
    ${BINDIR}/certutil ${DIRPASS} -L ${CERTNAME} --dump-ext-val ${OID} > ${OUTFILE}

    RET=$?
    if [ "${RET}" -ne "${EXPECT}" ]; then
        CERTFAILED=1
        html_failed "${TESTNAME} (${COUNT}) - dump to file"
        cert_log "ERROR: ${TESTNAME} - dump to file failed"
        return 1
    fi

    html_passed "${TESTNAME} (${COUNT})"
    return 0
}

cert_delete()
{
    DIRPASS="$1"
    CERTNAME="$2"
    EXPECT="$3"
    TESTNAME="$4"

    echo certutil ${DIRPASS} -D ${CERTNAME}
    ${BINDIR}/certutil ${DIRPASS} -D ${CERTNAME}

    RET=$?
    if [ "${RET}" -ne "${EXPECT}" ]; then
        CERTFAILED=1
        html_failed "${TESTNAME} (${COUNT}) - delete cert"
        cert_log "ERROR: ${TESTNAME} - delete cert failed"
        return 1
    fi

    html_passed "${TESTNAME} (${COUNT})"
    return 0
}

cert_inc_count()
{
    COUNT=`expr ${COUNT} + 1`
}

############################## cert_crl_ssl ############################
# test adding subject-alt-name, dumping, and adding generic extension
########################################################################
cert_san_and_generic_extensions()
{
    EXTDUMP=sanext.der

    DIR="-d ${CERT_EXTENSIONS_DIR} -f ${R_PWFILE}"
    CERTNAME="-n WithSAN"
    MAKE="-S -t ,, -x -z ${R_NOISE_FILE}"
    SUBJ="CN=example.com"

    TESTNAME="san-and-generic-extensions"

    cert_inc_count
    cert_make_with_param "${DIR}" "${CERTNAME}" "${MAKE}" "${SUBJ}" \
        "--extSAN example.com" 255 \
        "create cert with invalid SAN parameter"

    cert_inc_count
    cert_make_with_param "${DIR}" "${CERTNAME}" "${MAKE}" "${SUBJ}" \
        "--extSAN example.com,dns:www.example.com" 255 \
        "create cert with invalid SAN parameter"

    TN="create cert with valid SAN parameter"

    cert_inc_count
    cert_make_with_param "${DIR}" "${CERTNAME}" "${MAKE}" "${SUBJ}" \
        "--extSAN dns:example.com,dns:www.example.com" 0 \
        "${TN}"

    cert_inc_count
    cert_list_and_count_dns "${DIR}" "${CERTNAME}" 0 2 \
        "${TN}"

    cert_inc_count
    cert_dump_ext_to_file "${DIR}" "${CERTNAME}" "2.5.29.17" "${EXTDUMP}" 0 \
        "dump extension 2.5.29.17 to file ${EXTDUMP}"

    cert_inc_count
    cert_delete "${DIR}" "${CERTNAME}" 0 \
        "${TN}"

    cert_inc_count
    cert_list_and_count_dns "${DIR}" "${CERTNAME}" 255 0 \
        "expect failure to list cert, because we deleted it"

    cert_inc_count
    cert_make_with_param "${DIR}" "${CERTNAME}" "${MAKE}" "${SUBJ}" \
        "--extGeneric ${EXTDUMP}" 255 \
        "create cert with invalid generic ext parameter"

    cert_inc_count
    cert_make_with_param "${DIR}" "${CERTNAME}" "${MAKE}" "${SUBJ}" \
        "--extGeneric not-critical:${EXTDUMP}" 255 \
        "create cert with invalid generic ext parameter"

    cert_inc_count
    cert_make_with_param "${DIR}" "${CERTNAME}" "${MAKE}" "${SUBJ}" \
        "--extGeneric not-critical:${EXTDUMP},2.5.29.17:critical:${EXTDUMP}" 255 \
        "create cert with invalid generic ext parameter"

    TN="create cert with valid generic ext parameter"

    cert_inc_count
    cert_make_with_param "${DIR}" "${CERTNAME}" "${MAKE}" "${SUBJ}" \
        "--extGeneric 2.5.29.17:not-critical:${EXTDUMP}" 0 \
        "${TN}"

    cert_inc_count
    cert_list_and_count_dns "${DIR}" "${CERTNAME}" 0 2 \
        "${TN}"

    cert_inc_count
    cert_delete "${DIR}" "${CERTNAME}" 0 \
        "${TN}"

    cert_inc_count
    cert_list_and_count_dns "${DIR}" "${CERTNAME}" 255 0 \
        "expect failure to list cert, because we deleted it"
}

############################## cert_crl_ssl ############################
# local shell function to generate certs and crls for SSL tests
########################################################################
cert_crl_ssl()
{

  ################# Creating Certs ###################################
  #
  CERTFAILED=0
  CERTSERIAL=${CRL_GRP_1_BEGIN}

  cd $CADIR

  PROFILEDIR=`cd ${CLIENTDIR}; pwd`
  if [ "${OS_ARCH}" = "WINNT" -a "$OS_NAME" = "CYGWIN_NT" ]; then
     PROFILEDIR=`cygpath -m ${PROFILEDIR}`
  fi
  CRL_GRPS_END=`expr ${CRL_GRP_1_BEGIN} + ${TOTAL_CRL_RANGE} - 1`
  echo "$SCRIPTNAME: Creating Client CA Issued Certificates Range $CRL_GRP_1_BEGIN - $CRL_GRPS_END ==="
  CU_ACTION="Creating client test certs"

  while [ $CERTSERIAL -le $CRL_GRPS_END ]
  do
      CERTNAME="TestUser$CERTSERIAL"
      cert_add_cert
      CERTSERIAL=`expr $CERTSERIAL + 1 `
  done

  #################### CRL Creation ##############################
  CRL_GEN_RES=0
  echo "$SCRIPTNAME: Creating CA CRL ====================================="

  CRL_GRP_END=`expr ${CRL_GRP_1_BEGIN} + ${CRL_GRP_1_RANGE} - 1`
  CRL_FILE_GRP_1=${R_SERVERDIR}/root.crl_${CRL_GRP_1_BEGIN}-${CRL_GRP_END}
  CRL_FILE=${CRL_FILE_GRP_1}

  CRLUPDATE=`date -u "+%Y%m%d%H%M%SZ"`

  for i in ${!keyType[@]}
  do
    suffix=${keySuffix[$i]}
    key_type=${keyType[$i]}
    CU_ACTION="Generating CRL ($key_type) for range ${CRL_GRP_1_BEGIN}-${CRL_GRP_END} TestCA${suffix} authority"
    CRL_GRP_END_=`expr ${CRL_GRP_END} - 1`
    crlu -d $CADIR -G -n "TestCA${suffix}" -f ${R_PWFILE} \
        -o ${CRL_FILE_GRP_1}_or${suffix} <<EOF_CRLINI
update=$CRLUPDATE
addcert ${CRL_GRP_1_BEGIN}-${CRL_GRP_END_} $CRL_GRP_DATE
addext reasonCode 0 4
addext issuerAltNames 0 "rfc822Name:ca${suffix}email@ca.com|dnsName:ca${suffix}.com|directoryName:CN=NSS Test CA ($key_type),O=BOGUS NSS,L=Mountain View,ST=California,C=US|URI:http://ca${suffix}.com|ipAddress:192.168.0.1|registerID=reg CA ($key_type)"
EOF_CRLINI
    # This extension should be added to the list, but currently nss has bug
    #addext authKeyId 0 "CN=NSS Test CA,O=BOGUS NSS,L=Mountain View,ST=California,C=US" 1
    CRL_GEN_RES=`expr $? + $CRL_GEN_RES`
    chmod 600 ${CRL_FILE_GRP_1}_or${suffix}
  done

  echo test > file
  ############################# Modification ##################################

  echo "$SCRIPTNAME: Modifying CA CRL by adding one more cert ============"
  sleep 2
  CRLUPDATE=`date -u "+%Y%m%d%H%M%SZ"`
  CRL_GRP_DATE=`date -u "+%Y%m%d%H%M%SZ"`
  for i in ${!keyType[@]}
  do
    suffix=${keySuffix[$i]}
    key_type=${keyType[$i]}
    CU_ACTION="Modify CRL ($key_type)by adding one more cert"
    crlu -d $CADIR -M -n "TestCA${suffix}" -f ${R_PWFILE} \
        -o ${CRL_FILE_GRP_1}_or1${suffix} \
        -i ${CRL_FILE_GRP_1}_or${suffix} <<EOF_CRLINI
update=$CRLUPDATE
addcert ${CRL_GRP_END} $CRL_GRP_DATE
EOF_CRLINI
    CRL_GEN_RES=`expr $? + $CRL_GEN_RES`
    chmod 600 ${CRL_FILE_GRP_1}_or1${suffix}
    TEMPFILES="$TEMPFILES ${CRL_FILE_GRP_1}_or${suffix}"
  done

  ########### Removing one cert ${UNREVOKED_CERT_GRP_1} #######################
  sleep 2
  CRLUPDATE=`date -u "+%Y%m%d%H%M%SZ"`
  for i in ${!keyType[@]}
  do
    suffix=${keySuffix[$i]}
    key_type=${keyType[$i]}
    echo "$SCRIPTNAME: Modifying CA CRL by removing one cert ==============="
    CU_ACTION="Modify CRL ($key_type) by removing one cert"
    crlu -d $CADIR -M -n "TestCA${suffix}" -f ${R_PWFILE} \
        -o ${CRL_FILE_GRP_1}${suffix} \
        -i ${CRL_FILE_GRP_1}_or1${suffix} <<EOF_CRLINI
update=$CRLUPDATE
rmcert  ${UNREVOKED_CERT_GRP_1}
EOF_CRLINI
    chmod 600 ${CRL_FILE_GRP_1}${suffix}
    TEMPFILES="$TEMPFILES ${CRL_FILE_GRP_1}_or1${suffix}"
  done

  ########### Creating second CRL which includes groups 1 and 2 ##############
  CRL_GRP_END=`expr ${CRL_GRP_2_BEGIN} + ${CRL_GRP_2_RANGE} - 1`
  CRL_FILE_GRP_2=${R_SERVERDIR}/root.crl_${CRL_GRP_2_BEGIN}-${CRL_GRP_END}

  echo "$SCRIPTNAME: Creating CA CRL for groups 1 and 2  ==============="
  sleep 2
  CRLUPDATE=`date -u "+%Y%m%d%H%M%SZ"`
  CRL_GRP_DATE=`date -u "+%Y%m%d%H%M%SZ"`

  for i in ${!keyType[@]}
  do
    suffix=${keySuffix[$i]}
    key_type=${keyType[$i]}
    CU_ACTION="Creating CRL ($key_type} for groups 1 and 2"
    crlu -d $CADIR -M -n "TestCA${suffix}" -f ${R_PWFILE} \
            -o ${CRL_FILE_GRP_2}${suffix} \
            -i ${CRL_FILE_GRP_1}${suffix} <<EOF_CRLINI
update=$CRLUPDATE
addcert ${CRL_GRP_2_BEGIN}-${CRL_GRP_END} $CRL_GRP_DATE
addext invalidityDate 0 $CRLUPDATE
rmcert  ${UNREVOKED_CERT_GRP_2}
EOF_CRLINI
    CRL_GEN_RES=`expr $? + $CRL_GEN_RES`
    chmod 600 ${CRL_FILE_GRP_2}${suffix}
   done

  ########### Creating second CRL which includes groups 1, 2 and 3 ##############
  CRL_GRP_END=`expr ${CRL_GRP_3_BEGIN} + ${CRL_GRP_3_RANGE} - 1`
  CRL_FILE_GRP_3=${R_SERVERDIR}/root.crl_${CRL_GRP_3_BEGIN}-${CRL_GRP_END}

  echo "$SCRIPTNAME: Creating CA CRL for groups 1, 2 and 3  ==============="
  sleep 2
  CRLUPDATE=`date -u "+%Y%m%d%H%M%SZ"`
  CRL_GRP_DATE=`date -u "+%Y%m%d%H%M%SZ"`
  for i in ${!keyType[@]}
  do
    suffix=${keySuffix[$i]}
    key_type=${keyType[$i]}
    CU_ACTION="Creating CRL ($key_type) for groups 1, 2 and 3"
    crlu -d $CADIR -M -n "TestCA${suffix}" -f ${R_PWFILE} \
       -o ${CRL_FILE_GRP_3}${suffix} \
       -i ${CRL_FILE_GRP_2}${suffix} <<EOF_CRLINI
update=$CRLUPDATE
addcert ${CRL_GRP_3_BEGIN}-${CRL_GRP_END} $CRL_GRP_DATE
rmcert  ${UNREVOKED_CERT_GRP_3}
addext crlNumber 0 2
EOF_CRLINI
    CRL_GEN_RES=`expr $? + $CRL_GEN_RES`
    chmod 600 ${CRL_FILE_GRP_3}${suffix}
  done

  ############ Importing Server CA Issued CRL for certs of first group #######

  echo "$SCRIPTNAME: Importing Server CA Issued CRL for certs ${CRL_GRP_BEGIN} trough ${CRL_GRP_END}"
  for i in ${!keyType[@]}
  do
    suffix=${keySuffix[$i]}
    key_type=${keyType[$i]}
    CU_ACTION="Importing CRL ($key_type) for groups 1"
    crlu -D -n TestCA${suffix}  -f "${R_PWFILE}" -d "${R_SERVERDIR}"
    crlu -I -i ${CRL_FILE}${suffix} -n "TestCA${suffix}" -f "${R_PWFILE}" -d "${R_SERVERDIR}"
    CRL_GEN_RES=`expr $? + $CRL_GEN_RES`
  done
  if [ "$CERTFAILED" != 0 -o "$CRL_GEN_RES" != 0 ] ; then
      cert_log "ERROR: SSL CRL prep failed $CERTFAILED : $CRL_GEN_RES"
  else
      cert_log "SUCCESS: SSL CRL prep passed"
  fi
}

#################
# Verify the we can successfully change the password on the database
#
cert_test_password()
{
  CERTFAILED=0
  echo "$SCRIPTNAME: Create A Password Test Cert  =============="
  cert_init_cert "${DBPASSDIR}" "Password Test Cert" 1000 "${D_DBPASSDIR}"

  echo "$SCRIPTNAME: Create A Password Test Ca  --------"
  ALL_CU_SUBJECT="CN=NSS Password Test CA, O=BOGUS NSS, L=Mountain View, ST=California, C=US"
  cert_CA RSA ${DBPASSDIR} PasswordCA -x "CTu,CTu,CTu" ${D_DBPASS} "1"

  # now change the password
  CU_ACTION="Changing password on ${CERTNAME}'s Cert DB"
  certu -W -d "${PROFILEDIR}" -f "${R_PWFILE}" -@ "${R_FIPSPWFILE}" 2>&1

  # finally make sure we can use the old key with the new password
  CU_ACTION="Generate Certificate for ${CERTNAME} with new password"
  CU_SUBJECT="CN=${CERTNAME}, E=password@example.com, O=BOGUS NSS, L=Mountain View, ST=California, C=US"
  certu -S -n PasswordCert -c PasswordCA -t "u,u,u" -d "${PROFILEDIR}" -f "${R_FIPSPWFILE}" -z "${R_NOISE_FILE}" 2>&1
  if [ "$RET" -eq 0 ]; then
    cert_log "SUCCESS: PASSWORD passed"
  fi
  CU_ACTION="Verify Certificate for ${CERTNAME} with new password"
  certu -V -n PasswordCert -u S -d "${PROFILEDIR}" -f "${R_FIPSPWFILE}" 2>&1
}

###############################
# test if we can distrust a certificate.
#
# we create 3 new certs:
#   1 leaf signed by the trusted root.
#   1 intermediate signed by the trusted root.
#   1 leaf signed by the intermediate.
#
#  we mark the first leaf and the intermediate as explicitly untrusted.
#  we then try to verify the two leaf certs for our possible usages.
#  All verification should fail.
#
cert_test_distrust()
{
  echo "$SCRIPTNAME: Creating Distrusted Certificate"
  cert_create_cert ${DISTRUSTDIR} "Distrusted" 2000 ${D_DISTRUST}
  CU_ACTION="Mark CERT as unstrusted"
  certu -M -n "Distrusted" -t p,p,p -d ${PROFILEDIR} -f "${R_PWFILE}" 2>&1
  echo "$SCRIPTNAME: Creating Distrusted Intermediate"
  CERTNAME="DistrustedCA"
  ALL_CU_SUBJECT="CN=${CERTNAME}, E=${CERTNAME}@example.com, O=BOGUS NSS, L=Mountain View, ST=California, C=US"
  cert_CA RSA ${CADIR} "${CERTNAME}" "-c TestCA" ",," ${D_CA} 2010 2>&1
  CU_ACTION="Import Distrusted Intermediate"
  certu -A -n "${CERTNAME}" -t "p,p,p" -f "${R_PWFILE}" -d "${PROFILEDIR}" \
          -i "${R_CADIR}/DistrustedCA.ca.cert" 2>&1

  # now create the last leaf signed by our distrusted CA
  # since it's not signed by TestCA it requires more steps.
  CU_ACTION="Generate Cert Request for Leaf Chained to Distrusted CA"
  CERTNAME="LeafChainedToDistrustedCA"
  CU_SUBJECT="CN=${CERTNAME}, E=${CERTNAME}@example.com, O=BOGUS NSS, L=Mountain View, ST=California, C=US"
  certu -R -d "${PROFILEDIR}" -f "${R_PWFILE}" -z "${R_NOISE_FILE}" -o req 2>&1

  CU_ACTION="Sign ${CERTNAME}'s Request"
  cp ${CERTDIR}/req ${CADIR}
  certu -C -c "DistrustedCA" -m 100 -v 60 -d "${P_R_CADIR}" \
        -i req -o "${CERTNAME}.cert" -f "${R_PWFILE}" 2>&1

  CU_ACTION="Import $CERTNAME's Cert  -t u,u,u"
  certu -A -n "$CERTNAME" -t "u,u,u" -d "${PROFILEDIR}" -f "${R_PWFILE}" \
        -i "${CERTNAME}.cert" 2>&1

  RETEXPECTED=255
  CU_ACTION="Verify ${CERTNAME} Cert for SSL Server"
  certu -V -n ${CERTNAME} -u V -d "${PROFILEDIR}" -f "${R_PWFILE}" 2>&1
  CU_ACTION="Verify ${CERTNAME} Cert for SSL Client"
  certu -V -n ${CERTNAME} -u C -d "${PROFILEDIR}" -f "${R_PWFILE}" 2>&1
  CU_ACTION="Verify ${CERTNAME} Cert for Email signer"
  certu -V -n ${CERTNAME} -u S -d "${PROFILEDIR}" -f "${R_PWFILE}" 2>&1
  CU_ACTION="Verify ${CERTNAME} Cert for Email recipient"
  certu -V -n ${CERTNAME} -u R -d "${PROFILEDIR}" -f "${R_PWFILE}" 2>&1
  CU_ACTION="Verify ${CERTNAME} Cert for OCSP responder"
  certu -V -n ${CERTNAME} -u O -d "${PROFILEDIR}" -f "${R_PWFILE}" 2>&1
  CU_ACTION="Verify ${CERTNAME} Cert for Object Signer"
  certu -V -n ${CERTNAME} -u J -d "${PROFILEDIR}" -f "${R_PWFILE}" 2>&1

  CERTNAME="Distrusted"
  CU_ACTION="Verify ${CERTNAME} Cert for SSL Server"
  certu -V -n ${CERTNAME} -u V -d "${PROFILEDIR}" -f "${R_PWFILE}" 2>&1
  CU_ACTION="Verify ${CERTNAME} Cert for SSL Client"
  certu -V -n ${CERTNAME} -u C -d "${PROFILEDIR}" -f "${R_PWFILE}" 2>&1
  CU_ACTION="Verify ${CERTNAME} Cert for Email signer"
  certu -V -n ${CERTNAME} -u S -d "${PROFILEDIR}" -f "${R_PWFILE}" 2>&1
  CU_ACTION="Verify ${CERTNAME} Cert for Email recipient"
  certu -V -n ${CERTNAME} -u R -d "${PROFILEDIR}" -f "${R_PWFILE}" 2>&1
  CU_ACTION="Verify ${CERTNAME} Cert for OCSP responder"
  certu -V -n ${CERTNAME} -u O -d "${PROFILEDIR}" -f "${R_PWFILE}" 2>&1
  CU_ACTION="Verify ${CERTNAME} Cert for Object Signer"
  certu -V -n ${CERTNAME} -u J -d "${PROFILEDIR}" -f "${R_PWFILE}" 2>&1
  RETEXPECTED=0
}

cert_test_ocspresp()
{
  echo "$SCRIPTNAME: OCSP response creation selftest"
  OR_ACTION="perform selftest"
  RETEXPECTED=0
  ocspr ${SERVER_CADIR} "serverCA" "chain-1-serverCA" -f "${R_PWFILE}" 2>&1
}

cert_test_implicit_db_init()
{
  echo "$SCRIPTNAME: test implicit database init"

  CU_ACTION="Add cert with trust flags to db with implicit init"
  mkdir ${IMPLICIT_INIT_DIR}
  certu -A -n ca -t 'C,C,C' -d ${P_R_IMPLICIT_INIT_DIR} -i "${SERVER_CADIR}/serverCA.ca.cert"
}

cert_test_token_uri()
{
  echo "$SCRIPTNAME: specify token with PKCS#11 URI"

  CERTIFICATE_DB_URI=`${BINDIR}/certutil -U -f "${R_PWFILE}" -d ${P_R_SERVERDIR} | sed -n 's/^ *uri: \(.*NSS%20Certificate%20DB.*\)/\1/p'`
  BUILTIN_OBJECTS_URI=`${BINDIR}/certutil -U -f "${R_PWFILE}" -d ${P_R_SERVERDIR} | sed -n 's/^ *uri: \(.*Builtin%20Object%20Token.*\)/\1/p'`

  CU_ACTION="List keys in NSS Certificate DB"
  certu -K -f "${R_PWFILE}" -d ${P_R_SERVERDIR} -h ${CERTIFICATE_DB_URI}

  # This token shouldn't have any keys
  CU_ACTION="List keys in NSS Builtin Objects"
  RETEXPECTED=255
  certu -K -f "${R_PWFILE}" -d ${P_R_SERVERDIR} -h ${BUILTIN_OBJECTS_URI}
  RETEXPECTED=0
}

check_sign_algo()
{
  certu -L -n "$CERTNAME" -d "${PROFILEDIR}" -f "${R_PWFILE}" | \
      sed -n '/^ *Data:/,/^$/{
/^        Signature Algorithm/,/^ *Salt length/s/^        //p
}' > ${TMP}/signalgo.txt

  diff ${TMP}/signalgo.exp ${TMP}/signalgo.txt
  RET=$?
  if [ "$RET" -ne 0 ]; then
      CERTFAILED=$RET
      html_failed "${CU_ACTION} ($RET) "
      cert_log "ERROR: ${CU_ACTION} failed $RET"
  else
      html_passed "${CU_ACTION}"
  fi
}

cert_test_rsapss()
{
  TEMPFILES="$TEMPFILES ${TMP}/signalgo.exp ${TMP}/signalgo.txt"

  cert_init_cert "${RSAPSSDIR}" "RSA-PSS Test Cert" 1000 "${D_RSAPSS}"

  CU_ACTION="Initialize Cert DB"
  certu -N -d "${PROFILEDIR}" -f "${R_PWFILE}" 2>&1

  CU_ACTION="Import RSA CA Cert"
  certu -A -n "TestCA" -t "C,," -d "${PROFILEDIR}" -f "${R_PWFILE}" \
        -i "${R_CADIR}/TestCA.ca.cert" 2>&1

  CU_ACTION="Import RSA-PSS CA Cert"
  certu -A -n "TestCA-rsa-pss" -t "C,," -d "${PROFILEDIR}" -f "${R_PWFILE}" \
        -i "${R_CADIR}/TestCA-rsa-pss.ca.cert" 2>&1

  CU_ACTION="Verify RSA-PSS CA Cert"
  certu -V -u L -e -n "TestCA-rsa-pss" -d "${PROFILEDIR}" -f "${R_PWFILE}"

  CU_ACTION="Import RSA-PSS CA Cert (SHA1)"
  certu -A -n "TestCA-rsa-pss-sha1" -t "C,," -d "${PROFILEDIR}" -f "${R_PWFILE}" \
        -i "${R_CADIR}/TestCA-rsa-pss-sha1.ca.cert" 2>&1

  CU_ACTION="Import Bogus RSA-PSS CA Cert (invalid trailerField)"
  certu -A -n "TestCA-bogus-rsa-pss1" -t "C,," -d "${PROFILEDIR}" -f "${R_PWFILE}" \
        -i "${QADIR}/cert/TestCA-bogus-rsa-pss1.crt" 2>&1
  RETEXPECTED=255
  certu -V -b 1712101010Z -n TestCA-bogus-rsa-pss1 -u L -e -d "${PROFILEDIR}" -f "${R_PWFILE}" 2>&1
  RETEXPECTED=0

  CU_ACTION="Import Bogus RSA-PSS CA Cert (invalid hashAlg)"
  certu -A -n "TestCA-bogus-rsa-pss2" -t "C,," -d "${PROFILEDIR}" -f "${R_PWFILE}" \
        -i "${QADIR}/cert/TestCA-bogus-rsa-pss2.crt" 2>&1
  RETEXPECTED=255
  certu -V -b 1712101010Z -n TestCA-bogus-rsa-pss2 -u L -e -d "${PROFILEDIR}" -f "${R_PWFILE}" 2>&1
  RETEXPECTED=0

  CERTSERIAL=200

  # Subject certificate: RSA
  # Issuer certificate: RSA
  # Signature: RSA-PSS (explicit, with --pss-sign)
  CERTNAME="TestUser-rsa-pss1"

  CU_ACTION="Generate Cert Request for $CERTNAME"
  CU_SUBJECT="CN=$CERTNAME, E=${CERTNAME}@example.com, O=BOGUS NSS, L=Mountain View, ST=California, C=US"
  certu -R -d "${PROFILEDIR}" -f "${R_PWFILE}" -z "${R_NOISE_FILE}" -o req  2>&1

  CU_ACTION="Sign ${CERTNAME}'s Request"
  certu -C -c "TestCA" --pss-sign -m "${CERTSERIAL}" -v 60 -d "${P_R_CADIR}" \
        -i req -o "${CERTNAME}.cert" -f "${R_PWFILE}" "$1" 2>&1

  CU_ACTION="Import $CERTNAME's Cert"
  certu -A -n "$CERTNAME" -t ",," -d "${PROFILEDIR}" -f "${R_PWFILE}" \
        -i "${CERTNAME}.cert" 2>&1

  CU_ACTION="Verify $CERTNAME's Cert"
  certu -V -u V -e -n "$CERTNAME" -d "${PROFILEDIR}" -f "${R_PWFILE}"
  cat > ${TMP}/signalgo.exp <<EOF
Signature Algorithm: PKCS #1 RSA-PSS Signature
    Parameters:
        Hash algorithm: SHA-256
        Mask algorithm: PKCS #1 MGF1 Mask Generation Function
        Mask hash algorithm: SHA-256
        Salt length: 32 (0x20)
EOF
  check_sign_algo

  CERTSERIAL=`expr $CERTSERIAL + 1`

  # Subject certificate: RSA
  # Issuer certificate: RSA
  # Signature: RSA-PSS (explict, with --pss-sign -Z SHA512)
  CERTNAME="TestUser-rsa-pss2"

  CU_ACTION="Generate Cert Request for $CERTNAME"
  CU_SUBJECT="CN=$CERTNAME, E=${CERTNAME}@example.com, O=BOGUS NSS, L=Mountain View, ST=California, C=US"
  certu -R -d "${PROFILEDIR}" -f "${R_PWFILE}" -z "${R_NOISE_FILE}" -o req  2>&1

  CU_ACTION="Sign ${CERTNAME}'s Request"
  certu -C -c "TestCA" --pss-sign -Z SHA512 -m "${CERTSERIAL}" -v 60 -d "${P_R_CADIR}" \
        -i req -o "${CERTNAME}.cert" -f "${R_PWFILE}" "$1" 2>&1

  CU_ACTION="Import $CERTNAME's Cert"
  certu -A -n "$CERTNAME" -t ",," -d "${PROFILEDIR}" -f "${R_PWFILE}" \
        -i "${CERTNAME}.cert" 2>&1

  CU_ACTION="Verify $CERTNAME's Cert"
  certu -V -u V -e -n "$CERTNAME" -d "${PROFILEDIR}" -f "${R_PWFILE}"
  cat > ${TMP}/signalgo.exp <<EOF
Signature Algorithm: PKCS #1 RSA-PSS Signature
    Parameters:
        Hash algorithm: SHA-512
        Mask algorithm: PKCS #1 MGF1 Mask Generation Function
        Mask hash algorithm: SHA-512
        Salt length: 64 (0x40)
EOF
  check_sign_algo

  CERTSERIAL=`expr $CERTSERIAL + 1`

  # Subject certificate: RSA
  # Issuer certificate: RSA-PSS
  # Signature: RSA-PSS
  CERTNAME="TestUser-rsa-pss3"

  CU_ACTION="Generate Cert Request for $CERTNAME"
  CU_SUBJECT="CN=$CERTNAME, E=${CERTNAME}@example.com, O=BOGUS NSS, L=Mountain View, ST=California, C=US"
  certu -R -d "${PROFILEDIR}" -f "${R_PWFILE}" -z "${R_NOISE_FILE}" -o req  2>&1

  CU_ACTION="Sign ${CERTNAME}'s Request"
  certu -C -c "TestCA-rsa-pss" -m "${CERTSERIAL}" -v 60 -d "${P_R_CADIR}" \
        -i req -o "${CERTNAME}.cert" -f "${R_PWFILE}" "$1" 2>&1

  CU_ACTION="Import $CERTNAME's Cert"
  certu -A -n "$CERTNAME" -t ",," -d "${PROFILEDIR}" -f "${R_PWFILE}" \
        -i "${CERTNAME}.cert" 2>&1

  CU_ACTION="Verify $CERTNAME's Cert"
  certu -V -u V -e -n "$CERTNAME" -d "${PROFILEDIR}" -f "${R_PWFILE}"
  cat > ${TMP}/signalgo.exp <<EOF
Signature Algorithm: PKCS #1 RSA-PSS Signature
    Parameters:
        Hash algorithm: SHA-256
        Mask algorithm: PKCS #1 MGF1 Mask Generation Function
        Mask hash algorithm: SHA-256
        Salt length: 32 (0x20)
EOF
  check_sign_algo

  CERTSERIAL=`expr $CERTSERIAL + 1`

  # Subject certificate: RSA-PSS
  # Issuer certificate: RSA
  # Signature: RSA-PSS (explicit, with --pss-sign)
  CERTNAME="TestUser-rsa-pss4"

  CU_ACTION="Generate Cert Request for $CERTNAME"
  CU_SUBJECT="CN=$CERTNAME, E=${CERTNAME}@example.com, O=BOGUS NSS, L=Mountain View, ST=California, C=US"
  certu -R -d "${PROFILEDIR}" -f "${R_PWFILE}" -z "${R_NOISE_FILE}" --pss -o req  2>&1

  CU_ACTION="Sign ${CERTNAME}'s Request"
  certu -C -c "TestCA" --pss-sign -m "${CERTSERIAL}" -v 60 -d "${P_R_CADIR}" \
        -i req -o "${CERTNAME}.cert" -f "${R_PWFILE}" "$1" 2>&1

  CU_ACTION="Import $CERTNAME's Cert"
  certu -A -n "$CERTNAME" -t ",," -d "${PROFILEDIR}" -f "${R_PWFILE}" \
        -i "${CERTNAME}.cert" 2>&1

  CU_ACTION="Verify $CERTNAME's Cert"
  certu -V -u V -e -n "$CERTNAME" -d "${PROFILEDIR}" -f "${R_PWFILE}"
  cat > ${TMP}/signalgo.exp <<EOF
Signature Algorithm: PKCS #1 RSA-PSS Signature
    Parameters:
        Hash algorithm: SHA-256
        Mask algorithm: PKCS #1 MGF1 Mask Generation Function
        Mask hash algorithm: SHA-256
        Salt length: 32 (0x20)
EOF
  check_sign_algo

  CERTSERIAL=`expr $CERTSERIAL + 1`

  # Subject certificate: RSA-PSS
  # Issuer certificate: RSA-PSS
  # Signature: RSA-PSS (explicit, with --pss-sign)
  CERTNAME="TestUser-rsa-pss5"

  CU_ACTION="Generate Cert Request for $CERTNAME"
  CU_SUBJECT="CN=$CERTNAME, E=${CERTNAME}@example.com, O=BOGUS NSS, L=Mountain View, ST=California, C=US"
  certu -R -d "${PROFILEDIR}" -f "${R_PWFILE}" -z "${R_NOISE_FILE}" --pss -o req  2>&1

  CU_ACTION="Sign ${CERTNAME}'s Request"
  certu -C -c "TestCA-rsa-pss" --pss-sign -m "${CERTSERIAL}" -v 60 -d "${P_R_CADIR}" \
        -i req -o "${CERTNAME}.cert" -f "${R_PWFILE}" "$1" 2>&1

  CU_ACTION="Import $CERTNAME's Cert"
  certu -A -n "$CERTNAME" -t ",," -d "${PROFILEDIR}" -f "${R_PWFILE}" \
        -i "${CERTNAME}.cert" 2>&1

  CU_ACTION="Verify $CERTNAME's Cert"
  certu -V -u V -e -n "$CERTNAME" -d "${PROFILEDIR}" -f "${R_PWFILE}"
  cat > ${TMP}/signalgo.exp <<EOF
Signature Algorithm: PKCS #1 RSA-PSS Signature
    Parameters:
        Hash algorithm: SHA-256
        Mask algorithm: PKCS #1 MGF1 Mask Generation Function
        Mask hash algorithm: SHA-256
        Salt length: 32 (0x20)
EOF
  check_sign_algo

  CERTSERIAL=`expr $CERTSERIAL + 1`

  # Subject certificate: RSA-PSS
  # Issuer certificate: RSA-PSS
  # Signature: RSA-PSS (implicit, without --pss-sign)
  CERTNAME="TestUser-rsa-pss6"

  CU_ACTION="Generate Cert Request for $CERTNAME"
  CU_SUBJECT="CN=$CERTNAME, E=${CERTNAME}@example.com, O=BOGUS NSS, L=Mountain View, ST=California, C=US"
  certu -R -d "${PROFILEDIR}" -f "${R_PWFILE}" -z "${R_NOISE_FILE}" --pss -o req  2>&1

  CU_ACTION="Sign ${CERTNAME}'s Request"
  # Sign without --pss-sign nor -Z option
  certu -C -c "TestCA-rsa-pss" -m "${CERTSERIAL}" -v 60 -d "${P_R_CADIR}" \
        -i req -o "${CERTNAME}.cert" -f "${R_PWFILE}" "$1" 2>&1

  CU_ACTION="Import $CERTNAME's Cert"
  certu -A -n "$CERTNAME" -t ",," -d "${PROFILEDIR}" -f "${R_PWFILE}" \
        -i "${CERTNAME}.cert" 2>&1

  CU_ACTION="Verify $CERTNAME's Cert"
  certu -V -u V -e -n "$CERTNAME" -d "${PROFILEDIR}" -f "${R_PWFILE}"
  cat > ${TMP}/signalgo.exp <<EOF
Signature Algorithm: PKCS #1 RSA-PSS Signature
    Parameters:
        Hash algorithm: SHA-256
        Mask algorithm: PKCS #1 MGF1 Mask Generation Function
        Mask hash algorithm: SHA-256
        Salt length: 32 (0x20)
EOF
  check_sign_algo

  CERTSERIAL=`expr $CERTSERIAL + 1`

  # Subject certificate: RSA-PSS
  # Issuer certificate: RSA-PSS
  # Signature: RSA-PSS (with conflicting hash algorithm)
  CERTNAME="TestUser-rsa-pss7"

  CU_ACTION="Generate Cert Request for $CERTNAME"
  CU_SUBJECT="CN=$CERTNAME, E=${CERTNAME}@example.com, O=BOGUS NSS, L=Mountain View, ST=California, C=US"
  certu -R -d "${PROFILEDIR}" -f "${R_PWFILE}" -z "${R_NOISE_FILE}" --pss -o req  2>&1

  CU_ACTION="Sign ${CERTNAME}'s Request"
  RETEXPECTED=255
  certu -C -c "TestCA-rsa-pss" --pss-sign -Z SHA512 -m "${CERTSERIAL}" -v 60 -d "${P_R_CADIR}" \
        -i req -o "${CERTNAME}.cert" -f "${R_PWFILE}" "$1" 2>&1
  RETEXPECTED=0

  CERTSERIAL=`expr $CERTSERIAL + 1`

  # Subject certificate: RSA-PSS
  # Issuer certificate: RSA-PSS
  # Signature: RSA-PSS (with compatible hash algorithm)
  CERTNAME="TestUser-rsa-pss8"

  CU_ACTION="Generate Cert Request for $CERTNAME"
  CU_SUBJECT="CN=$CERTNAME, E=${CERTNAME}@example.com, O=BOGUS NSS, L=Mountain View, ST=California, C=US"
  certu -R -d "${PROFILEDIR}" -f "${R_PWFILE}" -z "${R_NOISE_FILE}" --pss -o req  2>&1

  CU_ACTION="Sign ${CERTNAME}'s Request"
  certu -C -c "TestCA-rsa-pss" --pss-sign -Z SHA256 -m "${CERTSERIAL}" -v 60 -d "${P_R_CADIR}" \
        -i req -o "${CERTNAME}.cert" -f "${R_PWFILE}" "$1" 2>&1

  CU_ACTION="Import $CERTNAME's Cert"
  certu -A -n "$CERTNAME" -t ",," -d "${PROFILEDIR}" -f "${R_PWFILE}" \
        -i "${CERTNAME}.cert" 2>&1

  CU_ACTION="Verify $CERTNAME's Cert"
  certu -V -u V -e -n "$CERTNAME" -d "${PROFILEDIR}" -f "${R_PWFILE}"
  cat > ${TMP}/signalgo.exp <<EOF
Signature Algorithm: PKCS #1 RSA-PSS Signature
    Parameters:
        Hash algorithm: SHA-256
        Mask algorithm: PKCS #1 MGF1 Mask Generation Function
        Mask hash algorithm: SHA-256
        Salt length: 32 (0x20)
EOF
  check_sign_algo

  CERTSERIAL=`expr $CERTSERIAL + 1`

  # Subject certificate: RSA
  # Issuer certificate: RSA
  # Signature: RSA-PSS (explict, with --pss-sign -Z SHA1)
  CERTNAME="TestUser-rsa-pss9"

  CU_ACTION="Generate Cert Request for $CERTNAME"
  CU_SUBJECT="CN=$CERTNAME, E=${CERTNAME}@example.com, O=BOGUS NSS, L=Mountain View, ST=California, C=US"
  certu -R -d "${PROFILEDIR}" -f "${R_PWFILE}" -z "${R_NOISE_FILE}" -o req  2>&1

  CU_ACTION="Sign ${CERTNAME}'s Request"
  certu -C -c "TestCA" --pss-sign -Z SHA1 -m "${CERTSERIAL}" -v 60 -d "${P_R_CADIR}" \
        -i req -o "${CERTNAME}.cert" -f "${R_PWFILE}" "$1" 2>&1

  CU_ACTION="Import $CERTNAME's Cert"
  certu -A -n "$CERTNAME" -t ",," -d "${PROFILEDIR}" -f "${R_PWFILE}" \
        -i "${CERTNAME}.cert" 2>&1

  CU_ACTION="Verify $CERTNAME's Cert"
  certu -V -u V -e -n "$CERTNAME" -d "${PROFILEDIR}" -f "${R_PWFILE}"
  cat > ${TMP}/signalgo.exp <<EOF
Signature Algorithm: PKCS #1 RSA-PSS Signature
    Parameters:
        Hash algorithm: default, SHA-1
        Mask algorithm: default, MGF1
        Mask hash algorithm: default, SHA-1
        Salt length: default, 20 (0x14)
EOF
  check_sign_algo

  CERTSERIAL=`expr $CERTSERIAL + 1`

  # Subject certificate: RSA-PSS
  # Issuer certificate: RSA-PSS
  # Signature: RSA-PSS (implicit, without --pss-sign, default parameters)
  CERTNAME="TestUser-rsa-pss10"

  CU_ACTION="Generate Cert Request for $CERTNAME"
  CU_SUBJECT="CN=$CERTNAME, E=${CERTNAME}@example.com, O=BOGUS NSS, L=Mountain View, ST=California, C=US"
  certu -R -d "${PROFILEDIR}" -f "${R_PWFILE}" -z "${R_NOISE_FILE}" -o req  2>&1

  CU_ACTION="Sign ${CERTNAME}'s Request"
  # Sign without --pss-sign nor -Z option
  certu -C -c "TestCA-rsa-pss-sha1" -m "${CERTSERIAL}" -v 60 -d "${P_R_CADIR}" \
        -i req -o "${CERTNAME}.cert" -f "${R_PWFILE}" "$1" 2>&1

  CU_ACTION="Import $CERTNAME's Cert"
  certu -A -n "$CERTNAME" -t ",," -d "${PROFILEDIR}" -f "${R_PWFILE}" \
        -i "${CERTNAME}.cert" 2>&1

  CU_ACTION="Verify $CERTNAME's Cert"
  certu -V -u V -e -n "$CERTNAME" -d "${PROFILEDIR}" -f "${R_PWFILE}"
  cat > ${TMP}/signalgo.exp <<EOF
Signature Algorithm: PKCS #1 RSA-PSS Signature
    Parameters:
        Hash algorithm: default, SHA-1
        Mask algorithm: default, MGF1
        Mask hash algorithm: default, SHA-1
        Salt length: default, 20 (0x14)
EOF
  check_sign_algo

  CERTSERIAL=`expr $CERTSERIAL + 1`

  # Subject certificate: RSA-PSS
  # Issuer certificate: RSA-PSS
  # Signature: RSA-PSS (with conflicting hash algorithm, default parameters)
  CERTNAME="TestUser-rsa-pss11"

  CU_ACTION="Generate Cert Request for $CERTNAME"
  CU_SUBJECT="CN=$CERTNAME, E=${CERTNAME}@example.com, O=BOGUS NSS, L=Mountain View, ST=California, C=US"
  certu -R -d "${PROFILEDIR}" -f "${R_PWFILE}" -z "${R_NOISE_FILE}" --pss -o req  2>&1

  CU_ACTION="Sign ${CERTNAME}'s Request"
  RETEXPECTED=255
  certu -C -c "TestCA-rsa-pss-sha1" --pss-sign -Z SHA256 -m "${CERTSERIAL}" -v 60 -d "${P_R_CADIR}" \
        -i req -o "${CERTNAME}.cert" -f "${R_PWFILE}" "$1" 2>&1
  RETEXPECTED=0
}

cert_test_orphan_key_delete()
{
  CU_ACTION="Create orphan key in serverdir"
  certu -G -k ec -q nistp256 -f "${R_PWFILE}" -z ${R_NOISE_FILE} -d ${PROFILEDIR}
  # Let's get the key ID of the first orphan key.
  # The output of certutil -K (list keys) isn't well formatted.
  # The initial <key-number> part may or may not contain white space, which
  # makes the use of awk to filter the column unreliable.
  # To fix that, we remove the initial <number> field using sed, then select the
  # column that contains the key ID.
  ORPHAN=`${BINDIR}/certutil -d ${PROFILEDIR} -K -f ${R_PWFILE} | \
          sed 's/^<.*>//g' | grep -w orphan | head -1 | awk '{print $2}'`
  CU_ACTION="Delete orphan key"
  certu -F -f "${R_PWFILE}" -k ${ORPHAN} -d ${PROFILEDIR}
  # Ensure that the key is removed
  certu -K -f "${R_PWFILE}" -d ${PROFILEDIR} | grep ${ORPHAN}
  RET=$?
  if [ "$RET" -eq 0 ]; then
    html_failed "Deleting orphan key ($RET)"
    cert_log "ERROR: Deleting orphan key failed $RET"
  fi
}

cert_test_orphan_key_reuse()
{
  CU_ACTION="Create orphan key in serverdir"
  certu -G -f "${R_PWFILE}" -z ${R_NOISE_FILE} -d ${PROFILEDIR}
  # Let's get the key ID of the first orphan key.
  # The output of certutil -K (list keys) isn't well formatted.
  # The initial <key-number> part may or may not contain white space, which
  # makes the use of awk to filter the column unreliable.
  # To fix that, we remove the initial <number> field using sed, then select the
  # column that contains the key ID.
  ORPHAN=`${BINDIR}/certutil -d ${PROFILEDIR} -K -f ${R_PWFILE} | \
          sed 's/^<.*>//g' | grep -w orphan | head -1 | awk '{print $2}'`
  CU_ACTION="Create cert request for orphan key"
  certu -R -f "${R_PWFILE}" -k ${ORPHAN} -s "CN=orphan" -d ${PROFILEDIR} \
        -o ${SERVERDIR}/orphan.req
  # Ensure that creating the request really works by listing it, and check
  # if listing was successful.
  ${BINDIR}/pp -t certificate-request -i ${SERVERDIR}/orphan.req
  RET=$?
  if [ "$RET" -ne 0 ]; then
    html_failed "Listing cert request for orphan key ($RET)"
    cert_log "ERROR: Listing cert request for orphan key failed $RET"
  fi
}

cert_test_rsapss_policy()
{
  CERTSERIAL=`expr $CERTSERIAL + 1`

  CERTNAME="TestUser-rsa-pss-policy"

  # Subject certificate: RSA-PSS
  # Issuer certificate: RSA
  # Signature: RSA-PSS (explicit, with --pss-sign and -Z SHA1)
  CU_ACTION="Generate Cert Request for $CERTNAME"
  CU_SUBJECT="CN=$CERTNAME, E=${CERTNAME}@example.com, O=BOGUS NSS, L=Mountain View, ST=California, C=US"
  certu -R -d "${PROFILEDIR}" -f "${R_PWFILE}" -z "${R_NOISE_FILE}" --pss -o req  2>&1

  CU_ACTION="Sign ${CERTNAME}'s Request"
  certu -C -c "TestCA" --pss-sign -Z SHA1 -m "${CERTSERIAL}" -v 60 -d "${P_R_CADIR}" \
        -i req -o "${CERTNAME}.cert" -f "${R_PWFILE}" "$1" 2>&1

  CU_ACTION="Import $CERTNAME's Cert"
  certu -A -n "$CERTNAME" -t ",," -d "${PROFILEDIR}" -f "${R_PWFILE}" \
        -i "${CERTNAME}.cert" 2>&1

  CU_ACTION="Verify $CERTNAME's Cert"
  certu -V -n "TestUser-rsa-pss-policy" -u V -V -e -d "${PROFILEDIR}" -f "${R_PWFILE}"

  CU_ACTION="Verify $CERTNAME's Cert with Policy"
  cp ${PROFILEDIR}/pkcs11.txt pkcs11.txt.orig
  cat >> ${PROFILEDIR}/pkcs11.txt << ++EOF++
library=
name=Policy
config="disallow=SHA1"
++EOF++
  RETEXPECTED=255
  certu -V -n "TestUser-rsa-pss-policy" -u V -V -e -d "${PROFILEDIR}" -f "${R_PWFILE}"
  RETEXPECTED=0
  cp pkcs11.txt.orig ${PROFILEDIR}/pkcs11.txt
}

############################## cert_cleanup ############################
# local shell function to finish this script (no exit since it might be
# sourced)
########################################################################
cert_cleanup()
{
  cert_log "$SCRIPTNAME: finished $SCRIPTNAME"
  html "</TABLE><BR>"
  cd ${QADIR}
  . common/cleanup.sh
}

CERTCACHE=${TESTDIR}/${HOST}.${TEST_MODE}.cert.cache.tar.gz

cert_make_cache()
{
  if [ -n "${NSS_USE_CERT_CACHE}" ] ; then
    pushd ${HOSTDIR}
    tar czf "${CERTCACHE}" .
    popd
  fi
}

cert_use_cache()
{
  if [ -n "${NSS_USE_CERT_CACHE}" ] ; then
    pushd ${HOSTDIR}
    if [ -r "${CERTCACHE}" ]; then
      tar xzf "${CERTCACHE}"
      return 1;
    fi
    popd
  fi

  rm "${CERTCACHE}"
  return 0;
}

################## main #################################################

cert_use_cache
USING_CACHE=$?
if [[ $USING_CACHE -eq 1 ]]; then
  return 0;
fi

cert_init
cert_all_CA
cert_test_implicit_db_init
cert_extended_ssl
cert_ssl
cert_test_orphan_key_delete
cert_test_orphan_key_reuse
cert_smime_client
IS_FIPS_DISABLED=`certutil --build-flags |grep -cw NSS_FIPS_DISABLED`
if [ $IS_FIPS_DISABLED -ne 0 ]; then
  cert_rsa_exponent_nonfips
else
  cert_fips
fi
cert_eccurves
cert_extensions
cert_san_and_generic_extensions
cert_test_password
cert_test_distrust
cert_test_ocspresp
cert_test_rsapss
if using_sql ; then
  cert_test_rsapss_policy
fi
cert_test_token_uri

if [ -z "$NSS_TEST_DISABLE_CRL" ] ; then
    cert_crl_ssl
else
    echo "$SCRIPTNAME: Skipping CRL Tests"
fi

if [ -n "$DO_DIST_ST" -a "$DO_DIST_ST" = "TRUE" ] ; then
    cert_stresscerts
fi

cert_iopr_setup

cert_cleanup
cert_make_cache
