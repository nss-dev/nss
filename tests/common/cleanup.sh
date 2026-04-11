#!/bin/bash
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


if [ -z "${CLEANUP}" -o "${CLEANUP}" = "${SCRIPTNAME}" ]; then
    if [ -z "${BUILD_OPT}" ] && [ "${OBJDIR}" == "Debug"  ]; then
        BUILD_OPT=0;
    elif [ -z "${BUILD_OPT}" ] && [ "${OBJDIR}" == "Release" ]; then
        BUILD_OPT=1;
    fi

    echo
    echo "SUMMARY:"
    echo "========"
    echo "NSS variables:"
    echo "--------------"
    echo "HOST=${HOST}"
    echo "DOMSUF=${DOMSUF}"
    echo "BUILD_OPT=${BUILD_OPT}"
    if [ "${OS_ARCH}" = "Linux" ]; then
        echo "USE_X32=${USE_X32}"
    fi
    echo "USE_64=${USE_64}"
    echo "NSS_CYCLES=\"${NSS_CYCLES}\""
    echo "NSS_TESTS=\"${NSS_TESTS}\""
    echo "NSS_SSL_TESTS=\"${NSS_SSL_TESTS}\""
    echo "NSS_SSL_RUN=\"${NSS_SSL_RUN}\""
    echo "NSS_AIA_PATH=${NSS_AIA_PATH}"
    echo "NSS_AIA_HTTP=${NSS_AIA_HTTP}"
    echo "NSS_AIA_OCSP=${NSS_AIA_OCSP}"
    echo "IOPR_HOSTADDR_LIST=${IOPR_HOSTADDR_LIST}"
    echo "PKITS_DATA=${PKITS_DATA}"
    echo "NSS_DISABLE_HW_AES=${NSS_DISABLE_HW_AES}"
    echo "NSS_DISABLE_HW_SHA1=${NSS_DISABLE_HW_SHA1}"
    echo "NSS_DISABLE_HW_SHA2=${NSS_DISABLE_HW_SHA2}"
    echo "NSS_DISABLE_PCLMUL=${NSS_DISABLE_PCLMUL}"
    echo "NSS_DISABLE_AVX=${NSS_DISABLE_AVX}"
    echo "NSS_DISABLE_ARM_NEON=${NSS_DISABLE_ARM_NEON}"
    echo "NSS_DISABLE_SSSE3=${NSS_DISABLE_SSSE3}"
    echo
    printf "${COLOR_BOLD}Tests summary:${COLOR_RESET}\n"
    echo "--------------"
    LINES_CNT=$(grep -c ">Passed<" ${RESULTS} 2>/dev/null | sed s/\ *//)
    echo "Passed:             ${LINES_CNT}"
    FAILED_CNT=$(grep -c ">Failed<" ${RESULTS} 2>/dev/null | sed s/\ *//)
    echo "Failed:             ${FAILED_CNT}"
    CORE_CNT=$(grep -c ">Failed Core<" ${RESULTS} 2>/dev/null | sed s/\ *//)
    echo "Failed with core:   ${CORE_CNT}"
    ASAN_CNT=$(grep -c "SUMMARY: AddressSanitizer" $LOGFILE 2>/dev/null | sed s/\ *//)
    echo "ASan failures:      ${ASAN_CNT}"
    LINES_CNT=$(grep -c ">Unknown<" ${RESULTS} 2>/dev/null | sed s/\ *//)
    echo "Unknown status:     ${LINES_CNT}"
    if [ ${LINES_CNT} -gt 0 ]; then
        echo "TinderboxPrint:Unknown: ${LINES_CNT}"
    fi
    echo

    # List which tests failed, if any.
    if [ -s "${FAILED_TESTS_FILE}" ]; then
        printf "${COLOR_RED}${COLOR_BOLD}Failed tests:${COLOR_RESET}\n"
        while IFS= read -r ft; do
            printf "  ${COLOR_RED}- ${ft}${COLOR_RESET}\n"
        done < "${FAILED_TESTS_FILE}"
        echo
    fi

    html "END_OF_TEST<BR>"
    html "</BODY></HTML>"
    rm -f ${TEMPFILES} 2>/dev/null
    if [ ${FAILED_CNT} -gt 0 ] || [ ${ASAN_CNT} -gt 0 ] ||
       ([ ${CORE_CNT} -gt 0 ] && [ -n "${BUILD_OPT}" ] && [ ${BUILD_OPT} -eq 1 ]); then
        exit 1
    fi

fi
