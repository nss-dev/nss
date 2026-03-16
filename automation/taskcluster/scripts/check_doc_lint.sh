#!/bin/bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

set -e

warn_file=$(mktemp)
sphinx-build --keep-going -b html -w "${warn_file}" "${VCS_PATH}/nss/doc/rst" /tmp/sphinx-doc-out
sphinx_status=$?

failures=0
while IFS= read -r line; do
    if [[ "$line" =~ (WARNING|ERROR|CRITICAL) ]]; then
        if [[ "$line" =~ ^(.*):([0-9]+):[[:space:]]*(WARNING|ERROR|CRITICAL):[[:space:]]*(.*) ]]; then
            echo "TEST-UNEXPECTED-FAIL | check_doc_lint.sh | ${BASH_REMATCH[1]}:${BASH_REMATCH[2]} | ${BASH_REMATCH[4]}" >&2
        elif [[ "$line" =~ ^(.*):[[:space:]]*(WARNING|ERROR|CRITICAL):[[:space:]]*(.*) ]]; then
            echo "TEST-UNEXPECTED-FAIL | check_doc_lint.sh | ${BASH_REMATCH[1]} | ${BASH_REMATCH[3]}" >&2
        else
            echo "TEST-UNEXPECTED-FAIL | check_doc_lint.sh | ${line}" >&2
        fi
        failures=$((failures + 1))
    fi
done < "${warn_file}"

rm -f "${warn_file}"

echo "Failures: ${failures}"

if [ "${failures}" -gt 0 ] || [ "${sphinx_status}" -ne 0 ]; then
    exit 1
fi
