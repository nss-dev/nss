#!/usr/bin/env bash

set -v -e -x

if [ $(id -u) -eq 0 ]; then
    # Drop privileges by re-running this script.
    exec su worker $0 "$@"
fi

# Apply clang-format 3.8 on the provided folder and verify that this doesn't change any file.
# If any file differs after formatting, the script eventually exits with 1.
# Any differences between formatted and unformatted files is printed to stdout to give a hint what's wrong.

# Includes a default set of directories.

if [ $# -gt 0 ]; then
    dirs=("$@")
else
    top=$(dirname $0)/../../..
    dirs=( \
         "$top/lib/ssl" \
         "$top/lib/softoken" \
    )
fi

STATUS=0
for dir in "${dirs[@]}"; do
    for i in $(find "$dir" -type f \( -name '*.[ch]' -o -name '*.cc' \) -print); do
        if ! clang-format "$i" | diff -Naur "$i" -; then
            echo "Sorry, $i is not formatted properly. Please use clang-format 3.8 on your patch before landing."
            STATUS=1
        fi
    done
done
exit $STATUS
