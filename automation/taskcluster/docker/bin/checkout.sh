#!/usr/bin/env bash

set -v -e -x

if [ $(id -u) = 0 ]; then
    # Drop privileges by re-running this script.
    exec su worker $0
fi

# Clone NSS.
hg clone -r $NSS_HEAD_REVISION $NSS_HEAD_REPOSITORY nss
