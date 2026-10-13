#!/usr/bin/env bash

# Source this for install_gyp. The macOS and Windows builds install gyp-next
# with it; the Linux builds get gyp from their docker images.

# Windows ARM64 needs at least 0.22.2, the first release with arm64 environment
# files.
GYP_NEXT_VERSION=0.22.2

# Usage: install_gyp venv_dir [extra_package...]
# Installs gyp-next and any extra packages into a new virtualenv and puts its
# scripts at the front of PATH, ahead of any other gyp.
install_gyp() {
    local venv=$1
    shift
    python3 -m venv "$venv"
    local bin
    bin="$(cd "$venv" && pwd)/bin"
    # Windows venvs put their scripts in Scripts instead.
    [ -d "$bin" ] || bin="${bin%/bin}/Scripts"
    "$bin/python" -m pip install --upgrade pip
    "$bin/python" -m pip install "gyp-next==${GYP_NEXT_VERSION}" "$@"
    export PATH="${bin}:${PATH}"
}
