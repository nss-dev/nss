#!/usr/bin/env bash

set -v -e -x

# Usage: hg_clone repo dir [revision=@]
hg_clone() {
    repo=$1
    dir=$2
    rev=${3:-@}
    for i in 0 2 5; do
        sleep $i
        hg clone -r "$rev" "$repo" "$dir" && return
        rm -rf "$dir"
    done
    exit 1
}

export SSL_CERT_FILE=/c/mozilla-build/python3/Lib/site-packages/certifi/cacert.pem

# Fetch the named packages from releng.manifest, or all of them if none are
# named.
tooltool_fetch() {
    /c/mozilla-build/python3/python3.exe /c/mozilla-build/tooltool.py -c /c/mozilla-build/tooltool_cache --url ${TASKCLUSTER_PROXY_URL}/tooltool.mozilla-releng.net/ --overwrite -m $(dirname $0)/releng.manifest fetch "$@"
}

# Echo the highest-versioned entry in directory $1, which must be non-empty.
latest_subdir() {
    local entry
    entry=$(cd "$1" && ls -1 | sort -V | tail -1)
    if [ -z "$entry" ]; then
        echo "setup.sh: $1 is empty" 1>&2
        return 1
    fi
    echo "$entry"
}

# Echo the highest-versioned directory under $1 whose full path matches the
# find(1) -path pattern $2. Used where a component carries a version of its own
# that need not match the toolset's.
find_dir() {
    local match
    match=$(find "$1" -type d -path "$2" | sort -V | tail -1)
    if [ -z "$match" ]; then
        echo "setup.sh: no directory matching $2 under $1" 1>&2
        return 1
    fi
    echo "$match"
}

# The tooltool package is VS 2017 15.4.2 with SDK 10.0.15063, laid out as
# VC/bin/Host<host>/<target> and SDK/{Include,lib}/<version>.
setup_vs2017() {
    export VSPATH="${PWD}/vs2017_15.4.2"
    local UCRTVersion="10.0.15063.0"

    export WINDOWSSDKDIR="${VSPATH}/SDK"
    export VS90COMNTOOLS="${VSPATH}/VC"
    export WIN32_REDIST_DIR="${VSPATH}/VC/redist/${m}/Microsoft.VC141.CRT"
    export WIN_UCRT_REDIST_DIR="${VSPATH}/SDK/Redist/ucrt/DLLs/${m}"

    if [ "$m" == "x86" ]; then
        PATH="${VSPATH}/VC/bin/Hostx64/x64:${PATH}"
        PATH="${VSPATH}/VC/bin/Hostx64/x86:${PATH}"
    fi
    PATH="${VSPATH}/VC/bin/Host${m}/${m}:${PATH}"
    PATH="${WIN32_REDIST_DIR}:${PATH}"
    PATH="${WIN_UCRT_REDIST_DIR}:${PATH}"
    PATH="${VSPATH}/SDK/bin/${UCRTVersion}/x64:${PATH}"
    export PATH

    LIB="${LIB}:${VSPATH}/VC/lib/${m}"
    LIB="${LIB}:${VSPATH}/SDK/lib/${UCRTVersion}/ucrt/${m}"
    LIB="${LIB}:${VSPATH}/SDK/lib/${UCRTVersion}/um/${m}"
    export LIB

    INCLUDE="${INCLUDE}:${VSPATH}/VC/include"
    INCLUDE="${INCLUDE}:${VSPATH}/SDK/Include/${UCRTVersion}/ucrt"
    INCLUDE="${INCLUDE}:${VSPATH}/SDK/Include/${UCRTVersion}/shared"
    INCLUDE="${INCLUDE}:${VSPATH}/SDK/Include/${UCRTVersion}/um"
    export INCLUDE

    # gyp finds the toolchain by running vcvarsall.bat and reading the
    # environment back out. Everything is set up above already, so an empty
    # file is enough -- but it has to exist, under VC/Auxiliary/Build for VS
    # 2017 and later. gyp-next asks for an arm64 environment even when nothing
    # targets it, and its pre-2017 lookup knows only x86 and x64, so it must
    # not be told this is VS 2015.
    mkdir -p "${VSPATH}/VC/Auxiliary/Build"
    touch "${VSPATH}/VC/Auxiliary/Build/vcvarsall.bat"
    export GYP_MSVS_OVERRIDE_PATH="${VSPATH}"
    export GYP_MSVS_VERSION=2017
}

# ARM64 is not in the tooltool package -- ARM64 desktop tools only arrived in
# VS 15.9 with SDK 10.0.16299 -- so those tasks build against the Visual Studio
# layout gecko publishes: VS 2026 / MSVC 14.51 including the
# HostX64 -> TargetARM64 cross compiler, the Win11 SDK, and the ARM64 CRT
# redist.
#
# run-task's fetch-content has already downloaded it into MOZ_FETCHES_DIR by
# the time we get here; nss_taskgraph.transforms.build:add_vs_toolchain_fetch
# sets that up, and holds the index route and the
# queue:get-artifact:project/gecko/vs/* scope the private artifact needs.
setup_vs_gecko() {
    # fetch-content hands us a Windows path. cygpath makes it usable from MSYS
    # and leaves an already-POSIX value alone.
    local fetches
    fetches=$(cygpath -u "${MOZ_FETCHES_DIR}")
    export VSPATH="${fetches}/vs"
    # The component versions are discovered, not pinned, so that moving the
    # index route in add_vs_toolchain_fetch is the only change a Visual Studio
    # update needs. Assign before exporting: `export x=$(...)` would swallow
    # a failure.
    local vc sdkdir sdk
    vc=$(latest_subdir "${VSPATH}/VC/Tools/MSVC")
    vc="${VSPATH}/VC/Tools/MSVC/${vc}"
    sdkdir="${VSPATH}/Windows Kits/10"
    sdk=$(latest_subdir "${sdkdir}/Lib")

    export WINDOWSSDKDIR="${sdkdir}"
    # The redistributables are versioned independently of the toolset (the
    # VCRedistVersion / VCToolsVersion distinction), and the Microsoft.VCnnn
    # number tracks the toolset, so match on shape rather than spelling either
    # out. Microsoft.VC*.CRT deliberately does not match the neighbouring
    # debug_nonredist Microsoft.VC*.DebugCRT.
    WIN32_REDIST_DIR=$(find_dir "${VSPATH}/VC/Redist/MSVC" "*/${m}/Microsoft.VC*.CRT")
    WIN_UCRT_REDIST_DIR=$(find_dir "${sdkdir}/Redist" "*/ucrt/DLLs/${m}")
    export WIN32_REDIST_DIR WIN_UCRT_REDIST_DIR

    # cl.exe for a cross target is an x64 binary that loads its DLLs out of the
    # x64 host directory, so that has to be on PATH as well. The SDK tools
    # (rc.exe, mt.exe) likewise have to be the ones that run on the host, not
    # the ones built for the target.
    PATH="${vc}/bin/Hostx64/x64:${PATH}"
    PATH="${vc}/bin/Hostx64/${m}:${PATH}"
    PATH="${sdkdir}/bin/${sdk}/x64:${PATH}"
    PATH="${WIN32_REDIST_DIR}:${PATH}"
    PATH="${WIN_UCRT_REDIST_DIR}:${PATH}"
    export PATH

    LIB="${LIB}:${vc}/lib/${m}"
    LIB="${LIB}:${vc}/atlmfc/lib/${m}"
    LIB="${LIB}:${sdkdir}/Lib/${sdk}/ucrt/${m}"
    LIB="${LIB}:${sdkdir}/Lib/${sdk}/um/${m}"
    export LIB

    INCLUDE="${INCLUDE}:${vc}/include"
    INCLUDE="${INCLUDE}:${vc}/atlmfc/include"
    INCLUDE="${INCLUDE}:${sdkdir}/Include/${sdk}/ucrt"
    INCLUDE="${INCLUDE}:${sdkdir}/Include/${sdk}/shared"
    INCLUDE="${INCLUDE}:${sdkdir}/Include/${sdk}/um"
    INCLUDE="${INCLUDE}:${sdkdir}/Include/${sdk}/winrt"
    export INCLUDE

    # As above.
    mkdir -p "${VSPATH}/VC/Auxiliary/Build"
    touch "${VSPATH}/VC/Auxiliary/Build/vcvarsall.bat"
    export GYP_MSVS_OVERRIDE_PATH="${VSPATH}"
    export GYP_MSVS_VERSION=2026
}

# Only builds set $m; the certs and test tasks need no toolchain.
if [ -n "$m" ]; then
    if [ "$m" == "arm64" ]; then
        # The 300 MB Visual Studio package would go unused.
        tooltool_fetch ninja171.zip
        setup_vs_gecko
    else
        tooltool_fetch
        setup_vs2017
    fi
fi
