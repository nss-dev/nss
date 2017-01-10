#!/usr/bin/env bash
# This script builds NSS with gyp and ninja.
#
# This build system is still under development.  It does not yet support all
# the features or platforms that NSS supports.

set -e

source $(dirname $0)/coreconf/nspr.sh

# Usage info
show_help() {
cat << EOF

Usage: ${0##*/} [-hcv] [-j <n>] [--nspr] [--gyp|-g] [--opt|-o] [-m32]
                [--test] [--fuzz] [--pprof] [--scan-build[=output]]
                [--asan] [--ubsan] [--msan] [--sancov[=edge|bb|func|...]]

This script builds NSS with gyp and ninja.

This build system is still under development.  It does not yet support all
the features or platforms that NSS supports.

NSS build tool options:

    -h            display this help and exit
    -c            clean before build
    -v            verbose build
    -j <n>        run at most <n> concurrent jobs
    --nspr        force a rebuild of NSPR
    --gyp|-g      force a rerun of gyp
    --opt|-o      do an opt build
    -m32          do a 32-bit build on a 64-bit system
    --test        ignore map files and export everything we have
    --fuzz        enable fuzzing mode. this always enables test builds
    --pprof       build with gperftool support
    --scan-build  run the build with scan-build (scan-build has to be in the path)
                  --scan-build=/out/path sets the output path for scan-build
    --asan        do an asan build
    --ubsan       do an ubsan build
                  --ubsan=bool,shift,... sets specific UB sanitizers
    --msan        do an msan build
    --sancov      do sanitize coverage builds
                  --sancov=func sets coverage to function level for example
EOF
}

if [ -n "$CCC" ] && [ -z "$CXX" ]; then
    export CXX="$CCC"
fi

opt_build=0
build_64=0
clean=0
rebuild_gyp=0
rebuild_nspr=0
target=Debug
verbose=0
fuzz=0
ubsan_default=bool,signed-integer-overflow,shift,vptr
sancov_default=edge,indirect-calls,8bit-counters
cwd=$(cd $(dirname $0); pwd -P)

gyp_params=(--depth="$cwd" --generator-output=".")
nspr_params=()
ninja_params=()
scanbuild=()

# try to guess sensible defaults
arch=$(python "$cwd"/coreconf/detect_host_arch.py)
if [ "$arch" = "x64" -o "$arch" = "aarch64" ]; then
    build_64=1
fi

sancov_default()
{
    clang_version=$($CC --version | grep -oE 'clang version (3\.9\.|4\.)')
    if [ -z "$clang_version" ]; then
        echo "Need at least clang-3.9 (better 4.0) for sancov." 1>&2
        exit 1
    fi

    if [ "$clang_version" = "clang version 3.9." ]; then
        echo edge,indirect-calls,8bit-counters
    else
        echo trace-pc-guard
    fi
}

enable_fuzz()
{
    fuzz=1
    nspr_sanitizer asan
    nspr_sanitizer ubsan $ubsan_default
    nspr_sanitizer sancov $(sancov_default)
    gyp_params+=(-Duse_asan=1)
    gyp_params+=(-Duse_ubsan=$ubsan_default)
    gyp_params+=(-Duse_sancov=$(sancov_default))

    # Adding debug symbols even for opt builds.
    nspr_params+=(--enable-debug-symbols)
}

# parse command line arguments
while [ $# -gt 0 ]; do
    case $1 in
        -c) clean=1 ;;
        --gyp|-g) rebuild_gyp=1 ;;
        --nspr) nspr_clean; rebuild_nspr=1 ;;
        -j) ninja_params+=(-j "$2"); shift ;;
        -v) ninja_params+=(-v); verbose=1 ;;
        --test) gyp_params+=(-Dtest_build=1) ;;
        --fuzz) gyp_params+=(-Dtest_build=1 -Dfuzz=1); enable_fuzz ;;
        --scan-build) scanbuild=(scan-build) ;;
        --scan-build=?*) scanbuild=(scan-build -o "${1#*=}") ;;
        --opt|-o) opt_build=1 ;;
        -m32|--m32) build_64=0 ;;
        --asan) gyp_params+=(-Duse_asan=1); nspr_sanitizer asan ;;
        --ubsan) gyp_params+=(-Duse_ubsan=$ubsan_default); nspr_sanitizer ubsan $ubsan_default ;;
        --ubsan=?*) gyp_params+=(-Duse_ubsan="${1#*=}"); nspr_sanitizer ubsan "${1#*=}" ;;
        --sancov) gyp_params+=(-Duse_sancov=$(sancov_default)); nspr_sanitizer sancov $(sancov_default) ;;
        --sancov=?*) gyp_params+=(-Duse_sancov="${1#*=}"); nspr_sanitizer sancov "${1#*=}" ;;
        --pprof) gyp_params+=(-Duse_pprof=1) ;;
        --msan) gyp_params+=(-Duse_msan=1); nspr_sanitizer msan ;;
        *) show_help; exit ;;
    esac
    shift
done

if [ "$opt_build" = 1 ]; then
    target=Release
else
    target=Debug
fi
if [ "$build_64" = 1 ]; then
    nspr_params+=(--enable-64bit)
else
    gyp_params+=(-Dtarget_arch=ia32)
fi

# clone fuzzing stuff
if [ "$fuzz" = 1 ]; then
    [ $verbose = 0 ] && exec 3>/dev/null || exec 3>&1

    echo "fuzz [1/2] Cloning libFuzzer files ..."
    "$cwd"/fuzz/clone_libfuzzer.sh 1>&3 2>&3

    echo "fuzz [2/2] Cloning fuzzing corpus ..."
    "$cwd"/fuzz/clone_corpus.sh 1>&3 2>&3

    exec 3>&-
fi

# set paths
target_dir="$cwd"/out/$target
mkdir -p "$target_dir"
dist_dir="$cwd"/../dist
dist_dir=$(mkdir -p "$dist_dir"; cd "$dist_dir"; pwd -P)
gyp_params+=(-Dnss_dist_dir="$dist_dir")

# pass on CC and CCC to scanbuild
if [ "${#scanbuild[@]}" -gt 0 ]; then
    if [ -n "$CC" ]; then
       scanbuild+=(--use-cc="$CC")
    fi
    if [ -n "$CCC" ]; then
       scanbuild+=(--use-c++="$CCC")
    fi
fi

# This saves a canonical representation of arguments that we are passing to gyp
# or the NSPR build so that we can work out if a rebuild is needed.
normalize_config()
{
    conf="$1"
    mkdir -p $(dirname "$conf")
    shift
    echo CC="$CC" >"$conf"
    echo CCC="$CCC" >>"$conf"
    for i in "$@"; do echo $i; done | sort >>"$conf"
}

gyp_config="$cwd"/out/gyp_config
nspr_config="$cwd"/out/$target/nspr_config

# If we don't have a build directory make sure that we rebuild.
if [ ! -d "$target_dir" ]; then
    rebuild_nspr=1
    rebuild_gyp=1
fi

# -c = clean first
if [ "$clean" = 1 ]; then
    rebuild_gyp=1
    rebuild_nspr=1
    nspr_clean
    rm -rf "$cwd"/out
    rm -rf "$dist_dir"
    mkdir -p "$dist_dir"
fi

# save the chosen target
echo $target > "$dist_dir"/latest

normalize_config "$gyp_config".new "${gyp_params[@]}"
if ! diff -q "$gyp_config".new "$gyp_config" >/dev/null 2>&1; then
    rebuild_gyp=1
fi

normalize_config "$nspr_config".new "${nspr_params[@]}" \
                 nspr_cflags="$nspr_cflags" nspr_cxxflags="$nspr_cxxflags" \
                 nspr_ldflags="$nspr_ldflags"
if [ ! -d "$dist_dir"/$target ] || \
   ! diff -q "$nspr_config".new "$nspr_config" >/dev/null 2>&1; then
    rebuild_nspr=1
fi

if [ "$rebuild_nspr" = 1 ]; then
    nspr_build "${nspr_params[@]}"
    mv -f "$nspr_config".new "$nspr_config"
fi
if [ "$rebuild_gyp" = 1 ]; then
    if [ $verbose = 1 ]; then set -v -x; else echo gyp ...; fi

    # These extra arguments aren't used in determining whether to rebuild.
    obj_dir="$dist_dir"/$target
    gyp_params+=(-Dnss_dist_obj_dir=$obj_dir)
    gyp_params+=(-Dnspr_lib_dir=$obj_dir/lib)
    gyp_params+=(-Dnspr_include_dir=$obj_dir/include/nspr)

    "${scanbuild[@]}" gyp -f ninja "${gyp_params[@]}" "$cwd"/nss.gyp
    [ $verbose = 1 ] && set +v +x

    mv -f "$gyp_config".new "$gyp_config"
fi

# Run ninja.
if hash ninja 2>/dev/null; then
    ninja=ninja
elif which ninja-build 2>/dev/null; then
    ninja=ninja-build
else
    echo "Please install ninja" 1>&2
    exit 1
fi
"${scanbuild[@]}" $ninja -C "$target_dir" "${ninja_params[@]}"
