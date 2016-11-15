#!/bin/bash
# This script builds NSPR for NSS.
#
# This build system is still under development.  It does not yet support all
# the features or platforms that the regular NSPR build supports.

# variables
nspr_opt=()
nspr_cflags=
nspr_cxxflags=
nspr_ldflags=

nspr_sanitizer()
{
    nspr_cflags="$nspr_cflags $(python $cwd/coreconf/sanitizers.py $1 $2)"
    nspr_cxxflags="$nspr_cxxflags $(python $cwd/coreconf/sanitizers.py $1 $2)"
    nspr_ldflags="$nspr_ldflags $(python $cwd/coreconf/sanitizers.py $1 $2)"
}

build_nspr()
{
    mkdir -p "$cwd/../nspr/$target"
    cd "$cwd/../nspr/$target"
    if [ "$1" == 1 ]; then
        out=/dev/stdout
    else
        out=/dev/null
    fi
    echo "[1/3] configure NSPR ..."
    CFLAGS=$nspr_cflags CXXFLAGS=$nspr_cxxflags LDFLAGS=$nspr_ldflags \
      CC=$CC CXX=$CCC ../configure "${nspr_opt[@]}" --prefix="$obj_dir" 1> $out
    echo "[2/3] make NSPR ..."
    make -C "$cwd/../nspr/$target" 1> $out
    echo "[3/3] install NSPR ..."
    make -C "$cwd/../nspr/$target" install 1> $out
}
