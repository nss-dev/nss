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
    CFLAGS=$nspr_cflags CXXFLAGS=$nspr_cxxflags LDFLAGS=$nspr_ldflags \
    CC=$CC CXX=$CCC ../configure "${nspr_opt[@]}" --prefix="$obj_dir"
    make -C "$cwd/../nspr/$target"
    make -C "$cwd/../nspr/$target" install
}
