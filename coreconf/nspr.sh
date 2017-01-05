#!/usr/bin/env bash
# This script builds NSPR for NSS.
#
# This build system is still under development.  It does not yet support all
# the features or platforms that the regular NSPR build supports.

# variables
nspr_cflags=
nspr_cxxflags=
nspr_ldflags=

# Try to avoid bmake on OS X and BSD systems
if hash gmake 2>/dev/null; then
    make() { command gmake "$@"; }
fi

nspr_sanitizer()
{
    extra=$(python $cwd/coreconf/sanitizers.py "$@")
    nspr_cflags="$nspr_cflags $extra"
    nspr_cxxflags="$nspr_cxxflags $extra"
    nspr_ldflags="$nspr_ldflags $extra"
}

nspr_build()
{
    [ "$verbose" = 0 ] && exec 3>/dev/null || exec 3>&1

    mkdir -p "$cwd"/../nspr/$target
    pushd "$cwd"/../nspr/$target >/dev/null

    # These NSPR options are directory-specific, so they don't need to be
    # included in nspr_opt and changing them doesn't force a rebuild of NSPR.
    extra_params=(--prefix="$dist_dir"/$target)
    if [ "$opt_build" = 1 ]; then
        extra_params+=(--disable-debug --enable-optimize)
    fi

    echo "NSPR [1/3] configure ..."
    CFLAGS="$nspr_cflags" CXXFLAGS="$nspr_cxxflags" LDFLAGS="$nspr_ldflags" \
          CC="$CC" CXX="$CCC" ../configure "${extra_params[@]}" "$@" 1>&3 2>&3
    echo "NSPR [2/3] make ..."
    make 1>&3 2>&3
    echo "NSPR [3/3] install ..."
    make install 1>&3 2>&3

    popd >/dev/null

    exec 3>&-
}

nspr_clean()
{
    rm -rf "$cwd"/../nspr/$target
}
