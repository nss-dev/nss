#!/usr/bin/env bash
# This file is used by build.sh to setup fuzzing.

gyp_params+=(-Dtest_build=1 -Dfuzz=1)

# Add debug symbols even for opt builds.
nspr_params+=(--enable-debug-symbols)

if [ "$fuzz_oss" = 1 ]; then
  gyp_params+=(-Dno_zdefs=1)
else
  enable_sanitizer asan
  enable_ubsan
  enable_sancov
fi

if [ "$fuzz_tls" = 1 ]; then
  gyp_params+=(-Dfuzz_tls=1)
fi

if [ ! -f "/usr/lib/libFuzzingEngine.a" ]; then
  echo "Cloning libFuzzer files ..."
  run_verbose "$cwd"/fuzz/clone_libfuzzer.sh
fi
