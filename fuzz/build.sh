#!/usr/bin/env bash
# Build the fuzz targets. Run inside the katipo-fuzz image (fuzz/Dockerfile),
# or anywhere with clang, erlang-dev, libcurl and libevent installed.
#
#   fuzz/build.sh [libfuzzer|afl|cmplog|coverage|replay] [target...]
#
# libfuzzer  clang + libFuzzer + ASan + UBSan (default)
# afl        afl-clang-fast + ASan + UBSan, for afl-fuzz
# cmplog     afl-clang-fast with AFL_LLVM_CMPLOG, the -c companion binary
# coverage   source-based coverage, replaying inputs, for llvm-cov
# replay     the system cc, replaying inputs, no instrumentation
#
# Binaries land in fuzz/out/<mode>/. EXTRA_CFLAGS is added to every compile.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
mode=${1:-libfuzzer}
shift || true
targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
  targets=()
  for f in "$here"/fuzz_*.c; do
    targets+=("$(basename "$f" .c)")
  done
fi

ei_dir=$(erl -noshell -eval 'io:format("~s", [code:lib_dir(erl_interface)]), halt().')
erts_inc=$(erl -noshell -eval 'io:format("~s/erts-~s/include", [code:root_dir(), erlang:system_info(version)]), halt().')
common=(${EXTRA_CFLAGS:-} -g -std=c99 -D_DEFAULT_SOURCE -Wall -Wextra -Wno-unused-function
        -I "$erts_inc" -I "$ei_dir/include" $(curl-config --cflags)
        $(pkg-config --cflags libevent))
libs=(-L "$ei_dir/lib" -lei $(curl-config --libs) $(pkg-config --libs libevent) -lpthread)
san=(-fsanitize=address,undefined -fno-sanitize-recover=undefined
     -fno-omit-frame-pointer)

case "$mode" in
  libfuzzer) cc=clang;          flags=(-O1 "${san[@]}" -fsanitize=fuzzer) ;;
  afl)       cc=afl-clang-fast; flags=(-O1 "${san[@]}" -fsanitize=fuzzer) ;;
  cmplog)    cc=afl-clang-fast; flags=(-O1 -fsanitize=fuzzer)
             export AFL_LLVM_CMPLOG=1 ;;
  coverage)  cc=clang;          flags=(-O0 -fprofile-instr-generate -fcoverage-mapping
                                       "$here/replay_main.c") ;;
  replay)    cc=${CC:-cc};      flags=(-O1 "$here/replay_main.c") ;;
  *) echo "unknown mode: $mode" >&2; exit 2 ;;
esac

out="$here/out/$mode"
mkdir -p "$out"
for t in "${targets[@]}"; do
  echo "  $mode  $t"
  "$cc" "${common[@]}" "${flags[@]}" "$here/$t.c" "${libs[@]}" -o "$out/$t"
done
