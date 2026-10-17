#!/usr/bin/env bash
# Buffered-response throughput of the C port: bench/run.sh [reps]
set -euo pipefail
cd "$(dirname "$0")/.."
rebar3 compile >/dev/null
out=_build/bench
mkdir -p "$out"
erlc -o "$out" bench/katipo_bench.erl
erl -noshell -pa "$out" -pa _build/default/lib/*/ebin \
    -eval "katipo_bench:main([\"${1:-3}\"]), halt()."
