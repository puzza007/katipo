#!/usr/bin/env bash
# Trace validation: run the Common Test suites with tracing on, then replay
# every recorded worker run against the Lean admission model. Extra
# arguments go to `rebar3 ct` (e.g. --suite katipo_stress_SUITE, which
# needs no httpbin).
set -euo pipefail
cd "$(dirname "$0")/.."
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
KATIPO_TRACE_DIR="$dir" rebar3 ct "$@"
(cd formal/lean && lake exe tracecheck "$dir"/*.trace)
