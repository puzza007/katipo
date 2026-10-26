#!/usr/bin/env bash
# Build every proof. KatipoProofs/Axioms.lean pins the axioms of each
# headline theorem with #guard_msgs, so a sorry / native_decide / new axiom
# fails the build. Then re-run the TLC <-> Lean state-graph cross-check.
set -euo pipefail
cd "$(dirname "$0")"
lake build
lake build tracecheck
if grep -rnE '\bsorry\b|native_decide|^axiom ' KatipoProofs --include=*.lean \
     | grep -v '^KatipoProofs/Axioms.lean'; then
  echo "FAIL: sorry / native_decide / axiom in proofs" >&2; exit 1
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
for cfg in KatipoFlow KatipoFlowCrash KatipoFlowLimit; do
  case "$cfg" in
    KatipoFlowCrash) arg=crash ;;
    KatipoFlowLimit) arg=limit ;;
    *) arg= ;;
  esac
  (cd .. && tlc -workers 1 -deadlock -config "$cfg.cfg" \
     -dump dot,actionlabels "$tmp/$cfg.dot" KatipoFlow.tla >/dev/null)
  lake env lean --run scripts/FlowGraph.lean $arg > "$tmp/$cfg.txt"
  echo "$cfg:"
  python3 scripts/crosscheck_flow.py "$tmp/$cfg.dot" "$tmp/$cfg.txt"
done
rm -f ../KatipoFlow_TTrace_*.tla
echo "OK: all proofs build, axioms pinned, flow graphs identical"
