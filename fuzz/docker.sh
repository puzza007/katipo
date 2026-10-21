#!/usr/bin/env bash
# Run a command in the katipo-fuzz image with the repo mounted at /katipo,
# as the calling user so build outputs and findings stay owned by you.
#   fuzz/docker.sh fuzz/build.sh libfuzzer
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
docker image inspect katipo-fuzz >/dev/null 2>&1 ||
  docker build -t katipo-fuzz "$repo/fuzz"
exec docker run --rm -i --user "$(id -u):$(id -g)" -e HOME=/tmp \
  --security-opt seccomp=unconfined -v "$repo":/katipo -w /katipo \
  katipo-fuzz "$@"
