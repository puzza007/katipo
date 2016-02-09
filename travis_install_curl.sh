#!/bin/bash
set -ex

function travis_artifacts_install() {
  local os=$(uname | tr '[:upper:]' '[:lower:]')
  local arch=$(uname -m)
  [[ $arch == x86_64 ]] && arch=amd64
  local source="https://s3.amazonaws.com/meatballhat/artifacts/stable/build/$os/$arch/artifacts"
  local target=$HOME/bin/artifacts

  mkdir -p $(dirname $target)
  curl -sL -o $target $source
  chmod +x $target
  PATH="$(dirname $target):$PATH" artifacts -v
}

# our version of curl causes travis_artifacts_install to fail, so do
# it now rather than later
travis_artifacts_install

wget --no-check-certificate https://curl.haxx.se/download/curl-7.47.1.tar.gz
tar zxf curl-7.47.1.tar.gz
cd curl-7.47.1
./configure --enable-silent-rules && make && sudo make install

