#!/bin/bash

set -e

if [ $# -eq 0 ]; then
    echo "Usage: $0 <file_to_repack>"
    exit 1
fi

# time ./build-linux.py --target-triple i686-unknown-linux-gnu --python cpython-3.7
# time ./build-linux.py --target-triple x86_64-unknown-linux-gnu --python cpython-3.7

rm -rf python
tar -I zstd -xvf "$1"
pushd python/install/
rm -rf lib/python*/test
#zip -r "${1%-*}.zip" bin include lib share
tar -jcvf "${1%-*}.tbz" bin include lib share
mv "${1%-*}.tbz" ../..
popd
