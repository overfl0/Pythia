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
find -name '*.a' -delete
#zip -r "${1%-*}.zip" bin include lib share
# Get the original libcrypt.so from a manylinux docker
pushd lib
docker run --platform linux/386 -v "$(pwd)"/:/data quay.io/pypa/manylinux2014_i686:latest /bin/bash -c "cp /usr/local/lib/libcrypt.so.1 /data/ && chown 1000:1000 /data/libcrypt.so.1 && chmod 555 /data/libcrypt.so.1"
popd
tar -jcvf "${1%-*}.tbz" bin include lib share
mv "${1%-*}.tbz" ../..
popd
