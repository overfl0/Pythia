#!/bin/bash

set -e

if [ $# -eq 0 ]; then
    echo "Usage: $0 <file_to_repack>"
    exit 1
fi

windows=false
if [[ "`basename $1`" == *"windows"* ]]; then
    windows=true
fi

# time ./build-linux.py --target-triple i686-unknown-linux-gnu --python cpython-3.7
# time ./build-linux.py --target-triple x86_64-unknown-linux-gnu --python cpython-3.7

rm -rf python

echo "Unpacking..."
tar -I zstd -xf "$1"
pushd python/install/ > /dev/null

echo "Modifying the installation..."
# We don't need tests
rm -rf lib/python*/test
rm -rf Lib/test

# Remove .a files because we won't be compiling anything statically
find -name '*.a' -delete
find -name '*.pdb' -delete

if [ "$windows" = false ]
then
    # Add paths to find our custom libcrypt for 32bit linux (installed below)
    patchelf --set-rpath '$ORIGIN/../lib' bin/python3

    # Dereference symlinks because they break Steam on Windows :(
    for i in `find -type l`
    do
      cp --remove-destination `readlink -f "$i"` "$i"
    done

    # Get the original libcrypt.so from a manylinux docker
    pushd lib > /dev/null
    docker run --platform linux/386 --rm -v "$(pwd)"/:/data quay.io/pypa/manylinux2014_i686:latest /bin/bash -c "cp /usr/local/lib/libcrypt.so.1 /data/ && chown 1000:1000 /data/libcrypt.so.1 && chmod 555 /data/libcrypt.so.1"
    popd > /dev/null
fi

# Pack everything back into a tbz file
echo "Packing into ${1%-*}.tbz..."
if [ "$windows" = false ]
then
    tar -jcf "${1%-*}.tbz" bin include lib share
else
    tar -jcf "${1%-*}.tbz" DLLs include Lib libs Scripts tcl *.txt *.dll *.exe
fi
mv "${1%-*}.tbz" ../..
popd > /dev/null
