import argparse
import os
import platform
import re
import shutil
import sys
import tarfile
from pathlib import Path

import zstandard


# time ./build-linux.py --target-triple i686-unknown-linux-gnu --python cpython-3.7
# time ./build-linux.py --target-triple x86_64-unknown-linux-gnu --python cpython-3.7


def zstd_unpack(filename, dest):
    with open(filename, 'rb') as ifh:
        dctx = zstandard.ZstdDecompressor()
        with dctx.stream_reader(ifh) as reader:
            with tarfile.open(mode='r|', fileobj=reader) as tf:
                tf.extractall(dest)


def dereference_symlinks(path):
    for root_, dirs, files in os.walk(path, followlinks=False):
        root = Path(root_)
        for f in files:
            filepath = root / f
            if filepath.is_symlink():
                dest = filepath.resolve()
                # print(f'Dereferencing {filepath} -> {dest}')
                filepath.unlink()
                shutil.copy2(dest, filepath)


def main(args):
    windows = True if 'windows' in args.file_to_repack else False

    if windows:
        if platform.system() != 'Windows':
            print('You need windows to convert windows builds')
            sys.exit(1)
    else:
        if platform.system() == 'Windows':
            print('You need linux to convert linux builds')
            sys.exit(1)

    shutil.rmtree('python', ignore_errors=True)

    print('Unpacking...')
    zstd_unpack(args.file_to_repack, '.')

    os.chdir('python/install/')

    print('Modifying the installation...')
    for path in Path('lib').glob('python*/test'):
        shutil.rmtree(path)
    shutil.rmtree('Lib/test', ignore_errors=True)

    for path in Path('.').glob('**/*.a'):
        path.unlink()
    for path in Path('.').glob('**/*.pdb'):
        path.unlink()

    if platform.system() == 'Linux':
        os.system("patchelf --set-rpath '$ORIGIN/../lib' bin/python3")

        dereference_symlinks('.')

        os.chdir('lib')
        os.system('docker run --platform linux/386 --rm -v "$(pwd)"/:/data quay.io/pypa/manylinux2014_i686:latest /bin/bash -c "cp /usr/local/lib/libcrypt.so.1 /data/ && chown 1000:1000 /data/libcrypt.so.1 && chmod 555 /data/libcrypt.so.1"')
        os.chdir('..')

    # Strip name of timestamps
    new_name = args.file_to_repack.rsplit('-', 1)[0]
    new_name = re.sub(r'\+[0-9]+-', '-', new_name) + '.tbz'
    print(f'Packing into {new_name}')

    if not windows:
        dirs = ['bin', 'include', 'lib', 'share']
    else:
        dirs = ['DLLs', 'include', 'Lib', 'libs', 'Scripts', 'tcl', '*.txt', '*.dll', '*.exe']

    tar = tarfile.open(new_name, "w:bz2")
    for g in dirs:
        for path in Path('.').glob(g):
            print(f'Adding {path}')
            tar.add(path)
    tar.close()

    new_path = Path('../..') / Path(new_name).name
    if new_path.exists():
        new_path.unlink()
    print(new_name, '->', new_path.resolve())
    shutil.move(new_name, new_path)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('file_to_repack')
    arguments = parser.parse_args()
    main(arguments)
