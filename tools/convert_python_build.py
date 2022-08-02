import argparse
import io
import os
import platform
import posixpath
import re
import shutil
import sys
import tarfile
from pathlib import Path

import zstandard


# time ./build-linux.py --target-triple i686-unknown-linux-gnu --optimizations pgo+lto --python cpython-3.7
# time ./build-linux.py --target-triple x86_64-unknown-linux-gnu --optimizations pgo+lto --python cpython-3.7


def zstd_unpack(filename, dest, archive_subfolder=None):
    """
    :param filename: zstd file to unpack
    :param dest: Directory where to unpack the atchive
    :param archive_subfolder: [sub, directory, to, unpack]
    """
    def members(tf, prefix):
        prefix_len = len(prefix)
        for member in tf.getmembers():
            if member.path.startswith(prefix):
                member.path = member.path[prefix_len:]
                yield member

    with open(filename, 'rb') as ifh:
        dctx = zstandard.ZstdDecompressor()

        with dctx.stream_reader(ifh) as reader:
            data_file = io.BytesIO(reader.read())

    with tarfile.open(mode='r:', fileobj=data_file) as tf:
        members_ = None
        if archive_subfolder:
            prefix = posixpath.join(*archive_subfolder) + '/'
            members_ = members(tf, prefix)

        tf.extractall(dest, members=members_)


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


def main(filename):
    windows = True if 'windows' in filename else False

    if windows:
        if platform.system() != 'Windows':
            print('You need windows to convert windows builds')
            sys.exit(1)
    else:
        if platform.system() == 'Windows':
            print('You need linux to convert linux builds')
            sys.exit(1)

    shutil.rmtree('python', ignore_errors=True)
    os.mkdir('python')

    print('Unpacking...')
    zstd_unpack(filename, 'python', ['python', 'install'])

    os.chdir('python')

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
    new_name = filename.rsplit('-', 1)[0]
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

    new_path = Path('..') / Path(new_name).name
    if new_path.exists():
        new_path.unlink()
    print(new_name, '->', new_path.resolve())
    shutil.move(new_name, new_path)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('file_to_repack')
    arguments = parser.parse_args()
    main(arguments.file_to_repack)
