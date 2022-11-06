import argparse
import io
import os
import platform
import posixpath
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import zstandard


# time ./build-linux.py --target-triple i686-unknown-linux-gnu --optimizations pgo+lto --python cpython-3.10
# time ./build-linux.py --target-triple x86_64-unknown-linux-gnu --optimizations pgo+lto --python cpython-3.10


def zstd_unpack(filename_or_file, dest, archive_subfolder=None):
    """
    :param filename_or_file: zstd file to unpack or a file object
    :param dest: Directory where to unpack the archive
    :param archive_subfolder: [sub, directory, to, unpack]
    """
    def members(tf, prefix):
        prefix_len = len(prefix)
        for member in tf.getmembers():
            if member.path.startswith(prefix):
                member.path = member.path[prefix_len:]
                yield member

    dctx = zstandard.ZstdDecompressor()
    if hasattr(filename_or_file, 'read'):
        with dctx.stream_reader(filename_or_file) as reader:
            data_file = io.BytesIO(reader.read())
    else:
        with open(filename_or_file, 'rb') as ifh:
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


def convert_standalone_build(directory):
    currdir = os.getcwd()
    os.chdir(directory)

    print('Modifying the installation...')
    for path in Path('lib').glob('python*/test'):
        shutil.rmtree(path)

    shutil.rmtree('Lib/test', ignore_errors=True)

    for path in Path('.').glob('**/*.a'):
        path.unlink()
    for path in Path('.').glob('**/*.pdb'):
        path.unlink()

    if platform.system() == 'Linux':
        subprocess.run("patchelf --set-rpath '$ORIGIN/../lib' bin/python3", shell=True, check=True)
        dereference_symlinks('.')
        subprocess.run('docker run --platform linux/386 --rm -v "$(pwd)"/:/data quay.io/pypa/manylinux2014_i686:latest /bin/bash -c "cp /usr/local/lib/libcrypt.so.1 /data/ && chown 1000:1000 /data/libcrypt.so.1 && chmod 555 /data/libcrypt.so.1"',
                       shell=True, cwd='lib', check=True)

    os.chdir(currdir)


def pack_to_tbz(orig_filename, directory_unpacked):
    windows = True if 'windows' in orig_filename else False

    currdir = os.getcwd()
    os.chdir(directory_unpacked)

    # Strip name of timestamps
    new_name = Path(orig_filename).name
    new_name = new_name.rsplit('-', 1)[0]
    new_name = re.sub(r'\+[0-9]+-', '-', new_name) + '.tbz'
    new_path = Path(currdir) / new_name
    print(f'Packing into {new_path}')

    if not windows:
        dirs = ['bin', 'include', 'lib', 'share']
    else:
        dirs = ['DLLs', 'include', 'Lib', 'libs', 'Scripts', 'tcl', '*.txt', '*.dll', '*.exe']

    with tarfile.open(new_path, "w:bz2") as tar:
        for g in dirs:
            for path in Path('.').glob(g):
                print(f'Adding {path}')
                tar.add(path)


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
    convert_standalone_build('python')
    pack_to_tbz(filename, 'python')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('file_to_repack')
    arguments = parser.parse_args()

    main(arguments.file_to_repack)
