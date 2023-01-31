import argparse
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from io import BytesIO

from common import ignore_no_file, get_python_version
from convert_python_build import zstd_unpack, convert_standalone_build
from obtain_python_builds import get_relevant_releases

USE_PYTHON_ORG = False

PIP_URL = 'https://bootstrap.pypa.io/get-pip.py'
BASE_STANDALONE_ADDRESS = 'https://github.com/overfl0/Pythia/releases/download/interpreters/cpython-{version}-{arch}-' \
                          'unknown-linux-gnu-pgo+lto.tbz'
BASE_STANDALONE_WINDOWS_ADDRESS = 'https://github.com/overfl0/Pythia/releases/download/interpreters/cpython-{version}' \
                                  '-{arch}-pc-windows-msvc-shared-pgo.tbz'
BASE_ADDRESS = 'https://www.python.org/ftp/python/{version}/python-{version}-embed-{arch}.zip'
MSI_ADDRESS = 'https://www.python.org/ftp/python/{version}/{arch}/{file}.msi'
EMBED_DIR = 'python-{version_short}-embed-{arch}'
ARCHITECTURES_WINDOWS = ['win32', 'amd64']
ARCHITECTURES_LINUX = ['linux32', 'linux64']
ARCHITECTURES_CURRENT = ARCHITECTURES_WINDOWS if platform.system() == 'Windows' else ARCHITECTURES_LINUX
STANDALONE_MAPPING = {
    'linux32': 'i686',
    'linux64': 'x86_64',
    'win32': 'i686',
    'amd64': 'x86_64',
}
PIP_REQUIREMENTS = ['pip==23.0', 'setuptools==65.1.1', 'wheel==0.38.4']


def install_pip_for(python_executable):
    """Fetch get_pip.py and run it with the given python executable."""

    file_raw = urllib.request.urlopen(PIP_URL).read()
    pip_installer = 'get-pip.py'
    with open(pip_installer, 'wb') as f:
        f.write(file_raw)
    try:
        subprocess.run([python_executable, pip_installer, '--no-warn-script-location'] + PIP_REQUIREMENTS, check=True)
    finally:
        os.unlink(pip_installer)


def install_pip_linux(python_executable):
    """Just call ensurepip and then the regular pip installation."""

    subprocess.run([python_executable, '-m', 'ensurepip'], check=True)
    subprocess.run([python_executable, '-m', 'pip', 'install'] + PIP_REQUIREMENTS, check=True)


def fetch_dev_files(directory, version, arch):
    """Fetch the include and libs directories contained in dev.msi"""

    print('* Fetching dev.msi')
    url = MSI_ADDRESS.format(version=version, arch=arch, file='dev')
    file_raw = urllib.request.urlopen(url).read()

    try:
        with open('dev.msi', 'wb') as f:
            f.write(file_raw)

        if platform.system() == 'Windows':
            cmd = ['msiexec.exe', '/a', 'dev.msi', '/qn', 'TARGETDIR={}'.format(os.path.realpath(directory))]
        else:
            cmd = ['msiextract', '--directory', directory, 'dev.msi']

        print('* Unpacking dev.msi')
        subprocess.check_call(cmd)

    finally:
        with ignore_no_file():
            os.unlink(os.path.join(directory, 'dev.msi'))  # It's created only with msiexec.exe, for some reason
        with ignore_no_file():
            os.unlink('dev.msi')


def prepare_distro(basedir, version, arch, install_pip=True):
    """Basically:
    1) Download the embedded version from Python.org
    2) Unpack it to a well known directory name
    3) Unpack its stdlib
    4) Install pip inside
    """

    windows = arch in ARCHITECTURES_WINDOWS
    if not USE_PYTHON_ORG:
        url = get_relevant_releases(version=version, arch=STANDALONE_MAPPING[arch], windows=windows)[0].url
    else:  # Legacy, TODO: remove me
        if windows:
            url = BASE_ADDRESS.format(version=version, arch=arch)
        else:
            url = BASE_STANDALONE_ADDRESS.format(version=version, arch=STANDALONE_MAPPING[arch])

    version_with_minor = ''.join(version.split('.')[:2])  # convert 3.5.4 to 35
    directory = os.path.join(basedir, EMBED_DIR.format(arch=arch, version_short=version_with_minor))

    print('* Preparing embedded python-{version} for {arch}...'.format(version=version, arch=arch))

    # Download compressed file
    print('* Downloading python compressed installation...')
    file_raw = urllib.request.urlopen(url).read()
    os.makedirs(directory)

    print('* Extracting...')
    # Python.org standalone windows executables need a few changes before they can be used
    if USE_PYTHON_ORG and arch in ARCHITECTURES_WINDOWS:
        python_zip_file = zipfile.ZipFile(BytesIO(file_raw), 'r')
        python_zip_file.extractall(directory)

        # Unpack stdlib (not doing so breaks some pip downloaded tools, like 2to3)
        # Prefetch the whole file prior to deletion
        print('* Unpacking stdlib')
        stdlib = 'python{version_with_minor}.zip'.format(version_with_minor=version_with_minor)
        stdlib_path = os.path.join(directory, stdlib)
        stdlib_zip_file = zipfile.ZipFile(BytesIO(open(stdlib_path, 'rb').read()), 'r')
        os.unlink(stdlib_path)
        os.makedirs(stdlib_path)
        stdlib_zip_file.extractall(stdlib_path)

        # ._pth file handling
        _pth = os.path.join(directory, 'python{version_with_minor}._pth'.format(version_with_minor=version_with_minor))

        # UPDATE: due to an issue with `pip install` starting in isolated
        # mode (and failing to resolve relative imports thus failing) we're
        # simply deleting the _pth file if it exists, instead of crafting
        # a special _pth file.

        # import site when executing python.exe (doesn't apply to the embedded
        # version) which gives access to site-packages and that allows pip (and
        # other packages) to be accessed
        # with open(_pth, 'a') as f:
        #     f.write('import site\n')

        if os.path.exists(_pth):
            os.unlink(_pth)

        # Fetch files required when building Cython extensions from source, for example
        fetch_dev_files(directory, version, arch)

    else:  # Linux or non-python.org-Windows
        if not USE_PYTHON_ORG:
            zstd_unpack(BytesIO(file_raw), directory, ['python', 'install'])
            convert_standalone_build(directory)
        else:
            python_tar_file = tarfile.open(None, "r:bz2", BytesIO(file_raw))
            python_tar_file.extractall(directory)
            python_tar_file.close()

    # Install pip
    if install_pip:
        print('* Installing pip into the python distribution...')
        if arch in ARCHITECTURES_WINDOWS:
            install_pip_for(os.path.join(directory, 'python.exe'))
        else:  # Linux
            # Don't install pip, for now, as the package is supposed to contain it already
            # install_pip_for(os.path.join(directory, 'bin', 'python'))
            install_pip_linux(os.path.join(directory, 'bin', 'python3'))
        print('* Pip installation done!\n')


def prepare_distros(basedir, version, architectures, do_cleanup=True):
    version_with_minor = ''.join(version.split('.')[:2])  # convert 3.5.4 to 35
    # Do a cleanup first
    if do_cleanup:
        for arch in ARCHITECTURES_CURRENT:
            path = os.path.join(basedir, EMBED_DIR.format(arch=arch, version_short=version_with_minor))

            with ignore_no_file():
                shutil.rmtree(path)

    for arch in architectures:
        prepare_distro(basedir, version, arch)

    print('=' * 80)
    print('Embedded versions of python-{version} for: {archs} have been created!'.format(
        version=version, archs=', '.join(architectures)))
    print('=' * 80)


if __name__ == '__main__':
    try:
        python_version = get_python_version()
    except AttributeError:
        print('Error: Could not parse python version from Github Actions yaml')
        sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument('base_directory', help='Directory in which the python directory will be created')
    parser.add_argument('-a', '--arch', help='Architecture name', choices=ARCHITECTURES_CURRENT,
                        action='append', default=None)
    parser.add_argument('-n', '--noclean', help='Don\'t remove other python installations', action='store_true')
    parser.add_argument('-v', '--version', help='Python version ("3.x.y")', default=python_version)
    args = parser.parse_args()

    if not args.arch:
        args.arch = ARCHITECTURES_CURRENT

    prepare_distros(args.base_directory, args.version, args.arch, do_cleanup=not args.noclean)
