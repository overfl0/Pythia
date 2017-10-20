import os
import shutil
import subprocess
import urllib.request
import zipfile
from io import BytesIO

PIP_URL = 'https://bootstrap.pypa.io/get-pip.py'
BASE_ADDRESS = 'https://www.python.org/ftp/python/{version}/python-{version}-embed-{arch}.zip'
EMBED_DIR = 'python-embed-{arch}'
ARCHITECTURES = ['win32', 'amd64']
PYTHON_VERSION = '3.5.4'


def install_pip_for(python_executable):
    """"Fetch get_pip.py and run it with the given python executable."""

    file_raw = urllib.request.urlopen(PIP_URL).read()
    pip_installer = 'get-pip.py'
    with open(pip_installer, 'wb') as f:
        f.write(file_raw)
    try:
        subprocess.run([python_executable, pip_installer], check=True)
    finally:
        os.unlink(pip_installer)


def prepare_distro(basedir, version, arch, install_pip=True):
    """Basically:
    1) Download the embedded version from Python.org
    2) Unpack it to a well known directory name
    3) Unpack its stdlib
    4) Install pip inside
    """

    url = BASE_ADDRESS.format(version=version, arch=arch)
    directory = os.path.join(basedir, EMBED_DIR.format(arch=arch))
    version_with_minor = version.replace('.', '')[0:2]  # convert 3.5.4 to 35

    print('* Preparing embedded python-{version} for {arch}...'.format(version=version, arch=arch))

    # Download zip file
    print('* Downloading python zip...')
    file_raw = urllib.request.urlopen(url).read()
    os.makedirs(directory)

    # Unpack it
    print('Extracting...')
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

    # Install pip
    if install_pip:
        print('* Installing pip into the python distribution...')
        install_pip_for(os.path.join(directory, 'python.exe'))
        print('* Pip installation done!\n')


def prepare_distros(basedir, version, architectures):
    # Do a cleanup first
    for arch in architectures:
        path = os.path.join(basedir, EMBED_DIR.format(arch=arch))

        try:
            shutil.rmtree(path)
        except FileNotFoundError:
            pass

    for arch in architectures:
        prepare_distro(basedir, version, arch)

    print('=' * 80)
    print('Embedded versions of python-{version} for: {archs} have been created!'.format(
        version=version, archs=', '.join(architectures)))
    print('=' * 80)


if __name__ == '__main__':
    prepare_distros('.', PYTHON_VERSION, ARCHITECTURES)
