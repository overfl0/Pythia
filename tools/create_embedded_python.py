import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

from common import ignore_no_file, get_python_version

EMBED_DIR = 'python-{version_short}-embed-{arch}'
ARCHITECTURES_WINDOWS = ['win32', 'amd64']
ARCHITECTURES_LINUX = ['linux64']
ARCHITECTURES_CURRENT = ARCHITECTURES_WINDOWS if platform.system() == 'Windows' else ARCHITECTURES_LINUX
STANDALONE_MAPPING = {
    'linux64': 'cpython-{version}-linux-x86_64-gnu',
    'win32': 'cpython-{version}-windows-x86-none',
    'amd64': 'cpython-{version}-windows-x86_64-none',
}
PIP_REQUIREMENTS = ['pip==23.0', 'setuptools==65.1.1', 'wheel==0.38.4']

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
    for path in Path('.').glob('**/*.a'):
        path.unlink()
    for path in Path('.').glob('**/*.pdb'):
        path.unlink()
    for path in Path('.').glob('**/EXTERNALLY-MANAGED'):
        path.unlink()

    if platform.system() == 'Linux':
        dereference_symlinks('.')

    os.chdir(currdir)


def install_pip(python_executable):
    """Just call ensurepip and then the regular pip installation."""

    subprocess.run([python_executable, '-m', 'ensurepip'], check=True)
    subprocess.run([python_executable, '-m', 'pip', 'install', '--no-warn-script-location'] + PIP_REQUIREMENTS, check=True)


def prepare_distro(basedir, version, arch, should_install_pip=True):
    """Basically:
    1) Download the embedded version with uv
    2) Apply several fixes to its structure
    3) Install pip and basic requirements
    """

    uv_python_name = STANDALONE_MAPPING[arch].format(version=version)
    uv_python_directory = os.path.join(basedir, uv_python_name)

    version_with_minor = ''.join(version.split('.')[:2])  # convert 3.5.4 to 35
    pythia_python_name = EMBED_DIR.format(arch=arch, version_short=version_with_minor)
    pythia_python_directory = os.path.join(basedir, pythia_python_name)

    with ignore_no_file():
        shutil.rmtree(uv_python_directory)
    with ignore_no_file():
        shutil.rmtree(pythia_python_directory)

    print('* Preparing embedded python-{version} for {arch}...'.format(version=version, arch=arch))

    # Download original python installation
    # uv python install --install-dir . --no-registry --no-bin cpython-3.10.9-windows-x86_64-none
    subprocess.run(['uv', 'python', 'install', '--install-dir', basedir, '--no-registry', '--no-bin', '--no-config', uv_python_name], check=True)

    # TODO: use uv in a temporary directory, so we don't have to clean after it
    os.unlink(os.path.join(basedir, '.gitignore'))
    os.unlink(os.path.join(basedir, '.lock'))
    os.rmdir(os.path.join(basedir, '.temp'))
    # End uv cleanup

    os.rename(uv_python_directory, pythia_python_directory)

    convert_standalone_build(pythia_python_directory)

    # Install pip
    if should_install_pip:
        print('* Installing pip into the python distribution...')
        if arch in ARCHITECTURES_WINDOWS:
            install_pip(os.path.join(pythia_python_directory, 'python.exe'))
        else:  # Linux
            install_pip(os.path.join(pythia_python_directory, 'bin', 'python3'))
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
