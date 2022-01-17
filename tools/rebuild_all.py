import os
import shutil
import subprocess
import sys
import textwrap

import setuptools
from pkg_resources import parse_version

PYTHON_VERSION = parse_version('3.7.9')
os.chdir(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))


def _verbose_run(cmd, **kwargs):
    print(' '.join(cmd))
    subprocess.run(cmd, **kwargs)


def create_interpreters(version):
    print(f'Creating Python {version} interpreters...')
    subprocess.run([sys.executable, os.path.join('tools', 'create_embedded_python.py'), '--version', str(version), '@Pythia'], check=True)


def build_binaries(version, arch, system, run_tests=True):
    print(f'Building {arch} binaries for {system}...')

    # Arch is x64/x86
    embed = {
        'linux': {
            'x86': os.path.join('@Pythia', f'python-{version.major}{version.minor}-embed-linux32', 'bin', 'python3'),
            'x64': os.path.join('@Pythia', f'python-{version.major}{version.minor}-embed-linux64', 'bin', 'python3'),
        },
        'windows': {
            'x86': os.path.join('@Pythia', f'python-{version.major}{version.minor}-embed-win32', 'python.exe'),
            'x64': os.path.join('@Pythia', f'python-{version.major}{version.minor}-embed-amd64', 'python.exe'),
        }
    }

    if system == 'linux':
        env = None
    else:
        env = setuptools.msvc.msvc14_get_vc_env(arch)

    if os.path.exists('ninja'):
        shutil.rmtree('ninja')
    os.makedirs('ninja')

    if system == 'linux':
        _verbose_run(['docker', 'build', '-f', f'Dockerfile.{arch}', '-t', 'pythia:latest', '.'], check=True)
        docker_prefix = ['docker', 'run', '--rm', '-v', f'{os.getcwd()}/:/data', '-w', '/data/ninja', 'pythia:latest']
        shell = False
    else:
        docker_prefix = []
        shell = True

    _verbose_run(docker_prefix + ['cmake', '-G', 'Ninja', f'-DUSE_64BIT_BUILD={"ON" if arch == "x64" else "OFF"}', '-DCMAKE_BUILD_TYPE=RelWithDebInfo', '..'], check=True, cwd='ninja', env=env, shell=shell)
    _verbose_run(docker_prefix + ['ninja'], check=True, cwd='ninja', env=env, shell=shell)

    if run_tests:
        _verbose_run([embed[system][arch], os.path.join('tests', 'tests.py')], check=True)


def build_pbo():
    print('Building PBOs...')
    subprocess.run([sys.executable, os.path.join('tools', 'create_pbos.py')], check=True)


def safety_checks(version):
    print('Running safety checks...')
    subprocess.run([sys.executable, os.path.join('tools', 'safety_checks.py'), str(version)], check=True)


def pack_mod():
    print('Packing the resulting mod to a tbz file...')
    shutil.make_archive('@Pythia', 'bztar', root_dir='.', base_dir='@Pythia')


def rebuild_all(version):
    run_tests = False
    create_interpreters(version)

    if sys.platform == 'linux':
        build_binaries(version, 'x86', 'linux', run_tests=run_tests)
        build_binaries(version, 'x64', 'linux', run_tests=run_tests)
    else:
        build_binaries(version, 'x86', 'windows', run_tests=run_tests)
        build_binaries(version, 'x64', 'windows', run_tests=run_tests)

    if sys.platform != 'linux':
        build_pbo()

    safety_checks(version)

    # if run_tests:
    #     print(textwrap.dedent('''\
    #         WARNING: Since the tests have been run, your python installation
    #         will contain additional packages installed by pip during testing!
    #         If you want to build a release version, do not run tests (or use CI)
    #     '''))
    # else:
    #     pack_mod()


if __name__ == '__main__':
    rebuild_all(PYTHON_VERSION)
