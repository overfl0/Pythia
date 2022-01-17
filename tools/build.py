import argparse
import os
import shutil
import subprocess
import sys

import setuptools
from pkg_resources import parse_version

os.chdir(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))


def _verbose_run(cmd, **kwargs):
    print(' '.join(cmd))
    subprocess.run(cmd, **kwargs)


def create_interpreters(version, func=None):
    version = parse_version(version)
    print(f'Creating Python {version} interpreters...')
    subprocess.run([sys.executable, os.path.join('tools', 'create_embedded_python.py'), '--version', str(version), '@Pythia'], check=True)


def build_binaries(version, arch, system, run_tests=True, func=None):
    version = parse_version(version)
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


def build_pbo(func=None):
    print('Building PBOs...')
    subprocess.run([sys.executable, os.path.join('tools', 'create_pbos.py')], check=True)


def copy_statics(version, func=None):
    version = parse_version(version)
    print('Copying files to @Pythia folder...')
    for f in os.listdir('templates'):
        with open(os.path.join('templates', f), 'rb') as fread:
            with open(os.path.join('@Pythia', f), 'wb') as fwrite:
                fwrite.write(fread.read().replace(b'{version}', f'{version.major}{version.minor}'.encode('ascii')))


def safety_checks(version, func=None):
    version = parse_version(version)
    print('Running safety checks...')
    subprocess.run([sys.executable, os.path.join('tools', 'safety_checks.py'), str(version)], check=True)


def pack_mod(func=None):
    print('Packing the resulting mod to a tbz file...')
    shutil.make_archive('@Pythia', 'bztar', root_dir='.', base_dir='@Pythia')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()
    subparsers.required = True

    parser_create_interpreters = subparsers.add_parser('create_interpreters')
    parser_create_interpreters.add_argument('version')
    parser_create_interpreters.set_defaults(func=create_interpreters)

    parser_copy_statics = subparsers.add_parser('copy_statics')
    parser_copy_statics.add_argument('version')
    parser_copy_statics.set_defaults(func=copy_statics)

    parser_build_binaries = subparsers.add_parser('build_binaries')
    parser_build_binaries.add_argument('version')
    parser_build_binaries.add_argument('arch', choices=['x86', 'x64'])
    parser_build_binaries.add_argument('system', choices=['windows', 'linux'])
    parser_build_binaries.add_argument('--no-tests', dest='run_tests', action='store_false')
    parser_build_binaries.set_defaults(func=build_binaries)

    parser_build_pbo = subparsers.add_parser('build_pbo')
    parser_build_pbo.set_defaults(func=build_pbo)

    parser_safety_checks = subparsers.add_parser('safety_checks')
    parser_safety_checks.add_argument('version')
    parser_safety_checks.set_defaults(func=safety_checks)

    parser_pack_mod = subparsers.add_parser('pack_mod')
    parser_pack_mod.set_defaults(func=pack_mod)

    args = parser.parse_args()
    args.func(**vars(args))