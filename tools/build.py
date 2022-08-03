import argparse
import os
import shutil
import stat
import subprocess
import sys

import setuptools
from pkg_resources import parse_version

os.chdir(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))


# Python 3.7 workaround:
def parse_version_wrapper(txt):
    version = parse_version(txt)

    try:
        version.major  # noqa
        version.minor  # noqa
    except AttributeError:
        # Python 3.7 doesn't have these so we patch them in
        version.major = version._version.release[0]
        version.minor = version._version.release[1]

    return version


def _verbose_run(cmd, **kwargs):
    print(' '.join(cmd), flush=True)
    subprocess.run(cmd, **kwargs)


def clear_pythia_directory():
    base = '@Pythia'
    print(f'Deleting {base} contents...')

    def del_rw(action, name, exc):
        """Fix permissions in case of a read-only file"""
        os.chmod(name, stat.S_IWRITE)
        if os.path.isdir(name):
            os.rmdir(name)
        else:
            os.remove(name)

    os.makedirs(base, exist_ok=True)
    for filename in os.listdir('@Pythia'):
        path = os.path.join(base, filename)
        if os.path.isdir(path):
            shutil.rmtree(path, onerror=del_rw)
        else:
            os.unlink(path)


def create_interpreters(version, dest):
    version = parse_version_wrapper(version)
    print(f'Creating Python {version} interpreters in "{dest}" directory...', flush=True)
    subprocess.run([sys.executable, os.path.join('tools', 'create_embedded_python.py'), '--version', str(version), dest], check=True)


def _get_embed(version, system, arch):
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

    return embed[system][arch]


def build_binaries(version, arch, system, run_tests=True):
    version = parse_version_wrapper(version)
    print(f'Building {arch} binaries for {system}...', flush=True)

    if system == 'linux':
        env = None
    else:
        env = setuptools.msvc.msvc14_get_vc_env(arch)

    if os.path.exists('ninja'):
        shutil.rmtree('ninja')
    os.makedirs('ninja')

    if system == 'linux':
        platform = ['--platform', 'linux/386'] if arch == 'x86' else []
        _verbose_run(['docker', 'build', '-f', f'Dockerfile.{arch}'] + platform + ['-t', 'pythia:latest', '.'], check=True)
        # Workaround for GitHub Actions
        # This is to fix GIT not liking owner of the checkout dir (git callback in cmake)
        # https://github.com/actions/runner/issues/2033
        uid_gid = ['-u', f'{os.getuid()}:{os.getgid()}'] if sys.platform == 'linux' else []
        docker_prefix = ['docker', 'run'] + platform + uid_gid + ['--rm', '-v', f'{os.getcwd()}/:/data', '-w', '/data/ninja', 'pythia:latest']
        shell = False
    else:
        docker_prefix = []
        shell = True

    _verbose_run(docker_prefix + ['cmake', '-G', 'Ninja', f'-DUSE_64BIT_BUILD={"ON" if arch == "x64" else "OFF"}', '-DCMAKE_BUILD_TYPE=RelWithDebInfo', '..'], check=True, cwd='ninja', env=env, shell=shell)
    _verbose_run(docker_prefix + ['ninja'], check=True, cwd='ninja', env=env, shell=shell)


def run_tests(version, arch, system):
    version = parse_version_wrapper(version)
    print(f'Running tests for {arch} {system}...', flush=True)

    _verbose_run([_get_embed(version, system, arch), os.path.join('tests', 'tests.py')], check=True)


def build_pbos():
    print('Building PBOs...', flush=True)
    subprocess.run([sys.executable, os.path.join('tools', 'create_pbos.py')], check=True)


def copy_templates(version):
    version = parse_version_wrapper(version)
    print('Copying files to @Pythia folder...', flush=True)

    for f in os.listdir('templates'):
        with open(os.path.join('templates', f), 'rb') as fread:
            with open(os.path.join('@Pythia', f), 'wb') as fwrite:
                fwrite.write(fread.read().replace(b'{version}', f'{version.major}{version.minor}'.encode('ascii')))


def safety_checks(version):
    version = parse_version_wrapper(version)
    print('Running safety checks...', flush=True)
    subprocess.run([sys.executable, os.path.join('tools', 'safety_checks.py'), str(version)], check=True)


def pack_mod():
    print('Packing the resulting mod to a tbz file...', flush=True)
    shutil.make_archive('@Pythia', 'bztar', root_dir='.', base_dir='@Pythia')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(required=True, dest='command')

    parser_create_interpreters = subparsers.add_parser('create_interpreters')
    parser_create_interpreters.add_argument('version')
    parser_create_interpreters.add_argument('--dest', default='@Pythia')
    parser_create_interpreters.set_defaults(func=create_interpreters)

    parser_copy_templates = subparsers.add_parser('copy_templates')
    parser_copy_templates.add_argument('version')
    parser_copy_templates.set_defaults(func=copy_templates)

    parser_build_binaries = subparsers.add_parser('build_binaries')
    parser_build_binaries.add_argument('version')
    parser_build_binaries.add_argument('arch', choices=['x86', 'x64'])
    parser_build_binaries.add_argument('system', choices=['windows', 'linux'], type=str.lower)
    parser_build_binaries.set_defaults(func=build_binaries)

    parser_run_tests = subparsers.add_parser('run_tests')
    parser_run_tests.add_argument('version')
    parser_run_tests.add_argument('arch', choices=['x86', 'x64'])
    parser_run_tests.add_argument('system', choices=['windows', 'linux'], type=str.lower)
    parser_run_tests.set_defaults(func=run_tests)

    parser_build_pbos = subparsers.add_parser('build_pbos')
    parser_build_pbos.set_defaults(func=build_pbos)

    parser_safety_checks = subparsers.add_parser('safety_checks')
    parser_safety_checks.add_argument('version')
    parser_safety_checks.set_defaults(func=safety_checks)

    parser_pack_mod = subparsers.add_parser('pack_mod')
    parser_pack_mod.set_defaults(func=pack_mod)

    parser_clear_pythia_directory = subparsers.add_parser('clear_pythia_directory')
    parser_clear_pythia_directory.set_defaults(func=clear_pythia_directory)

    args_vars = vars(parser.parse_args())

    # Python 3.7 required add_subparsers(dest='...') for when the command is
    # missing. So we need to pop it here so we don't pass it to functions
    del args_vars['command']

    func = args_vars.pop('func')
    func(**args_vars)
