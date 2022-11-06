import argparse
import os.path
import posixpath
import sys

from build import (create_interpreters, copy_templates, build_binaries, build_pbos, safety_checks,
                   _verbose_run, run_tests, clear_pythia_directory)
from common import get_python_version

THIS_DIR = os.path.dirname(__file__)


def rebuild_all(args):
    should_run_tests = True

    if not args.wsl:
        clear_pythia_directory()

    copy_templates(args.version)
    create_interpreters(args.version, '@Pythia')

    platform = 'windows' if sys.platform != 'linux' else sys.platform

    build_binaries(args.version, 'x86', platform)
    build_binaries(args.version, 'x64', platform)

    if should_run_tests:
        run_tests(args.version, 'x86', platform)
        run_tests(args.version, 'x64', platform)

    if args.wsl:
        return  # We've done all that was needed for the complementary linux tasks

    if sys.platform != 'linux':
        build_pbos()

        # Call ourselves through WSL to build the linux part of Pythia
        rebuild_all_py = posixpath.join(os.path.relpath(THIS_DIR), 'rebuild_all.py')
        _verbose_run(['wsl', '/bin/bash', '-ic', f'python {rebuild_all_py} {args.version} --wsl'], check=True)

    safety_checks(args.version)

    # if should_run_tests:
    #     print(textwrap.dedent('''\
    #         WARNING: Since the tests have been run, your python installation
    #         will contain additional packages installed by pip during testing!
    #         If you want to build a release version, do not run tests (or use CI)
    #     '''))
    # else:
    #     pack_mod()


if __name__ == '__main__':
    try:
        python_version = get_python_version()
    except AttributeError:
        print('Error: Could not parse python version from Github Actions yaml')
        sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument('--wsl', action='store_true',
                        help='Just do the minimum for the linux version')
    parser.add_argument('version', nargs='?', default=python_version)
    args = parser.parse_args()

    rebuild_all(args)
