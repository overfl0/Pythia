import sys
import textwrap

from build import (create_interpreters, copy_statics, build_binaries, build_pbo, safety_checks,
                   pack_mod)


PYTHON_VERSION = '3.7.9'


def rebuild_all(version):
    run_tests = False
    create_interpreters(version)
    copy_statics(version)

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
