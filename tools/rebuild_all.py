import sys
import textwrap

from build import (create_interpreters, copy_templates, build_binaries, build_pbos, safety_checks,
                   pack_mod)


PYTHON_VERSION = '3.7.9'


def rebuild_all(version):
    run_tests = False
    create_interpreters(version)
    copy_templates(version)

    if sys.platform == 'linux':
        build_binaries(version, 'x86', 'linux')
        build_binaries(version, 'x64', 'linux')
    else:
        build_binaries(version, 'x86', 'windows')
        build_binaries(version, 'x64', 'windows')

    if sys.platform != 'linux':
        build_pbos()

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
