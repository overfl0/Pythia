import os
import sys
import sysconfig

from setuptools import setup, Extension
from Cython.Build import cythonize

THIS_DIR = os.path.dirname(__file__)

# Workaround for building on PyOxidizer's 3.7 python
library_dirs = []
if sys.platform == 'linux' and sys.version_info.minor <= 7:
    library_dirs = [os.path.join(sysconfig.get_config_var('base'), 'lib')]

compiler_directives = {
    'language_level': 3
}

setup(
    # ext_modules=cythonize(os.path.join(THIS_DIR, 'cython_basic', 'cython_module.pyx'),
    ext_modules=cythonize(
        [
            Extension('cython_basic.cython_module', [os.path.join(THIS_DIR, 'cython_basic', 'cython_module.pyx')], library_dirs=library_dirs),
        ],
        compiler_directives=compiler_directives)
)
