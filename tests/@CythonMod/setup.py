import os
import sys
import sysconfig

from setuptools import setup, Extension
from Cython.Build import cythonize

THIS_DIR = os.path.dirname(__file__)

compiler_directives = {
    'language_level': 3
}

setup(
    # ext_modules=cythonize(os.path.join(THIS_DIR, 'cython_basic', 'cython_module.pyx'),
    ext_modules=cythonize(
        [
            Extension('cython_basic.cython_module', [os.path.join(THIS_DIR, 'cython_basic', 'cython_module.pyx')],),
        ],
        compiler_directives=compiler_directives)
)
