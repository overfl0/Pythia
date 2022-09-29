import os
import sys
import sysconfig

from setuptools import setup, Extension
from Cython.Build import cythonize
import numpy

THIS_DIR = os.path.dirname(__file__)

compiler_directives = {
    'language_level': 3
}

setup(
    # ext_modules=cythonize(os.path.join(THIS_DIR, 'cython_basic', 'cython_module.pyx'),
    ext_modules=cythonize(
        [
            Extension('cython_numpy_basic.cython_numpy_module',
                      [os.path.join(THIS_DIR, 'cython_numpy_basic', 'cython_numpy_module.pyx')],),
        ],
        compiler_directives=compiler_directives),
    include_dirs=[numpy.get_include()],
)
