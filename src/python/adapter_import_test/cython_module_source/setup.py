from distutils.core import setup
from Cython.Build import cythonize

setup(
    ext_modules = cythonize("hello.pyx")
)

# Get the build tools here:
# http://landinghub.visualstudio.com/visual-cpp-build-tools

# Compiling for 32bit
# "X:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build"\vcvarsall x86
# X:\Python35\python.exe cython_setup.py build_ext --inplace

# Compiling for 64bit
# "X:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build"\vcvarsall x64
# X:\Python35-x64\python.exe cython_setup.py build_ext --inplace
