import argparse
import os
import sys
from typing import List

from pkg_resources import parse_version


def check_dll_architecture(path: str, x86=False):
    arch = '32bit' if x86 else '64bit'
    print(f'Checking if file {path} is {arch}...')
    try:
        import pefile
    except ImportError:
        print('Install pefile: pip install pefile')
        sys.exit(1)

    if not os.path.exists(path):
        print(f'File {path} is missing!')
        sys.exit(1)

    pe = pefile.PE(path)
    arch32 = bool(pe.NT_HEADERS.FILE_HEADER.Characteristics & pefile.IMAGE_CHARACTERISTICS['IMAGE_FILE_32BIT_MACHINE'])

    if (x86 and not arch32) or (not x86 and arch32):
        print(f'File {path} is not {arch}!')
        sys.exit(1)


def check_dll_is_static(path: str, allowed_imports: List = None):
    """
    Ensure a given DLL doesn't try importing some funny dependencies
    because we messed up something in the compiler options or something.
    """

    print(f'Checking if file {path} is static...')
    try:
        import pefile
    except ImportError:
        print('Install pefile: pip install pefile')
        sys.exit(1)

    if not os.path.exists(path):
        print(f'File {path} is missing!')
        sys.exit(1)

    if allowed_imports is None:
        allowed_imports = []

    allowed_imports_lower = {b'kernel32.dll'}
    for allowed_import in allowed_imports:
        allowed_imports_lower.add(allowed_import.lower())

    pe = pefile.PE(path)
    file_imports = [entry.dll.lower() for entry in pe.DIRECTORY_ENTRY_IMPORT]
    for file_import in file_imports:
        if file_import not in allowed_imports_lower:
            print(f'File {path} is not static! It imports {file_import}!')
            sys.exit(1)


def check_so_architecture(path: str, x86=False):
    arch = '32bit' if x86 else '64bit'
    print(f'Checking if file {path} is {arch}...')
    try:
        import elftools
    except ImportError:
        print('Install elftools: pip install pyelftools')
        sys.exit(1)
    from elftools.elf.elffile import ELFFile

    if not os.path.exists(path):
        print(f'File {path} is missing!')
        sys.exit(1)

    with open(path, 'rb') as file:
        elffile = ELFFile(file)

    arch32 = elffile.elfclass == 32

    if (x86 and not arch32) or (not x86 and arch32):
        print(f'File {path} is not {arch}!')
        sys.exit(1)


def check_so_is_manylinux2014(path: str, allowed_imports: List = None):
    # PEP 599
    allowed_shared_objects = {
        'libgcc_s.so.1',
        'libstdc++.so.6',
        'libm.so.6',
        'libdl.so.2',
        'librt.so.1',
        'libc.so.6',
        'libnsl.so.1',
        'libutil.so.1',
        'libpthread.so.0',
        'libresolv.so.2',
        'libX11.so.6',
        'libXext.so.6',
        'libXrender.so.1',
        'libICE.so.6',
        'libSM.so.6',
        'libGL.so.1',
        'libgobject-2.0.so.0',
        'libgthread-2.0.so.0',
        'libglib-2.0.so.0',
    }

    allowed_symbol_versions = {
        'GLIBC': parse_version('2.17'),
        'CXXABI': parse_version('1.3.7'),
        'GLIBCXX': parse_version('3.4.19'),
        'GCC': parse_version('4.8.0'),
    }

    allowed_imports_lower = {'ld-linux.so.2', 'ld-linux-x86-64.so.2'}
    if allowed_imports:
        for allowed_import in allowed_imports:
            allowed_imports_lower.add(allowed_import)

    print(f'Checking if file {path} is manylinux2014...')
    try:
        import auditwheel
    except ImportError:
        print('Install auditwheel: pip install auditwheel')
        sys.exit(1)

    from auditwheel.lddtree import lddtree
    from auditwheel.elfutils import elf_find_versioned_symbols
    from elftools.elf.elffile import ELFFile

    if not os.path.exists(path):
        print(f'File {path} is missing!')
        sys.exit(1)

    # Check if all libs are in the allowed_shared_objects or whitelisted
    elftree = lddtree(path)
    libs = elftree['libs'].keys()
    for lib in libs:
        if lib not in allowed_shared_objects and lib not in allowed_imports_lower:
            print(f'File {path} depends on {lib} which doesn\'t match the manylinux2014 requirements. '
                  'This file will need to be vendored in!')
            sys.exit(1)

    # Check if all versioned symbols are at the values in allowed_symbol_versions or lower
    with open(path, 'rb') as file:
        elffile = ELFFile(file)
        for filename, symbol in elf_find_versioned_symbols(elffile):
            symbol_name, _, version = symbol.partition('_')
            if parse_version(version) > allowed_symbol_versions[symbol_name]:
                print(f'There is a call to {symbol_name} at version {version} which is not allowed for manylinux2014. '
                      'Rebuild the code using the manylinux2014 docker image!')
                sys.exit(1)


def safety_checks(python_version):
    major, minor, patch = python_version.split('.')
    dll_import = f'python3{minor}.dll'.encode('ascii')
    so_import = f'libpython3.{minor}.so.1.0'
    check_dll_is_static(os.path.join('@Pythia', 'Pythia.dll'), allowed_imports=[dll_import])
    check_dll_is_static(os.path.join('@Pythia', 'Pythia_x64.dll'), allowed_imports=[dll_import])
    check_dll_is_static(os.path.join('@Pythia', 'PythiaSetPythonPath.dll'))
    check_dll_is_static(os.path.join('@Pythia', 'PythiaSetPythonPath_x64.dll'))
    print()
    check_dll_architecture(os.path.join('@Pythia', 'Pythia.dll'), x86=True)
    check_dll_architecture(os.path.join('@Pythia', 'Pythia_x64.dll'), x86=False)
    check_dll_architecture(os.path.join('@Pythia', 'PythiaSetPythonPath.dll'), x86=True)
    check_dll_architecture(os.path.join('@Pythia', 'PythiaSetPythonPath_x64.dll'), x86=False)
    print()
    check_so_architecture(os.path.join('@Pythia', 'Pythia.so'), x86=True)
    check_so_architecture(os.path.join('@Pythia', 'Pythia_x64.so'), x86=False)
    check_so_architecture(os.path.join('@Pythia', 'PythiaSetPythonPath.so'), x86=True)
    check_so_architecture(os.path.join('@Pythia', 'PythiaSetPythonPath_x64.so'), x86=False)
    print()
    linux_imports = [so_import, 'libcrypt.so.1']
    check_so_is_manylinux2014(os.path.join('@Pythia', 'Pythia.so'), allowed_imports=linux_imports)
    check_so_is_manylinux2014(os.path.join('@Pythia', 'Pythia_x64.so'), allowed_imports=linux_imports)
    check_so_is_manylinux2014(os.path.join('@Pythia', 'PythiaSetPythonPath.so'))
    check_so_is_manylinux2014(os.path.join('@Pythia', 'PythiaSetPythonPath_x64.so'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Perform basic safety checks over the DLLs/SOs')
    parser.add_argument('version', help='Python version against which to check')

    args = parser.parse_args()

    safety_checks(args.version)
