import os
import sys
from typing import List


def check_dll_architecture(path: str, x86=False):
    arch = '32bit' if x86 else '64bit'
    print(f'Checking is file {path} is {arch}...')
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

    print(f'Checking is file {path} is static...')
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


def safety_checks():
    check_dll_is_static(os.path.join('@Pythia', 'Pythia.dll'), allowed_imports=[b'python37.dll'])
    check_dll_is_static(os.path.join('@Pythia', 'Pythia_x64.dll'), allowed_imports=[b'python37.dll'])
    check_dll_is_static(os.path.join('@Pythia', 'PythiaSetPythonPath.dll'))
    check_dll_is_static(os.path.join('@Pythia', 'PythiaSetPythonPath_x64.dll'))
    print()
    check_dll_architecture(os.path.join('@Pythia', 'Pythia.dll'), x86=True)
    check_dll_architecture(os.path.join('@Pythia', 'Pythia_x64.dll'), x86=False)
    check_dll_architecture(os.path.join('@Pythia', 'PythiaSetPythonPath.dll'), x86=True)
    check_dll_architecture(os.path.join('@Pythia', 'PythiaSetPythonPath_x64.dll'), x86=False)


if __name__ == '__main__':
    safety_checks()
