import os
import shutil
import subprocess
import sys
from contextlib import contextmanager
from typing import List


@contextmanager
def ignore_no_file():
    try:
        yield
    except FileNotFoundError:
        pass


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


os.chdir(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

with ignore_no_file():
    print('Removing @Pythia.zip')
    os.remove('@Pythia.zip')

with ignore_no_file():
    print('Removing Pythia Python 64-bit installation')
    shutil.rmtree(os.path.realpath(os.path.join('@Pythia', 'python-37-embed-amd64')))

with ignore_no_file():
    print('Removing Pythia Python 32-bit installation')
    shutil.rmtree(os.path.join('@Pythia', 'python-37-embed-win32'))

subprocess.run([sys.executable, os.path.join('tools', 'make_pbos.py')], check=True)
subprocess.run([sys.executable, os.path.join('tools', 'create_embedded_python.py'), '@Pythia'], check=True)

check_dll_is_static(os.path.join('@Pythia', 'Pythia.dll'), allowed_imports=[b'python37.dll'])
check_dll_is_static(os.path.join('@Pythia', 'Pythia_x64.dll'), allowed_imports=[b'python37.dll'])
check_dll_is_static(os.path.join('@Pythia', 'PythiaSetPythonPath.dll'))
check_dll_is_static(os.path.join('@Pythia', 'PythiaSetPythonPath_x64.dll'))

print('Packing the resulting mod to a zip file')
shutil.make_archive('@Pythia', 'zip', root_dir='.', base_dir='@Pythia')


# TODO: Use an empty directory to build
# TODO: Add building of the dlls
# TODO: Fix https://github.com/overfl0/Pythia/issues/41 to build the dlls
