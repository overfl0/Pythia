import os
import shutil
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


def print_and_delete(message, *path):
    print(message)
    full_path = os.path.realpath(os.path.join(*path))
    if not os.path.exists(full_path):
        return

    if os.path.isfile(full_path):
        os.remove(full_path)
    elif os.path.isdir(full_path):
        shutil.rmtree(full_path)
    else:
        print('Error: I don\'t know what this file type is!')
