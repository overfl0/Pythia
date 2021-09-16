import os
import shutil
import subprocess
import sys

from common import print_and_delete, check_dll_is_static


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


os.chdir(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

# Cleanup
print_and_delete('Removing @Pythia.zip', '@Pythia.zip')
print_and_delete('Removing Pythia Python 64-bit installation', '@Pythia', 'python-37-embed-amd64')
print_and_delete('Removing Pythia Python 32-bit installation', '@Pythia', 'python-37-embed-win32')
print_and_delete('Removing 32-bit Pythia binaries', 'vcproj')
print_and_delete('Removing 64-bit Pythia binaries', 'vcproj64')

subprocess.run([sys.executable, os.path.join('tools', 'make_pbos.py')], check=True)
subprocess.run([sys.executable, os.path.join('tools', 'create_embedded_python.py'), '@Pythia'], check=True)

# Build 32-bit
print('Building 32-bit Pythia')
os.mkdir('vcproj')
os.chdir('vcproj')
subprocess.run(['cmake', '..', '-G', 'Visual Studio 16 2019', '-A', 'Win32'], check=True)
os.chdir('..')
subprocess.run(['cmake', '--build', 'vcproj', '--config', 'RelWithDebInfo'], check=True)

# Build 64-bit
print('Building 64-bit Pythia')
os.mkdir('vcproj64')
os.chdir('vcproj64')
subprocess.run(['cmake', '..', '-G', 'Visual Studio 16 2019', '-A', 'x64'], check=True)
os.chdir('..')
subprocess.run(['cmake', '--build', 'vcproj64', '--config', 'RelWithDebInfo'], check=True)

# Post-build safety checks
check_dll_is_static(os.path.join('@Pythia', 'Pythia.dll'), allowed_imports=[b'python37.dll'])
check_dll_is_static(os.path.join('@Pythia', 'Pythia_x64.dll'), allowed_imports=[b'python37.dll'])
check_dll_is_static(os.path.join('@Pythia', 'PythiaSetPythonPath.dll'))
check_dll_is_static(os.path.join('@Pythia', 'PythiaSetPythonPath_x64.dll'))
print()
check_dll_architecture(os.path.join('@Pythia', 'Pythia.dll'), x86=True)
check_dll_architecture(os.path.join('@Pythia', 'Pythia_x64.dll'), x86=False)
check_dll_architecture(os.path.join('@Pythia', 'PythiaSetPythonPath.dll'), x86=True)
check_dll_architecture(os.path.join('@Pythia', 'PythiaSetPythonPath_x64.dll'), x86=False)

print('Packing the resulting mod to a zip file')
shutil.make_archive('@Pythia', 'zip', root_dir='.', base_dir='@Pythia')

# TODO: Use an empty directory to build the final mod
