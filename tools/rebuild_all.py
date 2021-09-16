import os
import shutil
import subprocess
import sys

from common import print_and_delete
from create_dlls import msbuild_32, msbuild_64
from safety_checks import safety_checks

os.chdir(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

# Cleanup
print_and_delete('Removing @Pythia.zip', '@Pythia.zip')
print_and_delete('Removing Pythia Python 64-bit installation', '@Pythia', 'python-37-embed-amd64')
print_and_delete('Removing Pythia Python 32-bit installation', '@Pythia', 'python-37-embed-win32')
print_and_delete('Removing 32-bit Pythia binaries', 'vcproj')
print_and_delete('Removing 64-bit Pythia binaries', 'vcproj64')

subprocess.run([sys.executable, os.path.join('tools', 'create_pbos.py')], check=True)
subprocess.run([sys.executable, os.path.join('tools', 'create_embedded_python.py'), '@Pythia'], check=True)


# Build 32-bit
# msbuild_32()

# Build 64-bit
# msbuild_64()

# Post-build safety checks
safety_checks()

print('Packing the resulting mod to a zip file')
shutil.make_archive('@Pythia', 'zip', root_dir='.', base_dir='@Pythia')

# TODO: Use an empty directory to build the final mod
