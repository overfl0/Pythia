import os
import shutil
import subprocess
import sys
from contextlib import contextmanager


@contextmanager
def ignore_no_file():
    try:
        yield
    except FileNotFoundError:
        pass


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

print('Packing the resulting mod to a zip file')
shutil.make_archive('@Pythia', 'zip', root_dir='.', base_dir='@Pythia')


# TODO: Use an empty directory to build
# TODO: Add building of the dlls
# TODO: Fix https://github.com/overfl0/Pythia/issues/41 to build the dlls
