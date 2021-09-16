import os
import subprocess


def msbuild_32():
    print('Building 32-bit Pythia')
    os.mkdir('vcproj')
    os.chdir('vcproj')
    subprocess.run(['cmake', '..', '-G', 'Visual Studio 16 2019', '-A', 'Win32'], check=True)
    os.chdir('..')
    subprocess.run(['cmake', '--build', 'vcproj', '--config', 'RelWithDebInfo'], check=True)


def msbuild_64():
    print('Building 64-bit Pythia')
    os.mkdir('vcproj64')
    os.chdir('vcproj64')
    subprocess.run(['cmake', '..', '-G', 'Visual Studio 16 2019', '-A', 'x64'], check=True)
    os.chdir('..')
    subprocess.run(['cmake', '--build', 'vcproj64', '--config', 'RelWithDebInfo'], check=True)
