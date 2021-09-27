import argparse
import glob
import os
import shutil
import subprocess
import sys

from install_bisign import install_bisign
from primitive_git import get_sha1_from_git_directory

PBO_SRC_DIR = ['src', 'Pythia', 'pbo']
PBO_DEST_DIR = ['@Pythia', 'addons']
KEYS_DIR = ['@Pythia', 'keys']
MAKE_PBO = r'C:\Program Files (x86)\Mikero\DePboTools\bin\makepbo.exe'  # It's not in the PATH in AppVeyor


def get_base_location():
    """Get base Pythia directory."""

    python_file = os.path.realpath(__file__)
    python_dir = os.path.dirname(python_file)
    base_dir = os.path.dirname(python_dir)

    return base_dir


def get_pbo_src_location():
    return os.path.join(get_base_location(), *PBO_SRC_DIR)


def get_destination_location():
    return os.path.join(get_base_location(), *PBO_DEST_DIR)


def get_keys_dir():
    return os.path.join(get_base_location(), *KEYS_DIR)


def get_bisign_executable():
    location = os.path.join(get_base_location(), 'tools', 'cache')
    executable = os.path.join(location, 'bisign.exe')
    return executable


def create_private_public_key(prefix, use_git=True):
    bisign = get_bisign_executable()
    print(f'Creating private/public keypair using {bisign}')
    key_name = prefix
    if use_git:
        key_name += '_' + get_sha1_from_git_directory(get_base_location())[:8]
    subprocess.check_call([bisign, 'keygen', key_name])

    return f'{key_name}.biprivatekey', f'{key_name}.bikey'


def sign_file(file_path, private_key):
    bisign = get_bisign_executable()
    print(f'Signing {file_path}...')
    subprocess.check_call([bisign, 'sign', private_key, file_path])


def create_junction(symlink_name, orig_path):
    """Create an NTFS Junction.
    For now, just use subprocess. Maybe switch to native libs later.
    """
    if os.path.exists(symlink_name):
        os.unlink(symlink_name)

    return subprocess.check_call(['cmd', '/c', 'mklink', '/J', symlink_name, orig_path])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--junction', '-j', action='store_true', help='Create a junction')
    args = parser.parse_args()

    pbo_src_location = get_pbo_src_location()
    pbo_dest_location = get_destination_location()

    if not os.path.exists(MAKE_PBO):
        print('Error! Can\'t find makepbo at {}'.format(MAKE_PBO))
        return 1

    files = []
    for node in os.listdir(pbo_src_location):
        full_path = os.path.join(pbo_src_location, node)
        print(full_path)

        if not os.path.isdir(full_path):
            continue

        print('Generating {}.pbo'.format(node))
        subprocess.check_call([MAKE_PBO, '-P', full_path, pbo_dest_location])
        files.append(str(os.path.join(pbo_dest_location, node)) + '.pbo')

        if args.junction:
            junction_path = os.path.join(pbo_dest_location, node)
            create_junction(junction_path, full_path)

    # Keys handling
    install_bisign()

    # Ensure keys directory is clean
    keys_dir = get_keys_dir()
    if os.path.exists(keys_dir):
        shutil.rmtree(keys_dir)
    os.mkdir(keys_dir)
    with open(os.path.join(keys_dir, 'DO NOT COPY THESE FILES IF YOU\'RE RUNNING PYTHIA AS A SERVER MOD'), 'w'):
        pass

    private_key, public_key = create_private_public_key('pythia')

    # Sign all the PBOs
    try:
        shutil.move(os.path.join(public_key), get_keys_dir())
        for file_path in files:
            for signature_file in glob.iglob(glob.escape(file_path) + '*.bisign'):
                print(f'Removing od signature file: {signature_file}')
                os.unlink(signature_file)

            sign_file(file_path, private_key)
    finally:
        os.remove(private_key)


if __name__ == '__main__':
    sys.exit(main())
