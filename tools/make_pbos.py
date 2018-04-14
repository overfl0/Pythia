import argparse
import os
import subprocess

PBO_SRC_DIR = ['src', 'Pythia', 'pbo']
PBO_DEST_DIR = ['@Pythia', 'Addons']
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

    base_dir = get_base_location()
    pbo_src_location = get_pbo_src_location()
    pbo_dest_location = get_destination_location()

    for node in os.listdir(pbo_src_location):
        full_path = os.path.join(pbo_src_location, node)
        print (full_path)

        if not os.path.isdir(full_path):
            continue

        print('Generating {}.pbo'.format(node))
        subprocess.check_call([MAKE_PBO, '-NUP', full_path, pbo_dest_location])

        if args.junction:
            junction_path = os.path.join(pbo_dest_location, node)
            create_junction(junction_path, full_path)


if __name__ == '__main__':
    main()
