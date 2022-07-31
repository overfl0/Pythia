import os
import re
import shutil
from contextlib import contextmanager


THIS_DIR = os.path.dirname(__file__)


@contextmanager
def ignore_no_file():
    try:
        yield
    except FileNotFoundError:
        pass


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


def get_python_version():
    with open(os.path.join(THIS_DIR, '..', '.github', 'workflows', 'build.yml'), 'r') as f:
        return re.search('PYTHON_VERSION: ([0-9.]+)', f.read()).group(1)
