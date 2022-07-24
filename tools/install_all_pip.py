import json
import os
import subprocess
import sys
import textwrap
import urllib.request

from tqdm import tqdm

URL = 'https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.json'
FILENAME = 'top-pypi-packages-30-days.json'
ABS_FILE = os.path.join(os.path.dirname(__file__), FILENAME)
BLACKLIST = {
    'typing-extensions',
}
COUNT = 100


def pip_download(package):
    cmd = [sys.executable, '-m', 'pip', 'download', package]
    # print(' '.join(cmd))
    subprocess.run(cmd, check=True)


def pip_install(package):
    cmd = [sys.executable, '-m', 'pip', 'install', package]
    # print(' '.join(cmd))
    subprocess.run(cmd, check=True)


def check(package):
    stub_39 = textwrap.dedent(f'''\
        import importlib, importlib.metadata, os
        dist_path = importlib.metadata.distribution("{package}")._path
        module_name = open(os.path.join(dist_path, "top_level.txt")).read().strip().splitlines()[-1].replace('/', '.')
        importlib.import_module(module_name)
        ''')
    stub_37 = textwrap.dedent(f'''\
        import importlib, pkg_resources, os
        dist_path = pkg_resources.get_distribution("{package}").egg_info
        module_name = open(os.path.join(dist_path, "top_level.txt")).read().strip().splitlines()[-1].replace('/', '.')
        importlib.import_module(module_name)
        ''')
    cmd = [sys.executable, '-c', ';'.join(stub_37.split('\n'))]
    print(' '.join(cmd))
    subprocess.run(cmd, check=True)


def main():
    if not os.path.isfile(ABS_FILE):
        print('Not in cache, downloading...')
        with urllib.request.urlopen(URL) as f:
            data = f.read().decode('utf-8')
            with open(ABS_FILE, 'w') as fw:
                fw.write(data)

    with open(ABS_FILE) as f:
        data = json.load(f)

        for row in tqdm(data['rows'][:COUNT]):
            project = row['project']
            if project in BLACKLIST:
                continue

            print(project)
            pip_install(project)
            check(project)


if __name__ == '__main__':
    main()
