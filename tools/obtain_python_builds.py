import argparse
import json
import urllib.request
from dataclasses import dataclass
from json import JSONDecodeError
from pathlib import Path


# https://docs.github.com/en/rest/releases/releases
GITHUB_RELEASES_URL = 'https://api.github.com/repos/overfl0/Pythia/releases?per_page=100'
GITHUB_RELEASES_URL_BACKUP = 'https://api.github.com/repos/indygreg/python-build-standalone/releases?per_page=100'

BASE_URL = Path(__file__).parent
RELEASES = BASE_URL / 'cache' / 'releases.json'
RELEASES_BACKUP = BASE_URL / 'cache' / 'releases_backup.json'


@dataclass
class Result:
    name: str
    url: str


def get_python_build_standalone_releases(use_cache=True, backup=False):
    filename = RELEASES_BACKUP if backup else RELEASES
    url = GITHUB_RELEASES_URL_BACKUP if backup else GITHUB_RELEASES_URL
    if use_cache:
        try:
            with open(filename, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, JSONDecodeError) as e:
            pass  # Fall through to fetch the data online

    file_contents = urllib.request.urlopen(url).read()
    json_data = json.loads(file_contents)

    with open(filename, 'w') as f:
        json.dump(json_data, f, indent=4)

    return json_data


def _find_python_release(version, use_cache=True, backup=False):
    results = []
    if version == '':
        return ValueError('Empty version provided')

    data = get_python_build_standalone_releases(use_cache=use_cache, backup=backup)
    for release in data:
        for asset in release['assets']:
            if not asset['name'].endswith('.zst'):
                continue

            if asset['name'].startswith(f'cpython-{version}-') or asset['name'].startswith(f'cpython-{version}+'):
                results.append(Result(asset['name'], asset['browser_download_url']))
            # print(asset['name'], asset['browser_download_url'])

    return results


def find_python_release(version):
    results = _find_python_release(version, use_cache=True)
    if not results:
        print(f'Python version {version} not found. Refreshing cache')
        results = _find_python_release(version, use_cache=False)

    if not results:
        print(f'Python version {version} still not found. Trying backup')
        results = _find_python_release(version, use_cache=True, backup=True)

    if not results:
        print(f'Python version {version} still not found. Refreshing backup cache')
        results = _find_python_release(version, use_cache=False, backup=True)

    return results


def get_relevant_releases(version, arch=None, windows=None):
    all_pythons = find_python_release(version)
    if not all_pythons:
        return all_pythons

    results = [
        list(filter(lambda result: f'-i686-pc-windows-msvc-shared-pgo-' in result.name, all_pythons))[0],
        list(filter(lambda result: f'-i686-unknown-linux-gnu-pgo+lto-' in result.name, all_pythons))[0],
        list(filter(lambda result: f'-x86_64-unknown-linux-gnu-pgo+lto-' in result.name, all_pythons))[0],
        list(filter(lambda result: f'-x86_64-pc-windows-msvc-shared-pgo-' in result.name, all_pythons))[0],
    ]

    if arch is not None:
        results = list(filter(lambda result: f'-{arch}-' in result.name, results))

    if windows is not None:
        results = list(filter(lambda result: ('-windows-' if windows else '-linux-') in result.name, results))

    return results


def show_releases(version):
    results = get_relevant_releases(version)

    for result in results:
        print(result.name)


def fetch_releases(version, arch=None, windows=None):
    results = get_relevant_releases(version, arch=arch, windows=windows)

    for result in results:
        print(f'Fetching {result.name}...')
        file_contents = urllib.request.urlopen(result.url).read()
        with open(result.name, 'wb') as f:
            f.write(file_contents)

    return [result.name for result in results]


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--preview', action='store_true',
                        help='Show versions that will be downloaded')
    parser.add_argument('version')
    args = parser.parse_args()

    if args.preview:
        show_releases(args.version)
    else:
        fetch_releases(args.version)
