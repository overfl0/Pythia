import contextlib
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import xml.etree.ElementTree as ET

"""Fetch and install missing Mikero's tools"""

toms_depot = 'http://tom4897.info/app/tools/community/'
disk_location = r'C:\Program Files (x86)\Mikero\DePboTools\bin' + '\\'

required_tools = {
    'DePbo': disk_location + 'DePbo64.dll',
    'MakePbo': disk_location + 'MakePbo.exe',
    'DeOgg': disk_location + 'deOgg64.dll',
}


@contextlib.contextmanager
def tempdir(prefix='tmp'):
    """A context manager for creating and then deleting a temporary directory."""
    tmpdir = tempfile.mkdtemp(prefix=prefix)
    try:
        yield tmpdir
    finally:
        shutil.rmtree(tmpdir)


def download_and_run(url, file_name):
    print ('Downloading {} from: {}'.format(file_name.split('.')[0], url))
    with tempdir() as directory:
        file_path = os.path.join(directory, file_name)
        file_raw = urllib.request.urlopen(url).read()

        with open(file_path, "wb") as location:
            location.write(file_raw)

        print('Running installer...')
        subprocess.check_call([file_path, '/S'], shell=True)


def all_installed(required_tools):
    for tool_name, tool_path in required_tools.items():
        if not os.path.exists(tool_path):
            return False

    return True


def install_tools(required_tools):
    xml = urllib.request.urlopen(toms_depot + 'xml').read()
    root = ET.fromstring(xml)
    tools = root.findall('tool')

    print('Fetching and installing tools...')

    for tool_name, tool_path in required_tools.items():
        if os.path.exists(tool_path):
            print('{} is already installed, continuing...'.format(tool_name))
            continue

        tool = root.find("tool[@toolName='{}']".format(tool_name))
        file_name = tool.get('fileName')
        download_url = toms_depot + file_name

        download_and_run(download_url, file_name)


def main():
    if all_installed(required_tools):
        print('All required Mikero tools are already installed. Exiting...')
        sys.exit(0)

    install_tools(required_tools)


if __name__ == '__main__':
    main()
