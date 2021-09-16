import os
import urllib.request
import zipfile
from io import BytesIO

RELEASE_URL = "https://github.com/BrettMayson/bisign/releases/download/v0.2/bisign-win-x86_64.zip"
current_path = os.path.dirname(os.path.realpath(__file__))
directory = os.path.join(current_path, 'cache')


def install_bisign():
    if os.path.exists(os.path.join(directory, 'bisign.exe')):
        print('Executable bisign.exe already present, not installing')
        return

    # Download zip file
    print(f'* Downloading bisign.exe from {RELEASE_URL}...')
    file_raw = urllib.request.urlopen(RELEASE_URL).read()
    os.makedirs(directory, exist_ok=True)

    # Unpack it
    print('Extracting...')
    python_zip_file = zipfile.ZipFile(BytesIO(file_raw), 'r')
    python_zip_file.extractall(directory)


install_bisign()
