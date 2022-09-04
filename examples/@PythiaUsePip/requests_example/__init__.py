import requests


def get_last_sitrep():
    """
    Returns the title of the last SITREP/SPOTREP from the Arma site
    To execute this function, call:
    ["requests_example.get_last_sitrep", []] call py3_fnc_callExtension

    Note that this function may take a long time and block ALL Arma scripts
    execution. If you need to call this more often, consider spawning a Python
    Thread.

    See examples/@PythiaThread.
    """
    url = 'https://arma3.com/loadDev'

    req = requests.get(url)
    if req.status_code != 200:
        return f'Error fetching data. Status code: {req.status_code}'

    return req.json()[0]['title']


if __name__ == '__main__':
    print(get_last_sitrep())
