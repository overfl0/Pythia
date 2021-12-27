def get_requests_version():
    import requests
    return requests.__version__


def uninstall_requests():
    import pip
    pip.main(['uninstall', '-y', 'requests'])
