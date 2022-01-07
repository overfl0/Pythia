def cython_function(*args):
    # if libpython3.X.so symbols are not preloaded, this will fail with
    # undefined symbol: PyExc_ImportError
    # https://stackoverflow.com/a/60746446/6543759
    # https://docs.python.org/3/whatsnew/3.8.html#changes-in-the-c-api
    import numpy as np

    return 'Hello from numpy cython!'
