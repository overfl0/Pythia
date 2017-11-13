print('### Importing subsecond')
from . import subsecond

print('### Importing from ..')
from ..file_one import fun as fileonefun

#import IPython; IPython.embed()

def fun(*args):
    return __file__

def fun2(*args):
    return subsecond.fun()

def fun3(*args):
    return fileonefun()
