# If this fails, that means that you haven't installed numpy using the
# install_requirements.bat script. See README.md for details
import numpy


def generate_random():
    """
    Generates random samples from a normal (Gaussian) distribution.
    To execute this function, call:
    ["numpy_example.generate_random", []] call py3_fnc_callExtension

    Make sure you've installed the pip requirements first! See README.md.

    Returning a numpy array will work because Pythia can iterate over it and
    convert it to a regular list, but you generally should make sure that you
    are returning correct types to SQF-land.
    """
    return numpy.random.normal(loc=[2., 20.], scale=[1., 3.5], size=(3, 2))
