# @PythiaBasic

This example shows how to call simple Python functions from SQF.

There are two directories: `basic` and `second` and each of them is considered
a separate python package because they have a separate `$PYTHIA$` file inside.
As such, calling `basic.hello` and `second.hello` will call the functions from
the respective packages.

Note that the directory name is _irrelevant_. The package name depends on the
contents of the `$PYTHIA$` file only!

The addons directory contains a dummy PBO file to force Arma to load it as a
mod (which lets Pythia know that it should search the directories next to the
addons directory for Python code). You can omit that file as long as you have
_any_ PBO in your mod (which should always be the case unless you're making a
pure-Python mod).
