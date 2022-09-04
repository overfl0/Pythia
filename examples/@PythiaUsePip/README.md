# @PythiaUsePip

This example shows how to use packages installed by pip.

Before you can use an external package, like `requests` in Python, you need to
make sure it is correctly installed. To do that, drag the `requirements.txt`
file over the `install_requirements*.bat` script. If you don't do that, Pythia
will fail while trying to import `requests`.

Make sure your requirements in the `requirements.txt` file are loose enough so
that different mods don't conflict later. using a mod with `requests==2.28.1`
and another with `requests==2.28.2` will cause issues with always unmet
requirements. See [requirement specifiers](https://pip.pypa.io/en/stable/reference/requirement-specifiers/)
for a way to set requirements that are more loose.

Note that the directory name is _irrelevant_. The package name depends on the
contents of the `$PYTHIA$` file only!

The addons directory contains a dummy PBO file to force Arma to load it as a
mod (which lets Pythia know that it should search the directories next to the
addons directory for Python code). You can omit that file as long as you have
_any_ PBO in your mod (which should always be the case unless you're making a
pure-Python mod).
