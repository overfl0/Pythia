# @PythiaClasses

This example shows how to call methods from classes.

At this point in time, you need to create a separate function for each method
you want to call a method on an instance of the class.

Note that the directory name is _irrelevant_. The package name depends on the
contents of the `$PYTHIA$` file only!

The addons directory contains a dummy PBO file to force Arma to load it as a
mod (which lets Pythia know that it should search the directories next to the
addons directory for Python code). You can omit that file as long as you have
_any_ PBO in your mod (which should always be the case unless you're making a
pure-Python mod).
