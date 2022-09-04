# @PythiaLogging

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


DO NOT pass arbitrary strings from SQF as the first argument!
If you do:
```python
def write_message(message):
    logger.log(message)  # Do NOT write like that!
```
and someone calls
```sqf
["logging_example.write_message", ["This will mess things up %s"]] call py3_fnc_callExtension
```
then the `%s` in the message will cause the logger to try to replace it with
the second argument to the `log()` call (which doesn't exist).

This is the correct way to log:
```python
def write_message(message):
    logger.log('%s', message)  # Correct!
```
