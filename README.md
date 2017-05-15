Pythia
======

An Arma 3 extension that allows you to write python extensions

Building requirements
---------------------

- Python 3.5 (64-bit for 64-bit Arma, 32-bit otherwise)
- Visual Studio Community 2015

Building
--------

- Open `Pythia.sln`, make sure that `Release` configuration is selected
  (instead of `Debug`) and press F7.
- Run `python tools\make_pbos.py` to build the required PBO files.

Installing
----------

- Build the mod yourself or get a prebuilt version.
- Copy `@Pythia` to `Arma 3` directory.
- Create a `python` directory in `Arma 3` directory. Put all your python functions there.

Running
-------

Run Arma 3 with `-mod=@Pythia`.

In SQF, execute:

```
hint str(["pythia.test"] call py3_fnc_callExtension)
```

This should reply with a `OK` hint message, if Pythia is working correctly. If it doesn't, ensure you've installed the right version of Python (currently 3.5 is supported) and that you're using 64-bit Python if you're using 64-bit Arma and 32-bit Python otherwise. You can install both Python versions to be safe.

```
hint str(["pythia.ping", "first", "second", 3] call py3_fnc_callExtension)
```

This should echo back all the arguments you're passing to the function.

In general, to call a custom (non-internal function), do the following:

```
["python.samplemodule.sample_function", "first", "second", 3] call py3_fnc_callExtension)
```

This will open the directory `Arma 3\python`, load the file `samplemodule.py`,
call the python function `sample_function("first", "second", 3)` and return the
value returned by that function to SQF.

Of course, you first need to create such a file.

Examples:
---------
In samplemodule.py:
```python
def print_args(*args):
    return_string = 'Received args: {}'.format(args)
    return return_string
```

In SQF:
```
["python.samplemodule.print_args", "First", "Second", 3] call py3_fnc_callExtension
```

Result: `"Received args: ('First', 'Second', 3)"`

---

In samplemodule.py:
```python
def get_multiples(multiplier, count):
    return [i * multiplier for i in range(count)]
```

In SQF:
```
["python.samplemodule.get_multiples", 3, 6] call py3_fnc_callExtension
```

Result: `[0, 3, 6, 9, 12, 15]`
