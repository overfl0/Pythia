Pythia
======

An Arma 3 extension that allows you to write python extensions

Building requirements
---------------------

- Python 3
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
`["python.samplemodule.sample_function", "first", "second", 3] call py3_fnc_callExtension)`

This will open the directory `Arma 3\python`, load the file `samplemodule.py`,
call the python function `sample_function("first", "second", 3)` and return the
value returned by that function to SQF.

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
