<img src="assets/logo-200px.png" alt="Pythia logo" title="Pythia" align="right" width="200" height="200" />

Pythia
======

An Arma 3 extension that lets you to write python extensions for Arma 3. And it's really simple and straightforward to
use!

TL;DR:
------

    ["MyAwesomeModule.my_function", ["arg1", 3.14256, False]] call py3_fnc_callExtension

Calling the above will return the SQF array below, containing exactly what was returned from Python:

    ["awesome", 42, True, [1, 3.5]]

Features:
---------

- Full type conversion both ways: pass in an SQF array of ints, get a python array of ints. Return a tuple of a float,
a bool and a string, get an SQF array containing the float, bool and the string
- Embedded python installation (you don't have to install anything; just run the mod)
- Python code stored inside `@YourOwnMod` directory
- Python modules can call and reuse each other, even between separate Arma mods
- Background Python threads
- Cython and other compiled python extensions "just work" (C-like speed for performance-critical modules)
- Extendable python environment through pip
- Proven to work with libraries such as numpy, scipy, matplotlib, PyQt5, etc...
- Automatic python code reloader for easier development
- Calling SQF back from Python (experimental)
- Allows returning more than 10240 characters from the extension transparently
- Annoying sloppy SQF developers with correct code indentation since Day One ;)

#### Potential features

These features could be implemented quite easily but for some reason have never been done. Want them in or want to help
developing them? Contact the developers!

- Mods contained inside single .pbo files
- Calling functions in the background and polling for them

Example mods:
-------------

The following are mods that use Pythia to accomplish their goal.

### Frontline

<p align="center">
   <img src="assets/Arma_3_2017.08.18_-_02.45.27.39_2.gif" alt="Dynamic Frontline in action" />
</p>

[Frontline](https://frontline-mod.com) is like *Squad* but done in Arma. Like *Project Reality: Arma 3* but better. With a
*Dynamic Frontline* feature that moves as you conquer terrain (and a bunch of other features).

The frontline computation is done in Python, with the use of `numpy`, `scipy`, `matplotlib` and custom `Cython` code.

### ObjectPlacementTBH

<p align="center">
   <img src="assets/ObjectPlacement.jpg" alt="ObjectPlacementTBH" />
</p>

It's just a tool for object placement, to be honest... ;)

Pythia is used for loading in xml files, file IO, writing images using `PIL`, loading layers.cfg (using [Armaclass](https://github.com/overfl0/Armaclass)).
The newest version is using `PyQt5` to [display Qt widgets over the Arma window](https://www.youtube.com/watch?v=Jt4eFG1sM50).

Status
------

Current status: Finishing touches before 1.0. You can use it right now - it's stable. Yes, really.

If you are serious about using Pythia, see [the issues page](https://github.com/overfl0/Pythia/issues) and especially
[this one](https://github.com/overfl0/Pythia/issues/9). You can contact me to ask for planned changes, on [Frontline's
Discord channel](https://discordapp.com/invite/TckWzF9). I don't bite :).

Example usage
------

Your directory structure:
```
@MyAwesomeMod/
├── Addons/  # (...)
└── python_code/  # Can be named however you want; you can have more than one
    ├── $PYTHIA$  # Contains the name of your python package, for example: MyAwesomeModule
    ├── __init__.py
    ├── module.py
    └── cython_module.cp35-win_amd64.pyd  # Compiled Cython code, because we can!
```

`__init__.py`:
```python
def my_function(my, arguments):
    return ["awesome", 42, True, (1, 2)]
```

`module.py`:
```python
from .cython_module import stuff  # You can import code from other modules, obviously

def call_stuff():
    return stuff()
```

Now run Arma 3 with `-mod=@Pythia;@MyAwesomeMod` and execute the following:

---

*Console:*

    ["MyAwesomeModule.my_function", [3.14256, False]] call py3_fnc_callExtension

*Result:*

    ["awesome", 42, True, [1, 2]]

---

*Console:*

    ["MyAwesomeModule.module.call_stuff"] call py3_fnc_callExtension


*Result:*

    ["Hello world from a Cython module!"]

*Note: `MyAwesomeModule` is the string that was in the `$PYTHIA$` file. You can use any string you want here,
obviously.*

Performance:
------------

The code is written with performance in mind, meaning that function lookups are cached to limit the number of
`getattr`s, for example. However, keep in mind that the accessibility requirements (SQF <=> Python type conversion) and
the general overhead caused by BIs design choice of allowing passing only strings to `callExtension` must take its toll.
I'm open to implementing an alternate set of restricted commands that swap convenience for speed, if required, though...

As such, it is suggested to limit the number of python calls in each frame. It is still faster to call one function with
two sets of arguments than two functions, one right after the other.

#### Concrete numbers:

The test below was executed by calling `pythia.ping` with different types of arguments, meaning that each list of
arguments had to be converted to python and the return value had to be converted back to SQF. Each test was conducted 3
times and the lowest value was written down.

The exact arguments for each test can be found on [the scratchpad](https://github.com/overfl0/Pythia/wiki/Scratchpad).

|  #  | Type of arguments | 10 arguments | 100 arguments |
| --- | ----------------- | :----------: | :-----------: |
|  1  | Integers          | 0.0198 ms    | 0.0858 ms     |
|  2  | Floats            | 0.0225 ms    | 0.1091 ms     |
|  3  | Booleans          | 0.0155 ms    | 0.0580 ms     |
|  4  | Strings           | 0.0161 ms    | 0.0580 ms     |
|  5  | Arrays with ints  | 0.0318 ms    | 0.2086 ms     |
|  6  | Empty arrays      | 0.0153 ms    | 0.0555 ms     |

Note that you will probably usually pass a number of arguments lower than 10 (and if you don't, your function will most
probably be slower than the (de)serializing overhead) so you can assume that **each Pythia call takes around 0.02 ms**
on a recent computer.

This allows for **under 150 Pythia calls per frame** if you want to stay under the 3ms arbitrary limit (arbitrary
because the callExtension calls are not really limited by the engine, they just block execution until finished).

*Note: You may get away with calls that take even 100 ms server-side, if they happen rarely enough.*

*Note: If your code is REALLY big and slow consider using a background Python thread. See below.*

Your own mod development
========================

Code reloader
-------------

Note: The reloader currently only works for native python code. If your code uses Cython or C extensions (dll/pyd files)
you should test your code using standalone unit tests.

```
["pythia.enable_reloader", [True]] call py3_fnc_callExtension
```

TODO

Threads
-------
TODO

Installing
----------

- Build the mod yourself or get a prebuilt version.
- Copy `@Pythia` to `Arma 3` directory.
- (Optional for development) Create a `python` directory in `Arma 3` directory. Put all your python functions there.

Pythia development
==================

Building requirements
---------------------

- Python 3.5 (64-bit for 64-bit Arma, 32-bit otherwise; it is suggested to have both installed)
- Visual Studio Community 2017

Building
--------

- File -> Open -> CMake: `CmakeLists.txt`, make sure that `Release` configuration is selected
  (instead of `Debug`) and CMake -> Build All.
- Run `python tools\make_pbos.py` to build the required PBO files.

Contributing
------------

All contributions are welcome! Feel free to submit a PR or drop a note on
[Frontline's Discord channel](https://discordapp.com/invite/TckWzF9).
