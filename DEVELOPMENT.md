Running with a debugger
-----------------------

Somehow, it is impossible to run arma3.exe with a debugger, because it results
in error 81. Google tells that error has something to do with antiviruses so my
guess is that the process cannot be debugged when started. I may be wrong
though.

Anyway, while you can't run Arma3 in a debugger (if you can, contact me!), you
cat run it normally and attach to it with the debugger when it's running.

Remember to **not** run the debugger if BattlEye is also running, unless you
like bans, of course :).

Preparation
-----------

Run the Arma editor and create a simple mission: select VR for fast loading
times, put a soldier and save that mission somewhere.

Create a junction to the @Pythia directory by opening cmd.exe and typing:
`mklink /J <path_to_arma>\@Pythia <Project_directory>\@Pythia`

If you want to Modify the Adapter.py code, create another junction:
`mklink /J <path_to_arma>\python <Project_directory>\src\python`

Visual Studio setup
-------------------

Select Debug->Pythia properties.
Go to debugging, and set:

* Command: `<path to arma3.exe>`
* Command Arguments: `-skipIntro -noSplash -window -showScriptErrors -mod=@Pythia -filePatching "<path to your mission.sqm>"`
* Working Directory: `<path to arma3 directory>`

Running
-------

Press `Ctrl+F5` to start without debugging and then `Ctrl+Alt+P` to attach to
Arma.
You can use a VS plugin called ReAttach to simplify attaching to the process.

That's it, you can now set your breakpoints and debug the dll. Visual studio
will tell you that the breakpoints will not be hit but that's because the dll
is loaded only after the first `callExtension` call so it's not loaded yet.

Defines
-------

* `#define EXTENSION_DEVELOPMENT 1` in `EmbeddedPython.cpp` - Lets you reload
the python adapter each time you call the function allowing you to make changes
* `#define DEVMODE true` in `@Pythia/Addons/Pythia/fn_callExtension.sqf` - Lets
you do the same with the SQF file, assuming you have `-filePatching` enabled.

If you want to do some benchmarks, Remember to:
* Comment out `#define EXTENSION_DEVELOPMENT`
* Comment out `#define DEVMODE true`
* Select `Release` in Visual Studio.
