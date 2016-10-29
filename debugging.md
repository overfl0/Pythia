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

Create a symlink to your dll file by opening cmd.exe and typing:
`mklink <path_to_arma>\RVPython.dll <...>\Debug\python-poc.dll`

Visual Studio setup
-------------------

Select Debug->python-poc properties.
Go to debugging, and set:

* Command: `<path to arma3.exe>`
* Command Arguments: `-noLauncher -skipIntro -noSplash -window "<your mission.sqm file path>" -showScriptErrors`
* Working Directory: `<path to arma3.exe>`

Running
-------

Press `Ctrl+F5` to start without debugging and then `Ctrl+Alt+P` to attach to
Arma.
You can use a VS plugin called ReAttach to simplify attaching to the process.

That's it, you can now set your breakpoints and debug the dll.
