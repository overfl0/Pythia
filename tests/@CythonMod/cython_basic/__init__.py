import os
import subprocess
import sys


def compile_python_extension_do_not_use_this_way(setup_py_path):
    """
    Note: DON'T do this normally. This is just a workaround to ensure
    that the right python interpreter is called!

    You're supposed to have a script that will probably call both pythons in
    sequence to build the extension for both 32bit and 64bit.
    """
    current_dir = os.getcwd()
    abs_executable = os.path.abspath(sys.executable)
    try:
        os.chdir(setup_py_path)
        cmd = [abs_executable, 'setup.py', 'build_ext', '--inplace']
        process = subprocess.run(cmd, capture_output=True)
        return process.stdout.decode('utf8'), process.stderr.decode('utf8'), process.returncode
    finally:
        os.chdir(current_dir)


def function(*args):
    """
    Note: Don't do this either. The import should be at the top of the file!

    We're doing this just because the import would fail if we wouldn't have
    already called the `compile()` function above.
    """
    from .cython_module import cython_function  # Import at the top of the file!
    return cython_function(args)
