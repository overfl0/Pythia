import importlib
import importlib.abc
import importlib.machinery
import importlib.util
import logging
import logging.handlers
import os
import site
import sys
import time
import traceback
import types

import pythiainternal
import pythialogger as logger

# If you want the user modules to be reloaded each time the function is called, set this to True
PYTHON_MODULE_DEVELOPMENT = False

COROUTINES_DICT = {}
COROUTINES_COUNTER = 0

def create_root_logger(name):
    file_handler = logging.handlers.RotatingFileHandler('pythia.log', maxBytes=1024*1024, backupCount=10)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(name)s] %(message)s')
    file_handler.setFormatter(formatter)

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    logger.name = name

    return logger

mod_logger = create_root_logger(__name__)

logger.info('=' * 80)
logger.info('Pythia is starting up...')
logger.info('=' * 80)
logger.info('sys.path: {}'.format(sys.path))
logger.info('sys.prefix: {}'.format(sys.prefix))
logger.info('sys.base_prefix: {}'.format(sys.base_prefix))
logger.info('sys.exec_prefix: {}'.format(sys.exec_prefix))
logger.info('sys.base_exec_prefix: {}'.format(sys.base_exec_prefix))
logger.info('sys.flags: {}'.format(sys.flags))
logger.info('site.ENABLE_USER_SITE: {}'.format(site.ENABLE_USER_SITE))
logger.info('site.USER_BASE: {}'.format(site.USER_BASE))
logger.info('site.USER_SITE: {}'.format(site.USER_SITE))
logger.info('site.PREFIXES: {}'.format(site.PREFIXES))
logger.info('site.getsitepackages(): {}'.format(site.getsitepackages()))
logger.info('=' * 80)


def split_by_len(item, itemlen, maxlen):
    """"Requires item to be sliceable (with __getitem__ defined)."""
    return [item[ind:ind + maxlen] for ind in range(0, itemlen, maxlen)]


def format_error_string(stacktrace_str):
    """Return a formatted exception."""
    # return '["e", "{}"]'.format(stacktrace_str.replace('"', '""'))
    return ("e", stacktrace_str)


def format_response_string(return_value, sql_call=False, coroutine_id=None):
    """Return a formatted response.
    For now, it's just doing a dumb str() which may or may not work depending
    on the arguments passed. This should work as long as none of the arguments
    contain double quotes (").
    """
    if sql_call:
        return ("s", coroutine_id, return_value)

    return ("r", return_value)


class PythiaExecuteException(Exception):
    pass


class PythiaImportException(Exception):
    pass


def handle_function_calling(function, args):
    """Calls the given function with the given arguments and formats the response."""
    global COROUTINES_DICT, COROUTINES_COUNTER

    if function == continue_coroutine:
        # Special handling
        return function(*args)

    # Call the requested function with the given arguments
    return_value = function(*args)

    if isinstance(return_value, types.CoroutineType):
        # This is a coroutine and has to be handled differently
        try:
            # Run the coroutine and get the yielded value
            yielded_value = return_value.send(None)

            COROUTINES_COUNTER += 1
            COROUTINES_DICT[COROUTINES_COUNTER] = return_value

            return format_response_string(yielded_value, True, COROUTINES_COUNTER)

        except StopIteration as iteration_exception:
            # The function has ended with a "return" statement
            return format_response_string(iteration_exception.value)

    else:
        return format_response_string(return_value)


def import_and_strip_traceback(full_module_name):
    """
    Suppress unneeded traceback that the user doesn't even care about.

    Import the module and in case of an error remove traceback entries that
    don't pertain to user-controlled code. In other words: delete all the
    frames that pertain to internal module loading processes.
    Do this by fetching the file name of the loaded module and only print
    traceback frames that show AFTER the file is shown in the traceback.

    Also because the import issue may come from a parent module that has not
    yet been imported and would automatically be imported during importing of
    the child module, we're importing all the parent modules first to ensure
    that we will catch the right exception.

    This may hide errors in the loading process so this functionality may have
    to be disabled to debug module loading issues.
    """
    # Based on https://stackoverflow.com/a/45771867

    try:
        # Import all the parent modules first to catch all the errors therein
        names = full_module_name.split('.')
        if not len(names) == 1:
            for i in range(1, len(names)):
                module_name = '.'.join(names[:i])
                # FIXME: A sys.modules entry can contain None in which case import_module will raise ImportError
                importlib.import_module(module_name)

        # All the parent modules have been imported. Now import the actual module
        module_name = full_module_name
        return importlib.import_module(module_name)

    except Exception as ex:
        spec = importlib.util.find_spec(module_name)
        if spec is None:
            # if the module is not found, then do not print traceback at all
            count = 0

        else:
            fileName = spec.loader.get_filename(module_name)
            extracts = traceback.extract_tb(sys.exc_info()[2])
            count = len(extracts)
            # find the first occurrence of the module file name
            for i, extract in enumerate(extracts):
                if extract[0] == fileName:
                    break
                count -= 1

        raise PythiaImportException(traceback.format_exc(limit=-count, chain=False))


def python_adapter(sqf_args):
    """The extension entry point in python."""

    global FUNCTION_CACHE
    global RELOADER_ENABLED

    try:
        if RELOADER_ENABLED:
            # Check if some files have changed and may need reloading
            check_reload()

        # Allow calling a [function_name] from SQF and just assume args = [] in that case
        if len(sqf_args) == 1:
            full_function_name = sqf_args[0]
            function_args = []
        else:
            try:
                full_function_name, function_args = sqf_args
            except ValueError:
                raise PythiaExecuteException('The syntax for calling a function is: [function_name, [args]]')

        if not isinstance(function_args, list):
            raise PythiaExecuteException('The arguments of a function need to be passed in an array')

        try:
            # Raise dummy exception if needs force-reload
            if PYTHON_MODULE_DEVELOPMENT:
                if full_function_name not in PYTHIA_INTERNAL_FUNCTIONS:
                    raise KeyError('Dummy KeyError')

            function = FUNCTION_CACHE[full_function_name]

        except KeyError:  # Function not cached, load the module
            function_path, function_name = full_function_name.rsplit('.', 1)

            # Prevent calling arbitrary python functions
            base_module = function_path.split('.')[0]
            if(base_module != 'python' and
               base_module != 'pythia' and
               base_module not in PythiaModuleWrapper.modules):
                message = 'Pythia module \'{}\' not recognized! Have you loaded the right Arma mods?'
                raise PythiaImportException(message.format(base_module))

            try:
                module = sys.modules[function_path]

            except KeyError:
                # Module not imported yet, import it
                module = import_and_strip_traceback(function_path)

            # Force reloading the module if we're developing
            if PYTHON_MODULE_DEVELOPMENT:
                importlib.reload(module)

            try:
                # Get the requested function
                function = getattr(module, function_name)
            except AttributeError as ex:
                raise PythiaImportException(str(ex))
            FUNCTION_CACHE[full_function_name] = function

        retval = handle_function_calling(function, function_args)

    except PythiaImportException as ex:
        retval = format_error_string(ex.args[0])
        logger.error('Exception while importing function:\n{}'.format(ex.args[0]))

    except PythiaExecuteException as ex:
        retval = format_error_string(ex.args[0])
        logger.error('Exception while calling function:\n{}'.format(ex.args[0]))

    except:
        retval = format_error_string(traceback.format_exc())
        logger.error('An exception occurred:\n{}'.format(traceback.format_exc()))

    return retval


def init_modules(modules_dict):
    logger.debug('Modules initialized with the following data: {}'.format(modules_dict))
    PythiaModuleWrapper.init_modules(modules_dict)


def continue_coroutine(_id, args):
    """Continue execution of a coroutine.

    Takes an ID of the coroutine to continue.
    """

    global COROUTINES_DICT, COROUTINES_COUNTER

    coroutine = COROUTINES_DICT.pop(_id)

    # Pass the value back to the coroutine and resume its execution
    try:
        next_request = coroutine.send(args)

        # Got next yield. Put the coroutine to the list again
        COROUTINES_DICT[_id] = coroutine
        return format_response_string(next_request, True, _id)

    except StopIteration as iteration_exception:
        # Function has ended with a return. Pass the value back
        return format_response_string(iteration_exception.value)


###############################################################################
# Below are testing functions which exist solely to check if everything is
# working correctly.
# If someone wants to check if their python module works, they should Call
# pythia.test() and later pythia.ping() to make sure they understand the syntax
###############################################################################

def test(*args):
    """Return the string "OK" to make sure the plugin is working correctly."""
    return "OK"


def ping(*args):
    """Return the arguments passed to the function."""
    return list(args)


def version(*args):
    """Return the version number of the plugin."""
    return pythiainternal.version()


def interactive(port):
    from remote_pdb import RemotePdb
    RemotePdb('127.0.0.1', port).set_trace()

    # To connect, do:
    # import telnetlib; telnetlib.Telnet('127.0.0.1', 4444).interact()

def _enable_reloader(enable):
    # Forward declaration
    enable_reloader(enable)

# Keep a separate dict of those functions for reloading purposes
PYTHIA_INTERNAL_FUNCTIONS = {
    'pythia.ping': ping,
    'pythia.test': test,
    'pythia.continue': continue_coroutine,
    'pythia.version': version,
    'pythia.interactive': interactive,
    'pythia.enable_reloader': _enable_reloader,
}

def invalidate_pythia_functions_cache():
    global FUNCTION_CACHE
    FUNCTION_CACHE = PYTHIA_INTERNAL_FUNCTIONS.copy()

# Comment the following lines out to enable remote interactive debugging
def interactive(port): raise NotImplementedError
PYTHIA_INTERNAL_FUNCTIONS['pythia.interactive'] = interactive

invalidate_pythia_functions_cache()

###############################################################################
# Module import hooks allowing importing modules from custom locations
# TODO: Move this to a separate file as soon as the C++ code permits
###############################################################################

class PythiaModuleWrapper(object):
    initialized = False
    modules = {}

    @staticmethod
    def _get_node(fullname):
        """Translate pythia dot-separated module name to the path on the disk (without file extension)."""
        logger.debug('_get_node({})'.format(fullname))

        bits = fullname.split('.')
        bits[0] = PythiaModuleWrapper.modules[bits[0]]
        node_path = os.path.join(*bits)

        logger.debug('Returning: {}'.format(node_path))
        return node_path


    @staticmethod
    def is_handled(fullname):
        """Check if the module can be loaded by Pythia."""
        name_split = fullname.split('.')

        # Protecting the `python` namespace (it's not used by this loader)
        if name_split[0] == 'python':
            return False

        if '' in name_split:
            # some..path, some.path.
            return False

        if name_split[0] not in PythiaModuleWrapper.modules:
            return False

        return True

    @staticmethod
    def get_filename(fullname):
        """Map the full module name to a file on disk that Pythia will load"""
        node_path = PythiaModuleWrapper._get_node(fullname)
        if PythiaModuleWrapper.is_package(fullname):
            filename = os.path.join(node_path, '__init__.py')
            return filename
        else:
            for suffix in importlib.machinery.all_suffixes():
                filename = node_path + suffix
                logger.debug('Checking: {}'.format(filename))
                if os.path.isfile(filename):
                    return filename

        raise ImportError('Can\'t get filename for {}'.format(fullname))

    @staticmethod
    def get_data(filename):
        """Actually read the module/extension data.
        This is the function that will probably have to be rewritten if we handle in-pbo
        loading, in the future.
        """
        with open(filename, 'rb') as f:
            return f.read()

    @staticmethod
    def is_package(fullname):
        """Return True if this module name is actually a package."""
        name_split = fullname.split('.')

        # Base module should always be a package
        if len(name_split) == 1:
            return True

        path = os.path.join(PythiaModuleWrapper._get_node(fullname), '__init__.py')
        return os.path.isfile(path)

    @staticmethod
    def init_modules(modules_dict):
        """Register the whole import mechanism and set the supported Pythia modules."""
        if not PythiaModuleWrapper.initialized:
            logger.info('Initializing module finder')
            sys.meta_path.insert(0, PythiaModuleFinder())
            PythiaModuleWrapper.initialized = True

        PythiaModuleWrapper.modules = modules_dict


class PythiaModuleFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path, target = None):
        logger.info('PythiaModuleFinder: Trying to load: {}'.format(name))

        if not PythiaModuleWrapper.is_handled(name):
            return None

        real_path = os.path.realpath(PythiaModuleWrapper.get_filename(name))

        # Determine if we're dealing with a source module or an extension (C/C++/Cython) module
        if any(map(real_path.endswith, importlib.machinery.EXTENSION_SUFFIXES)):
            loader = PythiaExtensionLoader(name, real_path)
        else:
            loader = PythiaSourceLoader(name, real_path)

        is_package = PythiaModuleWrapper.is_package(name)
        module_spec = importlib.machinery.ModuleSpec(
            name,
            loader,
            origin=real_path,
            is_package=is_package)

        if os.path.isfile(real_path):
            # This sets __file__ for the loaded module (if `origin` is set)
            module_spec.has_location = True

        return module_spec


class PythiaLoader(object):
    def __init__(self, name, path):
        self.name = name
        self.path = path

    def get_filename(self, fullname):
        logger.debug('PythiaLoader: Requesting filename for {}'.format(fullname))
        return self.path

    def get_data(self, filename):
        logger.debug('PythiaLoader: Fetching {}'.format(filename))
        return PythiaModuleWrapper.get_data(filename)


class PythiaSourceLoader(PythiaLoader, importlib.abc.SourceLoader):
    """Class that loads python code from custom locations."""
    pass


class PythiaExtensionLoader(PythiaLoader, importlib.machinery.ExtensionFileLoader):
    """
    Class that loads python extensions from custom locations.
    Only create_module and exec_module seem to really be needed from ExtensionFileLoader.
    """
    pass

###############################################################################
# Monkey patching routines
# TODO: Move this to a separate file as soon as the C++ code permits
###############################################################################

import threading

threading.OriginalThreadConstructor = threading.Thread.__init__

def DaemonThreadConstructor(self, *args, **kwargs):
    """
    Start daemon threads by default.
    Such threads will get automatically terminated when the main thread (and
    all non-deamon threads) is terminated.

    Pros: Arma will not keep on running indefinitely after terminating the main
    C++ thread.

    Cons: Your threads may terminate unexpectedly when closing Arma.
    To prevent this set t.daemon = False explicitly for your threads.
    You're responsible for ensuring they will terminate, otherwise arma.exe
    will hang.
    """
    threading.OriginalThreadConstructor(self, *args, **kwargs)
    self.daemon = True

threading.Thread.__init__ = DaemonThreadConstructor


###############################################################################
# Reloader for mod development purposes
# TODO: Move this to a separate file as soon as the C++ code permits
###############################################################################

MODIFICATION_TIMES = {}
LAST_CHECK_TIME = 0
RELOADER_ENABLED = False

def enable_reloader(enable):
    global RELOADER_ENABLED
    global LAST_CHECK_TIME
    global MODIFICATION_TIMES

    if not enable:
        RELOADER_ENABLED = False
        return
    else:
        if not RELOADER_ENABLED:
            RELOADER_ENABLED = True
            MODIFICATION_TIMES = {}
            LAST_CHECK_TIME = 0


def reload_everything():
    logger.warn('*' * 80)
    logger.warn('Some files have changed, reloading mods!')
    logger.warn('*' * 80)

    stash = {}
    reloadable_modules_list = list(reloadable_modules())

    # Call the __pre_reload__ hook for each module
    for module in reloadable_modules_list:
        if hasattr(module, '__pre_reload__'):
            stash[module.__name__] = module.__pre_reload__()

    # Reload the modules
    for module in list(reloadable_modules_list):
        del sys.modules[module.__name__]

    for module in list(reloadable_modules_list):
        import_and_strip_traceback(module.__name__)

    # Refresh the modules list with new modules after the reload
    reloadable_modules_list = list(reloadable_modules())

    # Call the __post_reload__ hook for each module
    for module in reloadable_modules_list:
        if hasattr(module, '__post_reload__') and module.__name__ in stash:
            module.__post_reload__(stash[module.__name__])

    invalidate_pythia_functions_cache()


def reloadable_modules():
    for module in sys.modules.values():
        if module.__name__.startswith('python.'):
            yield module
            continue

        for name in PythiaModuleWrapper.modules:
            if module.__name__ == name or  module.__name__.startswith(name + '.'):
                yield module


def file_changed(path):
    global MODIFICATION_TIMES

    real_mtime = os.stat(path).st_mtime
    try:
        mtime = MODIFICATION_TIMES[path]

    except KeyError:
        mtime = real_mtime
        MODIFICATION_TIMES[path] = mtime

    return real_mtime > mtime


def set_file_changed(path):
    global MODIFICATION_TIMES

    MODIFICATION_TIMES[path] = time.time()

def check_reload():
    global LAST_CHECK_TIME

    now = time.time()
    if now >= LAST_CHECK_TIME + 1:
        LAST_CHECK_TIME = time.time()
        any_file_changed = False
        pythia_modules = list(reloadable_modules())

        for module in pythia_modules:
            if file_changed(module.__file__):
                set_file_changed(module.__file__)
                any_file_changed = True

        if any_file_changed:
            reload_everything()

###############################################################################

if __name__ == '__main__':
    base_dir = os.path.dirname(__file__)
    modules = {
        'm_one': os.path.join(base_dir, 'adapter_import_test', 'module_one'),
        'm_two': os.path.join(base_dir, 'adapter_import_test', 'module_two'),
    }

    PythiaModuleWrapper.init_modules(modules)

    # #import pythia.m_one
    # import m_one.file_one
    # m_one.file_one.fun()
    #
    # # import m_two
    # # import m_two.file_two
    # #
    # # m_two.file_two.fun()
    #
    #
    # from m_two import file_two
    # file_two.fun()

    import m_one.submodule.subfile as sub
    print(sub.fun())
    print(sub.fun2())
    print(sub.fun3())

    import m_one.hello
    print(m_one.hello)
    print(m_one.hello.fun())
