import importlib
import importlib.abc
import importlib.machinery
import logging
import logging.handlers
import os
import sys
import time
import traceback
import types


# Decoding and encoding to SQF
SQF_DESCRIPTION = 'Using eval as SQF decoder and str as SQF encoder'
SQF_ENCODER = str

try:
    import ujson
    SQF_DESCRIPTION = 'Using internal SQF decoder and ujson.dumps as SQF encoder'
    SQF_ENCODER = ujson.dumps

except ImportError:
    import json
    SQF_DESCRIPTION = 'Using internal SQF decoder and str as SQF encoder'
    SQF_ENCODER = str  # str is still faster than json.dumps!

# If you want the user modules to be reloaded each time the function is called, set this to True
PYTHON_MODULE_DEVELOPMENT = False

COROUTINES_DICT = {}
COROUTINES_COUNTER = 0

MULTIPART_DICT = {}
MULTIPART_COUNTER = 0

def create_root_logger(name):
    file_handler = logging.handlers.RotatingFileHandler('pythia.log', maxBytes=1024*1024, backupCount=10)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(name)s] %(message)s')
    file_handler.setFormatter(formatter)

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    logger.name = name

    return logger

logger = create_root_logger(__name__)
logger.critical('=' * 80)
logger.critical('Pythia is starting up...')
logger.critical(SQF_DESCRIPTION)
logger.critical('=' * 80)

def split_by_len(item, itemlen, maxlen):
    """"Requires item to be sliceable (with __getitem__ defined)."""
    return [item[ind:ind + maxlen] for ind in range(0, itemlen, maxlen)]


def format_error_string(stacktrace_str):
    """Return a formatted exception."""
    return '["e", "{}"]'.format(stacktrace_str.replace('"', '""'))


def format_response_string(return_value, sql_call=False, coroutine_id=None):
    """Return a formatted response.
    For now, it's just doing a dumb str() which may or may not work depending
    on the arguments passed. This should work as long as none of the arguments
    contain double quotes (").
    """
    global SQF_ENCODER

    if sql_call:
        return SQF_ENCODER(["s", coroutine_id, return_value])

    return SQF_ENCODER(["r", return_value])


class PythiaImportException(Exception):
    pass


def handle_function_calling(function, args):
    """Calls the given function with the given arguments and formats the response."""
    global COROUTINES_DICT, COROUTINES_COUNTER

    if logger.level < logging.INFO:
        function_args = str(args)[1:-1]
    else:
        function_args = '...'

    logger.info('Calling {}({})'.format(function.__name__, function_args))

    try:
        timer_start = time.clock()
        if function == continue_coroutine or function == multipart:
            # Special handling
            return function(*args)

        # Call the requested function with the given arguments
        return_value = function(*args)

    finally:
        timer_stop = time.clock()
        # Log the time
        logger.debug('Function {} terminated in {:.7f} ms'.format(function.__name__, (timer_stop - timer_start) * 1000))

    try:
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

    finally:
        time_pack = time.clock()
        logger.debug('Function {} terminated and packed in {:.7f} ms'.format(function.__name__, (time_pack - timer_start) * 1000))


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
    global MULTIPART_DICT, MULTIPART_COUNTER
    global SQF_ENCODER

    try:
        full_function_name = sqf_args[0]
        function_args = sqf_args[1:]

        try:
            # Raise dummy exception if needs force-reload
            if PYTHON_MODULE_DEVELOPMENT:
                if full_function_name not in PYTHIA_INTERNAL_FUNCTIONS:
                    raise KeyError('Dummy KeyError')

            function = FUNCTION_CACHE[full_function_name]

        except KeyError:  # Function not cached, load the module
            function_path, function_name = full_function_name.rsplit('.', 1)

            try:
                module = sys.modules[function_path]

            except KeyError:
                # Module not imported yet, import it
                # print("Module not imported")
                module = import_and_strip_traceback(function_path)

            # Force reloading the module if we're developing
            if PYTHON_MODULE_DEVELOPMENT:
                importlib.reload(module)

            # Get the requested function
            # FIXME: Prettify the error in case the module does not have the requested function
            function = getattr(module, function_name)
            FUNCTION_CACHE[full_function_name] = function

        retval = handle_function_calling(function, function_args)

    except PythiaImportException as ex:
        retval = format_error_string(ex.args[0])
        logger.error('Exception while importing function:\n{}'.format(ex.args[0]))

    except:
        retval = format_error_string(traceback.format_exc())
        logger.exception('An exception occurred:')

    # Multipart response handling
    # If the returned value is larger than 10KB - 1, use multipart response
    # Note: Because of a lacking escaping function, we have to use shorter length strings
    response_max_length = 8000  #10239  # FIXME!!! Implement proper escaping!
    result_length = len(retval)

    if result_length > response_max_length:
        MULTIPART_COUNTER += 1
        response_split = split_by_len(retval, result_length, response_max_length)
        MULTIPART_DICT[MULTIPART_COUNTER] = list(reversed(response_split))

        # return multipart response
        retval = SQF_ENCODER(["m", MULTIPART_COUNTER, len(response_split)])

    return retval


def init_modules(modules_dict):
    logger.debug('Modules initialized with the following data: {}'.format(modules_dict))
    PythiaModuleWrapper.init_modules(modules_dict)


def multipart(_id):
    """Retrieve a part of a multipart response.

    Takes an ID of the response to return.
    """

    global MULTIPART_DICT

    try:
        entry = MULTIPART_DICT[_id]
        response = entry.pop()

        # Free memory
        if not entry:
            del MULTIPART_DICT[_id]

    except KeyError:
        # There is no more data to send
        response = ""
        #response = SQF_ENCODER(['e', 'Could not find multipart message for id {}'.format(_id)])

    return response


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
    return '1.0.0'

# Keep a separate dict of those functions for reloading purposes
PYTHIA_INTERNAL_FUNCTIONS = {
    'pythia.ping': ping,
    'pythia.test': test,
    'pythia.continue': continue_coroutine,
    'pythia.multipart': multipart,
    'pythia.version': version,
}

FUNCTION_CACHE = PYTHIA_INTERNAL_FUNCTIONS.copy()

###############################################################################
# TODO: Move this to a separate file as soon as the C++ code permits
###############################################################################

class PythiaModuleWrapper(object):
    initialized = False
    modules = {}

    @staticmethod
    def _get_node(fullname):
        """Translate pythia dot-separated module name to the path on the disk (without file extension)."""
        print('_get_node({})'.format(fullname))

        bits = fullname.split('.')
        bits[0] = PythiaModuleWrapper.modules[bits[0]]
        node_path = os.path.join(*bits)

        print('Returning:', node_path)
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
                print('Checking: {}'.format(filename))
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
            print('Initializing module finder')
            sys.meta_path.insert(0, PythiaModuleFinder())
            PythiaModuleWrapper.initialized = True

        PythiaModuleWrapper.modules = modules_dict


class PythiaModuleFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path, target = None):
        print('PythiaModuleFinder: Trying to load: {}'.format(name))

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
        print('PythiaLoader: Requesting filename for {}'.format(fullname))
        return self.path

    def get_data(self, filename):
        print('PythiaLoader: Fetching {}'.format(filename))
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
