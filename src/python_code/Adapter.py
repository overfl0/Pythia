import importlib
import logging
import logging.handlers
import traceback
import sys
import types

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

    if sql_call:
        return str(["s", coroutine_id, return_value])

    return str(["r", return_value])


def parse_input(input_value):
    """Parses the input value passed directly from the RVEngine.
    For now it just does an eval() which is INSECURE and HAS TO BE CHANGED!
    """

    return eval(input_value)


def handle_function_calling(function, args):
    """Calls the given function with the given arguments and formats the response."""
    global COROUTINES_DICT, COROUTINES_COUNTER

    if logger.level < logging.INFO:
        function_args = str(args)[1:-1]
    else:
        function_args = '...'

    logger.info('Calling {}({})'.format(function.__name__, function_args))

    if function == continue_coroutine or function == multipart:
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


def python_adapter(input_string):
    """The extension entry point in python."""

    global FUNCTION_CACHE
    global MULTIPART_DICT, MULTIPART_COUNTER

    try:
        if input_string == "":
            return format_error_string("Input string cannot be empty")

        real_input = parse_input(input_string)
        full_function_name = real_input[0]
        function_args = real_input[1:]

        try:
            # Raise dummy exception if needs force-reload
            if PYTHON_MODULE_DEVELOPMENT:
                if not full_function_name.startswith('Pythia.'):
                    raise KeyError('Dummy KeyError')

            function = FUNCTION_CACHE[full_function_name]

        except KeyError:  # Function not cached, load the module
            function_path, function_name = full_function_name.rsplit('.', 1)

            try:
                module = sys.modules[function_path]

            except KeyError:
                # Module not imported yet, import it
                # print("Module not imported")
                module = importlib.import_module(function_path)

            # Force reloading the module if we're developing
            if PYTHON_MODULE_DEVELOPMENT:
                importlib.reload(module)

            # Get the requested function
            function = getattr(module, function_name)
            FUNCTION_CACHE[full_function_name] = function

        retval = handle_function_calling(function, function_args)

    except:
        retval = format_error_string(traceback.format_exc())
        logger.exception('An exception occurred:')

    # Multipart response handling
    # If the returned value is larger than 10KB - 1, use multipart response
    # Note: Because of a lacking escaping function, we have to use shorter length strings
    response_max_length = 8000  #10239
    result_length = len(retval)

    if result_length > response_max_length:
        MULTIPART_COUNTER += 1
        response_split = split_by_len(retval, result_length, response_max_length)
        MULTIPART_DICT[MULTIPART_COUNTER] = list(reversed(response_split))

        # return multipart response
        retval = str(["m", MULTIPART_COUNTER, len(response_split)])

    return retval


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
        #response = str(['e', 'Could not find multipart message for id {}'.format(_id)])

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
# Pythia.test() and later Pythia.ping() to make sure they understand the syntax
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


FUNCTION_CACHE = {
    'Pythia.ping': ping,
    'Pythia.test': test,
    'Pythia.continue': continue_coroutine,
    'Pythia.multipart': multipart,
    'Pythia.version': version,
}
