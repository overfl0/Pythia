import importlib
import traceback
import sys
import types

# If you want the user modules to be reloaded each time the function is called, set this to True
PYTHON_MODULE_DEVELOPMENT = False

COROUTINES_DICT = {}
COROUTINES_COUNTER = 0

def format_error_string(stacktrace_str):
    """Return a formatted exception."""
    return '["e", "{}"]'.format(stacktrace_str.replace('"', '""'))

def format_response_string(return_value):
    """Return a formatted response.
    For now, it's just doing a dumb str() which may or may not work depending
    on the arguments passed. This should work as long as none of the arguments
    contain double quotes (").
    """
    global COROUTINES_DICT, COROUTINES_COUNTER

    if isinstance(return_value, types.GeneratorType):
        # Get what has been yielded
        yielded_request = next(return_value)
        COROUTINES_COUNTER += 1  # TODO: Find something to rotate this counter
        COROUTINES_DICT[COROUTINES_COUNTER] = return_value

        return str(["s", COROUTINES_COUNTER, yielded_request])

    return str(["r", return_value])

def parse_input(input_value):
    """Parses the input value passed directly from the RVEngine.
    For now it just does an eval() which is INSECURE and HAS TO BE CHANGED!
    """

    return eval(input_value)
# The extension entry point in python
def python_adapter(input_string):
    global FUNCTION_CACHE

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
                #print("Module not imported")
                module = importlib.import_module(function_path)

            # Force reloading the module if we're developing
            if PYTHON_MODULE_DEVELOPMENT:
                importlib.reload(module)

            # Get the requested function
            function = getattr(module, function_name)
            FUNCTION_CACHE[full_function_name] = function

        if full_function_name == 'Pythia.continue':
            # Special handling
            return continue_coroutine(*function_args)

        # Call the requested function with the given arguments
        return_value = function(*function_args)
        return format_response_string(return_value)

    except:
        return format_error_string(traceback.format_exc())

def continue_coroutine(_id, args):
    """Continue execution of a coroutine"""
    global COROUTINES_DICT, COROUTINES_COUNTER

    coroutine = COROUTINES_DICT.pop(_id)

    # Pass the value back to the coroutine and resume its execution
    try:
        next_request = coroutine.send(args)

        # Got next yield. Put the coroutine to the list again
        COROUTINES_DICT[_id] = coroutine
        return str(["s", _id, next_request])

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
    return "OK"

def ping(*args):
    return list(args)

FUNCTION_CACHE = {
    'Pythia.ping': ping,
    'Pythia.test': test,
    'Pythia.continue': continue_coroutine,
}

# Somehow Visual Studio cannot load this if there is a newline at The
# end of the file