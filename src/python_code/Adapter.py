import importlib
import traceback
import sys

# If you want the user modules to be reloaded each time the function is called, set this to True
PYTHON_MODULE_DEVELOPMENT = False

FUNCTION_CACHE = {}

def format_error_string(stacktrace_str):
    """Return a formatted exception."""
    return '["e", "{}"]'.format(stacktrace_str.replace('"', '""'))

def format_response_string(return_value):
    """Return a formatted response.
    For now, it's just doing a dumb str() which may or may not work depending
    on the arguments passed. This should work as long as none of the arguments
    contain double quotes (").
    """

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
        #return format_response_string(input_string)

        full_function_name = real_input[0]
        function_args = real_input[1:]

        try:
            # Raise dummy exception if needs force-reload
            if PYTHON_MODULE_DEVELOPMENT:
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

        # Call the requested function with the given arguments
        return_value = function(*function_args)
        return format_response_string(return_value)

    except:
        return format_error_string(traceback.format_exc())

# Somehow Visual Studio cannot load this if there is a newline at The
# end of the file