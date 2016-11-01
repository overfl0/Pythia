import traceback

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
    try:
        if input_string == "":
            return format_error_string("Input string cannot be empty")

        real_input = parse_input(input_string)

        return format_response_string(real_input)
    except:
        return format_error_string(traceback.format_exc())
