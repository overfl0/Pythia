def hello():
    """
    Returns the classic "Hello world!"
    To execute this function, call:
    ["basic.hello", []] call py3_fnc_callExtension
    """
    return 'Hello world!'


def ping(*args):
    """
    Returns all the arguments passed to the function
    To execute this function, call:
    ["basic.ping", ["string", 1, 2.3, true]] call py3_fnc_callExtension
    """
    return args


def fibonacci(n):
    """
    Returns the n-th Fibonacci number
    To execute this function, call:
    ["basic.fibonacci", [30]] call py3_fnc_callExtension

    Yes, if you pass a "large" number, like 100 in the input, Arma will hang.
    To use functions that take time to compute, spawn a separate thread and
    poll that thread for completion.
    """
    if n < 2:
        return n
    return fibonacci(n - 2) + fibonacci(n - 1)
