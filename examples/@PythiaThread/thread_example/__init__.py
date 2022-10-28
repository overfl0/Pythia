from .threading_utils import call_slow_function, has_call_finished, get_call_value


def fibonacci(n):
    """
    Returns the n-th Fibonacci number. Is slow for large numbers.
    """
    if n < 2:
        return n
    return fibonacci(n - 2) + fibonacci(n - 1)


def call_slow_fibonacci(n):
    """
    Call a slow function.
    Returns a Thread ID that has to then be polled from SQF to check if the
    function finished.

    To execute this function, call:
    ["thread_example.call_slow_fibonacci", [35]] call py3_fnc_callExtension

    Get the thread ID and use it with:
    ["thread_example.has_call_finished", [thread_id]] call py3_fnc_callExtension

    When ot returns True, you can get the value by doing:
    ["thread_example.get_call_value", [thread_id]] call py3_fnc_callExtension
    """
    return call_slow_function(fibonacci, (n,))


has_call_finished  # noqa - this function has been imported from threading_utils.py
get_call_value  # noqa - this function has been imported from threading_utils.py
