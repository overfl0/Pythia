

def test(*args):
    """Always return the string "OK"."""
    return "OK"

def ping(*args):
    """Return the list of arguments passed to the function.
    The function name is omitted in the list returned.
    """
    return list(args)

def get_multiples(multiplier, count):
    """Return [0, 1*multiplier, 2*multiplier, ...]."""
    return [i * multiplier for i in range(count)]
