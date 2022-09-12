class SomeClass:
    def __init__(self, init_value):
        self.init_value = init_value

    def get_init_value(self):
        return self.init_value


SOME_CLASS_INSTANCE: SomeClass = None


def init_some_class(init_value):
    """
    Initializes the SomeClass class instance and passes an argument to the
    constructor.
    To execute this function, call:
    ["classes.init_some_class", [30]] call py3_fnc_callExtension
    """
    global SOME_CLASS_INSTANCE

    SOME_CLASS_INSTANCE = SomeClass(init_value)


def deinit_some_class():
    """
    Denitializes the SomeClass class instance.
    To execute this function, call:
    ["classes.deinit_some_class"] call py3_fnc_callExtension
    """
    global SOME_CLASS_INSTANCE

    SOME_CLASS_INSTANCE = None


def get_init_value():
    """
    Calls the get_init_value method from the SomeClass class instance.
    To execute this function, call:
    ["classes.get_init_value"] call py3_fnc_callExtension
    """
    return SOME_CLASS_INSTANCE.get_init_value()
