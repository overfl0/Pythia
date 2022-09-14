# The uses below are equivalent and any can be used with the same effect
# Usage 1:
# ["classes.SomeClass.init", [30]] call py3_fnc_callExtension
# ["classes.SOME_CLASS_INSTANCE.get_init_value"] call py3_fnc_callExtension
# ["classes.SomeClass.deinit"] call py3_fnc_callExtension
#
# Usage 2:
# ["classes.init_some_class", [30]] call py3_fnc_callExtension
# ["classes.get_init_value"] call py3_fnc_callExtension
# ["classes.deinit_some_class"] call py3_fnc_callExtension
#
# Usage 3:
# ["classes.init_some_class", [30]] call py3_fnc_callExtension
# ["classes.SOME_CLASS_INSTANCE.get_init_value"] call py3_fnc_callExtension
# ["classes.deinit_some_class"] call py3_fnc_callExtension


class SomeClass:
    def __init__(self, init_value):
        self.init_value = init_value

    def get_init_value(self):
        return self.init_value

    @staticmethod
    def init(init_value):
        """
        Initializes the SomeClass class instance and passes an argument to the
        constructor.
        Note: you can also use a regular function outside the class, instead. See below.
        To execute this function, call:
        ["classes.SomeClass.init", [30]] call py3_fnc_callExtension
        """
        global SOME_CLASS_INSTANCE

        SOME_CLASS_INSTANCE = SomeClass(init_value)

    @staticmethod
    def deinit():
        """
        Denitializes the SomeClass class instance.
        To execute this function, call:
        Note: you can also use a regular function outside the class, instead. See below.
        ["classes.SomeClass.deinit"] call py3_fnc_callExtension
        """
        global SOME_CLASS_INSTANCE

        SOME_CLASS_INSTANCE = None


SOME_CLASS_INSTANCE = None


# Below are alternative ways of accessing the class instance.
# You may but don't _have to_ use them.
# You can use the @staticmethod methods or getinstance to access the instance.


def init_some_class(init_value):
    """
    ***ALTERNATIVE WAY IF YOU DON'T LIKE USING @STATICMETHOD ABOVE***
    Initializes the SomeClass class instance and passes an argument to the
    constructor.
    To execute this function, call:
    ["classes.init_some_class", [30]] call py3_fnc_callExtension
    """
    global SOME_CLASS_INSTANCE

    SOME_CLASS_INSTANCE = SomeClass(init_value)


def deinit_some_class():
    """
    ***ALTERNATIVE WAY IF YOU DON'T LIKE USING @STATICMETHOD ABOVE***
    Denitializes the SomeClass class instance.
    To execute this function, call:
    ["classes.deinit_some_class"] call py3_fnc_callExtension
    """
    global SOME_CLASS_INSTANCE

    SOME_CLASS_INSTANCE = None


def get_init_value():
    """
    ***ALTERNATIVE WAY IF YOU DON'T LIKE ACCESSING THE CLASS DIRECTLY***
    Calls the get_init_value method from the SomeClass class instance.
    To execute this function, call:
    ["classes.get_init_value"] call py3_fnc_callExtension
    """
    return SOME_CLASS_INSTANCE.get_init_value()
