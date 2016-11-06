import time
import types

def routine(arg):
    """Unused. kept for future reference and for tests."""
    print("Arg:", arg)

    newval = yield "yielded"
    print("Got newval:", newval)

    newval = yield "yielded2"
    print("Got newval:", newval)

    #raise Exception("asd")
    #yield "yielded"

    return "End of routine", "second"

def main():
    """Unused. kept for future reference and for tests."""
    r = routine("argument")

    if isinstance(r, types.GeneratorType):
        # Get what has been yielded
        yielded_request = next(r)
        print("Main: yielded:", yielded_request)


        try:
            next_value = r.send("value from main")
        except StopIteration as iteration_exception:
            #print("StopIteration has been hit. Running interactive shell... (value_exception variable)")
            #import IPython
            #IPython.embed()
            next_value = iteration_exception.value

    print("Main:", next_value)
    #next(r)

def test_coroutines():
    retval = "Start of function\n"

    get_player = yield "str(player)"  # SQF code here
    retval += 'Player: {}\n'.format(get_player)

    get_dayTime = yield "dayTime"  # SQF code here
    retval += 'Ingame time: {}\n'.format(get_dayTime)

    tralala = yield "str('tralala')"  # SQF code here
    retval += 'Tralala string: {}\n'.format(tralala)

    retval += "Function end"
    return retval

def test_coroutines2():
    retval = "Start of function2\n"

    get_player, get_dayTime, tralala = yield "[str(player), dayTime, str('tralala')]"  # SQF code here

    retval += 'Player: {}\n'.format(get_player)
    retval += 'Ingame time: {}\n'.format(get_dayTime)
    retval += 'Tralala string: {}\n'.format(tralala)
    retval += "Function end"
    return retval

if __name__ == '__main__':
    main()
