import time
import types

@types.coroutine
def SQF(command):
    return (yield command)

async def routine(arg):
    """Unused. kept for future reference and for tests."""
    print("Arg:", arg)
    return "test"

    newval = await SQF("yielded")
    print("Got newval:", newval)

    newval = await SQF("yielded2")
    print("Got newval:", newval)

    #raise Exception("asd")
    #await SQF("yielded")

    return "End of routine", "second"

def main():
    """Unused. kept for future reference and for tests."""
    r = routine("argument")

    if isinstance(r, types.CoroutineType):
        # Get what has been yielded
        yielded_request = r.send(None)  # Start the coroutine
        print("Main: yielded:", yielded_request)

        try:
            next_value = r.send("value from main")
            print("received value")
        except StopIteration as iteration_exception:
            #print("StopIteration has been hit. Running interactive shell... (value_exception variable)")
            #import IPython
            #IPython.embed()
            print("received StopIteration")
            next_value = iteration_exception.value


    print("Main:", next_value)
    #next(r)

async def test_coroutines():
    retval = "Start of function\n"

    get_player = await SQF("str(player)")
    retval += 'Player: {}\n'.format(get_player)

    get_dayTime = await SQF("dayTime")
    retval += 'Ingame time: {}\n'.format(get_dayTime)

    tralala = await SQF("str('tralala')")
    retval += 'Tralala string: {}\n'.format(tralala)

    retval += "Function end"
    return retval

async def test_coroutines2():
    retval = "Start of function2\n"

    get_player, get_dayTime, tralala = await SQF("[str(player), dayTime, str('tralala')]")

    retval += 'Player: {}\n'.format(get_player)
    retval += 'Ingame time: {}\n'.format(get_dayTime)
    retval += 'Tralala string: {}\n'.format(tralala)
    retval += "Function end"
    return retval

if __name__ == '__main__':
    main()
