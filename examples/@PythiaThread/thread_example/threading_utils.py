import threading


# https://stackoverflow.com/a/65447493/6543759
class ThreadWithResult(threading.Thread):
    def __init__(self, group=None, target=None, name=None, args=(), kwargs=None, *, daemon=None):
        if not kwargs:
            kwargs = {}

        def function():
            self.result = target(*args, **kwargs)
        super().__init__(group=group, target=function, name=name, daemon=daemon)


THREADS = {}
THREAD_ID = 0


def call_slow_function(function, args):
    global THREADS, THREAD_ID
    thread = ThreadWithResult(target=function, args=args, daemon=True)
    THREAD_ID += 1
    THREADS[THREAD_ID] = thread
    thread.start()

    return THREAD_ID


def has_call_finished(thread_id):
    global THREADS

    thread = THREADS[thread_id]
    if thread.is_alive():
        # Thread is still working
        return False

    # Thread has finished, we can return its value using get_call_value()
    return True


def get_call_value(thread_id):
    global THREADS

    thread = THREADS[thread_id]
    if thread.is_alive():
        # Thread is still working
        raise ValueError('Thread is still running!')

    # Thread has finished, we can return its value now
    thread.join()
    del THREADS[thread_id]
    return thread.result
