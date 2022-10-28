import sys
import threading


# https://stackoverflow.com/a/65447493/6543759
class ThreadWithResult(threading.Thread):
    def __init__(self, group=None, target=None, name=None, args=(), kwargs=None, *, daemon=None):
        self.exc = None
        if not kwargs:
            kwargs = {}

        def function():
            self.exc = None
            try:
                self.result = target(*args, **kwargs)
            except:  # noqa
                # Save details of the exception thrown but don't rethrow,
                # just complete the function
                self.exc = sys.exc_info()

        super().__init__(group=group, target=function, name=name, daemon=daemon)

    # https://stackoverflow.com/a/12223550/6543759
    def join(self, *args, **kwargs):
        super().join(*args, **kwargs)

        if self.exc:
            msg = "Thread '%s' threw an exception: %s" % (self.getName(), self.exc[1])
            new_exc = Exception(msg)
            raise new_exc.with_traceback(self.exc[2])


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
    try:
        thread.join()
    finally:
        del THREADS[thread_id]

    try:
        return thread.result
    except AttributeError:
        raise RuntimeError(
            'The thread does not have the "result" attribute. An unhandled error occurred inside your Thread')
