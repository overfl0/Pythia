import time

from thread_example import call_slow_fibonacci, has_call_finished, get_call_value

# Call this file if you want to check how it's supposed to work in pure python
if __name__ == '__main__':
    index = 35  # This should be slow enough to last a few seconds
    thread_id = call_slow_fibonacci(index)

    while not has_call_finished(thread_id):
        print('Waiting for the task to finish...')
        time.sleep(0.3)

    value = get_call_value(thread_id)
    print(f'Fibonacci number {index} equals to {value}')
