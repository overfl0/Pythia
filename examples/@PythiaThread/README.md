This example shows how to call Python functions that take a long time to
execute.

The function creates a separate thread that needs to be polled to see if it
finished, each time the function is called. This allows us to have a
long-running python function that does not block Arma itself.

Pseudocode:
```python
index = 35  # This should be slow enough to last a few seconds
thread_id = call_slow_fibonacci(index)

while not has_call_finished(thread_id):
    print('Waiting for the task to finish...')
    time.sleep(0.3)

value = get_call_value(thread_id)
print(f'Fibonacci number {index} equals to {value}')
```

Note that the directory name is _irrelevant_. The package name depends on the
contents of the `$PYTHIA$` file only!

The addons directory contains a dummy PBO file to force Arma to load it as a
mod (which lets Pythia know that it should search the directories next to the
addons directory for Python code). You can omit that file as long as you have
_any_ PBO in your mod (which should always be the case unless you're making a
pure-Python mod).
