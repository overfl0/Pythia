import logging

# This creates a logger with the name of the package you've imported
# which should be `logging_example`, in case of this file
logger = logging.getLogger(__name__)


# IMPORTANT: Never pass arbitrary strings from SQF as the first argument!
# Use %s formatting! See the readme for details.
# logger.info('%s', message) is better than logger.info(message)!


def log_debug(message):
    """
    Logs a message to pythia.log with at the info level.
    To execute this function, call:
    ["logging_example.log_debug", ["This is my message to pythia.log"]] call py3_fnc_callExtension
    """
    logger.debug('Got: %s', message)


def log_info(message):
    """
    Logs a message to pythia.log with at the info level.
    To execute this function, call:
    ["logging_example.log_info", ["This is my message to pythia.log"]] call py3_fnc_callExtension
    """
    logger.info('Got: %s', message)


def log_warning(message):
    """
    Logs a message to pythia.log with at the warning level.
    To execute this function, call:
    ["logging_example.log_warning", ["This is my message to pythia.log"]] call py3_fnc_callExtension
    """
    logger.warning('Got: %s', message)


def log_error(message):
    """
    Logs a message to pythia.log with at the error level.
    To execute this function, call:
    ["logging_example.log_error", ["This is my message to pythia.log"]] call py3_fnc_callExtension
    """
    logger.error('Got: %s', message)


def log_exception(message):
    """
    Logs a message to pythia.log with at the exception level AND adds a stacktrace.
    Use this only while handling exceptions.
    To execute this function, call:
    ["logging_example.log_exception", ["This is my message to pythia.log"]] call py3_fnc_callExtension
    """
    try:
        1/0
    except ZeroDivisionError:
        logger.exception('Got: %s', message)
