import multiprocessing
import logging

log = multiprocessing.get_logger()
if log.level == logging.NOTSET:
    log = multiprocessing.log_to_stderr()

