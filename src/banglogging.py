import logging

uselogging = None

def log(level, message):
    global uselogging
    if uselogging:
        logging.log(level, message)



