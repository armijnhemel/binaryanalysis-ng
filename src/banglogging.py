import logging

uselogging = False

def log(level, message):
    if uselogging:
        logging.log(level, message)



