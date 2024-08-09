import logging
import sys

class LoggerFormatter(logging.Formatter):
    def __init__(self):
        logging.Formatter.__init__(self,'%(bullet)s %(message)s', None)

    def format(self, record):
        match record.levelno:
            case logging.INFO:
                record.bullet = '[+]'
            case logging.WARNING:
                record.bullet = '[!]'
            case logging.DEBUG:
                record.bullet = '[*]'
            case logging.ERROR:
                record.bullet = '[-]'
            case _:
                record.bullet = '[x]'

        return logging.Formatter.format(self, record)
  
class LoggerFormatterTimeStamp(LoggerFormatter):
    def __init__(self):
        logging.Formatter.__init__(self,'[%(asctime)-15s] %(bullet)s %(message)s', None)

    def formatTime(self, record, datefmt=None):
        return LoggerFormatter.formatTime(self, record, datefmt="%Y-%m-%d %H:%M:%S")

def init(ts=False):
    handler = logging.StreamHandler(sys.stdout)
    if not ts:
        handler.setFormatter(LoggerFormatter())
    else:
        handler.setFormatter(LoggerFormatterTimeStamp())
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.INFO)

def save_output(path):
    fh = logging.FileHandler(filename=path, mode='w')
    logging.getLogger().addHandler(fh)
