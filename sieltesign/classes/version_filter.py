import logging
import subprocess


class MyFilter(logging.Filter):
    def filter(self, record):
        record.version = "1.0.0"
        return True
