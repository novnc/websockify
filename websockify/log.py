'''
Logging control and utilities
Licensed under LGPL version 3 (see docs/LICENSE.LGPL-3)
'''

import logging
import sys


def _add_default_handler(logger):
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s %(name)s %(message)s'))
    logger.addHandler(handler)


def get_logger(name="websockify"):
    rootlogger = logging.getLogger(name)
    if rootlogger.level == logging.NOTSET:
        rootlogger.setLevel(logging.WARN)
    if not rootlogger.handlers:
        _add_default_handler(rootlogger)
    return rootlogger
