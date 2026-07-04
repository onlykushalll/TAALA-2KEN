"""
TAALA-2KEN — Centralised logging configuration.

Provides a single `log` object shared across all modules.
Call `reconfigure()` after changing DEBUG_MODE to update log levels.
"""

import sys
import logging
from taala2ken import constants as C


def _create_logger() -> logging.Logger:
    """Create and configure the application logger."""
    logger = logging.getLogger("Taala2Ken")
    logger.setLevel(logging.DEBUG if C.DEBUG_MODE else logging.INFO)

    fmt = logging.Formatter(
        fmt="%(asctime)s  [%(levelname)-8s]  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    if C.LOG_FILE is not None:
        try:
            fh = logging.FileHandler(C.LOG_FILE, encoding="utf-8")
            fh.setFormatter(fmt)
            logger.addHandler(fh)
        except OSError as e:
            logger.warning(f"Could not open log file '{C.LOG_FILE}': {e}")

    return logger


log: logging.Logger = _create_logger()


def reconfigure() -> None:
    """Re-apply log levels after DEBUG_MODE changes at runtime."""
    level = logging.DEBUG if C.DEBUG_MODE else logging.INFO
    log.setLevel(level)
    for handler in log.handlers:
        handler.setLevel(level)
