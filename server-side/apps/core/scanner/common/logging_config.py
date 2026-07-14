import logging
import os

VALID_LOG_LEVELS = {
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
}


def get_log_level(default: str = "INFO") -> int:
    raw_level = os.getenv("LOG_LEVEL", default).strip().upper()
    return VALID_LOG_LEVELS.get(raw_level, VALID_LOG_LEVELS[default])


def configure_logging(fmt: str) -> None:
    logging.basicConfig(
        level=get_log_level(),
        format=fmt,
    )
