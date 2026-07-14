import logging

VALID_LOG_LEVELS = {
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
}


def resolve_log_level(level_name: str | None, default: str = "INFO") -> int:
    raw_level = (level_name or default).strip().upper()
    return VALID_LOG_LEVELS.get(raw_level, VALID_LOG_LEVELS[default])


def configure_logging(level_name: str | None, fmt: str) -> None:
    logging.basicConfig(
        level=resolve_log_level(level_name),
        format=fmt,
    )
