import logging
from pathlib import Path


LOGGER_NAME = "day18"


def configure_logging(
    verbose: bool = False,
    log_file: str = "output/logs/day18_detector.log",
) -> logging.Logger:
    """Configure console and file logging."""

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(
        logging.DEBUG if verbose else logging.INFO
    )

    logger.handlers.clear()
    logger.propagate = False

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | "
        "%(name)s | %(message)s"
    )

    Path(log_file).parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    file_handler = logging.FileHandler(
        log_file,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(
        logging.DEBUG if verbose else logging.INFO
    )
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger
