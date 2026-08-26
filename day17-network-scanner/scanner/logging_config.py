import logging
from pathlib import Path


LOGGER_NAME = "day17"


def configure_logging(
    log_directory: Path,
    verbose: bool = False,
) -> logging.Logger:
    """Configure application logging."""

    log_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    log_file = log_directory / "day17_scanner.log"

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(
        logging.DEBUG if verbose else logging.INFO
    )

    logger.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    return logger
