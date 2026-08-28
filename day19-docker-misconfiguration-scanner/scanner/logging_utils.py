import logging
from pathlib import Path


LOGGER_NAME = "day19"


def configure_logging(
    log_file: str = "output/logs/day19_detector.log",
    verbose: bool = False,
) -> logging.Logger:
    """Configure console and file logging for Day 19."""

    logger = logging.getLogger(LOGGER_NAME)

    logger.setLevel(
        logging.DEBUG if verbose else logging.INFO
    )

    logger.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    log_path = Path(log_file)
    log_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    file_handler = logging.FileHandler(
        log_path,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(
        logging.DEBUG if verbose else logging.INFO
    )

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger
