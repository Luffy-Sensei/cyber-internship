from pathlib import Path

from scanner.logging_utils import configure_logging


def test_logging_creates_log_file(tmp_path):
    log_file = tmp_path / "scanner.log"

    logger = configure_logging(
        log_file=str(log_file)
    )

    logger.info("test message")

    assert log_file.exists()

    content = log_file.read_text(
        encoding="utf-8"
    )

    assert "test message" in content
