from scanner.logging_utils import configure_logging


def test_logging_creates_file(tmp_path):
    log_file = (
        tmp_path / "logs" / "day18.log"
    )

    logger = configure_logging(
        verbose=True,
        log_file=str(log_file),
    )

    logger.info("test message")

    assert log_file.exists()

    content = log_file.read_text(
        encoding="utf-8"
    )

    assert "test message" in content
    assert "INFO" in content
