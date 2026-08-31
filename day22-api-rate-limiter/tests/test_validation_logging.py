from scanner.validation import configure_logging


def test_configure_logging_creates_log_file(tmp_path):
    log_path = tmp_path / "logs" / "validation.log"

    configure_logging(
        verbose=True,
        log_path=log_path,
    )

    assert log_path.exists()
