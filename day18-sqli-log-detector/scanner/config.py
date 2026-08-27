from dataclasses import dataclass


@dataclass(frozen=True)
class DetectorConfig:
    """Configuration for the Day 18 SQLi log detector."""

    input_file: str = "input/mock_access.log"
    log_format: str = "simple_http"
    max_line_length: int = 8192
