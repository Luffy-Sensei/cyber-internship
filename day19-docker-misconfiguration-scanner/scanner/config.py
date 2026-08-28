from dataclasses import dataclass


@dataclass(frozen=True)
class ScannerConfig:
    """Configuration for the Day 19 Dockerfile security scanner."""

    input_file: str = "input/Dockerfile.test"
    json_output: str = "output/reports/day19_docker.json"
    text_output: str = "output/reports/day19_docker.txt"
    max_line_length: int = 8192
