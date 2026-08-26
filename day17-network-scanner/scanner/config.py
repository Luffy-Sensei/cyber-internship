from dataclasses import dataclass


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORTS = [22, 80, 443, 5432, 8080]
DEFAULT_TIMEOUT = 1.0


@dataclass(frozen=True)
class ScannerConfig:
    """Runtime configuration for the TCP scanner."""

    host: str = DEFAULT_HOST
    ports: tuple[int, ...] = tuple(DEFAULT_PORTS)
    timeout: float = DEFAULT_TIMEOUT
