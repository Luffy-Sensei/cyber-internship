import errno
import socket
import time
import logging

from .models import PortState, ScanResult


class TCPScanner:
    """Controlled TCP connect scanner for authorized lab targets."""

    def __init__(
        self,
        timeout: float = 1.0,
        logger: logging.Logger | None = None,
    ):
        if timeout <= 0:
            raise ValueError(
                "Timeout must be greater than zero."
            )

        self.timeout = timeout
        self.logger = logger or logging.getLogger("day17")

    def scan_port(
        self,
        host: str,
        port: int,
    ) -> ScanResult:
        """Scan a single TCP port."""

        if not 1 <= port <= 65535:
            raise ValueError(
                f"Invalid TCP port: {port}"
            )

        self.logger.debug(
            "Scanning TCP/%s on %s",
            port,
            host,
        )

        start = time.perf_counter()

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )

        sock.settimeout(self.timeout)

        try:
            result = sock.connect_ex(
                (host, port)
            )

            latency_ms = (
                time.perf_counter() - start
            ) * 1000

            if result == 0:
                state = PortState.OPEN

                self.logger.info(
                    "TCP/%s OPEN on %s",
                    port,
                    host,
                )

            elif result == errno.ECONNREFUSED:
                state = PortState.CLOSED

                self.logger.debug(
                    "TCP/%s CLOSED on %s",
                    port,
                    host,
                )

            else:
                state = PortState.ERROR

                self.logger.warning(
                    "TCP/%s returned socket error code %s",
                    port,
                    result,
                )

            return ScanResult(
                host=host,
                port=port,
                protocol="TCP",
                state=state,
                latency_ms=round(
                    latency_ms,
                    2,
                ),
            )

        except socket.timeout:
            latency_ms = (
                time.perf_counter() - start
            ) * 1000

            self.logger.warning(
                "TCP/%s timed out on %s",
                port,
                host,
            )

            return ScanResult(
                host=host,
                port=port,
                protocol="TCP",
                state=PortState.TIMEOUT,
                latency_ms=round(
                    latency_ms,
                    2,
                ),
                error="Connection timed out",
            )

        except OSError as exc:
            latency_ms = (
                time.perf_counter() - start
            ) * 1000

            self.logger.error(
                "TCP/%s scan failed: %s",
                port,
                exc,
            )

            return ScanResult(
                host=host,
                port=port,
                protocol="TCP",
                state=PortState.ERROR,
                latency_ms=round(
                    latency_ms,
                    2,
                ),
                error=str(exc),
            )

        finally:
            sock.close()

    def scan_ports(
        self,
        host: str,
        ports: list[int] | tuple[int, ...],
    ) -> list[ScanResult]:
        """Scan multiple TCP ports sequentially."""

        results = []

        self.logger.info(
            "Starting TCP scan against %s",
            host,
        )

        for port in ports:
            results.append(
                self.scan_port(host, port)
            )

        self.logger.info(
            "TCP scan completed against %s",
            host,
        )

        return results
