import socket

from .models import ScanResult, ServiceResult


COMMON_SERVICES = {
    21: ("FTP", "FILE_TRANSFER"),
    22: ("SSH", "REMOTE_ADMINISTRATION"),
    23: ("TELNET", "REMOTE_ADMINISTRATION"),
    25: ("SMTP", "EMAIL"),
    53: ("DNS", "INFRASTRUCTURE"),
    80: ("HTTP", "WEB"),
    110: ("POP3", "EMAIL"),
    143: ("IMAP", "EMAIL"),
    443: ("HTTPS", "WEB"),
    3306: ("MySQL", "DATABASE"),
    5432: ("PostgreSQL", "DATABASE"),
    6379: ("Redis", "DATABASE"),
    8080: ("HTTP-ALT", "WEB"),
    8443: ("HTTPS-ALT", "WEB"),
}


class ServiceMapper:
    """Map and verify services on authorized lab targets."""

    def identify(self, result: ScanResult) -> ServiceResult:
        service, category = COMMON_SERVICES.get(
            result.port,
            ("UNKNOWN", "UNKNOWN"),
        )

        if result.state.value == "OPEN":
            confidence = "LOW"
            method = "PORT_HINT"
        else:
            confidence = "NONE"
            method = "NO_SERVICE_IDENTIFICATION"

        return ServiceResult(
            host=result.host,
            port=result.port,
            protocol=result.protocol,
            state=result.state,
            service=service,
            category=category,
            confidence=confidence,
            detection_method=method,
            latency_ms=result.latency_ms,
        )

    def identify_many(
        self,
        results: list[ScanResult],
    ) -> list[ServiceResult]:
        return [
            self.identify(result)
            for result in results
        ]

    def probe_http(
        self,
        host: str,
        port: int,
        timeout: float = 2.0,
    ) -> tuple[bool, str]:
        """
        Perform a minimal HTTP protocol probe.

        Intended for authorized local lab targets.
        """

        request = (
            "HEAD / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Connection: close\r\n"
            "User-Agent: Day17-ServiceProbe/1.0\r\n"
            "\r\n"
        )

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )

        sock.settimeout(timeout)

        try:
            sock.connect((host, port))
            sock.sendall(request.encode("ascii"))

            response = sock.recv(4096)

            if not response:
                return False, "No HTTP response received."

            text = response.decode(
                "iso-8859-1",
                errors="replace",
            )

            first_line = text.splitlines()[0] if text else ""

            if first_line.startswith("HTTP/"):
                return True, first_line

            return False, (
                "TCP response received, "
                "but HTTP status line was not detected."
            )

        except socket.timeout:
            return False, "HTTP probe timed out."

        except OSError as exc:
            return False, f"HTTP probe failed: {exc}"

        finally:
            sock.close()

    def verify(
        self,
        result: ScanResult,
        timeout: float = 2.0,
    ) -> ServiceResult:
        """
        Perform service verification where a safe
        protocol probe is supported.
        """

        mapped = self.identify(result)

        if result.state.value != "OPEN":
            return mapped

        if result.port not in {80, 8080}:
            return mapped

        success, evidence = self.probe_http(
            result.host,
            result.port,
            timeout,
        )

        if success:
            mapped.service = "HTTP"
            mapped.category = "WEB"
            mapped.confidence = "HIGH"
            mapped.detection_method = "HTTP_PROBE"
            mapped.evidence = evidence
        else:
            mapped.evidence = evidence

        return mapped