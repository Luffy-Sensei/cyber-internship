import re

from .models import HTTPMethod, LogEntry


LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+-\s+'
    r'"(?P<method>[A-Z]+)\s+'
    r'(?P<path>\S+)\s+'
    r'(?P<protocol>HTTP/\d(?:\.\d)?)"\s+'
    r'(?P<status>\d{3})$'
)


class LogParser:
    """Parse the controlled Day 18 access-log format."""

    def parse_line(self, line: str) -> LogEntry:
        line = line.strip()

        if not line:
            raise ValueError("Cannot parse an empty log entry.")

        match = LOG_PATTERN.match(line)

        if not match:
            raise ValueError(
                f"Invalid access-log entry: {line}"
            )

        method_text = match.group("method")

        try:
            method = HTTPMethod(method_text)
        except ValueError as exc:
            raise ValueError(
                f"Unsupported HTTP method: {method_text}"
            ) from exc

        return LogEntry(
            source_ip=match.group("ip"),
            method=method,
            path=match.group("path"),
            protocol=match.group("protocol"),
            status_code=int(match.group("status")),
            raw=line,
        )
