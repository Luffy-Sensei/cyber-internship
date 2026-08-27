from urllib.parse import unquote

from .models import Detection, Finding, LogEntry
from .signatures import SIGNATURES


class SQLiDetector:
    """Detect SQL injection indicators in HTTP log entries."""

    def normalize(self, value: str) -> str:
        """Decode URL-encoded content for signature inspection."""
        return unquote(value)

    def analyze(self, entry: LogEntry) -> Finding | None:
        normalized_path = self.normalize(entry.path)

        detections = []

        for signature in SIGNATURES:
            match = signature.pattern.search(normalized_path)

            if match:
                detections.append(
                    Detection(
                        signature=signature.name,
                        confidence=signature.confidence,
                        description=signature.description,
                        evidence=match.group(0),
                    )
                )

        if not detections:
            return None

        return Finding(
            source_ip=entry.source_ip,
            method=entry.method,
            path=entry.path,
            status_code=entry.status_code,
            detections=tuple(detections),
            raw=entry.raw,
        )
