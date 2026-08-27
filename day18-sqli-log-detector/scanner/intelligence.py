from .detector import SQLiDetector
from .models import Finding, LogEntry
from .risk import RiskEngine


class SecurityAnalyzer:
    """Combine detection and risk assessment."""

    def __init__(
        self,
        detector: SQLiDetector | None = None,
        risk_engine: RiskEngine | None = None,
    ):
        self.detector = detector or SQLiDetector()
        self.risk_engine = risk_engine or RiskEngine()

    def analyze(self, entry: LogEntry) -> Finding | None:
        finding = self.detector.analyze(entry)

        if finding is None:
            return None

        risk = self.risk_engine.assess(
            finding.detections
        )

        return Finding(
            source_ip=finding.source_ip,
            method=finding.method,
            path=finding.path,
            status_code=finding.status_code,
            detections=finding.detections,
            raw=finding.raw,
            risk=risk,
        )
