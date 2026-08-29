from __future__ import annotations

from typing import Iterable

from .detector import SecurityDetector, SecurityFinding
from .models import PathResult
from .reporting import ScanReporter
from .risk import RiskAnalyzer


class WebDirectoryAnalyzer:
    """Coordinate detection, risk analysis, and report generation."""

    def __init__(
        self,
        target: str,
        wordlist: list[str],
    ) -> None:
        self.target = target
        self.wordlist = wordlist
        self.detector = SecurityDetector()
        self.risk_analyzer = RiskAnalyzer()

    def analyze(
        self,
        results: Iterable[PathResult],
    ) -> dict:
        """
        Analyze path results and return a complete report dictionary.
        """

        findings: list[dict] = []

        for result in results:
            detections = self.detector.analyze(result)

            for detection in detections:
                risk = self.risk_analyzer.assess(detection)

                findings.append(
                    self._finding_to_dict(
                        detection,
                        risk,
                    )
                )

        reporter = ScanReporter(
            target=self.target,
            wordlist_size=len(self.wordlist),
            requests_sent=len(self.wordlist),
        )

        return reporter.build_report(findings)

    @staticmethod
    def _finding_to_dict(
        finding: SecurityFinding,
        risk,
    ) -> dict:
        """Convert internal finding objects into report data."""

        return {
            "rule_id": finding.rule_id,
            "path": finding.path,
            "url": finding.url,
            "status_code": finding.status_code,
            "message": finding.message,
            "evidence": finding.evidence,
            "severity": risk.severity,
            "risk_score": risk.score,
            "classification": risk.classification,
            "recommendation": risk.recommendation,
        }