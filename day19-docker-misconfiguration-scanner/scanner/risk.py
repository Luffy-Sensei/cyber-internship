from dataclasses import dataclass

from .detector import SecurityFinding


@dataclass(frozen=True)
class RiskAssessment:
    severity: str
    score: int
    classification: str
    recommendation: str


class RiskAnalyzer:
    """Convert security findings into normalized risk assessments."""

    SEVERITY_SCORES = {
        "CRITICAL": 100,
        "HIGH": 75,
        "MEDIUM": 50,
        "LOW": 25,
    }

    def assess(
        self,
        finding: SecurityFinding,
    ) -> RiskAssessment:
        severity = finding.severity.upper()

        score = self.SEVERITY_SCORES.get(
            severity,
            0,
        )

        return RiskAssessment(
            severity=severity,
            score=score,
            classification="DOCKERFILE_MISCONFIGURATION",
            recommendation=finding.recommendation,
        )
