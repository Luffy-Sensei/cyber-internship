from dataclasses import dataclass

from .detector import SecurityFinding


@dataclass(frozen=True)
class RiskAssessment:
    rule_id: str
    severity: str
    score: int
    classification: str
    recommendation: str


class RiskAnalyzer:
    BASE_RISK = {
        "DIRECTORY_200": (20, "MEDIUM"),
        "DIRECTORY_403": (5, "LOW"),
        "DIRECTORY_REDIRECT": (10, "LOW"),
        "DIRECTORY_5XX": (15, "MEDIUM"),
        "SENSITIVE_EXPOSURE": (90, "CRITICAL"),
    }

    RECOMMENDATIONS = {
        "DIRECTORY_200": (
            "Review whether the discovered endpoint "
            "should be publicly accessible."
        ),
        "DIRECTORY_403": (
            "Keep access controls in place and verify "
            "that restricted resources cannot be bypassed."
        ),
        "DIRECTORY_REDIRECT": (
            "Review redirect behavior and ensure the "
            "destination does not expose sensitive resources."
        ),
        "DIRECTORY_5XX": (
            "Investigate server-side errors and avoid "
            "revealing implementation details."
        ),
        "SENSITIVE_EXPOSURE": (
            "Remove sensitive files from the web root and "
            "enforce explicit server-side access restrictions."
        ),
    }

    def assess(self, finding: SecurityFinding) -> RiskAssessment:
        score, severity = self.BASE_RISK.get(
            finding.rule_id,
            (0, "INFO"),
        )

        classification = self._classify(score)

        recommendation = self.RECOMMENDATIONS.get(
            finding.rule_id,
            "Review the finding and apply appropriate access controls.",
        )

        return RiskAssessment(
            rule_id=finding.rule_id,
            severity=severity,
            score=score,
            classification=classification,
            recommendation=recommendation,
        )

    @staticmethod
    def _classify(score: int) -> str:
        if score >= 80:
            return "CRITICAL"

        if score >= 60:
            return "HIGH"

        if score >= 20:
            return "MEDIUM"

        if score > 0:
            return "LOW"

        return "INFO"
