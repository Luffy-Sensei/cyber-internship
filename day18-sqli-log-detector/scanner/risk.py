from dataclasses import dataclass

from .models import Detection


@dataclass(frozen=True)
class RiskAssessment:
    """Risk assessment for a detected SQLi event."""

    severity: str
    score: int
    classification: str
    recommendation: str


class RiskEngine:
    """Convert SQLi detection signals into defensive risk assessments."""

    SIGNATURE_WEIGHTS = {
        "UNION_SELECT": 80,
        "TAUTOLOGY": 70,
        "SQL_COMMENT": 30,
    }

    def assess(
        self,
        detections: tuple[Detection, ...],
    ) -> RiskAssessment:
        if not detections:
            return RiskAssessment(
                severity="NONE",
                score=0,
                classification="NO_SQLI_INDICATOR",
                recommendation="No immediate action is required.",
            )

        score = sum(
            self.SIGNATURE_WEIGHTS.get(
                detection.signature,
                0,
            )
            for detection in detections
        )

        score = min(score, 100)
        if score == 0:
            return RiskAssessment(
                severity="LOW",
                score=0,
                classification="UNWEIGHTED_SQLI_INDICATOR",
                recommendation=(
                    "Review the detection rule and manually investigate "
                    "the associated request."
                ),
            )

        if score >= 90:
            severity = "CRITICAL"
        elif score >= 70:
            severity = "HIGH"
        elif score >= 40:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return RiskAssessment(
            severity=severity,
            score=score,
            classification="SQLI_INDICATOR",
            recommendation=(
                "Investigate the source request, review application "
                "parameter handling, and verify that database access "
                "uses parameterized queries."
            ),
        )
