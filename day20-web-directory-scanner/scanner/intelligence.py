from dataclasses import dataclass

from .risk import RiskAssessment


@dataclass(frozen=True)
class AggregateRisk:
    total_score: int
    maximum_score: int
    overall_level: str
    finding_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int


class RiskIntelligence:
    def summarize(
        self,
        assessments: list[RiskAssessment],
    ) -> AggregateRisk:

        total_score = sum(
            assessment.score
            for assessment in assessments
        )

        maximum_score = len(assessments) * 100

        critical_count = sum(
            assessment.severity == "CRITICAL"
            for assessment in assessments
        )

        high_count = sum(
            assessment.severity == "HIGH"
            for assessment in assessments
        )

        medium_count = sum(
            assessment.severity == "MEDIUM"
            for assessment in assessments
        )

        low_count = sum(
            assessment.severity == "LOW"
            for assessment in assessments
        )

        overall_level = self._overall_level(
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            total_score=total_score,
        )

        return AggregateRisk(
            total_score=total_score,
            maximum_score=maximum_score,
            overall_level=overall_level,
            finding_count=len(assessments),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
        )

    @staticmethod
    def _overall_level(
        *,
        critical_count: int,
        high_count: int,
        medium_count: int,
        total_score: int,
    ) -> str:

        if critical_count:
            return "CRITICAL"

        if high_count:
            return "HIGH"

        if medium_count or total_score >= 20:
            return "MEDIUM"

        if total_score > 0:
            return "LOW"

        return "INFO"
