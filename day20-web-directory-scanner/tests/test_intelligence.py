from scanner.intelligence import RiskIntelligence
from scanner.risk import RiskAssessment


def assessment(rule_id: str, severity: str, score: int):
    return RiskAssessment(
        rule_id=rule_id,
        severity=severity,
        score=score,
        classification=severity,
        recommendation="Test recommendation",
    )


def test_empty_scan_is_info():
    result = RiskIntelligence().summarize([])

    assert result.total_score == 0
    assert result.finding_count == 0
    assert result.overall_level == "INFO"


def test_critical_finding_controls_overall_level():
    result = RiskIntelligence().summarize(
        [
            assessment(
                "SENSITIVE_EXPOSURE",
                "CRITICAL",
                90,
            ),
            assessment(
                "DIRECTORY_403",
                "LOW",
                5,
            ),
        ]
    )

    assert result.total_score == 95
    assert result.finding_count == 2
    assert result.critical_count == 1
    assert result.low_count == 1
    assert result.overall_level == "CRITICAL"


def test_high_finding_controls_overall_level():
    result = RiskIntelligence().summarize(
        [
            assessment("TEST_HIGH", "HIGH", 70),
            assessment("TEST_LOW", "LOW", 5),
        ]
    )

    assert result.overall_level == "HIGH"


def test_medium_finding_controls_overall_level():
    result = RiskIntelligence().summarize(
        [
            assessment("TEST_MEDIUM", "MEDIUM", 20),
        ]
    )

    assert result.overall_level == "MEDIUM"


def test_low_finding_controls_overall_level():
    result = RiskIntelligence().summarize(
        [
            assessment("TEST_LOW", "LOW", 5),
        ]
    )

    assert result.overall_level == "LOW"
