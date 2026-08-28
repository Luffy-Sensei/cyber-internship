from scanner.detector import SecurityFinding
from scanner.risk import RiskAnalyzer


def make_finding(
    rule_id="TEST_RULE",
    severity="HIGH",
):
    return SecurityFinding(
        rule_id=rule_id,
        severity=severity,
        line_number=1,
        message="Test finding",
        recommendation="Apply the recommended security control.",
    )


def test_critical_score():
    finding = make_finding(severity="CRITICAL")

    assessment = RiskAnalyzer().assess(finding)

    assert assessment.severity == "CRITICAL"
    assert assessment.score == 100


def test_high_score():
    finding = make_finding(severity="HIGH")

    assessment = RiskAnalyzer().assess(finding)

    assert assessment.severity == "HIGH"
    assert assessment.score == 75


def test_medium_score():
    finding = make_finding(severity="MEDIUM")

    assessment = RiskAnalyzer().assess(finding)

    assert assessment.severity == "MEDIUM"
    assert assessment.score == 50


def test_low_score():
    finding = make_finding(severity="LOW")

    assessment = RiskAnalyzer().assess(finding)

    assert assessment.severity == "LOW"
    assert assessment.score == 25


def test_classification():
    finding = make_finding()

    assessment = RiskAnalyzer().assess(finding)

    assert assessment.classification == (
        "DOCKERFILE_MISCONFIGURATION"
    )


def test_recommendation_preserved():
    finding = make_finding()

    assessment = RiskAnalyzer().assess(finding)

    assert assessment.recommendation == (
        "Apply the recommended security control."
    )
