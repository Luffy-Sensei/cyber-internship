from scanner.detector import SecurityFinding
from scanner.risk import RiskAnalyzer


def make_finding(rule_id: str) -> SecurityFinding:
    return SecurityFinding(
        rule_id=rule_id,
        path="test",
        url="http://127.0.0.1:5000/test",
        status_code=200,
        message="Test finding",
        evidence="HTTP 200",
    )


def test_sensitive_exposure_is_critical():
    assessment = RiskAnalyzer().assess(
        make_finding("SENSITIVE_EXPOSURE")
    )

    assert assessment.severity == "CRITICAL"
    assert assessment.score == 90
    assert assessment.classification == "CRITICAL"


def test_directory_200_is_medium():
    assessment = RiskAnalyzer().assess(
        make_finding("DIRECTORY_200")
    )

    assert assessment.severity == "MEDIUM"
    assert assessment.score == 20
    assert assessment.classification == "MEDIUM"


def test_forbidden_endpoint_is_low():
    assessment = RiskAnalyzer().assess(
        make_finding("DIRECTORY_403")
    )

    assert assessment.severity == "LOW"
    assert assessment.score == 5
    assert assessment.classification == "LOW"


def test_redirect_is_low():
    assessment = RiskAnalyzer().assess(
        make_finding("DIRECTORY_REDIRECT")
    )

    assert assessment.severity == "LOW"
    assert assessment.score == 10


def test_server_error_is_medium():
    assessment = RiskAnalyzer().assess(
        make_finding("DIRECTORY_5XX")
    )

    assert assessment.severity == "MEDIUM"
    assert assessment.score == 15


def test_unknown_rule_is_info():
    assessment = RiskAnalyzer().assess(
        make_finding("UNKNOWN_RULE")
    )

    assert assessment.severity == "INFO"
    assert assessment.score == 0
    assert assessment.classification == "INFO"
