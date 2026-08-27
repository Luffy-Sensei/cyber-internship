from scanner.risk import RiskEngine
from scanner.models import Detection


def detection(signature: str, confidence: str = "HIGH"):
    return Detection(
        signature=signature,
        confidence=confidence,
        description="test detection",
        evidence="test evidence",
    )


def test_no_detections_have_no_risk():
    engine = RiskEngine()

    result = engine.assess(())

    assert result.severity == "NONE"
    assert result.score == 0


def test_tautology_is_high():
    engine = RiskEngine()

    result = engine.assess(
        (detection("TAUTOLOGY"),)
    )

    assert result.severity == "HIGH"
    assert result.score == 70


def test_union_select_is_high():
    engine = RiskEngine()

    result = engine.assess(
        (detection("UNION_SELECT"),)
    )

    assert result.severity == "HIGH"
    assert result.score == 80


def test_union_select_with_comment_is_critical():
    engine = RiskEngine()

    result = engine.assess(
        (
            detection("UNION_SELECT"),
            detection("SQL_COMMENT", "MEDIUM"),
        )
    )

    assert result.severity == "CRITICAL"
    assert result.score == 100


def test_unknown_signature_has_zero_weight():
    engine = RiskEngine()

    result = engine.assess(
        (detection("UNKNOWN"),)
    )

    assert result.score == 0
    assert result.severity == "LOW"
