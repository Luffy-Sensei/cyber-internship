import pytest

from scanner.config import WAFPolicy
from scanner.models import (
    Confidence,
    RuleCategory,
    Severity,
    WAFAction,
    WAFDetection,
    WAFResult,
)
from scanner.policies import WAFPolicyEngine


def make_detection(
    rule_id: str,
    severity: Severity,
    confidence: Confidence = Confidence.HIGH,
) -> WAFDetection:
    return WAFDetection(
        rule_id=rule_id,
        category=RuleCategory.SQLI,
        severity=severity,
        matched_field="query",
        evidence="controlled-test",
        confidence=confidence,
    )


def make_result(*detections: WAFDetection) -> WAFResult:
    return WAFResult(
        request_id="policy-test-001",
        detections=tuple(detections),
    )


def test_no_detections_are_allowed():
    result = make_result()

    decision = WAFPolicyEngine().decide(result)

    assert decision.action is WAFAction.ALLOW
    assert decision.detections == ()


def test_medium_severity_is_monitored():
    result = make_result(
        make_detection(
            "TEST-MEDIUM",
            Severity.MEDIUM,
        )
    )

    decision = WAFPolicyEngine().decide(result)

    assert decision.action is WAFAction.MONITOR
    assert len(decision.detections) == 1


def test_high_severity_is_blocked():
    result = make_result(
        make_detection(
            "TEST-HIGH",
            Severity.HIGH,
        )
    )

    decision = WAFPolicyEngine().decide(result)

    assert decision.action is WAFAction.BLOCK


def test_critical_severity_is_blocked():
    result = make_result(
        make_detection(
            "TEST-CRITICAL",
            Severity.CRITICAL,
        )
    )

    decision = WAFPolicyEngine().decide(result)

    assert decision.action is WAFAction.BLOCK


def test_highest_severity_wins():
    result = make_result(
        make_detection(
            "TEST-MEDIUM",
            Severity.MEDIUM,
        ),
        make_detection(
            "TEST-HIGH",
            Severity.HIGH,
        ),
    )

    decision = WAFPolicyEngine().decide(result)

    assert decision.action is WAFAction.BLOCK
    assert len(decision.detections) == 2


def test_low_severity_falls_back_to_default_action():
    result = make_result(
        make_detection(
            "TEST-LOW",
            Severity.LOW,
        )
    )

    decision = WAFPolicyEngine().decide(result)

    assert decision.action is WAFAction.ALLOW


def test_low_confidence_detection_is_filtered():
    result = make_result(
        make_detection(
            "TEST-HIGH",
            Severity.HIGH,
            Confidence.LOW,
        )
    )

    decision = WAFPolicyEngine().decide(result)

    assert decision.action is WAFAction.ALLOW
    assert decision.detections == ()


def test_minimum_confidence_is_configurable():
    policy = WAFPolicy(
        minimum_confidence=Confidence.HIGH,
    )

    result = make_result(
        make_detection(
            "TEST-MEDIUM-CONFIDENCE",
            Severity.HIGH,
            Confidence.MEDIUM,
        )
    )

    decision = WAFPolicyEngine(policy).decide(result)

    assert decision.action is WAFAction.ALLOW
    assert decision.detections == ()


def test_medium_confidence_is_accepted_by_default():
    result = make_result(
        make_detection(
            "TEST-MEDIUM-CONFIDENCE",
            Severity.HIGH,
            Confidence.MEDIUM,
        )
    )

    decision = WAFPolicyEngine().decide(result)

    assert decision.action is WAFAction.BLOCK
    assert len(decision.detections) == 1


def test_custom_block_threshold_is_respected():
    policy = WAFPolicy(
        block_severity=Severity.CRITICAL,
        monitor_severity=Severity.MEDIUM,
    )

    result = make_result(
        make_detection(
            "TEST-HIGH",
            Severity.HIGH,
        )
    )

    decision = WAFPolicyEngine(policy).decide(result)

    assert decision.action is WAFAction.MONITOR


def test_policy_preserves_request_id():
    result = WAFResult(
        request_id="request-xyz",
        detections=(),
    )

    decision = WAFPolicyEngine().decide(result)

    assert decision.request_id == "request-xyz"


def test_policy_rejects_invalid_result():
    with pytest.raises(TypeError):
        WAFPolicyEngine().decide("invalid")  # type: ignore[arg-type]
