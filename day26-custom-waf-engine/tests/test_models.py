import pytest

from scanner.models import (
    Confidence,
    HTTPRequest,
    RuleCategory,
    Severity,
    WAFAction,
    WAFDecision,
    WAFDetection,
    WAFRule,
)


def test_http_request_model():
    request = HTTPRequest(
        request_id="req-001",
        method="GET",
        path="/search",
        query="q=test",
        headers={"Host": "localhost"},
        body="",
    )

    assert request.request_id == "req-001"
    assert request.method == "GET"
    assert request.path == "/search"
    assert request.query == "q=test"
    assert request.headers["Host"] == "localhost"


def test_waf_rule_model():
    rule = WAFRule(
        rule_id="SQLI-001",
        category=RuleCategory.SQLI,
        pattern=r"(?i)union\s+select",
        severity=Severity.HIGH,
        description="SQL injection indicator",
    )

    assert rule.rule_id == "SQLI-001"
    assert rule.category is RuleCategory.SQLI
    assert rule.severity is Severity.HIGH
    assert rule.enabled is True


def test_waf_detection_model():
    detection = WAFDetection(
        rule_id="XSS-001",
        category=RuleCategory.XSS,
        severity=Severity.HIGH,
        matched_field="query",
        evidence="<script>",
        confidence=Confidence.HIGH,
    )

    assert detection.rule_id == "XSS-001"
    assert detection.matched_field == "query"
    assert detection.confidence is Confidence.HIGH


def test_waf_decision_model():
    detection = WAFDetection(
        rule_id="TRAVERSAL-001",
        category=RuleCategory.PATH_TRAVERSAL,
        severity=Severity.HIGH,
        matched_field="path",
        evidence="../",
        confidence=Confidence.HIGH,
    )

    decision = WAFDecision(
        request_id="req-002",
        action=WAFAction.BLOCK,
        detections=(detection,),
    )

    assert decision.request_id == "req-002"
    assert decision.action is WAFAction.BLOCK
    assert len(decision.detections) == 1


def test_http_request_rejects_empty_request_id():
    with pytest.raises(ValueError):
        HTTPRequest(
            request_id="",
            method="GET",
            path="/",
        )


def test_waf_rule_rejects_empty_pattern():
    with pytest.raises(ValueError):
        WAFRule(
            rule_id="TEST-001",
            category=RuleCategory.SQLI,
            pattern="",
            severity=Severity.LOW,
            description="Test rule",
        )


def test_waf_detection_rejects_empty_evidence():
    with pytest.raises(ValueError):
        WAFDetection(
            rule_id="TEST-001",
            category=RuleCategory.SQLI,
            severity=Severity.LOW,
            matched_field="query",
            evidence="",
            confidence=Confidence.LOW,
        )


def test_waf_decision_rejects_non_tuple_detections():
    with pytest.raises(TypeError):
        WAFDecision(
            request_id="req-003",
            action=WAFAction.ALLOW,
            detections=[],  # type: ignore[arg-type]
        )
