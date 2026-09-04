import pytest

from scanner.config import DEFAULT_WAF_RULES
from scanner.engine import WAFDetectionEngine
from scanner.models import (
    HTTPRequest,
    RuleCategory,
)
from scanner.rules import WAFRuleEngine


def build_engine() -> WAFDetectionEngine:
    rule_engine = WAFRuleEngine(DEFAULT_WAF_RULES)
    return WAFDetectionEngine(rule_engine)


def test_clean_request_returns_empty_result():
    request = HTTPRequest(
        request_id="req-001",
        method="GET",
        path="/products",
        query="category=books",
    )

    result = build_engine().inspect(request)

    assert result.request_id == "req-001"
    assert result.detected is False
    assert result.detection_count == 0
    assert result.detections == ()


def test_sqli_request_returns_waf_result():
    request = HTTPRequest(
        request_id="req-002",
        method="GET",
        path="/search",
        query="q=UNION%20SELECT",
    )

    result = build_engine().inspect(request)

    assert result.detected is True
    assert result.detection_count == 1
    assert result.detections[0].rule_id == "SQLI-001"
    assert result.detections[0].category is RuleCategory.SQLI


def test_xss_request_returns_waf_result():
    request = HTTPRequest(
        request_id="req-003",
        method="GET",
        path="/search",
        query="q=%3Cscript%3E",
    )

    result = build_engine().inspect(request)

    assert result.detected is True
    assert result.detection_count == 1
    assert result.detections[0].rule_id == "XSS-001"


def test_traversal_request_returns_waf_result():
    request = HTTPRequest(
        request_id="req-004",
        method="GET",
        path="/files/%2e%2e/%2e%2e/secret",
    )

    result = build_engine().inspect(request)

    assert result.detected is True
    assert result.detection_count == 1
    assert result.detections[0].rule_id == "TRAVERSAL-001"


def test_multiple_detections_are_collected():
    request = HTTPRequest(
        request_id="req-005",
        method="GET",
        path="/files/%2e%2e/secret",
        query="q=%3Cscript%3E",
    )

    result = build_engine().inspect(request)

    assert result.detected is True
    assert result.detection_count == 2

    rule_ids = {
        detection.rule_id
        for detection in result.detections
    }

    assert rule_ids == {
        "XSS-001",
        "TRAVERSAL-001",
    }


def test_multiple_fields_can_produce_multiple_detections():
    request = HTTPRequest(
        request_id="req-006",
        method="POST",
        path="/submit",
        query="q=UNION%20SELECT",
        body="<script>",
    )

    result = build_engine().inspect(request)

    assert result.detection_count == 2

    fields = {
        detection.matched_field
        for detection in result.detections
    }

    assert "query" in fields
    assert "body" in fields


def test_normalization_occurs_before_detection():
    request = HTTPRequest(
        request_id="req-007",
        method="GET",
        path="/search",
        query="q=%55%4E%49%4F%4E%20%53%45%4C%45%43%54",
    )

    result = build_engine().inspect(request)

    assert result.detected is True
    assert result.detections[0].rule_id == "SQLI-001"


def test_engine_preserves_request_id():
    request = HTTPRequest(
        request_id="unique-request-123",
        method="GET",
        path="/",
    )

    result = build_engine().inspect(request)

    assert result.request_id == "unique-request-123"


def test_engine_rejects_invalid_request_type():
    with pytest.raises(TypeError):
        build_engine().inspect("invalid")  # type: ignore[arg-type]
