import pytest

from scanner.config import DEFAULT_WAF_RULES
from scanner.models import (
    Confidence,
    HTTPRequest,
    RuleCategory,
    Severity,
)
from scanner.normalizer import RequestNormalizer
from scanner.rules import WAFRuleEngine


def test_sqli_rule_generates_structured_detection():
    request = HTTPRequest(
        request_id="req-001",
        method="GET",
        path="/search",
        query="q=UNION%20SELECT",
    )

    engine = WAFRuleEngine(DEFAULT_WAF_RULES)

    detections = engine.inspect(request)

    assert len(detections) == 1

    detection = detections[0]

    assert detection.rule_id == "SQLI-001"
    assert detection.category is RuleCategory.SQLI
    assert detection.severity is Severity.HIGH
    assert detection.matched_field == "query"
    assert detection.evidence == "UNION SELECT"
    assert detection.confidence is Confidence.HIGH


def test_xss_rule_generates_detection():
    request = HTTPRequest(
        request_id="req-002",
        method="GET",
        path="/search",
        query="q=%3Cscript%3E",
    )

    engine = WAFRuleEngine(DEFAULT_WAF_RULES)

    detections = engine.inspect(request)

    assert len(detections) == 1
    assert detections[0].rule_id == "XSS-001"
    assert detections[0].matched_field == "query"


def test_path_traversal_rule_generates_detection():
    request = HTTPRequest(
        request_id="req-003",
        method="GET",
        path="/files/%2e%2e/%2e%2e/secret",
    )

    engine = WAFRuleEngine(DEFAULT_WAF_RULES)

    detections = engine.inspect(request)

    assert len(detections) == 1
    assert detections[0].rule_id == "TRAVERSAL-001"
    assert detections[0].category is RuleCategory.PATH_TRAVERSAL
    assert detections[0].matched_field == "path"


def test_clean_request_generates_no_detections():
    request = HTTPRequest(
        request_id="req-004",
        method="GET",
        path="/products",
        query="category=books",
    )

    engine = WAFRuleEngine(DEFAULT_WAF_RULES)

    detections = engine.inspect(request)

    assert detections == ()


def test_multiple_rules_can_trigger():
    request = HTTPRequest(
        request_id="req-005",
        method="GET",
        path="/files/%2e%2e/secret",
        query="q=%3Cscript%3E",
    )

    engine = WAFRuleEngine(DEFAULT_WAF_RULES)

    detections = engine.inspect(request)

    rule_ids = {detection.rule_id for detection in detections}

    assert "XSS-001" in rule_ids
    assert "TRAVERSAL-001" in rule_ids


def test_disabled_rule_is_not_evaluated():
    enabled_rule = DEFAULT_WAF_RULES[0]

    from scanner.models import WAFRule

    disabled_rule = WAFRule(
        rule_id="DISABLED-001",
        category=enabled_rule.category,
        pattern=enabled_rule.pattern,
        severity=enabled_rule.severity,
        description="Disabled test rule",
        enabled=False,
    )

    engine = WAFRuleEngine((disabled_rule,))

    request = HTTPRequest(
        request_id="req-006",
        method="GET",
        path="/search",
        query="UNION%20SELECT",
    )

    assert engine.inspect(request) == ()


def test_engine_accepts_already_normalized_request():
    request = HTTPRequest(
        request_id="req-007",
        method="GET",
        path="/search",
        query="q=%3Cscript%3E",
    )

    normalized = RequestNormalizer().normalize(request)
    engine = WAFRuleEngine(DEFAULT_WAF_RULES)

    detections = engine.inspect(normalized)

    assert len(detections) == 1
    assert detections[0].rule_id == "XSS-001"


def test_engine_rejects_invalid_request_type():
    engine = WAFRuleEngine(DEFAULT_WAF_RULES)

    with pytest.raises(TypeError):
        engine.inspect("not-a-request")  # type: ignore[arg-type]


def test_invalid_rule_pattern_is_rejected():
    from scanner.models import WAFRule

    invalid_rule = WAFRule(
        rule_id="INVALID-001",
        category=RuleCategory.SQLI,
        pattern="[invalid",
        severity=Severity.HIGH,
        description="Invalid regex test",
    )

    with pytest.raises(ValueError):
        WAFRuleEngine((invalid_rule,))
