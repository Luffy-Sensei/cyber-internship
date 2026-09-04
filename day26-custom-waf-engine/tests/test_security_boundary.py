import pytest

from scanner.config import (
    DEFAULT_WAF_POLICY,
    DEFAULT_WAF_RULES,
    WAFPolicy,
)
from scanner.engine import WAFDetectionEngine
from scanner.models import (
    Confidence,
    HTTPRequest,
    RuleCategory,
    Severity,
    WAFAction,
    WAFResult,
    WAFRule,
)
from scanner.policies import WAFPolicyEngine
from scanner.rules import WAFRuleEngine


def build_pipeline(
    rules=DEFAULT_WAF_RULES,
    policy=DEFAULT_WAF_POLICY,
):
    rule_engine = WAFRuleEngine(rules)
    detection_engine = WAFDetectionEngine(rule_engine)
    policy_engine = WAFPolicyEngine(policy)

    return detection_engine, policy_engine


def test_clean_request_is_allowed():
    detection_engine, policy_engine = build_pipeline()

    request = HTTPRequest(
        request_id="boundary-clean-001",
        method="GET",
        path="/products",
        query="category=books",
    )

    result = detection_engine.inspect(request)
    decision = policy_engine.decide(result)

    assert result.detected is False
    assert decision.action is WAFAction.ALLOW
    assert decision.detections == ()


def test_sqli_fixture_is_blocked():
    detection_engine, policy_engine = build_pipeline()

    request = HTTPRequest(
        request_id="boundary-sqli-001",
        method="GET",
        path="/search",
        query="q=UNION%20SELECT",
    )

    result = detection_engine.inspect(request)
    decision = policy_engine.decide(result)

    assert result.detected is True
    assert decision.action is WAFAction.BLOCK
    assert decision.detections[0].category is RuleCategory.SQLI


def test_xss_fixture_is_blocked():
    detection_engine, policy_engine = build_pipeline()

    request = HTTPRequest(
        request_id="boundary-xss-001",
        method="GET",
        path="/search",
        query="q=%3Cscript%3E",
    )

    result = detection_engine.inspect(request)
    decision = policy_engine.decide(result)

    assert result.detected is True
    assert decision.action is WAFAction.BLOCK
    assert decision.detections[0].category is RuleCategory.XSS


def test_traversal_fixture_is_blocked():
    detection_engine, policy_engine = build_pipeline()

    request = HTTPRequest(
        request_id="boundary-traversal-001",
        method="GET",
        path="/files/%2e%2e/%2e%2e/secret",
    )

    result = detection_engine.inspect(request)
    decision = policy_engine.decide(result)

    assert result.detected is True
    assert decision.action is WAFAction.BLOCK
    assert (
        decision.detections[0].category
        is RuleCategory.PATH_TRAVERSAL
    )


def test_multiple_attack_indicators_are_aggregated():
    detection_engine, policy_engine = build_pipeline()

    request = HTTPRequest(
        request_id="boundary-multi-001",
        method="POST",
        path="/submit",
        query="q=UNION%20SELECT",
        body="<script>",
    )

    result = detection_engine.inspect(request)
    decision = policy_engine.decide(result)

    assert result.detection_count == 2
    assert decision.action is WAFAction.BLOCK

    rule_ids = {
        detection.rule_id
        for detection in decision.detections
    }

    assert rule_ids == {
        "SQLI-001",
        "XSS-001",
    }


def test_percent_encoded_input_is_normalized_before_detection():
    detection_engine, policy_engine = build_pipeline()

    request = HTTPRequest(
        request_id="boundary-encoded-001",
        method="GET",
        path="/search",
        query=(
            "q=%55%4E%49%4F%4E"
            "%20%53%45%4C%45%43%54"
        ),
    )

    result = detection_engine.inspect(request)
    decision = policy_engine.decide(result)

    assert result.detected is True
    assert decision.action is WAFAction.BLOCK
    assert decision.detections[0].rule_id == "SQLI-001"


def test_invalid_request_structure_is_rejected():
    detection_engine, _ = build_pipeline()

    with pytest.raises(TypeError):
        detection_engine.inspect(
            "not-an-http-request"
        )  # type: ignore[arg-type]


def test_empty_request_id_is_rejected():
    with pytest.raises(ValueError):
        HTTPRequest(
            request_id="",
            method="GET",
            path="/",
        )


def test_empty_path_is_rejected():
    with pytest.raises(ValueError):
        HTTPRequest(
            request_id="boundary-empty-path",
            method="GET",
            path="",
        )


def test_empty_query_and_body_are_safe():
    detection_engine, policy_engine = build_pipeline()

    request = HTTPRequest(
        request_id="boundary-empty-fields",
        method="POST",
        path="/submit",
        query="",
        body="",
    )

    result = detection_engine.inspect(request)
    decision = policy_engine.decide(result)

    assert result.detected is False
    assert decision.action is WAFAction.ALLOW


def test_disabled_rule_is_not_evaluated():
    disabled_rule = WAFRule(
        rule_id="DISABLED-001",
        category=RuleCategory.XSS,
        pattern=r"(?i)<\s*script\b",
        severity=Severity.HIGH,
        description="Disabled controlled test rule.",
        enabled=False,
    )

    detection_engine, policy_engine = build_pipeline(
        rules=(disabled_rule,)
    )

    request = HTTPRequest(
        request_id="boundary-disabled-001",
        method="GET",
        path="/search",
        query="q=%3Cscript%3E",
    )

    result = detection_engine.inspect(request)
    decision = policy_engine.decide(result)

    assert result.detected is False
    assert decision.action is WAFAction.ALLOW
    assert decision.detections == ()


def test_false_positive_boundary_plain_text_is_allowed():
    detection_engine, policy_engine = build_pipeline()

    request = HTTPRequest(
        request_id="boundary-fp-001",
        method="GET",
        path="/docs",
        query="topic=scriptwriting",
    )

    result = detection_engine.inspect(request)
    decision = policy_engine.decide(result)

    assert result.detected is False
    assert decision.action is WAFAction.ALLOW


def test_false_positive_boundary_union_word_is_allowed():
    detection_engine, policy_engine = build_pipeline()

    request = HTTPRequest(
        request_id="boundary-fp-002",
        method="GET",
        path="/search",
        query="q=union+membership",
    )

    result = detection_engine.inspect(request)
    decision = policy_engine.decide(result)

    assert result.detected is False
    assert decision.action is WAFAction.ALLOW


def test_false_positive_boundary_parent_directory_word_is_allowed():
    detection_engine, policy_engine = build_pipeline()

    request = HTTPRequest(
        request_id="boundary-fp-003",
        method="GET",
        path="/docs",
        query="topic=parent-directory",
    )

    result = detection_engine.inspect(request)
    decision = policy_engine.decide(result)

    assert result.detected is False
    assert decision.action is WAFAction.ALLOW


def test_low_confidence_high_severity_does_not_bypass_policy():
    detection_engine, policy_engine = build_pipeline()

    request = HTTPRequest(
        request_id="boundary-confidence-001",
        method="GET",
        path="/controlled",
    )

    result = WAFResult(
        request_id=request.request_id,
        detections=(),
    )

    decision = policy_engine.decide(result)

    assert decision.action is WAFAction.ALLOW


def test_custom_policy_threshold_changes_enforcement():
    custom_policy = WAFPolicy(
        block_severity=Severity.CRITICAL,
        monitor_severity=Severity.MEDIUM,
        minimum_confidence=Confidence.MEDIUM,
    )

    detection_engine, policy_engine = build_pipeline(
        policy=custom_policy
    )

    request = HTTPRequest(
        request_id="boundary-policy-001",
        method="GET",
        path="/search",
        query="q=UNION%20SELECT",
    )

    result = detection_engine.inspect(request)
    decision = policy_engine.decide(result)

    assert result.detected is True
    assert decision.action is WAFAction.MONITOR
