from scanner.config import PipelineConfig
from scanner.models import FirewallAction, ThreatIndicator
from scanner.policies import ThreatPolicy, get_default_policy


def make_indicator(risk_score: int) -> ThreatIndicator:
    return ThreatIndicator(
        ip="103.45.67.89",
        indicator="malware_c2",
        risk_score=risk_score,
        source="mock-feed",
    )


def test_high_risk_indicator_is_blocked():
    policy = get_default_policy()

    decision = policy.evaluate(make_indicator(98))

    assert decision.action is FirewallAction.BLOCK
    assert decision.indicator == "malware_c2"
    assert decision.risk_score == 98
    assert decision.policy == "default-threat-block-policy"


def test_block_threshold_boundary_is_blocked():
    policy = get_default_policy()

    decision = policy.evaluate(make_indicator(90))

    assert decision.action is FirewallAction.BLOCK


def test_risk_89_is_monitored():
    policy = get_default_policy()

    decision = policy.evaluate(make_indicator(89))

    assert decision.action is FirewallAction.MONITOR


def test_monitor_threshold_boundary_is_monitored():
    policy = get_default_policy()

    decision = policy.evaluate(make_indicator(70))

    assert decision.action is FirewallAction.MONITOR


def test_risk_69_is_ignored():
    policy = get_default_policy()

    decision = policy.evaluate(make_indicator(69))

    assert decision.action is FirewallAction.IGNORE


def test_zero_risk_is_ignored():
    policy = get_default_policy()

    decision = policy.evaluate(make_indicator(0))

    assert decision.action is FirewallAction.IGNORE


def test_custom_thresholds_are_respected():
    config = PipelineConfig(
        block_threshold=80,
        monitor_threshold=50,
    )

    policy = get_default_policy(config)

    assert policy.evaluate(make_indicator(85)).action is FirewallAction.BLOCK
    assert policy.evaluate(make_indicator(70)).action is FirewallAction.MONITOR
    assert policy.evaluate(make_indicator(40)).action is FirewallAction.IGNORE


def test_policy_name_is_preserved():
    policy = ThreatPolicy(
        name="custom-threat-policy",
        block_threshold=95,
        monitor_threshold=70,
    )

    decision = policy.evaluate(make_indicator(98))

    assert decision.policy == "custom-threat-policy"


def test_block_reason_is_present():
    policy = get_default_policy()

    decision = policy.evaluate(make_indicator(98))

    assert "blocking threshold" in decision.reason


def test_monitor_reason_is_present():
    policy = get_default_policy()

    decision = policy.evaluate(make_indicator(85))

    assert "monitoring threshold" in decision.reason


def test_ignore_reason_is_present():
    policy = get_default_policy()

    decision = policy.evaluate(make_indicator(40))

    assert "monitoring threshold" in decision.reason
