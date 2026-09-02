from scanner.firewall import FirewallAdapter
from scanner.models import (
    FirewallAction,
    FirewallDecision,
    FirewallMode,
    RuleStatus,
)


def make_decision(
    action: FirewallAction,
    risk_score: int,
) -> FirewallDecision:
    return FirewallDecision(
        ip="103.45.67.89",
        indicator="malware_c2",
        action=action,
        reason="Threat intelligence policy decision",
        risk_score=risk_score,
        policy="default-threat-block-policy",
    )


def test_default_adapter_uses_dry_run():
    adapter = FirewallAdapter()

    assert adapter.mode is FirewallMode.DRY_RUN


def test_block_decision_generates_proposed_rule():
    adapter = FirewallAdapter()

    execution = adapter.process(
        make_decision(FirewallAction.BLOCK, 98),
        source="controlled-threat-feed",
    )

    assert execution.action is FirewallAction.BLOCK
    assert execution.mode is FirewallMode.DRY_RUN
    assert execution.status is RuleStatus.PROPOSED
    assert execution.rule is not None
    assert execution.rule.ip == "103.45.67.89"
    assert execution.rule.enabled is True


def test_monitor_decision_does_not_generate_block_rule():
    adapter = FirewallAdapter()

    execution = adapter.process(
        make_decision(FirewallAction.MONITOR, 85),
        source="controlled-threat-feed",
    )

    assert execution.action is FirewallAction.MONITOR
    assert execution.status is RuleStatus.SKIPPED
    assert execution.rule is None


def test_ignore_decision_does_not_generate_block_rule():
    adapter = FirewallAdapter()

    execution = adapter.process(
        make_decision(FirewallAction.IGNORE, 40),
        source="controlled-threat-feed",
    )

    assert execution.action is FirewallAction.IGNORE
    assert execution.status is RuleStatus.SKIPPED
    assert execution.rule is None


def test_process_many_preserves_order():
    adapter = FirewallAdapter()

    decisions = (
        make_decision(FirewallAction.BLOCK, 98),
        make_decision(FirewallAction.MONITOR, 85),
        make_decision(FirewallAction.BLOCK, 92),
    )

    executions = adapter.process_many(
        decisions,
        source="controlled-threat-feed",
    )

    assert len(executions) == 3
    assert executions[0].ip == "103.45.67.89"
    assert executions[0].status is RuleStatus.PROPOSED
    assert executions[1].status is RuleStatus.SKIPPED
    assert executions[2].status is RuleStatus.PROPOSED


def test_empty_source_is_rejected():
    adapter = FirewallAdapter()

    try:
        adapter.process(
            make_decision(FirewallAction.BLOCK, 98),
            source="   ",
        )
    except ValueError as exc:
        assert str(exc) == "source must not be empty"
    else:
        raise AssertionError("Expected ValueError")
