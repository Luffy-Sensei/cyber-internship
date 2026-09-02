import json

from scanner.firewall import FirewallAdapter
from scanner.models import FirewallAction, FirewallMode, RuleStatus
from scanner.policies import get_default_policy
from scanner.validation import ValidationEngine


def load_fixture():
    with open(
        "input/validation-threat-feed.json",
        "r",
        encoding="utf-8",
    ) as handle:
        return json.load(handle)


def test_valid_indicators_reach_policy_and_firewall_dry_run():
    payload = load_fixture()

    validation = ValidationEngine().validate(
        feed_id=payload["feed_id"],
        source=payload["source"],
        indicators=payload["indicators"],
    )

    policy = get_default_policy()
    firewall = FirewallAdapter(mode=FirewallMode.DRY_RUN)

    decisions = tuple(
        policy.evaluate(indicator)
        for indicator in validation.valid_indicators
    )

    executions = firewall.process_many(
        decisions,
        source=payload["source"],
    )

    assert len(decisions) == 3
    assert len(executions) == 3

    assert [decision.action for decision in decisions] == [
        FirewallAction.BLOCK,
        FirewallAction.MONITOR,
        FirewallAction.BLOCK,
    ]

    assert [execution.status for execution in executions] == [
        RuleStatus.PROPOSED,
        RuleStatus.SKIPPED,
        RuleStatus.PROPOSED,
    ]

    assert all(
        execution.mode is FirewallMode.DRY_RUN
        for execution in executions
    )


def test_rejected_indicators_never_reach_policy_or_firewall():
    payload = load_fixture()

    validation = ValidationEngine().validate(
        feed_id=payload["feed_id"],
        source=payload["source"],
        indicators=payload["indicators"],
    )

    policy = get_default_policy()
    firewall = FirewallAdapter(mode=FirewallMode.DRY_RUN)

    valid_ips = {
        indicator.ip
        for indicator in validation.valid_indicators
    }

    rejected_ips = {
        entry.raw_entry.get("ip")
        for entry in validation.rejected_indicators
        if isinstance(entry.raw_entry, dict)
    }

    decisions = tuple(
        policy.evaluate(indicator)
        for indicator in validation.valid_indicators
    )

    executions = firewall.process_many(
        decisions,
        source=payload["source"],
    )

    decision_ips = {decision.ip for decision in decisions}
    execution_ips = {execution.ip for execution in executions}

    assert valid_ips == {
        "103.45.67.89",
        "185.10.11.12",
        "198.51.100.33",
    }

    assert rejected_ips == {
        "not-an-ip",
        "192.0.2.10",
        "192.0.2.20",
    }

    assert decision_ips == valid_ips
    assert execution_ips == valid_ips

    assert decision_ips.isdisjoint(rejected_ips)
    assert execution_ips.isdisjoint(rejected_ips)


def test_only_high_risk_valid_indicators_produce_block_rules():
    payload = load_fixture()

    validation = ValidationEngine().validate(
        feed_id=payload["feed_id"],
        source=payload["source"],
        indicators=payload["indicators"],
    )

    policy = get_default_policy()
    firewall = FirewallAdapter(mode=FirewallMode.DRY_RUN)

    decisions = tuple(
        policy.evaluate(indicator)
        for indicator in validation.valid_indicators
    )

    executions = firewall.process_many(
        decisions,
        source=payload["source"],
    )

    proposed_blocks = [
        execution
        for execution in executions
        if execution.action is FirewallAction.BLOCK
    ]

    assert len(proposed_blocks) == 2

    assert {
        execution.ip
        for execution in proposed_blocks
    } == {
        "103.45.67.89",
        "198.51.100.33",
    }

    assert all(
        execution.status is RuleStatus.PROPOSED
        for execution in proposed_blocks
    )

    assert all(
        execution.mode is FirewallMode.DRY_RUN
        for execution in proposed_blocks
    )
