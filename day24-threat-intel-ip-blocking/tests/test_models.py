import pytest

from scanner.models import (
    BlockRule,
    FirewallAction,
    FirewallDecision,
    ThreatFeed,
    ThreatIndicator,
)


def test_threat_indicator_creation():
    indicator = ThreatIndicator(
        ip="103.45.67.89",
        indicator="malware_c2",
        risk_score=98,
        source="mock-feed",
    )

    assert indicator.ip == "103.45.67.89"
    assert indicator.indicator == "malware_c2"
    assert indicator.risk_score == 98
    assert indicator.source == "mock-feed"


def test_threat_indicator_rejects_invalid_risk_score():
    with pytest.raises(ValueError):
        ThreatIndicator(
            ip="103.45.67.89",
            indicator="malware_c2",
            risk_score=101,
            source="mock-feed",
        )


def test_threat_feed_creation():
    indicator = ThreatIndicator(
        ip="198.51.100.33",
        indicator="brute_forcer",
        risk_score=92,
        source="mock-feed",
    )

    feed = ThreatFeed(
        source="mock-feed",
        indicators=(indicator,),
    )

    assert feed.source == "mock-feed"
    assert len(feed.indicators) == 1


def test_firewall_decision_creation():
    decision = FirewallDecision(
        ip="103.45.67.89",
        indicator="malware_c2",
        action=FirewallAction.BLOCK,
        reason="High risk indicator",
        risk_score=98,
        policy="default-threat-block-policy",
    )

    assert decision.action is FirewallAction.BLOCK
    assert decision.risk_score == 98


def test_block_rule_creation():
    rule = BlockRule(
        ip="103.45.67.89",
        indicator="malware_c2",
        reason="Risk score meets or exceeds the configured blocking threshold.",
        source="mock-feed",
    )

    assert rule.ip == "103.45.67.89"
    assert rule.enabled is True


def test_block_rule_rejects_empty_ip():
    with pytest.raises(ValueError):
        BlockRule(
            ip="",
            indicator="malware_c2",
            reason="malware_c2",
            source="mock-feed",
        )
