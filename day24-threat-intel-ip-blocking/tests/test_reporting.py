import json

from scanner.firewall import FirewallAdapter
from scanner.ingestion import ThreatFeedIngestor
from scanner.models import FirewallMode
from scanner.policies import get_default_policy
from scanner.reporting import ThreatIntelReportWriter


def build_pipeline():
    feed = ThreatFeedIngestor().load_file(
        "input/mock-threat-feed.json"
    )

    policy = get_default_policy()

    decisions = tuple(
        policy.evaluate(indicator)
        for indicator in feed.indicators
    )

    adapter = FirewallAdapter(
        mode=FirewallMode.DRY_RUN,
    )

    executions = adapter.process_many(
        decisions,
        source=feed.source,
    )

    return feed, policy, executions


def test_build_report_counts_decisions():
    feed, policy, executions = build_pipeline()

    writer = ThreatIntelReportWriter()

    report = writer.build_report(
        feed,
        executions,
        policy=policy.name,
        execution_mode=FirewallMode.DRY_RUN.value,
    )

    assert report["indicators_received"] == 3
    assert report["indicators_valid"] == 3
    assert report["blocks_proposed"] == 2
    assert report["monitored"] == 1
    assert report["ignored"] == 0
    assert report["rejected"] == 0
    assert report["firewall_modification"] is False


def test_report_contains_decision_details():
    feed, policy, executions = build_pipeline()

    writer = ThreatIntelReportWriter()

    report = writer.build_report(
        feed,
        executions,
        policy=policy.name,
    )

    assert len(report["decisions"]) == 3
    assert report["decisions"][0]["ip"] == "103.45.67.89"
    assert report["decisions"][0]["indicator"] == "malware_c2"
    assert report["decisions"][0]["action"] == "BLOCK"


def test_json_report_is_written(tmp_path):
    feed, policy, executions = build_pipeline()

    writer = ThreatIntelReportWriter(
        report_directory=tmp_path / "reports",
    )

    report = writer.build_report(
        feed,
        executions,
        policy=policy.name,
    )

    output_path = writer.write_json(report)

    assert output_path.exists()

    loaded = json.loads(
        output_path.read_text(encoding="utf-8")
    )

    assert loaded["feed_id"] == "day24-mock-feed-001"
    assert loaded["blocks_proposed"] == 2


def test_text_report_is_written(tmp_path):
    feed, policy, executions = build_pipeline()

    writer = ThreatIntelReportWriter(
        report_directory=tmp_path / "reports",
    )

    report = writer.build_report(
        feed,
        executions,
        policy=policy.name,
    )

    output_path = writer.write_text(report)

    content = output_path.read_text(
        encoding="utf-8"
    )

    assert "THREAT INTELLIGENCE PIPELINE REPORT" in content
    assert "103.45.67.89" in content
    assert "BLOCK" in content
    assert "DRY-RUN" in content


def test_log_file_is_created(tmp_path):
    feed, policy, executions = build_pipeline()

    writer = ThreatIntelReportWriter(
        log_directory=tmp_path / "logs",
    )

    report = writer.build_report(
        feed,
        executions,
        policy=policy.name,
    )

    log_path = writer.configure_logging()

    writer.log_report(
        report,
        log_path=log_path,
    )

    assert log_path.exists()

    content = log_path.read_text(
        encoding="utf-8"
    )

    assert "blocks_proposed=2" in content
    assert "monitored=1" in content
    assert "firewall_modification=False" in content
