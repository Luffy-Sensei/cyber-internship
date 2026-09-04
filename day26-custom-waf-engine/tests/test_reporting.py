import json

from scanner.models import (
    Confidence,
    RuleCategory,
    Severity,
    WAFAction,
    WAFDecision,
    WAFDetection,
)
from scanner.reporting import WAFReportWriter


def make_detection(
    rule_id: str,
    severity: Severity,
) -> WAFDetection:
    return WAFDetection(
        rule_id=rule_id,
        category=RuleCategory.SQLI,
        severity=severity,
        matched_field="query",
        evidence="controlled-test",
        confidence=Confidence.HIGH,
    )


def test_build_report_counts_actions():
    decisions = (
        WAFDecision(
            request_id="req-001",
            action=WAFAction.ALLOW,
        ),
        WAFDecision(
            request_id="req-002",
            action=WAFAction.MONITOR,
            detections=(
                make_detection(
                    "TEST-MEDIUM",
                    Severity.MEDIUM,
                ),
            ),
        ),
        WAFDecision(
            request_id="req-003",
            action=WAFAction.BLOCK,
            detections=(
                make_detection(
                    "TEST-HIGH",
                    Severity.HIGH,
                ),
            ),
        ),
    )

    report = WAFReportWriter().build_report(decisions)

    assert report["requests_processed"] == 3
    assert report["allowed"] == 1
    assert report["monitored"] == 1
    assert report["blocked"] == 1
    assert report["detections"] == 2


def test_report_collects_unique_rules():
    decisions = (
        WAFDecision(
            request_id="req-001",
            action=WAFAction.BLOCK,
            detections=(
                make_detection(
                    "RULE-A",
                    Severity.HIGH,
                ),
            ),
        ),
        WAFDecision(
            request_id="req-002",
            action=WAFAction.BLOCK,
            detections=(
                make_detection(
                    "RULE-A",
                    Severity.HIGH,
                ),
                make_detection(
                    "RULE-B",
                    Severity.CRITICAL,
                ),
            ),
        ),
    )

    report = WAFReportWriter().build_report(decisions)

    assert report["rules_triggered"] == [
        "RULE-A",
        "RULE-B",
    ]


def test_json_report_can_be_written(tmp_path):
    writer = WAFReportWriter()

    report = writer.build_report(())

    output = tmp_path / "reports" / "day26-report.json"

    writer.write_json(report, output)

    assert output.exists()

    loaded = json.loads(
        output.read_text(
            encoding="utf-8"
        )
    )

    assert loaded["requests_processed"] == 0
    assert "run_id" in loaded
    assert "timestamp" in loaded


def test_text_report_can_be_written(tmp_path):
    writer = WAFReportWriter()

    decisions = (
        WAFDecision(
            request_id="req-004",
            action=WAFAction.BLOCK,
            detections=(
                make_detection(
                    "PATH-TRAVERSAL-001",
                    Severity.HIGH,
                ),
            ),
        ),
    )

    report = writer.build_report(decisions)

    output = tmp_path / "reports" / "day26-report.txt"

    writer.write_text(report, output)

    content = output.read_text(
        encoding="utf-8"
    )

    assert "DAY 26 WAF SECURITY REPORT" in content
    assert "req-004" in content
    assert "BLOCK" in content
    assert "PATH-TRAVERSAL-001" in content
    assert "HIGH" in content
