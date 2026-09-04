import json

from scanner.logging import WAFAuditLogger
from scanner.models import (
    Confidence,
    RuleCategory,
    Severity,
    WAFAction,
    WAFDecision,
    WAFDetection,
)


def make_decision(
    action: WAFAction = WAFAction.BLOCK,
) -> WAFDecision:
    detection = WAFDetection(
        rule_id="TEST-RULE-001",
        category=RuleCategory.SQLI,
        severity=Severity.HIGH,
        matched_field="query",
        evidence="UNION SELECT",
        confidence=Confidence.HIGH,
    )

    return WAFDecision(
        request_id="req-004",
        action=action,
        detections=(detection,),
    )


def test_logger_creates_parent_directory(tmp_path):
    log_path = tmp_path / "logs" / "waf-audit.jsonl"

    logger = WAFAuditLogger(log_path)

    logger.log_decision(
        make_decision(),
        method="GET",
        path="/controlled/test",
    )

    assert log_path.exists()


def test_logger_writes_valid_jsonl(tmp_path):
    log_path = tmp_path / "waf-audit.jsonl"

    logger = WAFAuditLogger(log_path)

    logger.log_decision(
        make_decision(),
        method="GET",
        path="/controlled/test",
    )

    lines = log_path.read_text(
        encoding="utf-8"
    ).splitlines()

    assert len(lines) == 1

    event = json.loads(lines[0])

    assert event["request_id"] == "req-004"
    assert event["method"] == "GET"
    assert event["path"] == "/controlled/test"
    assert event["action"] == "BLOCK"
    assert event["detection_count"] == 1


def test_logger_records_triggered_rule(tmp_path):
    log_path = tmp_path / "waf-audit.jsonl"

    logger = WAFAuditLogger(log_path)

    logger.log_decision(
        make_decision(),
        method="GET",
        path="/controlled/test",
    )

    event = json.loads(
        log_path.read_text(
            encoding="utf-8"
        )
    )

    assert event["rules_triggered"] == [
        "TEST-RULE-001"
    ]


def test_logger_appends_multiple_events(tmp_path):
    log_path = tmp_path / "waf-audit.jsonl"

    logger = WAFAuditLogger(log_path)

    logger.log_decision(
        make_decision(WAFAction.BLOCK),
        method="GET",
        path="/blocked",
    )

    logger.log_decision(
        make_decision(WAFAction.MONITOR),
        method="POST",
        path="/monitored",
    )

    lines = log_path.read_text(
        encoding="utf-8"
    ).splitlines()

    assert len(lines) == 2
