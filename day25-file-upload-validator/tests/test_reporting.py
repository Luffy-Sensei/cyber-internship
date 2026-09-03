import json
from pathlib import Path

from scanner.config import DEFAULT_UPLOAD_POLICY
from scanner.logging import AuditLogger
from scanner.models import (
    FileType,
    ValidationAction,
    ValidationResult,
    ValidationStatus,
)
from scanner.reporting import ReportWriter
from scanner.storage import SafeStorage


def make_validation(
    filename: str,
    accepted: bool,
) -> ValidationResult:
    if accepted:
        return ValidationResult(
            filename=filename,
            action=ValidationAction.ACCEPT,
            status=ValidationStatus.VALID,
            reason="File passed validation.",
            detected_type=FileType.JPEG,
            size_bytes=128,
        )

    return ValidationResult(
        filename=filename,
        action=ValidationAction.REJECT,
        status=ValidationStatus.INVALID,
        reason="Magic bytes do not match the allowed file type.",
        detected_type=None,
        size_bytes=32,
    )


def build_events(tmp_path: Path):
    logger = AuditLogger(tmp_path / "audit.jsonl")
    storage = SafeStorage(DEFAULT_UPLOAD_POLICY)

    events = []

    for validation in [
        make_validation("valid.jpg", True),
        make_validation("fake.jpg", False),
    ]:
        storage_result = storage.prepare(validation)
        events.append(
            logger.build_event(validation, storage_result)
        )

    return events


def test_build_summary(tmp_path: Path):
    events = build_events(tmp_path)
    writer = ReportWriter(tmp_path / "reports")

    summary = writer.build_summary(events)

    assert summary == {
        "total_events": 2,
        "accepted": 1,
        "rejected": 1,
        "stored": 1,
        "not_stored": 1,
    }


def test_write_json_report(tmp_path: Path):
    events = build_events(tmp_path)
    writer = ReportWriter(tmp_path / "reports")

    report_path = writer.write_json(events)

    assert report_path.exists()

    report = json.loads(
        report_path.read_text(encoding="utf-8")
    )

    assert report["summary"]["total_events"] == 2
    assert report["summary"]["accepted"] == 1
    assert report["summary"]["rejected"] == 1
    assert len(report["events"]) == 2


def test_write_text_report(tmp_path: Path):
    events = build_events(tmp_path)
    writer = ReportWriter(tmp_path / "reports")

    report_path = writer.write_text(events)

    assert report_path.exists()

    content = report_path.read_text(encoding="utf-8")

    assert "DAY 25 FILE UPLOAD SECURITY REPORT" in content
    assert "Accepted     : 1" in content
    assert "Rejected     : 1" in content
    assert "valid.jpg" in content
    assert "fake.jpg" in content


def test_report_preserves_rejection_evidence(tmp_path: Path):
    events = build_events(tmp_path)
    writer = ReportWriter(tmp_path / "reports")

    report_path = writer.write_json(events)

    report = json.loads(
        report_path.read_text(encoding="utf-8")
    )

    rejected = [
        event
        for event in report["events"]
        if event["action"] == "REJECT"
    ]

    assert len(rejected) == 1
    assert rejected[0]["filename"] == "fake.jpg"
    assert rejected[0]["stored"] is False
    assert rejected[0]["storage_name"] is None
