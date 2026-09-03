import json
from pathlib import Path

from scanner.logging import AuditLogger
from scanner.models import (
    FileType,
    ValidationAction,
    ValidationResult,
    ValidationStatus,
)
from scanner.storage import SafeStorage
from scanner.config import DEFAULT_UPLOAD_POLICY


def make_validation(
    filename: str = "valid.jpg",
) -> ValidationResult:
    return ValidationResult(
        filename=filename,
        action=ValidationAction.ACCEPT,
        status=ValidationStatus.VALID,
        reason="File passed magic-byte and extension validation.",
        detected_type=FileType.JPEG,
        size_bytes=128,
    )


def test_build_event_contains_validation_and_storage_data(tmp_path: Path):
    logger = AuditLogger(tmp_path / "audit.jsonl")
    validation = make_validation()
    storage = SafeStorage(DEFAULT_UPLOAD_POLICY).prepare(validation)

    event = logger.build_event(validation, storage)

    assert event.filename == "valid.jpg"
    assert event.action == "ACCEPT"
    assert event.status == "VALID"
    assert event.detected_type == "JPEG"
    assert event.size_bytes == 128
    assert event.stored is True
    assert event.storage_class == "NON_EXECUTABLE_UPLOAD_STORAGE"


def test_write_event_creates_jsonl_record(tmp_path: Path):
    log_path = tmp_path / "output" / "audit.jsonl"
    logger = AuditLogger(log_path)

    validation = make_validation()
    storage = SafeStorage(DEFAULT_UPLOAD_POLICY).prepare(validation)
    event = logger.build_event(validation, storage)

    logger.write_event(event)

    assert log_path.exists()

    line = log_path.read_text(encoding="utf-8").strip()
    record = json.loads(line)

    assert record["filename"] == "valid.jpg"
    assert record["action"] == "ACCEPT"
    assert record["status"] == "VALID"


def test_write_event_appends_records(tmp_path: Path):
    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path)

    validation = make_validation()
    storage = SafeStorage(DEFAULT_UPLOAD_POLICY).prepare(validation)
    event = logger.build_event(validation, storage)

    logger.write_event(event)
    logger.write_event(event)

    lines = log_path.read_text(encoding="utf-8").splitlines()

    assert len(lines) == 2
    assert json.loads(lines[0])["filename"] == "valid.jpg"
    assert json.loads(lines[1])["filename"] == "valid.jpg"


def test_rejected_event_records_no_storage(tmp_path: Path):
    logger = AuditLogger(tmp_path / "audit.jsonl")

    validation = ValidationResult(
        filename="fake.jpg",
        action=ValidationAction.REJECT,
        status=ValidationStatus.INVALID,
        reason="Magic bytes do not match an allowed image format.",
        detected_type=None,
        size_bytes=32,
    )

    storage = SafeStorage(DEFAULT_UPLOAD_POLICY).prepare(validation)
    event = logger.build_event(validation, storage)

    assert event.action == "REJECT"
    assert event.status == "INVALID"
    assert event.stored is False
    assert event.storage_name is None
