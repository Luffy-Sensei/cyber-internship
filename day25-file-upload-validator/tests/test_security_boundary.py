from pathlib import Path

from scanner.config import DEFAULT_UPLOAD_POLICY
from scanner.models import (
    FileType,
    ValidationAction,
    ValidationResult,
    ValidationStatus,
)
from scanner.pipeline import UploadSecurityPipeline
from scanner.storage import SafeStorage


def make_uploaded_file(path: Path):
    from scanner.models import UploadedFile

    return UploadedFile(
        path=str(path),
        filename=path.name,
        size_bytes=path.stat().st_size,
    )


def test_fake_jpeg_never_reaches_storage(tmp_path: Path):
    fixture = tmp_path / "fake.jpg"

    fixture.write_text(
        "#!/bin/sh\nMOCK-NON-IMAGE-CONTENT\n",
        encoding="utf-8",
    )

    pipeline = UploadSecurityPipeline(
        log_path=tmp_path / "audit.jsonl",
        report_dir=tmp_path / "reports",
    )

    result = pipeline.process(
        make_uploaded_file(fixture)
    )

    assert result.action is ValidationAction.REJECT

    log_content = (
        (tmp_path / "audit.jsonl")
        .read_text(encoding="utf-8")
    )

    assert '"stored": false' in log_content
    assert '"storage_name": null' in log_content


def test_extension_only_bypass_is_rejected(tmp_path: Path):
    fixture = tmp_path / "script.jpg"

    fixture.write_text(
        "<?php echo 'MOCK'; ?>",
        encoding="utf-8",
    )

    pipeline = UploadSecurityPipeline(
        log_path=tmp_path / "audit.jsonl",
        report_dir=tmp_path / "reports",
    )

    result = pipeline.process(
        make_uploaded_file(fixture)
    )

    assert result.action is ValidationAction.REJECT
    assert result.detected_type is None


def test_extension_signature_mismatch_is_rejected(tmp_path: Path):
    fixture = tmp_path / "image.png"

    fixture.write_bytes(
        b"\xFF\xD8\xFFMOCK-JPEG-DATA"
    )

    pipeline = UploadSecurityPipeline(
        log_path=tmp_path / "audit.jsonl",
        report_dir=tmp_path / "reports",
    )

    result = pipeline.process(
        make_uploaded_file(fixture)
    )

    assert result.action is ValidationAction.REJECT


def test_rejected_validation_produces_no_storage_name():
    validation = ValidationResult(
        filename="fake.jpg",
        action=ValidationAction.REJECT,
        status=ValidationStatus.INVALID,
        reason="File signature is unknown or unsupported.",
        detected_type=None,
        size_bytes=33,
    )

    storage = SafeStorage(DEFAULT_UPLOAD_POLICY)
    result = storage.prepare(validation)

    assert result.stored is False
    assert result.storage_name is None


def test_valid_upload_gets_server_generated_name(tmp_path: Path):
    fixture = tmp_path / "valid.jpg"

    fixture.write_bytes(
        b"\xFF\xD8\xFFMOCK-JPEG-DATA"
    )

    pipeline = UploadSecurityPipeline(
        log_path=tmp_path / "audit.jsonl",
        report_dir=tmp_path / "reports",
    )

    result = pipeline.process(
        make_uploaded_file(fixture)
    )

    assert result.action is ValidationAction.ACCEPT

    log_content = (
        (tmp_path / "audit.jsonl")
        .read_text(encoding="utf-8")
    )

    assert '"stored": true' in log_content
    assert '"storage_name": null' not in log_content
