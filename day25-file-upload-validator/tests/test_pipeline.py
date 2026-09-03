from pathlib import Path

from scanner.models import (
    ValidationAction,
    UploadedFile,
)
from scanner.pipeline import UploadSecurityPipeline


def make_uploaded_file(path: Path) -> UploadedFile:
    return UploadedFile(
        path=str(path),
        filename=path.name,
        size_bytes=path.stat().st_size,
    )


def test_pipeline_accepts_valid_png(tmp_path: Path):
    fixture = tmp_path / "valid.png"

    fixture.write_bytes(
        b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"
        b"MOCK-PNG-DATA"
    )

    pipeline = UploadSecurityPipeline(
        log_path=tmp_path / "logs" / "audit.jsonl",
        report_dir=tmp_path / "reports",
    )

    result = pipeline.process(
        make_uploaded_file(fixture)
    )

    assert result.action is ValidationAction.ACCEPT


def test_pipeline_rejects_fake_image(tmp_path: Path):
    fixture = tmp_path / "fake.jpg"

    fixture.write_text(
        "#!/bin/sh\nMOCK-NON-IMAGE-CONTENT\n",
        encoding="utf-8",
    )

    pipeline = UploadSecurityPipeline(
        log_path=tmp_path / "logs" / "audit.jsonl",
        report_dir=tmp_path / "reports",
    )

    result = pipeline.process(
        make_uploaded_file(fixture)
    )

    assert result.action is ValidationAction.REJECT


def test_pipeline_writes_audit_log(tmp_path: Path):
    fixture = tmp_path / "valid.jpg"

    fixture.write_bytes(
        b"\xFF\xD8\xFF"
        b"MOCK-JPEG-DATA"
    )

    log_path = tmp_path / "logs" / "audit.jsonl"

    pipeline = UploadSecurityPipeline(
        log_path=log_path,
        report_dir=tmp_path / "reports",
    )

    pipeline.process(
        make_uploaded_file(fixture)
    )

    assert log_path.exists()

    content = log_path.read_text(
        encoding="utf-8"
    )

    assert "valid.jpg" in content
    assert "ACCEPT" in content
    assert "JPEG" in content


def test_pipeline_generates_reports(tmp_path: Path):
    fixture = tmp_path / "valid.png"

    fixture.write_bytes(
        b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"
        b"MOCK-PNG-DATA"
    )

    report_dir = tmp_path / "reports"

    pipeline = UploadSecurityPipeline(
        log_path=tmp_path / "logs" / "audit.jsonl",
        report_dir=report_dir,
    )

    pipeline.process(
        make_uploaded_file(fixture)
    )

    json_path, text_path = pipeline.generate_reports()

    assert json_path.exists()
    assert text_path.exists()

    assert "DAY 25 FILE UPLOAD SECURITY REPORT" in (
        text_path.read_text(encoding="utf-8")
    )


def test_pipeline_rejected_upload_is_not_stored(tmp_path: Path):
    fixture = tmp_path / "fake.png"

    fixture.write_text(
        "This is not a PNG file.",
        encoding="utf-8",
    )

    pipeline = UploadSecurityPipeline(
        log_path=tmp_path / "logs" / "audit.jsonl",
        report_dir=tmp_path / "reports",
    )

    result = pipeline.process(
        make_uploaded_file(fixture)
    )

    assert result.action is ValidationAction.REJECT

    log_content = (
        (tmp_path / "logs" / "audit.jsonl")
        .read_text(encoding="utf-8")
    )

    assert '"stored": false' in log_content
    assert '"storage_name": null' in log_content
