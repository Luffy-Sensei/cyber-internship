from pathlib import Path

from scanner.config import DEFAULT_UPLOAD_POLICY
from scanner.models import (
    FileType,
    UploadedFile,
    ValidationAction,
    ValidationStatus,
)
from scanner.validator import UploadValidator


BASE_DIR = Path(__file__).resolve().parents[1]


def make_uploaded_file(relative_path: str, filename: str) -> UploadedFile:
    path = BASE_DIR / relative_path

    return UploadedFile(
        path=str(path),
        filename=filename,
        size_bytes=path.stat().st_size,
    )


def test_valid_png_is_accepted() -> None:
    validator = UploadValidator(DEFAULT_UPLOAD_POLICY)

    uploaded = make_uploaded_file(
        "input/benign/valid.png",
        "valid.png",
    )

    result = validator.validate(uploaded)

    assert result.action is ValidationAction.ACCEPT
    assert result.status is ValidationStatus.VALID
    assert result.detected_type is FileType.PNG


def test_valid_jpeg_is_accepted() -> None:
    validator = UploadValidator(DEFAULT_UPLOAD_POLICY)

    uploaded = make_uploaded_file(
        "input/benign/valid.jpg",
        "valid.jpg",
    )

    result = validator.validate(uploaded)

    assert result.action is ValidationAction.ACCEPT
    assert result.status is ValidationStatus.VALID
    assert result.detected_type is FileType.JPEG


def test_fake_jpeg_is_rejected() -> None:
    validator = UploadValidator(DEFAULT_UPLOAD_POLICY)

    uploaded = make_uploaded_file(
        "input/malicious/fake.jpg",
        "fake.jpg",
    )

    result = validator.validate(uploaded)

    assert result.action is ValidationAction.REJECT
    assert result.status is ValidationStatus.INVALID
    assert "signature" in result.reason.lower()


def test_fake_png_is_rejected() -> None:
    validator = UploadValidator(DEFAULT_UPLOAD_POLICY)

    uploaded = make_uploaded_file(
        "input/malicious/fake.png",
        "fake.png",
    )

    result = validator.validate(uploaded)

    assert result.action is ValidationAction.REJECT
    assert result.status is ValidationStatus.INVALID


def test_unsupported_extension_is_rejected() -> None:
    validator = UploadValidator(DEFAULT_UPLOAD_POLICY)

    uploaded = make_uploaded_file(
        "input/malicious/unknown.txt",
        "unknown.txt",
    )

    result = validator.validate(uploaded)

    assert result.action is ValidationAction.REJECT
    assert "extension" in result.reason.lower()


def test_extension_signature_mismatch_is_rejected(tmp_path) -> None:
    path = tmp_path / "wrong.jpg"
    path.write_bytes(b"\x89PNG\r\n\x1a\nMOCK-PNG")

    uploaded = UploadedFile(
        path=str(path),
        filename="wrong.jpg",
        size_bytes=path.stat().st_size,
    )

    validator = UploadValidator(DEFAULT_UPLOAD_POLICY)

    result = validator.validate(uploaded)

    assert result.action is ValidationAction.REJECT
    assert "does not match" in result.reason.lower()


def test_missing_file_is_rejected() -> None:
    validator = UploadValidator(DEFAULT_UPLOAD_POLICY)

    uploaded = UploadedFile(
        path="input/benign/does-not-exist.png",
        filename="does-not-exist.png",
        size_bytes=0,
    )

    result = validator.validate(uploaded)

    assert result.action is ValidationAction.REJECT
    assert "does not exist" in result.reason.lower()


def test_size_metadata_mismatch_is_rejected() -> None:
    path = BASE_DIR / "input/benign/valid.png"

    uploaded = UploadedFile(
        path=str(path),
        filename="valid.png",
        size_bytes=999999,
    )

    validator = UploadValidator(DEFAULT_UPLOAD_POLICY)

    result = validator.validate(uploaded)

    assert result.action is ValidationAction.REJECT
    assert "size" in result.reason.lower()
