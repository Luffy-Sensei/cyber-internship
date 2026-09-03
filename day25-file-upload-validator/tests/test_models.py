import pytest

from scanner.models import (
    FileType,
    StorageDecision,
    UploadedFile,
    ValidationAction,
    ValidationResult,
    ValidationStatus,
)


def test_uploaded_file_accepts_valid_metadata() -> None:
    uploaded = UploadedFile(
        path="input/benign/photo.jpg",
        filename="photo.jpg",
        size_bytes=1024,
    )

    assert uploaded.filename == "photo.jpg"
    assert uploaded.size_bytes == 1024


def test_uploaded_file_rejects_empty_filename() -> None:
    with pytest.raises(ValueError, match="filename must not be empty"):
        UploadedFile(
            path="input/benign/photo.jpg",
            filename="",
            size_bytes=1024,
        )


def test_uploaded_file_rejects_negative_size() -> None:
    with pytest.raises(ValueError, match="size_bytes must not be negative"):
        UploadedFile(
            path="input/benign/photo.jpg",
            filename="photo.jpg",
            size_bytes=-1,
        )


def test_accept_result_requires_detected_type() -> None:
    with pytest.raises(
        ValueError,
        match="ACCEPT action requires detected_type",
    ):
        ValidationResult(
            filename="photo.jpg",
            action=ValidationAction.ACCEPT,
            status=ValidationStatus.VALID,
            reason="Valid file",
        )


def test_valid_accept_result() -> None:
    result = ValidationResult(
        filename="photo.jpg",
        action=ValidationAction.ACCEPT,
        status=ValidationStatus.VALID,
        reason="JPEG signature validated",
        detected_type=FileType.JPEG,
        size_bytes=2048,
    )

    assert result.action is ValidationAction.ACCEPT
    assert result.status is ValidationStatus.VALID
    assert result.detected_type is FileType.JPEG


def test_reject_result_requires_invalid_status() -> None:
    with pytest.raises(
        ValueError,
        match="REJECT action requires INVALID status",
    ):
        ValidationResult(
            filename="payload.jpg",
            action=ValidationAction.REJECT,
            status=ValidationStatus.VALID,
            reason="Signature mismatch",
        )


def test_storage_decision_requires_reason() -> None:
    with pytest.raises(
        ValueError,
        match="reason must not be empty",
    ):
        StorageDecision(
            filename="payload.jpg",
            allowed=False,
            reason="",
            storage_class="NON_EXECUTABLE_UPLOAD_STORAGE",
        )
