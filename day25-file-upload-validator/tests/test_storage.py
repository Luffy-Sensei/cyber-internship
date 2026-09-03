from scanner.config import DEFAULT_UPLOAD_POLICY
from scanner.models import (
    FileType,
    ValidationAction,
    ValidationResult,
    ValidationStatus,
)
from scanner.storage import SafeStorage


def valid_jpeg_result() -> ValidationResult:
    return ValidationResult(
        filename="photo.jpg",
        action=ValidationAction.ACCEPT,
        status=ValidationStatus.VALID,
        reason="JPEG signature validated",
        detected_type=FileType.JPEG,
        size_bytes=2048,
    )


def invalid_result() -> ValidationResult:
    return ValidationResult(
        filename="fake.jpg",
        action=ValidationAction.REJECT,
        status=ValidationStatus.INVALID,
        reason="File signature is unknown or unsupported.",
        size_bytes=100,
    )


def test_valid_file_is_eligible_for_storage() -> None:
    storage = SafeStorage(DEFAULT_UPLOAD_POLICY)

    result = storage.prepare(valid_jpeg_result())

    assert result.stored is True
    assert result.storage_name is not None
    assert result.storage_class == "NON_EXECUTABLE_UPLOAD_STORAGE"


def test_server_generated_name_does_not_preserve_original_name() -> None:
    storage = SafeStorage(DEFAULT_UPLOAD_POLICY)

    result = storage.prepare(valid_jpeg_result())

    assert result.storage_name is not None
    assert result.storage_name != "photo.jpg"
    assert result.storage_name.endswith(".jpg")


def test_rejected_file_never_enters_storage() -> None:
    storage = SafeStorage(DEFAULT_UPLOAD_POLICY)

    result = storage.prepare(invalid_result())

    assert result.stored is False
    assert result.storage_name is None
    assert "must not enter storage" in result.reason


def test_generated_storage_name_is_unique() -> None:
    storage = SafeStorage(DEFAULT_UPLOAD_POLICY)

    first = storage.prepare(valid_jpeg_result())
    second = storage.prepare(valid_jpeg_result())

    assert first.storage_name != second.storage_name


def test_generated_storage_name_preserves_safe_extension() -> None:
    storage = SafeStorage(DEFAULT_UPLOAD_POLICY)

    result = storage.prepare(valid_jpeg_result())

    assert result.storage_name is not None
    assert result.storage_name.endswith(".jpg")
