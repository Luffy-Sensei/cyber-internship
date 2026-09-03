import pytest

from scanner.config import DEFAULT_UPLOAD_POLICY, UploadPolicy
from scanner.models import FileType


def test_default_policy_allows_png_and_jpeg() -> None:
    policy = DEFAULT_UPLOAD_POLICY

    assert FileType.PNG in policy.allowed_types
    assert FileType.JPEG in policy.allowed_types


def test_default_policy_contains_expected_extensions() -> None:
    policy = DEFAULT_UPLOAD_POLICY

    assert ".png" in policy.allowed_extensions
    assert ".jpg" in policy.allowed_extensions
    assert ".jpeg" in policy.allowed_extensions


def test_default_policy_has_positive_size_limit() -> None:
    assert DEFAULT_UPLOAD_POLICY.max_file_size_bytes > 0


def test_default_policy_requires_extension_match() -> None:
    assert DEFAULT_UPLOAD_POLICY.require_extension_match is True


def test_default_storage_is_non_executable() -> None:
    assert (
        DEFAULT_UPLOAD_POLICY.storage_class
        == "NON_EXECUTABLE_UPLOAD_STORAGE"
    )


def test_policy_rejects_empty_allowed_types() -> None:
    with pytest.raises(
        ValueError,
        match="allowed_types must not be empty",
    ):
        UploadPolicy(allowed_types=())


def test_policy_rejects_invalid_extension() -> None:
    with pytest.raises(
        ValueError,
        match="allowed_extensions must start with '.'",
    ):
        UploadPolicy(
            allowed_extensions=("png",),
        )


def test_policy_rejects_invalid_size_limit() -> None:
    with pytest.raises(
        ValueError,
        match="max_file_size_bytes must be greater than zero",
    ):
        UploadPolicy(max_file_size_bytes=0)

def test_server_generated_filename_is_enabled() -> None:
    assert DEFAULT_UPLOAD_POLICY.generate_server_filename is True


def test_original_filename_preservation_is_disabled() -> None:
    assert DEFAULT_UPLOAD_POLICY.preserve_original_filename is False


def test_direct_execution_is_disabled() -> None:
    assert DEFAULT_UPLOAD_POLICY.allow_direct_execution is False


def test_policy_rejects_direct_execution() -> None:
    with pytest.raises(
        ValueError,
        match="direct execution",
    ):
        UploadPolicy(allow_direct_execution=True)


def test_policy_rejects_conflicting_filename_settings() -> None:
    with pytest.raises(
        ValueError,
        match="cannot both be enabled",
    ):
        UploadPolicy(
            generate_server_filename=True,
            preserve_original_filename=True,
        )        
