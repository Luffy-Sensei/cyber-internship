from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ValidationAction(str, Enum):
    """Security action produced by the upload validator."""

    ACCEPT = "ACCEPT"
    REJECT = "REJECT"


class ValidationStatus(str, Enum):
    """Final validation state for an uploaded file."""

    VALID = "VALID"
    INVALID = "INVALID"


class FileType(str, Enum):
    """Supported upload formats."""

    PNG = "PNG"
    JPEG = "JPEG"


@dataclass(frozen=True)
class UploadedFile:
    """Metadata describing a file presented to the upload validator."""

    path: str
    filename: str
    size_bytes: int

    def __post_init__(self) -> None:
        if not self.path.strip():
            raise ValueError("path must not be empty")

        if not self.filename.strip():
            raise ValueError("filename must not be empty")

        if self.size_bytes < 0:
            raise ValueError("size_bytes must not be negative")


@dataclass(frozen=True)
class FileSignature:
    """Description of a recognized file signature."""

    file_type: FileType
    signature: bytes

    def __post_init__(self) -> None:
        if not self.signature:
            raise ValueError("signature must not be empty")


@dataclass(frozen=True)
class ValidationResult:
    """Result produced by the file-upload security validator."""

    filename: str
    action: ValidationAction
    status: ValidationStatus
    reason: str
    detected_type: FileType | None = None
    size_bytes: int = 0

    def __post_init__(self) -> None:
        if not self.filename.strip():
            raise ValueError("filename must not be empty")

        if not self.reason.strip():
            raise ValueError("reason must not be empty")

        if self.size_bytes < 0:
            raise ValueError("size_bytes must not be negative")

        if self.action is ValidationAction.ACCEPT:
            if self.status is not ValidationStatus.VALID:
                raise ValueError(
                    "ACCEPT action requires VALID status"
                )

            if self.detected_type is None:
                raise ValueError(
                    "ACCEPT action requires detected_type"
                )

        if self.action is ValidationAction.REJECT:
            if self.status is not ValidationStatus.INVALID:
                raise ValueError(
                    "REJECT action requires INVALID status"
                )


@dataclass(frozen=True)
class StorageDecision:
    """Security decision describing whether a file may enter storage."""

    filename: str
    allowed: bool
    reason: str
    storage_class: str

    def __post_init__(self) -> None:
        if not self.filename.strip():
            raise ValueError("filename must not be empty")

        if not self.reason.strip():
            raise ValueError("reason must not be empty")

        if not self.storage_class.strip():
            raise ValueError("storage_class must not be empty")
