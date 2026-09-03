from __future__ import annotations

from pathlib import Path

from scanner.config import UploadPolicy
from scanner.models import (
    UploadedFile,
    ValidationAction,
    ValidationResult,
    ValidationStatus,
)
from scanner.signatures import SignatureDetector


class UploadValidator:
    """Validate uploaded files against the configured security policy."""

    HEADER_READ_SIZE = 8

    def __init__(
        self,
        policy: UploadPolicy,
        detector: SignatureDetector | None = None,
    ) -> None:
        self.policy = policy
        self.detector = detector or SignatureDetector()

    def validate(self, uploaded_file: UploadedFile) -> ValidationResult:
        """Validate one uploaded file."""

        path = Path(uploaded_file.path)

        if not path.is_file():
            return self._reject(
                uploaded_file,
                "File does not exist or is not a regular file.",
            )

        actual_size = path.stat().st_size

        if actual_size != uploaded_file.size_bytes:
            return self._reject(
                uploaded_file,
                "File metadata size does not match the actual file size.",
                size_bytes=actual_size,
            )

        if actual_size > self.policy.max_file_size_bytes:
            return self._reject(
                uploaded_file,
                (
                    "File exceeds the configured maximum size "
                    f"of {self.policy.max_file_size_bytes} bytes."
                ),
                size_bytes=actual_size,
            )

        extension = Path(uploaded_file.filename).suffix.lower()

        if extension not in self.policy.allowed_extensions:
            return self._reject(
                uploaded_file,
                f"File extension is not allowlisted: {extension or '<none>'}",
                size_bytes=actual_size,
            )

        try:
            with path.open("rb") as file_handle:
                file_header = file_handle.read(self.HEADER_READ_SIZE)
        except OSError as exc:
            return self._reject(
                uploaded_file,
                f"Unable to read file safely: {exc}",
                size_bytes=actual_size,
            )

        detected_type = self.detector.detect(file_header)

        if detected_type is None:
            return self._reject(
                uploaded_file,
                "File signature is unknown or unsupported.",
                size_bytes=actual_size,
            )

        if detected_type not in self.policy.allowed_types:
            return self._reject(
                uploaded_file,
                f"Detected file type is not allowlisted: {detected_type.value}",
                size_bytes=actual_size,
            )

        if self.policy.require_extension_match:
            expected_extensions = self._extensions_for_type(detected_type)

            if extension not in expected_extensions:
                return self._reject(
                    uploaded_file,
                    (
                        f"Extension {extension} does not match "
                        f"detected type {detected_type.value}."
                    ),
                    size_bytes=actual_size,
                )

        return ValidationResult(
            filename=uploaded_file.filename,
            action=ValidationAction.ACCEPT,
            status=ValidationStatus.VALID,
            reason=(
                f"File signature validated as {detected_type.value} "
                "and matches the upload policy."
            ),
            detected_type=detected_type,
            size_bytes=actual_size,
        )

    @staticmethod
    def _extensions_for_type(file_type) -> tuple[str, ...]:
        if file_type.value == "PNG":
            return (".png",)

        if file_type.value == "JPEG":
            return (".jpg", ".jpeg")

        return ()

    @staticmethod
    def _reject(
        uploaded_file: UploadedFile,
        reason: str,
        *,
        size_bytes: int | None = None,
    ) -> ValidationResult:
        return ValidationResult(
            filename=uploaded_file.filename,
            action=ValidationAction.REJECT,
            status=ValidationStatus.INVALID,
            reason=reason,
            size_bytes=(
                uploaded_file.size_bytes
                if size_bytes is None
                else size_bytes
            ),
        )
