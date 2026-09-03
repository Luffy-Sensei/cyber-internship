from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

from scanner.config import UploadPolicy
from scanner.models import ValidationAction, ValidationResult


@dataclass(frozen=True)
class StorageResult:
    """Result describing the storage decision for a validated upload."""

    filename: str
    stored: bool
    storage_name: str | None
    storage_class: str
    reason: str


class SafeStorage:
    """Apply safe-storage rules without executing uploaded content."""

    def __init__(self, policy: UploadPolicy) -> None:
        self.policy = policy

    def prepare(
        self,
        validation: ValidationResult,
    ) -> StorageResult:
        """Prepare a validated file for safe storage."""

        if validation.action is not ValidationAction.ACCEPT:
            return StorageResult(
                filename=validation.filename,
                stored=False,
                storage_name=None,
                storage_class=self.policy.storage_class,
                reason=(
                    "File was rejected by validation and must not "
                    "enter storage."
                ),
            )

        storage_name = self._generate_storage_name(
            validation.filename,
        )

        return StorageResult(
            filename=validation.filename,
            stored=True,
            storage_name=storage_name,
            storage_class=self.policy.storage_class,
            reason=(
                "File passed validation and is eligible for "
                "non-executable upload storage."
            ),
        )

    @staticmethod
    def _generate_storage_name(filename: str) -> str:
        """Generate an opaque server-side storage name."""

        extension = ""

        if "." in filename:
            extension = "." + filename.rsplit(".", 1)[1].lower()

        return f"{uuid4().hex}{extension}"
