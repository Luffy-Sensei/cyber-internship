from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from scanner.models import ValidationResult
from scanner.storage import StorageResult


@dataclass(frozen=True)
class ValidationEvent:
    timestamp: str
    filename: str
    action: str
    status: str
    reason: str
    detected_type: str | None
    size_bytes: int
    stored: bool
    storage_name: str | None
    storage_class: str


class AuditLogger:
    def __init__(self, log_path: Path) -> None:
        self.log_path = Path(log_path)

    def build_event(
        self,
        validation: ValidationResult,
        storage: StorageResult,
    ) -> ValidationEvent:
        detected_type = (
            validation.detected_type.value
            if validation.detected_type is not None
            else None
        )

        return ValidationEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            filename=validation.filename,
            action=validation.action.value,
            status=validation.status.value,
            reason=validation.reason,
            detected_type=detected_type,
            size_bytes=validation.size_bytes,
            stored=storage.stored,
            storage_name=storage.storage_name,
            storage_class=storage.storage_class,
        )

    def write_event(self, event: ValidationEvent) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    asdict(event),
                    sort_keys=True,
                )
                + "\n"
            )
