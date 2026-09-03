from __future__ import annotations

from pathlib import Path

from scanner.config import DEFAULT_UPLOAD_POLICY, UploadPolicy
from scanner.logging import AuditLogger
from scanner.models import UploadedFile, ValidationResult
from scanner.reporting import ReportWriter
from scanner.storage import SafeStorage
from scanner.validator import UploadValidator


class UploadSecurityPipeline:
    def __init__(
        self,
        policy: UploadPolicy = DEFAULT_UPLOAD_POLICY,
        log_path: Path = Path("output/logs/upload-audit.jsonl"),
        report_dir: Path = Path("output/reports"),
    ) -> None:
        self.policy = policy
        self.validator = UploadValidator(policy)
        self.storage = SafeStorage(policy)
        self.logger = AuditLogger(log_path)
        self.report_writer = ReportWriter(report_dir)

    def process(self, uploaded_file: UploadedFile) -> ValidationResult:
        validation = self.validator.validate(uploaded_file)

        storage_result = self.storage.prepare(validation)

        event = self.logger.build_event(
            validation,
            storage_result,
        )

        self.logger.write_event(event)

        return validation

    def generate_reports(self) -> tuple[Path, Path]:
        events = self._load_events()

        json_report = self.report_writer.write_json(events)
        text_report = self.report_writer.write_text(events)

        return json_report, text_report

    def _load_events(self) -> list:
        events = []

        if not self.logger.log_path.exists():
            return events

        import json

        with self.logger.log_path.open(
            "r",
            encoding="utf-8",
        ) as handle:
            for line in handle:
                if line.strip():
                    data = json.loads(line)

                    from scanner.logging import ValidationEvent

                    events.append(
                        ValidationEvent(**data)
                    )

        return events
