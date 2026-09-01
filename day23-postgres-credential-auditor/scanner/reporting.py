from __future__ import annotations

import json
import logging
from collections import Counter
from dataclasses import fields
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from uuid import uuid4

from .auditor import AuditResult
from .models import AuditFinding
from .policies import CredentialPolicy


DEFAULT_REPORT_DIR = Path("output/reports")
DEFAULT_LOG_DIR = Path("output/logs")

JSON_REPORT_NAME = "day23_credential_audit.json"
TXT_REPORT_NAME = "day23_credential_audit.txt"
LOG_FILE_NAME = "day23_credential_audit.log"


def configure_logging(
    log_dir: Path = DEFAULT_LOG_DIR,
) -> Path:
    """Configure Day 23 report logging."""

    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / LOG_FILE_NAME

    logger = logging.getLogger("day23")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    file_handler = logging.FileHandler(
        log_path,
        encoding="utf-8",
    )

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return log_path


class ReportWriter:
    """Generate safe JSON and text evidence reports."""

    def __init__(
        self,
        policy: CredentialPolicy,
        report_dir: Path = DEFAULT_REPORT_DIR,
        log_dir: Path = DEFAULT_LOG_DIR,
    ) -> None:
        self.policy = policy
        self.report_dir = report_dir
        self.log_dir = log_dir

    def build_report(
        self,
        result: AuditResult,
        validation_status: str | None = None,
    ) -> dict[str, object]:
        """Build a structured report without exposing raw secrets."""

        severity_summary = Counter(
            finding.severity.value
            for finding in result.findings
        )

        status = validation_status or result.status

        return {
            "audit_id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": {
                "host": result.target.host,
                "port": result.target.port,
                "service": result.target.service,
            },
            "accounts_evaluated": result.credentials_evaluated,
            "finding_count": result.finding_count,
            "findings": [
                self._serialize_finding(finding)
                for finding in result.findings
            ],
            "severity_summary": {
                severity: severity_summary.get(severity, 0)
                for severity in (
                    "INFO",
                    "LOW",
                    "MEDIUM",
                    "HIGH",
                    "CRITICAL",
                )
            },
            "policy": self._serialize_policy(),
            "validation_status": status,
        }

    def write_reports(
        self,
        result: AuditResult,
        validation_status: str | None = None,
    ) -> tuple[Path, Path]:
        """Write JSON and TXT evidence reports."""

        self.report_dir.mkdir(parents=True, exist_ok=True)
        log_path = configure_logging(self.log_dir)

        logger = logging.getLogger("day23")

        report = self.build_report(
            result,
            validation_status=validation_status,
        )

        json_path = self.report_dir / JSON_REPORT_NAME
        txt_path = self.report_dir / TXT_REPORT_NAME

        json_path.write_text(
            json.dumps(report, indent=2) + "\n",
            encoding="utf-8",
        )

        txt_path.write_text(
            self._build_text_report(report),
            encoding="utf-8",
        )

        logger.info(
            "Credential audit reports generated "
            "audit_id=%s findings=%s json=%s txt=%s",
            report["audit_id"],
            result.finding_count,
            json_path,
            txt_path,
        )

        logger.info(
            "Report log stored at %s",
            log_path,
        )

        return json_path, txt_path

    @staticmethod
    def _serialize_finding(
        finding: AuditFinding,
    ) -> dict[str, str]:
        """Serialize only safe finding data."""

        return {
            "category": finding.category,
            "severity": finding.severity.value,
            "username": finding.username,
            "message": finding.message,
            "redacted_secret": finding.redacted_secret,
        }

    def _serialize_policy(self) -> dict[str, object]:
        """Serialize policy configuration without credential secrets."""

        policy: dict[str, object] = {}

        for field in fields(self.policy):
            value = getattr(self.policy, field.name)

            if isinstance(value, Enum):
                value = value.value
            elif isinstance(value, tuple):
                value = [
                    list(item) if isinstance(item, tuple) else item
                    for item in value
                ]

            policy[field.name] = value

        # Never expose the policy's raw default credential secret.
        policy.pop("default_admin_secret", None)

        # The username is configuration metadata, not a secret.
        return policy

    @staticmethod
    def _build_text_report(
        report: dict[str, object],
    ) -> str:
        target = report["target"]
        findings = report["findings"]
        severity_summary = report["severity_summary"]

        lines = [
            "=" * 60,
            "DAY 23 - POSTGRES CREDENTIAL AUDIT REPORT",
            "=" * 60,
            "",
            f"Audit ID      : {report['audit_id']}",
            f"Timestamp     : {report['timestamp']}",
            (
                "Target        : "
                f"{target['host']}:{target['port']}"
            ),
            f"Service       : {target['service']}",
            f"Accounts      : {report['accounts_evaluated']}",
            f"Findings      : {report['finding_count']}",
            f"Status        : {report['validation_status']}",
            "",
            "SEVERITY SUMMARY",
            "-" * 60,
        ]

        for severity, count in severity_summary.items():
            lines.append(f"{severity:<10}: {count}")

        lines.extend([
            "",
            "FINDINGS",
            "-" * 60,
        ])

        if findings:
            for finding in findings:
                lines.extend([
                    (
                        f"{finding['severity']:<8} "
                        f"{finding['category']}"
                    ),
                    f"  user={finding['username']}",
                    f"  secret={finding['redacted_secret']}",
                    f"  message={finding['message']}",
                    "",
                ])
        else:
            lines.extend([
                "No policy violations detected.",
                "",
            ])

        lines.extend([
            "POLICY",
            "-" * 60,
        ])

        for name, value in report["policy"].items():
            lines.append(f"{name}: {value}")

        lines.extend([
            "",
            "SECURITY NOTE",
            "-" * 60,
            "Raw credential secrets are intentionally excluded from this report.",
            "",
        ])

        return "\n".join(lines)