from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .report_schema import validate_report


def utc_now() -> str:
    """Return the current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


class ScanReporter:
    """Generate JSON and TXT reports for Day 20 scans."""

    def __init__(
        self,
        target: str,
        wordlist_size: int,
        requests_sent: int,
    ) -> None:
        self.target = target
        self.wordlist_size = wordlist_size
        self.requests_sent = requests_sent
        self.scan_id = str(uuid.uuid4())
        self.started_at = utc_now()
        self._start_time = time.monotonic()

    def build_report(
        self,
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        completed_at = utc_now()
        duration = round(time.monotonic() - self._start_time, 4)

        summary = {
            "total_findings": len(findings),
            "critical": sum(
                1
                for finding in findings
                if finding.get("severity") == "CRITICAL"
            ),
            "high": sum(
                1
                for finding in findings
                if finding.get("severity") == "HIGH"
            ),
            "medium": sum(
                1
                for finding in findings
                if finding.get("severity") == "MEDIUM"
            ),
            "low": sum(
                1
                for finding in findings
                if finding.get("severity") == "LOW"
            ),
        }

        return {
            "schema_version": "1.0",
            "scan_id": self.scan_id,
            "target": self.target,
            "started_at": self.started_at,
            "completed_at": completed_at,
            "duration_seconds": duration,
            "wordlist_size": self.wordlist_size,
            "requests_sent": self.requests_sent,
            "findings": findings,
            "summary": summary,
        }

    def write_json(
        self,
        report: dict[str, Any],
        path: str | Path,
    ) -> None:
        valid, errors = validate_report(report)

        if not valid:
            raise ValueError(
                "Invalid report schema: " + "; ".join(errors)
            )

        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        output_path.write_text(
            json.dumps(report, indent=2),
            encoding="utf-8",
        )

    def write_text(
        self,
        report: dict[str, Any],
        path: str | Path,
    ) -> None:
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        summary = report["summary"]

        lines = [
            "=" * 60,
            "DAY 20 - WEB DIRECTORY DISCOVERY SCAN",
            "=" * 60,
            "",
            f"Target           : {report['target']}",
            f"Scan ID          : {report['scan_id']}",
            f"Started          : {report['started_at']}",
            f"Completed        : {report['completed_at']}",
            f"Duration         : {report['duration_seconds']}s",
            f"Wordlist size    : {report['wordlist_size']}",
            f"Requests sent    : {report['requests_sent']}",
            "",
            "SUMMARY",
            "-" * 60,
            f"Total findings   : {summary['total_findings']}",
            f"Critical         : {summary['critical']}",
            f"High             : {summary['high']}",
            f"Medium           : {summary['medium']}",
            f"Low              : {summary['low']}",
            "",
            "FINDINGS",
            "-" * 60,
        ]

        if not report["findings"]:
            lines.append("No security findings detected.")

        for index, finding in enumerate(
            report["findings"],
            start=1,
        ):
            lines.extend(
                [
                    "",
                    f"[{index}] {finding.get('rule_id', 'UNKNOWN')}",
                    f"Severity       : {finding.get('severity', 'UNKNOWN')}",
                    f"Path           : {finding.get('path', 'N/A')}",
                    f"Status         : {finding.get('status_code', 'N/A')}",
                    f"Evidence       : {finding.get('evidence', 'N/A')}",
                    f"Recommendation : "
                    f"{finding.get('recommendation', 'N/A')}",
                ]
            )

        lines.extend(
            [
                "",
                "=" * 60,
                "END OF REPORT",
                "=" * 60,
                "",
            ]
        )

        output_path.write_text(
            "\n".join(lines),
            encoding="utf-8",
        )
