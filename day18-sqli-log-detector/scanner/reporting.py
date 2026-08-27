import json
from dataclasses import asdict
from pathlib import Path
from uuid import uuid4
from datetime import datetime, timezone

from .models import Finding
from .report_schema import validate_report


class ReportWriter:
    """Generate JSON and TXT security reports."""

    def build_report(
        self,
        input_file: str,
        total_entries: int,
        findings: list[Finding],
    ) -> dict:
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

        serialized_findings = []

        for finding in findings:
            severity = finding.risk.severity.lower()

            if severity in severity_counts:
                severity_counts[severity] += 1

            serialized_findings.append(
                {
                    "source_ip": finding.source_ip,
                    "method": finding.method.value,
                    "path": finding.path,
                    "status_code": finding.status_code,
                    "severity": finding.risk.severity,
                    "score": finding.risk.score,
                    "classification": (
                        finding.risk.classification
                    ),
                    "recommendation": (
                        finding.risk.recommendation
                    ),
                    "detections": [
                        asdict(detection)
                        for detection in finding.detections
                    ],
                }
            )

        report = {
            "report_version": "1.0",
            "run_id": str(uuid4()),
            "generated_at": (
                datetime.now(timezone.utc)
                .isoformat()
            ),
            "input_file": input_file,
            "statistics": {
                "total_entries": total_entries,
                "detections": len(findings),
                **severity_counts,
            },
            "findings": serialized_findings,
        }

        validate_report(report)

        return report

    def write_json(
        self,
        report: dict,
        output_file: str,
    ) -> None:
        path = Path(output_file)
        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        path.write_text(
            json.dumps(
                report,
                indent=2,
            ),
            encoding="utf-8",
        )

    def write_text(
        self,
        report: dict,
        output_file: str,
    ) -> None:
        path = Path(output_file)
        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        lines = [
            "DAY 18 - SQL INJECTION SECURITY REPORT",
            "=" * 60,
            "",
            f"Run ID       : {report['run_id']}",
            f"Generated    : {report['generated_at']}",
            f"Input        : {report['input_file']}",
            "SUMMARY",
            "-" * 60,
            f"Entries      : "
            f"{report['statistics']['total_entries']}",
            f"Detections   : "
            f"{report['statistics']['detections']}",
            f"Critical     : "
            f"{report['statistics']['critical']}",
            f"High         : "
            f"{report['statistics']['high']}",
            f"Medium       : "
            f"{report['statistics']['medium']}",
            f"Low          : "
            f"{report['statistics']['low']}",
            "",
            "FINDINGS",
            "-" * 60,
        ]

        if not report["findings"]:
            lines.append(
                "[NONE] No SQL injection indicators detected."
            )

        for index, finding in enumerate(
            report["findings"],
            start=1,
        ):
            lines.extend(
                [
                    "",
                    f"Finding #{index}",
                    f"Source       : "
                    f"{finding['source_ip']}",
                    f"Method       : "
                    f"{finding['method']}",
                    f"Path         : "
                    f"{finding['path']}",
                    f"Status       : "
                    f"{finding['status_code']}",
                    f"Severity     : "
                    f"{finding['severity']}",
                    f"Risk Score   : "
                    f"{finding['score']}",
                    f"Classification: "
                    f"{finding['classification']}",
                    "",
                    "Detections:",
                ]
            )

            for detection in finding["detections"]:
                lines.append(
                    f"  - {detection['signature']} "
                    f"({detection['confidence']}) "
                    f"Evidence: "
                    f"{detection['evidence']}"
                )

            lines.extend(
                [
                    "",
                    "Recommendation:",
                    f"  {finding['recommendation']}",
                ]
            )

        path.write_text(
            "\n".join(lines) + "\n",
            encoding="utf-8",
        )
