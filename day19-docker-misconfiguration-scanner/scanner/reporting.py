import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .detector import SecurityFinding
from .risk import RiskAnalyzer


class ReportWriter:
    """Generate JSON and TXT Docker security reports."""

    def build_report(
        self,
        input_file: str,
        findings: list[SecurityFinding],
    ) -> dict:
        risk_analyzer = RiskAnalyzer()

        serialized_findings = []
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

        for finding in findings:
            risk = risk_analyzer.assess(finding)

            severity = risk.severity.lower()

            if severity in severity_counts:
                severity_counts[severity] += 1

            serialized_findings.append(
                {
                    "rule_id": finding.rule_id,
                    "line_number": finding.line_number,
                    "message": finding.message,
                    "severity": risk.severity,
                    "score": risk.score,
                    "classification": risk.classification,
                    "recommendation": risk.recommendation,
                }
            )

        report = {
            "report_version": "1.0",
            "run_id": str(uuid4()),
            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "input_file": input_file,
            "statistics": {
                "findings": len(findings),
                **severity_counts,
            },
            "findings": serialized_findings,
        }

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

        statistics = report["statistics"]

        lines = [
            "DAY 19 - DOCKER SECURITY REPORT",
            "=" * 60,
            "",
            f"Run ID       : {report['run_id']}",
            f"Generated    : {report['generated_at']}",
            f"Input        : {report['input_file']}",
            "",
            "SUMMARY",
            "-" * 60,
            f"Findings     : {statistics['findings']}",
            f"Critical     : {statistics['critical']}",
            f"High         : {statistics['high']}",
            f"Medium       : {statistics['medium']}",
            f"Low          : {statistics['low']}",
            "",
            "FINDINGS",
            "-" * 60,
        ]

        if not report["findings"]:
            lines.append(
                "[NONE] No Dockerfile misconfigurations detected."
            )

        for index, finding in enumerate(
            report["findings"],
            start=1,
        ):
            lines.extend(
                [
                    "",
                    f"Finding #{index}",
                    f"Rule         : {finding['rule_id']}",
                    f"Line         : {finding['line_number']}",
                    f"Severity     : {finding['severity']}",
                    f"Risk Score   : {finding['score']}",
                    f"Classification: "
                    f"{finding['classification']}",
                    f"Message      : {finding['message']}",
                    f"Recommendation: "
                    f"{finding['recommendation']}",
                ]
            )

        path.write_text(
            "\n".join(lines) + "\n",
            encoding="utf-8",
        )
