import json
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .models import (
    RiskLevel,
    ScanResult,
    SecurityFinding,
    ServiceResult,
)
from .topology import TopologyBuilder

class ReportWriter:
    """Write structured Day 17 scan reports."""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

    def build_report(
        self,
        host: str,
        ports: tuple[int, ...],
        timeout: float,
        scan_results: list[ScanResult],
        service_results: list[ServiceResult],
        findings: list[SecurityFinding],
    ) -> dict:
        risk_summary = {
            level.value: 0
            for level in RiskLevel
        }

        for finding in findings:
            risk_summary[finding.risk.value] += 1

        topology = TopologyBuilder().build(
            host=host,
            service_results=service_results,
            findings=findings,
        )    

        return {
            "metadata": {
                "tool": "Day 17 Local Network Port Scanner",
                "version": "1.0.0",
                "run_id": str(uuid.uuid4()),
                "generated_at": datetime.now(
                    timezone.utc
                ).isoformat(),
            },
            "target": {
                "host": host,
                "ports": list(ports),
                "timeout": timeout,
            },
            "scan_results": [
                self._serialize(result)
                for result in scan_results
            ],
            "service_results": [
                self._serialize(result)
                for result in service_results
            ],
            "security_findings": [
                self._serialize(finding)
                for finding in findings
            ],
            "risk_summary": risk_summary,
            "topology": topology,
        }

    @staticmethod
    def _serialize(value):
        data = asdict(value)

        for key, item in data.items():
            if hasattr(item, "value"):
                data[key] = item.value

        return data

    def write_json(
        self,
        report: dict,
        filename: str = "day17_scan.json",
    ) -> Path:
        path = self.output_dir / filename

        with path.open(
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                report,
                file,
                indent=4,
            )

        return path

    def write_text(
        self,
        report: dict,
        filename: str = "day17_scan.txt",
    ) -> Path:
        path = self.output_dir / filename

        lines = []

        lines.append(
            "DAY 17 - LOCAL NETWORK SECURITY REPORT"
        )
        lines.append("=" * 60)
        lines.append("")

        target = report["target"]

        lines.append(
            f"Target : {target['host']}"
        )
        lines.append(
            f"Ports  : {target['ports']}"
        )
        lines.append(
            f"Timeout: {target['timeout']}s"
        )
        lines.append("")

        lines.append("PORT RESULTS")
        lines.append("-" * 60)

        for result in report["service_results"]:
            lines.append(
                f"{result['port']}/TCP "
                f"{result['state']:<8} "
                f"{result['service']:<16} "
                f"{result['category']:<22}"
            )

            if result["state"] == "OPEN":
                lines.append(
                    f"  Detection: "
                    f"{result['detection_method']}"
                )

                lines.append(
                    f"  Confidence: "
                    f"{result['confidence']}"
                )

                if result.get("evidence"):
                    lines.append(
                        f"  Evidence: "
                        f"{result['evidence']}"
                    )

        lines.append("")
        lines.append("SECURITY FINDINGS")
        lines.append("-" * 60)

        for finding in report["security_findings"]:
            lines.append(
                f"[{finding['risk']}] "
                f"{finding['port']}/TCP - "
                f"{finding['title']}"
            )

            lines.append(
                f"  Service: {finding['service']}"
            )

            lines.append(
                f"  Description: "
                f"{finding['description']}"
            )

            lines.append(
                f"  Recommendation: "
                f"{finding['recommendation']}"
            )

            lines.append("")

        lines.append("RISK SUMMARY")
        lines.append("-" * 60)

        for level, count in report["risk_summary"].items():
            lines.append(
                f"{level:<10}: {count}"
            )

        path.write_text(
            "\n".join(lines) + "\n",
            encoding="utf-8",
        )

        return path
