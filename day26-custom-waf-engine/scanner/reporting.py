from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from scanner.models import WAFDecision


class WAFReportWriter:
    """Build and persist aggregate WAF audit reports."""

    def build_report(
        self,
        decisions: tuple[WAFDecision, ...],
    ) -> dict[str, object]:
        allowed = sum(
            decision.action.value == "ALLOW"
            for decision in decisions
        )

        monitored = sum(
            decision.action.value == "MONITOR"
            for decision in decisions
        )

        blocked = sum(
            decision.action.value == "BLOCK"
            for decision in decisions
        )

        detections = sum(
            len(decision.detections)
            for decision in decisions
        )

        rules_triggered = sorted(
            {
                detection.rule_id
                for decision in decisions
                for detection in decision.detections
            }
        )

        return {
            "run_id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "requests_processed": len(decisions),
            "allowed": allowed,
            "monitored": monitored,
            "blocked": blocked,
            "detections": detections,
            "rules_triggered": rules_triggered,
            "decisions": [
                self._serialize_decision(decision)
                for decision in decisions
            ],
        }

    def write_json(
        self,
        report: dict[str, object],
        output_path: Path,
    ) -> None:
        output_path = Path(output_path)
        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with output_path.open(
            "w",
            encoding="utf-8",
        ) as handle:
            json.dump(
                report,
                handle,
                indent=2,
                sort_keys=True,
            )
            handle.write("\n")

    def write_text(
        self,
        report: dict[str, object],
        output_path: Path,
    ) -> None:
        output_path = Path(output_path)
        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        lines = [
            "DAY 26 WAF SECURITY REPORT",
            "=" * 28,
            "",
            f"Run ID            : {report['run_id']}",
            f"Timestamp         : {report['timestamp']}",
            f"Requests processed: {report['requests_processed']}",
            f"Allowed           : {report['allowed']}",
            f"Monitored         : {report['monitored']}",
            f"Blocked           : {report['blocked']}",
            f"Detections        : {report['detections']}",
            "",
            "Rules Triggered",
            "---------------",
        ]

        rules_triggered = report["rules_triggered"]

        for rule_id in rules_triggered:
            lines.append(f"- {rule_id}")

        lines.extend(
            [
                "",
                "Decisions",
                "---------",
            ]
        )

        for decision in report["decisions"]:
            lines.extend(
                [
                    "",
                    f"Request ID : {decision['request_id']}",
                    f"Action     : {decision['action']}",
                    f"Detections : {len(decision['detections'])}",
                ]
            )

            for detection in decision["detections"]:
                lines.append(
                    f"Rule       : {detection['rule_id']}"
                )
                lines.append(
                    f"Category   : {detection['category']}"
                )
                lines.append(
                    f"Severity   : {detection['severity']}"
                )
                lines.append(
                    f"Field      : {detection['matched_field']}"
                )
                lines.append(
                    f"Confidence : {detection['confidence']}"
                )

        with output_path.open(
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write("\n".join(lines))
            handle.write("\n")

    @staticmethod
    def _serialize_decision(
        decision: WAFDecision,
    ) -> dict[str, object]:
        return {
            "request_id": decision.request_id,
            "action": decision.action.value,
            "detections": [
                {
                    "rule_id": detection.rule_id,
                    "category": detection.category.value,
                    "severity": detection.severity.value,
                    "matched_field": detection.matched_field,
                    "evidence": detection.evidence,
                    "confidence": detection.confidence.value,
                }
                for detection in decision.detections
            ],
        }
